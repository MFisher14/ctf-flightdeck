"""Synthetic HCFG samples for the binary CRC-transform opener (B-246).

The binary lane's config container is `HCFG | version u8 | key u8 | length u16 | crc32 u32 | payload`, and the
CRC-32 is that of the DECODED payload, so every widened reading of solvers/binary/crc_transforms.py is a
never-wrong reading behind it. These builders write samples whose records are encoded the ways oracle-audit
row 4 lists, from code, so `python -m ctf arm` and the B-036 lane gate replay the widened readers on every
change:

  cheap      one sample, thirteen records: a rotate-then-XOR payload, a repeating ADD key, a repeating SUB key,
             raw deflate, (count, byte) RLE, PackBits, bz2, xz, an LZ4 frame, (byte, count) RLE, and three
             `_outer` forms (raw deflate, bz2 and (count, byte) RLE compressed outside the XOR). Each campaign
             value names its encoding.
  costly     one sample, four records (the costly pass reads the first four headers nothing else opened): LZNT1,
             Okumura LZSS, ChaCha20 under a 32-character key string and the 12 bytes after it, and an MSVC
             rand() keystream seeded by the u32 stored right after the payload.
  costly_lz  raw and size-prefixed LZ4 blocks, aPLib, and Salsa20 under a 16-character key string.
  costly_lcg K&R, Numerical Recipes and minstd LCG keystreams, and glibc rand() (TYPE_3).
  costly_java
             java.util.Random nextBytes and nextInt(256), xorshift32 and MT19937 (init_genrand).
  costly_py  Python's random getrandbits(8), randint(0, 255) and randbytes, and LZNT1 outside the XOR.
             Each PRNG seed sits in another place the seed search looks: the header byte, a value in 0..255,
             a u32 (LE or BE) beside the record, decimal text near it.
  broken     controls: the records with one bit of every stored CRC-32 flipped. `broken` holds the cheap and
             costly samples; broken_lz, broken_lcg, broken_java and broken_py one costly sample each, since the
             costly pass reads only the first four headers of a file. No reading may hold: the CRC-32 is the
             only proof any of them has.

The encoders here are written independently of the decoders they test (the tests pin each against a public
reference vector or a second implementation), and every builder is deterministic.
"""
from __future__ import annotations

import bz2
import functools
import json
import lzma
import random
import struct
import zlib
from pathlib import Path

OPENING = b'{"campaign":"'


def config(campaign: str, **more) -> bytes:
    """A lane-shaped config: compact JSON whose first member is the campaign."""
    d = {"campaign": campaign, "c2_url": "https://relay.example.net/api/beacon", "mutex": "Global\\B246Mutex",
         "sleep": 30}
    d.update(more)
    return json.dumps(d, separators=(",", ":")).encode()


def record(plain: bytes, payload: bytes, key: int, version: int = 1, crc: int | None = None) -> bytes:
    """An HCFG record: the header storing the CRC-32 of `plain`, then the encoded `payload`."""
    c = zlib.crc32(plain) & 0xFFFFFFFF if crc is None else crc
    return b"HCFG" + bytes([version, key]) + struct.pack("<HI", len(payload), c) + payload


def xor1(b: bytes, k: int) -> bytes:
    return bytes(x ^ k for x in b)


def repeat(plain: bytes, key: bytes, op: str) -> bytes:
    """`plain` under a repeating key: xor, add (payload = plain + key) or sub (payload = plain - key)."""
    out = bytearray()
    for i, c in enumerate(plain):
        k = key[i % len(key)]
        out.append(c ^ k if op == "xor" else (c + k) & 0xFF if op == "add" else (c - k) & 0xFF)
    return bytes(out)


def rotl(plain: bytes, r: int) -> bytes:
    return bytes(((c << r) | (c >> (8 - r))) & 0xFF for c in plain)


def rle_cb(plain: bytes) -> bytes:
    out, i = bytearray(), 0
    while i < len(plain):
        j = i
        while j < len(plain) and plain[j] == plain[i] and j - i < 255:
            j += 1
        out += bytes([j - i, plain[i]])
        i = j
    return bytes(out)


def packbits(plain: bytes) -> bytes:
    """PackBits with runs of 3+ as repeats and the rest as literal runs of up to 128."""
    out, i, n = bytearray(), 0, len(plain)
    lit = bytearray()

    def flush():
        while lit:
            part = lit[:128]
            out.append(len(part) - 1)
            out.extend(part)
            del lit[:128]

    while i < n:
        j = i
        while j < n and plain[j] == plain[i] and j - i < 128:
            j += 1
        if j - i >= 3:
            flush()
            out += bytes([257 - (j - i), plain[i]])
            i = j
        else:
            lit.append(plain[i])
            i += 1
    flush()
    return bytes(out)


def lznt1(data: bytes) -> bytes:
    """A greedy LZNT1 compressor (4 KiB chunks, every chunk compressed): the NT phrase split widens with the
    chunk position exactly as RtlDecompressBuffer reads it."""
    out = bytearray()
    for c0 in range(0, len(data), 4096):
        chunk = data[c0:c0 + 4096]
        body, i = bytearray(), 0
        while i < len(chunk):
            fpos, flags = len(body), 0
            body.append(0)
            for bit in range(8):
                if i >= len(chunk):
                    break
                best, disp = 0, 0
                if i:
                    p, lmask, oshift = i - 1, 0x0FFF, 12
                    while p >= 0x10:
                        p >>= 1
                        lmask >>= 1
                        oshift -= 1
                    for d in range(1, min(i, 1 << (16 - oshift)) + 1):
                        n = 0
                        while n < lmask + 3 and i + n < len(chunk) and chunk[i + n - d] == chunk[i + n]:
                            n += 1
                        if n > best:
                            best, disp = n, d
                if best >= 3:
                    body += (((disp - 1) << oshift) | (best - 3)).to_bytes(2, "little")
                    flags |= 1 << bit
                    i += best
                else:
                    body.append(chunk[i])
                    i += 1
            body[fpos] = flags
        out += (0xB000 | (len(body) - 1)).to_bytes(2, "little") + body
    return bytes(out)


def lzss(data: bytes, fill: int = 0x20) -> bytes:
    """A greedy Okumura-LZSS compressor (N 4096, F 18, threshold 2, ring start N-F; flag 1 a literal). A match
    copies earlier output: output byte q sits at ring index (N - F + q) mod N. `fill` is unused by matches
    here (none reaches before the output start), so either ring fill decodes it."""
    N, F = 4096, 18
    out, i = bytearray(), 0
    while i < len(data):
        fpos, flags = len(out), 0
        out.append(0)
        for bit in range(8):
            if i >= len(data):
                break
            best, src = 0, 0
            for s in range(max(0, i - (N - F)), i):
                n = 0
                while n < F and i + n < len(data) and data[s + n] == data[i + n]:
                    n += 1
                if n > best:
                    best, src = n, s
            if best >= 3:
                pos = (N - F + src) % N
                out += bytes([pos & 0xFF, ((pos >> 4) & 0xF0) | (best - 3)])
                i += best
            else:
                flags |= 1 << bit
                out.append(data[i])
                i += 1
        out[fpos] = flags
    return bytes(out)


def aplib_literals(data: bytes) -> bytes:
    """A literal-only aPLib stream: the first byte raw, then a 0 tag bit and the byte for each literal, then the
    terminating short match (tag bits 110 and a zero byte). Tag bytes are MSB-first and stand in the stream where
    the decoder first needs a bit."""
    out = bytearray(data[:1])
    state = {"pos": 0, "left": 0}

    def bit(b):
        if not state["left"]:
            state["pos"], state["left"] = len(out), 8
            out.append(0)
        if b:
            out[state["pos"]] |= 1 << (state["left"] - 1)
        state["left"] -= 1

    for c in data[1:]:
        bit(0)
        out.append(c)
    for b in (1, 1, 0):
        bit(b)
    out.append(0)
    return bytes(out)


def msvc_stream(seed: int, n: int) -> bytes:
    """MSVC rand() low bytes after srand(seed) (rand() = (s >> 16) & 0x7FFF)."""
    s, out = seed & 0xFFFFFFFF, bytearray()
    for _ in range(n):
        s = (s * 214013 + 2531011) & 0xFFFFFFFF
        out.append((s >> 16) & 0x7FFF & 0xFF)
    return bytes(out)


def lcg_stream(seed: int, n: int, mul: int, inc: int, shift: int) -> bytes:
    """A 32-bit LCG s = s * mul + inc (mod 2**32), the byte at bit `shift` of each state: K&R rand() (1103515245,
    12345, 16) and Numerical Recipes' ranqd1 (1664525, 1013904223, 24)."""
    s, out = seed & 0xFFFFFFFF, bytearray()
    for _ in range(n):
        s = (s * mul + inc) & 0xFFFFFFFF
        out.append((s >> shift) & 0xFF)
    return bytes(out)


def minstd_stream(seed: int, n: int) -> bytes:
    """Park-Miller minimal standard (16807, modulus 2**31 - 1), the low byte of each output."""
    s, out = seed, bytearray()
    for _ in range(n):
        s = (16807 * s) % 0x7FFFFFFF
        out.append(s & 0xFF)
    return bytes(out)


def glibc_stream(seed: int, n: int) -> bytes:
    """glibc rand() after srand(seed) (random_r.c, TYPE_3): 31 words seeded by r = 16807 * r mod (2**31 - 1), the
    first three repeated, 310 outputs discarded, then r[i] = r[i-31] + r[i-3] (mod 2**32) and rand() = r[i] >> 1;
    the low byte of each."""
    r = [seed or 1]
    for _ in range(30):
        r.append((16807 * r[-1]) % 0x7FFFFFFF)
    r += r[:3]
    while len(r) < 344:
        r.append((r[-31] + r[-3]) & 0xFFFFFFFF)
    out = bytearray()
    while len(out) < n:
        r.append((r[-31] + r[-3]) & 0xFFFFFFFF)
        out.append((r[-1] >> 1) & 0xFF)
    return bytes(out)


def java_next32(seed: int, count: int) -> list:
    """java.util.Random(seed).nextInt() x count, as unsigned 32-bit values."""
    mask = (1 << 48) - 1
    s, vals = (seed ^ 0x5DEECE66D) & mask, []
    for _ in range(count):
        s = (s * 0x5DEECE66D + 11) & mask
        vals.append(s >> 16)
    return vals


def java_next_bytes(seed: int, n: int) -> bytes:
    """Random.nextBytes: each nextInt() fills four bytes, least significant first."""
    return b"".join(v.to_bytes(4, "little") for v in java_next32(seed, (n + 3) // 4))[:n]


def java_next_int256(seed: int, n: int) -> bytes:
    """Random.nextInt(256): a power-of-two bound returns (256 * next(31)) >> 31, the top byte of nextInt()."""
    return bytes(v >> 24 for v in java_next32(seed, n))


def xorshift32_stream(seed: int, n: int) -> bytes:
    """Marsaglia's xorshift32 (13, 17, 5), the low byte of each state."""
    x, out = seed, bytearray()
    for _ in range(n):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        out.append(x & 0xFF)
    return bytes(out)


def mt19937_stream(seed: int, n: int) -> bytes:
    """MT19937 after init_genrand(seed) (std::mt19937(seed)), the low byte of each genrand_int32(): the
    reference algorithm, its twist and tempering written out."""
    mt = [seed & 0xFFFFFFFF]
    for i in range(1, 624):
        mt.append((1812433253 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xFFFFFFFF)
    out, idx = bytearray(), 624
    while len(out) < n:
        if idx == 624:
            for i in range(624):
                y = (mt[i] & 0x80000000) | (mt[(i + 1) % 624] & 0x7FFFFFFF)
                mt[i] = mt[(i + 397) % 624] ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)
            idx = 0
        y = mt[idx]
        idx += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        out.append(y & 0xFF)
    return bytes(out)


def py_stream(seed: int, n: int, how: str) -> bytes:
    """Python's random.Random(seed): getrandbits(8), randint(0, 255) or randbytes."""
    rng = random.Random(seed)
    if how == "randbytes":
        return rng.randbytes(n)
    return bytes(rng.getrandbits(8) if how == "getrandbits8" else rng.randint(0, 255) for _ in range(n))


def keyed(plain: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(plain, stream))


def raw_deflate(plain: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(plain) + c.flush()


PAD = b"\x00" * 24
CHACHA_KEY = b"B246-chacha-key-0123456789abcdef"     # 32 characters: a ChaCha20 key string
CHACHA_NONCE = bytes(range(0xA0, 0xAC))              # the 12 bytes after the key's NUL
PRNG_SEED = 0x1337BEEF


def cheap_records(crc_flip: int = 0) -> bytes:
    def rec(plain, payload, key):
        return record(plain, payload, key, crc=(zlib.crc32(plain) & 0xFFFFFFFF) ^ crc_flip) + PAD

    import lz4.frame

    p = [config("B246-rotate-r3"), config("B246-repeat-add"), config("B246-repeat-sub"),
         config("B246-deflate-raw"), config("B246-rle-" + "z" * 40), config("B246-packbits-" + "q" * 40),
         config("B246-bz2"), config("B246-xz"), config("B246-lz4-frame"), config("B246-rle-bc-" + "w" * 40),
         config("B246-deflate-raw-outer"), config("B246-bz2-outer"), config("B246-rle-outer-" + "v" * 40)]
    pairs = rle_cb(p[9])
    rle_bc = bytes(b for i in range(0, len(pairs), 2) for b in pairs[i:i + 2][::-1])     # (byte, count)
    return (PAD + rec(p[0], rotl(xor1(p[0], 0x5A), 3), 0x5A)
            + rec(p[1], repeat(p[1], b"\x11\x22\x33\x44\x55", "add"), 0x11)
            + rec(p[2], repeat(p[2], b"subkey-0123", "sub"), 0x73)
            + rec(p[3], xor1(raw_deflate(p[3]), 0x29), 0x29)
            + rec(p[4], xor1(rle_cb(p[4]), 0x3C), 0x3C)
            + rec(p[5], xor1(packbits(p[5]), 0x47), 0x47)
            + rec(p[6], xor1(bz2.compress(p[6]), 0x13), 0x13)
            + rec(p[7], xor1(lzma.compress(p[7]), 0x14), 0x14)
            + rec(p[8], xor1(lz4.frame.compress(p[8]), 0x15), 0x15)
            + rec(p[9], xor1(rle_bc, 0x3D), 0x3D)
            + rec(p[10], raw_deflate(xor1(p[10], 0x2A)), 0x2A)
            + rec(p[11], bz2.compress(xor1(p[11], 0x16)), 0x16)
            + rec(p[12], rle_cb(xor1(p[12], 0x3E)), 0x3E))


def costly_records(crc_flip: int = 0) -> bytes:
    from Cryptodome.Cipher import ChaCha20

    def rec(plain, payload, key):
        return record(plain, payload, key, crc=(zlib.crc32(plain) & 0xFFFFFFFF) ^ crc_flip)

    p = [config("B246-lznt1-" + "n" * 30), config("B246-lzss-" + "s" * 30), config("B246-chacha20"),
         config("B246-prng-msvc")]
    chacha = ChaCha20.new(key=CHACHA_KEY, nonce=CHACHA_NONCE).encrypt(p[2])
    return (PAD + rec(p[0], xor1(lznt1(p[0]), 0x61), 0x61) + PAD
            + rec(p[1], xor1(lzss(p[1]), 0x62), 0x62) + PAD
            + CHACHA_KEY + b"\x00" + CHACHA_NONCE + PAD + rec(p[2], chacha, 0x63) + PAD
            + rec(p[3], bytes(a ^ b for a, b in zip(p[3], msvc_stream(PRNG_SEED, len(p[3])))), 0x64)
            + struct.pack("<I", PRNG_SEED) + PAD)


SALSA_KEY = b"B246-salsa-k16!!"                     # 16 characters: a Salsa20 key string (zero nonce)
SEEDS = {"ansi": 4711, "nr": 0xA1B2C3D4, "minstd": 0x0BADF00D, "glibc": 0x9C, "java_bytes": 0xCAFE1234,
         "java_int256": 0x00C0FFEE, "xorshift32": 0x2468ACE1, "mt19937": 31337, "py_getrandbits8": 0x5B,
         "py_randint": 200, "py_randbytes": 0x7E57AB1E}


def _records(parts, crc_flip: int) -> bytes:
    """PAD, then for each (before, plain, payload, key byte, after): before + record + after + PAD."""
    out = bytearray(PAD)
    for before, plain, payload, key, after in parts:
        out += before + record(plain, payload, key, crc=(zlib.crc32(plain) & 0xFFFFFFFF) ^ crc_flip) + after + PAD
    return bytes(out)


def costly_lz_records(crc_flip: int = 0) -> bytes:
    import lz4.block
    from Cryptodome.Cipher import Salsa20

    p = [config("B246-lz4-block-" + "b" * 30), config("B246-lz4-sized-" + "c" * 30), config("B246-aplib"),
         config("B246-salsa20")]
    return _records([
        (b"", p[0], xor1(lz4.block.compress(p[0], store_size=False), 0x67), 0x67, b""),
        (b"", p[1], xor1(lz4.block.compress(p[1]), 0x68), 0x68, b""),
        (b"", p[2], xor1(aplib_literals(p[2]), 0x66), 0x66, b""),
        (SALSA_KEY + b"\x00" + PAD, p[3], Salsa20.new(key=SALSA_KEY, nonce=bytes(8)).encrypt(p[3]), 0x03, b""),
    ], crc_flip)


def costly_lcg_records(crc_flip: int = 0) -> bytes:
    p = [config("B246-prng-" + n) for n in ("ansi", "nr", "minstd", "glibc")]
    sd = SEEDS
    return _records([
        (b"seed=%d\x00" % sd["ansi"], p[0], keyed(p[0], lcg_stream(sd["ansi"], len(p[0]), 1103515245, 12345, 16)),
         0x41, b""),                                                                    # decimal text before
        (b"", p[1], keyed(p[1], lcg_stream(sd["nr"], len(p[1]), 1664525, 1013904223, 24)), 0x42,
         struct.pack("<I", sd["nr"])),                                                  # a LE word after
        (struct.pack(">I", sd["minstd"]), p[2], keyed(p[2], minstd_stream(sd["minstd"], len(p[2]))), 0x43,
         b""),                                                                          # a BE word before
        (b"", p[3], keyed(p[3], glibc_stream(sd["glibc"], len(p[3]))), sd["glibc"], b""),   # the header byte
    ], crc_flip)


def costly_java_records(crc_flip: int = 0) -> bytes:
    p = [config("B246-prng-" + n) for n in ("java-bytes", "java-int256", "xorshift32", "mt19937")]
    sd = SEEDS
    return _records([
        (struct.pack(">I", sd["java_bytes"]), p[0], keyed(p[0], java_next_bytes(sd["java_bytes"], len(p[0]))),
         0x05, b""),
        (b"", p[1], keyed(p[1], java_next_int256(sd["java_int256"], len(p[1]))), 0x51,
         struct.pack("<I", sd["java_int256"])),
        (struct.pack("<I", sd["xorshift32"]), p[2], keyed(p[2], xorshift32_stream(sd["xorshift32"], len(p[2]))),
         0x52, b""),
        (b"mt_seed %d\x00" % sd["mt19937"], p[3], keyed(p[3], mt19937_stream(sd["mt19937"], len(p[3]))), 0x53,
         b""),
    ], crc_flip)


def costly_py_records(crc_flip: int = 0) -> bytes:
    p = [config("B246-prng-py-" + n) for n in ("getrandbits8", "randint", "randbytes")] \
        + [config("B246-lznt1-outer-" + "o" * 30)]
    sd = SEEDS
    return _records([
        (b"", p[0], keyed(p[0], py_stream(sd["py_getrandbits8"], len(p[0]), "getrandbits8")), 0x09, b""),  # 0..255
        (b"rand %d\x00" % sd["py_randint"], p[1], keyed(p[1], py_stream(sd["py_randint"], len(p[1]), "randint")),
         0x0A, b""),
        (b"", p[2], keyed(p[2], py_stream(sd["py_randbytes"], len(p[2]), "randbytes")), 0x0B,
         struct.pack("<I", sd["py_randbytes"])),
        (b"", p[3], lznt1(xor1(p[3], 0x6B)), 0x6B, b""),
    ], crc_flip)


COSTLY_SAMPLES = {"lz": costly_lz_records, "lcg": costly_lcg_records, "java": costly_java_records,
                  "py": costly_py_records}


def _write(dest: Path, name: str, data: bytes) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / name
    path.write_bytes(data)
    return path


def hcfg_cheap(dest: Path) -> Path:
    """Base: thirteen records, each read only by a cheap widened reading (module docstring)."""
    return _write(dest, "sample.bin", cheap_records())


def hcfg_costly(dest: Path) -> Path:
    """Case: four records, each read only by a costly widened reading (module docstring)."""
    return _write(dest, "sample.bin", costly_records())


def hcfg_broken(dest: Path) -> Path:
    """Control: every record of both samples with one stored CRC-32 bit flipped. Nothing may be read."""
    return _write(dest, "sample.bin", cheap_records(1 << 7) + costly_records(1 << 7))


def _sample(build, crc_flip: int, dest: Path) -> Path:
    """A costly sample (COSTLY_SAMPLES) as a case (crc_flip 0) or as its control (one stored CRC-32 bit flipped)."""
    return _write(dest, "sample.bin", build(crc_flip))


BUILDERS = {"hcfg_crc_cheap": hcfg_cheap, "hcfg_crc_costly": hcfg_costly, "hcfg_crc_broken": hcfg_broken}
for _name, _build in COSTLY_SAMPLES.items():
    BUILDERS[f"hcfg_crc_costly_{_name}"] = functools.partial(_sample, _build, 0)
    BUILDERS[f"hcfg_crc_broken_{_name}"] = functools.partial(_sample, _build, 1 << 7)
