"""In-test embedders for B-245 (audio, palette and JPEG carriers). Every carrier is synthetic and made
here in memory with numpy, Pillow and a tiny baseline-JPEG writer; nothing is read from a challenge and
no stego tool is run. The embedders are written from the published descriptions of each method, not
from the readers under test."""
from __future__ import annotations

import io
import math
import struct
import zlib

import numpy as np


# ---- containers ----------------------------------------------------------------------------------

def len_crc(payload: bytes) -> bytes:
    """[len:u32 BE][crc32:u32 BE][payload]: the layout stego_containers.validate_container proves."""
    return struct.pack(">II", len(payload), zlib.crc32(payload) & 0xFFFFFFFF) + payload


def bits_of(data: bytes, msb_first=True) -> list[int]:
    order = range(7, -1, -1) if msb_first else range(8)
    return [(b >> s) & 1 for b in data for s in order]


# ---- WAV -----------------------------------------------------------------------------------------

def wav16(samples, rate=8000, channels=1) -> bytes:
    """16-bit PCM WAV; `samples` is (frames,) or (frames, channels) of ints."""
    arr = np.clip(np.asarray(samples), -32768, 32767).astype("<i2")
    body = arr.tobytes()
    fmt = struct.pack("<HHIIHH", 1, channels, rate, rate * 2 * channels, 2 * channels, 16)
    chunks = b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", len(body)) + body
    if len(body) & 1:
        chunks += b"\x00"
    return b"RIFF" + struct.pack("<I", 4 + len(chunks)) + b"WAVE" + chunks


def cover(frames, seed=1, amp=6000.0, tones=True) -> np.ndarray:
    """A float cover: band-limited noise plus a few tones (not white, so the readers face some colour)."""
    rng = np.random.default_rng(seed)
    x = rng.standard_normal(frames) * amp
    if tones:
        t = np.arange(frames)
        x += 0.5 * amp * np.sin(2 * math.pi * 0.0137 * t) + 0.3 * amp * np.sin(2 * math.pi * 0.071 * t + 1.0)
    return x


def dsss_embed(x: np.ndarray, bits, chips, spc, alpha) -> np.ndarray:
    """Additive DSSS: bit b over one symbol adds alpha * (+1 if b else -1) * the PN repeated spc times."""
    pn = np.repeat(np.asarray(chips, dtype=np.float64), spc)
    L = len(pn)
    y = x.copy()
    for i, b in enumerate(bits):
        y[i * L:(i + 1) * L] += alpha * (1 if b else -1) * pn
    return y


def echo_embed(x: np.ndarray, bits, window, d0, d1, alpha=0.6) -> np.ndarray:
    """Classic echo hiding: window i gets x[n - d] * alpha added, d = d1 for a 1 bit, d0 for a 0."""
    y = x.copy()
    for i, b in enumerate(bits):
        d = d1 if b else d0
        lo, hi = i * window, (i + 1) * window
        src = np.arange(lo, hi) - d
        ok = src >= 0
        y[lo:hi][ok] += alpha * x[src[ok]]
    return y


def phase_embed(x: np.ndarray, bits, L, place="low", jitter=None) -> np.ndarray:
    """Bender phase coding: the first L-sample segment's bins carry +pi/2 (0) / -pi/2 (1); later
    segments keep their original phase differences. place 'low' uses bins 1..m, 'high' the m bins
    just below Nyquist. jitter {i: delta} moves the phase of the i-th message bin by delta radians
    (a sloppy embedder or a lossy step: the sign, and so the bit, survives a small delta)."""
    n = len(x) // L
    segs = x[:n * L].reshape(n, L)
    F = np.fft.rfft(segs, axis=1)
    A, P = np.abs(F), np.angle(F)
    dP = np.diff(P, axis=0)
    m = len(bits)
    data = np.array([-math.pi / 2 if b else math.pi / 2 for b in bits])
    for i, delta in (jitter or {}).items():
        data[i] += delta
    P0 = P[0].copy()
    if place == "low":
        P0[1:1 + m] = data
    else:
        P0[L // 2 - m:L // 2] = data
    newP = np.empty_like(P)
    newP[0] = P0
    for k in range(1, n):
        newP[k] = newP[k - 1] + dP[k - 1]
    out = np.fft.irfft(A * np.exp(1j * newP), n=L, axis=1).ravel()
    return np.concatenate([out, x[n * L:]])


def parity_embed(ints: np.ndarray, bits, region) -> np.ndarray:
    """Parity coding: flip the LSB of a region's first sample when the region parity is not the bit."""
    y = ints.copy()
    for i, b in enumerate(bits):
        r = y[i * region:(i + 1) * region]
        if (int(np.sum(r & 1)) & 1) != b:
            r[0] ^= 1
    return y


# ---- palette images ------------------------------------------------------------------------------

def palette_png(indices: np.ndarray, palette: list[tuple[int, int, int]]) -> bytes:
    """A mode-P PNG with exactly this palette (PLTE length = len(palette))."""
    from PIL import Image
    h, w = indices.shape
    im = Image.frombytes("P", (w, h), indices.astype(np.uint8).tobytes())
    flat = [c for rgb in palette for c in rgb]
    im.putpalette(flat, rawmode="RGB")
    out = io.BytesIO()
    im.save(out, "PNG", optimize=False)
    return out.getvalue()


def palette_gif(indices: np.ndarray, palette: list[tuple[int, int, int]]) -> bytes:
    from PIL import Image
    h, w = indices.shape
    im = Image.frombytes("P", (w, h), indices.astype(np.uint8).tobytes())
    im.putpalette([c for rgb in palette for c in rgb], rawmode="RGB")
    out = io.BytesIO()
    im.save(out, "GIF", optimize=False)
    return out.getvalue()


def palette_bmp8(indices: np.ndarray, palette: list[tuple[int, int, int]]) -> bytes:
    """An uncompressed 8-bit BMP written by hand (bottom-up rows, BGR0 colour table)."""
    h, w = indices.shape
    stride = (w + 3) & ~3
    table = b"".join(bytes((b, g, r, 0)) for r, g, b in palette)
    pix = bytearray()
    for y in range(h - 1, -1, -1):
        pix += bytes(indices[y].astype(np.uint8)) + b"\x00" * (stride - w)
    off = 14 + 40 + len(table)
    hdr = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 8, 0, len(pix), 2835, 2835, len(palette), 0)
    return b"BM" + struct.pack("<IHHI", off + len(pix), 0, 0, off) + hdr + table + bytes(pix)


def luma(rgb) -> float:
    r, g, b = rgb
    return 0.299 * r + 0.587 * g + 0.114 * b


def ezstego_embed(indices: np.ndarray, palette, bits) -> np.ndarray:
    """EzStego: sort the palette by luminance; each pixel's colour moves to the neighbour in sorted
    order (2k <-> 2k+1) whose sorted rank has the message bit as LSB."""
    order = sorted(range(len(palette)), key=lambda i: (luma(palette[i]), i))
    rank = {idx: r for r, idx in enumerate(order)}
    flat = indices.reshape(-1).copy()
    for i, b in enumerate(bits):
        r = rank[int(flat[i])]
        if (r & 1) != b:
            r ^= 1
        flat[i] = order[r]
    return flat.reshape(indices.shape)


def factorial_permutation(number: int, n: int) -> list[int]:
    """The Lehmer-code permutation of 0..n-1 for `number` (most significant digit first): perm[i] is
    the sorted rank placed at palette position i."""
    digits = []
    for i in range(n):
        f = math.factorial(n - 1 - i)
        digits.append(number // f)
        number %= f
    pool = list(range(n))
    return [pool.pop(d) for d in digits]


def insertion_permutation(number: int, n: int) -> list[int]:
    """Gifshuffle-style insertion: sorted colour r is inserted at position (number mod (r+1)) of the
    list built so far, then number //= r+1. Returns the final list of sorted ranks by position."""
    out: list[int] = []
    for r in range(n):
        pos = number % (r + 1)
        number //= r + 1
        out.insert(pos, r)
    return out


# ---- a tiny baseline JPEG writer (standard Annex K Huffman tables, explicit coefficients) -----------

_BITS_DC = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
_VALS_DC = list(range(12))
_BITS_AC = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d]
_VALS_AC = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa]


def _enc_map(bits, vals):
    code, k, out = 0, 0, {}
    for length in range(1, 17):
        for _ in range(bits[length - 1]):
            out[vals[k]] = (code, length)
            code += 1
            k += 1
        code <<= 1
    return out


_DC = _enc_map(_BITS_DC, _VALS_DC)
_AC = _enc_map(_BITS_AC, _VALS_AC)


class _BitWriter:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, code, length):
        for i in range(length - 1, -1, -1):
            self.acc = (self.acc << 1) | ((code >> i) & 1)
            self.n += 1
            if self.n == 8:
                self.out.append(self.acc)
                if self.acc == 0xFF:
                    self.out.append(0)
                self.acc = self.n = 0

    def flush(self):
        while self.n:
            self.put(1, 1)


def _size(v):
    v = abs(v)
    s = 0
    while v:
        s += 1
        v >>= 1
    return s


def _mant(v, s):
    return v if v >= 0 else v + (1 << s) - 1


def _seg(marker, body):
    return bytes((0xFF, marker)) + struct.pack(">H", len(body) + 2) + body


ZIGZAG = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
          13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52,
          45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63]   # zigzag index -> natural (row-major) index


def jpeg_from_blocks(blocks, W, H, ncomp=1, qtables=None, sampling=None):
    """A baseline JPEG from explicit quantised blocks in ZIGZAG order (64 ints each, DC absolute).
    ncomp 1 (grayscale) or 3 (interleaved per MCU: `blocks` is in decode order). sampling: (h, v) per
    component, default 1x1 each (4:4:4); [(2, 2), (1, 1), (1, 1)] is 4:2:0, whose MCU holds four Y
    blocks (row by row) then Cb then Cr. One Huffman table pair for every component. qtables: list of
    64-int tables (8-bit), default all ones."""
    qtables = qtables or [[1] * 64]
    sampling = sampling or [(1, 1)] * ncomp
    pattern = [c for c, (h, v) in enumerate(sampling) for _ in range(h * v)]
    bw = _BitWriter()
    preds = [0] * ncomp
    for i, blk in enumerate(blocks):
        c = pattern[i % len(pattern)]
        diff = blk[0] - preds[c]
        preds[c] = blk[0]
        s = _size(diff)
        bw.put(*_DC[s])
        if s:
            bw.put(_mant(diff, s), s)
        ac = blk[1:]
        last = max((j for j, v in enumerate(ac) if v), default=-1)
        run = 0
        for j in range(last + 1):
            v = ac[j]
            if v == 0:
                run += 1
                continue
            while run > 15:
                bw.put(*_AC[0xF0])
                run -= 16
            sz = _size(v)
            bw.put(*_AC[(run << 4) | sz])
            bw.put(_mant(v, sz), sz)
            run = 0
        if last < 62:
            bw.put(*_AC[0x00])
    bw.flush()
    out = bytearray(b"\xFF\xD8")
    for t, table in enumerate(qtables):
        out += _seg(0xDB, bytes([t]) + bytes(table))
    comps = b"".join(struct.pack(">BBB", c + 1, (sampling[c][0] << 4) | sampling[c][1], min(c, len(qtables) - 1))
                     for c in range(ncomp))
    out += _seg(0xC0, struct.pack(">BHHB", 8, H, W, ncomp) + comps)
    out += _seg(0xC4, bytes([0x00]) + bytes(_BITS_DC) + bytes(_VALS_DC))
    out += _seg(0xC4, bytes([0x10]) + bytes(_BITS_AC) + bytes(_VALS_AC))
    sos = b"".join(struct.pack(">BB", c + 1, 0x00) for c in range(ncomp))
    out += _seg(0xDA, bytes([ncomp]) + sos + bytes([0, 63, 0]))
    out += bw.out
    out += b"\xFF\xD9"
    return bytes(out)


def random_blocks(nblocks, rng, lo=-20, hi=20):
    """Cover blocks: every coefficient random in lo..hi (dense, so every reading rule has carriers)."""
    return [[int(v) for v in rng.integers(lo, hi + 1, size=64)] for _ in range(nblocks)]
