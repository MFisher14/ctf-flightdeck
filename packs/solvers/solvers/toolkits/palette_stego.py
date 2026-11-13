#!/usr/bin/env python3
"""Palette-image stego carriers (B-245): the palette-order channel and the palette readings the LSB
battery does not make. Offline; numpy and carve_stego's PNG/GIF/BMP readers; nothing is executed.

carve_stego reads a palette image's INDEX bit planes (zsteg's b1,p); steganalysis skips paletted
images. A palette image carries more than its index LSBs: the colour each index NAMES and the ORDER of
the colour table are channels too. This module reads, for a PNG (colour type 3), a GIF (first frame;
its local colour table when it has one, else the global one) and an 8-bit BMP:

  index       the LSB of each pixel's palette index (the baseline, so a survey stands alone)
  ezstego     EzStego (Machado): the palette is sorted (by luminance; also by RGB value and by
              R+G+B), and each pixel's bit is the LSB of its colour's RANK in that order, so a bit flip
              moves a pixel only to the visually nearest colour
  parity      Fridrich's palette parity: each pixel's bit is (R + G + B) mod 2 of the colour it names
  table_lsb   the LSBs of the colour table bytes themselves (R G B of entry 0, then entry 1, ...; and
              per channel R..., G..., B...)
  order       the palette ORDER (gifshuffle-style): the table is a permutation of the colours sorted
              by a canonical key (RGB value, luminance); the permutation is a number in the
              factorial number system (Lehmer code) or built by successive insertion (gifshuffle), and
              the number is the message, read big-endian with and without a leading marker bit

Pixels are scanned row by row (top-down; a BMP also in its stored bottom-up order) and column by
column. Bounded: pixels read, bits per reading, palette size (256).

Never-wrong: every reading goes through _carrier_judge (stego_containers.validate_container plus
jpeg_stego._provable). PLAIN only on a stored length + CRC-32 or a checksum-carrying gzip/zip, and only
when it is the one distinct proven payload of the survey; a printable or structure-only reading is a
candidate. A palette with repeated colours makes a sort order ambiguous (ties are broken by index,
which an embedder may not do): the survey says so in a note.

DECLINED, said out loud: a palette-order or EzStego embedding keyed by a password (a seeded walk over
the pixels, an encrypted number) is not read; gifshuffle's optional compression and ICE encryption
are not undone (a compressed payload that is gzip still validates).
"""
from __future__ import annotations

import argparse
import json
import math
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))

import _carrier_judge as cj          # noqa: E402
import carve_stego as cs             # noqa: E402

MAX_PIXEL_BITS = 1 << 18             # bits taken from a pixel scan per reading
MAX_PALETTE = 256
ORDER_MIN_COLOURS = 8                # a permutation of fewer colours carries under 2 bytes


class PaletteStegoError(ValueError):
    """A parameter a caller gave is out of range (never raised for a bad image: that is a note)."""


@dataclass
class PaletteImage:
    kind: str                        # png | gif | bmp
    indices: np.ndarray              # (height, width) uint8, top-down
    palette: list                    # [(r, g, b)] as stored, its real length
    stored_bottom_up: bool = False   # a BMP's rows are stored bottom-up

    @property
    def colours(self) -> int:
        return len(self.palette)


# ---- readers ---------------------------------------------------------------------------------------

def _triples(raw: bytes, step: int = 3, order=(0, 1, 2)) -> list:
    n = min(len(raw) // step, MAX_PALETTE)
    return [tuple(raw[i * step + o] for o in order) for i in range(n)]


def _gif_table(data: bytes):
    """The colour table frame 0 is drawn with: its local table when it has one, else the global one."""
    if len(data) < 13:
        return None
    flags = data[10]
    pos = 13
    table = None
    if flags & 0x80:
        size = 3 << ((flags & 7) + 1)
        table = data[pos:pos + size]
        pos += size
    while pos < len(data):
        b = data[pos]
        if b == 0x21:                                   # extension: label, then sub-blocks
            pos += 2
            while pos < len(data) and data[pos]:
                pos += 1 + data[pos]
            pos += 1
        elif b == 0x2C:                                 # image descriptor
            if pos + 10 > len(data):
                return table
            lflags = data[pos + 9]
            if lflags & 0x80:
                size = 3 << ((lflags & 7) + 1)
                return data[pos + 10:pos + 10 + size]
            return table
        else:
            return table
    return table


def load_palette_image(data: bytes) -> PaletteImage | None:
    """A palette image's indices and colour table, or None (not a palette PNG/GIF/8-bit BMP, or one
    the carve_stego readers do not decode)."""
    kind = cs.sniff(data)
    if kind == "png":
        px = cs.png_pixels(data)
        if not px or px["mode"] != "P":
            return None
        plte = next((c["data"] for c in cs.png_chunks(data) if c["type"] == "PLTE"), None)
        if not plte:
            return None
        palette = _triples(plte)
        bottom_up = False
    elif kind == "gif":
        px = cs.gif_pixels(data)
        table = _gif_table(data)
        if not px or not table:
            return None
        palette = _triples(table)
        bottom_up = False
    elif kind == "bmp":
        px = cs.bmp_pixels(data)
        if not px or px["mode"] != "P":
            return None
        hdr = struct.unpack_from("<I", data, 14)[0]
        used = struct.unpack_from("<I", data, 46)[0] if hdr >= 40 else 0
        count = used or 256
        start = 14 + hdr
        palette = _triples(data[start:start + 4 * count], step=4, order=(2, 1, 0))
        bottom_up = bool(px.get("bottom_up"))
    else:
        return None
    w, h = px["width"], px["height"]
    body = np.frombuffer(px["data"], dtype=np.uint8, count=w * h).reshape(h, w)
    if bottom_up:
        body = body[::-1]
    if not palette:
        return None
    return PaletteImage(kind, body.copy(), palette, bottom_up)


# ---- the readings ----------------------------------------------------------------------------------

def luma(rgb) -> float:
    r, g, b = rgb
    return 0.299 * r + 0.587 * g + 0.114 * b


SORT_KEYS = (
    ("luma", lambda c: luma(c)),
    ("rgb", lambda c: (c[0] << 16) | (c[1] << 8) | c[2]),
    ("sum", lambda c: c[0] + c[1] + c[2]),
)


def sort_order(palette, key) -> list:
    """Palette indices in ascending `key` order, ties broken by index."""
    return sorted(range(len(palette)), key=lambda i: (key(palette[i]), i))


def scans(img: PaletteImage):
    """[(name, flat index array)] in the scan orders read."""
    out = [("rows", img.indices.reshape(-1))]
    if img.stored_bottom_up:
        out.append(("stored", img.indices[::-1].reshape(-1)))
    out.append(("columns", img.indices.T.reshape(-1)))
    return [(n, a[:MAX_PIXEL_BITS]) for n, a in out]


def index_bits(flat: np.ndarray, lut: np.ndarray) -> np.ndarray:
    """One bit per pixel through a 256-entry lookup table (index -> bit)."""
    return lut[flat.astype(np.intp)].astype(np.uint8)


def ezstego_lut(palette, key) -> np.ndarray:
    lut = np.zeros(256, np.uint8)
    for rank, idx in enumerate(sort_order(palette, key)):
        lut[idx] = rank & 1
    return lut


def parity_lut(palette) -> np.ndarray:
    lut = np.zeros(256, np.uint8)
    for i, (r, g, b) in enumerate(palette):
        lut[i] = (r + g + b) & 1
    return lut


def table_lsb_streams(palette):
    """[(name, bits)] of the colour table's own LSBs: interleaved RGB, then channel by channel."""
    arr = np.asarray(palette, dtype=np.uint8).reshape(-1, 3) & 1
    return [("rgb", arr.reshape(-1)), ("planar", arr.T.reshape(-1))]


def permutation_of(palette, key) -> list | None:
    """perm[i] = the sorted rank of the colour at palette position i, or None when colours repeat."""
    if len(set(palette)) != len(palette):
        return None
    order = sort_order(palette, key)
    rank = {idx: r for r, idx in enumerate(order)}
    return [rank[i] for i in range(len(palette))]


def lehmer_number(perm) -> int:
    """The permutation's rank in the factorial number system, most significant digit first."""
    n = len(perm)
    pool = list(range(n))
    number = 0
    for i, p in enumerate(perm):
        d = pool.index(p)
        pool.pop(d)
        number = number * (n - i) + d
    return number


def insertion_number(perm) -> int:
    """The number a successive-insertion encoder (gifshuffle style) used: rank r was inserted at
    position (number mod (r + 1)) of the list built from ranks 0 .. r-1, then number //= r + 1."""
    positions = []
    current = list(perm)
    for r in range(len(perm) - 1, -1, -1):
        pos = current.index(r)
        positions.append(pos)
        current.pop(pos)
    positions.reverse()                                 # positions[r]: where rank r went
    number = 0
    for r in range(len(perm) - 1, -1, -1):
        number = number * (r + 1) + positions[r]
    return number


def inverse(perm) -> list:
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def number_readings(number: int, colours: int):
    """[(name, bytes)] the number may be: big-endian at its own length and padded with leading zero
    bytes up to the permutation's capacity, little-endian, and with a leading marker bit stripped."""
    out = []
    if number <= 0:
        return out
    capacity = max(1, int(math.lgamma(colours + 1) / math.log(2)) // 8)
    nbytes = (number.bit_length() + 7) // 8
    for size in sorted({nbytes, *range(nbytes + 1, min(capacity, nbytes + 4) + 1), capacity}):
        if size >= nbytes:
            out.append((f"be{size}", number.to_bytes(size, "big")))
    out.append(("le", number.to_bytes(nbytes, "little")))
    top = number.bit_length() - 1
    if top >= 8:
        rest = number ^ (1 << top)
        out.append(("marker", rest.to_bytes((top + 7) // 8, "big")))
    return out


def order_read(img: PaletteImage, S: cj.Survey):
    if img.colours < ORDER_MIN_COLOURS:
        S.notes.append(f"order: {img.colours} colours carry under 2 bytes; not read")
        return
    for kname, key in SORT_KEYS:
        perm = permutation_of(img.palette, key)
        if perm is None:
            S.notes.append("order: the palette repeats a colour, so its order is not a permutation of "
                           "distinct colours; not read")
            return
        if perm == list(range(len(perm))):
            S.notes.append(f"order by {kname}: the palette is already sorted (identity: no message)")
            continue
        for pname, p in (("perm", perm), ("inverse", inverse(perm))):
            for ename, number in (("lehmer", lehmer_number(p)), ("insertion", insertion_number(p))):
                for rname, blob in number_readings(number, img.colours):
                    S.judge(blob, f"order {kname} {pname} {ename} {rname}")


def survey(data, *, deadline=None) -> dict:
    """Every palette reading of one image. {plain, method, channel: 'palette', candidates, readings,
    notes, judged}; plain only through _carrier_judge."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise PaletteStegoError("data must be bytes")
    S = cj.Survey("palette")
    img = load_palette_image(bytes(data))
    if img is None:
        S.notes.append("not a palette image this reader decodes (PNG colour type 3, GIF, 8-bit BMP)")
        return S.result()
    h, w = img.indices.shape
    S.notes.append(f"{img.kind}: {w}x{h}, {img.colours} colours")
    if len(set(img.palette)) != img.colours:
        S.notes.append("the palette repeats a colour: sort orders break ties by index")
    luts = [("index", np.arange(256, dtype=np.int64) & 1)]
    luts += [(f"ezstego {k}", ezstego_lut(img.palette, key)) for k, key in SORT_KEYS]
    luts.append(("parity", parity_lut(img.palette)))
    for lname, lut in luts:
        for sname, flat in scans(img):
            if deadline is not None and time.monotonic() > deadline:
                S.notes.append("palette: out of time")
                return S.result()
            S.judge_bits(index_bits(flat, lut), f"{lname} {sname}")
    for tname, bits in table_lsb_streams(img.palette):
        S.judge_bits(bits, f"table_lsb {tname}")
    order_read(img, S)
    return S.result()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="palette_stego.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    a = ap.parse_args(argv)
    rc = 0
    for path in a.files:
        try:
            res = survey(path.read_bytes())
        except (OSError, PaletteStegoError) as e:
            print(f"palette_stego.py: {path}: {e}", file=sys.stderr)
            rc = 2
            continue
        print(json.dumps({"input": str(path), **cj.jsonable(res)}, sort_keys=True))
    return rc


__all__ = ["PaletteImage", "PaletteStegoError", "load_palette_image", "sort_order", "ezstego_lut", "parity_lut",
           "table_lsb_streams", "permutation_of", "lehmer_number", "insertion_number", "number_readings",
           "order_read", "survey", "SORT_KEYS"]


if __name__ == "__main__":
    sys.exit(main())
