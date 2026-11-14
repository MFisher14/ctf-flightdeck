#!/usr/bin/env python3
"""JPEG DCT readings the coefficient survey does not make (B-245, coverage-matrix row F8). Offline;
numpy and jpeg_stego's baseline decoder; nothing is executed.

jpeg_stego.coefficient_survey reads each rule (jsteg, non-zero, AC-only, F5 un-permuted, every) in
DECODE order: block after block as the entropy coder emits them, the 64 coefficients of a block in
zigzag order. f5_stego adds F5 matrix decoding in that order. A re-implementation that loads the
coefficients with a library (jpegio, jpeglib, libjpeg's coefficient arrays) sees them differently, and
writes its message in that order. This module reads those orders, plus the channels nobody read:

  orders   decode     the decode order (only for the new rules below)
           natural    decode order of blocks, each block row by row (8x8 natural order, not zigzag)
           plane      the coefficient PLANE of each component as a library returns it: an
                      (8 * blocks high) x (8 * blocks wide) array, block (by, bx) at rows 8by.., columns
                      8bx.., natural order inside; read row by row ('plane') and column by column
                      ('plane_cols'); components one after another (Y, then Cb, then Cr)
           compmajor  decode order, but every Y block first, then Cb, then Cr
  rules    jsteg, nonzero, ac_nonzero, f4 (parity with negative values inverted), every: as in
           jpeg_stego, in the orders above
           sign       the sign of each non-zero AC coefficient (1 = negative), every order
           dc         the LSB of each block's DC coefficient, every order of blocks
  f5       F5 matrix decoding (k = 1..7, f5_stego.matrix_decode) of the f4 stream in the natural and
           plane orders
  dqt      the quantisation tables: the LSB of each entry, and the entries themselves as bytes

Never-wrong: every reading goes through _carrier_judge (stego_containers.validate_container plus
jpeg_stego._provable). PLAIN only on a stored length + CRC-32 or a checksum-carrying gzip/zip, and only
when it is the one distinct proven payload of this survey; jpeg_stego.survey runs this module only when
its own readings proved nothing, so a payload two modules read alike is not counted twice. Only a
complete file structure is offered as a candidate: with this many orders, a printable start or a
too-short checksum match turns up in clean flat or gradient images, which must give no candidate.

DECLINED, said out loud: keyed JPEG embedders (OutGuess, JPHide, steghide, F5 with a password, nsF5
and other wet-paper codes) need the key's PRNG walk and are not read here (stego_tools runs the
steghide/outguess binaries in the sandbox); progressive JPEGs are declined by the decoder.

Bounded: coefficients decoded, bytes per reading, and an optional deadline checked between readings.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))

import _carrier_judge as cj          # noqa: E402
import f5_stego as f5                # noqa: E402
import jpeg_stego as js              # noqa: E402

MAX_COEFFS = 1 << 21                 # coefficients decoded (32768 blocks)
READING_BYTES = 1 << 14              # bytes per reading judged
F5_KS = tuple(range(1, 8))

# zigzag index -> natural (row-major) index within an 8x8 block
ZIGZAG = np.array([0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27,
                   20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58,
                   59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63], dtype=np.intp)
COMP_NAMES = ("Y", "Cb", "Cr", "C3")


class JpegF8Error(ValueError):
    """A parameter a caller gave is out of range (never raised for a bad JPEG: that is a note)."""


# ---- the coefficient layouts ------------------------------------------------------------------------

def decode_blocks(data: bytes):
    """(blocks (n, 64) int64 in zigzag order, tags (n,) component index, frame) of a baseline JPEG.
    Raises js._Unsupported for a shape the decoder declines."""
    tags = []
    coeffs = js._decode_coeffs(bytes(data), limit_bits=MAX_COEFFS, comp_out=tags)
    n = min(len(coeffs) // 64, len(tags))
    frame, _scan, _off = js._parse(bytes(data))
    blocks = np.asarray(coeffs[:n * 64], dtype=np.int64).reshape(n, 64)
    return blocks, np.asarray(tags[:n], dtype=np.int64), frame


def to_natural(blocks: np.ndarray) -> np.ndarray:
    """Zigzag-ordered blocks to natural (row-major 8x8) order."""
    out = np.empty_like(blocks)
    out[:, ZIGZAG] = blocks
    return out


def block_grid(frame: dict, comp: int, nblocks_seen: int):
    """[(block row, block column)] of component `comp`'s blocks in decode order (interleaved MCUs:
    each MCU holds h x v blocks of the component, row by row), and the component's size in blocks as
    libjpeg reports it (width_in_blocks = ceil(ceil(W * h / hmax) / 8))."""
    comps = frame["comps"]
    hmax = max(c["h"] for c in comps)
    vmax = max(c["v"] for c in comps)
    c = comps[comp]
    mcu_x = (frame["w"] + 8 * hmax - 1) // (8 * hmax)
    if len(comps) == 1:
        h = v = 1
        mcu_x = (frame["w"] + 7) // 8
    else:
        h, v = c["h"], c["v"]
    out = []
    m = 0
    while len(out) < nblocks_seen:
        mx, my = m % mcu_x, m // mcu_x
        for bv in range(v):
            for bh in range(h):
                out.append((my * v + bv, mx * h + bh))
        m += 1
    cw = -(-frame["w"] * (c["h"] if len(comps) > 1 else 1) // (hmax if len(comps) > 1 else 1))
    ch = -(-frame["h"] * (c["v"] if len(comps) > 1 else 1) // (vmax if len(comps) > 1 else 1))
    return out[:nblocks_seen], (-(-ch // 8), -(-cw // 8))


def coefficient_plane(natural: np.ndarray, grid, size) -> np.ndarray:
    """A component's coefficient plane (8 * rows, 8 * cols) from its natural-order blocks; blocks
    outside libjpeg's width/height in blocks (MCU padding) are dropped, as a library drops them."""
    rows, cols = size
    plane = np.zeros((rows * 8, cols * 8), dtype=np.int64)
    filled = np.zeros((rows, cols), dtype=bool)
    for blk, (by, bx) in zip(natural, grid):
        if by < rows and bx < cols:
            plane[by * 8:by * 8 + 8, bx * 8:bx * 8 + 8] = blk.reshape(8, 8)
            filled[by, bx] = True
    if not filled.all():
        last = np.flatnonzero(filled.any(axis=1))
        rows_used = int(last[-1]) + 1 if len(last) else 0
        plane = plane[:rows_used * 8]
    return plane


def dc_mask_plane(shape) -> np.ndarray:
    r = (np.arange(shape[0]) % 8 == 0)[:, None]
    c = (np.arange(shape[1]) % 8 == 0)[None, :]
    return r & c


# ---- the rules ----------------------------------------------------------------------------------------

def rule_bits(values: np.ndarray, is_dc: np.ndarray, rule: str) -> np.ndarray:
    """The bits `rule` picks from a coefficient sequence (both 1-D, same length), in order."""
    v = values
    if rule == "jsteg":
        take = (v != 0) & (v != 1)
        bit = v & 1
    elif rule == "nonzero":
        take = v != 0
        bit = v & 1
    elif rule == "ac_nonzero":
        take = ~is_dc & (v != 0)
        bit = v & 1
    elif rule == "f4":
        take = ~is_dc & (v != 0)
        bit = np.where(v > 0, v & 1, 1 - (v & 1))
    elif rule == "every":
        take = np.ones(len(v), dtype=bool)
        bit = v & 1
    elif rule == "sign":
        take = ~is_dc & (v != 0)
        bit = (v < 0).astype(np.int64)
    else:
        raise JpegF8Error(f"unknown rule {rule!r}")
    return bit[take].astype(np.uint8)


OLD_RULES = ("jsteg", "nonzero", "ac_nonzero", "f4", "every")     # read in decode order by jpeg_stego
NEW_RULES = ("sign",)


def _cap(bits: np.ndarray) -> np.ndarray:
    return bits[:READING_BYTES * 8]


def orders(blocks: np.ndarray, tags: np.ndarray, frame: dict):
    """[(name, values, is_dc, rules)] of every coefficient order read, with the rules new to it."""
    nat = to_natural(blocks)
    comps = sorted(set(int(t) for t in tags))
    zz_dc = np.zeros(64, dtype=bool)
    zz_dc[0] = True
    out = []
    # decode order: only the rules jpeg_stego does not read there
    out.append(("decode all", blocks.reshape(-1), np.tile(zz_dc, len(blocks)), NEW_RULES))
    # natural order inside each block, blocks in decode order
    out.append(("natural all", nat.reshape(-1), np.tile(zz_dc, len(nat)), OLD_RULES + NEW_RULES))
    # component-major decode order (only differs from decode order with more than one component)
    if len(comps) > 1:
        order = np.argsort(tags, kind="stable")
        cm = blocks[order]
        out.append(("compmajor", cm.reshape(-1), np.tile(zz_dc, len(cm)), OLD_RULES + NEW_RULES))
    # the coefficient planes
    planes = []
    for comp in comps:
        sel = np.flatnonzero(tags == comp)
        grid, size = block_grid(frame, comp, len(sel))
        planes.append((comp, coefficient_plane(nat[sel], grid, size)))
    for direction in ("plane", "plane_cols"):
        vals, dcs = [], []
        for comp, plane in planes:
            p = plane if direction == "plane" else plane.T
            mask = dc_mask_plane(plane.shape)
            m = mask if direction == "plane" else mask.T
            vals.append(p.reshape(-1))
            dcs.append(m.reshape(-1))
            if len(planes) > 1:
                out.append((f"{direction} {COMP_NAMES[min(comp, 3)]}", p.reshape(-1), m.reshape(-1),
                            OLD_RULES + NEW_RULES))
        out.append((f"{direction} all", np.concatenate(vals), np.concatenate(dcs), OLD_RULES + NEW_RULES))
    return out


def dc_streams(blocks: np.ndarray, tags: np.ndarray):
    out = [("dc decode", blocks[:, 0] & 1)]
    if len(set(tags.tolist())) > 1:
        out.append(("dc compmajor", blocks[np.argsort(tags, kind="stable"), 0] & 1))
        out.append(("dc Y", blocks[tags == 0, 0] & 1))
    return out


def dqt_tables(data: bytes):
    """[(table id, [64 values in stored (zigzag) order])] of every DQT segment before the scan."""
    out = []
    i, n = 2, len(data)
    while i + 4 <= n and data[i] == 0xFF:
        m = data[i + 1]
        if m == 0xDA or m == 0xD9:
            break
        ln = struct.unpack_from(">H", data, i + 2)[0]
        seg = data[i + 4:i + 2 + ln]
        if m == 0xDB:
            off = 0
            while off < len(seg):
                pq, tq = seg[off] >> 4, seg[off] & 15
                width = 2 if pq else 1
                vals = seg[off + 1:off + 1 + 64 * width]
                if len(vals) < 64 * width:
                    break
                table = list(struct.unpack(">64H", vals)) if pq else list(vals)
                out.append((tq, table))
                off += 1 + 64 * width
        i += 2 + ln
    return out


# ---- the survey ---------------------------------------------------------------------------------------

def survey(data, *, deadline=None) -> dict:
    """Every F8 reading of one baseline JPEG. {plain, method, channel: 'jpeg-f8', candidates, readings,
    notes, judged}; plain only through _carrier_judge."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise JpegF8Error("data must be bytes")
    data = bytes(data)
    S = cj.Survey("jpeg-f8", files_only=True)
    if data[:2] != b"\xff\xd8":
        S.notes.append("not a JPEG")
        return S.result()
    tables = dqt_tables(data)
    if tables:
        lsb = np.concatenate([np.asarray(t, dtype=np.int64) & 1 for _, t in tables])
        S.judge_bits(lsb, "dqt lsb")
        raw = b"".join(bytes(v & 0xFF for v in t) for _, t in tables)
        S.judge(raw, "dqt bytes")
    try:
        blocks, tags, frame = decode_blocks(data)
    except js._Unsupported as e:
        S.notes.append(f"coefficient domain not read: {e}")
        return S.result()
    except Exception as e:                          # a hostile file: say so, read nothing
        S.notes.append(f"coefficient domain not read: {type(e).__name__}")
        return S.result()
    if len(blocks) < 1:
        S.notes.append("no decodable DCT blocks")
        return S.result()
    S.notes.append(f"{len(blocks)} blocks, components {sorted(set(tags.tolist()))}, "
                   f"{frame['w']}x{frame['h']}")
    for name, bits in dc_streams(blocks, tags):
        S.judge_bits(_cap(bits.astype(np.uint8)), name)
    try:
        layouts = orders(blocks, tags, frame)
    except (ValueError, IndexError, KeyError) as e:  # a frame shape the layout code does not expect: say
        # so. Only the shape errors of the reshape / grid / frame lookups are caught; any other
        # exception is a bug in this module and propagates
        S.notes.append(f"coefficient orders not read: {type(e).__name__}: {e}")
        return S.result()
    for name, values, is_dc, rules in layouts:
        for rule in rules:
            if deadline is not None and time.monotonic() > deadline:
                S.notes.append("jpeg-f8: out of time")
                return S.result()
            S.judge_bits(_cap(rule_bits(values, is_dc, rule)), f"{name} {rule}")
            if rule == "f4" and name.endswith("all") and not name.startswith("decode"):
                carriers = rule_bits(values, is_dc, "f4")[:f5.MAX_CARRIERS].tolist()
                for k in F5_KS:
                    blob = f5.matrix_decode(carriers, k, 0, max_bytes=READING_BYTES)
                    S.judge(blob, f"{name} f5 k{k} msb-first")
    return S.result()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="jpeg_stego_f8.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    a = ap.parse_args(argv)
    rc = 0
    for path in a.files:
        try:
            res = survey(path.read_bytes())
        except (OSError, JpegF8Error) as e:
            print(f"jpeg_stego_f8.py: {path}: {e}", file=sys.stderr)
            rc = 2
            continue
        print(json.dumps({"input": str(path), **cj.jsonable(res)}, sort_keys=True))
    return rc


__all__ = ["JpegF8Error", "decode_blocks", "to_natural", "block_grid", "coefficient_plane", "rule_bits",
           "orders", "dc_streams", "dqt_tables", "survey", "ZIGZAG"]


if __name__ == "__main__":
    sys.exit(main())
