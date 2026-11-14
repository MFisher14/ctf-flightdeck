"""R-15: carve_stego's deep LSB readings (the CSCTF lsb_deep_scan) at the cost of the readings it joined.

The CSCTF port read snake orders, cross-plane XOR, channel arithmetic and adjacent-pixel parity one
pixel at a time in Python: 2-3 s CPU on a 480x480 picture, inside solve_set's one-second budget, so
the budget ran out, the reading was marked left out and the stg300 LSB flag went unanswered. The
readers now work on whole rows, columns and planes. These tests hold them to the per-pixel
definitions below (the spec, written out here pixel by pixel) and bound their CPU cost.
"""
from __future__ import annotations

import random
import struct
import sys
import time
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers/toolkits"))
import carve_stego as C  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from sh09_clocks import cost_not_run, work_seconds_unless_missing  # noqa: E402

ORDERS = ("xy", "yx", "column", "col", "row", "snake", "serpentine", "column_snake", "column-serpentine")


# ---- the per-pixel definitions --------------------------------------------------------------------

def ref_order(w, h, order):
    order = {"row": "xy", "column": "yx", "col": "yx", "serpentine": "snake",
             "column-serpentine": "column_snake"}.get(order, order)
    if order == "xy":
        return [y * w + x for y in range(h) for x in range(w)]
    if order == "yx":
        return [y * w + x for x in range(w) for y in range(h)]
    if order == "snake":
        return [y * w + x for y in range(h) for x in (range(w) if y % 2 == 0 else range(w - 1, -1, -1))]
    if order == "column_snake":
        return [y * w + x for x in range(w) for y in (range(h) if x % 2 == 0 else range(h - 1, -1, -1))]
    raise AssertionError(order)


def ref_samples(px, idx, order, limit):
    c = px["channels"]
    return bytes(px["data"][p * c + i] for p in ref_order(px["width"], px["height"], order) for i in idx)[:limit]


def ref_pack(bits, msb_first):
    out = bytearray()
    for k in range(0, len(bits) // 8 * 8, 8):
        group = bits[k:k + 8] if msb_first else bits[k:k + 8][::-1]
        out.append(int("".join(map(str, group)), 2))
    return bytes(out)


def ref_cross(px, ch, planes, order, msb, mb):
    s = ref_samples(px, [px["mode"].index(ch)], order, mb * 8)
    return ref_pack([sum((v >> p) & 1 for p in planes) % 2 for v in s], msb)


def ref_arith(px, left, right, op, bit, order, msb, mb):
    c, li, ri = px["channels"], px["mode"].index(left), px["mode"].index(right)
    f = {"xor": lambda a, b: a ^ b, "add": lambda a, b: (a + b) % 256,
         "sub": lambda a, b: (a - b) % 256, "absdiff": lambda a, b: abs(a - b)}[op]
    bits = [(f(px["data"][p * c + li], px["data"][p * c + ri]) >> bit) & 1
            for p in ref_order(px["width"], px["height"], order)]
    return ref_pack(bits[:mb * 8], msb)


def ref_parity(px, ch, order, overlap, invert, msb, mb):
    s = ref_samples(px, [px["mode"].index(ch)], order, min(px["width"] * px["height"], mb * 16 + 1))
    step = 1 if overlap else 2
    bits = [((s[i] + s[i + 1]) & 1) ^ int(invert) for i in range(0, len(s) - 1, step)]
    return ref_pack(bits[:mb * 8], msb)


def carrier(rng, mode, w, h, extra=0):
    return {"mode": mode, "channels": len(mode), "width": w, "height": h,
            "data": rng.randbytes(w * h * len(mode) + extra)}


CARRIERS = [(mode, w, h, extra) for mode in ("L", "LA", "RGB", "BGR", "RGBA")
            for w, h, extra in ((1, 1, 0), (1, 7, 0), (7, 1, 2), (5, 4, 0), (13, 9, 3), (16, 16, 0))]


# ---- the fast readers give the per-pixel definitions' bytes ---------------------------------------

@pytest.mark.parametrize("mode,w,h,extra", CARRIERS)
def test_selected_samples_follow_every_order_channel_by_channel(mode, w, h, extra):
    rng = random.Random(f"{mode}{w}{h}")
    px = carrier(rng, mode, w, h, extra)
    c = len(mode)
    for order in ORDERS:
        for idx in ([0], list(range(c)), list(range(c))[::-1], [c - 1, 0] if c > 1 else [0]):
            for limit in (1, 2, 3, w, w * h + 1, 10 ** 6):
                assert C._selected_samples(px, idx, order, limit) == ref_samples(px, idx, order, limit), (order, idx, limit)
        assert C._selected_samples(px, [0], order, 0) == b""
        assert C._selected_samples(px, [], order, 50) == b""


@pytest.mark.parametrize("mode,w,h,extra", CARRIERS)
def test_snake_and_column_lsb_extract_match_the_pixel_walk(mode, w, h, extra):
    rng = random.Random(f"lsb{mode}{w}{h}")
    px = carrier(rng, mode, w, h, extra)
    for order in ("snake", "column_snake", "serpentine"):
        for channels in (mode, mode[::-1], mode[0]):
            for bit in (0, 3, 7):
                for msb in (True, False):
                    for mb in (0, 1, 2, 64):
                        bits = [(v >> bit) & 1 for v in ref_samples(px, [mode.index(ch) for ch in channels], order, mb * 8)]
                        assert C.lsb_extract(px, channels, bit, order, msb, mb) == ref_pack(bits, msb), (order, channels, bit, msb, mb)


@pytest.mark.parametrize("mode,w,h,extra", CARRIERS)
def test_cross_plane_xor_matches_the_pixel_walk(mode, w, h, extra):
    rng = random.Random(f"x{mode}{w}{h}")
    px = carrier(rng, mode, w, h, extra)
    for order in ("xy", "snake", "column", "column_snake"):
        for planes in ((0, 1), (1, 2), (0, 7), (2, 5, 6), (0, 1, 2, 3, 4, 5, 6, 7)):
            for msb in (True, False):
                for mb in (0, 1, 3, 64):
                    ch = mode[-1]
                    assert C.cross_plane_xor_extract(px, ch, planes, order=order, msb_first=msb, max_bytes=mb) == \
                        ref_cross(px, ch, planes, order, msb, mb), (order, planes, msb, mb)


@pytest.mark.parametrize("mode,w,h,extra", [cr for cr in CARRIERS if len(cr[0]) >= 2])
def test_channel_arithmetic_matches_the_pixel_walk_for_every_operation_and_bit(mode, w, h, extra):
    rng = random.Random(f"a{mode}{w}{h}")
    px = carrier(rng, mode, w, h, extra)
    pairs = [(mode[0], mode[1]), (mode[1], mode[0]), (mode[-1], mode[0])]
    for order in ("xy", "snake", "column_snake"):
        for left, right in pairs:
            for op in ("xor", "add", "sub", "absdiff"):
                for bit in range(8):
                    for msb, mb in ((True, 64), (False, 64), (True, 1), (True, 0)):
                        assert C.channel_arithmetic_extract(px, left, right, op, bit=bit, order=order, msb_first=msb,
                                                            max_bytes=mb) == \
                            ref_arith(px, left, right, op, bit, order, msb, mb), (order, left, right, op, bit, msb, mb)


@pytest.mark.parametrize("mode,w,h,extra", CARRIERS)
def test_adjacent_parity_matches_the_pixel_walk(mode, w, h, extra):
    rng = random.Random(f"p{mode}{w}{h}")
    px = carrier(rng, mode, w, h, extra)
    for order in ("xy", "snake", "column"):
        for overlap in (False, True):
            for invert in (False, True):
                for msb in (True, False):
                    for mb in (0, 1, 2, 64):
                        ch = mode[0]
                        assert C.adjacent_pixel_parity_extract(px, ch, order=order, overlap=overlap, invert=invert,
                                                               msb_first=msb, max_bytes=mb) == \
                            ref_parity(px, ch, order, overlap, invert, msb, mb), (order, overlap, invert, msb, mb)


def test_bad_orders_and_carriers_still_fail_loudly():
    px = carrier(random.Random(1), "RGB", 4, 4)
    with pytest.raises(ValueError, match="order must be"):
        C._selected_samples(px, [0], "diagonal", 8)
    with pytest.raises(ValueError, match="order must be"):
        C.cross_plane_xor_extract(px, "R", (0, 1), order="zigzag")
    with pytest.raises(ValueError, match="truncated"):
        C._selected_samples({**px, "data": px["data"][:-1]}, [0], "snake", 8)
    with pytest.raises(ValueError, match="truncated"):
        C.channel_arithmetic_extract({**px, "data": px["data"][:-1]}, "R", "G")
    with pytest.raises(ValueError, match="invalid or over-cap"):
        C._selected_samples({**px, "width": 0, "data": b""}, [0], "xy", 8)
    with pytest.raises(ValueError, match="truncated"):
        C._selected_samples(px, [0], "xy", -1)


# ---- the cost, in CPU seconds (a loaded machine does not fail it) ---------------------------------

def _cpu(fn, *args, **kw):
    t0 = time.process_time()
    out = fn(*args, **kw)
    return out, time.process_time() - t0


FLAG = "4E34B38257200616FB75CD869B8C3CF0"
MESSAGE = f"Congrats\nYou win!\nThe\nFlag\nis\n{FLAG}\x00".encode()


def _photo_png_with_red_lsb_text(w=480, h=479):
    """A stg300-sized RGB picture (smooth gradients, the low two bits of every sample noise, as in a
    photograph; pure noise would mostly time the barcode reader) whose red channel's bit 0, row by
    row, MSB first, holds MESSAGE."""
    rng = random.Random(300)
    noise = rng.randbytes(w * h * 3)
    data = bytearray(w * h * 3)
    for y in range(h):
        for x in range(w):
            i = (y * w + x) * 3
            for k, v in enumerate((x * 255 // w, y * 255 // h, (x + y) * 255 // (w + h))):
                data[i + k] = (v & 0xFC) | (noise[i + k] & 3)
    bits = [(byte >> (7 - k)) & 1 for byte in MESSAGE for k in range(8)]
    for pixel, b in enumerate(bits):
        data[pixel * 3] = (data[pixel * 3] & 0xFE) | b

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    raw = b"".join(b"\x00" + bytes(data[y * w * 3:(y + 1) * w * 3]) for y in range(h))
    return (C.PNG_SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 1)) + chunk(b"IEND", b""))


def test_the_deep_scan_of_a_500x500_picture_costs_a_fraction_of_the_budget():
    px = carrier(random.Random(2), "RGB", 480, 479)
    hits, cpu = _cpu(C.lsb_deep_scan, px)
    assert hits == []                                   # noise: no reading is judged a payload
    # the per-pixel port took 2-3 s here; the whole-plane readers take well under a tenth of a second
    assert cpu < 0.4, f"lsb_deep_scan took {cpu:.2f} s CPU on 480x479 RGB"
    rgba = carrier(random.Random(3), "RGBA", 450, 600)  # cats.png's shape: two more channel sets
    _, cpu = _cpu(C.lsb_deep_scan, rgba)
    assert cpu < 0.5, f"lsb_deep_scan took {cpu:.2f} s CPU on 450x600 RGBA"


def test_the_stg300_shape_is_answered_by_its_pattern_inside_the_budget():
    """The lost flag: one set's whole reading (lsb_scan, the deep readings, the high planes, the codes)
    fits solve_set's budget, so nothing is marked left out and the pattern question is answered.

    The cost is work at the core's top clock (SH-09, tests/sh09_clocks.work_seconds): the budget is what the
    deadline gives on an idle machine, and under the suite's load this machine runs its cores at about half
    their top clock, so the same scan read 0.90 s of CPU in a full-suite run (0.45 s of work). Without the
    work meter (another chip) the answer checks still run and only the cost bounds are reported not run."""
    png = _photo_png_with_red_lsb_text()
    q = {"id": "f", "qid": "f", "question": "What is the flag hidden in the least significant bits?",
         "answer_format": {"kind": "exact_text", "pattern": "^[0-9A-F]{32}$"}}
    skipped = []
    found, work, no_meter = work_seconds_unless_missing(C.scan, "stg300.png", png, skipped=skipped)
    assert skipped == []
    assert any(f["channel"] == "lsb" and FLAG in (f["text"] or "") and "bit0 R xy" in f["method"] for f in found)
    if not no_meter:
        assert work < C.BUDGET * 0.8, f"scan took {work:.2f} s of work, of solve_set's {C.BUDGET} s budget"
    # the answer, with a budget load cannot use up (the cost is the work bound)
    got, work, no_meter = work_seconds_unless_missing(C.solve_set, [q], {"stg300.png": png},
                                                      {"carve_stego_budget": 120.0})
    assert got == {"f": FLAG}
    if no_meter:
        cost_not_run(no_meter)
    assert work < C.BUDGET * 0.8, f"solve_set took {work:.2f} s of work, of its {C.BUDGET} s budget"


def test_a_deep_reading_cut_by_the_deadline_still_leaves_the_answer_unproven():
    """The fix is cost, not a looser rule: a deadline that has passed still marks the reading left out."""
    png = _photo_png_with_red_lsb_text(64, 64)
    skipped = []
    C.lsb_deep_scan(C.png_pixels(png), deadline=time.monotonic() - 1, skipped=skipped)
    assert skipped == ["deep lsb: out of time"]
