"""B-245: JPEG readings of coverage-matrix row F8 (solvers/toolkits/jpeg_stego_f8.py): coefficient
orders a library-based embedder writes in (natural, coefficient plane by rows and columns, component
major), the sign and DC channels, F5 matrix decoding in those orders, and the quantisation tables.

Every JPEG is written here from explicit coefficients by the baseline writer in tests/b245_fixtures.py;
the message is placed by the test, from the published description of each rule. PLAIN only on a
stored length + CRC-32; a clean image gives plain None."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

REPO = Path(__file__).resolve().parent.parent
for p in ("tests", "solvers/toolkits", "solvers/common"):
    if str(REPO / p) not in sys.path:
        sys.path.insert(0, str(REPO / p))

import b245_fixtures as fx             # noqa: E402
import f5_stego as f5                  # noqa: E402
import jpeg_stego as js                # noqa: E402
import jpeg_stego_f8 as f8             # noqa: E402

FLAG = b"flag{jpeg_f8_orders}"
MSG = fx.len_crc(FLAG)
BITS = fx.bits_of(MSG)


def _cover_plane(h, w, seed=1, no_ones=False):
    rng = np.random.default_rng(seed)
    p = rng.integers(-20, 21, size=(h, w)).astype(np.int64)
    if no_ones:
        p[np.abs(p) == 1] = 2 * np.sign(p[np.abs(p) == 1])
    return p


def _plane_blocks(plane):
    """Natural-order coefficient plane -> zigzag blocks in decode (block-raster) order."""
    out = []
    for by in range(plane.shape[0] // 8):
        for bx in range(plane.shape[1] // 8):
            nat = plane[by * 8:by * 8 + 8, bx * 8:bx * 8 + 8].reshape(64)
            out.append([int(v) for v in nat[f8.ZIGZAG]])
    return out


def _gray(plane):
    return fx.jpeg_from_blocks(_plane_blocks(plane), plane.shape[1], plane.shape[0])


def _dc_mask(shape):
    return f8.dc_mask_plane(shape)


def _embed_jsteg(values, bits):
    """jsteg rule on a flat sequence (a view is modified in place): coefficients not 0 and not 1."""
    j = 0
    for i in range(len(values)):
        if j >= len(bits):
            return
        if values[i] not in (0, 1):
            values[i] = (values[i] & ~1) | bits[j]
            j += 1
    assert j == len(bits), "cover too small"


def test_zigzag_table_matches_the_fixture_writer():
    assert f8.ZIGZAG.tolist() == fx.ZIGZAG
    blocks = np.arange(128).reshape(2, 64)
    nat = f8.to_natural(blocks)
    assert nat[0, 8] == 2 and nat[0, 1] == 1 and nat[1, 63] == 127


def test_plane_order_jsteg_is_read_and_the_decode_order_survey_misses_it():
    plane = _cover_plane(64, 64)
    flat = plane.reshape(-1)                    # a view: row by row over the whole plane
    _embed_jsteg(flat, BITS)
    data = _gray(plane)
    assert js.coefficient_survey(data)[0] == {}       # the gap this item closes
    res = f8.survey(data)
    assert res["plain"] == FLAG and res["method"].startswith("plane all jsteg")


def test_plane_columns_every_rule():
    plane = _cover_plane(64, 64, seed=2)
    col = plane.T.copy().reshape(-1)
    col[:len(BITS)] = (col[:len(BITS)] & ~1) | np.asarray(BITS)
    plane = col.reshape(64, 64).T.copy()
    res = f8.survey(_gray(plane))
    assert res["plain"] == FLAG and res["method"].startswith("plane_cols all every")


def test_natural_block_order_jsteg():
    plane = _cover_plane(64, 64, seed=3)
    blocks = [np.asarray(b) for b in _plane_blocks(plane)]
    nat = f8.to_natural(np.asarray(blocks)).reshape(-1)
    _embed_jsteg(nat, BITS)
    zz = nat.reshape(-1, 64)[:, f8.ZIGZAG]
    res = f8.survey(fx.jpeg_from_blocks(zz.tolist(), 64, 64))
    assert res["plain"] == FLAG and res["method"].startswith("natural all jsteg")


def test_sign_channel_in_decode_order():
    plane = _cover_plane(64, 64, seed=4, no_ones=True)
    blocks = np.asarray(_plane_blocks(plane))
    flat = blocks.reshape(-1)
    dc = np.tile(np.arange(64) == 0, len(blocks))
    pos = np.flatnonzero(~dc & (flat != 0))[:len(BITS)]
    flat[pos] = np.abs(flat[pos]) * np.where(np.asarray(BITS) == 1, -1, 1)
    res = f8.survey(fx.jpeg_from_blocks(blocks.tolist(), 64, 64))
    assert res["plain"] == FLAG and res["method"].startswith("decode all sign")


def test_dc_lsb_channel():
    plane = _cover_plane(128, 128, seed=5)
    blocks = np.asarray(_plane_blocks(plane))
    blocks[:len(BITS), 0] = (blocks[:len(BITS), 0] & ~1) | np.asarray(BITS)
    res = f8.survey(fx.jpeg_from_blocks(blocks.tolist(), 128, 128))
    assert res["plain"] == FLAG and res["method"].startswith("dc decode")


def test_f5_matrix_in_plane_order():
    plane = _cover_plane(96, 96, seed=6, no_ones=True)
    flat = plane.reshape(-1)
    dc = _dc_mask(plane.shape).reshape(-1)
    carriers = np.flatnonzero(~dc & (flat != 0))
    k, n = 3, 7
    msg_bits = BITS + [0] * (-len(BITS) % k)
    for g in range(len(msg_bits) // k):
        idx = carriers[g * n:(g + 1) * n]
        vals = flat[idx]
        bit = np.where(vals > 0, vals & 1, 1 - (vals & 1))
        h = 0
        for j in range(n):
            if bit[j]:
                h ^= j + 1
        m = int("".join(map(str, msg_bits[g * k:(g + 1) * k])), 2)
        s = h ^ m
        if s:
            c = idx[s - 1]
            flat[c] = flat[c] - 1 if flat[c] > 0 else flat[c] + 1
    data = _gray(plane)
    assert f5.f5_survey(data)[0] == {}                   # f5_stego (decode order) does not read it
    res = f8.survey(data)
    assert res["plain"] == FLAG and res["method"] == "plane all f5 k3 msb-first; len+crc (be)"


def test_quantisation_table_lsb():
    flag = b"flag{dqt_bits}"
    bits = fx.bits_of(fx.len_crc(flag))
    rng = np.random.default_rng(7)
    vals = (rng.integers(1, 120, size=192) * 2).tolist()
    for i, b in enumerate(bits):
        vals[i] |= b
    tables = [vals[0:64], vals[64:128], vals[128:192]]
    data = fx.jpeg_from_blocks(_plane_blocks(_cover_plane(16, 16)), 16, 16, qtables=tables)
    assert [t for _, t in f8.dqt_tables(data)] == tables
    res = f8.survey(data)
    assert res["plain"] == flag and res["method"].startswith("dqt lsb")


def _colour_blocks(planes):
    """Three natural-order planes (4:4:4) -> interleaved decode-order zigzag blocks."""
    per = [_plane_blocks(p) for p in planes]
    return [blk for trio in zip(*per) for blk in trio]


def test_colour_planes_component_after_component():
    planes = [_cover_plane(8, 16, seed=s) for s in (8, 9, 10)]
    flat = np.concatenate([p.reshape(-1) for p in planes])
    _embed_jsteg(flat, BITS)                     # 128 coefficients a plane: the message runs from Y into Cb
    planes = [flat[i * 128:(i + 1) * 128].reshape(8, 16) for i in range(3)]
    data = fx.jpeg_from_blocks(_colour_blocks(planes), 16, 8, ncomp=3)
    res = f8.survey(data)
    assert res["plain"] == FLAG and res["method"].startswith("plane all jsteg")


def test_component_major_order():
    planes = [_cover_plane(16, 32, seed=s) for s in (11, 12, 13)]
    blocks = np.asarray(_colour_blocks(planes))           # decode order: Y Cb Cr Y Cb Cr ...
    tags = np.tile([0, 1, 2], len(blocks) // 3)
    order = np.argsort(tags, kind="stable")
    cm = blocks[order].reshape(-1)
    _embed_jsteg(cm, BITS)
    blocks[order] = cm.reshape(-1, 64)
    res = f8.survey(fx.jpeg_from_blocks(blocks.tolist(), 32, 16, ncomp=3))
    assert res["plain"] == FLAG and res["method"].startswith("compmajor jsteg")


S420 = [(2, 2), (1, 1), (1, 1)]


def _blocks_420(planes, W, H, seed):
    """Natural-order planes at libjpeg's sizes (Y, Cb, Cr) -> 4:2:0 decode-order zigzag blocks. Y
    blocks past libjpeg's width/height in blocks are MCU padding: random cover, outside the plane."""
    rng = np.random.default_rng(seed)
    mcu_x, mcu_y = -(-W // 16), -(-H // 16)
    out = []

    def block(plane, by, bx):
        if by * 8 < plane.shape[0] and bx * 8 < plane.shape[1]:
            nat = plane[by * 8:by * 8 + 8, bx * 8:bx * 8 + 8].reshape(64)
        else:
            nat = rng.integers(-20, 21, size=64)
        return [int(v) for v in nat[f8.ZIGZAG]]

    for my in range(mcu_y):
        for mx in range(mcu_x):
            for v in range(2):
                for h in range(2):
                    out.append(block(planes[0], 2 * my + v, 2 * mx + h))
            out.append(block(planes[1], my, mx))
            out.append(block(planes[2], my, mx))
    return out


@pytest.mark.parametrize("W,H", [(100, 70), (33, 17)])
def test_plane_order_at_a_size_with_mcu_padding(W, H):
    # 4:2:0 at a size that is not a multiple of the 16x16 MCU: the decoder emits Y blocks past
    # libjpeg's width/height in blocks; a library's coefficient plane drops them, so must the reader
    yb = (-(-H // 8), -(-W // 8))
    cb = (-(-(-(-H // 2)) // 8), -(-(-(-W // 2)) // 8))
    planes = [_cover_plane(yb[0] * 8, yb[1] * 8, seed=30)] + [_cover_plane(cb[0] * 8, cb[1] * 8, seed=s)
                                                               for s in (31, 32)]
    flat = np.concatenate([p.reshape(-1) for p in planes])
    _embed_jsteg(flat, BITS)
    sizes = [p.size for p in planes]
    planes = [flat[sum(sizes[:i]):sum(sizes[:i + 1])].reshape(p.shape) for i, p in enumerate(planes)]
    data = fx.jpeg_from_blocks(_blocks_420(planes, W, H, seed=33), W, H, ncomp=3, sampling=S420)
    res = f8.survey(data)
    assert res["plain"] == FLAG, res["notes"]
    # the message sits inside the Y plane, so the Y-only and the all-components plane both prove it
    assert {m.split(" msb")[0] for m in res["proven"][FLAG]} >= {"plane Y jsteg", "plane all jsteg"}


@pytest.mark.parametrize("W,H", [(100, 70), (33, 17), (57, 41)])
def test_clean_padded_4_2_0_jpegs_are_read_and_give_no_candidate(W, H):
    import io
    from PIL import Image
    im = Image.fromarray(np.random.default_rng(W).integers(0, 256, (H, W, 3), dtype=np.uint8))
    out = io.BytesIO()
    im.save(out, "JPEG", quality=75, subsampling=2)
    res = f8.survey(out.getvalue())
    assert res["plain"] is None and res["candidates"] == []
    assert not any("not read" in n for n in res["notes"]), res["notes"]
    assert any(n.endswith(f"{W}x{H}") for n in res["notes"])


def test_a_layout_failure_is_a_note_not_a_traceback(monkeypatch):
    def boom(*_a, **_k):
        raise ValueError("synthetic layout failure")

    monkeypatch.setattr(f8, "coefficient_plane", boom)
    res = f8.survey(_gray(_cover_plane(64, 64, seed=21)))
    assert res["plain"] is None
    assert any(n.startswith("coefficient orders not read: ValueError") for n in res["notes"])


@pytest.mark.parametrize("exc", [IndexError, KeyError])
def test_other_shape_errors_are_notes_too(monkeypatch, exc):
    def boom(*_a, **_k):
        raise exc("synthetic layout failure")

    monkeypatch.setattr(f8, "block_grid", boom)
    res = f8.survey(_gray(_cover_plane(64, 64, seed=21)))
    assert any(n.startswith(f"coefficient orders not read: {exc.__name__}") for n in res["notes"])


def test_a_bug_outside_the_layout_shapes_is_not_swallowed(monkeypatch):
    # only the reshape / grid / frame-lookup errors become a note; a TypeError is a bug and must fail
    def boom(*_a, **_k):
        raise TypeError("synthetic bug")

    monkeypatch.setattr(f8, "coefficient_plane", boom)
    with pytest.raises(TypeError, match="synthetic bug"):
        f8.survey(_gray(_cover_plane(64, 64, seed=21)))


def test_block_grid_follows_mcu_layout_and_libjpeg_sizes():
    frame = {"w": 33, "h": 17, "comps": [{"h": 2, "v": 2}, {"h": 1, "v": 1}, {"h": 1, "v": 1}]}
    grid, size = f8.block_grid(frame, 0, 8)
    assert grid == [(0, 0), (0, 1), (1, 0), (1, 1), (0, 2), (0, 3), (1, 2), (1, 3)]
    assert size == (3, 5)                     # ceil(17/8) x ceil(33/8)
    grid, size = f8.block_grid(frame, 1, 4)
    assert grid == [(0, 0), (0, 1), (0, 2), (1, 0)] and size == (2, 3)   # ceil(ceil(17/2)/8) x ceil(ceil(33/2)/8)


def test_clean_jpeg_has_no_plain():
    res = f8.survey(_gray(_cover_plane(64, 64, seed=20)))
    assert res["plain"] is None and res["proven"] == {} and res["candidates"] == []
    assert f8.survey(b"not a jpeg")["notes"] == ["not a JPEG"]
    with pytest.raises(f8.JpegF8Error):
        f8.survey("text")
    with pytest.raises(f8.JpegF8Error):
        f8.rule_bits(np.zeros(3, np.int64), np.zeros(3, bool), "nope")


@pytest.mark.parametrize("pattern", ["blocks", "gradient", "noise"])
@pytest.mark.parametrize("quality,subsampling", [(50, 0), (75, 2), (95, 2)])
def test_clean_pillow_jpegs_give_no_candidate(pattern, quality, subsampling):
    # a flat, blocky image has near-constant coefficient planes whose bit streams read as short
    # printable runs ('333333000000w17' at 4:2:0 q75); the F8 survey must not offer them
    import io
    from PIL import Image
    w, h = 96, 64
    if pattern == "blocks":
        x = np.arange(w)[None, :].repeat(h, 0)
        y = np.arange(h)[:, None].repeat(w, 1)
        im = Image.fromarray(np.stack([((x // 16) * 40) % 256, ((y // 16) * 60) % 256,
                                       np.full((h, w), 128)], axis=2).astype(np.uint8))
    elif pattern == "gradient":
        g = np.tile(np.arange(w, dtype=np.uint8) * 2, (h, 1))
        im = Image.fromarray(np.stack([g, g[:, ::-1], g // 2], axis=2))
    else:
        im = Image.fromarray(np.random.default_rng(quality).integers(0, 256, (h, w, 3), dtype=np.uint8))
    out = io.BytesIO()
    im.save(out, "JPEG", quality=quality, subsampling=subsampling)
    res = f8.survey(out.getvalue())
    assert res["plain"] is None and res["candidates"] == [], res["candidates"][:3]


def test_corrupted_crc_is_not_plain():
    bad = bytearray(MSG)
    bad[12] ^= 4
    plane = _cover_plane(64, 64)
    _embed_jsteg(plane.reshape(-1), fx.bits_of(bytes(bad)))
    assert f8.survey(_gray(plane))["plain"] is None


def test_jpeg_stego_survey_runs_the_f8_readings():
    plane = _cover_plane(64, 64)
    _embed_jsteg(plane.reshape(-1), BITS)
    res = js.survey(_gray(plane))
    assert res["plain"] == FLAG and res["method"].startswith("plane all jsteg")


def test_jpeg_stego_survey_refuses_two_distinct_payloads_across_modules():
    # the quantisation tables carry one payload, the coefficient plane another: ambiguous, none plain
    other = b"flag{2nd_one}"
    ob = fx.bits_of(fx.len_crc(other))
    vals = [2 * (1 + i % 100) for i in range(192)]
    for i, b in enumerate(ob):
        vals[i] |= b
    plane = _cover_plane(64, 64, seed=14)
    _embed_jsteg(plane.reshape(-1), BITS)
    data = fx.jpeg_from_blocks(_plane_blocks(plane), 64, 64, qtables=[vals[:64], vals[64:128], vals[128:]])
    alone = f8.survey(data)
    assert set(alone["proven"]) == {FLAG, other} and alone["plain"] is None
    res = js.survey(data)
    assert res["plain"] is None
    assert any("ambiguous" in n for n in res["notes"])
    assert {v for _, v in res["candidates"]} >= {FLAG, other}
