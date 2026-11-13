"""B-245: palette-image carriers (solvers/toolkits/palette_stego.py): EzStego rank LSB, Fridrich palette
parity, colour-table LSB and the palette-order (permutation) channel, in PNG, GIF and 8-bit BMP.

Carriers are synthetic: the palette, the pixels and every embedding are made here (tests/b245_fixtures.py
holds the shared embedders). PLAIN only on a stored length + CRC-32; a clean image gives plain None."""
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
import palette_stego as ps             # noqa: E402

FLAG = b"flag{palette_order}"
MSG = fx.len_crc(FLAG)
BITS = fx.bits_of(MSG)
WRITERS = {"png": fx.palette_png, "gif": fx.palette_gif, "bmp": fx.palette_bmp8}


def _palette(n=256, seed=1):
    rng = np.random.default_rng(seed)
    seen, out = set(), []
    while len(out) < n:
        c = tuple(int(v) for v in rng.integers(0, 256, size=3))
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _indices(n_colours=256, shape=(48, 64), seed=2):
    return np.random.default_rng(seed).integers(0, n_colours, size=shape).astype(np.uint8)


def test_lehmer_and_insertion_numbers_invert_the_embedders():
    for number in (0, 1, 5, 4321, 10 ** 20 + 7):
        assert ps.lehmer_number(fx.factorial_permutation(number, 40)) == number
        assert ps.insertion_number(fx.insertion_permutation(number, 40)) == number


@pytest.mark.parametrize("kind", ["png", "gif", "bmp"])
def test_ezstego_luminance_rank(kind):
    pal = _palette()
    idx = fx.ezstego_embed(_indices(), pal, BITS)
    res = ps.survey(WRITERS[kind](idx, pal))
    assert res["plain"] == FLAG and res["method"].startswith("ezstego luma rows")


def test_ezstego_on_a_small_palette_png():
    pal = _palette(16, seed=3)
    idx = fx.ezstego_embed(_indices(16), pal, BITS)
    res = ps.survey(fx.palette_png(idx, pal))
    assert res["plain"] == FLAG


def _parity_embed(indices, pal, bits):
    """Fridrich: move each pixel to the nearest colour (RGB distance) whose R+G+B parity is the bit."""
    arr = np.asarray(pal, dtype=np.int64)
    par = arr.sum(axis=1) & 1
    flat = indices.reshape(-1).copy()
    for i, b in enumerate(bits):
        c = arr[flat[i]]
        if par[flat[i]] != b:
            d = ((arr - c) ** 2).sum(axis=1)
            d[par != b] = 1 << 40
            flat[i] = int(np.argmin(d))
    return flat.reshape(indices.shape)


def test_fridrich_parity():
    pal = _palette()
    res = ps.survey(fx.palette_png(_parity_embed(_indices(), pal, BITS), pal))
    assert res["plain"] == FLAG and res["method"].startswith("parity rows")


def test_column_scan():
    pal = _palette()
    idx = fx.ezstego_embed(_indices().T.copy(), pal, BITS).T.copy()
    res = ps.survey(fx.palette_png(idx, pal))
    assert res["plain"] == FLAG and "columns" in res["method"]


def test_colour_table_lsb():
    pal = _palette()
    flat = [c for rgb in pal for c in rgb]
    for i, b in enumerate(BITS):
        flat[i] = (flat[i] & 0xFE) | b
    pal2 = [tuple(flat[i:i + 3]) for i in range(0, len(flat), 3)]
    res = ps.survey(fx.palette_gif(_indices(), pal2))
    assert res["plain"] == FLAG and res["method"].startswith("table_lsb rgb")


def _reorder(pal, perm, key):
    sorted_cols = [pal[i] for i in ps.sort_order(pal, key)]
    return [sorted_cols[r] for r in perm]


@pytest.mark.parametrize("kind", ["png", "gif", "bmp"])
@pytest.mark.parametrize("scheme", ["lehmer", "insertion"])
def test_palette_order_channel(kind, scheme):
    pal = _palette()
    number = int.from_bytes(MSG, "big")
    perm = (fx.factorial_permutation if scheme == "lehmer" else fx.insertion_permutation)(number, 256)
    key = dict(ps.SORT_KEYS)["rgb"]
    res = ps.survey(WRITERS[kind](_indices(), _reorder(pal, perm, key)))
    assert res["plain"] == FLAG
    assert res["method"].startswith(f"order rgb perm {scheme} be")


def test_palette_order_with_a_marker_bit_and_luminance_sort():
    pal = _palette()
    number = (1 << (8 * len(MSG))) | int.from_bytes(MSG, "big")
    perm = fx.factorial_permutation(number, 256)
    res = ps.survey(fx.palette_png(_indices(), _reorder(pal, perm, dict(ps.SORT_KEYS)["luma"])))
    assert res["plain"] == FLAG and res["method"].startswith("order luma perm lehmer marker")


def test_repeated_colours_are_said_and_order_is_not_read():
    pal = _palette()
    pal[5] = pal[6]
    res = ps.survey(fx.palette_png(_indices(), pal))
    assert any(n.startswith("the palette repeats a colour") for n in res["notes"])
    assert any(n.startswith("order: the palette repeats a colour") for n in res["notes"])
    assert ps.permutation_of(pal, dict(ps.SORT_KEYS)["rgb"]) is None


def test_clean_palette_image_has_no_plain():
    for kind, write in WRITERS.items():
        res = ps.survey(write(_indices(seed=9), _palette(seed=9)))
        assert res["plain"] is None and res["proven"] == {} and res["candidates"] == [], kind


def test_corrupted_crc_is_not_plain():
    bad = bytearray(MSG)
    bad[9] ^= 1
    pal = _palette()
    res = ps.survey(fx.palette_png(fx.ezstego_embed(_indices(), pal, fx.bits_of(bytes(bad))), pal))
    assert res["plain"] is None


def test_non_palette_inputs_are_said():
    from PIL import Image
    import io
    out = io.BytesIO()
    Image.new("RGB", (8, 8), (1, 2, 3)).save(out, "PNG")
    res = ps.survey(out.getvalue())
    assert res["plain"] is None and "not a palette image" in res["notes"][0]
    with pytest.raises(ps.PaletteStegoError):
        ps.survey("a string")


def test_load_reads_the_exact_table_length_and_bmp_rows_top_down():
    pal = _palette(37, seed=4)
    idx = _indices(37)
    for kind in ("png", "bmp"):
        img = ps.load_palette_image(WRITERS[kind](idx, pal))
        assert img.colours == 37 and img.palette == pal
        assert img.indices.tolist() == idx.tolist()
    img = ps.load_palette_image(fx.palette_gif(idx, pal))
    assert img.palette[:37] == pal                  # a GIF table is a power of two: padded
    assert img.indices.tolist() == idx.tolist()


def test_cli(tmp_path, capsys):
    import json
    pal = _palette()
    p = tmp_path / "x.png"
    p.write_bytes(fx.palette_png(fx.ezstego_embed(_indices(), pal, BITS), pal))
    assert ps.main([str(p)]) == 0
    assert bytes.fromhex(json.loads(capsys.readouterr().out)["plain_hex"]) == FLAG
