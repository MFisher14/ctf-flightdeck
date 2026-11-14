"""QR decode engine: single image, grid, and flag-regex filtering, on synthetic in-test fixtures."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "solvers" / "toolkits"))

qrcode = pytest.importorskip("qrcode")
PIL = pytest.importorskip("PIL")
pytest.importorskip("pyzbar")

import qr_decode  # noqa: E402
from PIL import Image  # noqa: E402


def _qr(text, box=6, border=4):
    q = qrcode.QRCode(box_size=box, border=border)
    q.add_data(text)
    q.make(fit=True)
    return q.make_image(fill_color="black", back_color="white").convert("RGB")


def test_single(tmp_path):
    p = tmp_path / "one.png"
    _qr("CSCTF{qr_single_payload}").save(p)
    rep = qr_decode.decode(p)
    assert "CSCTF{qr_single_payload}" in rep["payloads"]
    assert rep["flag_matches"] == ["CSCTF{qr_single_payload}"]


def test_grid_split_one_real_among_decoys(tmp_path):
    # 3x3 grid: 8 decoy hex QRs + one real flag, like Lost flag (scaled down).
    rows, cols = 3, 3
    cell = 180
    sheet = Image.new("RGB", (cols * cell, rows * cell), "white")
    real_r, real_c = 1, 2
    for r in range(rows):
        for c in range(cols):
            text = "CSCTF{AABBCCDDEEFF00112}" if (r, c) == (real_r, real_c) else f"DEADBEEF{r}{c}"
            img = _qr(text).resize((cell, cell))
            sheet.paste(img, (c * cell, r * cell))
    p = tmp_path / "grid.png"
    sheet.save(p)
    cells = qr_decode.decode_grid(p, rows, cols)
    payloads = [t[2] for t in cells]
    matches = qr_decode.find_flag(payloads, pattern=r"CSCTF\{[0-9A-F]{17}\}")   # a challenge-stated shape
    assert matches == ["CSCTF{AABBCCDDEEFF00112}"]
    # the real flag came from the expected cell
    assert any((r, c) == (real_r, real_c) and v == "CSCTF{AABBCCDDEEFF00112}" for r, c, v in cells)


def test_find_flag_dedupes_and_filters():
    payloads = ["noise", "CSCTF{a}", "CSCTF{a}", "prefix CSCTF{b} suffix", "CTF{c}"]
    assert qr_decode.find_flag(payloads) == ["CSCTF{a}", "CSCTF{b}", "CTF{c}"]
    assert qr_decode.find_flag(payloads, r"CSCTF\{b\}") == ["CSCTF{b}"]
