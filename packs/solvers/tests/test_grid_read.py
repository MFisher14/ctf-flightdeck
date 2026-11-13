"""grid_read: read a character grid in route-cipher orders (columns/spiral/boustrophedon/...)."""
from __future__ import annotations

import pytest

import grid_read as gr


def _spiral_positions(h, w):
    pos = []
    top, bottom, left, right = 0, h - 1, 0, w - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            pos.append((top, c))
        top += 1
        for r in range(top, bottom + 1):
            pos.append((r, right))
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                pos.append((bottom, c))
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                pos.append((r, left))
            left += 1
    return pos


def test_columns_reading():
    flag = "CSCTF{grid_columns}".ljust(25)  # 25 cells -> 5x5, column-major
    h = w = 5
    grid = [[" "] * w for _ in range(h)]
    for c in range(w):
        for r in range(h):
            grid[r][c] = flag[c * h + r]
    text = "\n".join("".join(row) for row in grid)
    res = gr.read_all(text)
    cols = next(r for r in res if r["order"] == "columns")
    assert "CSCTF{grid_columns}" in cols["text"]
    assert res[0]["flag"]  # a flag-shaped reading ranks first


def test_spiral_reading():
    flag = "CSCTF{spiral_route}".ljust(25)
    h = w = 5
    grid = [[" "] * w for _ in range(h)]
    for i, (r, c) in enumerate(_spiral_positions(h, w)):
        grid[r][c] = flag[i]
    text = "\n".join("".join(row) for row in grid)
    res = gr.read_all(text)
    sp = next(r for r in res if r["order"] == "spiral_cw")
    assert sp["text"].rstrip() == "CSCTF{spiral_route}"


def test_rows_is_identity():
    text = "ABC\nDEF\nGHI"
    res = gr.read_all(text)
    rows = next(r for r in res if r["order"] == "rows")
    assert rows["text"] == "ABCDEFGHI"


def test_boustrophedon_rows():
    text = "ABC\nDEF"
    res = gr.read_all(text)
    b = next(r for r in res if r["order"] == "rows_boustrophedon")
    assert b["text"] == "ABCFED"  # row0 L->R, row1 R->L


def test_flat_with_width():
    res = gr.read_all("ABCDEF", width=3)  # 2 rows of 3
    cols = next(r for r in res if r["order"] == "columns")
    assert cols["text"] == "ADBECF"


def test_fail_closed():
    assert gr.read_all("") == []
    assert gr.read_all(12345) == []
    assert gr.read_all("abc", width=0) == []


def test_cli(tmp_path, capsys):
    flag = "CSCTF{grid_columns}".ljust(25)
    h = w = 5
    grid = [[" "] * w for _ in range(h)]
    for c in range(w):
        for r in range(h):
            grid[r][c] = flag[c * h + r]
    f = tmp_path / "grid.txt"
    f.write_text("\n".join("".join(row) for row in grid))
    rc = gr.main([str(f), "--json"])
    assert rc == 0
    import json
    out = json.loads(capsys.readouterr().out)
    assert any("CSCTF{grid_columns}" in r["text"] for r in out)
    assert gr.main([str(tmp_path / "nope")]) == 1
    assert gr.main(["--help"]) == 0
