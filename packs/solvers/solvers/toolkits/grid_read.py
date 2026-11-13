#!/usr/bin/env python3
"""Read a character grid in many orders (route / grid ciphers), offline.

A recurring misc puzzle: the flag is written into a W x H grid and you must read it in the RIGHT order
— down columns, in a spiral, along diagonals, boustrophedon (snaking). This produces every common
reading and ranks the one that looks like a flag / English first. Distinct from rail-fence and columnar
transposition (`common/classical.py`). Offline, ranked candidates — never submits.
"""
from __future__ import annotations

import argparse
import math
import sys
from typing import Iterable

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_CELLS = 1 << 20
_FLAG = flagfmt.TEXT


def _grid_from_text(text: str) -> list[list[str]] | None:
    lines = text.split("\n")
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        return None
    width = max(len(ln) for ln in lines)
    if width * len(lines) > MAX_CELLS or width == 0:
        return None
    return [list(ln.ljust(width)) for ln in lines]


def _grid_from_flat(data: str, width: int) -> list[list[str]] | None:
    if width < 1 or len(data) > MAX_CELLS:
        return None
    rows = [list(data[i:i + width]) for i in range(0, len(data), width)]
    if rows and len(rows[-1]) < width:
        rows[-1] += [" "] * (width - len(rows[-1]))
    return rows or None


def _rows(g):           # left-to-right, top-to-bottom
    return "".join("".join(r) for r in g)


def _cols(g):           # top-to-bottom, left-to-right
    return "".join(g[r][c] for c in range(len(g[0])) for r in range(len(g)))


def _rows_bous(g):      # snaking rows: row0 L->R, row1 R->L, ...
    out = []
    for i, r in enumerate(g):
        out.append("".join(r if i % 2 == 0 else r[::-1]))
    return "".join(out)


def _cols_bous(g):      # snaking columns
    h, w = len(g), len(g[0])
    out = []
    for c in range(w):
        rng = range(h) if c % 2 == 0 else range(h - 1, -1, -1)
        out.extend(g[r][c] for r in rng)
    return "".join(out)


def _spiral_cw(g):      # clockwise inward from top-left
    g = [row[:] for row in g]
    out = []
    top, bottom, left, right = 0, len(g) - 1, 0, len(g[0]) - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            out.append(g[top][c])
        top += 1
        for r in range(top, bottom + 1):
            out.append(g[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                out.append(g[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                out.append(g[r][left])
            left += 1
    return "".join(out)


def _diagonals(g):      # anti-diagonals, top-left to bottom-right
    h, w = len(g), len(g[0])
    out = []
    for s in range(h + w - 1):
        for r in range(h):
            c = s - r
            if 0 <= c < w:
                out.append(g[r][c])
    return "".join(out)


_ORDERS = {
    "rows": _rows, "rows_reversed": lambda g: _rows(g)[::-1],
    "columns": _cols, "columns_reversed": lambda g: _cols(g)[::-1],
    "rows_boustrophedon": _rows_bous, "columns_boustrophedon": _cols_bous,
    "spiral_cw": _spiral_cw, "spiral_cw_reversed": lambda g: _spiral_cw(g)[::-1],
    "diagonals": _diagonals,
}


def _score(text: str) -> float:
    if not text:
        return -1e9
    letters = sum(1 for c in text if c.isalpha() or c == " ")
    return letters / len(text)


def read_all(grid: object, *, width: int | None = None) -> list[dict]:
    """Ranked [{order, text, score, flag}] readings of the grid in every supported order.

    `grid` is a multi-line string, or a flat string plus `width`. Flag-shaped readings rank first."""
    if isinstance(grid, bytes):
        try:
            grid = grid.decode("latin-1")
        except Exception:
            return []
    if not isinstance(grid, str) or not grid:
        return []
    g = _grid_from_flat(grid, width) if width is not None else _grid_from_text(grid)
    if not g or not g[0]:
        return []
    out = []
    for name, fn in _ORDERS.items():
        try:
            text = fn(g)
        except (IndexError, ValueError):
            continue
        out.append({"order": name, "text": text, "score": round(_score(text), 3),
                    "flag": bool(_FLAG.search(text))})
    out.sort(key=lambda d: (0 if d["flag"] else 1, -d["score"]))
    return out


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read a character grid in route/grid-cipher orders "
                                            "(spiral/columns/boustrophedon/diagonals; offline).")
    p.add_argument("file", help="grid as a text file (rows = lines), or flat data with --width")
    p.add_argument("--width", type=int, default=None, help="treat the file as flat data of this row width")
    p.add_argument("--json", action="store_true")
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with open(a.file, "r", encoding="latin-1") as fh:
            data = fh.read(MAX_CELLS + 1)
    except OSError as exc:
        print(f"grid_read: {exc}", file=sys.stderr)
        return 1
    results = read_all(data, width=a.width)
    if a.json:
        import json
        print(json.dumps(results, indent=1))
    else:
        for r in results:
            tag = " FLAG" if r["flag"] else ""
            print(f"[{r['order']:22} score={r['score']}{tag}] {r['text'][:120]}")
    return 0 if results else 1


if __name__ == "__main__":
    raise SystemExit(main())
