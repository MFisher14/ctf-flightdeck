#!/usr/bin/env python3
"""QR / barcode decoding — single image, grid-of-codes, and flag-regex filtering.

Offline reader for the recurring CSCTF QR archetypes:
  - Misc "Decoding" (2024): a single QR -> binary -> base64 chain; this gets the QR payload out.
  - Programming "Lost flag" (2024): a 50x50 GRID of QR codes, exactly one of which is the real flag
    among decoy hex QRs -> decode every cell, regex-filter to the one that matches the flag shape.

Everything here is pure analysis: it returns the decoded payload strings (and, with a pattern, the ones
that match) for you to READ and reason about. It never submits anything and never guesses — a cell that
will not decode is reported as undecoded, not invented.

  decode_image(path)                 -> list[str]          # every symbol found in one image
  decode_grid(path, rows, cols)      -> list[(r,c,str)]    # split into rows*cols cells, decode each
  decode_grid_auto(path)             -> list[(r,c,str)]    # detect the grid from symbol positions
  find_flag(payloads, pattern)       -> list[str]          # keep payloads matching a flag regex
  decode(path, pattern=..., grid=..) -> dict               # one-shot report (what the CLI prints)

Backends, tried in order: pyzbar (libzbar, best — reads many symbols per image), then the `zbarimg`
host binary as a fallback, then the pure-Python `qr_matrix` reader with its repair decode (a QR
whose finder patterns were removed, B-117). A missing backend is reported, never fatal.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

__all__ = ["decode_image", "decode_image_how", "decode_grid", "decode_grid_auto", "find_flag", "decode"]

# The matrix fallback's repair decode (B-117) is a last resort on a picture nothing else read. A
# forced decode of a candidate that does not read costs most of a CPU second, and a picture of
# plain text samples into a handful of QR-shaped candidates, so the fallback forces only the two
# with the most structure left, and none after this many seconds.
FALLBACK_REPAIRS = 2
FALLBACK_REPAIR_SECONDS = 20.0

# The default filter is the event's flag format (ctf.flagfmt); the CLI's --pattern takes a
# challenge-stated answer shape instead (e.g. the 2024 Lost-flag variant with 17 uppercase hex digits).


def _pyzbar():
    try:
        from pyzbar import pyzbar  # type: ignore
        from PIL import Image  # type: ignore
        return pyzbar, Image
    except Exception:
        return None


def _decode_pyzbar(img) -> list[str]:
    got = _pyzbar()
    if not got:
        return []
    pyzbar, _ = got
    out = []
    for sym in pyzbar.decode(img):
        try:
            out.append(sym.data.decode("utf-8", "replace"))
        except Exception:
            out.append(repr(sym.data))
    return out


def _decode_zbarimg(path: Path) -> list[str]:
    exe = shutil.which("zbarimg")
    if not exe:
        return []
    try:
        # -q quiet, -Sdisable then -Sqrcode.enable keeps it to QR unless you want all; keep all symbols.
        res = subprocess.run([exe, "-q", "--raw", str(path)], capture_output=True, timeout=30)
    except Exception:
        return []
    lines = res.stdout.decode("utf-8", "replace").splitlines()
    return [ln for ln in lines if ln != ""]


def _matrix_fallback(path: Path) -> tuple[list[str], bool]:
    """(payloads, whether any needed the repair) from the pure-Python QR fallback. Import lazily so
    pyzbar remains the fast path. The repair decode is on (B-117): a code whose finder patterns
    were removed or painted over, which no camera decoder finds, is still read here when its
    modules sample cleanly (Reed--Solomon decides). The repair is bounded: FALLBACK_REPAIRS
    candidates, FALLBACK_REPAIR_SECONDS."""
    import time
    try:
        import qr_matrix
        found = [item for item in qr_matrix.decode_path(path, repair=True, repair_limit=FALLBACK_REPAIRS,
                                                        repair_deadline=time.monotonic() + FALLBACK_REPAIR_SECONDS)
                 if isinstance(item.get("text"), str)]
    except Exception:
        return [], False
    return [item["text"] for item in found], any(item.get("repaired") for item in found)


def _decode_matrix_fallback(path: Path) -> list[str]:
    return _matrix_fallback(path)[0]


def decode_image_how(path) -> tuple[list[str], str]:
    """(payloads, what read them): "pyzbar", "zbarimg", "qr_matrix", "qr_matrix repair" (the
    pure-Python reader had to drop its finder gate or force the format: a reading to look at
    twice, though Reed--Solomon accepted it) or "none"."""
    p = Path(path)
    got = _pyzbar()
    if got:
        _, Image = got
        try:
            with Image.open(p) as im:
                out = _decode_pyzbar(im.convert("RGB"))
            if out:
                return out, "pyzbar"
        except Exception:
            pass
    out = _decode_zbarimg(p)
    if out:
        return out, "zbarimg"
    out, repaired = _matrix_fallback(p)
    return out, ("qr_matrix repair" if repaired else "qr_matrix") if out else "none"


def decode_image(path) -> list[str]:
    """Every barcode/QR symbol decoded from one image, as strings. Empty list if none/no backend."""
    return decode_image_how(path)[0]


def _cells(path, rows, cols):
    got = _pyzbar()
    if not got:
        raise RuntimeError("grid decode needs pyzbar + PIL (pip install pyzbar pillow; brew install zbar)")
    _, Image = got
    with Image.open(path) as im:
        im = im.convert("RGB")
        W, H = im.size
        cw, ch = W / cols, H / rows
        for r in range(rows):
            for c in range(cols):
                box = (int(c * cw), int(r * ch), int((c + 1) * cw), int((r + 1) * ch))
                yield r, c, im.crop(box)


def decode_grid(path, rows: int, cols: int) -> list[tuple[int, int, str]]:
    """Split the image into rows*cols equal cells and decode each. Returns (row, col, payload) for every
    cell that decodes to at least one symbol (its first symbol)."""
    if not all(isinstance(value, int) and value > 0 for value in (rows, cols)):
        return []
    if not _pyzbar():
        return []
    out = []
    try:
        for r, c, cell in _cells(path, rows, cols):
            syms = _decode_pyzbar(cell)
            if syms:
                out.append((r, c, syms[0]))
    except Exception:
        # Match decode_image's empty-result contract for unreadable images and
        # backend failures, including failures while the cell generator runs.
        return []
    return out


def decode_grid_auto(path) -> list[tuple[int, int, str]]:
    """Decode a grid without being told its dimensions: decode the whole image at once (pyzbar returns
    every symbol with its position), then order by (y, x) into row/col-ish indices. Falls back to
    whole-image decode. Best when symbols are well separated."""
    got = _pyzbar()
    if not got:
        return [(0, i, s) for i, s in enumerate(decode_image(path))]
    pyzbar, Image = got
    try:
        with Image.open(path) as im:
            im = im.convert("RGB")
            syms = pyzbar.decode(im)
    except Exception:
        return []
    rows_tol = 0
    items = []
    for s in syms:
        try:
            payload = s.data.decode("utf-8", "replace")
        except Exception:
            payload = repr(s.data)
        items.append((s.rect.top, s.rect.left, payload))
    items.sort(key=lambda t: (t[0], t[1]))
    # Bucket by y into rows (gap-based), then index within row by x order.
    out = []
    last_y = None
    r = -1
    cidx = 0
    for y, x, payload in items:
        if last_y is None or y - last_y > 20:
            r += 1
            cidx = 0
        else:
            cidx += 1
        out.append((r, cidx, payload))
        last_y = y
    return out


def find_flag(payloads, pattern: str | None = None) -> list[str]:
    """The payloads (or substrings) matching the event's flag format, or `pattern` (a challenge-stated
    shape). Deduped, order-preserving. This is the 'filter the 2500 decoy QRs down to the real flag'
    step — it reports matches, never guesses."""
    if pattern is None:
        rx = flagfmt.TEXT
    else:
        try:
            rx = re.compile(pattern)
        except (re.error, TypeError, OverflowError, RecursionError):
            return []
    seen, out = set(), []
    for p in payloads:
        for m in rx.finditer(p or ""):
            v = m.group(0)
            if v not in seen:
                seen.add(v)
                out.append(v)
    return out


def decode(path, pattern: str | None = None, grid: tuple[int, int] | None = None) -> dict:
    """One-shot report. If `grid=(rows,cols)` decode as a grid, else try whole-image then auto-grid."""
    p = Path(path)
    if grid is not None:
        if (not isinstance(grid, (tuple, list)) or len(grid) != 2
                or not all(isinstance(value, int) and value > 0 for value in grid)):
            return {}
        cells = decode_grid(p, grid[0], grid[1])
        payloads = [c[2] for c in cells]
        mode = f"grid {grid[0]}x{grid[1]}"
        read_by = "pyzbar" if payloads else "none"
    else:
        payloads, read_by = decode_image_how(p)
        mode = "single"
        if len(payloads) <= 1:
            cells = decode_grid_auto(p)
            if len(cells) > len(payloads):
                payloads = [c[2] for c in cells]
                mode = "auto-grid"
                read_by = "pyzbar"
    return {
        "file": str(p),
        "mode": mode,
        "symbol_count": len(payloads),
        "payloads": payloads[:200],
        "flag_matches": find_flag(payloads, pattern),
        "backend": "pyzbar" if _pyzbar() else ("zbarimg" if shutil.which("zbarimg") else "none"),
        "read_by": read_by,                 # what read these payloads; "qr_matrix repair" says the repair did (B-117)
    }


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Decode QR/barcodes from an image (single or grid).")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--pattern", default=None, help="answer regex to filter payloads (default: the event's flag format)")
    ap.add_argument("--grid", help="ROWSxCOLS, e.g. 50x50, to decode as an equal-cell grid")
    ap.add_argument("--json", action="store_true")
    try:
        a = ap.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        grid = None
        if a.grid:
            rs, cs = a.grid.lower().split("x")
            grid = (int(rs), int(cs))
            if min(grid) <= 0:
                raise ValueError("grid dimensions must be positive")
        reports = [decode(f, a.pattern, grid) for f in a.files]
    except (OSError, ValueError, TypeError, OverflowError) as exc:
        print(f"qr_decode.py: {exc}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(reports, indent=2))
        return 0
    for rep in reports:
        repaired = ", read by the qr_matrix repair decode" if rep.get("read_by") == "qr_matrix repair" else ""
        print(f"== {rep['file']}  [{rep['mode']}, backend={rep['backend']}{repaired}]  {rep['symbol_count']} symbol(s)")
        if rep["flag_matches"]:
            print("  FLAG MATCHES:")
            for m in rep["flag_matches"]:
                print(f"    {m}")
        else:
            for pl in rep["payloads"][:20]:
                print(f"    {pl!r}")
            if rep["symbol_count"] > 20:
                print(f"    ... ({rep['symbol_count'] - 20} more; use --json)")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
