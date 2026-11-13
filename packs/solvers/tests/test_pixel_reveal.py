#!/usr/bin/env python3
"""Offline tests of solvers/toolkits/pixel_reveal.py -- near-background hidden-text reveal.

  .venv/bin/python tests/test_pixel_reveal.py

Builds the 2024 Stegano "Neighbour" fixture directly: a white canvas with a word drawn in RGB(254,254,254)
(difference of 1 from the 255 background). The reveal must find the white background, mark exactly the
hidden pixels, box them tightly, and emit a readable black-on-white PNG. A noise test confirms the
threshold ignores small dithering when asked. Pillow required; skipped with a pass when absent.
"""
import io
import os
import sys
import random
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import pixel_reveal as pr       # noqa: E402

FAILED = []
random.seed(7)


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)


def have_pil():
    try:
        import PIL  # noqa: F401
        return True
    except Exception:
        return False


def make_hidden(w, h, pixels, fg=(254, 254, 254), bg=(255, 255, 255)):
    """White canvas with `pixels` (set of (x,y)) drawn at `fg` (near-background)."""
    from PIL import Image
    im = Image.new("RGB", (w, h), bg)
    px = im.load()
    for (x, y) in pixels:
        px[x, y] = fg
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def test_reveal_near_background_marks_hidden_pixels():
    # a 5-pixel "dot" cluster inside a 40x30 canvas, drawn at 254 on 255 white
    pixels = {(10, 5), (11, 5), (12, 5), (11, 6), (11, 7)}
    data = make_hidden(40, 30, pixels)
    r = pr.reveal_near_background(data)              # threshold=0 -> any non-background pixel
    check("reveal: returns a result on a valid image", r is not None, r)
    check("reveal: background detected as white (255,255,255)", bool(r) and r["background"] == (255, 255, 255), r and r["background"])
    check("reveal: exactly the hidden pixels are marked", bool(r) and r["n_marked"] == len(pixels), r and r.get("n_marked"))
    # tight bbox around xs 10..12, ys 5..7 (right/bottom exclusive)
    check("reveal: bounding box is tight around the text", bool(r) and r["bbox"] == (10, 5, 13, 8), r and r.get("bbox"))
    check("reveal: size is reported", bool(r) and r["size"] == (40, 30), r and r.get("size"))
    check("reveal: a revealed PNG was produced",
          bool(r) and bool(r["png_bytes"]) and r["png_bytes"][:8] == b"\x89PNG\r\n\x1a\n", None)
    # the revealed PNG opens, is L mode, and has black exactly where the hidden pixels were
    if r and r["png_bytes"]:
        from PIL import Image
        rev = Image.open(io.BytesIO(r["png_bytes"])); rev.load()
        check("reveal: revealed image matches carrier size", (rev.width, rev.height) == (40, 30), (rev.width, rev.height))
        px = rev.convert("L").load()
        black_ok = all(px[x, y] == 0 for (x, y) in pixels)
        check("reveal: hidden pixels are rendered black in the reveal", black_ok, None)
        check("reveal: a background pixel stays white in the reveal", px[0, 0] == 255, px[0, 0])


def test_reveal_no_hidden_pixels():
    from PIL import Image
    buf = io.BytesIO(); Image.new("RGB", (20, 20), (255, 255, 255)).save(buf, "PNG")
    r = pr.reveal_near_background(buf.getvalue())
    check("reveal: a blank canvas marks nothing", r is not None and r["n_marked"] == 0 and r["bbox"] is None, r)
    check("reveal: no reveal PNG when nothing is marked", bool(r) and r["png_bytes"] is None, r)


def test_threshold_ignores_small_noise():
    # background white with +-1 dithering everywhere, and a true message at difference 20
    from PIL import Image
    w, h = 24, 18
    im = Image.new("RGB", (w, h))
    px = im.load()
    for y in range(h):
        for x in range(w):
            n = 255 - random.randrange(2)            # 255 or 254 noise
            px[x, y] = (n, n, n)
    msg = {(5, 5), (6, 5), (7, 5)}
    for (x, y) in msg:
        px[x, y] = (235, 235, 235)                   # difference 20 from white
    buf = io.BytesIO(); im.save(buf, "PNG")
    # threshold 0 would mark the noise too; threshold 10 keeps only the real message
    r = pr.reveal_near_background(buf.getvalue(), threshold=10)
    check("reveal(threshold): background is white", bool(r) and r["background"] == (255, 255, 255), r and r["background"])
    check("reveal(threshold): only the strong message survives threshold 10",
          bool(r) and r["n_marked"] == len(msg) and r["bbox"] == (5, 5, 8, 6), r and (r.get("n_marked"), r.get("bbox")))


def test_non_image_is_none():
    check("reveal: non-image bytes -> None", pr.reveal_near_background(b"not an image" * 4) is None)
    check("reveal: empty -> None", pr.reveal_near_background(b"") is None)


def main():
    if not have_pil():
        check("(skipped: Pillow not installed)", True)
        print("ok")
        return 0
    tests = [test_reveal_near_background_marks_hidden_pixels, test_reveal_no_hidden_pixels,
             test_threshold_ignores_small_noise, test_non_image_is_none]
    for t in tests:
        try:
            t()
        except Exception as e:
            import traceback
            check(f"{t.__name__} ran", False, f"{type(e).__name__}: {e} | {traceback.format_exc()[-400:]}")
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED[:10]))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
