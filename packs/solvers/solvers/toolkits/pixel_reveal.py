#!/usr/bin/env python3
"""Reveal text hidden in near-background pixels of an image (the 2024 Stegano "Neighbour" trick).

The carrier looks blank: the message is drawn in a colour one or two steps off the background --
e.g. text at RGB(254, 254, 254) on a 255-white canvas, invisible to the eye and to a naive threshold.
The decode is not stego-with-a-key; it is a contrast operation. This module finds the dominant
(background) colour, marks every pixel that differs from it by more than `threshold` per channel, and
renders a clean high-contrast image (black marks on white) that an eye or OCR can read. It also returns
the tight bounding box of the marked pixels so a caller can crop to the message.

It is a TRANSFORM, not a flag claim: it emits a revealed image (and stats) for a human/OCR to read,
never a submitted answer. Pure offline pixel math (Pillow required; numpy used when present, with a
pure-Pillow fallback). Nothing is executed and nothing is written unless a caller saves `png_bytes`.

  reveal_near_background(image) -> {"background", "n_marked", "bbox", "png_bytes", "size", ...} | None

`image` is raw image bytes or a filesystem path. `threshold=0` marks ANY pixel unequal to the
background (the 254-on-255 case, difference 1); raise it to ignore dithering/JPEG noise.
"""
import io

__all__ = ["reveal_near_background"]

MAX_PIXELS = 80 * 1000 * 1000     # a ceiling so a hostile file cannot exhaust memory (e.g. 5000x5000)


def _load(image):
    """Open `image` (bytes or path) as an RGB Pillow image, or return None."""
    try:
        from PIL import Image
    except Exception:
        return None
    try:
        if isinstance(image, (bytes, bytearray)):
            im = Image.open(io.BytesIO(bytes(image)))
        else:
            im = Image.open(image)
        im.load()
    except Exception:
        return None
    if im.width * im.height > MAX_PIXELS or im.width < 1 or im.height < 1:
        return None
    return im.convert("RGB")


def reveal_near_background(image, threshold: int = 0, background=None):
    """Reveal near-background hidden text. Returns a dict or None.

    Keys:
      "background"   (r, g, b) the detected (or supplied) background colour;
      "n_marked"     count of pixels that differ from the background by > threshold per channel;
      "bbox"         (left, top, right, bottom) tight box of the marked pixels (right/bottom exclusive),
                     or None when nothing was marked;
      "size"         (width, height) of the carrier;
      "png_bytes"    a 1-bit-look PNG, black where marked on white, for eye/OCR reading (None if nothing
                     marked);
      "fraction"     n_marked / total pixels (a sanity read: a hidden message marks a small fraction).

    None when Pillow is absent, the bytes are not an image, or the image is implausibly large. When
    `background` is given (an (r,g,b) tuple) it is used instead of the detected dominant colour."""
    im = _load(image)
    if im is None:
        return None
    w, h = im.width, im.height

    try:
        import numpy as np
    except Exception:
        np = None

    if np is not None:
        arr = np.asarray(im, dtype=np.int16).reshape(h * w, 3)
        if background is None:
            # dominant colour = the most frequent exact RGB triple
            packed = (arr[:, 0].astype(np.int64) << 16) | (arr[:, 1].astype(np.int64) << 8) | arr[:, 2]
            vals, counts = np.unique(packed, return_counts=True)
            bg_packed = int(vals[int(counts.argmax())])
            bg = ((bg_packed >> 16) & 255, (bg_packed >> 8) & 255, bg_packed & 255)
        else:
            bg = tuple(int(c) for c in background)
        diff = np.abs(arr - np.asarray(bg, dtype=np.int16)).max(axis=1)
        mask = diff > threshold
        n_marked = int(mask.sum())
        mask2d = mask.reshape(h, w)
    else:
        px = list(im.getdata())
        if background is None:
            from collections import Counter
            bg = Counter(px).most_common(1)[0][0]
        else:
            bg = tuple(int(c) for c in background)
        mask_flat = [max(abs(p[0] - bg[0]), abs(p[1] - bg[1]), abs(p[2] - bg[2])) > threshold for p in px]
        n_marked = sum(mask_flat)
        mask2d = [mask_flat[y * w:(y + 1) * w] for y in range(h)]

    # bounding box + rendered reveal
    bbox = None
    png_bytes = None
    if n_marked:
        from PIL import Image
        if np is not None:
            ys, xs = np.nonzero(mask2d)
            bbox = (int(xs.min()), int(ys.min()), int(xs.max()) + 1, int(ys.max()) + 1)
            out = np.where(mask2d, 0, 255).astype("uint8")
            rev = Image.fromarray(out, mode="L")
        else:
            xs = [x for y in range(h) for x in range(w) if mask2d[y][x]]
            ys = [y for y in range(h) for x in range(w) if mask2d[y][x]]
            bbox = (min(xs), min(ys), max(xs) + 1, max(ys) + 1)
            rev = Image.new("L", (w, h), 255)
            rev.putdata([0 if mask2d[y][x] else 255 for y in range(h) for x in range(w)])
        buf = io.BytesIO()
        rev.save(buf, "PNG")
        png_bytes = buf.getvalue()

    return {"background": tuple(int(c) for c in bg), "n_marked": n_marked, "bbox": bbox,
            "size": (w, h), "png_bytes": png_bytes,
            "fraction": n_marked / float(w * h) if w * h else 0.0}


if __name__ == "__main__":
    import sys
    if not sys.argv[1:] or any(a in ("-h", "--help") for a in sys.argv[1:]):
        print("usage: pixel_reveal.py [--threshold=N] <image> [...]",
              file=sys.stderr if not sys.argv[1:] else sys.stdout)
        raise SystemExit(2 if not sys.argv[1:] else 0)
    thr = 0
    paths = []
    for a in sys.argv[1:]:
        if a.startswith("--threshold="):
            thr = int(a.split("=", 1)[1])
        else:
            paths.append(a)
    for path in paths:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            r = reveal_near_background(raw, threshold=thr)
        except (OSError, ValueError, TypeError, OverflowError) as exc:
            print(f"pixel_reveal.py: {exc}", file=sys.stderr)
            raise SystemExit(2)
        if not r:
            print(f"{path}: not an image / Pillow missing")
            continue
        print(f"{path}: bg={r['background']} marked={r['n_marked']} "
              f"({r['fraction']*100:.3f}%) bbox={r['bbox']} size={r['size']}")
        if r["png_bytes"]:
            out = path + ".revealed.png"
            with open(out, "wb") as fh:
                fh.write(r["png_bytes"])
            print(f"{path}: revealed image -> {out}")
