#!/usr/bin/env python3
"""Offline tests of solvers/common/image_repair.py::fix_magic -- signature/header repair.

  .venv/bin/python tests/test_image_magic_repair.py

Covers the 2024 "Magical Bytes 1/2" archetypes and the generic junk-prefix case:
  * junk bytes prepended before an intact PNG / JPEG / GIF signature (carve the real start);
  * a GIF magic whose bytes had their nibbles swapped (Magical Bytes 2: 47 49 46 38 -> 74 94 64 83);
  * junk prefix AND a nibble-swapped magic together (the dd-skip-then-fix-magic combo);
  * never-wrong refusals: an intact image, and non-image garbage, both yield None.

Fixtures are synthetic (Pillow writes real PNG/GIF/JPEG); the whole file is skipped with a pass when
Pillow is absent. No network, no token.
"""
import io
import os
import struct
import sys
import random
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))
import image_repair as ir       # noqa: E402

FAILED = []
random.seed(99)


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


def make_gif(w=20, h=12):
    from PIL import Image
    im = Image.new("P", (w, h))
    im.putpalette(bytes(random.randrange(256) for _ in range(768)))
    im.putdata([random.randrange(128) for _ in range(w * h)])
    buf = io.BytesIO()
    im.save(buf, "GIF")
    return buf.getvalue()


def make_png(w=16, h=10):
    from PIL import Image
    im = Image.new("RGB", (w, h))
    im.putdata([(random.randrange(256), random.randrange(256), random.randrange(256)) for _ in range(w * h)])
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def make_jpeg(w=24, h=16):
    from PIL import Image
    im = Image.new("L", (w, h))
    im.putdata([random.randrange(256) for _ in range(w * h)])
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=80)
    return buf.getvalue()


def nibswap_prefix(data, n):
    out = bytearray(data)
    for i in range(n):
        out[i] = ((out[i] & 0x0F) << 4) | (out[i] >> 4)
    return bytes(out)


def opens(data):
    from PIL import Image
    im = Image.open(io.BytesIO(data))
    im.load()
    return (im.width, im.height)


# ---------------------------------------------------------------------------------------------------
def test_png_junk_prefix():
    png = make_png(16, 10)
    junk = bytes([random.randrange(256) for _ in range(38)])     # "Magical Bytes 1": 38 junk bytes
    r = ir.fix_magic(junk + png)
    check("png: junk prefix detected and stripped",
          r is not None and r["kind"] == "png" and r["method"] == "strip_prefix" and r["junk_prefix_len"] == 38, r)
    check("png: fixed bytes equal the original clean PNG", bool(r) and r["fixed_bytes"] == png, None)
    if r:
        check("png: fixed bytes re-open at the right size", opens(r["fixed_bytes"]) == (16, 10), opens(r["fixed_bytes"]))


def test_jpeg_junk_prefix():
    jpg = make_jpeg(24, 16)
    r = ir.fix_magic(b"\x00\x01GARBAGE" + jpg)
    check("jpeg: junk prefix detected and stripped",
          r is not None and r["kind"] == "jpeg" and r["method"] == "strip_prefix", r)
    check("jpeg: fixed bytes equal the original clean JPEG", bool(r) and r["fixed_bytes"] == jpg, None)


def test_gif_junk_prefix():
    gif = make_gif(20, 12)
    r = ir.fix_magic(bytes(13) + gif)                            # 13 junk bytes before an intact GIF
    check("gif: junk prefix detected and stripped",
          r is not None and r["kind"] == "gif" and r["method"] == "strip_prefix" and r["junk_prefix_len"] == 13, r)
    check("gif: fixed bytes equal the original clean GIF", bool(r) and r["fixed_bytes"] == gif, None)


def test_gif_nibble_swapped_magic():
    # "Magical Bytes 2": the GIF magic ships nibble-swapped (47 49 46 38 39 61 -> 74 94 64 83 93 16).
    gif = make_gif(20, 12)
    bad = nibswap_prefix(gif, 6)
    check("gif: the corrupted magic really is nibble-swapped (74 94 64 83 ...)",
          bad[:4] == bytes([0x74, 0x94, 0x64, 0x83]), bad[:6].hex())
    r = ir.fix_magic(bad)
    check("gif: nibble-swapped magic repaired",
          r is not None and r["kind"] == "gif" and r["method"] == "nibble_swap" and r["junk_prefix_len"] == 0, r)
    check("gif: repaired bytes equal the original clean GIF", bool(r) and r["fixed_bytes"] == gif, None)
    if r:
        check("gif: repaired bytes re-open at the right size", opens(r["fixed_bytes"]) == (20, 12), opens(r["fixed_bytes"]))


def test_gif_junk_and_nibble_swapped_magic():
    # The full 2024 combo: a junk prefix AND a nibble-swapped magic (dd skip=13, then fix the magic).
    gif = make_gif(20, 12)
    bad = bytes(13) + nibswap_prefix(gif, 6)
    r = ir.fix_magic(bad)
    check("gif: junk prefix + nibble-swapped magic repaired together",
          r is not None and r["kind"] == "gif" and r["method"] == "strip_and_nibble_swap"
          and r["junk_prefix_len"] == 13, r)
    check("gif: combined repair reproduces the original clean GIF", bool(r) and r["fixed_bytes"] == gif, None)


def test_intact_image_is_left_alone():
    for name, data in (("png", make_png()), ("jpeg", make_jpeg()), ("gif", make_gif())):
        check(f"{name}: an intact image needs no magic repair -> None", ir.fix_magic(data) is None, name)


def test_garbage_is_refused():
    check("garbage: random bytes with no embedded signature -> None",
          ir.fix_magic(bytes(random.randrange(256) for _ in range(200))) is None)
    check("garbage: too short -> None", ir.fix_magic(b"\x00\x01\x02") is None)
    check("garbage: non-bytes -> None", ir.fix_magic(None) is None)
    # a near-signature that does NOT structurally validate must not be 'repaired'
    check("garbage: GIF magic but truncated body (no clean parse) -> None",
          ir.fix_magic(b"GIF89a" + bytes(4)) is None)


def main():
    if not have_pil():
        check("(skipped: Pillow not installed)", True)
        print("ok")
        return 0
    tests = [test_png_junk_prefix, test_jpeg_junk_prefix, test_gif_junk_prefix,
             test_gif_nibble_swapped_magic, test_gif_junk_and_nibble_swapped_magic,
             test_intact_image_is_left_alone, test_garbage_is_refused]
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
