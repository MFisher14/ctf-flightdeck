#!/usr/bin/env python3
"""Offline tests of solvers/common/image_repair.py: JPEG/GIF structural dimension repair validated by
a clean decode.

  .venv/bin/python tests/test_image_repair.py

No network and no token. Every fixture is synthetic and built here (Pillow writes real baseline JPEGs
and real GIFs; a check is skipped with a pass if Pillow is absent). Prints one line per check and `ok`
at the end; exits 1 when a check fails.

The never-wrong focus is the AMBIGUOUS case, which the fixtures exercise directly:
  * a JPEG / GIF with BOTH dimension axes zeroed -> the decode pins only width*height, every factor
    pair is equally clean -> None (never "pick one");
  * an irreparably corrupt / truncated stream -> no clean decode -> None;
  * an intact file -> nothing to repair -> None.
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


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def have_pil() -> bool:
    try:
        import PIL  # noqa: F401
        return True
    except Exception:
        return False


random.seed(1234)


def make_jpeg(w, h, mode="L", subsampling=0, quality=80) -> bytes:
    from PIL import Image
    if mode == "L":
        im = Image.new("L", (w, h))
        im.putdata([random.randrange(256) for _ in range(w * h)])
    else:
        im = Image.new("RGB", (w, h))
        im.putdata([(random.randrange(256), random.randrange(256), random.randrange(256)) for _ in range(w * h)])
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=quality, subsampling=subsampling, optimize=False)
    return buf.getvalue()


def make_gif(w, h) -> bytes:
    from PIL import Image
    im = Image.new("P", (w, h))
    im.putpalette([i % 256 for _ in range(256) for i in (0, 1, 2)][:768] or list(range(256)) * 3)
    im.putpalette(bytes(random.randrange(256) for _ in range(768)))
    im.putdata([random.randrange(256) for _ in range(w * h)])
    buf = io.BytesIO()
    im.save(buf, "GIF")
    return buf.getvalue()


def build_raw_gif(canvas_w, canvas_h, iw, ih, n_index_codes, mcs=7):
    """A hand-built GIF89a whose LZW code stream emits exactly `n_index_codes` color indices before
    EOI (one 8-bit code per index, mcs=7, so every code is byte-aligned). When n_index_codes != iw*ih
    the stream is NON-MINIMAL -- it decodes cleanly to EOI yet carries more indices than the image has
    pixels, the adversarial stego case Pillow cannot build. GCT is present (128 colors), so mcs=7 is
    conformant and real decoders open the file."""
    hdr = b"GIF89a"
    packed = 0x80 | (6 << 4) | 6                       # GCT flag, color res, GCT size 6 => 128 entries
    lsd = struct.pack("<HHBBB", canvas_w, canvas_h, packed, 0, 0)
    gct = bytes(384)                                   # 128 * 3 RGB
    imgdesc = bytes([0x2C]) + struct.pack("<HHHHB", 0, 0, iw, ih, 0x00)
    clear, end = 1 << mcs, (1 << mcs) + 1
    codes = bytes([clear]) + bytes([0]) * n_index_codes + bytes([end])
    data = bytes([mcs]) + bytes([len(codes)]) + codes + bytes([0x00])
    return hdr + lsd + gct + imgdesc + data + bytes([0x3B])


RAW_GIF_DESC_OFF = 6 + 7 + 384                         # header + logical screen descriptor + GCT


def zero_jpeg_height(data):
    info = ir._parse_jpeg(data)
    out = bytearray(data)
    struct.pack_into(">H", out, info["sof_off"] + 4 + 1, 0)
    return bytes(out), info


def zero_jpeg_width(data):
    info = ir._parse_jpeg(data)
    out = bytearray(data)
    struct.pack_into(">H", out, info["sof_off"] + 4 + 3, 0)
    return bytes(out), info


def zero_jpeg_both(data):
    info = ir._parse_jpeg(data)
    out = bytearray(data)
    struct.pack_into(">H", out, info["sof_off"] + 4 + 1, 0)
    struct.pack_into(">H", out, info["sof_off"] + 4 + 3, 0)
    return bytes(out)


# ---------------------------------------------------------------------------------------------------
def test_jpeg_recover_height():
    data = make_jpeg(40, 24, mode="L")               # grayscale -> MCU 8x8, 40x24 is MCU-aligned
    bad, info = zero_jpeg_height(data)
    r = ir.fix_jpeg(bad)
    check("jpeg: zeroed SOF height recovered", r is not None and r["width"] == 40 and r["height"] == 24, r)
    check("jpeg: recovery is flagged NOT pixel-exact (MCU-grid granularity)", bool(r) and r["exact"] is False, r)
    check("jpeg: bounds pin height to its MCU block (17..24), truth 24 inside",
          bool(r) and r["bounds"]["height"] == (17, 24) and r["bounds"]["width"] == (40, 40), r and r.get("bounds"))
    check("jpeg: 'height' is reported as the repaired axis", bool(r) and r["repaired"] == ["height"], r and r["repaired"])
    # the fixed bytes actually re-decode to the stated dimensions
    if r:
        from PIL import Image
        im = Image.open(io.BytesIO(r["fixed_bytes"]))
        im.load()
        check("jpeg: fixed bytes re-decode cleanly at (40, 24)", (im.width, im.height) == (40, 24), (im.width, im.height))
        # and our own strict decoder confirms the patched grid
        info2 = ir._parse_jpeg(r["fixed_bytes"])
        spec, sx, sy = ir._jpeg_blockspec(info2)
        t, clean = ir._jpeg_total_mcus(r["fixed_bytes"], info2, spec)
        check("jpeg: strict decode of fixed bytes is clean and matches the grid", clean and t == (40 // 8) * (24 // 8), (t, clean))


def test_jpeg_recover_width():
    data = make_jpeg(40, 24, mode="L")
    bad, info = zero_jpeg_width(data)
    r = ir.fix_jpeg(bad)
    check("jpeg: zeroed SOF width recovered", r is not None and r["width"] == 40 and r["height"] == 24, r)
    check("jpeg: 'width' is reported as the repaired axis", bool(r) and r["repaired"] == ["width"], r and r["repaired"])


def test_jpeg_color_subsampled():
    # 4:2:0 subsampling -> MCU 16x16; 32x32 is aligned so recovery is exact.
    data = make_jpeg(32, 32, mode="RGB", subsampling=2)
    info = ir._parse_jpeg(data)
    bs = ir._jpeg_blockspec(info)
    if bs is None or (bs[1], bs[2]) != (16, 16):
        check("jpeg(color): fixture is 4:2:0 (MCU 16x16); skipped otherwise", True, bs and (bs[1], bs[2]))
        return
    bad, _ = zero_jpeg_height(data)
    r = ir.fix_jpeg(bad)
    check("jpeg(color 4:2:0): zeroed height recovered at 16px MCU granularity",
          r is not None and r["width"] == 32 and r["height"] == 32 and r["mcu_granularity"] == (16, 16), r)
    check("jpeg(color 4:2:0): bounds pin height to its 16px block (17..32)",
          bool(r) and r["bounds"]["height"] == (17, 32), r and r.get("bounds"))


def test_jpeg_nonaligned_is_grid_bounded_not_exact():
    # The sub-MCU limitation, exercised head-on: a true height of 20 (grayscale, step 8) is NOT a whole
    # number of MCUs, so entropy decode cannot resolve it below its block. The repair yields the MCU
    # EXTENT (24), flags exact=False, and reports bounds (17, 24) that CONTAIN the true 20 -- it never
    # claims 24 as a proven pixel count.
    data = make_jpeg(40, 20, mode="L")
    bad, _ = zero_jpeg_height(data)
    r = ir.fix_jpeg(bad)
    check("jpeg: non-aligned true height recovered to its MCU extent (24), not claimed exact",
          r is not None and r["height"] == 24 and r["exact"] is False, r)
    check("jpeg: bounds (17..24) contain the true height 20 (never a wrong exact claim)",
          bool(r) and r["bounds"]["height"][0] <= 20 <= r["bounds"]["height"][1], r and r.get("bounds"))


def test_jpeg_both_zero_ambiguous():
    # BOTH axes zeroed: the entropy decode pins only mpl*rows == total; 40x24 grayscale -> 15 MCUs,
    # which factors several ways -> fix_jpeg must refuse (never pick one).
    data = make_jpeg(40, 24, mode="L")
    bad = zero_jpeg_both(data)
    r = ir.fix_jpeg(bad)
    check("jpeg: BOTH dimensions zeroed is ambiguous -> None", r is None, r)


def test_jpeg_both_zero_square_still_ambiguous():
    data = make_jpeg(32, 32, mode="L")               # 16 MCUs -> (4,4) and (2,8) and (1,16)... -> ambiguous
    bad = zero_jpeg_both(data)
    r = ir.fix_jpeg(bad)
    check("jpeg: BOTH zeroed on a square image is still ambiguous -> None", r is None, r)


def test_jpeg_truncated_irreparable():
    data = make_jpeg(40, 24, mode="L")
    info = ir._parse_jpeg(data)
    # cut the entropy stream in half and drop the EOI: no clean decode is possible
    cut = info["scan_start"] + max(4, (len(data) - info["scan_start"]) // 2)
    bad = bytearray(data[:cut])
    struct.pack_into(">H", bad, info["sof_off"] + 4 + 1, 0)         # also zero the height
    r = ir.fix_jpeg(bytes(bad))
    check("jpeg: truncated entropy (no clean decode) -> None", r is None, r)


def test_jpeg_intact_nothing_to_fix():
    data = make_jpeg(40, 24, mode="L")
    r = ir.fix_jpeg(data)
    check("jpeg: an intact JPEG needs no repair -> None", r is None, r)


def test_jpeg_garbage():
    check("jpeg: non-JPEG bytes -> None", ir.fix_jpeg(b"not a jpeg at all" * 8) is None)
    check("jpeg: empty -> None", ir.fix_jpeg(b"") is None)


# ---------------------------------------------------------------------------------------------------
def test_gif_lzw_count_matches():
    data = make_gif(37, 19)                           # odd dims, so N=703 is nontrivial
    st = ir._gif_structure(data)
    check("gif: parsed to a single image block", st is not None and len(st["images"]) == 1, st)
    if st and st["images"]:
        img = st["images"][0]
        check("gif: LZW decodes to exactly width*height indices (count validated)",
              img["clean"] and img["pixels"] == 37 * 19, (img.get("pixels"), img.get("clean")))


def test_gif_recover_screen_descriptor():
    data = make_gif(37, 19)
    out = bytearray(data)
    struct.pack_into("<HH", out, 6, 0, 0)             # corrupt the logical-screen descriptor
    r = ir.fix_gif(bytes(out))
    check("gif: corrupted screen descriptor recovered (frame dims proven by LZW)",
          r is not None and r["width"] == 37 and r["height"] == 19, r)
    check("gif: GIF dimensions are proven EXACT (LZW has no padding ambiguity)",
          bool(r) and r["exact"] is True and r["bounds"] == {"width": (37, 37), "height": (19, 19)}, r)
    check("gif: the screen descriptor was the repaired field",
          bool(r) and ("screen_width" in r["repaired"] and "screen_height" in r["repaired"]), r and r["repaired"])
    if r and have_pil():
        from PIL import Image
        im = Image.open(io.BytesIO(r["fixed_bytes"]))
        im.load()
        check("gif: fixed bytes re-open and load cleanly", True)


def test_gif_recover_image_height():
    data = make_gif(37, 19)
    st = ir._gif_structure(data)
    img = st["images"][0]
    out = bytearray(data)
    struct.pack_into("<H", out, img["desc_off"] + 1 + 2 + 2 + 2, 0)   # zero image-descriptor height
    r = ir.fix_gif(bytes(out))
    check("gif: zeroed image-descriptor height recovered via N/width",
          r is not None and r["width"] == 37 and r["height"] == 19 and "image_height" in r["repaired"], r)
    # The value is right, but it was DERIVED from N (the LZW index count), which is only an upper
    # bound on the true pixel count: there is no checksum to prove minimality, so a recovered axis is
    # never PLAIN-exact. (exact=False, bound (1, recovered); the true axis is at the top of the bound.)
    check("gif: a recovered image HEIGHT is not claimed exact (N is an upper bound, never a PLAIN count)",
          bool(r) and r["exact"] is False and r["bounds"]["height"] == (1, 19)
          and r["bounds"]["width"] == (37, 37), r and r.get("bounds"))


def test_gif_recover_image_width():
    data = make_gif(37, 19)
    st = ir._gif_structure(data)
    img = st["images"][0]
    out = bytearray(data)
    struct.pack_into("<H", out, img["desc_off"] + 1 + 2 + 2, 0)        # zero image-descriptor width
    r = ir.fix_gif(bytes(out))
    check("gif: zeroed image-descriptor width recovered via N/height",
          r is not None and r["width"] == 37 and r["height"] == 19 and "image_width" in r["repaired"], r)
    check("gif: a recovered image WIDTH is not claimed exact (N is an upper bound, never a PLAIN count)",
          bool(r) and r["exact"] is False and r["bounds"]["width"] == (1, 37)
          and r["bounds"]["height"] == (19, 19), r and r.get("bounds"))


def test_gif_recovered_image_axis_overcount_bound_not_exact():
    # THE never-wrong hole (GAP-IMGFIX), head-on: a GIF whose LZW decodes cleanly to EOI but carries
    # MORE indices (20) than the image's true pixel count (4*4 = 16) -- a non-minimal / overshooting
    # stream, routine for the adversarial stego carriers this module targets. The old code trusted N
    # as the pixel count and shipped a WRONG dimension flagged exact=True.
    intact = build_raw_gif(4, 4, 4, 4, n_index_codes=20)
    st = ir._gif_structure(intact)
    img = st["images"][0]
    check("gif(overcount): LZW decodes cleanly to N=20 while the true image is 4x4 (16 px)",
          img["clean"] and img["pixels"] == 20 and (img["width"], img["height"]) == (4, 4),
          (img.get("pixels"), img.get("clean")))
    if have_pil():
        from PIL import Image
        im = Image.open(io.BytesIO(intact)); im.load()
        check("gif(overcount): an independent decoder opens the intact file as 4x4 (ground truth)",
              (im.width, im.height) == (4, 4), (im.width, im.height))
    # both dims present but 4*4=16 != N=20 -> the both-present path correctly refuses (overcount caught)
    check("gif(overcount): both dims present but iw*ih != N -> None (overcount rejected, not 'fixed')",
          ir.fix_gif(intact) is None, ir.fix_gif(intact))
    # zero ONLY the image width: the module recovers 20/4 = 5, but 5 is NOT the true width (4). The
    # fix must flag exact=False and report the width as an upper bound, never a PLAIN count of 5.
    bad = bytearray(intact)
    struct.pack_into("<H", bad, RAW_GIF_DESC_OFF + 5, 0)       # zero iw (after sep, left, top)
    r = ir.fix_gif(bytes(bad))
    check("gif(overcount): a recovered axis over a non-minimal stream is NOT claimed exact",
          r is not None and r["exact"] is False, r)
    check("gif(overcount): the recovered width is an upper bound (1, recovered), never a PLAIN 5",
          bool(r) and r["bounds"]["width"] == (1, r["width"]) and r["width"] == 5
          and "image_width" in r["repaired"], r and r.get("bounds"))
    check("gif(overcount): the proven bound (1, 5) CONTAINS the true width 4 (never a wrong exact claim)",
          bool(r) and r["bounds"]["width"][0] <= 4 <= r["bounds"]["width"][1], r and r.get("bounds"))


def test_gif_both_zero_ambiguous():
    # BOTH frame axes zeroed: LZW pins only width*height = 512; many factor pairs -> None.
    data = make_gif(32, 16)
    st = ir._gif_structure(data)
    img = st["images"][0]
    out = bytearray(data)
    struct.pack_into("<HH", out, 6, 0, 0)                               # screen zeroed
    struct.pack_into("<HH", out, img["desc_off"] + 1 + 2 + 2, 0, 0)     # both frame axes zeroed
    r = ir.fix_gif(bytes(out))
    check("gif: BOTH frame dimensions zeroed is ambiguous -> None", r is None, r)


def test_gif_truncated_irreparable():
    data = make_gif(37, 19)
    st = ir._gif_structure(data)
    img = st["images"][0]
    # cut the file inside the LZW sub-blocks so the end code is never reached
    cut = img["desc_off"] + 20
    bad = bytearray(data[:cut]) + b"\x00\x3b"          # a bogus block terminator + trailer
    struct.pack_into("<HH", bad, 6, 0, 0)
    r = ir.fix_gif(bytes(bad))
    check("gif: truncated LZW stream (no clean decode) -> None", r is None, r)


def test_gif_intact_nothing_to_fix():
    data = make_gif(37, 19)
    r = ir.fix_gif(data)
    check("gif: an intact GIF needs no repair -> None", r is None, r)


def test_gif_garbage():
    check("gif: non-GIF bytes -> None", ir.fix_gif(b"GIF but not really" + b"\x00" * 20) is None)
    check("gif: empty -> None", ir.fix_gif(b"") is None)


def main() -> int:
    if not have_pil():
        check("(skipped: Pillow is not installed, no image fixtures can be built)", True)
        print("ok")
        return 0
    tests = [test_jpeg_recover_height, test_jpeg_recover_width, test_jpeg_color_subsampled,
             test_jpeg_nonaligned_is_grid_bounded_not_exact,
             test_jpeg_both_zero_ambiguous, test_jpeg_both_zero_square_still_ambiguous,
             test_jpeg_truncated_irreparable, test_jpeg_intact_nothing_to_fix, test_jpeg_garbage,
             test_gif_lzw_count_matches, test_gif_recover_screen_descriptor, test_gif_recover_image_height,
             test_gif_recover_image_width, test_gif_recovered_image_axis_overcount_bound_not_exact,
             test_gif_both_zero_ambiguous, test_gif_truncated_irreparable,
             test_gif_intact_nothing_to_fix, test_gif_garbage]
    for t in tests:
        try:
            t()
        except Exception as e:
            import traceback
            check(f"{t.__name__} ran", False, f"{type(e).__name__}: {e} | {traceback.format_exc()[-500:]}")
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED[:10]))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
