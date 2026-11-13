#!/usr/bin/env python3
"""Offline tests of the wave-121 never-wrong stego gap: LSB planes of a GIF (palette indices) and a
WebP, fed to the SAME self-validating container reader as the PNG/BMP path (ticket #9).

    solvers/toolkits/carve_stego.py       gif_pixels() / webp_pixels() (the px dict shape of png_pixels)
    solvers/toolkits/stego_containers.py  _pixels() now accepts gif/webp -> read_image() reads them

  .venv/bin/python tests/test_wave121_palette_webp_lsb.py

No network and no token. Every fixture is synthetic and made here, in memory, with Pillow. The one
invariant under test is unchanged: a value is PLAIN only when a stored length/CRC (or a complete
checksum-carrying file structure) self-validates it. A random carrier, a corrupt CRC, a lossy WebP
whose low bits the codec re-quantised, or a structure-only (forgeable) magic -> None or an unsure
candidate, NEVER plain. The new code only widens which containers the existing reader can see pixels
of; it adds no new way to claim PLAIN. The flag is never used or submitted.

Prints one line per check and `ok` at the end; exits 1 when a check fails. When Pillow (or its WebP
codec) is missing the affected checks are skipped and the run still passes (exit 0), like the jar
sections of tests/test_day20_web_java.py.
"""
import gzip
import io
import os
import random
import struct
import sys
import tempfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_wave121_"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import carve_stego as cs            # noqa: E402
import stego_containers as sc       # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def _crc(b):
    return zlib.crc32(b) & 0xFFFFFFFF


def container_be(payload):
    return struct.pack(">I", len(payload)) + struct.pack(">I", _crc(payload)) + payload


def container_le(payload):
    return struct.pack("<I", len(payload)) + struct.pack("<I", _crc(payload)) + payload


# ---- fixtures (made here, in memory) ---------------------------------------------------------------

def _have_pillow():
    try:
        import PIL  # noqa: F401
        from PIL import Image  # noqa: F401
        return True
    except Exception:
        return False


def _have_webp():
    try:
        from PIL import features
        return bool(features.check("webp"))
    except Exception:
        return False


def _set_lsbs(raw: bytearray, payload: bytes):
    """Write the MSB-first bit stream of `payload` into the low bit of raw[0], raw[1], ... -- what
    zsteg calls b1,...,msb,xy: exactly the stream carve_stego.lsb_extract reads back."""
    bits = [(b >> (7 - i)) & 1 for b in payload for i in range(8)]
    if len(bits) > len(raw):
        raise ValueError("payload does not fit the carrier")
    for i, bit in enumerate(bits):
        raw[i] = (raw[i] & 0xFE) | bit


def lsb_gif(payload: bytes, w=96, h=64, seed=5) -> bytes:
    """A GIF whose palette INDICES' least significant bits, row by row, spell `payload` (what zsteg
    calls b1,index / b1,p). A full 256-entry distinct palette and optimize=False keep Pillow from
    remapping the indices, so the stored samples are exactly what we wrote."""
    from PIL import Image
    rnd = random.Random(seed)
    raw = bytearray(rnd.randrange(256) for _ in range(w * h))
    _set_lsbs(raw, payload)
    im = Image.frombytes("P", (w, h), bytes(raw))
    im.putpalette([v for i in range(256) for v in (i, (i * 7) % 256, (i * 13) % 256)])
    out = io.BytesIO()
    im.save(out, "GIF", optimize=False)
    return out.getvalue()


def noise_gif(w=96, h=64, seed=9) -> bytes:
    from PIL import Image
    rnd = random.Random(seed)
    im = Image.frombytes("P", (w, h), bytes(rnd.randrange(256) for _ in range(w * h)))
    im.putpalette([v for i in range(256) for v in (i, (i * 7) % 256, (i * 13) % 256)])
    out = io.BytesIO()
    im.save(out, "GIF", optimize=False)
    return out.getvalue()


def lsb_webp(payload: bytes, w=96, h=64, seed=5, lossless=True, quality=80) -> bytes:
    """An RGB WebP whose channel bytes' low bits (R then G then B, row by row) spell `payload`.
    lossless keeps them; lossy re-quantises them (a never-wrong control: the payload is destroyed)."""
    from PIL import Image
    rnd = random.Random(seed)
    raw = bytearray(rnd.randrange(256) for _ in range(w * h * 3))
    _set_lsbs(raw, payload)
    im = Image.frombytes("RGB", (w, h), bytes(raw))
    out = io.BytesIO()
    im.save(out, "WEBP", lossless=lossless, quality=quality)
    return out.getvalue()


def noise_webp(w=96, h=64, seed=9) -> bytes:
    from PIL import Image
    rnd = random.Random(seed)
    im = Image.frombytes("RGB", (w, h), bytes(rnd.randrange(256) for _ in range(w * h * 3)))
    out = io.BytesIO()
    im.save(out, "WEBP", lossless=True)
    return out.getvalue()


# ---- gif_pixels / webp_pixels: the px dict shape ---------------------------------------------------

def test_pixel_shape():
    if not _have_pillow():
        check("wave121 pixel shape SKIP (Pillow unavailable)", True)
        return
    pl = b"PROVEN_BY_CRC_payload_0123456789"
    g = cs.gif_pixels(lsb_gif(container_be(pl)))
    check("gif_pixels: mode P, one channel, one byte per sample, right size",
          g is not None and g["mode"] == "P" and g["channels"] == 1 and g["width"] == 96 and g["height"] == 64
          and len(g["data"]) == 96 * 64, g)
    check("gif_pixels: a non-GIF -> None", cs.gif_pixels(b"not a gif at all") is None)
    check("gif_pixels: palette carried back", g is not None and g.get("palette"))
    if _have_webp():
        w = cs.webp_pixels(lsb_webp(container_be(pl)))
        check("webp_pixels: mode RGB, three channels, three bytes per sample, right size",
              w is not None and w["mode"] in ("RGB", "RGBA") and w["channels"] == len(w["mode"])
              and len(w["data"]) == 96 * 64 * w["channels"], w)
        check("webp_pixels: a non-WebP (a RIFF/WAVE) -> None",
              cs.webp_pixels(b"RIFF" + struct.pack("<I", 4) + b"WAVE") is None)
    else:
        check("webp_pixels SKIP (no WebP codec)", True)


# ---- read_image (stego_containers, the #9 reader) over GIF and WebP --------------------------------

def test_gif_read_image():
    if not _have_pillow():
        check("wave121 GIF read_image SKIP (Pillow unavailable)", True)
        return
    pl = b"PROVEN_BY_CRC_payload_0123456789"
    r = sc.read_image(lsb_gif(container_be(pl)))
    check("GIF read_image: a CRC-headed payload in the palette LSBs -> plain", r["plain"] == pl, r)
    r = sc.read_image(lsb_gif(container_le(pl)))
    check("GIF read_image: a little-endian CRC container also -> plain", r["plain"] == pl, r)
    # a complete gzip file (checksum kind) embedded in the LSBs -> plain (file magic)
    gz = gzip.compress(b"embedded gzip through the gif palette lsb channel")
    r = sc.read_image(lsb_gif(gz))
    check("GIF read_image: an embedded gzip file -> plain (file magic, checksum kind)",
          r["plain"] is not None and cs.sniff(r["plain"]) == "gzip", r)
    # never-wrong: a random palette image has no self-validating payload -> None
    r = sc.read_image(noise_gif())
    check("GIF read_image: a random palette image -> None (no plain)", r["plain"] is None, r)
    # never-wrong: a corrupt CRC -> None
    bad = bytearray(container_be(pl))
    bad[7] ^= 0x01
    r = sc.read_image(lsb_gif(bytes(bad)))
    check("GIF read_image: a corrupt CRC -> None (no plain)", r["plain"] is None, r)
    # H12: a forged RIFF/WAVE (self-declared length, no payload checksum) in the LSBs -> not plain
    forged_riff = b"RIFF" + struct.pack("<I", 44) + b"WAVE" + b"\x00" * 40
    r = sc.read_image(lsb_gif(forged_riff))
    check("GIF read_image H12: a forged RIFF in the LSBs -> no plain (structure-only, no checksum)",
          r["plain"] is None, r)


def test_webp_read_image():
    if not (_have_pillow() and _have_webp()):
        check("wave121 WebP read_image SKIP (Pillow/WebP unavailable)", True)
        return
    pl = b"PROVEN_BY_CRC_payload_0123456789"
    r = sc.read_image(lsb_webp(container_be(pl)))
    check("WebP read_image: a CRC-headed payload in the lossless LSBs -> plain", r["plain"] == pl, r)
    gz = gzip.compress(b"embedded gzip through the lossless webp lsb channel")
    r = sc.read_image(lsb_webp(gz))
    check("WebP read_image: an embedded gzip file -> plain (file magic)",
          r["plain"] is not None and cs.sniff(r["plain"]) == "gzip", r)
    # never-wrong: random lossless WebP -> None
    r = sc.read_image(noise_webp())
    check("WebP read_image: a random image -> None (no plain)", r["plain"] is None, r)
    # never-wrong: corrupt CRC -> None
    bad = bytearray(container_be(pl))
    bad[7] ^= 0x01
    r = sc.read_image(lsb_webp(bytes(bad)))
    check("WebP read_image: a corrupt CRC -> None (no plain)", r["plain"] is None, r)
    # never-wrong: a LOSSY WebP re-quantises the low bits, so the CRC no longer validates -> None
    r = sc.read_image(lsb_webp(container_be(pl), lossless=False, quality=80))
    check("WebP read_image: a lossy WebP (codec re-quantised the LSBs) -> None (no plain)",
          r["plain"] is None, r)


# ---- the carve walker (carve_stego.scan / lsb_scan) sees GIF/WebP pixels too -----------------------

def test_carve_scan_sees_gif_webp():
    if not _have_pillow():
        check("wave121 carve scan SKIP (Pillow unavailable)", True)
        return
    gz = gzip.compress(b"a file hidden in the palette LSBs of a gif, found by scan()")
    px = cs.gif_pixels(lsb_gif(gz))
    hits = [h for h in cs.lsb_scan(px) if h["what"] == "file" and h["kind"] == "gzip"]
    check("lsb_scan: a gzip file in a GIF's palette LSBs is found", bool(hits), hits[:1])
    found = [h for h in cs.scan("hidden.gif", lsb_gif(gz), deep=True)
             if h.get("channel") == "lsb" or (isinstance(h.get("method"), str) and "P " in h["method"])]
    check("scan: the GIF LSB channel is walked (a hidden file surfaces)", bool(found), len(found))
    # a clean (noise) GIF yields no LSB file finding
    clean = [h for h in cs.lsb_scan(cs.gif_pixels(noise_gif())) if h["what"] == "file"]
    check("lsb_scan: a noise GIF yields no file payload", not clean, clean[:1])
    if _have_webp():
        pw = cs.webp_pixels(lsb_webp(gz))
        hw = [h for h in cs.lsb_scan(pw) if h["what"] == "file" and h["kind"] == "gzip"]
        check("lsb_scan: a gzip file in a lossless WebP's LSBs is found", bool(hw), hw[:1])
    else:
        check("WebP lsb_scan SKIP (no WebP codec)", True)


# ---- the shared never-wrong rules still hold (non-image, non-pixel) --------------------------------

def test_non_image():
    r = sc.read_image(b"not an image at all")
    check("read_image: a non-image -> None with a note", r["plain"] is None and bool(r["notes"]), r)
    # _pixels must not mis-route a JPEG (no pixel reader for it here) -> None
    check("_pixels: a kind with no reader (text) -> None", sc._pixels(b"just some ascii text here") is None)


def main():
    import shutil
    try:
        for t in (test_pixel_shape, test_gif_read_image, test_webp_read_image,
                  test_carve_scan_sees_gif_webp, test_non_image):
            try:
                t()
            except Exception as e:
                import traceback
                check(f"{t.__name__} ran", False, f"{type(e).__name__}: {e} | {traceback.format_exc()[-500:]}")
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED[:8]))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
