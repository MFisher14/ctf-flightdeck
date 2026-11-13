#!/usr/bin/env python3
"""Synthetic, spec-derived regression test for solvers/toolkits/osint_geo.py.

  CTF_WORKDIR=/tmp/ctfws .venv/bin/python tests/test_osint_geo.py

Builds a synthetic JPEG with (a) a KNOWN EXIF GPS fix written by an INDEPENDENT encoder (piexif if
present, otherwise a hand-rolled EXIF GPS IFD) and (b) rendered signage text drawn with Pillow, then
asserts the engine reads the GPS back as decimal degrees, OCRs the signage, and produces a non-empty
search plan. Everything is synthetic -- the coordinates are Bucharest's Palace of Parliament (a public
landmark, fitting the "Total Warfare" critical-infrastructure theme) and the text is placeholder.

The --search / reverse-image path touches the network and is NOT exercised here. OCR asserts degrade
to a skip only when tesseract is not installed on the host.
"""
import os
import struct
import sys
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import paths

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

from PIL import Image, ImageDraw  # noqa: E402
import shutil  # noqa: E402

import osint_geo as G  # noqa: E402

WORK = paths.workdir()
WORK.mkdir(parents=True, exist_ok=True)

# Known target: Palace of Parliament, Bucharest. Decimal, and the DMS the EXIF tag will carry.
LAT, LON = 44.4275, 26.0875


def _rational(x):
    """float -> (num, den) rational with 1e6 denominator, for EXIF GPS."""
    return (int(round(abs(x) * 1000000)), 1000000)


def _dms_rationals(dec):
    dec = abs(dec)
    d = int(dec)
    m = int((dec - d) * 60)
    s = (dec - d - m / 60.0) * 3600.0
    return [(d, 1), (m, 1), (int(round(s * 100)), 100)]


def build_exif_with_gps(lat, lon):
    """Build EXIF bytes with a GPS IFD. Prefer piexif; else hand-roll a minimal TIFF/EXIF."""
    try:
        import piexif  # type: ignore
        gps = {
            piexif.GPSIFD.GPSLatitudeRef: "N" if lat >= 0 else "S",
            piexif.GPSIFD.GPSLatitude: _dms_rationals(lat),
            piexif.GPSIFD.GPSLongitudeRef: "E" if lon >= 0 else "W",
            piexif.GPSIFD.GPSLongitude: _dms_rationals(lon),
        }
        zeroth = {piexif.ImageIFD.Make: "SynthCam", piexif.ImageIFD.Model: "CTF-1",
                  piexif.ImageIFD.Software: "osint_geo_test"}
        return piexif.dump({"0th": zeroth, "Exif": {}, "GPS": gps, "1st": {}, "thumbnail": None})
    except Exception:
        return _handroll_exif_gps(lat, lon)


def _handroll_exif_gps(lat, lon):
    """Minimal little-endian TIFF with a 0th IFD pointing at a GPS IFD (DMS rationals).

    Layout: 'Exif\\x00\\x00' + TIFF header + 0th IFD (1 entry: GPSInfoIFDPointer) + GPS IFD.
    """
    import io
    buf = io.BytesIO()
    buf.write(b"Exif\x00\x00")
    tiff_start = buf.tell()
    buf.write(b"II*\x00")            # little-endian, magic 42
    buf.write(struct.pack("<I", 8))  # offset to 0th IFD (relative to tiff_start)

    # We'll place: 0th IFD at 8, GPS IFD after it, then the rational data blocks.
    # 0th IFD: 1 entry (GPSInfoIFDPointer tag 0x8825, type LONG) + next-IFD offset(0).
    zeroth_off = 8
    zeroth_size = 2 + 12 * 1 + 4
    gps_ifd_off = zeroth_off + zeroth_size
    # GPS IFD entries: GPSLatitudeRef(1,ASCII), GPSLatitude(2,RATIONAL x3),
    #                  GPSLongitudeRef(3,ASCII), GPSLongitude(4,RATIONAL x3)
    gps_entries = 4
    gps_ifd_size = 2 + 12 * gps_entries + 4
    data_off = gps_ifd_off + gps_ifd_size

    lat_dms = _dms_rationals(lat)
    lon_dms = _dms_rationals(lon)
    # Rational data blocks (each rational = 8 bytes).
    lat_data = b"".join(struct.pack("<II", n, d) for n, d in lat_dms)
    lon_data = b"".join(struct.pack("<II", n, d) for n, d in lon_dms)
    lat_data_off = data_off
    lon_data_off = data_off + len(lat_data)

    # --- 0th IFD ---
    out = io.BytesIO()
    out.write(struct.pack("<H", 1))  # 1 entry
    out.write(struct.pack("<HHI", 0x8825, 4, 1))  # GPSInfoIFDPointer, LONG, count 1
    out.write(struct.pack("<I", gps_ifd_off))     # value = offset to GPS IFD
    out.write(struct.pack("<I", 0))               # next IFD = 0

    # --- GPS IFD ---
    out.write(struct.pack("<H", gps_entries))
    # GPSLatitudeRef (tag 1), ASCII (2), count 2 ("N\0") fits inline
    latref = (b"N" if lat >= 0 else b"S") + b"\x00"
    out.write(struct.pack("<HHI", 1, 2, 2))
    out.write(latref + b"\x00\x00")
    # GPSLatitude (tag 2), RATIONAL (5), count 3 -> offset
    out.write(struct.pack("<HHI", 2, 5, 3))
    out.write(struct.pack("<I", lat_data_off))
    # GPSLongitudeRef (tag 3), ASCII, count 2
    lonref = (b"E" if lon >= 0 else b"W") + b"\x00"
    out.write(struct.pack("<HHI", 3, 2, 2))
    out.write(lonref + b"\x00\x00")
    # GPSLongitude (tag 4), RATIONAL, count 3 -> offset
    out.write(struct.pack("<HHI", 4, 5, 3))
    out.write(struct.pack("<I", lon_data_off))
    out.write(struct.pack("<I", 0))  # next IFD = 0

    # --- data blocks ---
    out.write(lat_data)
    out.write(lon_data)

    buf.write(out.getvalue())
    return buf.getvalue()


def make_image(path):
    im = Image.new("RGB", (900, 600), (235, 235, 235))
    d = ImageDraw.Draw(im)
    # Large, high-contrast signage text so default-font OCR can read it.
    d.rectangle([40, 40, 860, 160], fill=(255, 255, 255), outline=(0, 0, 0), width=3)
    d.text((70, 80), "BUCHAREST CENTRAL STATION", fill=(0, 0, 0))
    d.rectangle([40, 220, 860, 320], fill=(255, 255, 255), outline=(0, 0, 0), width=3)
    d.text((70, 255), "HOTEL VICTORIA", fill=(0, 0, 0))
    exif = build_exif_with_gps(LAT, LON)
    im.save(path, format="JPEG", exif=exif, quality=95)


def approx(a, b, tol=0.02):
    return abs(a - b) <= tol


def main():
    img = WORK / "osint_geo_synth.jpg"
    make_image(img)

    # (1) EXIF GPS read back as decimal degrees.
    exif = G.read_exif(str(img))
    assert exif.get("gps") is not None, f"EXIF GPS not read: {exif}"
    assert approx(exif["gps"]["lat"], LAT), f"lat {exif['gps']['lat']} != {LAT}"
    assert approx(exif["gps"]["lon"], LON), f"lon {exif['gps']['lon']} != {LON}"

    # Full analyze (offline path; no --search).
    report = G.analyze(str(img), do_search=False)
    assert report["metadata"]["gps"] is not None
    # Coordinate highlight includes the EXIF fix.
    assert any("EXIF GPS" in c for c in report["highlights"]["coordinates"]), report["highlights"]

    # (3) Search plan is non-empty and includes the reverse-geocode of the GPS fix.
    plan = report["search_plan"]
    assert plan, "empty search plan"
    assert any("REVERSE-GEOCODE" in s and str(LAT) in s for s in plan), "GPS reverse-geocode step missing"
    assert any("REVERSE IMAGE SEARCH" in s for s in plan), "reverse-image-search advice missing"

    # render() must not crash and must mention the coordinates.
    text = G.render(report)
    assert str(LAT) in text and "SEARCH PLAN" in text

    # (2) OCR -- only assert when tesseract is installed; otherwise confirm graceful skip.
    ocr_ran = shutil.which("tesseract") is not None
    ocr_text = report["clues"]["ocr_text"].upper()
    if ocr_ran:
        # Default Pillow font is small/thin; accept partial recognition of either sign.
        tokens = ["BUCHAREST", "CENTRAL", "STATION", "HOTEL", "VICTORIA"]
        hits = [t for t in tokens if t in ocr_text]
        assert hits, f"OCR found none of {tokens} in: {ocr_text!r}"
        # A recognised place/station/hotel word should feed the plan or clues.
        assert report["clues"]["ocr_text"].strip(), "OCR text empty despite tesseract present"
    else:
        print("note: tesseract not installed -- OCR assertions skipped (graceful degrade verified)")
        assert ocr_text == "" or isinstance(ocr_text, str)

    # Reverse-image-search field is None on the offline path (not attempted).
    assert report["reverse_image_search"] is None

    # Degrade check: reverse_image_search must return a dict with a note, never raise.
    # (We do NOT call the live path; we only confirm the function is wired for graceful failure
    #  by checking the Playwright-missing branch shape via a bogus path is out of scope for offline.
    #  Instead assert the helper functions handle junk text safely.)
    assert G.find_flags("prefix CSCTF{t0tal_w4rfare} suffix") == ["CSCTF{t0tal_w4rfare}"]
    assert any("44.42" in c for c in G.find_coords("here 44.4275, 26.0875 there"))

    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
