#!/usr/bin/env python3
"""OSINT geolocation assistant (the one OSINT capability the rehearsal lacked).

An OSINT geo challenge hands you a photo and asks *where was this taken*. The answer is almost never
in the bytes -- it is in the signage, the skyline, the EXIF GPS tag, a phone-number country code, a
language on a shopfront. This module does the offline, deterministic part of that work and then
writes the exact search plan a human (or an agent with web access) runs to pin the location:

  (1) METADATA -- EXIF GPS (decimal lat/long), camera make/model, software, and every timestamp,
      read with Pillow and, when present, cross-checked / backfilled with `exiftool`.
  (2) VISUAL CLUES (offline OCR) -- `tesseract` is run over the whole image and over tiles (small
      signage text is illegible at full-frame scale), the recognised text is de-duplicated, and
      candidate place names, languages/scripts, phone numbers (with country hints), and business /
      street words are pulled out of it.
  (3) SEARCH PLAN -- from the clues, the exact lookups to run are emitted as advice for the human:
      landmark / skyline search terms, a Nominatim reverse-geocode of any GPS fix or named place,
      which public sources answer which question (OpenStreetMap/Nominatim, Wayback, cert/DNS, a
      straight web search of the OCR'd names).
  (4) ONLINE ENRICHMENT (explicit --online only) -- one best clue is handed to the allow-listed,
      throttled, capped :mod:`osint_online` client for Nominatim or a narrow public search.  Results
      are ranked evidence, never an answer.  Image upload is deliberately left as a human action:
      a browser-driven reverse-image page fans out many opaque requests and cannot meet this lane's
      hard single-item/request-cap guarantee.

Nothing in the offline path (1-3) makes a network request. Only ``--online`` may touch the public
web, through the shared guard client. Flag-shaped (`CSCTF{...}`) and coordinate-shaped strings anywhere in
the metadata or OCR are highlighted.

CLI:

  .venv/bin/python solvers/toolkits/osint_geo.py <image>            # offline clues + search plan
  .venv/bin/python solvers/toolkits/osint_geo.py <image> --online   # one capped public enrichment
  .venv/bin/python solvers/toolkits/osint_geo.py <image> --json     # machine-readable report

Libraries: Pillow (required), tesseract + exiftool (shelled out when on PATH; skipped otherwise).
Online enrichment uses the stdlib guarded client and degrades to a clear decline rather than failing.
"""
import io
import json
import os
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

try:
    from PIL import Image, ImageOps  # type: ignore
    from PIL.ExifTags import TAGS, GPSTAGS  # type: ignore
except Exception:  # pragma: no cover - Pillow is a hard dep of this repo
    Image = None
    TAGS = GPSTAGS = {}


# =====================================================================================
#  Flag / coordinate highlighting
# =====================================================================================

FLAG_RE = flagfmt.TEXT  # CSCTF{...} and the rare bare CTF{...} outlier
# Decimal coords like "44.4268, 26.1025" or "44.4268N, 26.1025E"
DECIMAL_COORD_RE = re.compile(
    r"[-+]?\d{1,3}\.\d{3,}\s*[NSns]?\s*[,/ ]\s*[-+]?\d{1,3}\.\d{3,}\s*[EWew]?"
)
# DMS like 44°25'36.5"N 26°06'09.0"E
DMS_COORD_RE = re.compile(
    r"\d{1,3}[°]\s*\d{1,2}['′]\s*[\d.]+[\"″]?\s*[NSns]"
    r"[ ,]*\d{1,3}[°]\s*\d{1,2}['′]\s*[\d.]+[\"″]?\s*[EWew]"
)


def find_flags(text):
    return sorted(set(m.group(0) for m in FLAG_RE.finditer(text or "")))


def find_coords(text):
    out = []
    for rx in (DECIMAL_COORD_RE, DMS_COORD_RE):
        for m in rx.finditer(text or ""):
            s = m.group(0).strip()
            if s not in out:
                out.append(s)
    return out


# =====================================================================================
#  (1) Metadata -- EXIF via Pillow, backfilled with exiftool
# =====================================================================================

def _rational(v):
    """Pillow returns IFDRational / tuples for GPS values; coerce to float."""
    try:
        return float(v)
    except (TypeError, ValueError):
        try:
            return float(v[0]) / float(v[1])
        except Exception:
            return None


def _dms_to_decimal(dms, ref, axis=None):
    """(deg, min, sec) + hemisphere ref -> signed decimal degrees."""
    try:
        values = [_rational(dms[index]) for index in range(3)]
    except Exception:
        return None
    if any(value is None for value in values):
        return None
    if any(value != value or value in (float("inf"), float("-inf")) for value in values):
        return None
    d, m, s = values
    direction = str(ref).upper().strip() if ref is not None else ""
    allowed = {"N", "S"} if axis == "lat" else {"E", "W"} if axis == "lon" else {"N", "S", "E", "W"}
    limit = 90 if axis == "lat" else 180 if axis == "lon" else 180
    if direction not in allowed or d < 0 or not 0 <= m < 60 or not 0 <= s < 60 or d > limit:
        return None
    dec = d + m / 60.0 + s / 3600.0
    if dec > limit:
        return None
    if direction in ("S", "W"):
        dec = -dec
    return round(dec, 7)


def read_exif(path):
    """Return a dict of camera/software/timestamp fields plus decimal lat/long if GPS is present."""
    info = {"gps": None, "camera": {}, "software": None, "timestamps": {}, "raw_gps": {}}
    if Image is None:
        return info
    try:
        with Image.open(path) as im:
            exif = im.getexif()
    except Exception:
        return info
    if not exif:
        return info

    gps_ifd = {}
    for tag_id, value in exif.items():
        name = TAGS.get(tag_id, str(tag_id))
        if name == "GPSInfo":
            try:
                gi = exif.get_ifd(tag_id)
            except Exception:
                gi = value if isinstance(value, dict) else {}
            for gk, gv in (gi or {}).items():
                gps_ifd[GPSTAGS.get(gk, str(gk))] = gv
        elif name in ("Make", "Model", "LensModel", "BodySerialNumber"):
            info["camera"][name] = _clean(value)
        elif name in ("Software",):
            info["software"] = _clean(value)
        elif name in ("DateTime", "DateTimeOriginal", "DateTimeDigitized"):
            info["timestamps"][name] = _clean(value)

    if gps_ifd:
        info["raw_gps"] = {k: _clean(v) for k, v in gps_ifd.items()}
        lat = gps_ifd.get("GPSLatitude")
        lat_ref = gps_ifd.get("GPSLatitudeRef")
        lon = gps_ifd.get("GPSLongitude")
        lon_ref = gps_ifd.get("GPSLongitudeRef")
        if lat is not None and lon is not None:
            dlat = _dms_to_decimal(lat, lat_ref, "lat")
            dlon = _dms_to_decimal(lon, lon_ref, "lon")
            if dlat is not None and dlon is not None:
                info["gps"] = {"lat": dlat, "lon": dlon}
                alt = gps_ifd.get("GPSAltitude")
                if alt is not None:
                    info["gps"]["alt_m"] = _rational(alt)
    return info


def _clean(v):
    if isinstance(v, bytes):
        try:
            v = v.decode("utf-8", "replace")
        except Exception:
            v = repr(v)
    s = str(v).strip().strip("\x00")
    return s


def exiftool_backfill(path, info):
    """When exiftool is on PATH, add any GPS/camera fields Pillow missed. Best-effort, offline."""
    exe = shutil.which("exiftool")
    if not exe:
        return info
    try:
        out = subprocess.run(
            [exe, "-json", "-n", "-GPSLatitude", "-GPSLongitude", "-Make", "-Model",
             "-Software", "-DateTimeOriginal", str(path)],
            capture_output=True, timeout=30,
        )
        data = json.loads(out.stdout.decode("utf-8", "replace") or "[]")
    except Exception:
        return info
    if not data:
        return info
    row = data[0]
    if info.get("gps") is None and row.get("GPSLatitude") is not None and row.get("GPSLongitude") is not None:
        try:
            info["gps"] = {"lat": round(float(row["GPSLatitude"]), 7),
                           "lon": round(float(row["GPSLongitude"]), 7)}
        except Exception:
            pass
    for k, dst in (("Make", "Make"), ("Model", "Model")):
        if row.get(k) and dst not in info["camera"]:
            info["camera"][dst] = _clean(row[k])
    if row.get("Software") and not info.get("software"):
        info["software"] = _clean(row["Software"])
    if row.get("DateTimeOriginal") and "DateTimeOriginal" not in info["timestamps"]:
        info["timestamps"]["DateTimeOriginal"] = _clean(row["DateTimeOriginal"])
    return info


# =====================================================================================
#  (2) Visual-clue extraction -- tiled OCR via tesseract
# =====================================================================================

def _tesseract_ocr(png_bytes, exe):
    try:
        p = subprocess.run(
            [exe, "stdin", "stdout", "-l", "eng", "--psm", "6"],
            input=png_bytes, capture_output=True, timeout=60,
        )
        return p.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def _to_png_bytes(im):
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def ocr_image(path, max_tiles=9):
    """OCR the whole frame plus a grid of tiles so small signage text is legible.

    Returns (full_text, list_of_tile_texts). Empty/`None` if tesseract is not installed.
    """
    exe = shutil.which("tesseract")
    if exe is None or Image is None:
        return "", []
    try:
        im = Image.open(path)
        im = ImageOps.exif_transpose(im).convert("RGB")
    except Exception:
        return "", []

    texts = []
    # Full frame, upscaled if small (OCR likes ~300+ px of text height).
    w, h = im.size
    scale = 1
    if max(w, h) < 1600:
        scale = max(1, 1600 // max(w, h))
    full = im.resize((w * scale, h * scale)) if scale > 1 else im
    full_text = _tesseract_ocr(_to_png_bytes(full), exe)

    # Tile the (upscaled) image into a grid so tiny text fills more of a frame.
    grid = 3 if max(w, h) >= 600 else 1
    if grid > 1 and grid * grid <= max_tiles:
        tw, th = full.size[0] // grid, full.size[1] // grid
        for gy in range(grid):
            for gx in range(grid):
                box = (gx * tw, gy * th, (gx + 1) * tw, (gy + 1) * th)
                tile = full.crop(box)
                t = _tesseract_ocr(_to_png_bytes(tile), exe)
                if t.strip():
                    texts.append(t)
    return full_text, texts


# --- clue parsing over the OCR text -------------------------------------------------

PHONE_RE = re.compile(r"(?:\+|00)\d{1,3}[\s().-]?(?:\d[\s().-]?){6,12}\d")
# Country dialling code -> rough country hint (small, common set; advisory only).
DIAL_HINTS = {
    "+1": "US/Canada", "+7": "Russia/Kazakhstan", "+20": "Egypt", "+27": "South Africa",
    "+30": "Greece", "+31": "Netherlands", "+32": "Belgium", "+33": "France", "+34": "Spain",
    "+36": "Hungary", "+39": "Italy", "+40": "Romania", "+41": "Switzerland", "+43": "Austria",
    "+44": "United Kingdom", "+45": "Denmark", "+46": "Sweden", "+47": "Norway", "+48": "Poland",
    "+49": "Germany", "+51": "Peru", "+52": "Mexico", "+54": "Argentina", "+55": "Brazil",
    "+57": "Colombia", "+60": "Malaysia", "+61": "Australia", "+62": "Indonesia", "+63": "Philippines",
    "+64": "New Zealand", "+65": "Singapore", "+66": "Thailand", "+81": "Japan", "+82": "South Korea",
    "+84": "Vietnam", "+86": "China", "+90": "Turkey", "+91": "India", "+92": "Pakistan",
    "+351": "Portugal", "+352": "Luxembourg", "+353": "Ireland", "+358": "Finland", "+359": "Bulgaria",
    "+380": "Ukraine", "+381": "Serbia", "+385": "Croatia", "+386": "Slovenia", "+420": "Czechia",
    "+421": "Slovakia", "+971": "UAE", "+972": "Israel", "+974": "Qatar", "+966": "Saudi Arabia",
}

# Rough script detection by Unicode block -> a language/region hint.
SCRIPT_RANGES = [
    ("Cyrillic", 0x0400, 0x04FF, "Russia/Ukraine/Serbia/Bulgaria"),
    ("Greek", 0x0370, 0x03FF, "Greece/Cyprus"),
    ("Arabic", 0x0600, 0x06FF, "Arabic-speaking region"),
    ("Hebrew", 0x0590, 0x05FF, "Israel"),
    ("Han", 0x4E00, 0x9FFF, "China/Japan/Taiwan"),
    ("Hiragana", 0x3040, 0x309F, "Japan"),
    ("Katakana", 0x30A0, 0x30FF, "Japan"),
    ("Hangul", 0xAC00, 0xD7A3, "Korea"),
    ("Thai", 0x0E00, 0x0E7F, "Thailand"),
    ("Devanagari", 0x0900, 0x097F, "India/Nepal"),
]

PLACE_SUFFIXES = (
    "street", "str", "straße", "strasse", "avenue", "ave", "road", "rd", "boulevard", "blvd",
    "strada", "piata", "piazza", "plaza", "platz", "rue", "calle", "via", "ulica", "ulitsa",
    "square", "bahnhof", "station", "gare", "hotel", "hospital", "university", "bank", "cafe",
)


def extract_clues(full_text, tile_texts):
    """Pull place names, languages/scripts, phone numbers, and business words from OCR text."""
    all_text = "\n".join([full_text] + list(tile_texts))
    clues = {
        "ocr_text": all_text.strip(),
        "place_words": [],
        "phone_numbers": [],
        "scripts": [],
        "candidate_names": [],
        "flags": find_flags(all_text),
        "coords": find_coords(all_text),
    }

    # Scripts / languages present.
    seen_scripts = {}
    for ch in all_text:
        cp = ord(ch)
        for name, lo, hi, hint in SCRIPT_RANGES:
            if lo <= cp <= hi:
                seen_scripts[name] = hint
                break
    clues["scripts"] = [{"script": k, "region_hint": v} for k, v in seen_scripts.items()]

    # Phone numbers + dialling-code country hint.
    for m in PHONE_RE.finditer(all_text):
        raw = m.group(0).strip()
        digits = re.sub(r"\D", "", raw)
        hint = None
        norm = "+" + digits.lstrip("0") if raw.startswith("00") else ("+" + digits if raw.startswith("+") else None)
        if norm:
            for code in sorted(DIAL_HINTS, key=len, reverse=True):
                if norm.startswith(code):
                    hint = DIAL_HINTS[code]
                    break
        clues["phone_numbers"].append({"number": raw, "country_hint": hint})

    # Place words and candidate proper nouns.
    words = re.findall(r"[A-Za-zÀ-ɏ][A-Za-zÀ-ɏ.'-]{2,}", all_text)
    lower_join = all_text.lower()
    for suf in PLACE_SUFFIXES:
        if suf in lower_join:
            # keep the line that mentions it as a place lead
            for line in all_text.splitlines():
                if suf in line.lower() and line.strip() and line.strip() not in clues["place_words"]:
                    clues["place_words"].append(line.strip())
    # Capitalised multi-word runs -> candidate names (businesses, landmarks, people).
    for m in re.finditer(r"(?:[A-ZÀ-ɏ][\w.'-]+(?:\s+|$)){1,4}", all_text):
        cand = m.group(0).strip()
        if len(cand) >= 4 and cand not in clues["candidate_names"] and not cand.isupper() or (
            cand.isupper() and 4 <= len(cand) <= 24
        ):
            if cand not in clues["candidate_names"]:
                clues["candidate_names"].append(cand)
    clues["candidate_names"] = clues["candidate_names"][:25]
    clues["place_words"] = clues["place_words"][:25]
    return clues


# =====================================================================================
#  (3) Search plan
# =====================================================================================

def build_search_plan(exif, clues):
    """Emit the exact lookups to run next, as advice for the human/agent. No network here."""
    plan = []
    gps = exif.get("gps")
    if gps:
        lat, lon = gps["lat"], gps["lon"]
        plan.append(
            f"REVERSE-GEOCODE the EXIF GPS fix {lat}, {lon}: "
            f"https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={lat}&lon={lon} "
            f"(and open https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=18/{lat}/{lon} ). "
            "A GPS tag usually IS the answer -- confirm it matches the visible scene, do not blind-trust."
        )
    if clues.get("coords"):
        for c in clues["coords"]:
            plan.append(f"OCR'd a coordinate-shaped string {c!r}: paste into OpenStreetMap / Google Maps to place it.")

    cam = exif.get("camera") or {}
    if cam.get("Make") or cam.get("Model"):
        plan.append(
            f"Camera {cam.get('Make','?')} {cam.get('Model','?')}: a phone model narrows the era; "
            "check the lens field of view against the skyline."
        )

    for pw in clues.get("place_words", [])[:8]:
        plan.append(f"Named place/street in signage {pw!r}: Nominatim search "
                    f"https://nominatim.openstreetmap.org/search?format=jsonv2&q={_q(pw)} , then a straight web search.")

    names = clues.get("candidate_names", [])
    if names:
        joined = " ".join(names[:4])
        plan.append(f"Business/landmark words {names[:6]} -> web-search the most specific as a phrase, "
                    f"e.g. \"{joined}\"; a unique business name geocodes directly.")

    for sc in clues.get("scripts", []):
        plan.append(f"Script {sc['script']} on signage -> region hint: {sc['region_hint']}. "
                    "Narrow the landmark search to that region.")

    for ph in clues.get("phone_numbers", []):
        if ph.get("country_hint"):
            plan.append(f"Phone {ph['number']} -> dialling code country: {ph['country_hint']}.")
        else:
            plan.append(f"Phone {ph['number']}: look up the dialling code / area code for a country+city hint.")

    # Always-on landmark/skyline advice.
    plan.append("SKYLINE/LANDMARK: describe the most distinctive structure (tower, bridge, dome, "
                "mountain profile) and run an image/landmark web search; cross-check with the script/phone region.")
    plan.append("REVERSE IMAGE SEARCH: after reviewing image privacy, make one manual upload to "
                "Yandex Images / Google Lens / Bing Visual Search and bring one caption back as a text lead. "
                "Browser automation is intentionally not used because its subrequests cannot be hard-capped.")
    plan.append("WAYBACK / web-check: if a business name or URL is visible, check its listing "
                "(address, hours) and Wayback for an older address.")
    return plan


def _q(s):
    import urllib.parse
    return urllib.parse.quote_plus(s)


# =====================================================================================
#  (4) Guarded online enrichment and reverse-image human handoff
# =====================================================================================

def reverse_image_search(path, timeout_s=45):
    """Return the safe human handoff for reverse-image search without opening a browser.

    A reverse-image web application makes an unbounded set of page, analytics and upload requests;
    that cannot be enclosed by :class:`osint_online.PublicOSINTClient`'s hard cap.  Keep the API for
    callers from earlier rounds, but decline honestly instead of silently bypassing the guard.
    """
    del path, timeout_s
    return {
        "ok": False,
        "note": ("automatic reverse-image upload declined: use one manual Google Lens/Bing/Yandex "
                 "upload after reviewing image privacy; bring the captions back as a single text lead"),
        "results": [],
    }


def enrich_online(report, client):
    """Query one best geolocation lead through ``PublicOSINTClient``.

    EXIF GPS wins; then a signage/place line; then a candidate landmark name.  The function never
    queries all clues and never turns the first result into a final coordinate.
    """
    gps = (report.get("metadata") or {}).get("gps")
    if gps:
        rows = client.reverse_geocode((gps["lat"], gps["lon"]))
        basis = "EXIF GPS"
    else:
        clues = report.get("clues") or {}
        candidates = list(clues.get("place_words") or []) + list(clues.get("candidate_names") or [])
        if not candidates:
            return {"basis": None, "evidence": [], "requests": client.request_count,
                    "requires_human_pin": True,
                    "note": "no sufficiently specific clue was found; no public request was made"}
        basis = str(candidates[0])[:300]
        rows = client.geocode(basis)
    import dataclasses
    return {
        "basis": basis,
        "evidence": [dataclasses.asdict(row) for row in rows],
        "requests": client.request_count,
        "requires_human_pin": True,
        "note": "ranked public evidence only; cross-check the visible scene before choosing a pin",
    }


# =====================================================================================
#  Report assembly
# =====================================================================================

def analyze(path, do_search=False, online_client=None):
    path = str(path)
    exif = read_exif(path)
    exif = exiftool_backfill(path, exif)
    full_text, tiles = ocr_image(path)
    clues = extract_clues(full_text, tiles)
    plan = build_search_plan(exif, clues)

    # Highlight flags/coords from metadata too.
    meta_blob = json.dumps(exif, default=str)
    flags = sorted(set(clues["flags"]) | set(find_flags(meta_blob)))
    coords = list(clues["coords"])
    if exif.get("gps"):
        coords.insert(0, f"{exif['gps']['lat']}, {exif['gps']['lon']} (EXIF GPS)")

    report = {
        "image": path,
        "metadata": exif,
        "clues": clues,
        "search_plan": plan,
        "highlights": {"flags": flags, "coordinates": coords},
        "tools": {
            "pillow": Image is not None,
            "exiftool": shutil.which("exiftool") is not None,
            "tesseract": shutil.which("tesseract") is not None,
        },
        "reverse_image_search": None,
        "online_enrichment": None,
    }
    if online_client is not None:
        report["online_enrichment"] = enrich_online(report, online_client)
    elif do_search:
        report["reverse_image_search"] = reverse_image_search(path)
    return report


def render(report):
    L = []
    L.append(f"== OSINT geolocation: {report['image']} ==")
    t = report["tools"]
    L.append(f"tools: pillow={t['pillow']} exiftool={t['exiftool']} tesseract={t['tesseract']}")

    hl = report["highlights"]
    if hl["flags"]:
        L.append("")
        L.append("!! FLAG-SHAPED HITS:")
        for f in hl["flags"]:
            L.append(f"   >>> {f}")
    if hl["coordinates"]:
        L.append("")
        L.append("!! COORDINATE-SHAPED HITS:")
        for c in hl["coordinates"]:
            L.append(f"   >>> {c}")

    m = report["metadata"]
    L.append("")
    L.append("-- METADATA --")
    if m.get("gps"):
        g = m["gps"]
        extra = f" alt={g.get('alt_m')}m" if g.get("alt_m") is not None else ""
        L.append(f"GPS: {g['lat']}, {g['lon']}{extra}")
    else:
        L.append("GPS: (none in EXIF)")
    if m.get("camera"):
        L.append("camera: " + ", ".join(f"{k}={v}" for k, v in m["camera"].items()))
    if m.get("software"):
        L.append(f"software: {m['software']}")
    if m.get("timestamps"):
        L.append("timestamps: " + ", ".join(f"{k}={v}" for k, v in m["timestamps"].items()))

    c = report["clues"]
    L.append("")
    L.append("-- VISUAL CLUES (OCR) --")
    if c["ocr_text"]:
        preview = c["ocr_text"].replace("\n", " / ")
        L.append("text: " + (preview[:300] + ("..." if len(preview) > 300 else "")))
    else:
        L.append("text: (no OCR text -- tesseract missing or no legible signage)")
    if c["scripts"]:
        L.append("scripts: " + ", ".join(f"{s['script']}({s['region_hint']})" for s in c["scripts"]))
    if c["phone_numbers"]:
        L.append("phones: " + ", ".join(f"{p['number']}[{p.get('country_hint') or '?'}]" for p in c["phone_numbers"]))
    if c["place_words"]:
        L.append("place lines: " + " | ".join(c["place_words"][:6]))
    if c["candidate_names"]:
        L.append("candidate names: " + ", ".join(c["candidate_names"][:8]))

    L.append("")
    L.append("-- SEARCH PLAN --")
    for i, step in enumerate(report["search_plan"], 1):
        L.append(f"{i:2d}. {step}")

    r = report.get("reverse_image_search")
    if r is not None:
        L.append("")
        L.append("-- REVERSE IMAGE SEARCH --")
        L.append(r["note"])
        for it in r.get("results", []):
            L.append(f"   - {it['title']}  <{it['url']}>")
    online = report.get("online_enrichment")
    if online is not None:
        L.append("")
        L.append("-- CAPPED PUBLIC-SOURCE EVIDENCE --")
        L.append(online["note"])
        L.append(json.dumps(online, indent=2, ensure_ascii=False))
    return "\n".join(L)


# =====================================================================================
#  CLI
# =====================================================================================

def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    opts = set(a for a in argv if a.startswith("--"))
    if not args:
        print("usage: osint_geo.py <image> [--online] [--json]", file=sys.stderr)
        return 2
    path = Path(args[0])
    if not path.is_file():
        print(f"osint_geo.py: no such file: {path}", file=sys.stderr)
        return 2
    online_client = None
    if "--online" in opts:
        try:
            import osint_online
            online_client = osint_online.PublicOSINTClient(request_cap=2)
        except (ImportError, ValueError) as exc:
            print(f"osint_geo.py: cannot initialize public OSINT client: {exc}", file=sys.stderr)
            return 2
    try:
        report = analyze(path, do_search="--search" in opts, online_client=online_client)
    except (ValueError, OSError) as exc:
        print(f"osint_geo.py: {exc}", file=sys.stderr)
        return 2
    if "--json" in opts:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
