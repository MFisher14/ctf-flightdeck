#!/usr/bin/env python3
"""Answer metadata-forensics questions from file bytes: identity, magic, text encoding, image structure.

Usage:
  python3 solvers/metadata-forensics/file_properties.py <file-or-zip> [property ...]

With no property it prints every fact it can derive for the file (or for each
member of a zip). With properties (for example jpeg.sof_dimensions_pixels) it
prints just those answers.

The lane asks one property about one file, and both change with the variant,
so nothing here keys on a question id. The property is read from the question
text ("Determine <property> for <file>.") or, for the older phrasings, from
the id suffix; the file comes from the question's artifact. Image dimensions
are parsed from the structure itself (JPEG SOFn, PNG IHDR, GIF logical screen,
BMP DIB header, WebP, TIFF IFD0), never from the name or extension. A property
whose structure is absent in the file answers the literal `none`.
"""
import hashlib
import io
import re
import struct
import sys
import zipfile
from pathlib import Path

SOF_MARKERS = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
BOMS = [("utf32le", b"\xff\xfe\x00\x00"), ("utf32be", b"\x00\x00\xfe\xff"), ("utf8", b"\xef\xbb\xbf"),
        ("utf16le", b"\xff\xfe"), ("utf16be", b"\xfe\xff")]
NONE = "none"


# ---------------------------------------------------------------- structure parsers

def tiff_tags(t: bytes):
    """Parse a TIFF/EXIF block into {"ifd0": {tag: value}, "exif": {...}, "ifd1": {...}}."""
    if len(t) < 8 or t[:2] not in (b"II", b"MM"):
        return None
    e = "<" if t[:2] == b"II" else ">"
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8}
    codes = {1: "B", 3: "H", 4: "I", 6: "b", 8: "h", 9: "i"}

    def value(typ, cnt, raw):
        size = sizes.get(typ, 1) * cnt
        if size <= 4:
            data = raw[:size]
        else:  # the same bytes as t[off:][:size]; a value that runs past the file is cut, so it is None below
            off = struct.unpack(e + "I", raw)[0]
            data = t[off:off + size] if off + size <= len(t) else b""
        if len(data) < size:
            return None
        if typ == 2:
            return data.split(b"\x00", 1)[0].decode("latin-1")  # the text before the first NUL: one cut, not every one
        if typ in codes:
            v = struct.unpack(e + str(cnt) + codes[typ], data)
            return v[0] if cnt == 1 else list(v)
        if typ in (5, 10):
            c = "I" if typ == 5 else "i"
            v = struct.unpack(e + str(cnt * 2) + c, data)
            pairs = [(v[i], v[i + 1]) for i in range(0, len(v), 2)]
            return pairs[0] if cnt == 1 else pairs
        return data

    def ifd(off, into):
        if off <= 0 or off + 2 > len(t):
            return 0
        n = struct.unpack(e + "H", t[off:off + 2])[0]
        for k in range(n):
            ent = t[off + 2 + 12 * k: off + 14 + 12 * k]
            if len(ent) < 12:
                break
            tag, typ, cnt = struct.unpack(e + "HHI", ent[:8])
            try:
                into[tag] = value(typ, cnt, ent[8:12])
            except Exception:
                into[tag] = None
        nxt = t[off + 2 + 12 * n: off + 6 + 12 * n]
        return struct.unpack(e + "I", nxt)[0] if len(nxt) == 4 else 0

    out = {"byte_order": t[:2].decode(), "ifd0": {}, "exif": {}, "ifd1": {}}
    nxt = ifd(struct.unpack(e + "I", t[4:8])[0], out["ifd0"])
    if isinstance(out["ifd0"].get(0x8769), int):
        ifd(out["ifd0"][0x8769], out["exif"])
    if nxt:
        ifd(nxt, out["ifd1"])
    return out


def jpeg_info(b: bytes):
    if b[:2] != b"\xff\xd8":
        return None
    info = {"sof": [], "app": [], "com": [], "exif": None, "jfif": None}
    i, n = 2, len(b)
    while i + 4 <= n:
        if b[i] != 0xFF:
            j = b.find(b"\xff", i)
            if j < 0:
                break
            i = j
            continue
        m = b[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0xD9:
            break
        if m in (0x00, 0x01, 0xD8) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        length = struct.unpack(">H", b[i + 2:i + 4])[0]
        seg = b[i + 4:i + 2 + length]
        if m in SOF_MARKERS and len(seg) >= 6:
            p, h, w, c = struct.unpack(">BHHB", seg[:6])
            info["sof"].append({"marker": m, "precision": p, "height": h, "width": w, "components": c, "offset": i})
        elif m == 0xE0 and seg[:5] == b"JFIF\x00" and len(seg) >= 14:
            ver, units, xd, yd, tw, th = struct.unpack(">HBHHBB", seg[5:14])
            info["jfif"] = {"version": ver, "units": units, "xdensity": xd, "ydensity": yd, "thumb_w": tw, "thumb_h": th}
        elif m == 0xE1 and seg[:6] == b"Exif\x00\x00" and info["exif"] is None:
            info["exif"] = tiff_tags(seg[6:])
        elif m == 0xFE:
            info["com"].append(seg)
        if 0xE0 <= m <= 0xEF:
            info["app"].append(m - 0xE0)
        if m == 0xDA:  # entropy-coded data runs to the next real marker
            j = i + 2 + length
            while j + 1 < n and not (b[j] == 0xFF and b[j + 1] != 0x00 and not 0xD0 <= b[j + 1] <= 0xD7):
                j += 1
            i = j
            continue
        i += 2 + length
    return info


def png_info(b: bytes):
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    info = {"ihdr": None, "chunks": [], "phys": None}
    i = 8
    while i + 8 <= len(b):
        length, typ = struct.unpack(">I4s", b[i:i + 8])
        data = b[i + 8:i + 8 + length]
        info["chunks"].append(typ.decode("latin-1"))
        if typ == b"IHDR" and len(data) >= 13 and info["ihdr"] is None:
            w, h, bd, ct, cm, fm, il = struct.unpack(">IIBBBBB", data[:13])
            info["ihdr"] = {"width": w, "height": h, "bit_depth": bd, "color_type": ct, "compression": cm,
                            "filter": fm, "interlace": il}
        elif typ == b"pHYs" and len(data) >= 9:
            info["phys"] = struct.unpack(">IIB", data[:9])
        i += 12 + length
        if typ == b"IEND":
            break
    return info


def gif_info(b: bytes):
    if b[:6] not in (b"GIF87a", b"GIF89a") or len(b) < 10:
        return None
    w, h = struct.unpack("<HH", b[6:10])
    return {"version": b[3:6].decode(), "width": w, "height": h}


def bmp_info(b: bytes):
    if b[:2] != b"BM" or len(b) < 26:
        return None
    hdr = struct.unpack("<I", b[14:18])[0]
    if hdr == 12:
        w, h = struct.unpack("<HH", b[18:22])
        bpp = struct.unpack("<H", b[24:26])[0]
    else:
        w, h = struct.unpack("<ii", b[18:26])
        bpp = struct.unpack("<H", b[28:30])[0] if len(b) >= 30 else None
    return {"width": abs(w), "height": abs(h), "top_down": h < 0, "bits_per_pixel": bpp, "header_size": hdr}


def webp_info(b: bytes):
    if b[:4] != b"RIFF" or b[8:12] != b"WEBP" or len(b) < 30:
        return None
    fourcc = b[12:16]
    if fourcc == b"VP8X":
        w = int.from_bytes(b[24:27], "little") + 1
        h = int.from_bytes(b[27:30], "little") + 1
    elif fourcc == b"VP8L" and b[20] == 0x2F:
        bits = int.from_bytes(b[21:25], "little")
        w, h = (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    elif fourcc == b"VP8 " and b[23:26] == b"\x9d\x01\x2a":
        w, h = struct.unpack("<HH", b[26:30])
        w, h = w & 0x3FFF, h & 0x3FFF
    else:
        return {"chunk": fourcc.decode("latin-1"), "width": None, "height": None}
    return {"chunk": fourcc.decode("latin-1"), "width": w, "height": h}


def tiff_info(b: bytes):
    if b[:4] not in (b"II*\x00", b"MM\x00*"):
        return None
    t = tiff_tags(b)
    if not t:
        return None
    return {"byte_order": t["byte_order"], "width": t["ifd0"].get(0x0100), "height": t["ifd0"].get(0x0101), "tags": t}


PARSERS = {"jpeg": jpeg_info, "png": png_info, "gif": gif_info, "bmp": bmp_info, "webp": webp_info, "tiff": tiff_info}


def detect(b: bytes):
    """Image type by structure, or None."""
    for name, fn in PARSERS.items():
        if fn(b) is not None:
            return name
    return None


def dims(kind: str, b: bytes, source: str = ""):
    """(width, height) for the named structure, or None when that structure is absent."""
    if kind == "jpeg":
        j = jpeg_info(b)
        if not j:
            return None
        if source == "exif":
            ex = (j["exif"] or {}).get("exif", {})
            w, h = ex.get(0xA002), ex.get(0xA003)
            return (w, h) if isinstance(w, int) and isinstance(h, int) else None
        if source == "thumbnail":
            jf = j["jfif"]
            return (jf["thumb_w"], jf["thumb_h"]) if jf and jf["thumb_w"] and jf["thumb_h"] else None
        return (j["sof"][0]["width"], j["sof"][0]["height"]) if j["sof"] else None
    if kind == "png":
        p = png_info(b)
        return (p["ihdr"]["width"], p["ihdr"]["height"]) if p and p["ihdr"] else None
    if kind in ("gif", "bmp", "webp", "tiff"):
        g = PARSERS[kind](b)
        return (g["width"], g["height"]) if g and isinstance(g.get("width"), int) and isinstance(g.get("height"), int) else None
    if kind == "exif":
        j = jpeg_info(b)
        ex = ((j or {}).get("exif") or {}).get("exif", {}) if j else {}
        w, h = ex.get(0xA002), ex.get(0xA003)
        return (w, h) if isinstance(w, int) and isinstance(h, int) else None
    found = detect(b)
    return dims(found, b) if found else None


def exif_orientation(b: bytes):
    j = jpeg_info(b)
    t = (j or {}).get("exif") if j else (tiff_info(b) or {}).get("tags")
    v = (t or {}).get("ifd0", {}).get(0x0112)
    return v if isinstance(v, int) else None


def bom_name(b: bytes):
    for name, sig in BOMS:
        if b.startswith(sig):
            return name
    return None


# ---------------------------------------------------------------- property resolution

def _b(v: bool) -> str:
    return "true" if v else "false"


def _wh(d) -> str:
    return f"{d[0]}x{d[1]}" if d else NONE


def answer(prop: str, name: str, data: bytes):
    """Value of one property for one file as the exact answer string, or None if the property is unknown."""
    key = re.sub(r"[^a-z0-9]+", "_", prop.lower()).strip("_")
    base = name.split(" -> ")[-1].split("/")[-1]
    ns = key.split("_")[0]

    # identity
    if key in ("filename", "file_name", "name", "file_filename", "file_basename", "basename"):
        return base
    if key in ("size_bytes", "file_size_bytes", "size", "file_size", "length_bytes"):
        return str(len(data))
    m = re.fullmatch(r"(?:file_|hash_|digest_)?(md5|sha1|sha224|sha256|sha384|sha512)(?:_hex|_digest)?", key)
    if m:
        return hashlib.new(m.group(1), data).hexdigest()
    m = re.fullmatch(r"(?:magic|file|header)_prefix_hex_(\d+)", key) or re.fullmatch(r"magic_hex_(\d+)", key)
    if m:
        return data[:int(m.group(1))].hex()

    # text encoding
    m = re.fullmatch(r"text_(utf8|utf16le|utf16be|utf32le|utf32be)_bom_present", key)
    if m:
        return _b(bom_name(data) == m.group(1))
    if key in ("text_bom_present", "text_has_bom"):
        return _b(bom_name(data) is not None)
    if key == "text_utf8_bom_hex":
        return data[:3].hex() if bom_name(data) == "utf8" else NONE

    # image structure
    kinds = ("jpeg", "png", "gif", "bmp", "webp", "tiff", "exif")
    kind = ns if ns in kinds else "jpg" == ns and "jpeg" or None
    if "dimensions" in key or key.endswith("_size_pixels"):
        if kind == "jpeg":
            return _wh(dims("jpeg", data, "exif" if "exif" in key else "thumbnail" if "thumb" in key else ""))
        return _wh(dims(kind or "auto", data))
    for word, idx in (("width", 0), ("height", 1)):
        if re.search(rf"(^|_){word}(_|$)", key):
            d = dims(kind or "auto", data, "exif" if kind == "jpeg" and "exif" in key else "")
            return str(d[idx]) if d else NONE
    if "orientation" in key:
        v = exif_orientation(data)
        return str(v) if v is not None else NONE
    if kind == "jpeg" or ns == "jfif":
        j = jpeg_info(data)
        sof = j["sof"][0] if j and j["sof"] else None
        if "precision" in key:
            return str(sof["precision"]) if sof else NONE
        if "component" in key:
            return str(sof["components"]) if sof else NONE
        if "progressive" in key:
            return _b(sof["marker"] in (0xC2, 0xC6, 0xCA, 0xCE)) if sof else NONE
        if key.endswith("sof_marker") or key.endswith("sof_marker_hex"):
            return f"ff{sof['marker']:02x}" if sof else NONE
        if key.endswith("exif_present") or key.endswith("has_exif"):
            return _b(bool(j and j["exif"]))
        if key.endswith("jfif_present") or key.endswith("has_jfif"):
            return _b(bool(j and j["jfif"]))
    if kind == "png":
        p = png_info(data)
        ih = p["ihdr"] if p else None
        for word, field in (("bit_depth", "bit_depth"), ("color_type", "color_type"), ("colour_type", "color_type"),
                            ("interlace", "interlace"), ("compression", "compression"), ("filter", "filter")):
            if word in key:
                return str(ih[field]) if ih else NONE
    if key in ("image_format", "image_type", "file_detected_type", "magic_type", "file_type"):
        return detect(data) or NONE
    return None


NAMESPACES = ("jpeg", "jpg", "png", "gif", "bmp", "webp", "tiff", "exif", "jfif", "image", "text", "magic", "file",
              "header", "hash", "digest", "filename", "name", "basename", "size", "length", "md5", "sha1", "sha224",
              "sha256", "sha384", "sha512")
ITEM_ID = re.compile(r"^(d\d+)-([a-z0-9]+)-(\d+)-(.+)$")
NUMBER_WORDS = {"four": 4, "eight": 8, "twelve": 12, "sixteen": 16, "twenty": 20, "thirty-two": 32, "sixty-four": 64}


def _known(prop: str) -> bool:
    return bool(prop) and answer(prop, "x", b"") is not None


def property_from_id(ident: str):
    """Property named by an id such as `d04-jpeg-002-jpeg-sof-dimensions-pixels` or `roster-magic-prefix-hex-16`."""
    ident = re.sub(r"^set\d+\.", "", ident or "")
    m = ITEM_ID.match(ident)
    if m and _known(m.group(4)):
        return m.group(4).replace("-", "_")
    parts = ident.split("-")
    for i in range(1, len(parts)):
        if parts[i] in NAMESPACES and _known("_".join(parts[i:])):
            return "_".join(parts[i:])
    return None


def question_property(q: dict):
    """(property, filename-or-None) for a question.

    The answer id is what the judge keys on, so its property wins; the question
    text and the question's own id are fallbacks (they can describe another
    variant on timed attempts).
    """
    text = q.get("question") or ""
    m = re.search(r"Determine\s+([A-Za-z0-9_.\-]+)\s+for\s+(.+?)\.?\s*$", text)
    named = m.group(2) if m else None
    for ident in (q.get("answer_id"), q.get("qid"), q.get("id")):
        prop = property_from_id(ident)
        if prop:
            return prop, named
    if m:
        return m.group(1), named
    m = re.search(r"first (\S+) bytes", text)
    if m and (m.group(1).isdigit() or m.group(1).lower() in NUMBER_WORDS):
        n = int(m.group(1)) if m.group(1).isdigit() else NUMBER_WORDS[m.group(1).lower()]
        return f"magic.prefix_hex_{n}", named
    low = text.lower()
    for needle, prop in (("sha-256", "sha256"), ("sha-1", "sha1"), ("md5", "md5"), ("size in bytes", "size_bytes"),
                         ("filename", "filename")):
        if needle in low:
            return prop, named
    return None, named


def is_archive(b: bytes) -> bool:
    return b[:4] == b"PK\x03\x04" or b[:6] == b"7z\xbc\xaf\x27\x1c"


EXT_TYPES = {"jpg": "jpeg", "jpeg": "jpeg", "jpe": "jpeg", "png": "png", "gif": "gif", "bmp": "bmp", "webp": "webp",
             "tif": "tiff", "tiff": "tiff", "txt": "text", "csv": "text", "text": "text"}


def target_file(q: dict, files: dict, ctx: dict, named):
    """Pick the file a question is about from what was actually delivered: (name, bytes) or (None, None).

    Order: the item number in the answer id (d04-jpeg-002 -> the leaf with 002 in
    its name), then the file the question names, then the only leaf in the
    delivery, then the only leaf of the type the answer id names.
    """
    leaves = [(n, d) for n, d in files.items()
              if " -> " not in n and n != ctx.get("delivery_name") and not is_archive(d)]
    if not leaves and ctx.get("delivery") is not None and not is_archive(ctx["delivery"]):
        leaves = [(ctx.get("delivery_name") or "delivery", ctx["delivery"])]
    base = lambda n: n.split(" -> ")[-1].split("/")[-1]
    wanted = [w.split("/")[-1] for w in (q.get("member"), named) if w]

    item = ITEM_ID.match(re.sub(r"^set\d+\.", "", q.get("answer_id") or q.get("qid") or ""))
    if item:
        num, kind = item.group(3), EXT_TYPES.get(item.group(2), item.group(2))
        hits = [(n, d) for n, d in leaves if re.search(rf"(?<!\d)0*{int(num)}(?!\d)", base(n))]
        if len(hits) > 1:
            typed = [(n, d) for n, d in hits
                     if (detect(d) or EXT_TYPES.get(base(n).rsplit(".", 1)[-1].lower())) == kind]
            hits = typed or hits
        if len(hits) > 1:
            hits = [h for h in hits if base(h[0]) in wanted] or hits[:1]
        if hits:
            return hits[0]
    for w in wanted:
        for n, d in leaves:
            if base(n) == w:
                return n, d
    if len(leaves) == 1:
        return leaves[0]
    if item:
        kind = EXT_TYPES.get(item.group(2), item.group(2))
        typed = [(n, d) for n, d in leaves if detect(d) == kind]
        if len(typed) == 1:
            return typed[0]
    return None, None


def solve_set(questions, files, ctx):
    out = {}
    for q in questions:
        prop, named = question_property(q)
        name, data = target_file(q, files, ctx, named)
        out[q["qid"]] = answer(prop, name, data) if prop and data is not None else None
    return out


# ---------------------------------------------------------------- CLI

def facts(name: str, data: bytes) -> dict:
    out = {"filename": name.split("/")[-1], "size_bytes": str(len(data)), "md5": hashlib.md5(data).hexdigest(),
           "sha1": hashlib.sha1(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest(),
           "magic.prefix_hex_16": data[:16].hex(), "text.utf8_bom_present": _b(bom_name(data) == "utf8"),
           "image.format": detect(data) or NONE}
    for prop in ("jpeg.sof_dimensions_pixels", "jpeg.exif_dimensions_pixels", "png.ihdr_dimensions_pixels",
                 "gif.logical_screen_dimensions_pixels", "bmp.dib_dimensions_pixels", "webp.canvas_dimensions_pixels",
                 "tiff.ifd0_dimensions_pixels", "exif.orientation"):
        out[prop] = answer(prop, name, data)
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] in ("-h", "--help"):
        print("usage: file_properties.py <file-or-zip> [property ...]")
        return 0
    if not argv:
        print("file_properties.py: expected a file", file=sys.stderr)
        return 2
    try:
        path, props = argv[0], argv[1:]
        with open(path, "rb") as fh:
            blob = fh.read()
        members = {path: blob}
        if blob[:4] == b"PK\x03\x04":
            sys.path.append(str(Path(__file__).resolve().parent.parent / "common"))
            import archive_passwords   # `infected`, then the passwords of <challenges>/_passwords.json
            members, _ = archive_passwords.read_all(blob)
        for name, data in members.items():
            print(f"## {name}")
            if props:
                for p in props:
                    print(f"{p} = {answer(p, name, data)}")
            else:
                for k, v in facts(name, data).items():
                    print(f"{k} = {v}")
    except Exception as exc:
        print(f"file_properties.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
