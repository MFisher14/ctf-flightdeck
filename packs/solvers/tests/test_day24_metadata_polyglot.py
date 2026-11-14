#!/usr/bin/env python3
"""Day 24 Metadata look-ahead: the POLYGLOT / APPENDED-OVERLAY reader (solvers/metadata-forensics/
readers_polyglot.py), the predicted next DECEPTION container.

  .venv/bin/python -m pytest tests/test_day24_metadata_polyglot.py   (or `python tests/test_day24_metadata_polyglot.py`)

Offline, synthetic fixtures built in memory from each format's spec (no ffmpeg, no Game Master, no token,
no challenges/ dir), so the test is variant-proof and CI-safe.

What it pins forever:
  * the host container's LOGICAL END is computed EXACTLY by walking its structure (PNG->IEND, GIF->0x3B,
    JPEG->EOI, PDF->last %%EOF, ZIP->EOCD), so a carrier's appended-overlay offset/size/digest are exact;
  * the reader is DECOY-BY-MAGIC: it reads by true magic, never by extension, and flags a mislabeled file;
  * NEVER WRONG: every answer is unsure (labels.pick / None), never a plain batch-sinking guess; a
    malformed or unbounded host raises Unknown -> None, never an estimated end;
  * registering the pack changes NO existing reader (clash guard) and NO judged key.
"""
import importlib.util
import io
import hashlib
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
META = ROOT / "solvers" / "metadata-forensics"
COMMON = ROOT / "solvers" / "common"
for p in (str(COMMON), str(META)):
    if p not in sys.path:
        sys.path.insert(0, p)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RP = _load("readers_polyglot_test", META / "readers_polyglot.py")
labels = _load("labels_polyglot_test", COMMON / "labels.py")

# Load properties_strict. readers_polyglot is wired into MORE_FILES, so M auto-registers it (via a SEPARATE
# module instance) at import. Re-registering THIS standalone RP with RP.register(M) would double-register and
# self-clash -- every polyglot.* name reported as a clash with its own prior load (the bug this replaces). So
# just WIRE RP's module reference to M, so the reader functions called directly below (group A: RP._png_end,
# RP._host_and_end -> M.Unknown) resolve against M. If MORE_FILES did not load it (older tree), register now;
# register() both wires M and records clashes. Either way the integration path (M.answer_question) runs the
# auto-loaded instance already in M.REG.
M = _load("ps_polyglot_test", META / "properties_strict.py")
if "readers_polyglot.py" in getattr(M, "MORE_LOADED", {}):
    RP.M = M
else:
    RP.register(M)
# This pack's own clash delta must be EMPTY, by whichever path it loaded: a name it tried to register over a
# shipped reader is recorded in M.MORE_CLASHES under one of this pack's OWN namespaces (register appends the
# overwriting -- polyglot/overlay/... -- name, then restores the earlier reader).
_POLY_NS = tuple(ns + "." for ns in RP.NEW_NAMESPACES)
_NEW_CLASHES = [c for c in getattr(M, "MORE_CLASHES", []) if str(c).startswith(_POLY_NS)]


def check(name, ok, detail=""):
    print(("ok  " if ok else "FAIL") + " : " + name + ("" if ok else f"   {detail}"))
    assert ok, f"{name}   {detail}"


# --------------------------------------------------------------------------- fixtures

def png_bytes(extra_chunks=b""):
    """A minimal valid PNG: signature, an IHDR, extra chunks, IEND. Exactly structured so the end is known."""
    def chunk(ctype, body):
        import zlib
        return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", zlib.crc32(ctype + body) & 0xffffffff)
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    return b"\x89PNG\r\n\x1a\n" + ihdr + extra_chunks + chunk(b"IEND", b"")


def gif_bytes():
    """A minimal valid GIF89a: header, screen descriptor (no GCT), one empty extension, trailer."""
    hdr = b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0x00, 0, 0)         # packed 0x00 -> no global colour table
    ext = b"\x21\xfe\x00"                                              # comment extension, empty, terminator
    return hdr + ext + b"\x3b"


def jpeg_bytes():
    """A tiny structurally valid JPEG: SOI, an APP0, a one-scan SOS with a little entropy data, EOI."""
    soi = b"\xff\xd8"
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sos = b"\xff\xda" + struct.pack(">H", 8) + bytes(6)
    entropy = b"\x12\x34\xff\x00\x56\xff\xd0\x78"                      # includes a stuffed FF00 and a restart
    eoi = b"\xff\xd9"
    return soi + app0 + sos + entropy + eoi


def pdf_bytes():
    return b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


def zip_bytes(names=("a.txt", "b.txt")):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for i, n in enumerate(names):
            z.writestr(n, f"body-{i}".encode())
    return buf.getvalue()


def ask(prop, name, data):
    """Run the full strict wrapper on a one-property question and return the answer string (plain or unsure)
    or None, exactly as Layer 1 would submit it. The id mirrors the real lane shape: <stem>-<property words
    joined by dashes>, no extension in the id (so the stem-strip leaves exactly the property)."""
    stem = name.rsplit(".", 1)[0]
    aid = f"{stem}-" + prop.replace(".", "-").replace("_", "-")
    q = {"id": aid, "answer_id": aid,
         "question": f"Inspect `{name}`. Determine {prop} for {name}.",
         "artifact": f"evidence.zip -> {name}",
         "answer_format": {"kind": "exact_text", "syntax": "exact artifact-derived value only"}}
    return M.answer_question(q, {name: data}, {})


# --------------------------------------------------------------------------- (A) exact logical end

PNG = png_bytes()
APP = b"PK\x03\x04" + bytes(40) + b"appended-secret-blob"
carrier = PNG + APP


# --------------------------------------------------------------------------- (B) overlay facts are exact

def _val(ans):
    """The first offered value of an unsure/plain answer (for asserting the fact, ledger-independent)."""
    if ans is None:
        return None
    p = labels.parse(ans)
    if p is None:
        return ans
    opts = p.options if hasattr(p, "options") else p["o"]
    return opts[0][1]


def test_a_exact_logical_end():
    check("(A) _png_end finds the exact IEND boundary", RP._png_end(carrier) == len(PNG), f"{RP._png_end(carrier)} vs {len(PNG)}")
    check("(A) _gif_end finds the 0x3B trailer", RP._gif_end(gif_bytes() + b"TAIL") == len(gif_bytes()))
    check("(A) _jpeg_end finds EOI past a stuffed FF00 and a restart marker", RP._jpeg_end(jpeg_bytes() + b"X") == len(jpeg_bytes()))
    check("(A) _pdf_end finds the last %%EOF", RP._pdf_end(pdf_bytes() + b"more") == len(pdf_bytes()))
    check("(A) _zip_end finds the EOCD end", RP._zip_end(zip_bytes() + b"tail") == len(zip_bytes()))

    # a malformed / unterminated host raises Unknown -> never an estimated end
    for label, bad in [("PNG with no IEND", b"\x89PNG\r\n\x1a\n" + bytes(8)),
                       ("GIF with no trailer", b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0, 0, 0) + b"\x21\xfe"),
                       ("JPEG with no EOI", b"\xff\xd8\xff\xe0" + struct.pack(">H", 4)),
                       ("PDF with no %%EOF", b"%PDF-1.4\nno terminator")]:
        try:
            RP._host_and_end(bad)
        except Exception as e:
            check(f"(A) {label} -> Unknown (no estimate)", type(e).__name__ == "Unknown" or "Unknown" in type(e).__name__, repr(e))
        else:
            check(f"(A) {label} -> Unknown (no estimate)", False, "did not raise")


def test_b_overlay_facts_are_exact():
    check("(B) overlay.size_bytes == exact appended length", RP._overlay_size("x.png", carrier) == len(APP), str(RP._overlay_size("x.png", carrier)))
    check("(B) overlay.offset == IEND boundary", RP._overlay_offset("x.png", carrier) == len(PNG))
    check("(B) overlay.sha256 == sha256 of exactly the appended bytes",
          RP._overlay_digest("sha256")("x.png", carrier) == hashlib.sha256(APP).hexdigest())
    check("(B) overlay.format reads the appended magic (zip)", RP._overlay_format("x.png", carrier) == "zip")
    check("(B) overlay.present True on a carrier", RP._overlay_present("x.png", carrier) is True)

    clean = PNG
    check("(B) a clean PNG has no overlay: present False", RP._overlay_present("x.png", clean) is False)
    check("(B) a clean PNG overlay.offset is absent (None)", RP._overlay_offset("x.png", clean) is None)
    check("(B) a clean PNG overlay.size_bytes is 0", RP._overlay_size("x.png", clean) == 0)
    check("(B) a clean PNG overlay.sha256 is absent (None)", RP._overlay_digest("sha256")("x.png", clean) is None)


# --------------------------------------------------------------------------- (C) polyglot structure
def test_c_polyglot_structure():
    clean = PNG
    check("(C) is_polyglot True on PNG+ZIP carrier", RP._is_polyglot("x.png", carrier) is True)
    check("(C) is_polyglot False on a clean single-format PNG", RP._is_polyglot("x.png", clean) is False)
    check("(C) format_count 2 on the carrier", RP._format_count("x.png", carrier) == 2)
    check("(C) formats lists png then zip in offset order", RP._all_formats("x.png", carrier) == ["png", "zip"])
    check("(C) second_format is the hidden zip", RP._second_format("x.png", carrier) == "zip")
    # a host we cannot bound (ELF) with NO embedded 2nd magic -> is_polyglot honestly None, never a false False
    elf = b"\x7fELF" + bytes(60)
    check("(C) is_polyglot None on an unboundable host with no 2nd magic (never a false False)",
          RP._is_polyglot("x.bin", elf) is None)
    # an ELF with an appended zip IS caught by the embedded scan -> True
    check("(C) is_polyglot True on an unboundable host WITH an embedded strong magic",
          RP._is_polyglot("x.bin", elf + b"PK\x03\x04" + bytes(30)) is True)


# --------------------------------------------------------------------------- (D) decoy-by-magic (uses name)
def test_d_decoy_by_magic_uses_name():
    clean = PNG
    check("(D) a .wav whose real magic is FLAC: is_decoy True", RP._is_decoy("audio.wav", b"fLaC" + bytes(40)) is True)
    check("(D) a .png that is really a zip: is_decoy True", RP._is_decoy("image.png", b"PK\x03\x04" + bytes(40)) is True)
    check("(D) a genuine .png: is_decoy False", RP._is_decoy("image.png", clean) is False)
    check("(D) a .jar that is a zip: not a decoy (jar IS zip)", RP._is_decoy("app.jar", zip_bytes()) is False)
    check("(D) no extension claim -> is_decoy None (never a false bool)", RP._is_decoy("blob", b"PK\x03\x04" + bytes(40)) is None)
    check("(D) true_format reads the bytes regardless of extension",
          RP._true_format("audio.wav", b"fLaC" + bytes(40)) == "flac")
    check("(D) the same decoy bytes read the same true_format under any name (magic-only)",
          RP._true_format("a.wav", b"OggS" + bytes(60)) == RP._true_format("b.bin", b"OggS" + bytes(60)) == "ogg")


# --------------------------------------------------------------------------- (E) never plain, through the wrapper
def test_e_never_plain_through_the_wrapper():
    for prop in ["overlay.size_bytes", "overlay.offset", "overlay.sha256", "overlay.format",
                 "polyglot.true_format", "polyglot.is_polyglot", "polyglot.format_count", "polyglot.second_format"]:
        ans = ask(prop, "carrier.png", carrier)
        is_unsure = ans is None or (isinstance(ans, str) and ans.startswith("??"))
        check(f"(E) {prop} is NEVER plain through the wrapper (unsure or None)", is_unsure, f"{ans!r}")

    # the raw fact is still carried as the first offered option, so one probe on the base settles it
    check("(E) overlay.size_bytes carries the exact value as its first option",
          _val(ask("overlay.size_bytes", "carrier.png", carrier)) == str(len(APP)),
          repr(ask("overlay.size_bytes", "carrier.png", carrier)))
    check("(E) polyglot.true_format carries 'png' as a first option",
          _val(ask("polyglot.true_format", "carrier.png", carrier)) in ("png", "PNG"))


# --------------------------------------------------------------------------- (F) additive: no existing reader moved
# A judged identity key stays plain and correct (the pack never touches it).
def test_f_additive_no_existing_reader_moved():
    sha = ask("sha256", "carrier.png", carrier)
    check("(F) sha256 still answers plain (judged key untouched)",
          sha == hashlib.sha256(carrier).hexdigest(), f"{sha!r}")
    # This pack's own clash delta must be EMPTY: every name it registers is new (the clash guard would have
    # restored the earlier reader otherwise, and the pack must never shadow a shipped reader).
    check("(F) the pack registers only new names (its clash delta is empty)",
          _NEW_CLASHES == [], f"new clashes={_NEW_CLASHES}")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
