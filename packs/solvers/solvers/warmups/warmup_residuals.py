#!/usr/bin/env python3
"""B-250: the Warmups lane residuals, folded into crib_decode's one pass.

The Huntress Warmups lane closed 29 of 33 decoding modes on Layer 1; what it left open (backlog rows
151-155, the oracle-search audit's "missing" list, the Day 30 coverage row U2) is carried here as
strict readers that crib_decode folds in through its B-230 extension point (`register_family`). Each
reader is one information-preserving step: its output re-enters the strict search like any decode,
and a reading becomes an answer only through crib_decode's own oracle (a flag-format string, or the
known sentence plus a slug). Nothing here answers anything on its own.

  ita1, ita1rev   Baudot's continental code, ITA1 letters and figures, as 5-bit binary groups written
                  bit I first (`ita1`) or bit V first (`ita1rev`). LTRS 00001 and FIGS 00010 change the
                  shift; the blank of the shift already in force is a space (the code has no space of
                  its own). One case, so a slug read through it is case-lossy: CASE_LOSSY puts it under
                  warmups.case/ita1, a candidate (unsure) until the judge accepts it, never plain on this
                  module's word. A national-use figure (the column the sources leave blank or disagree
                  on) is refused, as ITA2's are, never guessed.
  yencraw         yEnc with no =ybegin header: every byte 42 higher, '=' escaping the next (64 more),
                  line breaks not data. Only for bytes that are not all ASCII (yEnc of any lower-case
                  text is) and only when the whole output is printable text.
  dtmfwav         DTMF re-entry from audio: a PCM WAV's keys by carve_stego's Goertzel reader, as text
                  ('0'-'9', '*', '#', 'A'-'D'), only when that reader calls the reading sure (stable
                  under window shifts, one burst per key). The keys then re-enter the search (a big
                  decimal, a decimal list, the multitap code).
  dtmfwavsep      the same keys with '*' and '#' read as separators (a space), so separated multitap
                  runs and decimal byte lists reach their readers.
  qrimg           QR re-entry from an image (PNG, GIF, BMP or JPEG): the pure-Python
                  solvers/toolkits/qr_matrix.py samples and decodes it (Reed-Solomon with zero syndromes
                  is its acceptance boundary): the payload of the first sampled matrix that decodes, or
                  nothing when that matrix gives two. At most QR_MAX_PIXELS pixels.
  chicken         a Chicken program (every line only the word "chicken") run on B-055's bounded VM
                  (solvers/common/chicken.py, completed with peck/fr/BBQ by this item). Its output is
                  HTML-escaped characters (BBQ), which the strict html step then reads.

keyed_digit_option() is the B6 third digit option for crib_decode's _digit_options: a keyboard wrap
(kbdw:<n>) or a Vigenere-family key whose writer moved the digits too (the digit row of the keyboard by
the same n; each digit by its key letter modulo ten). Always an option, never plain.

Missing optional machinery (Pillow, the toolkit files) is a named, loud refusal: MISSING records the
reader and the reason and one NOTE line goes to stderr; the reader then reads nothing.
"""
from __future__ import annotations

import io
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
TOOLKITS = HERE.parent / "toolkits"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

MAX_INPUT = 1 << 20        # crib_decode's MAX_BLOB: nothing larger is read
TEXT_MAX = 1 << 16         # bytes of an ITA1 / yEnc text this module reads
ITA1_FLOOR = 8             # codes a payload must hold (ITA2's floor outside the walk by the days)
YENC_FLOOR = 8             # bytes of output a headerless yEnc reading must give
DTMF_SECONDS = 60.0        # seconds of a recording the DTMF reader reads
QR_MAX_PIXELS = 512 * 512  # an image larger than this is not sampled (the sampler is pure Python: ~1 CPU s at 400x400)
CHICKEN_STEPS = 200_000    # opcodes one Chicken run may execute inside the search
CHICKEN_MIN_LINES = 3

MISSING: dict = {}         # reader -> the named reason it is unavailable


def _missing(reader: str, reason: str) -> None:
    if reader not in MISSING:
        MISSING[reader] = reason
        print(f"NOTE warmups residuals: the {reader} reader is unavailable: {reason}", file=sys.stderr)


def _load(path: Path, alias: str):
    from _shadowed import module_at
    return module_at(path, alias)


# --------------------------------------------------------------------------------------------- ITA1

# Baudot's continental code as ITA1 kept it, each code written bit I first (I II III IV V). Baudot laid
# the letters out as a reflected Gray code, vowels first; the digits sit on A E Y U O J G B C D.
# (letter, figure); None where the sources leave the national-use cell open.
ITA1 = {
    "10000": ("a", "1"), "11000": ("é", None), "01000": ("e", "2"), "01100": ("i", None),
    "11100": ("o", "5"), "10100": ("u", "4"), "00100": ("y", "3"), "00110": ("b", "8"),
    "10110": ("c", "9"), "11110": ("d", "0"), "01110": ("f", None), "01010": ("g", "7"),
    "11010": ("h", None), "10010": ("j", "6"), "10011": ("k", "("), "11011": ("l", "="),
    "01011": ("m", ")"), "01111": ("n", None), "11111": ("p", "%"), "10111": ("q", "/"),
    "00111": ("r", "-"), "00101": ("s", ";"), "10101": ("t", "!"), "11101": ("v", "'"),
    "01101": ("w", "?"), "01001": ("x", ","), "11001": ("z", ":"), "10001": (None, "."),
}
ITA1_LTRS, ITA1_FIGS, ITA1_ERASE, ITA1_IDLE = "00001", "00010", "00011", "00000"
CASE_LOSSY = {"ita1": "ita1", "ita1rev": "ita1"}   # step -> warmups.case/<form> (crib_decode merges it)
_ITA1_SHAPE = re.compile(rb"\s*(?:[01]{5}(?:[\s,;]+|$))+\s*|\s*(?:[01]{5})+\s*")


def _ita1(b: bytes, rev: bool):
    if len(b) > TEXT_MAX or not _ITA1_SHAPE.fullmatch(b):
        return None
    bits = re.sub(rb"[^01]", b"", b).decode()
    if len(bits) % 5 or len(bits) < 5 * ITA1_FLOOR:
        return None
    out, figs, letters = [], False, 0
    for i in range(0, len(bits), 5):
        code = bits[i:i + 5][::-1] if rev else bits[i:i + 5]
        if code in (ITA1_IDLE, ITA1_ERASE):
            continue
        if code in (ITA1_LTRS, ITA1_FIGS):
            to_figs = code == ITA1_FIGS
            if to_figs == figs:          # the blank of the shift already in force is a space
                out.append(" ")
            figs = to_figs
            continue
        c = ITA1[code][1 if figs else 0]
        if c is None:
            return None
        letters += c.isalpha()
        out.append(c)
    return "".join(out).encode("utf-8") if out and letters else None


def d_ita1(b: bytes):
    return _ita1(b, False)


def d_ita1rev(b: bytes):
    return _ita1(b, True)


# ------------------------------------------------------------------------------------ headerless yEnc

def d_yencraw(b: bytes):
    if len(b) > TEXT_MAX or b.isascii() or b.lstrip().startswith(b"=ybegin"):
        return None
    out = bytearray()
    for ln in b.replace(b"\r\n", b"\n").split(b"\n"):
        i = 0
        while i < len(ln):
            c = ln[i]
            if c == 0x3D:                  # '=': the next byte is escaped
                i += 1
                if i >= len(ln):
                    return None
                c = (ln[i] - 64) & 255
            out.append((c - 42) & 255)
            i += 1
    if len(out) < YENC_FLOOR or any(not (32 <= x <= 126 or x in (9, 10, 13)) for x in out):
        return None
    return bytes(out)


# ----------------------------------------------------------------------------------- DTMF from audio

_CARVE = []


def _carve():
    if not _CARVE:
        try:
            _load(TOOLKITS / "carve_stego_fs.py", "carve_stego_fs")
            _CARVE.append(_load(TOOLKITS / "carve_stego.py", "carve_stego"))
        except Exception as exc:   # a named, loud refusal, once
            _missing("dtmfwav", f"solvers/toolkits/carve_stego.py could not be loaded ({type(exc).__name__}: {exc})")
            _CARVE.append(None)
    return _CARVE[0]


_DTMF_MEMO: dict = {}


def _is_wav(b: bytes) -> bool:
    return len(b) > 44 and b[:4] == b"RIFF" and b[8:12] == b"WAVE"


def dtmf_keys(b: bytes):
    """The DTMF keys of a PCM WAV when carve_stego reads them sure, else None."""
    if not _is_wav(b) or len(b) > MAX_INPUT:
        return None
    key = (len(b), hash(b))
    if key not in _DTMF_MEMO:
        cs = _carve()
        got = None
        if cs is not None:
            keys, sure = cs.dtmf_read(b, DTMF_SECONDS)
            got = keys if keys and sure and len(keys) >= 2 else None
        if len(_DTMF_MEMO) > 64:
            _DTMF_MEMO.clear()
        _DTMF_MEMO[key] = got
    return _DTMF_MEMO[key]


def d_dtmfwav(b: bytes):
    keys = dtmf_keys(b)
    return keys.encode() if keys else None


def d_dtmfwavsep(b: bytes):
    keys = dtmf_keys(b)
    if not keys or not re.search(r"[*#]", keys):
        return None
    spaced = re.sub(r"[*#]+", " ", keys).strip()
    return spaced.encode() if spaced and " " in spaced else None


# ----------------------------------------------------------------------------------- QR from an image

_IMAGE_MAGIC = (b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"\xff\xd8\xff", b"BM")
_QR = []


def _qr_module():
    if not _QR:
        try:
            import PIL  # noqa: F401  -- the sampler needs it; name it here rather than deep in a call
            _load(TOOLKITS / "matrix_barcodes.py", "matrix_barcodes")
            _QR.append(_load(TOOLKITS / "qr_matrix.py", "qr_matrix"))
        except Exception as exc:
            _missing("qrimg", f"Pillow or solvers/toolkits/qr_matrix.py could not be loaded ({type(exc).__name__}: {exc})")
            _QR.append(None)
    return _QR[0]


_QR_MEMO: dict = {}


def qr_payload(b: bytes):
    """The one payload a QR symbol in this image carries, or None (no symbol, an unreadable or
    oversized image, or two symbols that disagree)."""
    if len(b) > MAX_INPUT or not b.startswith(_IMAGE_MAGIC):
        return None
    key = (len(b), hash(b))
    if key in _QR_MEMO:
        return _QR_MEMO[key]
    got = None
    qm = _qr_module()
    if qm is not None:
        try:
            from PIL import Image
            with Image.open(io.BytesIO(b)) as im:
                w, h = im.size
            if 0 < w * h <= QR_MAX_PIXELS:
                # The first sampled matrix that decodes ends the look (the rest are resamplings of the same
                # symbol, and decoding all 256 costs about a CPU second more); two payloads in it decline.
                for matrix in qm.raster_matrices(io.BytesIO(b)):
                    if len(matrix) != len(matrix[0]):
                        continue
                    payloads = {bytes(res["bytes"]) for res in qm.decode_matrix(matrix) if res.get("bytes")}
                    if payloads:
                        got = next(iter(payloads)) if len(payloads) == 1 else None
                        break
        except Exception:
            got = None             # bytes that only look like an image: nothing to read, not a fault
    if len(_QR_MEMO) > 64:
        _QR_MEMO.clear()
    _QR_MEMO[key] = got
    return got


def d_qrimg(b: bytes):
    return qr_payload(b)


# ------------------------------------------------------------------------------------------- Chicken

_CHICKEN = []
_CHICKEN_LINE = re.compile(rb"[ \t]*(?:chicken(?:[ \t]+chicken)*)?[ \t]*\r?")


def _chicken_vm():
    if not _CHICKEN:
        try:
            _CHICKEN.append(_load(COMMON / "chicken.py", "chicken"))
        except Exception as exc:
            _missing("chicken", f"solvers/common/chicken.py could not be loaded ({type(exc).__name__}: {exc})")
            _CHICKEN.append(None)
    return _CHICKEN[0]


def d_chicken(b: bytes):
    if len(b) > MAX_INPUT or b"chicken" not in b[:64]:
        return None
    lines = b.rstrip(b"\r\n").split(b"\n")
    if sum(1 for ln in lines if b"chicken" in ln) < CHICKEN_MIN_LINES:
        return None
    if not all(_CHICKEN_LINE.fullmatch(ln) for ln in lines):
        return None
    vm = _chicken_vm()
    if vm is None:
        return None
    try:
        out = vm.run_source(b.decode("ascii").replace("\r", ""), steps=CHICKEN_STEPS)
    except vm.ChickenError:
        return None
    return out or None


# ---------------------------------------------------------------------------------- the family face

READERS = {"ita1": d_ita1, "ita1rev": d_ita1rev, "yencraw": d_yencraw, "dtmfwav": d_dtmfwav,
           "dtmfwavsep": d_dtmfwavsep, "qrimg": d_qrimg, "chicken": d_chicken}
NAMES = frozenset(READERS)
_BINARYISH = re.compile(rb"[01\s,;]+")


def _which(b: bytes):
    """The readers whose shape this payload has: a cheap look before any of them runs."""
    if _is_wav(b):
        return ("dtmfwav", "dtmfwavsep")
    if b.startswith(_IMAGE_MAGIC):
        return ("qrimg",)
    if not b.isascii():
        return ("yencraw",)
    if b"chicken" in b[:64]:
        return ("chicken",)
    if len(b) >= 5 * ITA1_FLOOR and _BINARYISH.fullmatch(b):
        return ("ita1", "ita1rev")
    return ()


def steps(b: bytes):
    """(name, bytes) of every residual reader that reads this payload."""
    for name in _which(b):
        try:
            out = READERS[name](b)
        except Exception:
            out = None
        if out:
            yield name, out


def step_fn(name: str):
    return READERS.get(name)


# ------------------------------------------------------------------------ B6: keyed digit options

_DIGIT_ROW = "1234567890"
_VIG_KINDS = ("vigenere", "beaufort", "variant")


def keyed_digit_option(slug: str, chain, crib: str):
    """(name, slug) of the third way to read a slug's two digits under the keyed letter step that read
    them, when its writer may have moved the digits too; None when the chain's last keyed step is not
    a keyboard wrap or a Vigenere-family key. `crib` is the sentence the slug follows (the keyed text is
    taken to be crib + slug, the whole-blob reading).

      kbdw:<n>        the keyboard's digit row 1234567890 moved n keys like the letter rows: each digit
                      read n keys back along that row (`kbdrow`).
      vigenere:<k>    each digit moved by its key letter modulo ten, the key advancing over the digits as
      beaufort:<k>    over letters (a writer whose alphabet takes the digits in); with '+' (the key also
      variant:<k>     advancing on every other character) at that character's place (`keyed`)."""
    if len(slug) < 2 or not slug[-2:].isdigit():
        return None
    last = None
    for step in reversed(tuple(chain)):
        kind = step.split(":", 1)[0]
        if ":" in step and (kind == "kbdw" or kind in _VIG_KINDS):
            last = step
            break
    if last is None:
        return None
    kind, _, key = last.partition(":")
    if kind == "kbdw":
        try:
            n = int(key)
        except ValueError:
            return None
        moved = "".join(_DIGIT_ROW[(_DIGIT_ROW.index(c) - n) % 10] for c in slug[-2:])
        return "kbdrow", slug[:-2] + moved
    every = key.endswith("+")
    ks = [ord(c) - 97 for c in key.rstrip("+").lower() if "a" <= c <= "z"]
    if not ks:
        return None
    text = crib + slug
    first = len(text) - 2
    digits = []
    for j in (first, first + 1):
        before = text[:j]
        i = len(before) if every else sum(1 for c in before if (c.isascii() and c.isalpha()) or c.isdigit())
        k, c = ks[i % len(ks)], int(text[j])
        if kind == "beaufort":
            d = (k - c) % 10
        elif kind == "vigenere":
            d = (c - k) % 10
        else:                        # variant: c = p - k
            d = (c + k) % 10
        digits.append(str(d))
    return "keyed", slug[:-2] + "".join(digits)


__all__ = ["CASE_LOSSY", "MISSING", "NAMES", "READERS", "d_chicken", "d_dtmfwav", "d_dtmfwavsep", "d_ita1",
           "d_ita1rev", "d_qrimg", "d_yencraw", "dtmf_keys", "keyed_digit_option", "qr_payload", "step_fn",
           "steps"]
