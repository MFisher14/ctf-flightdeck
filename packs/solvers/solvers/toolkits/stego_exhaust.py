#!/usr/bin/env python3
"""Toolkit `stego_exhaust` (B-182): run the whole stego catalog over a delivery and say "nothing further".

A stego row that stalls is tried again and again: the same LSB scan, the same bit planes, the same
appended-zip carve, re-derived by hand on every pass, and after a rejected flag nothing said what had
already been ruled out (Spooky 2026 phasmophobia: three more passes; PINK+ White Noise: two days). This
harness runs a fixed catalog of steps on every image and recording, composed from what the master
already has, records each step in the hypothesis ledger (ctf.hypothesis, B-181) so a settled step is
not run again, and ends with ONE deterministic verdict (below). What a step recovers (its texts, the
carriers it finds, its human steps) is kept beside the ledger (store_dir: <workdir>/stego_exhaust/<id>/)
and handed back when the ledger settles the step, so the text decode and the carriers inside are
reached without running it again. Only a settled step the store does not hold (filed by another agent,
the store removed) is re-run, unrecorded, while what it recovers is still wanted, and only after every
unsettled step has had the clock. A text the decode has read with no flag is not decoded again.
The verdict:

  flag             a step reached a flag of the event that was not rejected
  open             something was found that the catalog cannot read further (an encrypted member, steghide
                   data that needs its passphrase): the item says what it needs
  nothing further  every step that ran is negative: do not try these steps again. Every step that did not
                   run (a tool missing, the sandbox down, the clock, an unknown flag prefix) is listed as
                   NOT RUN, never as negative, and the verdict says whether the catalog is complete.

Steps, per file (a carrier: PNG, BMP, GIF, WebP, JPEG, TIFF, WAV):

  trailing         data after the file's own end (carve_stego.trailing)
  carve            files embedded anywhere in it, archives unpacked (carve_stego.carve, image_carve.unpack)
  chunk-crc        PNG: every chunk's CRC (a wrong IHDR CRC: the real size, and the repaired picture is
                   swept as a file of its own), non-standard chunks, data in IDAT past the picture
  metadata-concat  text chunks, comments, EXIF, XMP, RIFF INFO: each field alone, then all of them
                   concatenated in file order and in field-name order (a flag split across fields)
  lsb-planes       all 8 bit planes of every channel set (each channel, all colours, reversed, alpha), rows
                   and columns, both bit orders, two bits a sample: carve_stego.lsb_scan (bits 0-1) and
                   plane_scan (bits 2-7), judged by file magic, a length prefix and text
  lsb-deep         carve_stego.lsb_deep_scan: snake orders, cross-plane XOR, channel arithmetic, parity
  plane-grep       the event's flag, as it stands or base64/base32/hex (image_carve.flags_in), anywhere in
                   the first 64 KiB of each of those plane readings (needs a known flag prefix)
  steganalysis     the statistical detectors (steganalysis.analyze_image): an indicator, never a payload
  wav-lsb          sample bits 0-1 of a PCM WAV (carve_stego.wav_lsb)
  wav-named-tools  B-130's reproduced WAV-stego tools: WavSteg and the password-seeded LSB sweep
  stegseek-seed    JPEG, BMP, WAV: steghide data found with no passphrase (stego_tools.stegseek_seed)
  exiftool         every tag exiftool reads, alone and concatenated (stego_tools.exif)

then, over the delivery: B-126's render-and-read sweep (render_ocr_sweep: the spectrogram to Nyquist
read by OCR and as exact 5x7 glyphs, bit planes 0-2 rendered and read, its keyless decode and
cross-file keys; method strings are that engine's own), and `text-decode`: every text the steps
recovered through crib_decode's keyless readings (rotations, atbash, reversals, xor, the base families).

Every payload a step recovers is unpacked (gzip, zip, tar) and searched for the flag as it stands and
decoded; one that is itself a carrier (a PNG in an LSB plane, a WAV after the JPEG end, base64 of a
picture) is swept as a file of its own, two levels deep.

stegseek --seed and exiftool run inside the stego sandbox through stego_tools (docker exec). This
harness only USES a container that is already up (stego_tools.no_start): it never starts, builds or
pulls one. With none up, those steps are NOT RUN and the verdict is not complete.

  exhaust(files, ff, ...) -> Report             the harness over {name: bytes}
  Report.verdict() -> dict; verdict_text(report) -> str      deterministic: same inputs, same bytes
  solve(challenge_dir, profile, **opts) -> SolverResult        the engine contract (python -m ctf run)

  .venv/bin/python solvers/toolkits/stego_exhaust.py DIR [--event SLUG] [--rejected FLAG]... [--seconds S]
        [--ocr auto|on|off] [--no-sandbox] [--cid ID] [--no-ledger] [--json]

Never here: a passphrase or password search beyond B-130's committed WAV list, OCR as proof (an OCR
read is `candidate`), any network, any program run on this machine except tesseract (B-126).
Exhaustion proves only that the catalog is negative: the `not_covered` list says what it never looks at.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import re
import struct
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common", HERE.parent / "warmups"):
    if str(_p) not in sys.path:
        sys.path.append(str(_p))

import carve_stego as cs            # noqa: E402
import image_carve as ic            # noqa: E402
import render_ocr_sweep as rs       # noqa: E402
import steganalysis as sa           # noqa: E402
import stego_tools as st            # noqa: E402
import wav_stego_tools as wst       # noqa: E402

ENGINE = "toolkits.stego_exhaust"
SCHEMA = 1
DEFAULT_SECONDS = 180.0
MAX_DEPTH = 2                       # a carrier found inside a carrier is swept this deep
MAX_CHILDREN = 24                   # carriers found inside the delivery that are swept, at most
MAX_PAYLOADS = 12                   # payloads listed per step (the rest are counted)
MAX_TEXTS = 40                      # recovered texts given to the keyless decoder
MAX_TEXT = 4000                     # characters of one text kept for the decoder
DECODE_SECONDS = 1.0                # crib_decode's budget for one text
PLANE_BITS = tuple(range(8))
ENCRYPTED = " (encrypted or unreadable)"    # image_carve.unpack's label of a member it could not open
OUT_NAME = "stego_exhaust"

FLAG, REJECTED, OPEN, INDICATOR, RECOVERED, NEGATIVE, NOT_RUN, NA = (
    "flag", "rejected", "open", "indicator", "recovered", "negative", "not-run", "n/a")
STATES = (FLAG, REJECTED, OPEN, INDICATOR, RECOVERED, NEGATIVE, NOT_RUN, NA)
V_FLAG, V_OPEN, V_NOTHING = "flag", "open", "nothing further"

IMAGE = frozenset({"png", "bmp", "gif", "webp"})               # carve_stego reads their pixels
STILL = IMAGE | {"jpeg", "tiff"}
AUDIO = frozenset({"wav"})
CARRIERS = STILL | AUDIO
STEGHIDE = frozenset({"jpeg", "bmp", "wav"})                    # the covers steghide (and stegseek) read
ANALYSIS = frozenset({"PNG", "BMP", "TIFF", "PPM", "JPEG"})       # Pillow formats steganalysis judges
ANALYSIS_MODES = frozenset({"L", "LA", "RGB", "RGBA"})
_PIXELS = {"png": cs.png_pixels, "bmp": cs.bmp_pixels, "gif": cs.gif_pixels, "webp": cs.webp_pixels}


@dataclass(frozen=True)
class Step:
    key: str
    kinds: frozenset
    hypothesis: str


CATALOG = (
    Step("trailing", CARRIERS, "data after the end of {file}'s own structure"),
    Step("carve", CARRIERS, "a file embedded in {file} (zip, 7z, rar, gzip, zlib, png, jpeg, gif, pdf, elf, pe, riff), "
                            "archives unpacked"),
    Step("chunk-crc", frozenset({"png"}), "a chunk of {file} with a wrong CRC (IHDR: the real size), a non-standard "
                                          "chunk, or data in IDAT past the picture"),
    Step("metadata-concat", CARRIERS, "a flag in the metadata fields of {file} (text chunks, comments, EXIF, XMP, "
                                      "RIFF INFO), alone or split across fields"),
    Step("lsb-planes", IMAGE, "a payload in bit planes 0-7 of {file}, every channel set, rows and columns, both bit "
                              "orders, judged by file magic, a length prefix and text"),
    Step("lsb-deep", IMAGE, "a payload in bit 0 of {file} in snake orders, planes or channels combined, or "
                            "adjacent-pixel parity"),
    Step("plane-grep", IMAGE, "the flag, as it stands or base64/base32/hex, anywhere in the first 64 KiB of a bit "
                              "plane reading of {file}"),
    Step("steganalysis", STILL, "a statistical trace of embedding in {file} (chi-square, RS, sample pairs, JPEG "
                                "DCT and ELA)"),
    Step("wav-lsb", AUDIO, "a payload in sample bits 0-1 of {file}"),
    Step("wav-named-tools", AUDIO, "a named WAV-stego tool's payload in {file} (WavSteg, the password-seeded LSB "
                                   "sweep over B-130's committed list)"),
    Step("stegseek-seed", STEGHIDE, "steghide data in {file}, found with no passphrase (stegseek --seed)"),
    Step("exiftool", CARRIERS, "a flag in any tag exiftool reads in {file}, alone or split across tags"),
)
STEP_KEYS = tuple(s.key for s in CATALOG)
# the steps that recover payloads (texts for text-decode, carriers swept as files of their own); plane-grep
# and steganalysis only judge, so a settled one hides nothing
REPLAY_STEPS = frozenset(STEP_KEYS) - {"plane-grep", "steganalysis"}
RENDER_PREFIX = "render:"
TEXT_DECODE = "text-decode"
TEXT_DECODE_HYPOTHESIS = ("a text recovered by a step is the flag under a keyless encoding (rot13 and the other "
                          "rotations, atbash, reversal, single-byte xor, the base families)")

NOT_COVERED = (
    "passphrase tools under a passphrase the question states (steghide, outguess, stegseek's word list): "
    "stego_tools.survey",
    "JPEG DCT-coefficient stego (jsteg, F5) and OutGuess: jpeg_stego, f5_stego",
    "QR codes, barcodes and drawn symbol streams: carve_stego.decode_codes and the B-117 visual suite",
    "a password-protected archive member: the password is the player's (archive_passwords, tools/password.py)",
    "data after the end of a TIFF (its end is not proven here)",
    "speech, SSTV, DTMF, Morse and modem tones meant to be heard: stego_tools, signal_stego",
    "a keyed pixel shuffle with a key the delivery does not state",
    "a message only in the difference of the stereo channels (the spectrogram read averages them)",
    "audio that is not PCM WAV (convert it first: only WAV is swept)",
    "frames of an animated GIF or WebP after the first",
    "pictures with samples wider than 8 bits, and the pixel bits of a JPEG (its stored bits are coefficients)",
    "writing OCR cannot read: a rendering with something drawn is written as PNG for a human or model",
)


class StepNA(Exception):
    """The step does not apply to this file (the reason says why); it is no gap in the catalog."""


class StepNotRun(Exception):
    """The step could not run (the reason names what is missing): NOT RUN, never negative."""


# ---- one run's state ---------------------------------------------------------------------------------

@dataclass
class Outcome:
    step: str
    file: str | None
    sha256: str | None
    method: str
    hypothesis: str
    state: str
    evidence: str
    flags: list = field(default_factory=list)       # flags of the event it reaches, none rejected
    rejected: list = field(default_factory=list)    # rejected flags it reaches
    payloads: list = field(default_factory=list)    # [{where, size, sha256, kind, preview}]
    more: int = 0                                   # payloads past MAX_PAYLOADS
    plain: list = field(default_factory=list)       # of `flags`, those read from bytes as they stand
    ledger: str | None = None                       # set when the hypothesis ledger settled it: why

    def to_dict(self) -> dict:
        return asdict(self)


def method_of(step: str, file: str | None = None, sha256: str | None = None) -> str:
    """The hypothesis-ledger method string of one step: what `ctf hypothesis check` is asked. A file
    step names the file and its content (a changed file is a new method)."""
    return f"{ENGINE} {step}" + (f" {file}@{sha256[:12]}" if file else "")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _preview(data: bytes, n: int = 72) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in data[:n])


def _text(part: bytes):
    """The bytes as a printable text worth decoding (6 to MAX_TEXT characters), or None."""
    if not 6 <= len(part) <= 4 * MAX_TEXT:
        return None
    try:
        t = part.decode("utf-8")
    except UnicodeDecodeError:
        return None
    t = t.strip("\x00").strip()
    if len(t) < 6 or not all(c.isprintable() or c in "\r\n\t" for c in t):
        return None
    return t[:MAX_TEXT]


_B64 = re.compile(r"[A-Za-z0-9+/=\s]{16,}")


def _b64_blob(text: str):
    """The bytes a whole text decodes to as base64 when they are a file this harness sweeps or unpacks
    (a carrier or an archive), else None."""
    if not _B64.fullmatch(text):
        return None
    s = re.sub(r"\s+", "", text)
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if cs.sniff(raw) in CARRIERS | {"zip", "gzip", "7z", "rar", "tar"} else None


class _Run:
    def __init__(self, ff, *, deadline, rejected, sandbox, clock):
        self.ff, self.deadline, self.clock = ff, deadline, clock
        self.rejected = set(rejected)
        self.sandbox = sandbox
        self.texts: list = []                       # (file, where, text) for text-decode
        self.queue: list = []                       # (name, data, depth, parent, where)
        self.seen: set = set()                      # sha256 of every file swept or queued
        self.human_steps: list = []
        self.skipped_children: list = []
        self.regained: set = set()                  # settled steps whose payloads this run has again
        #                                             (handed back by the store, or the step re-run)
        self.unreplayed: list = []                  # settled steps that could not be run again, and why
        self.store: Path | None = None              # store_dir of the challenge (ledger runs only)
        self.recovered: dict = {}                   # method -> what a step that ran to its end recovered
        self.decoded_new: list = []                 # decode keys of texts read with no flag in this run

    def late(self) -> bool:
        return self.deadline is not None and self.clock() > self.deadline

    def child(self, parent: str, where: str, data: bytes, depth: int) -> None:
        """Queue a carrier found inside a file, to be swept as a file of its own."""
        if not _is_carrier(data):
            return
        kind = cs.sniff(data)
        digest = _sha(data)
        if digest in self.seen:
            return
        name = f"{parent}{cs.ARROW}{where}"
        if depth + 1 > MAX_DEPTH:
            self.skipped_children.append(f"{name}: a {kind} deeper than {MAX_DEPTH} levels is not swept")
            return
        if len(self.queue) >= MAX_CHILDREN:
            self.skipped_children.append(f"{name}: more than {MAX_CHILDREN} carriers found inside: not swept")
            return
        self.seen.add(digest)
        self.queue.append((name, data, depth + 1, parent, where))


def _is_carrier(data: bytes) -> bool:
    return len(data) > 8 and cs.sniff(data) in CARRIERS


class _Look:
    """What one step saw: the payloads it recovered (each searched for the flag), the flags, what stays
    open, the indicators, and why it stopped early (`cut`). `texts`, `children` and `human` are what
    it handed on (to text-decode, to the sweep, to the human steps): the store keeps them."""

    def __init__(self, run: _Run, name: str, depth: int):
        self.run, self.name, self.depth = run, name, depth
        self.payloads, self.flags, self.plain, self.rejected = [], [], [], []
        self.open, self.indicators, self.notes = [], [], []
        self.texts, self.children, self.human = [], [], []
        self.where: dict = {}
        self.cut: str | None = None

    def _child(self, where: str, data: bytes) -> None:
        if _is_carrier(data):
            self.children.append((where, bytes(data)))
        self.run.child(self.name, where, data, self.depth)

    def human_step(self, line: str) -> None:
        self.human.append(line)
        if line not in self.run.human_steps:
            self.run.human_steps.append(line)

    def _flag(self, found, plain, where: str) -> None:
        for f in found:
            if f in self.run.rejected:
                if f not in self.rejected:
                    self.rejected.append(f)
            elif f not in self.flags:
                self.flags.append(f)
                self.where[f] = where
            if f in plain and f not in self.plain and f not in self.run.rejected:
                self.plain.append(f)

    def blob(self, where: str, data: bytes, *, decoded: bool = False) -> None:
        """One recovered payload: listed, unpacked (gzip, zip, tar), searched for the flag as it stands
        and decoded, its texts kept for text-decode, a carrier inside it queued as a file."""
        data = bytes(data)
        self.payloads.append({"where": where, "size": len(data), "sha256": _sha(data)[:16],
                              "kind": cs.sniff(data) if len(data) > 8 else "data", "preview": _preview(data)})
        for label, part in ic.unpack(data):
            if label.endswith(ENCRYPTED):
                self.open.append(f"{where}{label[:-len(ENCRYPTED)]}: an encrypted archive member (its password "
                                 "is the player's to give)")
                continue
            here = where + label
            self._flag(ic.flags_in(part, self.run.ff), self.run.ff.find_flags(part), here)
            if label:
                self._child(here, part)
            t = _text(part)
            if t is not None:
                self.texts.append((here, t))
                self.run.texts.append((self.name, here, t))
                inner = None if decoded else _b64_blob(t)
                if inner is not None:
                    self.blob(f"{here} (base64)", inner, decoded=True)
        self._child(where, data)

    def fields(self, fields: list, what: str) -> int:
        """Metadata fields [(where, text)]: each searched alone, then concatenated in file order and in
        field-name order (stripped), so a flag split across fields is read whole."""
        fields = [(w, t) for w, t in fields if isinstance(t, str) and t.strip()]
        for w, t in fields:
            self.blob(w, t.encode("utf-8", "replace"))
        if len(fields) >= 2:
            for label, joined in (("in file order", "".join(t.strip() for _, t in fields)),
                                  ("in field-name order", "".join(t.strip() for _, t in sorted(fields)))):
                self._flag(ic.flags_in(joined, self.run.ff), self.run.ff.find_flags(joined),
                           f"{what} fields concatenated {label}")
        return len(fields)


# ---- the per-file steps -------------------------------------------------------------------------------

def _step_trailing(look: _Look, kind: str, data: bytes) -> str:
    end = cs.primary(data)[1]
    if not end:
        raise StepNA(f"where a {kind} ends is not proven here, so data after it is not looked for")
    t = cs.trailing(data)
    if t is None:
        return f"nothing after the {kind} end at {end:#x}"
    look.blob(f"after the {kind} end at {t[0]:#x}", t[1])
    return f"{len(t[1])} bytes after the {kind} end at {t[0]:#x}"


def _step_carve(look: _Look, kind: str, data: bytes) -> str:
    hits = cs.carve(data)
    if len(data) > cs.MAX_SCAN:
        # carve_stego.carve looks for embedded files only in the first MAX_SCAN bytes: the rest is not
        # ruled out, so the step is cut (NOT RUN unless it reached a flag), never negative
        look.cut = (f"carve_stego.carve searches only the first {cs.MAX_SCAN} of the {len(data)} bytes for "
                    "embedded files")
    for h in hits:
        body = h.get("inflated") if h["kind"] == "zlib" else h["data"]
        look.blob(f"{h['kind']} at {h['offset']:#x}" + ("" if h.get("validated", True) else " (not validated)"), body)
    return f"{len(hits)} embedded files" if hits else "no embedded file"


def _step_chunk_crc(look: _Look, kind: str, data: bytes) -> str:
    chunks = cs.png_chunks(data)
    if not chunks:
        raise StepNotRun("the PNG chunks could not be walked")
    bad, odd = [], []
    for c in chunks:
        if not c["crc_ok"]:
            bad.append(c["type"])
            if c["type"] == "IHDR":
                fix = cs.png_fix_dimensions(data)
                if fix:
                    fixed = data[:16] + struct.pack(">II", *fix) + data[24:]
                    look.notes.append(f"IHDR CRC matches {fix[0]}x{fix[1]}: the repaired picture is swept")
                    look.blob(f"IHDR repaired to {fix[0]}x{fix[1]}", fixed)
                else:
                    look.open.append("the IHDR CRC is wrong and no width or height up to the search limit "
                                     "makes it right: repair the header by hand")
            else:
                look.blob(f"chunk {c['type']} at {c['offset']:#x} (wrong CRC)", c["data"])
        if not c["standard"] and not c["after_iend"]:
            odd.append(c["type"])
            look.blob(f"non-standard chunk {c['type']} at {c['offset']:#x}", c["data"])
    for where, extra in cs.png_idat_extra(data, chunks):
        look.blob(f"IDAT: {len(extra)} bytes {where}", extra)
    return (f"{len(chunks)} chunks; " + (f"wrong CRC: {', '.join(bad)}" if bad else "every CRC right")
            + (f"; non-standard: {', '.join(odd)}" if odd else ""))


def _riff_chunks(data: bytes) -> list:
    out, i = [], 12
    while i + 8 <= len(data) and len(out) < 1000:
        cid, size = data[i:i + 4], struct.unpack_from("<I", data, i + 4)[0]
        out.append((cid.decode("latin-1"), i, data[i + 8:i + 8 + size]))
        i += 8 + size + (size & 1)
    return out


_XMP_TEXT = re.compile(r">([^<>]+)<")
_XMP_ATTR = re.compile(r"\s([\w:.-]+)=\"([^\"]*)\"")
XMP_ID = b"http://ns.adobe.com/xap/1.0/\x00"


def _xmp_fields(xml: str, where: str) -> list:
    out = [(f"{where} @{name}", v) for name, v in _XMP_ATTR.findall(xml) if not name.startswith("xmlns")]
    out += [(f"{where} text", t) for t in _XMP_TEXT.findall(xml) if t.strip()]
    return out


def _exif_blocks(kind: str, data: bytes) -> list:
    """[(where, raw EXIF/TIFF bytes)] of a file, read from its own structure (no decoder opens the
    picture, so a damaged one still gives its EXIF)."""
    if kind == "png":
        return [(f"eXIf at {c['offset']:#x}", c["data"]) for c in cs.png_chunks(data) if c["type"] == "eXIf"]
    if kind == "jpeg":
        return [(f"APP1 Exif at {s['offset']:#x}", data[s["offset"] + 4:s["offset"] + 2 + s["length"]])
                for s in cs.jpeg_segments(data) if s.get("ident") == "Exif"]
    if kind == "webp":
        return [(f"EXIF chunk at {off:#x}", body) for cid, off, body in _riff_chunks(data) if cid == "EXIF"]
    if kind == "tiff":
        return [("the TIFF's own IFDs", data)]
    return []


def _exif_fields(raw: bytes, where: str) -> list:
    """The text tags of one EXIF block (IFD0, Exif, GPS): [(where, text)]. Pillow parses it; a block
    Pillow cannot parse is handed back whole as one field."""
    try:
        from PIL import ExifTags, Image
    except ImportError as e:
        raise StepNotRun(f"Pillow is not importable, so the EXIF in {where} is not read ({e})") from e
    ex = Image.Exif()
    try:
        ex.load(raw)
        ifds = [("IFD0", dict(ex))]
        for tag, name in ((0x8769, "Exif"), (0x8825, "GPS")):
            try:
                ifds.append((name, dict(ex.get_ifd(tag))))
            except Exception:                       # an IFD pointer to nowhere: the others still read
                continue
    except Exception:
        return [(f"{where} (not parsed)", raw.decode("latin-1"))]
    out = []
    for ifd, tags in ifds:
        for tag in sorted(tags):
            v = tags[tag]
            if isinstance(v, bytes):
                v = (v[8:] if v[:8] in (b"ASCII\x00\x00\x00", b"UNICODE\x00", b"\x00" * 8) else v)
                v = v.decode("utf-8", "replace")
            if isinstance(v, str) and v.strip("\x00 "):
                out.append((f"{where} {ifd}:{ExifTags.TAGS.get(tag, hex(tag))}", v.strip("\x00")))
    return out


def _step_metadata(look: _Look, kind: str, data: bytes) -> str:
    fields = []
    if kind == "png":
        fields += [(f"{typ} {key}", value) for typ, key, value in cs.png_text(data)]
        for typ, key, value in cs.png_text(data):
            if key == "XML:com.adobe.xmp":
                fields += _xmp_fields(value, f"XMP in {typ}")
    elif kind == "jpeg":
        for s in cs.jpeg_segments(data):
            if s["name"] == "COM":
                fields.append((f"COM at {s['offset']:#x}", s.get("text", "")))
            elif s.get("ident", "").startswith("http://ns.adobe.com/xap/1.0/"):
                body = data[s["offset"] + 4:s["offset"] + 2 + s["length"]]
                xml = body[len(XMP_ID):].decode("utf-8", "replace") if body.startswith(XMP_ID) else ""
                fields += _xmp_fields(xml, f"XMP at {s['offset']:#x}")
    elif kind == "gif":
        blocks = cs.gif_blocks(data)
        fields += [(f"GIF comment {i}", t) for i, t in enumerate(blocks["comments"])]
        fields += [(f"GIF application {i}", t) for i, t in enumerate(blocks["apps"])]
    elif kind == "webp":
        for cid, off, body in _riff_chunks(data):
            if cid == "XMP ":
                fields += _xmp_fields(body.decode("utf-8", "replace"), f"XMP chunk at {off:#x}")
    elif kind == "wav":
        info = cs.wav_info(data) or {"chunks": [], "info": {}}
        fields += [(f"LIST/INFO {k}", v) for k, v in info["info"].items()]
        for c in info["chunks"]:
            if c["id"] not in cs.WAV_STANDARD:
                look.blob(f"chunk {c['id']!r} at {c['offset']:#x}", data[c["offset"] + 8:c["offset"] + 8 + c["size"]])
    for where, raw in _exif_blocks(kind, data):
        fields += _exif_fields(raw, where)
    n = look.fields(fields, "metadata")
    return f"{n} metadata fields" if n else "no metadata text"


def _pixels(kind: str, data: bytes) -> dict:
    try:
        px = _PIXELS[kind](data)
    except Exception as e:
        raise StepNotRun(f"the {kind}'s pixels could not be read ({type(e).__name__}: {e})") from e
    if not px:
        raise StepNotRun(f"the {kind}'s pixels could not be read (a damaged or unsupported picture)")
    if px["width"] * px["height"] > cs.MAX_PIXELS:
        raise StepNotRun(f"{px['width']}x{px['height']} is over carve_stego's {cs.MAX_PIXELS} pixels")
    return px


def channel_sets(mode: str) -> list:
    """The channel sets lsb_scan reads: every colour channel together, reversed, each alone, and the
    alpha with and without the rest."""
    color = mode.replace("A", "") or mode
    sets = [color]
    if len(color) == 3:
        sets += [color[::-1], *color]
    if "A" in mode:
        sets += [mode, "A"]
    return list(dict.fromkeys(sets))


def _cut(look: _Look, skipped: list) -> None:
    late = [s for s in skipped if "out of time" in s]
    if late:
        look.cut = late[0]
    look.notes += [s for s in skipped if "out of time" not in s]


def _step_lsb_planes(look: _Look, kind: str, data: bytes, px: dict) -> str:
    skipped: list = []
    hits = cs.lsb_scan(px, deadline=look.run.deadline, skipped=skipped)
    seen = {h["data"] if h["what"] == "file" else h["text"] for h in hits}
    hits += cs.plane_scan(px, deadline=look.run.deadline, skipped=skipped, seen=seen)
    for h in hits:
        look.blob(h["method"], h["data"] if h["what"] == "file" else h["text"].encode("utf-8", "replace"))
    _cut(look, skipped)
    return f"{px['mode']} {px['width']}x{px['height']}: {len(hits)} readings parse"


def _step_lsb_deep(look: _Look, kind: str, data: bytes, px: dict) -> str:
    skipped: list = []
    hits = cs.lsb_deep_scan(px, deadline=look.run.deadline, skipped=skipped)
    for h in hits:
        look.blob(h["method"], h["data"] if h["what"] == "file" else h["text"].encode("utf-8", "replace"))
    _cut(look, skipped)
    return f"{len(hits)} readings parse"


def _step_plane_grep(look: _Look, kind: str, data: bytes, px: dict) -> str:
    if not look.run.ff.known:
        raise StepNotRun("the event's flag prefix is not known, so a match in a bit plane proves nothing")
    n = 0
    for bit in PLANE_BITS:
        for chans in channel_sets(px["mode"]):
            for order in ("xy", "yx"):
                for msb in (True, False):
                    if look.run.late():
                        look.cut = f"out of time after {n} plane readings"
                        return f"{n} plane readings searched"
                    blob = cs.lsb_extract(px, chans, bit, order, msb)
                    n += 1
                    found = ic.flags_in(blob, look.run.ff)
                    if found:
                        where = f"bit{bit} {chans} {order} {'msb' if msb else 'lsb'}-first"
                        look._flag(found, look.run.ff.find_flags(blob), where)
                        look.payloads.append({"where": where, "size": len(blob), "sha256": _sha(blob)[:16],
                                              "kind": "plane", "preview": _preview(blob)})
    return f"{n} plane readings searched (bits 0-7, {len(channel_sets(px['mode']))} channel sets, rows and " \
           f"columns, both bit orders)"


def _analysable(data: bytes) -> str | None:
    """Why steganalysis cannot judge this picture, or None when it can."""
    try:
        from PIL import Image
    except ImportError as e:
        raise StepNotRun(f"Pillow is not importable ({e})") from e
    try:
        with Image.open(io.BytesIO(data)) as im:
            fmt, mode, frames = (im.format or "").upper(), im.mode, getattr(im, "n_frames", 1)
    except Exception as e:
        return f"Pillow cannot open it ({type(e).__name__})"
    if fmt not in ANALYSIS:
        return f"its detectors do not judge {fmt or 'this format'} (decoding replaces the stored samples)"
    if frames != 1:
        return "an animated picture"
    if fmt != "JPEG" and mode not in ANALYSIS_MODES:
        return f"its detectors do not judge {mode} samples (a paletted or wide picture)"
    return None


def _step_steganalysis(look: _Look, kind: str, data: bytes) -> str:
    why = _analysable(data)
    if why:
        raise StepNA(f"steganalysis does not apply: {why}")
    found = sa.analyze_image(data)
    for f in found:
        look.indicators.append(f"{f.method} on {f.channel} (score {f.score:.2f}): {f.evidence}")
    return f"{len(found)} detectors fired" if found else "no detector fired"


def _step_wav_lsb(look: _Look, kind: str, data: bytes) -> str:
    info = cs.wav_info(data)
    if not info or info["data_offset"] is None or not info["bits"] or info["bits"] % 8:
        raise StepNA("not a PCM WAV with byte-wide samples")
    hits = cs.wav_lsb(data, info)
    for h in hits:
        look.blob(h["method"], h["data"] if h["what"] == "file" else h["text"].encode("utf-8", "replace"))
    return f"{info['bits']}-bit samples: {len(hits)} readings parse"


def _step_wav_named(look: _Look, kind: str, data: bytes) -> str:
    fp = wst.fingerprint(data)
    if fp["carrier"] is None:
        raise StepNA("; ".join(fp["notes"]) or "not a PCM WAV")
    r = wst.offline_sweep(data)
    for key, step in fp["human"]:
        look.human_step(f"{key}: {step}")
    if r.plain is not None:
        look.blob(f"{r.tool}: {r.method}", r.plain)
    for name, value in r.candidates:
        look.blob(f"candidate {name}", value if isinstance(value, bytes) else str(value).encode("utf-8", "replace"))
    if r.need_password:
        look.open.append("a named tool's container is there but needs a passphrase the delivery does not state")
    return ("self-validated payload by " + r.tool if r.plain is not None
            else f"WavSteg N=1..4 and the password-seeded sweep: no self-validated payload")


def _unread(rec) -> str | None:
    """Why a sandbox Rec is no reading (sandbox down, not started, timed path, a tool that failed), or
    None when the program gave its verdict."""
    if getattr(rec, "ok", False):
        return None
    return getattr(rec, "note", "") or "the sandbox tool gave no reading"


def _step_stegseek_seed(look: _Look, kind: str, data: bytes) -> str:
    rec = look.run.sandbox.stegseek_seed(data)
    why = _unread(rec)
    if why:
        raise StepNotRun(why)
    if rec.data is None:
        return rec.note or "no steghide seed"
    payload = (rec.files or {}).get("payload")
    if payload is not None:
        look.blob(f"steghide payload (seed {rec.data.get('seed')})", payload)
    else:
        look.open.append(f"steghide data (seed {rec.data.get('seed')}, encryption {rec.data.get('algorithm')}): "
                         "it needs its passphrase")
    return rec.note


def _step_exiftool(look: _Look, kind: str, data: bytes, name: str) -> str:
    rec = look.run.sandbox.exif(data, name)
    why = _unread(rec)
    if why:
        raise StepNotRun(why)
    row = rec.data or {}
    said = [f"{k.split(':', 1)[1]}: {v}" for k, v in row.items() if k.startswith("ExifTool:")]
    fields = [(f"exiftool {k}", v if isinstance(v, str) else json.dumps(v)) for k, v in row.items()
              if not k.startswith("ExifTool:")]
    n = look.fields(fields, "exiftool")
    look.notes += said
    return f"{n} tags" + (f"; {'; '.join(said)[:200]}" if said else "")


_FILE_STEPS = {
    "trailing": _step_trailing, "carve": _step_carve, "chunk-crc": _step_chunk_crc,
    "metadata-concat": _step_metadata, "steganalysis": _step_steganalysis, "wav-lsb": _step_wav_lsb,
    "wav-named-tools": _step_wav_named, "stegseek-seed": _step_stegseek_seed,
}
_PIXEL_STEPS = {"lsb-planes": _step_lsb_planes, "lsb-deep": _step_lsb_deep, "plane-grep": _step_plane_grep}


def _outcome(step: Step, name: str, digest: str, look: _Look, base: str) -> Outcome:
    if look.flags:
        state = FLAG
    elif look.cut:
        state = NOT_RUN
    elif look.open:
        state = OPEN
    elif look.rejected:
        state = REJECTED
    elif look.indicators:
        state = INDICATOR
    elif look.payloads:
        state = RECOVERED
    else:
        state = NEGATIVE
    parts = [base]
    if look.flags:
        parts.append("flag " + "; ".join(f"{f} ({look.where[f]})" for f in look.flags))
    if look.rejected:
        parts.append("rejected flag reached again: " + ", ".join(look.rejected))
    if look.cut:
        parts.append(f"cut: {look.cut}: not ruled out")
    parts += look.open + look.indicators + look.notes
    return Outcome(step.key, name, digest, method_of(step.key, name, digest), step.hypothesis.format(file=name),
                   state, "; ".join(parts), flags=list(look.flags), rejected=list(look.rejected),
                   payloads=look.payloads[:MAX_PAYLOADS], more=max(0, len(look.payloads) - MAX_PAYLOADS),
                   plain=list(look.plain))


def _run_step(run: _Run, step: Step, name: str, kind: str, data: bytes, depth: int, px_cache: dict,
              cuts: list | None = None) -> Outcome:
    """One step over one file. `cuts` (when given) gets why the step stopped before its end, if it did."""
    digest = _sha(data)
    look = _Look(run, name, depth)

    def plain(state, evidence):
        return Outcome(step.key, name, digest, method_of(step.key, name, digest), step.hypothesis.format(file=name),
                       state, evidence)

    if run.late():
        return plain(NOT_RUN, "out of time before this step")
    try:
        if step.key in _PIXEL_STEPS:
            if "px" not in px_cache:
                try:
                    px_cache["px"] = _pixels(kind, data)
                except StepNotRun as e:
                    px_cache["px"] = e
            if isinstance(px_cache["px"], StepNotRun):
                raise px_cache["px"]
            base = _PIXEL_STEPS[step.key](look, kind, data, px_cache["px"])
        elif step.key == "exiftool":
            base = _step_exiftool(look, kind, data, Path(name.split(cs.ARROW)[-1]).name or "file")
        else:
            base = _FILE_STEPS[step.key](look, kind, data)
    except StepNA as e:
        return plain(NA, str(e))
    except StepNotRun as e:
        return plain(NOT_RUN, str(e))
    if cuts is not None and look.cut:
        cuts.append(look.cut)
    out = _outcome(step, name, digest, look, base)
    if look.cut is None and step.key in REPLAY_STEPS:      # (a step that ran uncut is never NOT RUN)
        # it ran to its end: what it handed on is kept, so a run the ledger settles it in gets it back
        run.recovered[out.method] = {"texts": list(look.texts), "children": list(look.children),
                                     "human": list(look.human)}
    return out


def _replay(run: _Run, step: Step, name: str, kind: str, data: bytes, depth: int, px_cache: dict,
            method: str) -> None:
    """Run a step the ledger settled again, for what it recovers only: its texts go to text-decode and
    the carriers it finds are swept. Its outcome is not kept (the ledger's stands) and not recorded."""
    cuts: list = []
    again = _run_step(run, step, name, kind, data, depth, px_cache, cuts=cuts)
    if again.state == NOT_RUN or cuts:
        run.unreplayed.append(f"{name} {step.key}: {(cuts[0] if cuts else again.evidence)[:160]}")
    else:
        run.regained.add(method)


# ---- what the steps recovered, kept beside the ledger ------------------------------------------------

STORE_SCHEMA = 1


def store_dir(cid: str, workdir=None) -> Path:
    """Where the harness keeps what each step recovered for one challenge: <workdir>/stego_exhaust/<id>/
    (steps/<method key>.json, blobs/<sha256>, decoded/<key>). It sits beside the hypothesis ledger
    and is read only when the ledger is, written only when the run records."""
    from ctf import hypothesis as hyp
    p = hyp.path(cid, workdir)
    return p.parent.parent / OUT_NAME / p.stem


def _entry_path(store: Path, method: str) -> Path:
    from ctf import hypothesis as hyp
    return store / "steps" / f"{_sha(hyp.normalize_method(method).encode('utf-8'))[:32]}.json"


def _atomic_write(p: Path, data: bytes) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{_sha(data)[:8]}.tmp")
    tmp.write_bytes(data)
    tmp.replace(p)


def _write_store(store: Path, recovered: dict, decoded: list) -> None:
    """Keep what each step that ran to its end recovered (its carriers as blobs named by sha256) and
    the texts decoded with no flag."""
    from ctf import hypothesis as hyp
    for method in sorted(recovered):
        got = recovered[method]
        for _where, data in got["children"]:
            blob = store / "blobs" / _sha(data)
            if not blob.is_file():
                _atomic_write(blob, data)
        row = {"schema": STORE_SCHEMA, "method": hyp.normalize_method(method),
               "texts": [list(t) for t in got["texts"]],
               "children": [[where, _sha(data)] for where, data in got["children"]], "human": list(got["human"])}
        _atomic_write(_entry_path(store, method), json.dumps(row, sort_keys=True).encode("utf-8"))
    for key in decoded:
        mark = store / "decoded" / key
        if not mark.is_file():
            _atomic_write(mark, b"")


def _restore(run: _Run, method: str, name: str, depth: int) -> bool:
    """Hand back what a settled step recovered when it ran (its texts, its carriers, queued as files of
    their own, its human steps), as if it had run again. False when the store does not hold it whole
    (no entry, another schema, a blob missing or not matching its sha256): then nothing is handed
    back and the caller re-runs the step."""
    from ctf import hypothesis as hyp
    if run.store is None:
        return False
    try:
        row = json.loads(_entry_path(run.store, method).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(row, dict) or row.get("schema") != STORE_SCHEMA \
            or row.get("method") != hyp.normalize_method(method):
        return False
    children = []
    for where, digest in row.get("children", []):
        try:
            data = (run.store / "blobs" / str(digest)).read_bytes()
        except OSError:
            return False
        if _sha(data) != digest:
            return False
        children.append((where, data))
    for where, t in row.get("texts", []):
        run.texts.append((name, where, t))
    for line in row.get("human", []):
        if line not in run.human_steps:
            run.human_steps.append(line)
    for where, data in children:
        run.child(name, where, data, depth)
    run.regained.add(method)
    return True


def decode_key(ff, text: str) -> str:
    """The store's name for one text read through the keyless decoder under this flag format."""
    return _sha(f"{ff.pattern}\x00{ff.spec.case}\x00{text}".encode("utf-8", "surrogateescape"))


def _decoded(run: _Run, key: str) -> bool:
    return run.store is not None and (run.store / "decoded" / key).is_file()


# ---- the hypothesis ledger ---------------------------------------------------------------------------

def _ledger_rejected(cid: str, workdir) -> set:
    """Every flag the ledger holds as a false positive: the payload of the positive each correction
    corrects. They are rejected everywhere in this run, whichever step reaches them."""
    from ctf import hypothesis as hyp
    out, last_positive = set(), {}
    for r in hyp.read(cid, workdir):
        if r.get("result") == hyp.POSITIVE and r.get("payload"):
            last_positive[r.get("method_key")] = r["payload"]
        elif r.get("result") == hyp.FALSE_POSITIVE and r.get("method_key") in last_positive:
            out.add(last_positive[r["method_key"]])
    return out


def _settled(cid: str, method: str, workdir, rejected: set) -> tuple | None:
    """(state, flags, rejected, why) when the ledger settles this method, else None."""
    from ctf import hypothesis as hyp
    s = hyp.should_skip(cid, method, workdir)
    if not s.skip:
        return None
    prior = s.prior or {}
    why = f"settled in the hypothesis ledger by {prior.get('agent', 'unknown')} ({prior.get('result')})"
    if prior.get("evidence"):
        why += f": {str(prior['evidence'])[:300]}"
    res = prior.get("result")
    if res == hyp.POSITIVE:
        f = prior.get("payload") or ""
        return (REJECTED, [], [f], why) if f in rejected else (FLAG, [f] if f else [], [], why)
    if res == hyp.FALSE_POSITIVE:
        pos = [r.get("payload") for r in hyp.read(cid, workdir)
               if r.get("method_key") == hyp.normalize_method(method) and r.get("result") == hyp.POSITIVE]
        return REJECTED, [], [p for p in pos[-1:] if p], why
    return NEGATIVE, [], [], why


def _parse_method(m: str):
    """(step, file) of one of this engine's file-step methods, else None."""
    prefix = f"{ENGINE} "
    if not m.startswith(prefix):
        return None
    step, _, rest = m[len(prefix):].partition(" ")
    file, at, _sha12 = rest.rpartition("@")
    if step not in STEP_KEYS or not at:
        return None
    return step, file


def _ledger_open_files(cid: str, workdir) -> set:
    """The files (as the methods name them) of which the ledger holds a step it does not settle."""
    from ctf import hypothesis as hyp
    methods = {}
    for r in hyp.read(cid, workdir):
        m = str(r.get("method") or "")
        got = _parse_method(m)
        if got is not None:
            methods.setdefault(hyp.normalize_method(m), (m, got[1]))
    return {file for m, file in methods.values() if not hyp.should_skip(cid, m, workdir).skip}


def _ledger_descendants(cid: str, workdir, rep, run: _Run) -> list:
    """The outcomes of carriers found INSIDE a file by an earlier run, read back from the ledger. A
    settled step is not run, so the carrier it found then (a PNG after the end, a picture in a plane)
    is not found again and its steps would drop out of the verdict: a flag found in it would turn into
    'nothing further'. Each step recorded under such a carrier comes back as the ledger has it (a
    settled one with its result, an unsettled one as NOT RUN). Only under a file swept in this run,
    at any depth, one of whose steps the ledger settled: its method names its sha256, so a changed
    file brings nothing back (a top-level file that changed while a carrier inside it did not still
    brings back what was found inside that carrier). When the ledger leaves a step under a file
    unsettled, that file's settled steps are handed back by the store or run again (_replay) and what
    they find is swept anew, so what comes back here is only what this run could not find again."""
    from ctf import hypothesis as hyp
    roots = sorted({o.file for o in rep.outcomes if o.ledger is not None and o.step in STEP_KEYS
                    and o.file in rep.files})
    if not roots:
        return []
    have = {hyp.normalize_method(o.method) for o in rep.outcomes}
    found = {}
    for r in hyp.read(cid, workdir):
        m = str(r.get("method") or "")
        got = _parse_method(m)
        if got is None:
            continue
        step, file = got
        root = next((x for x in roots if file.startswith(x + cs.ARROW)), None)
        if root is None:
            continue
        key = hyp.normalize_method(m)
        if key not in have:
            found[key] = (m, step, file, root)
    out = []
    for key in sorted(found):
        m, step, file, root = found[key]
        hypo = next(s.hypothesis for s in CATALOG if s.key == step).format(file=file)
        rep.files.setdefault(file, {"kind": None, "sha256": None, "size": None, "depth": file.count(cs.ARROW),
                                    "parent": root, "where": None, "from_ledger": True})
        s = _settled(cid, m, workdir, run.rejected)
        if s is not None:
            out.append(Outcome(step, file, None, m, hypo, s[0], f"found inside {root} by an earlier run; {s[3]}",
                               flags=s[1], rejected=s[2], ledger=s[3]))
        else:
            prior = hyp.seen(cid, m, workdir) or {}
            again = (f"; the settled step that found it could not be run again ({run.unreplayed[0]})"
                     if run.unreplayed else "")
            why = (f"found inside {root} by an earlier run and not found again in this run{again}; its last "
                   f"result is {prior.get('result')} ({str(prior.get('evidence', ''))[:160]}): not ruled out")
            out.append(Outcome(step, file, None, m, hypo, NOT_RUN, why, ledger=why))
    return out


_TO_LEDGER = {NEGATIVE: "negative", RECOVERED: "negative", INDICATOR: "negative", OPEN: "inconclusive",
              NOT_RUN: "error"}


def record_outcomes(cid: str, outcomes: list, *, workdir=None, profile=None, agent: str = ENGINE) -> list:
    """Write the fresh outcomes of a run (not those the ledger settled, not n/a ones) to the challenge's
    hypothesis ledger: a flag as a positive, a rejected reading as a positive followed by its
    false-positive correction, a step that ran with no flag as a negative (its evidence lists what it
    recovered), an open one as inconclusive and a step that did not run as an error (never negative,
    so it is run again). Render steps are written by render_ocr_sweep.file_checklist instead."""
    from ctf import hypothesis as hyp
    written = []
    for o in outcomes:
        if o.ledger is not None or o.state == NA or o.step.startswith(RENDER_PREFIX):
            continue
        common = dict(hypothesis=o.hypothesis, method=o.method, agent=agent, workdir=workdir)
        if o.state == FLAG:
            written.append(hyp.record(cid, result=hyp.POSITIVE, payload=o.flags[0], evidence=o.evidence,
                                      profile=profile, **common))
        elif o.state == REJECTED:
            prior = hyp.seen(cid, o.method, workdir)
            if prior is None or prior.get("result") != hyp.POSITIVE:
                written.append(hyp.record(cid, result=hyp.POSITIVE, payload=o.rejected[0], profile=profile,
                                          evidence="the reading the platform then rejected", **common))
            written.append(hyp.mark_false_positive(cid, o.method, agent=agent, evidence=o.evidence, workdir=workdir))
        else:
            written.append(hyp.record(cid, result=_TO_LEDGER[o.state], evidence=o.evidence, **common))
    return written


# ---- the delivery-wide steps -------------------------------------------------------------------------

_RS_STATE = {"negative": NEGATIVE, "positive": FLAG, "false_positive": REJECTED, "inconclusive": NOT_RUN,
             "error": NOT_RUN}


def _merge_checklists(rep, rejected: list) -> list:
    """render_ocr_sweep.checklist under every rejected flag: per item, a flag that is not rejected wins,
    then a rejected reading, then the item as it is."""
    runs = [rs.checklist(rep, rejected=r) for r in rejected] or [rs.checklist(rep)]
    out = []
    for i, first in enumerate(runs[0]):
        items = [run[i] for run in runs]
        pick = next((it for it in items if it["result"] == "positive" and it["payload"] not in rejected), None)
        pick = pick or next((it for it in items if it["result"] == "false_positive"), None)
        if pick is None and first["result"] == "positive":     # every flag it holds is rejected
            pick = {**first, "result": "false_positive",
                    "evidence": f"{first['evidence']}; its reading {first['payload']} was rejected"}
        out.append(pick or first)
    return out


def _render(run: _Run, files: dict, *, ocr: str, read, prefixes, rs_ledger: bool, cid, workdir, ledger: bool,
            out_dir) -> tuple:
    """B-126's sweep over the delivery: (outcomes, items to record)."""
    swept = {n: d for n, d in files.items() if rs.swept(d)}
    if not swept:
        return [], []
    if ledger:
        methods = [rs.method_of(p, n) for n, d in sorted(swept.items())
                   for p in ((rs.PROBE_SPEC, rs.PROBE_GLYPH) if d[:4] == b"RIFF" else (rs.PROBE_PLANE,))]
        methods += [rs.method_of(rs.PROBE_DECODE), rs.method_of(rs.PROBE_KEYS)]
        settled = [_settled(cid, m, workdir, run.rejected) for m in methods]
        if all(settled):
            return [Outcome(RENDER_PREFIX + m.split()[1], (m.split(None, 2)[2:] or [None])[0], None, m,
                            "render_ocr_sweep probe (settled)", s[0], s[3], flags=s[1], rejected=s[2], ledger=s[3])
                    for m, s in zip(methods, settled)], []
    if run.late():
        return [Outcome(RENDER_PREFIX + "sweep", None, None, f"{rs.ENGINE}", "render_ocr_sweep's probes", NOT_RUN,
                        "out of time before the render-and-read sweep")], []
    try:
        rep = rs.examine(swept, run.ff, ocr=ocr, out_dir=out_dir, deadline=run.deadline, prefixes=tuple(prefixes),
                         read=read, ledger=rs_ledger)
    except rs.ToolMissing as e:
        return [Outcome(RENDER_PREFIX + "sweep", None, None, f"{rs.ENGINE}", "render_ocr_sweep's probes", NOT_RUN,
                        f"OCR was asked for (ocr=on) but {e}")], []
    items = _merge_checklists(rep, sorted(run.rejected))
    outcomes, fresh = [], []
    for it in items:
        s = _settled(cid, it["method"], workdir, run.rejected) if ledger else None
        state = _RS_STATE[it["result"]]
        flags = [it["payload"]] if state == FLAG and it["payload"] else []
        rej = [it["payload"]] if state == REJECTED and it["payload"] else []
        outcomes.append(Outcome(RENDER_PREFIX + it["probe"], it["file"], None, it["method"], it["hypothesis"], state,
                                it["evidence"], flags=flags, rejected=rej, ledger=s[3] if s else None))
        if s is None:
            fresh.append(it)
    return outcomes, fresh


def delivery_digest(files: dict) -> str:
    """The sha256 of a delivery: its top-level names and their contents, in name order. The text
    decode's ledger method names it, so the same delivery is the same method whatever was recovered."""
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode("utf-8", "surrogateescape") + b"\x00" + _sha(bytes(files[name])).encode() + b"\n")
    return h.hexdigest()


def text_decode_method(files: dict) -> str:
    return f"{ENGINE} {TEXT_DECODE} {delivery_digest(files)[:12]}"


def _text_decode(run: _Run, outcomes: list, method: str) -> Outcome:
    texts = sorted({t for _f, _w, t in run.texts})[:MAX_TEXTS]
    o = Outcome(TEXT_DECODE, None, None, method, TEXT_DECODE_HYPOTHESIS, NEGATIVE, "")
    waiting = [x for x in outcomes if x.state == NOT_RUN and x.step in REPLAY_STEPS]
    # a step the ledger settled hands its texts back from the store, or is run again for them (_replay)
    # while this decode is not settled; one that did neither (the store does not hold it and the sandbox
    # is down now, the clock, found by an earlier run only) hid its texts
    hidden = [x for x in outcomes if x.ledger is not None and x.step in REPLAY_STEPS and x.method not in run.regained]
    if not run.ff.known:
        o.state, o.evidence = NOT_RUN, "the event's flag prefix is not known, so a decoded match proves nothing"
        return o
    if not texts:
        o.evidence = "no text was recovered, so there was nothing to decode"
    else:
        found, cut = {}, None
        # a text an earlier run read to the end with no flag of the event in any reading is not read again
        keys = {t: decode_key(run.ff, t) for t in texts}
        pending = [t for t in texts if not _decoded(run, keys[t])]
        for i, t in enumerate(pending):
            if run.late():
                cut = f"out of time before {len(pending) - i} of {len(texts)} texts"
                break
            try:
                got = rs.keyless_readings(t.encode("utf-8"), DECODE_SECONDS)
            except ImportError as e:
                o.state, o.evidence = NOT_RUN, f"crib_decode is not importable: {e}"
                return o
            hit = False
            for reading, chain in got.items():
                for f in run.ff.find_flags(reading):
                    hit = True
                    if f not in found or len(chain) < len(found[f][1]):
                        found[f] = (t, tuple(chain))
            if not hit:
                run.decoded_new.append(keys[t])
        # flags that differ only in case are one reading and its echo (rot13, then rot13 + swapcase):
        # only the shortest chain of each is kept, so a plain flag does not bring its case swap along
        shortest: dict = {}
        for f, (_t, chain) in found.items():
            shortest[f.casefold()] = min(shortest.get(f.casefold(), len(chain)), len(chain))
        found = {f: v for f, v in found.items() if len(v[1]) == shortest[f.casefold()]}
        flags = sorted(f for f in found if f not in run.rejected)
        rejected = sorted(f for f in found if f in run.rejected)
        o.evidence = f"{len(texts)} texts through crib_decode's keyless readings"
        if len(pending) < len(texts):
            o.evidence += f" ({len(texts) - len(pending)} read with no flag by an earlier run, not read again)"
        if flags:
            o.state, o.flags = FLAG, flags
            o.evidence += "; " + "; ".join(f"{f} from {found[f][0][:60]!r} "
                                           + (f"by {' + '.join(map(str, found[f][1]))}" if found[f][1] else "as it stands")
                                           for f in flags)
        elif cut:
            o.state, o.evidence = NOT_RUN, f"{o.evidence}; cut: {cut}: not ruled out"
        elif rejected:
            o.state, o.rejected = REJECTED, rejected
            o.evidence += f"; only rejected flags: {', '.join(rejected)}"
    if o.state == NEGATIVE and hidden:
        # the decode of the rest found nothing, but it has not read the delivery's texts all: not negative
        why = run.unreplayed[0] if run.unreplayed else (f"{hidden[0].file} {hidden[0].step}: found by an earlier "
                                                        "run and not found again")
        o.state = NOT_RUN
        o.evidence += (f"; not ruled out: {len(hidden)} steps settled by the hypothesis ledger could not be run "
                       f"again to recover their texts ({why}): run again once that is fixed")
    if o.state == NEGATIVE and waiting:
        o.state = NOT_RUN
        o.evidence += (f"; not ruled out: {len(waiting)} steps that recover texts did not run "
                       f"({waiting[0].file} {waiting[0].step}: {waiting[0].evidence[:120]})")
    return o


# ---- the report and its verdict ----------------------------------------------------------------------

@dataclass
class Report:
    files: dict = field(default_factory=dict)        # name -> {kind, sha256, depth, parent, where}
    outcomes: list = field(default_factory=list)
    skipped: list = field(default_factory=list)      # files not swept, and why
    rejected: list = field(default_factory=list)
    human_steps: list = field(default_factory=list)

    def verdict(self) -> dict:
        """The deterministic verdict: the same delivery, options and ledger give the same dict."""
        flags = list(dict.fromkeys(f for o in self.outcomes if o.state == FLAG for f in o.flags))
        not_run = [o for o in self.outcomes if o.state == NOT_RUN]
        open_ = [o for o in self.outcomes if o.state == OPEN]
        verdict = V_FLAG if flags else V_OPEN if open_ else V_NOTHING
        ran = [o for o in self.outcomes if o.state not in (NOT_RUN, NA)]

        def line(o):
            return {"file": o.file, "step": o.step, "method": o.method, "state": o.state, "evidence": o.evidence}

        return {
            "schema": SCHEMA, "engine": ENGINE, "verdict": verdict, "complete": bool(self.files) and not not_run,
            "flags": flags, "rejected": sorted(self.rejected),
            "rejected_reached": sorted({f for o in self.outcomes for f in o.rejected}),
            "files": {n: dict(i) for n, i in sorted(self.files.items())},
            "counts": {s: sum(o.state == s for o in self.outcomes) for s in STATES},
            "steps_ran": len(ran),
            "steps": [line(o) for o in self.outcomes],
            "not_run": [line(o) for o in not_run],
            "open": [line(o) for o in open_],
            "indicators": [line(o) for o in self.outcomes if o.state == INDICATOR],
            "skipped": list(self.skipped),
            "human_steps": list(self.human_steps),
            "not_covered": list(NOT_COVERED),
        }

    def to_dict(self) -> dict:
        return {**self.verdict(), "outcomes": [o.to_dict() for o in self.outcomes]}


LABEL = {FLAG: "FLAG", REJECTED: "REJECTED", OPEN: "OPEN", INDICATOR: "indicator", RECOVERED: "recovered",
         NEGATIVE: "negative", NOT_RUN: "NOT RUN", NA: "n/a"}


def verdict_text(rep: Report) -> str:
    v = rep.verdict()
    n_run, n_not = v["steps_ran"], len(v["not_run"])
    if v["verdict"] == V_FLAG:
        head = f"stego_exhaust verdict: FLAG {', '.join(v['flags'])}"
    elif v["verdict"] == V_OPEN:
        head = (f"stego_exhaust verdict: OPEN: {len(v['open'])} items the catalog cannot read further "
                "(each says what it needs)")
    elif not v["files"]:
        head = ("stego_exhaust verdict: NO CARRIER: nothing in the delivery is a file the catalog sweeps, so no "
                "step ran (see 'not swept')")
    elif v["complete"]:
        head = (f"stego_exhaust verdict: NOTHING FURTHER (complete): all {n_run} steps of the catalog ran and none "
                "reaches a flag. Do not try these steps again.")
    else:
        head = (f"stego_exhaust verdict: NOTHING FURTHER from the {n_run} steps that ran; {n_not} steps NOT RUN "
                "(not negative: run them to complete the catalog)")
    lines = [head]
    if v["rejected_reached"]:
        lines.append(f"  rejected flags reached again (not counted): {', '.join(v['rejected_reached'])}")
    lines.append("steps:")
    for o in rep.outcomes:
        where = o.file if o.file is not None else "(the delivery)"
        lines.append(f"  [{LABEL[o.state]:<9}] {where} {o.step}: {o.evidence[:400]}")
    if v["not_run"]:
        lines.append("not run (NOT negative):")
        lines += [f"  - {x['file'] or '(the delivery)'} {x['step']}: {x['evidence'][:300]}" for x in v["not_run"]]
    if v["skipped"]:
        lines.append("not swept:")
        lines += [f"  - {s}" for s in v["skipped"]]
    if v["human_steps"]:
        lines.append("human steps (named tools this machine never runs):")
        lines += [f"  - {s}" for s in v["human_steps"]]
    lines.append("not covered by the catalog:")
    lines += [f"  - {x}" for x in v["not_covered"]]
    return "\n".join(lines)


# ---- the harness -------------------------------------------------------------------------------------

class SandboxTools:
    """stegseek --seed and exiftool, run by stego_tools by docker exec in a stego sandbox container that
    is already up (stego_tools.no_start). Nothing here starts, builds or pulls a container."""

    def stegseek_seed(self, data: bytes):
        with st.no_start():
            return st.stegseek_seed(data)

    def exif(self, data: bytes, name: str):
        with st.no_start():
            return st.exif(data)


class NoSandbox:
    """The sandbox steps switched off: each is NOT RUN, saying so."""

    def stegseek_seed(self, data: bytes):
        return st.Rec(note="the sandbox steps are off (--no-sandbox / sandbox=off): not read", tool="stegseek")

    def exif(self, data: bytes, name: str):
        return st.Rec(note="the sandbox steps are off (--no-sandbox / sandbox=off): not read", tool="exiftool")


def exhaust(files: dict, ff, *, profile=None, deadline=None, rejected=(), sandbox=None, ocr: str = "auto", read=None,
            prefixes=(), cid: str | None = None, workdir=None, ledger: bool = False, record: bool = True,
            agent: str = ENGINE, out_dir: Path | None = None, rs_ledger: bool = True, clock=time.monotonic) -> Report:
    """The whole catalog over {name: bytes}. `ff` is the event's FlagFormat. `deadline` is a clock()
    value (time.monotonic); steps past it are NOT RUN. `sandbox` answers stegseek_seed(data) and
    exif(data, name) with stego_tools Recs (default SandboxTools: a container already up, never one
    started). `ocr` and `read` go to render_ocr_sweep. With `ledger` (needs `cid`), a step the
    hypothesis ledger settles keeps its recorded result and is not recorded again, and flags the
    ledger holds as false positives count as rejected. What it recovered when it ran comes back from
    the store (store_dir); a settled step the store does not hold is run again for what it recovers
    only while that is still wanted (the text decode is not settled, or a step under the file is
    not), and only after every unsettled step, so a partial run is completed by the next one. With
    `record` too, every fresh outcome is written there, and what the steps recovered to the store."""
    if ledger and not cid:
        raise ValueError("the hypothesis ledger needs a challenge id (cid)")
    if ocr not in ("auto", "on", "off"):
        raise ValueError("ocr must be auto, on or off")
    rejected = [str(r).strip() for r in rejected if str(r).strip()]
    prefixes = tuple(prefixes) or tuple(ff.spec.prefixes)
    if ledger:
        rejected += sorted(_ledger_rejected(cid, workdir) - set(rejected))
    run = _Run(ff, deadline=deadline, rejected=rejected, sandbox=sandbox or SandboxTools(), clock=clock)
    rep = Report(rejected=list(rejected))
    todo = []
    for name in sorted(files):
        data = bytes(files[name])
        kind = cs.sniff(data) if len(data) > 8 else "data"
        digest = _sha(data)
        if kind not in CARRIERS:
            rep.skipped.append(f"{name}: a {kind} file, not a carrier the catalog sweeps")
            continue
        if digest in run.seen:
            rep.skipped.append(f"{name}: the same bytes as a file already swept")
            continue
        run.seen.add(digest)
        todo.append((name, data, 0, None, None))
    swept: dict = {}
    td_method = text_decode_method(files)
    td_settled = _settled(cid, td_method, workdir, run.rejected) if ledger else None
    open_below = _ledger_open_files(cid, workdir) if ledger else set()
    if ledger:
        run.store = store_dir(cid, workdir)
    deferred: list = []                 # settled steps to run again, once every unsettled step has run
    while todo or run.queue or deferred:
        if not todo and not run.queue:
            # every unsettled step of every file found so far has had the clock: only now are settled
            # steps the store does not hold run again, with what time is left (what they find is queued)
            for args in deferred:
                _replay(run, *args)
            deferred = []
            continue
        if not todo:
            todo, run.queue = run.queue, []
        name, data, depth, parent, where = todo.pop(0)
        kind, digest = cs.sniff(data), _sha(data)
        rep.files[name] = {"kind": kind, "sha256": digest, "size": len(data), "depth": depth, "parent": parent,
                           "where": where}
        swept[name] = data
        px_cache: dict = {}
        # a settled step the store does not hold is run again (not recorded) while what it recovers is
        # still wanted: the text decode is not settled, or the ledger leaves a step under this file open
        replay = ledger and (td_settled is None or any(f.startswith(name + cs.ARROW) for f in open_below))
        for step in CATALOG:
            if kind not in step.kinds:
                continue
            method = method_of(step.key, name, digest)
            s = _settled(cid, method, workdir, run.rejected) if ledger else None
            if s is not None:
                rep.outcomes.append(Outcome(step.key, name, digest, method, step.hypothesis.format(file=name), s[0],
                                            s[3], flags=s[1], rejected=s[2], ledger=s[3]))
                if step.key in REPLAY_STEPS and not _restore(run, method, name, depth) and replay:
                    deferred.append((step, name, kind, data, depth, px_cache, method))
                continue
            rep.outcomes.append(_run_step(run, step, name, kind, data, depth, px_cache))
    if ledger:
        rep.outcomes += _ledger_descendants(cid, workdir, rep, run)
    rep.skipped += run.skipped_children
    render_outcomes, fresh_items = _render(run, swept, ocr=ocr, read=read, prefixes=prefixes, rs_ledger=rs_ledger,
                                           cid=cid, workdir=workdir, ledger=ledger, out_dir=out_dir)
    rep.outcomes += render_outcomes
    if rep.files:                   # no carrier, no step: the verdict says so instead of a decode of nothing
        s = td_settled
        if s is not None:
            decode = Outcome(TEXT_DECODE, None, None, td_method, TEXT_DECODE_HYPOTHESIS, s[0], s[3], flags=s[1],
                             rejected=s[2], ledger=s[3])
        else:
            decode = _text_decode(run, rep.outcomes, td_method)
        rep.outcomes.append(decode)
    rep.human_steps = list(run.human_steps)
    if ledger and record:
        _write_store(run.store, run.recovered, run.decoded_new)
        record_outcomes(cid, rep.outcomes, workdir=workdir, profile=profile, agent=agent)
        if fresh_items:
            rs.file_checklist(cid, fresh_items, workdir=workdir, profile=profile, agent=agent)
    return rep


# ---- the engine contract -----------------------------------------------------------------------------

def default_out(challenge_dir: Path) -> Path:
    return Path(challenge_dir) / "recon" / OUT_NAME


def _rejected_opt(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def save(rep: Report, out_dir: Path) -> list:
    """verdict.json (the whole report) and verdict.txt (verdict_text) under out_dir; their paths."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pj, pt = out_dir / "verdict.json", out_dir / "verdict.txt"
    pj.write_text(json.dumps(rep.to_dict(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    pt.write_text(verdict_text(rep) + "\n", encoding="utf-8")
    return [pj, pt]


def result_of(rep: Report, *, challenge_id=None, seconds: float = 0.0, written=()):
    """The SolverResult of a Report: one flag read from bytes as they stand is `solved`; any other flag
    is `candidate`; open items or steps not run are `unsure` (`blocked` when no step ran at all);
    nothing further over a complete catalog is `none`. The verdict's head line leads the notes."""
    from ctf.result import Cost, Evidence, SolverResult
    v = rep.verdict()
    evidence = []
    for o in rep.outcomes:
        for f in o.flags:
            evidence.append(Evidence("decode" if f not in o.plain else "carve", f"{o.step}: {o.evidence[:200]}",
                                     path=o.file))
    evidence += [Evidence("carve", "verdict written", path=str(p)) for p in written]
    plain = {f for o in rep.outcomes for f in o.plain if not o.step.startswith(RENDER_PREFIX)}
    if v["flags"]:
        status = "solved" if len(v["flags"]) == 1 and v["flags"][0] in plain else "candidate"
    elif v["steps_ran"] == 0:
        status = "blocked"
    elif v["verdict"] == V_OPEN or not v["complete"]:
        status = "unsure"
    else:
        status = "none"
    notes = [verdict_text(rep).splitlines()[0]]
    notes += [f"not run: {x['file'] or '(the delivery)'} {x['step']}: {x['evidence'][:160]}" for x in v["not_run"][:12]]
    notes += [f"open: {x['file']} {x['step']}: {x['evidence'][:160]}" for x in v["open"][:6]]
    if status == "blocked" and not v["not_run"]:
        notes.append("no carrier in the delivery: " + "; ".join(v["skipped"][:4]))
    return SolverResult(status=status, flags=list(v["flags"]), evidence=evidence,
                        cost=Cost(seconds=round(seconds, 3)), engine=ENGINE, challenge_id=challenge_id,
                        notes="; ".join(notes))


def run_dir(challenge_dir: Path, profile, **opts) -> Report:
    """exhaust() over a challenge folder with the engine's options (see solve)."""
    challenge_dir = Path(challenge_dir)
    try:
        seconds = float(opts.get("seconds", DEFAULT_SECONDS))
    except (TypeError, ValueError) as e:
        raise ValueError(f"seconds must be a number: {e}") from e
    sandbox = opts.get("sandbox", "on")
    if sandbox == "off":
        sandbox = NoSandbox()
    elif sandbox == "on":
        sandbox = SandboxTools()
    elif not (hasattr(sandbox, "stegseek_seed") and hasattr(sandbox, "exif")):
        raise ValueError("sandbox must be on, off or an object with stegseek_seed() and exif()")
    mode = str(opts.get("ledger", "auto")).lower()
    if mode not in ("auto", "on", "off"):
        raise ValueError("ledger must be auto, on or off")
    cid = str(opts["challenge_id"]) if opts.get("challenge_id") else rs.challenge_id_of(challenge_dir)
    if mode == "on" and cid is None:
        raise ValueError("ledger=on needs a challenge id: pass challenge_id= or run on a folder with a challenge.json")
    use_ledger = mode == "on" or (mode == "auto" and cid is not None)
    workdir = None
    if use_ledger:
        from ctf import paths
        workdir = Path(opts["workdir"]) if opts.get("workdir") else paths.workdir(profile.slug)
    record = str(opts.get("record", "1")).lower() in ("1", "true", "yes", "on")
    return exhaust(ic.challenge_files(challenge_dir), flagfmt.for_profile(profile), profile=profile,
                   deadline=time.monotonic() + seconds, rejected=_rejected_opt(opts.get("rejected")),
                   sandbox=sandbox, ocr=str(opts.get("ocr", "auto")),
                   read=opts["read"] if callable(opts.get("read")) else None,
                   prefixes=tuple(profile.flag.prefixes), cid=cid, workdir=workdir, ledger=use_ledger, record=record,
                   agent=str(opts.get("agent") or ENGINE), out_dir=Path(opts["out"]) / "renderings" if opts.get("out")
                   else default_out(challenge_dir) / "renderings")


def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. opts: seconds (budget, default 180), rejected (a flag or a list: flags the
    platform rejected), ocr (auto|on|off, the render sweep's), sandbox (on|off: stegseek --seed and
    exiftool in a container already up), ledger (auto|on|off: skip what the hypothesis ledger
    settles and record the rest; auto = when a challenge id resolves), record (1|0), challenge_id,
    workdir, agent, out (folder for verdict.json/.txt; default <challenge>/recon/stego_exhaust)."""
    from ctf.result import SolverResult
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    cid = str(opts["challenge_id"]) if opts.get("challenge_id") else rs.challenge_id_of(challenge_dir)
    try:
        rep = run_dir(challenge_dir, profile, **opts)
    except (ValueError, FileNotFoundError) as e:
        return SolverResult(status="blocked", engine=ENGINE, challenge_id=cid, notes=f"bad option or input: {e}")
    written = save(rep, Path(opts["out"]) if opts.get("out") else default_out(challenge_dir)) if rep.files else []
    return result_of(rep, challenge_id=cid, seconds=time.monotonic() - t0, written=written)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="stego_exhaust.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("challenge_dir", type=Path)
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--rejected", action="append", default=[], help="a flag the platform rejected (repeatable)")
    ap.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    ap.add_argument("--ocr", choices=("auto", "on", "off"), default="auto")
    ap.add_argument("--no-sandbox", action="store_true", help="stegseek --seed and exiftool: NOT RUN")
    ap.add_argument("--cid", help="challenge id (default: the id in challenge.json)")
    ap.add_argument("--no-ledger", action="store_true", help="neither read nor write the hypothesis ledger")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    from ctf import event
    profile = event.load(a.event) if a.event else event.current()
    opts = {"seconds": a.seconds, "rejected": a.rejected, "ocr": a.ocr, "sandbox": "off" if a.no_sandbox else "on",
            "ledger": "off" if a.no_ledger else "auto"}
    if a.cid:
        opts["challenge_id"] = a.cid
    try:
        rep = run_dir(a.challenge_dir, profile, **opts)
    except (ValueError, FileNotFoundError) as e:
        print(f"stego_exhaust.py: {e}", file=sys.stderr)
        return 2
    print(json.dumps(rep.verdict(), indent=1) if a.json else verdict_text(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
