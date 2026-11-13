#!/usr/bin/env python3
"""Offline self-test of solvers/metadata-forensics/properties_strict.py.

  .venv/bin/python solvers/metadata-forensics/selftest.py [-v]

No network and no token. Saved attempts are read from labels.challenges_root() and never written;
everything this test writes (the scratch label ledgers, a copy of the solver with a
day_patch.py stub) goes under one tempfile.mkdtemp() folder that is removed at the end.

What is checked:
  1. every Metadata attempt saved on Days 1 to 8 replays to its saved answers (key.json, else
     golden.json), all plain, and no file under those attempts changes. The replay runs with
     day_patch.py switched off: since rows 102 and 103 the shipped solver answers Days 7 and 8
     alone. A later day is added to FROZEN_DAYS once its live fix is in the shipped solver;
  2. the 89-property probe (synthetic PNG, GIF, BMP, WebP, TIFF, JPEG with EXIF, zip, PDF,
     docx and text files, asked in the Day 4 wording through run.split_sets): no wrong plain
     answer, the expected value is the plain answer or the first option of an unsure one for
     at least 83, the 5 whose format is unknown are unsure, the unregistered one is None;
     and again with those formats accepted in a scratch ledger: at least 83 plain;
  3. look-alike ids resolve to their own property or to None, never to another one;
  4. a true/false property never answers WIDTHxHEIGHT; enum and integer formats are kept;
  5. an unregistered property prints UNKNOWN PROPERTY and at most 40 lines of facts;
  6. target selection, archives included;
  7. covers() on the Day 4 timed contract and on a synthetic exif.unknown_tag;
  8. after labels.learn accepts 'raw' for exif.datetime_original, that property is plain;
  9. the day_patch.py hook: asked about a None or an unsure answer, never about a plain one;
     when it declines, the registry's answer stays;
 10. truncated and damaged files never make an extractor raise or a plain answer lose its shape;
 11. no guess about the file: a wrapper archive is not the target of a picture question, a
     question that names the delivery is about the delivery, two members that both fit give
     no answer;
 12. no look-alike through an id of the Day 1 form: 'camera-thumbnail-md5' is not md5;
 13. a fact the bytes leave ambiguous (a top-down BMP, a 0 by 0 JFIF thumbnail, an EXIF
     thumbnail whose IFD1 states another size) is never answered plain;
 14. covers() never raises and reports a property whose class cannot fit the answer format;
     a day_patch value that cannot be an answer costs one answer, not the set; a question
     text of 40000 spaces is read in well under a second;
 15. the literal `none` is never plain before the judge has accepted it for the property:
     not for a file of another type, not for a member the extractor cannot read; it is plain
     once 'absent' is accepted for the property and None once it is rejected;
 16. day_patch_template.py: as shipped it answers nothing; with ALIAS and NEW lines it
     answers like the registry would (plain for a synonym of a plain name, unsure like an
     unsure target, unsure and not vouched for until one probe is accepted); the shipped
     solver never loads it;
 17. more spellings of registered facts: a pure synonym of a judged structure is plain, a
     doubtful name and every other spelling is unsure under its own key; PNG chunks end at
     IEND, and three png.text_* names are not read as tEXt keywords;
 18. structural facts (counts, bytes after the end marker) and the fields of gzip, WAV, ID3,
     ELF and PE files are read from the bytes and are all unsure; a name with two readings
     in the file, a structure that does not parse, or a field kept in a form that is not
     read (an ID3v1 tag, an RF64 file) is no answer, never `none`; a gzip trailer is read
     where the member ends, and stays right once its format is accepted;
 19. an unregistered name with the words of exactly one reader (zip.eocd_total_entry_count) is
     unsure under its own name, its tie with agreeing readers in the option's name; an
     accepted tie name is plain only where those readers still agree; two readers, or a word
     no reader has, give None; a day_patch.py still overrides it;
 20. the reader pack (tar, SQLite, pcap and pcapng, lnk, OLE, EVTX, regf, 7z, RAR, bzip2, xz, MP4,
     ICO, Mach-O, FLAC, class, DEX, prefetch, the rest of gzip's header and of the zip end
     record): each header field is read from a synthetic file and is unsure (bar the two the
     tracked seed judges since Days 24 and 26, evtx.record_count and prefetch.executable_name:
     plain and covered under the seed, unsure again with those two seed entries taken out); a
     file of another type gives the unsure `none`; a field the bytes leave open offers each
     reading, a cut or packed one is no answer; no two readers of those namespaces share their
     words;
 21. an enum whose accepted values name a code's meaning (PNG colour type, PE and ELF machine,
     ELF class and data, TIFF byte order, gzip OS, PE32/PE32+) offers the one value the spec
     table maps the code to, unsure under 'enum_meaning'; none or two is no answer; plain and
     covered once that name is accepted;
 22. a member nested in tar, gzip, bzip2 or xz (two layers at most) is read only under the exact
     name the question gives; an unnamed container is not the file of a picture or text
     question; gzip.*, tar.* and identity questions on a lone container are answered as before;
 23. rows 102 and 103 (Day 8): the shipped day_patch.py is the template; an id of the Day 1 form
     whose question names no file is about the one delivered file with the id's stem (none or two
     is no answer); zip.central_directory_member_names is registered and plain as compact JSON; a
     json-kind question offers json_compact first; the central directory reader fails closed;
 24. row 112: the zip names and provenance readers (local header names, a renamed local header, a
     member the central directory does not list, duplicate base names, DOS and 0x5455 times,
     members newer than the entry that holds their archive, unsafe paths) on the Day 8 shape and
     on synthetic archives, all unsure, each new name resolving to its own extractor.
The reader packs (readers_more.py, readers_docs.py; readers_formats.py: tests/test_metadata_formats.py) and the nearest-reader resolver have their own
test, tests/test_metadata_readers.py.

Prints one line per check and `SELFTEST ok` or `SELFTEST FAILED <n>`; exits 1 on a failure.
"""
import bz2
import contextlib
import functools
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
import random
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TMP = Path(tempfile.mkdtemp(prefix="mdf_selftest_"))
VERBOSE = "-v" in sys.argv[1:]

sys.dont_write_bytecode = True                         # no __pycache__ in the repo
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "solvers" / "common"))
import run  # noqa: E402
import labels  # noqa: E402

# Where the saved attempts are (read only): labels.challenges_root(), i.e. $CTF_WORKDIR, else the
# main checkout's challenges/. The folder is untracked, so a fresh clone has none: every check that
# replays a saved attempt is then reported as SKIP (not run, never a pass).
ATTEMPTS = labels.challenges_root()
# The days whose saved attempts are replayed: the ones the shipped solver answers alone (Days 7
# and 8 since rows 102 and 103 moved their live fixes into it, Day 9 since row 179). A later day's attempts are left to
# tools/preflight.py (--replay, --regress): checks 1 to 8 run with day_patch.py switched off, so a
# base that is CORRECT on a property only today's patch answers would fail here on the day,
# whatever the live fix does. Add a day here once its fix is in the shipped solver.
FROZEN_DAYS = "day-0[1-9]"
# From here on the label ledger is a scratch folder: the seed alone decides what is plain,
# and nothing this test learns can reach the real ledger.
os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
os.environ.pop("CTF_LEDGER_MASK", None)
os.environ.pop("CTF_JUDGE_LEDGER", None)   # these checks are about the judged (seed + ledger) behaviour

solver = run.load_solver(str(HERE / "properties_strict.py"))
old = solver.base  # file_properties.py, the solver the wrapper replaces
if (HERE / "day_patch.py").exists():
    print("note: day_patch.py is present beside the solver; checks 1 to 8 run with it switched off")
solver._day_patch = lambda: None  # the registry is what is under test; check 9 tests the hook on a copy

DAY4_FORMAT = {"kind": "exact_text", "syntax": "exact artifact-derived value only, without quotes or explanatory "
               "text unless quotes are part of the value; use the literal none only when the requested field is absent"}
TRUE_FALSE = {"kind": "enum", "accepted_values": ["true", "false"]}
_failed = []


def check(name: str, ok: bool, detail: str = ""):
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail else ""))
    if not ok:
        _failed.append(name)


_skipped = []


def skip(name: str, why: str):
    """A check that could not run here (its saved attempt is not on disk): reported, never counted as passed."""
    print(f"SKIP {name}: {why}")
    _skipped.append(name)


def no_attempts() -> bool:
    """True when no saved attempt is on disk: the folder is absent (a fresh clone: challenges/ is untracked)
    or holds no day-* folder (only a scratch _ledger). Any day-* folder makes every replay check strict."""
    return not (ATTEMPTS.is_dir() and any(ATTEMPTS.glob("day-*")))


# ------------------------------------------------------------------ fixtures, built by hand (no Pillow)

def png(w=320, h=200, bd=8, ct=2, extra=True):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, bd, ct, 0, 0, 0))
    if extra:
        out += chunk(b"pHYs", struct.pack(">IIB", 2835, 2835, 1))
        out += chunk(b"tEXt", b"Software\x00HuntressCam 1.2")
        out += chunk(b"tIME", struct.pack(">HBBBBB", 2026, 10, 5, 9, 0, 0))
    out += chunk(b"IDAT", zlib.compress(b"\x00" * (h * (1 + 3 * w))))
    return out + chunk(b"IEND", b"")


def gif(w=123, h=45):
    return (b"GIF89a" + struct.pack("<HH", w, h) + b"\x80\x00\x00" + b"\x00\x00\x00\xff\xff\xff"
            + b"\x2c\x00\x00\x00\x00" + struct.pack("<HH", w, h) + b"\x00\x02\x02\x4c\x01\x00\x3b")


def bmp(w=64, h=-48, bpp=24):
    row = (w * 3 + 3) & ~3
    data = b"\x00" * (row * abs(h))
    hdr = struct.pack("<IiiHHIIiiII", 40, w, h, 1, bpp, 0, len(data), 2835, 2835, 0, 0)
    return b"BM" + struct.pack("<IHHI", 14 + 40 + len(data), 0, 0, 54) + hdr + data


def webp_vp8x(w=400, h=300):
    body = (b"VP8X" + struct.pack("<I", 10) + b"\x00\x00\x00\x00"
            + (w - 1).to_bytes(3, "little") + (h - 1).to_bytes(3, "little"))
    return b"RIFF" + struct.pack("<I", 4 + len(body)) + b"WEBP" + body


def tiff_block(entries_ifd0, exif=None, gps=None, ifd1=None, thumb=b"", endian="<"):
    """A TIFF structure from lists of (tag, type, count, value bytes or int). Returns (bytes, rational packer)."""
    e = endian
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}

    def pack_ifd(entries, at, next_off=0):
        n = len(entries)
        table_len = 2 + 12 * n + 4
        blob, table = b"", struct.pack(e + "H", n)
        for tag, typ, cnt, val in sorted(entries):
            if isinstance(val, int):
                raw = struct.pack(e + {1: "B", 3: "H", 4: "I"}[typ], val).ljust(4, b"\x00")
            elif sizes[typ] * cnt <= 4:
                raw = val.ljust(4, b"\x00")
            else:
                raw = struct.pack(e + "I", at + table_len + len(blob))
                blob += val + (b"\x00" if len(val) % 2 else b"")
            table += struct.pack(e + "HHI", tag, typ, cnt) + raw
        return table + struct.pack(e + "I", next_off) + blob

    def rat(*pairs):
        return b"".join(struct.pack(e + "II", a, b) for a, b in pairs)

    hdr = (b"II*\x00" if e == "<" else b"MM\x00*") + struct.pack(e + "I", 8)
    off_exif = off_gps = off_ifd1 = off_thumb = 0
    for _ in range(2):  # two passes: the sizes do not depend on the pointer values
        ifd0 = list(entries_ifd0)
        if exif:
            ifd0.append((0x8769, 4, 1, off_exif))
        if gps:
            ifd0.append((0x8825, 4, 1, off_gps))
        b0 = pack_ifd(ifd0, 8, off_ifd1)
        off_exif = 8 + len(b0)
        be = pack_ifd(exif, off_exif) if exif else b""
        off_gps = off_exif + len(be)
        bg = pack_ifd(gps, off_gps) if gps else b""
        off_ifd1 = off_gps + len(bg) if ifd1 is not None else 0
        b1 = b""
        if ifd1 is not None:
            b1 = pack_ifd(list(ifd1) + [(0x0201, 4, 1, off_thumb), (0x0202, 4, 1, len(thumb))], off_ifd1)
            off_thumb = off_ifd1 + len(b1)
    return hdr + b0 + be + bg + b1 + thumb, rat


def jpeg(w=257, h=146, sof=0xC0, jfif=False, exif=None, com=None):
    def seg(m, d):
        return b"\xff" + bytes([m]) + struct.pack(">H", len(d) + 2) + d
    out = b"\xff\xd8"
    if jfif:
        out += seg(0xE0, b"JFIF\x00" + struct.pack(">HBHHBB", 0x0102, 1, 72, 72, 0, 0))
    if exif is not None:
        out += seg(0xE1, b"Exif\x00\x00" + exif)
    if com:
        out += seg(0xFE, com)
    out += seg(0xDB, b"\x00" + bytes(range(1, 65)))
    out += seg(sof, struct.pack(">BHHB", 8, h, w, 3) + b"\x01\x22\x00\x02\x11\x00\x03\x11\x00")
    out += seg(0xC4, b"\x00" + bytes(16))
    return out + seg(0xDA, b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00") + b"\x12\x34\xff\x00\x56" + b"\xff\xd9"


def exif_jpeg():
    """257x146 JPEG with JFIF, a comment, and EXIF: 4000x3000 stated, a 160x120 thumbnail, GPS, two dates."""
    thumb = jpeg(160, 120)
    _, rat = tiff_block([])
    ifd0 = [(0x010F, 2, 9, b"Huntress\x00"), (0x0110, 2, 8, b"CamX-12\x00"), (0x0112, 3, 1, 6),
            (0x0131, 2, 12, b"Shuffler 2.0"[:11] + b"\x00"), (0x0132, 2, 20, b"2026:10:05 09:00:00\x00")]
    ex = [(0x9003, 2, 20, b"2026:09:30 18:45:12\x00"), (0xA002, 4, 1, 4000), (0xA003, 4, 1, 3000)]
    gps = [(0x0001, 2, 2, b"N\x00"), (0x0002, 5, 3, rat((39, 1), (17, 1), (2550, 100))),
           (0x0003, 2, 2, b"W\x00"), (0x0004, 5, 3, rat((76, 1), (36, 1), (4470, 100)))]
    block, _ = tiff_block(ifd0, ex, gps, ifd1=[(0x0103, 3, 1, 6)], thumb=thumb)
    return jpeg(257, 146, jfif=True, exif=block, com=b"resized by shuffler"), thumb


def tiff(w=640, h=480):
    return tiff_block([(0x0100, 4, 1, w), (0x0101, 4, 1, h), (0x0112, 3, 1, 6)])[0]


def zip_with_comment():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        zi = zipfile.ZipInfo("inner/report.txt", (2026, 10, 5, 8, 59, 58))
        zi.comment = b"entry note"
        z.writestr(zi, "hello\n")
        z.writestr(zipfile.ZipInfo("second.bin", (2025, 1, 2, 3, 4, 6)), b"\x00\x01")
        z.comment = b"case 4471 export"
    return buf.getvalue()


def pdf():
    return (b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
            b"4 0 obj\n<< /Title (Quarterly Report) /Author (J. Hammond) /Producer (HuntressPDF 3.1) "
            b"/CreationDate (D:20261005090000Z) >>\nendobj\n"
            b"trailer\n<< /Root 1 0 R /Info 4 0 R /Size 5 >>\n%%EOF\n")


def docx():
    core = (b'<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties '
            b'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            b'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Incident Summary</dc:title>'
            b'<dc:creator>alice.w</dc:creator><cp:lastModifiedBy>mallory.k</cp:lastModifiedBy>'
            b'<cp:revision>7</cp:revision>'
            b'<dcterms:created xsi:type="dcterms:W3CDTF">2026-10-01T12:00:00Z</dcterms:created>'
            b'<dcterms:modified xsi:type="dcterms:W3CDTF">2026-10-04T23:59:00Z</dcterms:modified>'
            b'</cp:coreProperties>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", b'<?xml version="1.0"?><Types/>')
        z.writestr("docProps/core.xml", core)
        z.writestr("word/document.xml", b"<w:document/>")
    return buf.getvalue()


J, THUMB = exif_jpeg()
PNG, GIF, BMP, WEBP, TIFF, ZIP, PDF, DOCX = png(), gif(), bmp(), webp_vp8x(), tiff(), zip_with_comment(), pdf(), docx()
PROGRESSIVE = jpeg(300, 100, sof=0xC2)
UTF16 = "﻿hi".encode("utf-16-le")
UTF8_BOM = b"\xef\xbb\xbfhi"


# ------------------------------------------------------------------ asking a question the way the runner does

def solve(attempt: dict, blobs: list, module=None):
    """{answer id: answer or None} through run.split_sets and the solver's solve_set, plus what it printed."""
    module = module or solver
    out, err = {}, io.StringIO()
    with contextlib.redirect_stderr(err):
        for _, qs, files, ctx in run.split_sets(attempt, blobs):
            got = module.solve_set(qs, files, ctx) or {}
            for q in qs:
                v = got.get(q["qid"])
                out[q["answer_id"]] = v if v is None or isinstance(v, str) else json.dumps(v, separators=(",", ":"))
    return out, err.getvalue()


def question(prop, fname, typ, item="001", day="05", legacy=False, fmt=None, text=None, qid=None):
    dash = prop.replace(".", "-").replace("_", "-")
    qid = qid or (f"{fname.rsplit('.', 1)[0]}-{dash}" if legacy else f"d{day}-{typ}-{item}-{dash}")
    zname = f"metadata-day-{day}-evidence.zip"
    return {"id": qid, "question": f"Determine {prop} for {fname}." if text is None else text,
            "artifact": f"{zname} -> {fname}", "answer_format": fmt or DAY4_FORMAT, "normalization": "trim"}


def ask(prop, fname, data, typ, members=None, module=None, **kw):
    """One question about one file in one evidence zip: (answer, stderr text, the question)."""
    q = question(prop, fname, typ, **kw)
    zname = q["artifact"].split(" -> ")[0]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in (members if members is not None else {fname: data}).items():
            z.writestr(n, d)
    attempt = {"mode": "single_solve", "questions": [q], "answer_ids": [q["id"]], "artifacts": [{"filename": zname}]}
    answers, err = solve(attempt, [buf.getvalue()], module)
    return answers.get(q["id"]), err, q


def values_of(answer) -> list:
    """Every value an answer could put on the wire: the plain value, or each option of an unsure one."""
    if answer is None:
        return []
    parsed = labels.parse(answer)
    return [answer] if parsed is None else [v for _, v in parsed.options]


def is_plain(answer) -> bool:
    return answer is not None and labels.parse(answer) is None


@contextlib.contextmanager
def seed_without(*keys):
    """The metadata lane's tracked seed with `keys` taken out of it, for the block: a copy goes to the scratch folder and
    labels.seed_path points at it. The runtime ledger stays this test's empty scratch one (CTF_WORKDIR above)."""
    data = json.loads((HERE / "conventions.json").read_text())
    for k in keys:
        assert k in data, f"{k} is not in the tracked seed"
        del data[k]
    path = TMP / "seed-without.json"
    path.write_text(json.dumps(data))
    old = labels.seed_path
    labels.seed_path = lambda lane: path if lane == "metadata" else old(lane)
    labels._cache.clear()
    try:
        yield
    finally:
        labels.seed_path = old
        labels._cache.clear()


# ------------------------------------------------------------------ 1. the saved attempts

def snapshot():
    """(path, size, mtime) of everything this test reads from the attempts folder: the Metadata
    attempts of the frozen days and the lane's own label ledger. Today's folders and the other
    lanes' ledgers are written by the day's play while this runs, and are never opened here."""
    out = set()
    files = [p for folder in ATTEMPTS.glob(f"{FROZEN_DAYS}/metadata-forensics-*") for p in folder.rglob("*")]
    for p in files + [ATTEMPTS / "_ledger" / "metadata.jsonl"]:
        if p.is_file():
            st = p.stat()
            out.add((str(p), st.st_size, st.st_mtime_ns))
    return out


def test_saved_attempts():
    """Every frozen attempt (key.json: judged; golden.json: the solver's snapshot) must replay
    identical and plain. The real label ledger is read through a copy, so a format accepted on
    a later day counts here exactly as it does in the lane's regression, and cannot be written."""
    if no_attempts():
        skip("saved attempts replay identical to the saved answers, plain, and covered",
             f"no saved attempts under {ATTEMPTS}")
        return
    scratch = TMP / "replay"
    (scratch / "_ledger").mkdir(parents=True)
    if (ATTEMPTS / "_ledger" / "metadata.jsonl").is_file():
        shutil.copy(ATTEMPTS / "_ledger" / "metadata.jsonl", scratch / "_ledger" / "metadata.jsonl")
    dirs = sorted(a.parent for a in ATTEMPTS.glob(f"{FROZEN_DAYS}/metadata-forensics-*/**/attempt.json"))
    bad, questions, unfrozen, by_ref = [], 0, 0, {"key.json": 0, "golden.json": 0}
    os.environ["CTF_WORKDIR"] = str(scratch)
    try:
        for d in dirs:
            ref_name = next((n for n in by_ref if (d / n).exists()), None)
            if ref_name is None:
                unfrozen += 1  # an attempt still in play has no frozen answers to replay against
                continue
            ref = json.loads((d / ref_name).read_text())["answers"]
            attempt, blobs, _ = run.load_offline("-", str(d))
            answers, _ = solve(attempt, blobs)
            by_ref[ref_name] += 1
            questions += len(ref)
            rel = d.relative_to(ATTEMPTS)
            if answers != ref:
                diff = sorted(k for k in set(ref) | set(answers) if answers.get(k) != ref.get(k))
                bad.append(f"{rel}: differs on {diff[:3]}")
            elif not all(is_plain(v) for v in answers.values()):
                bad.append(f"{rel}: an answer is not plain")
            elif solver.covers(attempt["questions"]):
                bad.append(f"{rel}: covers() reports {solver.covers(attempt['questions'])[0]}")
            elif VERBOSE:
                print(f"     {rel}: {len(ref)} answers identical and plain")
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    replayed = sum(by_ref.values())
    check("saved attempts replay identical to the saved answers, plain, and covered",
          not bad and replayed >= 10,
          f"{replayed} attempts, {questions} answers ({by_ref['key.json']} against key.json, "
          f"{by_ref['golden.json']} against golden.json) under {ATTEMPTS}"
          + (f"; {unfrozen} without frozen answers skipped" if unfrozen else "")
          + ("" if replayed >= 10 else "; expected at least the 10 saved attempts of Days 1 to 4")
          + ("".join("\n       " + b for b in bad)))


# ------------------------------------------------------------------ 2. the 89-property probe

SHA = hashlib.sha256(J).hexdigest()
PROBE = [  # (property, file name, bytes, type token of the id, expected answer; None = its format is unknown)
    ("png.ihdr_dimensions_pixels", "scan-001.png", PNG, "png", "320x200"),
    ("png.ihdr_width_pixels", "scan-001.png", PNG, "png", "320"),
    ("png.ihdr_height_pixels", "scan-001.png", PNG, "png", "200"),
    ("png.ihdr_bit_depth", "scan-001.png", PNG, "png", "8"),
    ("png.ihdr_color_type", "scan-001.png", PNG, "png", "2"),
    ("png.chunk_count", "scan-001.png", PNG, "png", "6"),
    ("png.chunk_types", "scan-001.png", PNG, "png", "IHDR,pHYs,tEXt,tIME,IDAT,IEND"),
    ("png.text_software", "scan-001.png", PNG, "png", "HuntressCam 1.2"),
    ("png.phys_pixels_per_unit", "scan-001.png", PNG, "png", "2835x2835"),
    ("png.time_last_modified", "scan-001.png", PNG, "png", "2026-10-05T09:00:00Z"),
    ("gif.logical_screen_dimensions_pixels", "anim-001.gif", GIF, "gif", "123x45"),
    ("gif.version", "anim-001.gif", GIF, "gif", "89a"),
    ("bmp.dib_dimensions_pixels", "shot-001.bmp", BMP, "bmp", "64x48"),
    ("bmp.bits_per_pixel", "shot-001.bmp", BMP, "bmp", "24"),
    ("webp.canvas_dimensions_pixels", "web-001.webp", WEBP, "webp", "400x300"),
    ("webp.vp8x_dimensions_pixels", "web-001.webp", WEBP, "webp", "400x300"),
    ("tiff.ifd0_dimensions_pixels", "scan-001.tif", TIFF, "tiff", "640x480"),
    ("tiff.byte_order", "scan-001.tif", TIFF, "tiff", "II"),
    ("image.dimensions_pixels", "scan-001.png", PNG, "image", "320x200"),
    ("image.format", "scan-001.png", PNG, "image", "png"),
    ("image.detected_format", "camera-005.jpg", PNG, "image", "png"),
    ("jpeg.sof_dimensions_pixels", "camera-005.jpg", PNG, "jpeg", "none"),
    ("jpeg.sof_dimensions_pixels", "camera-006.jpg", J, "jpeg", "257x146"),
    ("jpeg.sof_dimensions_pixels", "camera-007.jpg", PROGRESSIVE, "jpeg", "300x100"),
    ("jpeg.sof_marker", "camera-007.jpg", PROGRESSIVE, "jpeg", "ffc2"),
    ("jpeg.sof_component_count", "camera-006.jpg", J, "jpeg", "3"),
    ("jpeg.sof_precision_bits", "camera-006.jpg", J, "jpeg", "8"),
    ("jpeg.progressive", "camera-007.jpg", PROGRESSIVE, "jpeg", "true"),
    ("jpeg.exif_dimensions_pixels", "camera-006.jpg", J, "jpeg", "4000x3000"),
    ("jpeg.exif_pixel_dimensions", "camera-006.jpg", J, "jpeg", "4000x3000"),
    ("jpeg.exif_thumbnail_dimensions_pixels", "camera-006.jpg", J, "jpeg", "160x120"),
    ("jpeg.thumbnail_dimensions_pixels", "camera-006.jpg", J, "jpeg", "160x120"),
    ("jpeg.jfif_density", "camera-006.jpg", J, "jpeg", "72x72"),
    ("jpeg.jfif_version", "camera-006.jpg", J, "jpeg", "1.02"),
    ("jpeg.comment", "camera-006.jpg", J, "jpeg", "resized by shuffler"),
    ("jpeg.app_markers", "camera-006.jpg", J, "jpeg", None),
    ("jpeg.segment_count", "camera-006.jpg", J, "jpeg", None),
    ("jpeg.exif_present", "camera-006.jpg", J, "jpeg", "true"),
    ("jpeg.jfif_present", "camera-006.jpg", J, "jpeg", "true"),
    ("exif.orientation", "camera-006.jpg", J, "exif", "6"),
    ("jpeg.exif_orientation", "camera-006.jpg", J, "jpeg", "6"),
    ("exif.datetime_original", "camera-006.jpg", J, "exif", "2026:09:30 18:45:12"),
    ("exif.datetime", "camera-006.jpg", J, "exif", "2026:10:05 09:00:00"),
    ("exif.make", "camera-006.jpg", J, "exif", "Huntress"),
    ("exif.model", "camera-006.jpg", J, "exif", "CamX-12"),
    ("exif.software", "camera-006.jpg", J, "exif", "Shuffler 2."),
    ("exif.gps_latitude", "camera-006.jpg", J, "exif", None),
    ("exif.gps_latitude_ref", "camera-006.jpg", J, "exif", "N"),
    ("exif.pixel_x_dimension", "camera-006.jpg", J, "exif", "4000"),
    ("exif.image_width", "camera-006.jpg", J, "exif", None),
    ("image.dimensions_match_exif", "camera-006.jpg", J, "image", "false"),
    ("image.extension_matches_content", "camera-005.jpg", PNG, "image", "false"),
    ("jpeg.dimensions_match_filename", "camera-640x480.jpg", J, "jpeg", "false"),
    ("file.extension", "camera-005.jpg", PNG, "file", "jpg"),
    ("file.detected_type", "camera-005.jpg", PNG, "file", "png"),
    ("file.mime_type", "camera-005.jpg", PNG, "file", "image/png"),
    ("mime.type", "camera-005.jpg", PNG, "mime", "image/png"),
    ("file.size_bytes", "camera-006.jpg", J, "file", str(len(J))),
    ("file.sha256", "camera-006.jpg", J, "file", SHA),
    ("file.entropy_bits_per_byte", "camera-006.jpg", J, "file", None),
    ("magic.prefix_hex_8", "camera-006.jpg", J, "magic", J[:8].hex()),
    ("magic.prefix_hex_16", "camera-006.jpg", J, "magic", J[:16].hex()),
    ("zip.entry_count", "bundle-001.zip", ZIP, "zip", "2"),
    ("zip.comment", "bundle-001.zip", ZIP, "zip", "case 4471 export"),
    ("zip.comment_length_bytes", "bundle-001.zip", ZIP, "zip", "16"),
    ("zip.first_entry_name", "bundle-001.zip", ZIP, "zip", "inner/report.txt"),
    ("zip.first_entry_modified", "bundle-001.zip", ZIP, "zip", None),
    ("pdf.version", "report-001.pdf", PDF, "pdf", "1.7"),
    ("pdf.info_title", "report-001.pdf", PDF, "pdf", "Quarterly Report"),
    ("pdf.info_author", "report-001.pdf", PDF, "pdf", "J. Hammond"),
    ("pdf.info_producer", "report-001.pdf", PDF, "pdf", "HuntressPDF 3.1"),
    ("pdf.page_count", "report-001.pdf", PDF, "pdf", "1"),
    ("office.core_creator", "memo-001.docx", DOCX, "office", "alice.w"),
    ("office.core_last_modified_by", "memo-001.docx", DOCX, "office", "mallory.k"),
    ("docx.core_title", "memo-001.docx", DOCX, "docx", "Incident Summary"),
    ("ooxml.core_created", "memo-001.docx", DOCX, "ooxml", "2026-10-01T12:00:00Z"),
    ("text.line_ending", "export-001.txt", b"a\r\nb\r\n", "text", "crlf"),
    ("text.line_endings", "export-001.txt", b"a\nb\n", "text", "lf"),
    ("text.crlf_present", "export-001.txt", b"a\r\nb\r\n", "text", "true"),
    ("text.line_count", "export-001.txt", b"a\r\nb\r\n", "text", "2"),
    ("text.trailing_newline_present", "export-001.txt", b"a\nb", "text", "false"),
    ("text.encoding", "export-001.txt", UTF16, "text", "utf-16le"),
    ("text.bom_encoding", "export-001.txt", UTF16, "text", "utf-16le"),
    ("text.utf16le_bom_present", "export-001.txt", UTF16, "text", "true"),
    ("text.utf16_bom_present", "export-001.txt", UTF16, "text", "true"),
    ("text.utf8_bom_present", "export-001.txt", UTF8_BOM, "text", "true"),
    ("text.bom_hex", "export-001.txt", UTF8_BOM, "text", "efbbbf"),
    ("text.bom_present", "export-001.txt", UTF8_BOM, "text", "true"),
    ("text.null_byte_count", "export-001.txt", b"a\x00b", "text", "1"),
]
UNREGISTERED = {"jpeg.segment_count"}  # the one probe property the registry does not hold


def run_probe():
    """Each probe case as (verdict, property, answer, expected). Verdicts:
       plain_ok, plain_wrong, unsure_first (expected value is the first option), unsure_later,
       unsure_miss (expected value not offered), unsure_format (expected is None), none."""
    rows = []
    for prop, fname, data, typ, want in PROBE:
        got, _, _ = ask(prop, fname, data, typ)
        vals = values_of(got)
        if got is None:
            verdict = "none"
        elif is_plain(got):
            verdict = "plain_ok" if got == want else "plain_wrong"
        elif want is None:
            verdict = "unsure_format"
        else:
            verdict = "unsure_first" if vals[:1] == [want] else "unsure_later" if want in vals else "unsure_miss"
        rows.append((verdict, prop, got, want))
    return rows


def test_probe():
    rows = run_probe()
    count = lambda *vs: sum(1 for r in rows if r[0] in vs)
    known = [r for r in rows if r[3] is not None]
    unknown_format = [r for r in rows if r[3] is None and r[1] not in UNREGISTERED]
    if VERBOSE:
        for verdict, prop, got, want in rows:
            print(f"     {verdict:13} {prop:40} {got!r}")
    wrong = [f"{r[1]}: {r[2]!r}, expected {r[3]!r}" for r in rows if r[0] == "plain_wrong"]
    check("probe: no wrong plain answer", len(rows) == 89 and not wrong, f"{len(rows)} questions" + "".join("\n       " + w for w in wrong))
    right = count("plain_ok", "unsure_first")
    missed = [f"{r[1]}: {r[0]}, expected {r[3]!r}" for r in known if r[0] not in ("plain_ok", "unsure_first")]
    check("probe: the expected value is the plain answer or the first option of an unsure one for at least 83",
          right >= 83, f"{right} of {len(known)} ({count('plain_ok')} plain, {count('unsure_first')} unsure)"
          + "".join("\n       " + m for m in missed))
    check("probe: the 5 answers whose format is unknown are unsure",
          len(unknown_format) == 5 and all(r[0] == "unsure_format" for r in unknown_format),
          ", ".join(f"{r[1]} {r[0]}" for r in unknown_format))
    check("probe: the unregistered property is None",
          all(r[0] == "none" for r in rows if r[1] in UNREGISTERED), ", ".join(sorted(UNREGISTERED)))

    # The same probe once the base has had each new format accepted (one probe per key by tools/verify.py).
    os.environ["CTF_WORKDIR"] = str(TMP / "formats-accepted")
    try:
        for verdict, prop, got, want in rows:
            if verdict == "unsure_first":
                key, options = labels.parse(got)
                labels.learn(key, options[0][0], "accepted", attempt_id="selftest", answer_ids=[prop])
        after = run_probe()
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    plain_after = sum(1 for r in after if r[0] == "plain_ok")
    wrong_after = [r[1] for r in after if r[0] == "plain_wrong"]
    still_unsure = [r for r in after if r[3] is None and r[1] not in UNREGISTERED and r[0] == "unsure_format"]
    check("probe, with each first option accepted in a scratch ledger: at least 83 plain, none wrong, the 5 still unsure",
          plain_after >= 83 and not wrong_after and len(still_unsure) == 5,
          f"{plain_after} plain, {len(wrong_after)} wrong, {len(still_unsure)} unsure")
    print(f"note the plan's count 'at least 83 plain' holds once the formats are accepted ({plain_after} plain). "
          f"From the seed alone {count('plain_ok')} are plain and {count('unsure_first')} are unsure with the expected "
          f"value first: the registry rule returns every format the judge has not confirmed through labels.pick.")


# ------------------------------------------------------------------ 3. look-alikes

LOOKALIKES = [  # (property asked, type token, the file it is asked about)
    ("zip.entry_name", "zip", ("bundle-001.zip", ZIP)), ("zip.first_entry_name", "zip", ("bundle-001.zip", ZIP)),
    ("zip.comment_length_bytes", "zip", ("bundle-001.zip", ZIP)), ("pdf.info_file_size", "pdf", ("report-001.pdf", PDF)),
    ("office.core_file_name", "office", ("memo-001.docx", DOCX)),
    ("exif.thumbnail_size_bytes", "exif", ("camera-001.jpg", J)), ("png.text_filename", "png", ("scan-001.png", PNG)),
    ("zip.entry_sha256", "zip", ("bundle-001.zip", ZIP)), ("jpeg.exif_thumbnail_sha256", "jpeg", ("camera-001.jpg", J)),
    ("jpeg.thumbnail_md5", "jpeg", ("camera-001.jpg", J)), ("text.line_ending", "text", ("export-001.txt", b"a\r\nb\r\n")),
    ("jpeg.exif_thumbnail_dimensions_pixels", "jpeg", ("camera-001.jpg", J)),
    ("image.dimensions_match_exif", "image", ("camera-001.jpg", J)),
    ("zip.entry_uncompressed_size_bytes", "zip", ("bundle-001.zip", ZIP)),
    ("exif.image_description_length_bytes", "exif", ("camera-001.jpg", J)),
    ("png.ihdr_dimensions_pixels", "png", ("scan-001.png", PNG)),
]


def identity_values(fname, data) -> set:
    """What a look-alike would answer: the file's own name, size, digests, magic and picture size."""
    out = {fname, str(len(data)), data[:16].hex(), data[:8].hex()}
    out |= {hashlib.new(a, data).hexdigest() for a in ("md5", "sha1", "sha256")}
    d = old.dims("auto", data)
    if d:
        out.add(f"{d[0]}x{d[1]}")
    return out


def test_lookalikes():
    bad, substituted = [], []
    for prop, typ, (fname, data) in LOOKALIKES:
        q = question(prop, fname, typ)
        q.update(qid=q["id"], answer_id=q["id"])
        key = solver.resolve(q)[0]
        found = solver.lookup(key)
        own = solver.canon(prop)
        if key != own or (found is not None and solver.canon(found.name) != own):
            bad.append(f"{prop} resolved to {found.name if found else key}")
        got, _, _ = ask(prop, fname, data, typ)
        if found is None and got is not None:
            bad.append(f"{prop} is not registered but was answered {got!r}")
        # Only png.ihdr_dimensions_pixels may answer the picture's own size; nothing else may borrow an identity value.
        allowed = {"320x200"} if prop == "png.ihdr_dimensions_pixels" else set()
        leak = (set(values_of(got)) & identity_values(fname, data)) - allowed
        if leak:
            bad.append(f"{prop} answered an identity value of the file: {sorted(leak)}")
        was = old.question_property(q)[0]
        if was and solver.canon(was) != own:
            substituted.append(prop)
    check("the 16 look-alike ids resolve to their own property or to None, never to another one",
          len(LOOKALIKES) == 16 and not bad, "; ".join(bad) or
          f"file_properties.py substitutes another property for {len(substituted)} of them")

    thumb, _, _ = ask("jpeg.exif_thumbnail_sha256", "camera-001.jpg", J, "jpeg")
    check("an EXIF thumbnail hash is the thumbnail's digest, unsure, and never the file's",
          not is_plain(thumb) and values_of(thumb)[:1] == [hashlib.sha256(THUMB).hexdigest()]
          and SHA not in values_of(thumb), f"first option {values_of(thumb)[:1]}")

    # The Day 1 wording: no property in the text, so only the id says what is asked.
    legacy = []
    for qid, fname, data, want in [
            ("bundle-zip-entry-sha256", "bundle.zip", ZIP, None),
            ("camera-exif-thumbnail-md5", "camera.jpg", J, hashlib.md5(THUMB).hexdigest()),
            ("camera-sha256", "camera.jpg", J, SHA),
            ("report-pdf-attachment-size-bytes", "report.pdf", PDF, None),
            ("report-pdf-info-size-bytes", "report.pdf", PDF, "none")]:  # the Info entry /SizeBytes: absent
        got, _, _ = ask("-", fname, data, "-", qid=qid, text="What is the value?")
        if values_of(got)[:1] != ([want] if want else []) or (is_plain(got) and want != SHA):
            legacy.append(f"{qid}: {got!r}")
    check("an id suffix is read after the file's stem: zip-entry-sha256 is not sha256", not legacy, "; ".join(legacy))
    # A label that only names the file's type is part of the file's name in the id (Day 2 time trial variant,
    # harvested 2026-10-06): readme-executable-magic-prefix-hex-16 about readme.exe asks magic.prefix_hex_16
    exe = b"This is a UTF-8 text file named like a program.\n"
    got, _, _ = ask("-", "readme.exe", exe, "-", qid="readme-executable-magic-prefix-hex-16",
                    text="What are the first sixteen bytes as lowercase hexadecimal?")
    check("a type word between the stem and the property ('readme-executable' for readme.exe) is the file's label",
          values_of(got)[:1] == [exe[:16].hex()], repr(got))


# ------------------------------------------------------------------ 4. answer formats

def test_formats():
    bad = []
    for prop, fname, data, typ in [("image.dimensions_match_exif", "camera-001.jpg", J, "image"),
                                   ("jpeg.dimensions_match_filename", "camera-640x480.jpg", J, "jpeg"),
                                   ("jpeg.sof_matches_exif_dimensions", "camera-001.jpg", J, "jpeg"),
                                   ("image.extension_matches_content", "camera-001.jpg", PNG, "image"),
                                   ("jpeg.exif_present", "camera-001.jpg", J, "jpeg"),
                                   # true/false questions the registry has never heard of
                                   ("image.dimensions_consistent", "camera-001.jpg", J, "image"),
                                   ("jpeg.sof_dimensions_valid", "camera-001.jpg", J, "jpeg"),
                                   ("png.ihdr_dimensions_match_filename", "scan-001.png", PNG, "png"),
                                   ("jpeg.exif_dimensions_present", "camera-001.jpg", J, "jpeg")]:
        got, _, _ = ask(prop, fname, data, typ, fmt=TRUE_FALSE)
        if any(v not in ("true", "false") for v in values_of(got)):
            bad.append(f"{prop}: {got!r}")
        if solver.lookup(prop) is None and got is not None:
            bad.append(f"{prop} is not registered but was answered {got!r}")
    # The id asks a dimension property while the format is true/false: WxH does not fit, so no answer.
    got, _, _ = ask("jpeg.sof_dimensions_pixels", "camera-001.jpg", J, "jpeg", fmt=TRUE_FALSE)
    if got is not None:
        bad.append(f"jpeg.sof_dimensions_pixels under a true/false format: {got!r}")
    was, _, _ = ask("image.dimensions_consistent", "camera-001.jpg", J, "image", fmt=TRUE_FALSE, module=old)
    check("a true/false property never answers WIDTHxHEIGHT", not bad,
          "; ".join(bad) or f"file_properties.py answers {was!r} to image.dimensions_consistent")

    bad = []
    for label, got, want in [
            ("an enum answer outside accepted_values",
             ask("text.utf8_bom_present", "export-001.txt", UTF8_BOM, "text",
                 fmt={"kind": "enum", "accepted_values": ["yes", "no"]})[0], None),
            ("an integer answer that is not digits",
             ask("exif.make", "camera-001.jpg", J, "exif", fmt={"kind": "integer"})[0], None),
            ("a dimension answer under an integer format",
             ask("png.ihdr_dimensions_pixels", "scan-001.png", PNG, "png", fmt={"kind": "integer"})[0], None),
            ("'none' under an integer format",
             ask("png.ihdr_width_pixels", "camera-001.jpg", J, "png", fmt={"kind": "integer"})[0], None),
            ("the size under an integer format",
             ask("file.size_bytes", "camera-001.jpg", J, "file", fmt={"kind": "integer"})[0], str(len(J))),
            ("a BOM flag under its enum",
             ask("text.utf8_bom_present", "export-001.txt", UTF8_BOM, "text", fmt=TRUE_FALSE)[0], "true")]:
        if got != want:
            bad.append(f"{label}: {got!r}, expected {want!r}")
    check("enum answers are in accepted_values and integer answers are digits, else None", not bad, "; ".join(bad))

    # none: never plain from the seed; it is one unjudged form until the judge accepts it for the property.
    recognised, _, _ = ask("jpeg.sof_dimensions_pixels", "camera-005.jpg", PNG, "jpeg")
    garbage, _, _ = ask("jpeg.sof_dimensions_pixels", "camera-005.jpg", bytes(range(200, 256)) * 3, "jpeg")
    unjudged, _, _ = ask("exif.image_width", "camera-006.jpg", J, "exif")
    check("the literal none is never plain before the judge has accepted it for the property",
          all(not is_plain(a) and values_of(a) == ["none"] for a in (recognised, garbage, unjudged)),
          f"recognised {recognised!r}, unrecognised {garbage!r}, unjudged {unjudged!r}")


# ------------------------------------------------------------------ 15. `none` is a judged answer or no plain answer

def uncompressed_thumb_jpeg():
    """A JPEG whose EXIF IFD1 holds an uncompressed 16 by 12 thumbnail: ImageWidth, ImageLength
    and strips (StripOffsets, StripByteCounts), no JPEGInterchangeFormat pointer."""
    pixels = bytes(16 * 12 * 3)
    block, _ = tiff_block([(0x0112, 3, 1, 6)], ifd1=[(0x0100, 4, 1, 16), (0x0101, 4, 1, 12), (0x0103, 3, 1, 1)],
                          thumb=pixels)
    for old, new in ((0x0201, 0x0111), (0x0202, 0x0117)):   # the builder's JPEG pointers become strips
        entry = struct.pack("<HHI", old, 4, 1)
        assert block.count(entry) == 1
        block = block.replace(entry, struct.pack("<HHI", new, 4, 1))
    return jpeg(257, 146, exif=block)


def test_none_is_learned():
    """An extractor that finds nothing has not shown that the member is absent: the file may be
    another type, or the member may lie where the extractor does not look. So `none` is plain
    only after the judge has accepted it for the property (review finding 30)."""
    text = b"quarterly notes, nothing but text\n"
    app1 = J.index(b"\xff\xe1")
    fill = J[:app1] + b"\xff" + J[app1:]          # one legal fill byte before the APP1 marker
    strips = uncompressed_thumb_jpeg()
    plain = []
    for label, prop, fname, data, typ in [
            ("a PNG named .jpg", "jpeg.sof_dimensions_pixels", "camera-005.jpg", PNG, "jpeg"),
            ("a text file", "jpeg.sof_dimensions_pixels", "camera-005.jpg", text, "jpeg"),
            ("a JPEG", "png.ihdr_dimensions_pixels", "scan-001.png", J, "png"),
            ("a text file", "image.dimensions_pixels", "scan-001.png", text, "image"),
            ("EXIF behind a fill byte", "jpeg.exif_dimensions_pixels", "camera-006.jpg", fill, "jpeg"),
            ("EXIF behind a fill byte", "jpeg.exif_thumbnail_dimensions_pixels", "camera-006.jpg", fill, "jpeg"),
            ("an uncompressed EXIF thumbnail", "jpeg.exif_thumbnail_dimensions_pixels", "camera-006.jpg", strips, "jpeg"),
            ("an uncompressed EXIF thumbnail", "jpeg.thumbnail_dimensions_pixels", "camera-006.jpg", strips, "jpeg")]:
        got, _, _ = ask(prop, fname, data, typ)
        if is_plain(got):
            plain.append(f"{prop} for {label}: {got!r}")
    check("no plain answer for a file of another type or a member the extractor cannot read",
          not plain, "; ".join(plain))

    # Every judged property, asked of files that do not hold it: whatever comes back, never a plain none.
    judged = sorted({p.name for p in solver.REG.values() if p.confirmed and "." in p.name})
    foreign = [("notes-001.txt", text), ("scan-001.png", PNG), ("camera-001.jpg", jpeg(40, 30)), ("anim-001.gif", GIF)]
    leaked = []
    for prop in judged:
        for fname, data in foreign:
            got, _, _ = ask(prop, fname, data, prop.split(".")[0])
            if got == "none":
                leaked.append(f"{prop} for {fname}")
    check(f"no judged property answers a plain none from the seed ({len(judged)} properties, {len(foreign)} files each)",
          len(judged) >= 14 and not leaked,
          "; ".join(leaked[:4]) or ("" if len(judged) >= 14 else "expected at least the 14 dimension properties"))

    key = solver.lookup("jpeg.sof_dimensions_pixels").key
    aid = "d05-jpeg-005-jpeg-sof-dimensions-pixels"
    os.environ["CTF_WORKDIR"] = str(TMP / "absent-accepted")
    try:
        labels.learn(key, "absent", "accepted", attempt_id="selftest", answer_ids=[aid])
        taken, _, _ = ask("jpeg.sof_dimensions_pixels", "camera-005.jpg", PNG, "jpeg")
        still, _, _ = ask("jpeg.sof_dimensions_pixels", "camera-006.jpg", J, "jpeg")
        covered = solver.covers([question("jpeg.sof_dimensions_pixels", "camera-006.jpg", "jpeg")])
        other, _, _ = ask("png.ihdr_dimensions_pixels", "scan-001.png", J, "png")
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    check("after the judge accepts 'absent' for a property its none is plain, and only for that property",
          taken == "none" and still == "257x146" and covered == [] and not is_plain(other) and values_of(other) == ["none"],
          f"absent {taken!r}, present {still!r}, covers {covered}, another property {other!r}")
    os.environ["CTF_WORKDIR"] = str(TMP / "absent-rejected")
    try:
        labels.learn(key, "absent", "rejected", attempt_id="selftest", answer_ids=[aid])
        refused, _, _ = ask("jpeg.sof_dimensions_pixels", "camera-005.jpg", PNG, "jpeg")
        still, _, _ = ask("jpeg.sof_dimensions_pixels", "camera-006.jpg", J, "jpeg")
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    check("after the judge rejects 'absent' for a property there is no answer, and its value stays plain",
          refused is None and still == "257x146", f"absent {refused!r}, present {still!r}")
    again, _, _ = ask("jpeg.sof_dimensions_pixels", "camera-005.jpg", PNG, "jpeg")
    check("outside those ledgers none is unsure again", not is_plain(again) and values_of(again) == ["none"], repr(again))


# ------------------------------------------------------------------ 5. an unregistered property

def test_unknown():
    got, err, q = ask("exif.unknown_tag", "camera-001.jpg", J, "exif")
    lines = err.splitlines()
    head = f"UNKNOWN PROPERTY exif.unknown_tag for {q['id']}: {q['question']}"
    # Row 143: the asked namespace's own facts are printed in full, ahead of everything else; only
    # the other facts (the related namespaces, what every file has) are under the cap.
    fact_lines = [ln for ln in lines[1:] if ln.startswith("  ")]
    asked = [ln for ln in fact_lines if ln.startswith("  exif.")]
    other = [ln for ln in fact_lines if not ln.startswith("  exif.")]
    check("an unregistered property is None and prints UNKNOWN PROPERTY with the file's facts",
          got is None and lines[:1] == [head] and 1 <= len(other) <= 40 and fact_lines[:len(asked)] == asked
          and "  exif.datetime_original = 2026:09:30 18:45:12" in asked
          and fact_lines.index("  exif.datetime_original = 2026:09:30 18:45:12") < 12,
          f"{len(asked)} exif lines, {len(other)} others; the first line is {lines[:1]}")
    keep = solver.FACT_LINES
    try:
        solver.FACT_LINES = 6
        _, err, _ = ask("exif.unknown_tag", "camera-001.jpg", J, "exif")
    finally:
        solver.FACT_LINES = keep
    short = [ln for ln in err.splitlines()[1:] if ln.startswith("  ")]
    rest = [ln for ln in short if not ln.startswith("  exif.")]
    check("the facts beside the asked namespace are capped, the asked namespace's are whole (row 143)",
          len(rest) == 6 and rest[-1].startswith("  ... ") and len(other) <= keep == 40
          and [ln for ln in short if ln.startswith("  exif.")] == asked,
          f"{len(rest)} other lines under a cap of 6, ending {rest[-1:]!r}; {len(short) - len(rest)} exif lines of {len(asked)}")

    got, err, _ = ask("jpeg.sof_dimensions_pixels", "camera-001.jpg", J, "jpeg",
                      text="Determine png.ihdr_dimensions_pixels for camera-001.jpg.")
    check("a disagreement between the answer id and the text prints a NOTE; the id is answered",
          got == "257x146" and "NOTE d05-jpeg-001-jpeg-sof-dimensions-pixels: the answer id asks "
          "jpeg.sof_dimensions_pixels but the text asks png.ihdr_dimensions_pixels" in err, f"{got!r}")


# ------------------------------------------------------------------ 6. which file

def test_targets():
    bad = []

    def expect(label, got, want):
        if got != want:
            bad.append(f"{label}: {got!r}, expected {want!r}")

    dozen = {f"camera-{i:03d}.jpg": jpeg(240 + 17 * i, 135 + 11 * i) for i in range(1, 13)}
    expect("a dozen files, item 007",
           ask("jpeg.sof_dimensions_pixels", "camera-007.jpg", None, "jpeg", item="007", members=dozen)[0], "359x212")
    expect("item 007 while the text names another variant's file",
           ask("jpeg.sof_dimensions_pixels", "camera-002.jpg", None, "jpeg", item="007", members=dozen)[0], "359x212")
    renamed = {f"IMG_{1000 + i * 37}.jpg": jpeg(240 + 17 * i, 135 + 11 * i) for i in range(1, 13)}
    expect("no item number in the names, the named member is there",
           ask("jpeg.sof_dimensions_pixels", "IMG_1259.jpg", None, "jpeg", item="007", members=renamed)[0], "359x212")
    got, err, _ = ask("jpeg.sof_dimensions_pixels", "camera-007.jpg", None, "jpeg", item="007", members=renamed)
    expect("no item number in the names and the named member is missing", (got, "NO TARGET FILE" in err), (None, True))
    mixed = {"photo-640x480.jpg": jpeg(257, 146), "photo-003.png": PNG, "notes-003.txt": b"x"}
    expect("two files carry 003 and the id says png",
           ask("png.ihdr_dimensions_pixels", "photo-003.png", None, "png", item="003", members=mixed)[0], "320x200")
    # Archives as targets: file_properties.py never selects one.
    expect("the digest of a delivered zip is the zip's, not a member's",
           ask("sha256", "bundle-001.zip", ZIP, "zip")[0], hashlib.sha256(ZIP).hexdigest())
    expect("a zip property with the text naming another variant's file: the item's archive",
           values_of(ask("zip.comment", "bundle-009.zip", None, "zip", members={"bundle-001.zip": ZIP})[0])[:1],
           ["case 4471 export"])
    expect("a docx property: the single top-level member",
           values_of(ask("office.core_creator", "memo-009.docx", None, "office", item="009",
                         members={"memo.docx": DOCX})[0])[:1], ["alice.w"])
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w") as z:
        z.writestr("camera-001.jpg", jpeg(257, 146))
    expect("a picture inside a nested zip is still found by its name",
           ask("jpeg.sof_dimensions_pixels", "camera-001.jpg", None, "jpeg",
               members={"bundle-001.zip": nested.getvalue()})[0], "257x146")
    check("target selection: item number, named member, archives, single top-level member", not bad, "; ".join(bad))


# ------------------------------------------------------------------ 7 and 8. covers() and learning a format

def test_covers_and_learning():
    day4 = ATTEMPTS / "day-04" / "metadata-forensics-day-04-picture-this"
    contract, problems = 0, []
    if no_attempts():
        skip("covers() on the Day 4 timed contract returns no problem", f"no saved attempts under {ATTEMPTS}")
    else:
        for mode in ("time_trial", "mastery"):
            if (day4 / mode / "attempt.json").exists():
                qs = json.loads((day4 / mode / "attempt.json").read_text())["questions"]
                contract += len(qs)
                problems += solver.covers(qs)
        check("covers() on the Day 4 timed contract returns no problem", contract == 3 and not problems,
              f"{contract} questions" + "".join("\n       " + p for p in problems))
    unknown = solver.covers([question("exif.unknown_tag", "camera-001.jpg", "exif")])
    check("covers() on a synthetic exif.unknown_tag returns one problem",
          len(unknown) == 1 and "exif.unknown_tag is not registered" in unknown[0], "; ".join(unknown))

    os.environ["CTF_WORKDIR"] = str(TMP / "learn")
    try:
        key = "metadata.format/exif.datetime_original"
        q = question("exif.datetime_original", "camera-001.jpg", "exif")
        before, _, _ = ask("exif.datetime_original", "camera-001.jpg", J, "exif")
        parsed = labels.parse(before)
        open_before = solver.covers([q])
        learned = labels.learn(key, "raw", "accepted", attempt_id="selftest", answer_ids=[q["id"]])
        after, _, _ = ask("exif.datetime_original", "camera-001.jpg", J, "exif")
        open_after = solver.covers([q])
        ledger = TMP / "learn" / "_ledger" / "metadata.jsonl"
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    check("exif.datetime_original is unsure first, the raw EXIF date before ISO",
          parsed is not None and parsed.key == key and parsed.options[:2] ==
          [("raw", "2026:09:30 18:45:12"), ("iso", "2026-09-30T18:45:12")] and len(open_before) == 1,
          f"{before!r}; covers: {open_before}")
    check("after labels.learn accepts 'raw' in a mkdtemp ledger the property is plain and covered",
          learned and ledger.is_file() and after == "2026:09:30 18:45:12" and open_after == [],
          f"{after!r}; covers: {open_after}")
    again, _, _ = ask("exif.datetime_original", "camera-001.jpg", J, "exif")
    check("outside that ledger it is unsure again", not is_plain(again) and again is not None)

    # A judged format that the judge later refuses stops being plain.
    os.environ["CTF_WORKDIR"] = str(TMP / "refused")
    try:
        labels.learn("metadata.format/png.ihdr_dimensions_pixels", "wxh", "rejected", attempt_id="selftest",
                     answer_ids=["d05-png-001-png-ihdr-dimensions-pixels"])
        refused, _, _ = ask("png.ihdr_dimensions_pixels", "scan-001.png", PNG, "png")
        open_refused = solver.covers([question("png.ihdr_dimensions_pixels", "scan-001.png", "png")])
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    check("a confirmed format the ledger records as rejected is no longer answered plain",
          refused is None and len(open_refused) == 1, f"{refused!r}; covers: {open_refused}")


# ------------------------------------------------------------------ 9. the day_patch.py hook

PATCH = '''"""Selftest stub: answers one property the registry does not hold."""
def answer(q, files, ctx):
    text = q.get("question") or ""
    if "exif.unknown_tag" in text:
        return "patched-value"
    if "exif.raising_tag" in text:
        raise RuntimeError("boom")
    if "exif.yes_no_tag" in text:
        return "maybe"
    if "exif.bytes_tag" in text:
        return b"raw bytes are not an answer"
    if "exif.other_lane_tag" in text:
        return '??{"k":"binary.format/elf","o":[["elf","elf"]]}'
    if "exif.unsure_tag" in text:
        return '??{"k":"metadata.format/exif.unsure_tag","o":[["raw","a b"],["trimmed","ab"]]}'
    if "exif.model" in text:
        return "patched-model"      # the registry answers this one unsure
    if "exif.software" in text:
        raise RuntimeError("boom")  # and this one
    if "jpeg.sof_dimensions_pixels" in text:
        return "must-not-be-used"   # the registry answers this one plain
    return None                     # declined: the registry's own answer stays
def handles(q):
    return "exif.unknown_tag" in (q.get("question") or "")
'''


def patched_copy(tag: str, patch_text: str):
    """A copy of the solver under TMP with `patch_text` as its day_patch.py, loaded as a module."""
    folder = TMP / tag / "solvers" / "metadata-forensics"
    folder.mkdir(parents=True)
    (TMP / tag / "solvers" / "common").mkdir()
    for name in ("properties_strict.py", "file_properties.py", "readers_more.py", "readers_docs.py", "readers_formats.py",
                 "conventions.json"):
        shutil.copy(HERE / name, folder / name)
    shutil.copy(ROOT / "solvers" / "common" / "labels.py", TMP / tag / "solvers" / "common" / "labels.py")
    (folder / "day_patch.py").write_text(patch_text)
    spec = importlib.util.spec_from_file_location(f"properties_strict_{tag}", folder / "properties_strict.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_day_patch():
    patched = patched_copy("patched", PATCH)

    unknown, err, q = ask("exif.unknown_tag", "camera-001.jpg", J, "exif", module=patched)
    known, _, _ = ask("jpeg.sof_dimensions_pixels", "camera-001.jpg", J, "jpeg", module=patched)
    unsure, _, _ = ask("exif.make", "camera-001.jpg", J, "exif", module=patched)
    replaced, err_model, _ = ask("exif.model", "camera-001.jpg", J, "exif", module=patched)
    kept, err_soft, _ = ask("exif.software", "camera-001.jpg", J, "exif", module=patched)
    raising, err2, _ = ask("exif.raising_tag", "camera-001.jpg", J, "exif", module=patched)
    misfit, _, _ = ask("exif.yes_no_tag", "camera-001.jpg", J, "exif", module=patched,
                       fmt={"kind": "enum", "accepted_values": ["yes", "no"]})
    check("day_patch.answer is asked about a question answered None or unsure, never about a plain one",
          unknown == "patched-value" and "answered by day_patch.py" in err and known == "257x146"
          and replaced == "patched-model" and "answered by day_patch.py" in err_model,
          f"unknown {unknown!r}, unsure {replaced!r}, plain {known!r}")
    check("when day_patch declines or raises, the registry's unsure answer stays",
          values_of(unsure) == ["Huntress"] and not is_plain(unsure)
          and values_of(kept)[:1] == ["Shuffler 2."] and not is_plain(kept) and "day_patch.answer raised" in err_soft,
          f"declined {unsure!r}, raised {kept!r}")
    check("a day_patch that raises, or whose answer does not fit the format, leaves None",
          raising is None and "day_patch.answer raised RuntimeError" in err2 and misfit is None,
          f"raising {raising!r}, misfit {misfit!r}")
    check("covers() accepts a question day_patch.handles vouches for, and only that one",
          patched.covers([q]) == [] and len(solver.covers([q])) == 1
          and len(patched.covers([question("exif.other_tag", "camera-001.jpg", "exif")])) == 1)

    # A patch value that cannot be serialised must cost its own answer only: before the fix the
    # TypeError left solve_set, and the runner dropped every answer of the set.
    pair = [question("exif.bytes_tag", "camera-001.jpg", "exif"), question("jpeg.sof_dimensions_pixels", "camera-001.jpg", "jpeg")]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("camera-001.jpg", J)
    attempt = {"mode": "single_solve", "questions": pair, "answer_ids": [p["id"] for p in pair],
               "artifacts": [{"filename": "metadata-day-05-evidence.zip"}]}
    try:
        answers, err = solve(attempt, [buf.getvalue()], patched)
    except Exception as e:
        answers, err = {"raised": type(e).__name__}, ""
    check("a day_patch value that cannot be an answer costs that answer, not the set",
          answers == {pair[0]["id"]: None, pair[1]["id"]: "257x146"} and "cannot be an answer" in err, f"{answers!r}")
    other, err3, _ = ask("exif.other_lane_tag", "camera-001.jpg", J, "exif", module=patched)
    mine, _, _ = ask("exif.unsure_tag", "camera-001.jpg", J, "exif", module=patched)
    check("an unsure day_patch answer is passed on under a metadata key only",
          other is None and "not a metadata key" in err3 and values_of(mine) == ["a b", "ab"] and not is_plain(mine),
          f"another lane's key {other!r}; a metadata key {mine!r}")


# ------------------------------------------------------------------ 16. day_patch_template.py

TEMPLATE_LINES = {  # what an agent adds on the day: one line per table
    "ALIAS = {\n": '    "gif.descriptor_dimensions_pixels": "gif.logical_screen_dimensions_pixels",\n'
                   '    "exif.maker_name": "exif.make",\n',
    "NEW = {\n": '    "png.passenger_size_bytes": (lambda n, d: len(d) - d.rfind(b"IEND") - 8 if b"IEND" in d else None, '
                 '"integer"),\n',
}


def test_template():
    text = (HERE / "day_patch_template.py").read_text()
    source = (HERE / "properties_strict.py").read_text()
    # Row 553: the template's bytes are read once more, by name, only to skip importing a day_patch.py
    # equal to it (PATCH_TEMPLATE, used by nothing but that compare).
    template_uses = [ln for ln in source.splitlines() if "PATCH_TEMPLATE" in ln]
    check("the shipped solver loads day_patch.py and never the template",
          source.count("day_patch_template") == 2 and 'HERE / "day_patch.py"' in source
          and source.count('PATCH_TEMPLATE = HERE / "day_patch_template.py"') == 1
          and len(template_uses) == 2 and any("PATCH_TEMPLATE.read_bytes()" in ln for ln in template_uses)
          and all(text.count(marker) == 1 for marker in TEMPLATE_LINES),
          f"the template is named {source.count('day_patch_template')} time(s) in properties_strict.py (its docstring)")

    empty = patched_copy("template-empty", text)
    make, err, _ = ask("exif.make", "camera-001.jpg", J, "exif", module=empty)
    unknown, _, q_unknown = ask("exif.unknown_tag", "camera-001.jpg", J, "exif", module=empty)
    check("the template as shipped loads, answers nothing and vouches for nothing",
          "could not be loaded" not in err and values_of(make) == ["Huntress"] and not is_plain(make)
          and unknown is None and len(empty.covers([q_unknown])) == 1, f"{make!r}, {unknown!r}")

    filled_text = text
    for marker, line in TEMPLATE_LINES.items():
        filled_text = filled_text.replace(marker, marker + line)
    filled = patched_copy("template-filled", filled_text)
    passenger = PNG + b"PASSENGER-0001"
    key = "metadata.format/png.passenger_size_bytes"
    same, err, q_same = ask("gif.descriptor_dimensions_pixels", "anim-001.gif", GIF, "gif", module=filled)
    check("a template ALIAS line answers like its registered target, and covers() accepts it",
          same == "123x45" and "answered by day_patch.py" in err and filled.covers([q_same]) == []
          and len(solver.covers([q_same])) == 1, f"{same!r}; {err.strip()[:120]}")
    doubt, _, q_doubt = ask("exif.maker_name", "camera-001.jpg", J, "exif", module=filled)
    target, _, _ = ask("exif.make", "camera-001.jpg", J, "exif", module=filled)
    parsed = labels.parse(doubt) if doubt else None
    check("a template ALIAS line of an unsure name is unsure like it, under the asked name, and not vouched for",
          parsed is not None and parsed.key == "metadata.format/exif.maker_name"
          and parsed.options == labels.parse(target).options == [("raw", "Huntress")] and len(filled.covers([q_doubt])) == 1,
          f"{doubt!r}; covers: {filled.covers([q_doubt])}")
    new, _, q_new = ask("png.passenger_size_bytes", "scan-001.png", passenger, "png", module=filled)
    parsed = labels.parse(new) if new else None
    open_before = filled.covers([q_new])
    os.environ["CTF_WORKDIR"] = str(TMP / "template-learn")
    try:
        labels.learn(key, "integer", "accepted", attempt_id="selftest", answer_ids=[q_new["id"]])
        after, _, _ = ask("png.passenger_size_bytes", "scan-001.png", passenger, "png", module=filled)
        absent, _, _ = ask("png.passenger_size_bytes", "scan-001.png", J, "png", module=filled)
        open_after = filled.covers([q_new])
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    check("a template NEW line is unsure under the asked name and not vouched for until its format is accepted",
          parsed is not None and parsed.key == key and parsed.options == [("integer", "14")] and len(open_before) == 1,
          f"{new!r}; covers: {open_before}")
    check("after one accepted probe the NEW line is plain and covered; an absent field is still not a plain none",
          after == "14" and open_after == [] and not is_plain(absent) and values_of(absent) == ["none"],
          f"{after!r}; covers: {open_after}; absent {absent!r}")
    plain, _, _ = ask("jpeg.sof_dimensions_pixels", "camera-001.jpg", J, "jpeg", module=filled)
    make, _, _ = ask("exif.make", "camera-001.jpg", J, "exif", module=filled)
    other, _, q_other = ask("exif.unknown_tag", "camera-001.jpg", J, "exif", module=filled)
    check("the filled template leaves every other question as the registry answered it",
          plain == "257x146" and values_of(make) == ["Huntress"] and not is_plain(make) and other is None
          and len(filled.covers([q_other])) == 1, f"{plain!r}, {make!r}, {other!r}")

    broken = patched_copy("template-broken", text.replace("NEW = {\n", 'NEW = {\n    "png.x": (len, "no_such_class"),\n'))
    make, err, _ = ask("exif.make", "camera-001.jpg", J, "exif", module=broken)
    check("a table line with an unknown format class stops the patch from loading, with a NOTE, and costs nothing else",
          "day_patch.py could not be loaded" in err and "no_such_class" in err and values_of(make) == ["Huntress"],
          err.strip()[:160])


# ------------------------------------------------------------------ 17. more spellings of registered facts

def png_of(chunks, trailing=b""):
    """A PNG from (type, body) pairs, with whatever follows its last chunk."""
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + b"".join(chunk(t, d) for t, d in chunks) + trailing


IHDR = struct.pack(">IIBBBBB", 320, 200, 8, 2, 0, 0, 0)
BMP_UP = bmp(64, 48)
BMP_OS2 = b"BM" + struct.pack("<IHHI", 26 + 12, 0, 0, 26) + struct.pack("<IHHHH", 12, 64, 48, 1, 24) + bytes(12)
BMP_OS22, BMP_V5 = (b"BM" + struct.pack("<IHHI", 14 + size, 0, 0, 14 + size) + struct.pack("<IiiHH", size, 64, 48, 1, 24)
                    + bytes(size - 16) for size in (64, 124))
WEBP_SIMPLE = (b"RIFF" + struct.pack("<I", 22) + b"WEBPVP8 " + struct.pack("<I", 10) + b"\x00\x00\x00\x9d\x01\x2a"
               + struct.pack("<HH", 400, 300) + bytes(4))
# The names that answer plainly since Day 6 without having been asked: pure synonyms only.
PLAIN_SYNONYMS = [
    ("gif.lsd_dimensions_pixels", "anim-001.gif", GIF, "123x45"),
    ("gif.logical_screen_descriptor_dimensions_pixels", "anim-001.gif", GIF, "123x45"),
    ("gif.screen_dimensions_pixels", "anim-001.gif", GIF, "123x45"),
    ("gif.canvas_dimensions_pixels", "anim-001.gif", GIF, "123x45"),
    ("bmp.dib_header_dimensions_pixels", "shot-001.bmp", BMP_UP, "64x48"),
    ("bmp.dimensions_pixels", "shot-001.bmp", BMP_UP, "64x48"),
    ("bmp.infoheader_dimensions_pixels", "shot-001.bmp", BMP_UP, "64x48"),
    ("bmp.bitmapinfoheader_dimensions_pixels", "shot-001.bmp", BMP_UP, "64x48"),
    ("webp.vp8x_canvas_dimensions_pixels", "web-001.webp", WEBP, "400x300"),
]
DOUBTFUL = [  # a name that could mean another structure: the target's value, unsure
    ("gif.header_dimensions_pixels", "anim-001.gif", GIF, "123x45"),
    ("bmp.header_dimensions_pixels", "shot-001.bmp", BMP_UP, "64x48"),
    ("tiff.ifd_dimensions_pixels", "scan-001.tif", TIFF, "640x480"),
    ("tiff.image_dimensions_pixels", "scan-001.tif", TIFF, "640x480"),
]
SPELLINGS = [  # (asked, the registered name it spells, file, bytes): the same options under its own key
    ("png.ihdr_colour_type", "png.ihdr_color_type", "scan-001.png", PNG),
    ("png.ihdr_interlace_method", "png.ihdr_interlace", "scan-001.png", PNG),
    ("png.interlace_method", "png.interlace", "scan-001.png", PNG),
    ("png.ihdr_width", "png.ihdr_width_pixels", "scan-001.png", PNG),
    ("png.ihdr_height", "png.ihdr_height_pixels", "scan-001.png", PNG),
    ("jpeg.component_count", "jpeg.sof_component_count", "camera-001.jpg", J),
    ("jpeg.app_segments", "jpeg.app_markers", "camera-001.jpg", J),
    ("exif.ifd0_make", "exif.make", "camera-001.jpg", J),
    ("exif.date_time_original", "exif.datetime_original", "camera-001.jpg", J),
    ("exif.iso_speed", "exif.iso", "camera-001.jpg", J),
    ("exif.camera_model", "exif.model", "camera-001.jpg", J),
    ("pdf.producer", "pdf.info_producer", "report-001.pdf", PDF),
    ("pdf.title", "pdf.info_title", "report-001.pdf", PDF),
    ("zip.central_directory_entry_count", "zip.entry_count", "bundle-001.zip", ZIP),
    ("zip.eocd_comment", "zip.comment", "bundle-001.zip", ZIP),
    ("zip.archive_comment", "zip.comment", "bundle-001.zip", ZIP),
    ("text.eol_style", "text.line_ending", "export-001.txt", b"a\r\nb\r\n"),
]


def test_spellings():
    bad = []
    for prop, fname, data, want in PLAIN_SYNONYMS:
        got, _, q = ask(prop, fname, data, prop.split(".")[0])
        if got != want or solver.covers([q]):
            bad.append(f"{prop}: {got!r}, expected {want!r} plain and covered")
    confirmed = {p.name for p in solver.REG.values() if p.confirmed and "." in p.name}
    check("a pure synonym of a judged structure is plain, and no other name became plain",
          not bad and len(confirmed) == 31 and {r[0] for r in PLAIN_SYNONYMS} <= confirmed,
          "; ".join(bad) or f"{len(confirmed)} dotted names answer plainly, {len(PLAIN_SYNONYMS)} of them new")

    bad = []
    for prop, fname, data, want in DOUBTFUL:
        got, _, q = ask(prop, fname, data, prop.split(".")[0])
        parsed = labels.parse(got) if got else None
        if parsed is None or parsed.key != "metadata.format/" + prop or values_of(got) != [want] or not solver.covers([q]):
            bad.append(f"{prop}: {got!r}")
    for label, prop, fname, data, typ, want in [
            ("a top-down BMP through a synonym", "bmp.dimensions_pixels", "shot-001.bmp", BMP, "bmp", ["64x48", "64x-48"]),
            ("a top-down BMP through the Windows name", "bmp.infoheader_dimensions_pixels", "shot-001.bmp", BMP, "bmp",
             ["64x48", "64x-48"]),
            ("an OS/2 core header is not a BITMAPINFOHEADER", "bmp.infoheader_dimensions_pixels", "shot-001.bmp", BMP_OS2,
             "bmp", []),
            ("nor is a 64-byte OS/2 2.x header", "bmp.bitmapinfoheader_dimensions_pixels", "shot-001.bmp", BMP_OS22, "bmp", []),
            ("a WebP without a VP8X chunk", "webp.vp8x_canvas_dimensions_pixels", "web-001.webp", WEBP_SIMPLE, "webp",
             ["none"])]:
        got, _, _ = ask(prop, fname, data, typ)
        if is_plain(got) or values_of(got) != want:
            bad.append(f"{label}: {got!r}, expected {want} and never plain")
    for label, data in (("an OS/2 core header", BMP_OS2), ("a 64-byte OS/2 2.x header", BMP_OS22),
                        ("a 124-byte V5 header through the Windows name", BMP_V5)):
        name = "bmp.infoheader_dimensions_pixels" if data is BMP_V5 else "bmp.dib_header_dimensions_pixels"
        core, _, _ = ask(name, "shot-001.bmp", data, "bmp")
        if core != "64x48":
            bad.append(f"{label} through {name}: {core!r}")
    check("a doubtful name is unsure with its target's value, and a synonym follows its target into doubt",
          not bad, "; ".join(bad))

    bad = []
    for prop, target, fname, data in SPELLINGS:
        got, _, _ = ask(prop, fname, data, prop.split(".")[0])
        ref, _, _ = ask(target, fname, data, target.split(".")[0])
        a, b = labels.parse(got) if got else None, labels.parse(ref) if ref else None
        if a is None or b is None or a.options != b.options or a.key != "metadata.format/" + prop:
            bad.append(f"{prop}: {got!r} against {target}: {ref!r}")
    check(f"the {len(SPELLINGS)} other spellings answer unsure with their target's options, each under its own key",
          not bad, "; ".join(bad))

    # The two PNG readers: nothing after IEND is a chunk, and three names are not tEXt keywords.
    bad = []
    tail = PNG + b"PASSENGER-0001"
    for prop, want in [("png.chunk_count", "6"), ("png.chunk_types", "IHDR,pHYs,tEXt,tIME,IDAT,IEND"),
                       ("png.text_chunk_count", "1"), ("png.text_keywords", "Software"), ("png.text_chunk_present", "true"),
                       ("png.text_software", "HuntressCam 1.2")]:
        for label, data in (("", PNG), (" with 14 bytes after IEND", tail)):
            got, _, _ = ask(prop, "scan-001.png", data, "png")
            if is_plain(got) or values_of(got)[:1] != [want]:
                bad.append(f"{prop}{label}: {got!r}, expected first option {want!r}")
    keyworded = png_of([(b"IHDR", IHDR), (b"tEXt", b"Keywords\x00alpha, beta"), (b"IDAT", zlib.compress(b"\x00")), (b"IEND", b"")])
    mixed = png_of([(b"IHDR", IHDR), (b"tEXt", b"Title\x00x"), (b"iTXt", b"Author\x00\x00\x00\x00\x00y"), (b"IEND", b"")])
    for label, prop, data, want in [("a tEXt chunk whose keyword is Keywords", "png.text_keywords", keyworded, []),
                                    ("the same file, another of the three names", "png.text_chunk_count", keyworded, ["1"]),
                                    ("tEXt beside iTXt", "png.text_chunk_count", mixed, []),
                                    ("no tEXt chunk at all", "png.text_chunk_present", png(extra=False), ["false"]),
                                    ("not a PNG", "png.text_chunk_count", J, ["none"])]:
        got, _, _ = ask(prop, "scan-001.png", data, "png")
        if is_plain(got) or values_of(got) != want:
            bad.append(f"{label}: {prop} {got!r}, expected {want}")
    check("PNG chunks end at IEND, and text_chunk_count, text_keywords and text_chunk_present are not tEXt keywords",
          not bad, "; ".join(bad))


# ------------------------------------------------------------------ 18. structure and more file types, all unsure

def gif_animated(comments=(b"evidence frame",)):
    """320x200 GIF89a: a global colour table, a NETSCAPE loop count of 3, comments, two 300x180 frames."""
    out = b"GIF89a" + struct.pack("<HHBBB", 320, 200, 0x80, 0, 0) + bytes(6)
    out += b"\x21\xff\x0bNETSCAPE2.0\x03\x01" + struct.pack("<H", 3) + b"\x00"
    for text in comments:
        out += b"\x21\xfe" + bytes([len(text)]) + text + b"\x00"
    for _ in range(2):
        out += b"\x2c" + struct.pack("<HHHHB", 0, 0, 300, 180, 0) + b"\x02\x02\x4c\x01\x00"
    return out + b"\x3b"


def gz(mtime=1790755200, name=b"field-notes.txt"):
    body = b"field notes\n"
    deflate = zlib.compressobj(wbits=-15)
    packed = deflate.compress(body) + deflate.flush()
    return (b"\x1f\x8b\x08\x08" + struct.pack("<I", mtime) + b"\x00\xff" + name + b"\x00" + packed
            + struct.pack("<II", zlib.crc32(body), len(body)))


def wav():
    data = bytes(64)
    body = b"WAVE" + b"fmt " + struct.pack("<IHHIIHH", 16, 1, 2, 44100, 176400, 4, 16) + b"data" + struct.pack("<I", len(data)) + data
    return b"RIFF" + struct.pack("<I", len(body)) + body


def mp3(flags=0):
    def frame(fid, text):
        return fid + struct.pack(">I", len(text) + 1) + b"\x00\x00\x00" + text
    frames = frame(b"TIT2", b"Evidence Track") + frame(b"TPE1", b"The Analysts")
    return b"ID3\x03\x00" + bytes([flags, 0, 0, 0, len(frames)]) + frames + b"\xff\xfb\x90\x00" + bytes(64)


def elf64():
    return (b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
            + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 1, 64, 0, 0) + bytes(64))


def pe64():
    dos = b"MZ" + bytes(58) + struct.pack("<I", 0x80) + bytes(0x40)
    return dos + b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 3, 1790755200, 0, 0, 240, 0x22) + struct.pack("<H", 0x20B) + bytes(238)


def test_more_types():
    gifx, gzx, wavx, mp3x, elfx, pex = gif_animated(), gz(), wav(), mp3(), elf64(), pe64()
    tail = PNG + b"PASSENGER-0001"
    passenger = png_of([(b"IHDR", IHDR), (b"prVt", b"stowaway"), (b"IDAT", zlib.compress(b"\x00")), (b"IEND", b"")])
    appended = J + b"APPENDED"
    notes_crc = "%08x" % zlib.crc32(b"field notes\n")
    app = zipped({"docProps/app.xml": b"<Properties><Application>Microsoft Office Word</Application>"
                                      b"<TotalTime>42</TotalTime></Properties>"})
    cases = [  # (property, file, bytes, the value read from the bytes: the first option)
        ("png.bytes_after_iend", "scan-001.png", tail, "14"), ("png.trailing_bytes", "scan-001.png", tail, "14"),
        ("png.trailing_data_size_bytes", "scan-001.png", tail, "14"), ("png.trailing_data_present", "scan-001.png", tail, "true"),
        ("png.trailing_bytes", "scan-001.png", PNG, "0"), ("png.trailing_data_present", "scan-001.png", PNG, "false"),
        ("png.trailing_data_sha256", "scan-001.png", tail, hashlib.sha256(b"PASSENGER-0001").hexdigest()),
        ("png.idat_count", "scan-001.png", tail, "1"), ("png.first_chunk_type", "scan-001.png", tail, "IHDR"),
        ("png.last_chunk_type", "scan-001.png", tail, "IEND"), ("png.ancillary_chunk_types", "scan-001.png", tail, "pHYs,tEXt,tIME"),
        ("png.ihdr_crc_valid", "scan-001.png", tail, "true"), ("png.has_text_chunk", "scan-001.png", tail, "true"),
        ("png.unknown_chunk_type", "scan-001.png", passenger, "prVt"), ("png.private_chunk_type", "scan-001.png", passenger, "prVt"),
        ("png.unexpected_chunk_type", "scan-001.png", passenger, "prVt"), ("png.unknown_chunk_type", "scan-001.png", PNG, "none"),
        ("jpeg.bytes_after_eoi", "camera-001.jpg", appended, "8"), ("jpeg.trailing_bytes", "camera-001.jpg", J, "0"),
        ("jpeg.trailing_data_md5", "camera-001.jpg", appended, hashlib.md5(b"APPENDED").hexdigest()),
        ("jpeg.eoi_offset", "camera-001.jpg", appended, str(len(J) - 2)), ("jpeg.dqt_count", "camera-001.jpg", J, "1"),
        ("jpeg.dht_count", "camera-001.jpg", J, "1"), ("jpeg.quantization_table_count", "camera-001.jpg", J, "1"),
        ("jpeg.restart_interval", "camera-001.jpg", J, "none"), ("jpeg.comment_present", "camera-001.jpg", J, "true"),
        ("exif.gps_present", "camera-001.jpg", J, "true"), ("jpeg.exif_gps_present", "camera-001.jpg", PROGRESSIVE, "false"),
        ("gif.frame_count", "anim-001.gif", gifx, "2"), ("gif.image_count", "anim-001.gif", GIF, "1"),
        ("gif.first_frame_dimensions_pixels", "anim-001.gif", gifx, "300x180"),
        ("gif.image_descriptor_dimensions_pixels", "anim-001.gif", gifx, "300x180"),
        ("gif.comment", "anim-001.gif", gifx, "evidence frame"), ("gif.loop_count", "anim-001.gif", gifx, "3"),
        ("gif.loop_count", "anim-001.gif", GIF, "none"), ("gif.bytes_after_trailer", "anim-001.gif", gifx + b"XYZ", "3"),
        ("bmp.dib_header_size_bytes", "shot-001.bmp", BMP_UP, "40"), ("bmp.pixel_data_offset", "shot-001.bmp", BMP_UP, "54"),
        ("bmp.file_size_field_bytes", "shot-001.bmp", BMP_UP, str(len(BMP_UP))),
        ("webp.chunk_types", "web-001.webp", WEBP, "VP8X"), ("webp.riff_size_bytes", "web-001.webp", WEBP, str(len(WEBP) - 8)),
        ("webp.vp8_dimensions_pixels", "web-001.webp", WEBP_SIMPLE, "400x300"),
        ("tiff.ifd0_entry_count", "scan-001.tif", TIFF, "3"), ("tiff.compression", "scan-001.tif", TIFF, "none"),
        ("pdf.eof_marker_count", "report-001.pdf", PDF, "1"), ("pdf.encrypted", "report-001.pdf", PDF, "false"),
        ("zip.eocd_entry_count", "bundle-001.zip", ZIP, "2"), ("zip.file_count", "bundle-001.zip", ZIP, "2"),
        ("zip.entry_names", "bundle-001.zip", ZIP, "inner/report.txt,second.bin"),
        ("zip.first_entry_compression_method", "bundle-001.zip", ZIP, "0"), ("zip.encrypted", "bundle-001.zip", ZIP, "false"),
        ("zip.first_entry_compression_method", "bundle-001.zip", app, "8"),
        ("office.app_application", "memo-001.docx", app, "Microsoft Office Word"), ("docx.app_total_time", "memo-001.docx", app, "42"),
        ("docx.app_company", "memo-001.docx", app, "none"),
        ("gzip.mtime", "notes-001.txt.gz", gzx, "1790755200"), ("gzip.mtime_unix", "notes-001.txt.gz", gzx, "1790755200"),
        ("gzip.original_filename", "notes-001.txt.gz", gzx, "field-notes.txt"), ("gzip.fname", "notes-001.txt.gz", gzx, "field-notes.txt"),
        ("gzip.isize", "notes-001.txt.gz", gzx, "12"), ("gzip.os", "notes-001.txt.gz", gzx, "255"),
        ("gzip.comment", "notes-001.txt.gz", gzx, "none"),
        # the trailer is where the member ends, not the last 8 bytes of the file
        ("gzip.isize", "notes-001.txt.gz", gzx + b"PASSENGER-0001", "12"),
        ("gzip.trailer_isize", "notes-001.txt.gz", gzx + b"PASSENGER-0001", "12"),
        ("gzip.trailer_crc32", "notes-001.txt.gz", gzx + b"PASSENGER-0001", notes_crc),
        ("gzip.trailer_crc32", "notes-001.txt.gz", gzx, notes_crc),
        ("gzip.original_filename", "notes-001.txt.gz", gz(name=b""), "none"),
        ("docx.app_total_time", "memo-001.docx", zipped({"docProps/app.xml": b"<ep:Properties><ep:TotalTime>42</ep:TotalTime>"
                                                                           b"</ep:Properties>"}), "42"),
        ("wav.sample_rate_hz", "clip-001.wav", wavx, "44100"), ("wav.fmt_sample_rate_hz", "clip-001.wav", wavx, "44100"),
        ("wav.channels", "clip-001.wav", wavx, "2"), ("wav.channel_count", "clip-001.wav", wavx, "2"),
        ("wav.bits_per_sample", "clip-001.wav", wavx, "16"), ("wav.audio_format", "clip-001.wav", wavx, "1"),
        ("wav.chunk_types", "clip-001.wav", wavx, "fmt ,data"), ("wav.sample_rate_hz", "clip-001.wav", PNG, "none"),
        ("id3.title", "track-001.mp3", mp3x, "Evidence Track"), ("mp3.id3_title", "track-001.mp3", mp3x, "Evidence Track"),
        ("id3.tit2", "track-001.mp3", mp3x, "Evidence Track"), ("id3.artist", "track-001.mp3", mp3x, "The Analysts"),
        ("id3.album", "track-001.mp3", mp3x, "none"), ("id3.version", "track-001.mp3", mp3x, "2.3"),
        ("elf.machine", "tool-001.elf", elfx, "EM_X86_64"), ("elf.e_machine", "tool-001.elf", elfx, "62"),
        ("elf.class", "tool-001.elf", elfx, "ELF64"), ("elf.type", "tool-001.elf", elfx, "ET_EXEC"),
        ("elf.endianness", "tool-001.elf", elfx, "little"), ("elf.entry_point", "tool-001.elf", elfx, "0x401000"),
        ("elf.machine", "tool-001.elf", b"plain text\n", "none"),
        ("pe.machine", "tool-001.exe", pex, "IMAGE_FILE_MACHINE_AMD64"), ("pe.timestamp", "tool-001.exe", pex, "1790755200"),
        ("pe.section_count", "tool-001.exe", pex, "3"), ("pe.number_of_sections", "tool-001.exe", pex, "3"),
        ("pe.optional_header_magic", "tool-001.exe", pex, "0x20b"),
        ("sha3_256", "scan-001.png", PNG, hashlib.sha3_256(PNG).hexdigest()), ("blake2b", "scan-001.png", PNG, hashlib.blake2b(PNG).hexdigest()),
        ("crc32", "scan-001.png", PNG, f"{zlib.crc32(PNG):08x}"), ("hash.crc32_hex", "scan-001.png", PNG, f"{zlib.crc32(PNG):08x}"),
        ("magic.suffix_hex_8", "scan-001.png", PNG, PNG[-8:].hex()), ("text.non_ascii_byte_count", "export-001.txt", b"a\xc3\xa9\n", "2"),
    ]
    bad = []
    for prop, fname, data, want in cases:
        got, _, q = ask(prop, fname, data, prop.split(".")[0] if "." in prop else "file")
        if is_plain(got) or values_of(got)[:1] != [want] or not solver.covers([q]):
            bad.append(f"{prop} for {fname}: {got!r}, expected first option {want!r}, unsure and not covered")
    check(f"structure and more file types: {len(cases)} properties read from the bytes, every one of them unsure",
          not bad, "; ".join(bad[:6]))
    offered = values_of(ask("gzip.mtime", "notes-001.txt.gz", gzx, "gzip")[0]) + values_of(ask("pe.machine", "tool-001.exe", pex, "pe")[0])
    check("a header time offers the number and its UTC date, a code its constant, its number and its hex",
          offered == ["1790755200", "2026-09-30T08:00:00Z", "2026-09-30T08:00:00", "2026-09-30 08:00:00",
                      "IMAGE_FILE_MACHINE_AMD64", "34404", "0x8664"], f"{offered}")

    # A name with two readings in the file, or a structure that does not parse, is no answer.
    dqt = b"\x00" + bytes(range(1, 65))
    two_tables = jpeg(40, 30).replace(b"\xff\xdb" + struct.pack(">H", 67) + dqt, b"\xff\xdb" + struct.pack(">H", 132) + dqt + b"\x01" + dqt[1:])
    stale = bytearray(PNG)
    stale[16:20] = struct.pack(">I", 999)
    with_dir = io.BytesIO()
    with zipfile.ZipFile(with_dir, "w") as z:
        z.writestr("folder/", b"")
        z.writestr("folder/a.txt", b"a")
    id3v1 = b"\xff\xfb\x90\x00" + bytes(64) + b"TAG" + b"Quiet Harbor".ljust(125, b"\x00")
    frame = b"\x2c" + struct.pack("<HHHHB", 0, 0, 300, 180, 0)
    gif_mixed = gifx[:gifx.rfind(frame)] + b"\x2c" + struct.pack("<HHHHB", 0, 0, 150, 90, 0) + gifx[gifx.rfind(frame) + len(frame):]
    half_locked = bytearray(ZIP)
    half_locked[ZIP.find(b"PK\x01\x02") + 8] |= 1  # the first central directory header's encryption flag
    doubts = [  # (what, property, file, bytes, every value offered)
        ("one DQT segment with two tables", "jpeg.dqt_count", "camera-001.jpg", two_tables, []),
        ("the same, counted as segments", "jpeg.dqt_segment_count", "camera-001.jpg", two_tables, ["1"]),
        ("the same, counted as tables", "jpeg.quantization_table_count", "camera-001.jpg", two_tables, ["2"]),
        ("a JPEG cut before its EOI", "jpeg.bytes_after_eoi", "camera-001.jpg", J[:-2], []),
        ("a JPEG cut before its EOI", "jpeg.dht_count", "camera-001.jpg", J[:-2], []),
        ("a PNG without IEND", "png.trailing_bytes", "scan-001.png", png_of([(b"IHDR", IHDR), (b"IDAT", b"x")]), []),
        ("two unknown chunk types, one asked", "png.unknown_chunk_type", "scan-001.png",
         png_of([(b"IHDR", IHDR), (b"prVt", b"a"), (b"juNk", b"b"), (b"IEND", b"")]), []),
        ("two unknown chunk types, all asked", "png.unknown_chunk_types", "scan-001.png",
         png_of([(b"IHDR", IHDR), (b"prVt", b"a"), (b"juNk", b"b"), (b"IEND", b"")]),
         ["prVt,juNk", "prVt, juNk", "prVt juNk", '["prVt","juNk"]']),
        ("an IHDR edited under a stale CRC", "png.ihdr_crc_valid", "scan-001.png", bytes(stale), ["false"]),
        ("an IHDR edited under a stale CRC", "png.ihdr_crc32", "scan-001.png", bytes(stale), []),
        ("two different GIF comments", "gif.comment", "anim-001.gif", gif_animated((b"one", b"two")), []),
        ("a GIF cut inside a frame", "gif.frame_count", "anim-001.gif", gifx[:-4], []),
        ("a gzip header without a time", "gzip.mtime", "notes-001.txt.gz", gz(mtime=0), ["0", "none"]),
        ("an unsynchronised ID3 tag", "id3.title", "track-001.mp3", mp3(flags=0x80), []),
        ("a zip with a directory entry", "zip.file_count", "bundle-001.zip", with_dir.getvalue(), []),
        ("an ELF header cut short", "elf.machine", "tool-001.elf", elfx[:20], []),
        # a gzip trailer that is not the one trailer of an intact member
        ("two gzip members", "gzip.isize", "notes-001.txt.gz", gzx + gz(name=b"second.txt"), []),
        ("two gzip members", "gzip.trailer_crc32", "notes-001.txt.gz", gzx + gz(name=b"second.txt"), []),
        ("a gzip member cut inside its data", "gzip.isize", "notes-001.txt.gz", gzx[:-10], []),
        ("a gzip trailer edited after the fact", "gzip.trailer_isize", "notes-001.txt.gz", gzx[:-4] + struct.pack("<I", 99), []),
        # the field is in the file in a form that is not read: never `none`
        ("a gzip file cut inside its header", "gzip.mtime", "notes-001.txt.gz", gzx[:12], []),
        ("a gzip file cut inside its header", "gzip.original_filename", "notes-001.txt.gz", gzx[:17], []),
        ("an ID3v1 tag only", "id3.title", "track-001.mp3", id3v1, []),
        ("an ID3v1 tag only", "id3.version", "track-001.mp3", id3v1, []),
        ("an ID3v2 tag that is not at offset 0", "mp3.id3_title", "track-001.mp3", bytes(4) + mp3x, []),
        ("an ID3 header of a version that is not read", "id3.title", "track-001.mp3", b"ID3\x05" + mp3x[4:], []),
        ("an ID3 frame in an encoding that is not read", "id3.title", "track-001.mp3",
         mp3x.replace(b"\x00\x00\x00Evidence Track", b"\x00\x00\x09Evidence Track"), []),
        ("an RF64 WAVE file", "wav.sample_rate_hz", "clip-001.wav", b"RF64" + wavx[4:], []),
        ("a big-endian RIFX WAVE file", "wav.chunk_types", "clip-001.wav", b"RIFX" + wavx[4:], []),
        ("a WAVE file without a fmt chunk", "wav.channels", "clip-001.wav",
         b"RIFF" + struct.pack("<I", 12) + b"WAVEdata" + struct.pack("<I", 0), []),
        ("a tEXt chunk after IEND", "png.text_comment", "scan-001.png",
         PNG + png_of([(b"tEXt", b"Comment\x00after the end")])[8:], []),
        # the remaining guards of the new readers
        ("GIF frames of two sizes", "gif.frame_dimensions_pixels", "anim-001.gif", gif_mixed, []),
        ("GIF frames of two sizes, the first asked", "gif.first_frame_dimensions_pixels", "anim-001.gif", gif_mixed, ["300x180"]),
        ("a VP8 chunk without the key frame signature", "webp.vp8_dimensions_pixels", "web-001.webp",
         WEBP_SIMPLE.replace(b"\x9d\x01\x2a", b"\x9d\x01\x2b"), []),
        ("bytes after the end-of-central-directory record", "zip.eocd_entry_count", "bundle-001.zip", ZIP + b"JUNK", []),
        ("one entry encrypted and one not", "zip.encrypted", "bundle-001.zip", bytes(half_locked), []),
        ("one entry encrypted and one not, the first asked", "zip.first_entry_encrypted", "bundle-001.zip", bytes(half_locked), ["true"]),
    ]
    bad = []
    for label, prop, fname, data, want in doubts:
        got, _, _ = ask(prop, fname, data, prop.split(".")[0])
        if is_plain(got) or values_of(got) != want:
            bad.append(f"{label}: {prop} {got!r}, expected {want}")
    got, err, _ = ask("elf.machine", "tool-007.elf", None, "elf", item="007",
                      members={"bundle.zip": zipped({"x.bin": elfx, "y.bin": elfx[:40]})})
    if got is not None or "NO TARGET FILE" not in err:
        bad.append(f"elf.machine with only a wrapper archive delivered: {got!r}")
    got, err, _ = ask("gzip.mtime", "notes-007.txt.gz", None, "gzip", item="007",
                      members={"bundle.zip": zipped({"x.gz": gzx, "y.gz": gz(name=b"other.txt")})})
    if got is not None or "NO TARGET FILE" not in err:
        bad.append(f"gzip.mtime with only a wrapper archive delivered: {got!r}")
    check("a name with two readings in the file, a structure that does not parse, or a wrapper archive: no answer",
          not bad, "; ".join(bad))

    # What Layer 1 does with a new name: one probe on a clean base, then plain on the clocks. The
    # accepted form must not carry a wrong value, or a doubtful one, into a variant with a passenger.
    os.environ["CTF_WORKDIR"] = str(TMP / "more-types")
    try:
        q = question("gzip.mtime", "notes-001.txt.gz", "gzip")
        open_before = solver.covers([q])
        labels.learn("metadata.format/gzip.mtime", "unix", "accepted", attempt_id="selftest", answer_ids=[q["id"]])
        after, _, _ = ask("gzip.mtime", "notes-001.txt.gz", gzx, "gzip")
        open_after = solver.covers([q])
        no_time, _, _ = ask("gzip.mtime", "notes-001.txt.gz", gz(mtime=0), "gzip")
        for name in ("gzip.isize", "gzip.trailer_crc32"):
            labels.learn("metadata.format/" + name, "hex_lower" if name.endswith("crc32") else "integer", "accepted",
                         attempt_id="selftest", answer_ids=["selftest"])
        timed = [ask(name, "notes-001.txt.gz", data, "gzip")[0] for name in ("gzip.isize", "gzip.trailer_crc32")
                 for data in (gzx, gzx + b"PASSENGER-0001", gzx + gz(name=b"second.txt"))]
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    check("a new format class is covered and plain once one of its forms is accepted",
          len(open_before) == 1 and after == "1790755200" and open_after == [], f"{after!r}; covers: {open_before} then {open_after}")
    check("after that probe a gzip time of 0 is still unsure, and a gzip trailer is the member's own or no answer",
          not is_plain(no_time) and values_of(no_time) == ["0", "none"]
          and timed == ["12", "12", None, notes_crc, notes_crc, None], f"mtime 0: {no_time!r}; trailers: {timed}")
    _, err, _ = ask("gzip.unknown_field", "notes-001.txt.gz", gzx, "gzip")
    check("the facts page of a new file type lists its fields",
          "UNKNOWN PROPERTY gzip.unknown_field for" in err
          and "  gzip.mtime = 1790755200" in err and "  gzip.original_filename = field-notes.txt" in err,
          "; ".join(err.splitlines()[:3]))

    empty = solver.Prop("gzip.empty_text", lambda n, d: "", "text", False)
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            got = repr(solver.present(empty, question("gzip.empty_text", "notes-001.txt.gz", "gzip"), "notes-001.txt.gz", gzx))
    except Exception as e:
        got = f"raised {type(e).__name__}"
    big = (b"GIF89a" + struct.pack("<HHBBB", 4, 4, 0, 0, 0) + b"\x2c" + struct.pack("<HHHHB", 0, 0, 4, 4, 0) + b"\x02"
           + (b"\xff" + bytes(255)) * (4 << 20 >> 8) + b"\x00\x3b")
    started = time.perf_counter()
    frames = solver.lookup("gif.frame_count").fn("anim-001.gif", big)
    took = time.perf_counter() - started
    check("an extractor that reads an empty text is no answer and raises nothing; 4 MiB of GIF image data is walked, not joined",
          got == "None" and frames == 1 and took < 0.25, f"present() gave {got}; gif.frame_count {frames} in {took:.3f} s")


# ------------------------------------------------------------------ 10. truncated and damaged files

def test_robust():
    rng = random.Random(5)
    blobs = [b"", b"\x00", b"\xff\xd8", b"\xff\xd8\xff\xe1\x00\x08Exif\x00\x00", b"II*\x00\xff\xff\xff\xff",
             b"PK\x03\x04", b"%PDF-", b"\x89PNG\r\n\x1a\n\xff\xff\xff\xffIHDR", b"GIF89a", b"BM" + b"\x00" * 30,
             b"RIFF\x00\x00\x00\x00WEBPVP8X"]
    for whole in (J, PNG, GIF, BMP, WEBP, TIFF, ZIP, PDF, DOCX, UTF16):
        blobs += [whole[:n] for n in sorted({rng.randrange(1, len(whole)) for _ in range(6)})]
        for _ in range(3):  # the same file with a few bytes changed
            hit = bytearray(whole)
            for _ in range(4):
                hit[rng.randrange(len(hit))] = rng.randrange(256)
            blobs.append(bytes(hit))
    names = sorted(solver.REG) + ["sha256", "file_md5", "magic_prefix_hex_16", "text_utf16be_bom_present",
                                  "png_text_software", "pdf_info_title", "office_core_creator"]
    shapes = {"basename": r".+", "integer": r"\d+", "hex": r"[0-9a-f]+", "bool": r"true|false", "wxh": r"\d+x\d+",
              "text": r"\S(?:.*\S)?",   # pdf.header_version 'raw', judged 2026-10-06
              "list": r"\[\".*\"\]"}    # zip.central_directory_member_names 'json_compact', judged 2026-10-08
    raised, misshapen, asked = [], [], 0
    with contextlib.redirect_stderr(io.StringIO()):
        for i, data in enumerate(blobs):
            for name in names:
                p = solver.lookup(name)
                q = {"qid": name, "answer_id": name, "question": "", "answer_format": DAY4_FORMAT}
                asked += 1
                try:
                    got = solver.present(p, q, "sample.bin", data)
                except Exception as e:
                    raised.append(f"{name} on blob {i}: {type(e).__name__}")
                    continue
                if is_plain(got):
                    if not p.confirmed and not solver.labels.state(p.key).get("accepted"):
                        # plain without a judged format is wrong; a format the judge accepted since
                        # (pdf.header_version 'raw', 2026-10-06) reaches the seed through promote
                        misshapen.append(f"{name} on blob {i}: plain {got!r} from an unjudged format")
                    elif got != "none" and not re.fullmatch(shapes[p.fmt], got):
                        misshapen.append(f"{name} on blob {i}: {got!r} is not a {p.fmt}")
    check("truncated and damaged files: no extractor raises, and a plain answer always has its judged shape",
          not raised and not misshapen, f"{asked} property and file pairs" + "".join("; " + x for x in (raised + misshapen)[:5]))


# ------------------------------------------------------------------ 11. no guess about the file

def ask_prepared(q: dict, delivery: bytes, dname="metadata-day-05-evidence.zip"):
    """A prepared question about a delivery given as bytes: (answer, stderr text)."""
    attempt = {"mode": "single_solve", "questions": [q], "answer_ids": [q["id"]], "artifacts": [{"filename": dname}]}
    answers, err = solve(attempt, [delivery])
    return answers.get(q["id"]), err


def zipped(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in members.items():
            z.writestr(n, d)
    return buf.getvalue()


def test_no_file_guess():
    bad = []

    def expect(label, got, want):
        if got != want:
            bad.append(f"{label}: {got!r}, expected {want!r}")

    # A wrapper archive as the one top-level member, its pictures carrying neither the item number
    # nor the named file. Before the fix the wrapper itself was the target: 'none' for the JPEG
    # size, 'false' for the BOM flag and the wrapper's digest for a jpeg item, all plain.
    wrapper = {"bundle.zip": zipped({f"IMG_{1000 + 37 * i}.jpg": jpeg(240 + i, 135 + i) for i in range(3)})}
    for prop, typ, fname, fmt in [("jpeg.sof_dimensions_pixels", "jpeg", "camera-007.jpg", None),
                                  ("sha256", "jpeg", "camera-007.jpg", None),
                                  ("text.utf8_bom_present", "text", "notes-007.txt", TRUE_FALSE),
                                  ("pdf.version", "pdf", "report-007.pdf", None)]:
        got, err, _ = ask(prop, fname, None, typ, item="007", members=wrapper, fmt=fmt)
        expect(f"{prop} with only a wrapper archive delivered", (got, "NO TARGET FILE" in err), (None, True))
    # The fallback itself stays: an identity question with no content type in its id is about the one top-level member.
    expect("sha256 of the single top-level member, the text naming another variant's file",
           ask("sha256", "bundle-009.zip", None, "file", item="009", members=wrapper)[0],
           hashlib.sha256(wrapper["bundle.zip"]).hexdigest())
    check("an archive that is only the single top-level member is not the target of a picture, text or PDF question",
          not bad, "; ".join(bad))

    bad = []
    evidence = zipped({"note.txt": b"hello"})
    q = question("sha256", "metadata-day-05-evidence.zip", "zip")
    q["artifact"] = "metadata-day-05-evidence.zip"
    expect("the digest of the delivery the question names", ask_prepared(q, evidence)[0], hashlib.sha256(evidence).hexdigest())
    q = question("zip.entry_count", "metadata-day-05-evidence.zip", "zip")
    q["artifact"] = "metadata-day-05-evidence.zip"
    expect("the entry count of the delivery the question names", values_of(ask_prepared(q, evidence)[0]), ["1"])
    q = question("office.core_creator", "memo-001.docx", "office")
    q["artifact"] = "memo-001.docx"
    expect("a docx delivered bare", values_of(ask_prepared(q, DOCX, "memo-001.docx")[0])[:1], ["alice.w"])
    # The Day 1 shape (the artifact is the zip, the text names no file) still means the only member.
    q = {"id": "note-sha256", "question": "What is its SHA-256 digest?", "artifact": "metadata-day-05-evidence.zip",
         "answer_format": DAY4_FORMAT, "normalization": "trim"}
    expect("an artifact without a member and a text that names no file", ask_prepared(q, evidence)[0],
           hashlib.sha256(b"hello").hexdigest())
    # A member that has the delivery's own name wins over the delivery.
    same = zipped({"metadata-day-05-evidence.zip": b"inner"})
    q = question("sha256", "metadata-day-05-evidence.zip", "file")
    expect("a member named like the delivery", ask_prepared(q, same)[0], hashlib.sha256(b"inner").hexdigest())
    check("a question that names the delivery itself is about the delivery, not the file inside it", not bad, "; ".join(bad))

    bad = []
    twins = {"thumb-001.jpg": jpeg(10, 20), "camera-001.jpg": jpeg(30, 40)}
    for order in (twins, dict(reversed(list(twins.items())))):
        got, err, _ = ask("jpeg.sof_dimensions_pixels", "camera-009.jpg", None, "jpeg", item="001", members=order)
        expect(f"two pictures carry 001 and neither is named ({list(order)[0]} first)",
               (got, "both fit the question" in err), (None, True))
        expect(f"the same two with one of them named ({list(order)[0]} first)",
               ask("jpeg.sof_dimensions_pixels", "camera-001.jpg", None, "jpeg", item="001", members=order)[0], "30x40")
    copies = {"a/camera-001.jpg": jpeg(30, 40), "b/camera-001.jpg": jpeg(30, 40)}
    expect("two identical copies under one name are one file",
           ask("jpeg.sof_dimensions_pixels", "camera-001.jpg", None, "jpeg", item="001", members=copies)[0], "30x40")
    check("when two members fit the question and neither is named, no file is chosen", not bad, "; ".join(bad))


# ------------------------------------------------------------------ 12. ids of the Day 1 form

def test_stem_guard():
    file_md5, thumb_md5 = hashlib.md5(J).hexdigest(), hashlib.md5(THUMB).hexdigest()
    bad = []
    cases = [  # (answer id, text, file, bytes, expected first value or None, plain?)
        ("camera-thumbnail-md5", "What is the value?", "camera.jpg", J, None, False),
        ("camera-pixel-size-bytes", "What is the value?", "camera.jpg", J, None, False),
        ("camera-original-filename", "What is the value?", "camera.jpg", J, None, False),
        ("camera-jpeg-thumbnail-md5", "What is the value?", "camera.jpg", J, thumb_md5, False),
        # the id belongs to another variant's file: a namespace word still starts the property
        ("photo-exif-thumbnail-md5", "What is the value?", "IMG_001.jpg", J, thumb_md5, False),
        # the text asks the short name while the id carries the full one
        ("camera-exif-thumbnail-md5", "Determine md5 for camera.jpg.", "camera.jpg", J, thumb_md5, False),
        # the forms that were judged on Days 1 to 3 stay plain
        ("camera-md5", "What is its MD5 digest?", "camera.jpg", J, file_md5, True),
        ("evidence-note-copy-md5", "What is its MD5 digest?", "evidence-note-copy.txt", b"note", hashlib.md5(b"note").hexdigest(), True),
        ("evidence-note-copy-filename", "What is the exact filename?", "evidence-note-copy.txt", b"note", "evidence-note-copy.txt", True),
        ("roster-magic-prefix-hex-16", "What are the first sixteen bytes?", "roster.csv", b"id,name\n1,ann\n2,bo\n", b"id,name\n1,ann\n2,".hex(), True),
        ("roster-text-utf8-bom-present", "Determine text.utf8_bom_present for roster.csv.", "roster.csv", UTF8_BOM, "true", True),
        ("file-header-sha256", "What is its SHA-256 digest?", "file-header.bin", b"\x00\x01", hashlib.sha256(b"\x00\x01").hexdigest(), True),
        # the namespaces added on Day 6 are not looked for in such an id: it answers as it did before them
        ("tool-pe-sha256", "What is its SHA-256 digest?", "sample-002.bin", b"\x00\x01", hashlib.sha256(b"\x00\x01").hexdigest(), True),
        ("clip-wav-md5", "Determine md5 for sample-002.bin.", "sample-002.bin", b"note", hashlib.md5(b"note").hexdigest(), True),
        ("notes-gzip-filename", "What is the exact filename?", "sample-002.bin", b"note", "sample-002.bin", True),
        ("track-mp3-size-bytes", "What is the size in bytes?", "sample-002.bin", b"note", "4", True),
        # while one of Days 1 to 5 still starts the property
        ("tool-png-sha256", "What is its SHA-256 digest?", "sample-002.bin", b"\x00\x01", None, False),
    ]
    for qid, text, fname, data, want, plain in cases:
        got, _, _ = ask("-", fname, data, "-", qid=qid, text=text)
        if values_of(got)[:1] != ([want] if want else []) or is_plain(got) != plain:
            bad.append(f"{qid} about {fname}: {got!r}")
        if file_md5 in values_of(got) and qid != "camera-md5":
            bad.append(f"{qid}: the file's own digest was offered")
    check("an id of the Day 1 form names its property after the file's stem: thumbnail-md5 is not md5", not bad, "; ".join(bad))

    q = {"id": "camera-thumbnail-md5", "question": "What is the value?", "artifact": "evidence.zip -> camera.jpg"}
    ok = {"id": "roster-md5", "question": "What is its MD5 digest?", "artifact": "evidence.zip -> roster.csv"}
    first = {"id": "evidence-note-filename", "question": "What is the exact filename of the first evidence note?", "artifact": "evidence.zip"}
    problems = solver.covers([q, ok, first])
    check("covers() reads such an id the same way, from the file the artifact names",
          len(problems) == 1 and "thumbnail_md5 is not registered" in problems[0], "; ".join(problems))


# ------------------------------------------------------------------ 13. facts the bytes leave ambiguous

def test_ambiguous_facts():
    bad = []

    def expect(label, got, want):
        if got != want:
            bad.append(f"{label}: {got!r}, expected {want!r}")

    top_down, _, _ = ask("bmp.dib_dimensions_pixels", "shot-001.bmp", bmp(64, -48), "bmp")
    expect("a top-down BMP offers the magnitude and the stored height, unsure",
           (is_plain(top_down), values_of(top_down)), (False, ["64x48", "64x-48"]))
    expect("the same through image.dimensions_pixels",
           values_of(ask("image.dimensions_pixels", "shot-001.bmp", bmp(64, -48), "image")[0]), ["64x48", "64x-48"])
    expect("a bottom-up BMP is plain", ask("bmp.dib_dimensions_pixels", "shot-001.bmp", bmp(64, 48), "bmp")[0], "64x48")

    plain_jfif = jpeg(40, 30, jfif=True)  # its JFIF header states a 0 by 0 thumbnail, as most do
    at = plain_jfif.index(b"JFIF\x00") + 12
    with_thumb = plain_jfif[:at] + bytes([16, 8]) + plain_jfif[at + 2:]
    zero, _, _ = ask("jpeg.jfif_thumbnail_dimensions_pixels", "camera-001.jpg", plain_jfif, "jpeg")
    expect("a JFIF header that states 0 by 0 is unsure between none and 0x0",
           (is_plain(zero), values_of(zero)), (False, ["none", "0x0"]))
    expect("a JFIF header that states 16 by 8 is plain",
           ask("jpeg.jfif_thumbnail_dimensions_pixels", "camera-001.jpg", with_thumb, "jpeg")[0], "16x8")
    no_jfif, _, _ = ask("jpeg.jfif_thumbnail_dimensions_pixels", "camera-001.jpg", jpeg(40, 30), "jpeg")
    expect("no JFIF header at all in a JPEG: none, unsure until the judge has accepted it",
           (is_plain(no_jfif), values_of(no_jfif)), (False, ["none"]))

    def exif_thumb(ifd1_size):
        extra = [(0x0100, 4, 1, ifd1_size[0]), (0x0101, 4, 1, ifd1_size[1])] if ifd1_size else []
        block, _ = tiff_block([(0x0112, 3, 1, 6)], ifd1=extra + [(0x0103, 3, 1, 6)], thumb=jpeg(160, 120))
        return jpeg(257, 146, exif=block)

    got, err, _ = ask("jpeg.exif_thumbnail_dimensions_pixels", "camera-001.jpg", exif_thumb((80, 60)), "jpeg")
    expect("IFD1 states 80x60 and the embedded thumbnail's SOF 160x120", (got, "NOT ESTABLISHED" in err), (None, True))
    expect("the same through jpeg.thumbnail_dimensions_pixels",
           ask("jpeg.thumbnail_dimensions_pixels", "camera-001.jpg", exif_thumb((80, 60)), "jpeg")[0], None)
    expect("IFD1 and the SOF agree",
           ask("jpeg.exif_thumbnail_dimensions_pixels", "camera-001.jpg", exif_thumb((160, 120)), "jpeg")[0], "160x120")
    expect("IFD1 states no size",
           ask("jpeg.exif_thumbnail_dimensions_pixels", "camera-001.jpg", exif_thumb(None), "jpeg")[0], "160x120")

    # FF FE 00 00 is the UTF-32LE BOM and starts with the UTF-16LE one: 'present' has two readings there.
    utf32 = "\ufeffhi".encode("utf-32-le")
    for prop in ("text.utf16le_bom_present", "text.utf16_bom_present"):
        got, _, _ = ask(prop, "export-001.txt", utf32, "text", fmt=TRUE_FALSE)
        expect(f"{prop} in a UTF-32LE file", (is_plain(got), values_of(got)), (False, ["false", "true"]))
    for prop, data, want in [("text.utf32le_bom_present", utf32, "true"), ("text.utf8_bom_present", utf32, "false"),
                             ("text.bom_present", utf32, "true"), ("text.utf16le_bom_present", UTF16, "true"),
                             ("text.utf16_bom_present", UTF16, "true"), ("text.utf16le_bom_present", UTF8_BOM, "false"),
                             ("text.utf16be_bom_present", "\ufeffhi".encode("utf-16-be"), "true")]:
        expect(f"{prop} where the BOM has one reading", ask(prop, "export-001.txt", data, "text", fmt=TRUE_FALSE)[0], want)
    check("a fact the bytes leave ambiguous is unsure or None, never plain", not bad, "; ".join(bad))

    # Document fields: `none` is offered only when the field is absent, not when it is written in
    # a form the reader does not decode, and the value is the text, not its escaped spelling.
    bad = []
    base_pdf = pdf()
    for label, data, prop, want in [
            ("a literal string", base_pdf, "pdf.info_author", ["J. Hammond"]),
            ("an absent Info entry", base_pdf, "pdf.info_subject", ["none"]),
            # Day 14 look-ahead (9): a hex string is read (LibreOffice writes every Info string so); two that differ are not
            ("a hex string", base_pdf.replace(b"/Author (J. Hammond)", b"/Author <4A2E>"), "pdf.info_author", ["J."]),
            ("a hex string in UTF-16BE", base_pdf.replace(b"/Author (J. Hammond)", b"/Author <FEFF004A006F>"), "pdf.info_author", ["Jo"]),
            ("a hex string that is no text", base_pdf.replace(b"/Author (J. Hammond)", b"/Author <0102>"), "pdf.info_author", []),
            ("an indirect reference", base_pdf.replace(b"/Author (J. Hammond)", b"/Author 9 0 R"), "pdf.info_author", []),
            ("an octal escape", base_pdf.replace(b"/Author (J. Hammond)", b"/Author (J\\056 Hammond)"), "pdf.info_author", []),
            ("an escaped parenthesis", base_pdf.replace(b"/Author (J. Hammond)", b"/Author (J. \\(Jo\\) Hammond)"),
             "pdf.info_author", ["J. (Jo) Hammond"]),
            ("a UTF-16BE text string", base_pdf.replace(b"/Author (J. Hammond)", b"/Author (\xfe\xff\x00J\x00o)"),
             "pdf.info_author", ["Jo"]),
            ("object streams, the entry not in sight", base_pdf + b"5 0 obj\n<< /Type /ObjStm >>\nendobj\n", "pdf.info_subject", [])]:
        got, _, _ = ask(prop, "report-001.pdf", data, "pdf")
        if values_of(got)[:1] != want or is_plain(got):
            bad.append(f"{label}: {got!r}, expected first option {want}")
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(DOCX)) as zin, zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            body = zin.read(info)
            if info.filename == "docProps/core.xml":
                body = body.replace(b"<dc:title>Incident Summary</dc:title>", b"<dc:title>R&amp;D &lt;draft&gt;</dc:title>")
                body = body.replace(b"<dc:creator>alice.w</dc:creator>", b"<dc:creator><![CDATA[alice.w]]></dc:creator>")
            zout.writestr(info.filename, body)
    amp = buf.getvalue()
    title, _, _ = ask("docx.core_title", "memo-001.docx", amp, "docx")
    creator, _, _ = ask("office.core_creator", "memo-001.docx", amp, "office")
    if values_of(title)[:1] != ["R&D <draft>"] or creator is not None:
        bad.append(f"core.xml: title {title!r}, creator in CDATA {creator!r}")
    check("a document field written in a form that is not decoded is None, never `none`; XML entities are decoded",
          not bad, "; ".join(bad))


# ------------------------------------------------------------------ 14. covers() and hostile questions

def test_hostile_questions():
    import time
    odd = [{"id": "x", "question": 5}, {"id": 7, "question": "Determine a for b."}, {"question": None}, {},
           {"id": "d05-jpeg-001-", "question": ""}, {"id": ["x"], "question": ["y"], "answer_format": "text"},
           "not a dict", None, {"id": "d05-jpeg-001-sha256", "artifact": 9, "member": 3, "answer_format": {"kind": 4}}]
    try:
        got = solver.covers(odd[:-1])
        raised = ""
    except Exception as e:
        got, raised = [], f"{type(e).__name__}: {e}"
    # The last one is a readable question about a registered property: odd fields around it do not make it a problem.
    try:
        last = solver.covers(odd[-1:])
    except Exception as e:
        last, raised = ["raised"], f"{type(e).__name__}: {e}"
    check("covers() never raises: a question it cannot read is one problem",
          not raised and len(got) == len(odd) - 1 and last == [], raised or f"{len(got)} problems for {len(odd) - 1} unreadable questions")

    misfit = solver.covers([question("jpeg.sof_dimensions_pixels", "camera-001.jpg", "jpeg", fmt=TRUE_FALSE),
                            question("text.utf8_bom_present", "export-001.txt", "text", fmt={"kind": "enum", "accepted_values": ["yes", "no"]}),
                            question("png.ihdr_dimensions_pixels", "scan-001.png", "png", fmt={"kind": "integer"})])
    fits = solver.covers([question("text.utf8_bom_present", "export-001.txt", "text", fmt=TRUE_FALSE),
                          question("file.size_bytes", "export-001.txt", "file", fmt={"kind": "integer"}),
                          question("sha256", "export-001.txt", "file", fmt={"kind": "pattern", "syntax": "64 hex"}),
                          question("jpeg.sof_dimensions_pixels", "camera-001.jpg", "jpeg", fmt={"kind": "enum", "accepted_values": ["none", "small"]})])
    check("covers() reports a property whose class cannot fit the answer format, before a clock is spent on it",
          len(misfit) == 3 and all("answers as" in m for m in misfit) and fits == [],
          "; ".join(misfit + fits))

    # 'Determine X for F.' is matched lazily up to `\s*$`: on a long run of spaces that took time
    # cubic in its length (19 s for 2000). The text is cut and its white space collapsed first.
    hostile = [{"id": "x", "question": "Determine a for " + " " * 20000 + "x" + " " * 20000 + "y\n."},
               {"id": "x", "question": ("Determine a for " + "\n" * 300) * 200},
               {"id": "x", "question": "Determine a for b" * 50000}]
    start = time.monotonic()
    for q in hostile:
        solver.resolve(q)
        solver.covers([q])
    took = time.monotonic() - start
    spaced = solver.resolve({"id": "x", "question": "  Determine   exif.make \t for   camera-001.jpg.  \n"})
    check("a hostile question text is read in well under a second, and spacing does not change what is read",
          took < 1.0 and spaced[:2] == ("exif_make", "camera-001.jpg"), f"{took:.3f} s; spaced {spaced[:2]}")


# ------------------------------------------------------------------ 19. an unregistered name read as a registered one

def eocd_total(data: bytes, total: int, disk=None) -> bytes:
    """The zip with another entry total in its end-of-central-directory record (and the entries
    on this disk, the same unless `disk` says otherwise)."""
    at = data.rfind(b"PK\x05\x06")
    return data[:at + 8] + struct.pack("<HH", total if disk is None else disk, total) + data[at + 12:]


def test_synonyms():
    # Day 7's own name has its format in the seed; a name of the same words that no day has asked
    # is what the fallback meets on the morning.
    key = "metadata.format/zip.eocd_total_entry_count"
    ZIP3 = eocd_total(ZIP, 3, disk=2)  # the record says 3, the central directory (and this disk) holds 2
    got, err, q = ask("zip.eocd_total_entry_count", "bundle-001.zip", ZIP, "zip")
    parsed = labels.parse(got) if got else None
    check("a synonym (entries, total) is read by the one reader with its words, unsure under the asked name, "
          "and its tie with readers that agree on the file is in the name",
          parsed is not None and parsed.key == key
          and parsed.options == [("integer+same:zip.entry_count,zip.eocd_disk_entries,zip.file_count", "2")]
          and "SYNONYM zip.eocd_total_entry_count" in err and "read as zip.eocd_entry_count" in err
          and len(solver.covers([q])) == 1 and "read as zip.eocd_entry_count" in solver.covers([q])[0],
          f"{got!r}; covers: {solver.covers([q])}")
    alone, _, _ = ask("zip.eocd_total_entry_count", "bundle-001.zip", ZIP3, "zip")
    check("where no other reader gives its value, the option is the bare format name",
          labels.parse(alone) is not None and labels.parse(alone).options == [("integer", "3")], f"{alone!r}")
    unit, _, _ = ask("zip.comment_length", "bundle-001.zip", ZIP, "zip")
    check("a unit is no word: zip.comment_length is read as zip.comment_length_bytes, unsure",
          values_of(unit) == ["16"] and not is_plain(unit), f"{unit!r}")

    os.environ["CTF_WORKDIR"] = str(TMP / "synonym-tied")
    try:
        labels.learn(key, "integer+same:zip.entry_count,zip.file_count", "accepted", attempt_id="selftest",
                     answer_ids=[q["id"]])
        tied, _, _ = ask("zip.eocd_total_entry_count", "bundle-001.zip", ZIP, "zip")
        apart, _, _ = ask("zip.eocd_total_entry_count", "bundle-001.zip", ZIP3, "zip")
        open_tied = solver.covers([q])
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    check("a tie name accepted on the base is plain where those readers still agree, and the question is covered",
          tied == "2" and open_tied == [], f"{tied!r}; covers: {open_tied}")
    check("it is not plain on a file where they part: the verdict never said which of them the judge reads",
          apart is not None and not is_plain(apart) and values_of(apart) == ["3"], f"{apart!r}")

    os.environ["CTF_WORKDIR"] = str(TMP / "synonym-bare")
    try:
        labels.learn(key, "integer", "accepted", attempt_id="selftest", answer_ids=[q["id"]])
        bare_apart, _, _ = ask("zip.eocd_total_entry_count", "bundle-001.zip", ZIP3, "zip")
        bare_tied, _, _ = ask("zip.eocd_total_entry_count", "bundle-001.zip", ZIP, "zip")
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    check("a bare format name accepted (no reader agreed, or a day patch named the reader) is plain on every file",
          bare_apart == "3" and bare_tied == "2", f"{bare_apart!r}, {bare_tied!r}")

    two, err_two, q_two = ask("tiff.width_image", "scan-001.tif", TIFF, "tiff")
    check("ambiguous: two readers with the same words give no answer, and the question stays open",
          two is None and "NO SYNONYM" in err_two and "2 readers have its words" in err_two
          and len(solver.covers([q_two])) == 1, f"{two!r}; {err_two.strip().splitlines()[-1:]}")
    misses = {}
    for prop in ("zip.eocd_volume_entries", "zip.uncompressed_size", "zip.total_entries_on_disk"):
        a, e, _ = ask(prop, "bundle-001.zip", ZIP, "zip")
        if a is not None or "NO SYNONYM" not in e:
            misses[prop] = a
    check("no match: a word no reader has, or a reader with a word the name lacks, gives no answer",
          not misses, f"{misses}")

    patched = patched_copy("synonym-patch", 'def answer(q, files, ctx):\n'
                           '    return "9" if "zip.eocd_total_entry_count" in (q.get("question") or "") else None\n'
                           'def handles(q):\n    return "zip.eocd_total_entry_count" in (q.get("question") or "")\n')
    over, err_over, q_over = ask("zip.eocd_total_entry_count", "bundle-001.zip", ZIP, "zip", module=patched)
    check("a day_patch.py still overrides the synonym's unsure answer and vouches for the question",
          over == "9" and "answered by day_patch.py" in err_over and patched.covers([q_over]) == [], f"{over!r}")
    shipped = HERE / "day_patch.py"
    if shipped.is_file():
        copy = patched_copy("synonym-shipped-patch", shipped.read_text())
        mine, err_mine, _ = ask("zip.eocd_total_entries", "bundle-001.zip", ZIP3, "zip", module=copy)
        check("the shipped day_patch.py still answers (its accepted bare format makes the synonym plain, or it answers)",
              mine == "3" or (values_of(mine) == ["3"] and "answered by day_patch.py" in err_mine), f"{mine!r}")


# ------------------------------------------------------------------ 20. the reader pack: file types no day has asked

def tar_of(fmt=tarfile.USTAR_FORMAT, names=("room-0/item.txt", "room-1/item.txt", "room-2/big.bin"), folder=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as t:
        if folder:
            ti = tarfile.TarInfo("room-0")
            ti.type, ti.mode, ti.mtime = tarfile.DIRTYPE, 0o755, 1790755200
            t.addfile(ti)
        for i, name in enumerate(names):
            body = b"x" * (700 if i == 2 else 5 + i)
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = len(body), 0o640, 1790755200 + i, 1000, 50, "analyst", "staff"
            t.addfile(ti, io.BytesIO(body))
    return buf.getvalue()


def sqlite_db():
    path = TMP / "store.sqlite"
    con = sqlite3.connect(str(path))
    con.execute("PRAGMA page_size=4096")
    con.execute("PRAGMA user_version=7")
    con.execute("CREATE TABLE t(a, b)")
    con.executemany("INSERT INTO t VALUES (?, ?)", [(i, "x" * 50) for i in range(200)])
    con.commit()
    con.close()
    data = path.read_bytes()
    path.unlink()
    return data


def pcap_of(endian="<", packets=2, nano=False):
    head = struct.pack(endian + "IHHiIII", 0xA1B23C4D if nano else 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pkt = bytes(range(60))
    return head + (struct.pack(endian + "IIII", 1790755200, 5, len(pkt), len(pkt)) + pkt) * packets


def pcapng_of(packets=3):
    def block(btype, body):
        body += bytes(-len(body) % 4)
        return struct.pack("<II", btype, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))
    epb = block(6, struct.pack("<IIIII", 0, 0, 0, 60, 60) + bytes(60))
    return (block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + block(1, struct.pack("<HHI", 1, 0, 262144))
            + epb * packets)


LNK_TIMES = (133410000000000000, 133410000010000000, 133410000020000000)  # 2023-10-05T17:20:00Z, then one and two seconds on


def lnk_of(times=LNK_TIMES):
    flags = 0x2 | 0x10 | 0x20 | 0x80  # HasLinkInfo, HasWorkingDir, HasArguments, IsUnicode
    head = struct.pack("<I16sIIQQQIiIH", 0x4C, bytes.fromhex("0114020000000000c000000000000046"), flags, 0x20, *times,
                       12345, 0, 1, 0) + bytes(10)
    volume = struct.pack("<IIII", 17, 3, 0x1234ABCD, 16) + b"\x00"
    base, suffix = b"C:\\Tools\\probe.exe\x00", b"\x00"
    info = struct.pack("<IIIIIII", 0x1C + len(volume) + len(base) + len(suffix), 0x1C, 1, 0x1C, 0x1C + len(volume), 0,
                       0x1C + len(volume) + len(base)) + volume + base + suffix

    def string(text):
        return struct.pack("<H", len(text)) + text.encode("utf-16-le")
    return head + info + string("C:\\Tools") + string("-q --scan")


def cfb_of():
    head = bytearray(512)
    head[:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<HHHHH", head, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<9I", head, 40, 0, 1, 1, 0, 4096, 0xFFFFFFFE, 0, 0xFFFFFFFE, 0)
    struct.pack_into("<109I", head, 76, 0, *[0xFFFFFFFF] * 108)
    fat = struct.pack("<128I", 0xFFFFFFFD, 0xFFFFFFFE, *[0xFFFFFFFF] * 126)

    def entry(name, kind):
        raw = (name + "\x00").encode("utf-16-le")
        e = bytearray(128)
        e[:len(raw)] = raw
        struct.pack_into("<HBB", e, 64, len(raw), kind, 1)
        struct.pack_into("<III", e, 68, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
        struct.pack_into("<IQ", e, 116, 0xFFFFFFFE, 0)
        return bytes(e)
    return bytes(head) + fat + entry("Root Entry", 5) + entry("Data", 2) + entry("Sub", 1) + bytes(128)


def evtx_of(records=2):
    head = bytearray(4096)
    head[:8] = b"ElfFile\x00"
    struct.pack_into("<QQQIHHHH", head, 8, 0, 0, records + 1, 128, 1, 3, 4096, 1)
    chunk = bytearray(65536)
    chunk[:8] = b"ElfChnk\x00"
    struct.pack_into("<QQQQ", chunk, 8, 1, records, 1, records)
    rec = b"\x2a\x2a\x00\x00" + struct.pack("<IQQ", 32, 1, LNK_TIMES[0]) + bytes(4) + struct.pack("<I", 32)
    chunk[512:512 + 32 * records] = rec * records
    struct.pack_into("<I", chunk, 48, 512 + 32 * records)
    return bytes(head) + bytes(chunk)


def regf_of():
    b = bytearray(4096)
    b[:4] = b"regf"
    struct.pack_into("<IIQIIIIIII", b, 4, 7, 7, LNK_TIMES[0], 1, 5, 0, 1, 0x20, 4096, 1)
    b[48:64] = "SOFTWARE".encode("utf-16-le")
    struct.pack_into("<I", b, 508, functools.reduce(lambda a, w: a ^ w, struct.unpack("<127I", b[:508]), 0))
    return bytes(b) + bytes(4096)


def sevenz_of():
    nh = b"\x01\x04\x06\x00\x01\x09\x05\x00"  # a stand-in for the packed header the readers never open
    tail = struct.pack("<QQI", 5, len(nh), zlib.crc32(nh))
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(tail)) + tail + b"PACKD" + nh


def vint(v):
    out = bytearray()
    while True:
        out.append(v & 0x7F | (0x80 if v >> 7 else 0))
        v >>= 7
        if not v:
            return bytes(out)


def rar5_of(files=(b"a.txt", b"b.txt")):
    def block(kind, hflags, fields, data=b""):
        body = vint(kind) + vint(hflags) + (vint(len(data)) if hflags & 2 else b"") + fields
        size = vint(len(body))
        return struct.pack("<I", zlib.crc32(size + body)) + size + body + data
    out = b"Rar!\x1a\x07\x01\x00" + block(1, 0, vint(0x4))  # a solid archive
    for name in files:
        out += block(2, 2, vint(0) + vint(5) + vint(0x20) + vint(0) + vint(0) + vint(len(name)) + name, b"hello")
    return out + block(5, 0, vint(0))


def box(kind, body):
    return struct.pack(">I", 8 + len(body)) + kind + body


def mp4_of():
    mvhd = box(b"mvhd", bytes(4) + struct.pack(">IIII", 3790000000, 3790000100, 1000, 12345) + bytes(80))
    return box(b"ftyp", b"isom" + struct.pack(">I", 512) + b"isomiso2avc1mp41") + box(b"moov", mvhd) + box(b"mdat", bytes(32))


def ico_of(sizes=((16, 16), (32, 32))):
    dib = bytes(40)
    entries = b"".join(struct.pack("<BBBBHHII", w % 256, h % 256, 0, 0, 1, 32, len(dib), 6 + 16 * len(sizes) + i * len(dib))
                       for i, (w, h) in enumerate(sizes))
    return struct.pack("<HHH", 0, 1, len(sizes)) + entries + dib * len(sizes)


def macho_of():
    lc = struct.pack("<II", 0x19, 72) + b"__PAGEZERO".ljust(16, b"\x00") + bytes(48)
    return struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 1, len(lc), 0x200085, 0) + lc


def flac_of(md5=hashlib.md5(b"pcm").digest()):
    packed = 44100 << 44 | (2 - 1) << 41 | (16 - 1) << 36 | 441000
    info = struct.pack(">HH", 4096, 4096) + (16).to_bytes(3, "big") + (14000).to_bytes(3, "big") + packed.to_bytes(8, "big") + md5
    vendor, comments = b"reference libFLAC 1.4.3", [b"TITLE=Evidence Tone", b"ARTIST=The Analysts"]
    vc = (struct.pack("<I", len(vendor)) + vendor + struct.pack("<I", len(comments))
          + b"".join(struct.pack("<I", len(c)) + c for c in comments))
    return (b"fLaC" + b"\x00" + len(info).to_bytes(3, "big") + info + b"\x84" + len(vc).to_bytes(3, "big") + vc
            + b"\xff\xf8" + bytes(16))


def class_of(major=61):
    def utf8(s):
        return b"\x01" + struct.pack(">H", len(s)) + s
    pool = (utf8(b"com/example/Probe") + b"\x07" + struct.pack(">H", 1) + utf8(b"java/lang/Object") + b"\x07"
            + struct.pack(">H", 3) + b"\x05" + bytes(8))  # the long takes two slots: 7 in all
    return b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, major, 7) + pool + struct.pack(">HHH", 0x21, 2, 4) + bytes(8)


def dex_of():
    h = bytearray(128)
    h[:8] = b"dex\n035\x00"
    struct.pack_into("<III", h, 32, len(h), 0x70, 0x12345678)
    struct.pack_into("<I", h, 56, 4)
    struct.pack_into("<I", h, 88, 3)
    struct.pack_into("<I", h, 96, 1)
    h[12:32] = hashlib.sha1(h[32:]).digest()
    struct.pack_into("<I", h, 8, zlib.adler32(bytes(h[12:])))
    return bytes(h)


def prefetch_of(version=23, runs=5, metrics=None):
    b = bytearray(0x200)
    struct.pack_into("<I4sII", b, 0, version, b"SCCA", 0x11, len(b))
    name = "PROBE.EXE".encode("utf-16-le")
    b[16:16 + len(name)] = name
    struct.pack_into("<II", b, 76, 0xDEADBEEF, 0)
    last, count = {17: (0x78, 0x90), 23: (0x80, 0x98), 26: (0x80, 0xD0), 30: (0x80, 0xD0)}[version]
    struct.pack_into("<I", b, 84, metrics or {17: 0x98, 23: 0xF0, 26: 0x134, 30: 0x134}[version])
    struct.pack_into("<Q", b, last, LNK_TIMES[0])
    struct.pack_into("<I", b, count, runs)
    return bytes(b)


def gzip_of(data: bytes) -> bytes:
    return gzip.compress(data, mtime=1790755200)


def zip_comment_of(comment: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"a")
        z.comment = comment
    return buf.getvalue()


def test_reader_pack():
    tarx, sq, cap, capng, lnk, cfb, ev, hive = tar_of(), sqlite_db(), pcap_of(), pcapng_of(), lnk_of(), cfb_of(), evtx_of(), regf_of()
    sz, rar, mp4, ico, mach, flac, cls, dex = sevenz_of(), rar5_of(), mp4_of(), ico_of(), macho_of(), flac_of(), class_of(), dex_of()
    pf, gzx, bzx = prefetch_of(), gz(), bz2.compress(b"evidence\n" * 50, 9)
    xzx = lzma.compress(b"evidence\n" * 50, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64)
    eocd, cd_at = ZIP.rfind(b"PK\x05\x06"), ZIP.find(b"PK\x01\x02")
    version = sqlite3.sqlite_version_info
    cases = [  # (property, file, bytes, the value read from the bytes: the first option)
        ("tar.ustar_magic", "bundle-001.tar", tarx, "ustar"), ("tar.header_version", "bundle-001.tar", tarx, "00"),
        ("tar.entry_count", "bundle-001.tar", tarx, "3"), ("tar.total_entries", "bundle-001.tar", tarx, "3"),
        ("tar.file_count", "bundle-001.tar", tarx, "3"), ("tar.header_mode", "bundle-001.tar", tarx, "0640"),
        ("tar.first_entry_size_bytes", "bundle-001.tar", tarx, "5"), ("tar.header_mtime", "bundle-001.tar", tarx, "1790755200"),
        ("tar.ustar_uname", "bundle-001.tar", tarx, "analyst"), ("tar.header_gid", "bundle-001.tar", tarx, "50"),
        ("tar.first_entry_name", "bundle-001.tar", tarx, "room-0/item.txt"),
        ("tar.ustar_magic", "bundle-001.tar", tar_of(tarfile.GNU_FORMAT), "ustar "),
        ("tar.entry_count", "bundle-001.tar.gz", gzip_of(tarx), "3"), ("tar.entry_count", "bundle-001.tar", tar_of(folder=True), "4"),
        ("sqlite.header_page_size", "store-001.sqlite", sq, "4096"), ("sqlite.page_size", "store-001.sqlite", sq, "4096"),
        ("sqlite.header_text_encoding", "store-001.sqlite", sq, "utf-8"), ("sqlite.header_user_version", "store-001.sqlite", sq, "7"),
        ("sqlite.header_schema_format", "store-001.sqlite", sq, "4"),
        ("sqlite.header_page_count", "store-001.sqlite", sq, str(len(sq) // 4096)),
        ("sqlite.header_sqlite_version_number", "store-001.sqlite", sq, str(version[0] * 1000000 + version[1] * 1000 + version[2])),
        ("pcap.header_linktype", "capture-001.pcap", cap, "LINKTYPE_ETHERNET"),
        ("pcap.global_header_snaplen", "capture-001.pcap", cap, "65535"),
        ("pcap.header_version", "capture-001.pcap", cap, "2.4"), ("pcap.packet_count", "capture-001.pcap", cap, "2"),
        ("pcap.packet_count", "capture-001.pcap", pcap_of(">", 3), "3"), ("pcap.byte_order", "capture-001.pcap", pcap_of(">"), "big"),
        ("pcap.timestamp_resolution", "capture-001.pcap", pcap_of(nano=True), "nanosecond"),
        ("pcapng.shb_version", "capture-001.pcapng", capng, "1.0"),
        ("pcapng.idb_linktype", "capture-001.pcapng", capng, "LINKTYPE_ETHERNET"),
        ("pcapng.idb_snaplen", "capture-001.pcapng", capng, "262144"), ("pcapng.packet_count", "capture-001.pcapng", capng, "3"),
        ("pcapng.interface_count", "capture-001.pcapng", capng, "1"),
        ("lnk.header_link_flags", "shortcut-001.lnk", lnk, "0xb2"), ("lnk.header_file_attributes", "shortcut-001.lnk", lnk, "0x20"),
        ("lnk.header_file_size", "shortcut-001.lnk", lnk, "12345"), ("lnk.target_file_size", "shortcut-001.lnk", lnk, "12345"),
        ("lnk.header_creation_time", "shortcut-001.lnk", lnk, str(LNK_TIMES[0])),
        ("lnk.write_time", "shortcut-001.lnk", lnk, str(LNK_TIMES[2])),
        ("lnk.show_command", "shortcut-001.lnk", lnk, "SW_SHOWNORMAL"),
        ("lnk.target_path", "shortcut-001.lnk", lnk, "C:\\Tools\\probe.exe"),
        ("lnk.working_directory", "shortcut-001.lnk", lnk, "C:\\Tools"), ("lnk.arguments", "shortcut-001.lnk", lnk, "-q --scan"),
        ("lnk.relative_path", "shortcut-001.lnk", lnk, "none"),
        ("ole.header_sector_size", "report-001.doc", cfb, "512"), ("cfb.mini_sector_size", "report-001.doc", cfb, "64"),
        ("ole.header_major_version", "report-001.doc", cfb, "3"), ("ole.header_minor_version", "report-001.doc", cfb, "62"),
        ("ole.stream_count", "report-001.doc", cfb, "1"), ("ole.root_entry_name", "report-001.doc", cfb, "Root Entry"),
        ("ole.stream_names", "report-001.doc", cfb, "Data"), ("ole.header_mini_stream_cutoff", "report-001.doc", cfb, "4096"),
        ("evtx.header_version", "security-001.evtx", ev, "3.1"), ("evtx.header_chunk_count", "security-001.evtx", ev, "1"),
        ("evtx.chunk_count", "security-001.evtx", ev, "1"), ("evtx.record_count", "security-001.evtx", ev, "2"),
        ("evtx.header_next_record_id", "security-001.evtx", ev, "3"), ("evtx.header_flags", "security-001.evtx", ev, "0x0"),
        ("regf.base_block_major_version", "software-001.hve", hive, "1"), ("regf.header_version", "software-001.hve", hive, "1.5"),
        ("regf.root_cell_offset", "software-001.hve", hive, "0x20"),
        ("regf.last_written", "software-001.hve", hive, str(LNK_TIMES[0])),
        ("regf.checksum_valid", "software-001.hve", hive, "true"), ("regf.file_name", "software-001.hve", hive, "SOFTWARE"),
        ("7z.signature_header_version", "bundle-001.7z", sz, "0.4"), ("7z.next_header_size", "bundle-001.7z", sz, "8"),
        ("7z.next_header_offset", "bundle-001.7z", sz, "5"), ("7z.start_header_crc_valid", "bundle-001.7z", sz, "true"),
        ("rar.version", "bundle-001.rar", rar, "5"), ("rar.file_count", "bundle-001.rar", rar, "2"),
        ("rar.solid", "bundle-001.rar", rar, "true"), ("rar.version", "bundle-001.rar", b"Rar!\x1a\x07\x00" + bytes(20), "4"),
        ("bz2.header_block_size", "notes-001.txt.bz2", bzx, "900000"), ("bz2.compression_level", "notes-001.txt.bz2", bzx, "9"),
        ("bz2.uncompressed_size_bytes", "notes-001.txt.bz2", bzx, "450"),
        ("xz.stream_header_check_type", "notes-001.txt.xz", xzx, "CRC64"), ("xz.check_type", "notes-001.txt.xz", xzx, "CRC64"),
        ("xz.uncompressed_size_bytes", "notes-001.txt.xz", xzx, "450"),
        ("gzip.header_flags", "notes-001.txt.gz", gzx, "0x8"), ("gzip.xfl", "notes-001.txt.gz", gzx, "0"),
        ("gzip.compression_method", "notes-001.txt.gz", gzx, "8"), ("gzip.extra_field_length", "notes-001.txt.gz", gzx, "none"),
        ("gzip.member_count", "notes-001.txt.gz", gzx + gz(name=b"second.txt"), "2"),
        ("gzip.member_count", "notes-001.txt.gz", gzx, "1"),
        ("mp4.ftyp_major_brand", "clip-001.mp4", mp4, "isom"), ("mp4.ftyp_minor_version", "clip-001.mp4", mp4, "512"),
        ("mp4.ftyp_compatible_brands", "clip-001.mp4", mp4, "isom,iso2,avc1,mp41"),
        ("mp4.box_types", "clip-001.mp4", mp4, "ftyp,moov,mdat"),
        ("mp4.mvhd_timescale", "clip-001.mp4", mp4, "1000"), ("mp4.mvhd_duration", "clip-001.mp4", mp4, "12345"),
        ("mp4.mvhd_creation_time", "clip-001.mp4", mp4, "3790000000"),
        ("mp4.ftyp_major_brand", "clip-001.mp4", mp4[:60], "isom"),  # a file cut after its ftyp box
        ("ico.image_count", "app-001.ico", ico, "2"), ("ico.first_entry_dimensions_pixels", "app-001.ico", ico, "16x16"),
        ("ico.largest_image_dimensions_pixels", "app-001.ico", ico, "32x32"),
        ("ico.entry_dimensions", "app-001.ico", ico, "16x16,32x32"),
        ("ico.dimensions_pixels", "app-001.ico", ico_of(((256, 256),)), "256x256"), ("ico.type", "app-001.ico", ico, "ICON"),
        ("macho.header_cputype", "tool-001.macho", mach, "CPU_TYPE_X86_64"),
        ("macho.filetype", "tool-001.macho", mach, "MH_EXECUTE"),
        ("macho.header_ncmds", "tool-001.macho", mach, "1"), ("macho.sizeofcmds", "tool-001.macho", mach, "72"),
        ("macho.header_flags", "tool-001.macho", mach, "0x200085"),
        ("flac.streaminfo_sample_rate", "tone-001.flac", flac, "44100"), ("flac.sample_rate_hz", "tone-001.flac", flac, "44100"),
        ("flac.channels", "tone-001.flac", flac, "2"), ("flac.streaminfo_bits_per_sample", "tone-001.flac", flac, "16"),
        ("flac.total_samples", "tone-001.flac", flac, "441000"),
        ("flac.streaminfo_md5", "tone-001.flac", flac, hashlib.md5(b"pcm").hexdigest()),
        ("flac.vorbis_title", "tone-001.flac", flac, "Evidence Tone"),
        ("flac.vorbis_vendor", "tone-001.flac", flac, "reference libFLAC 1.4.3"),
        ("flac.metadata_block_types", "tone-001.flac", flac, "STREAMINFO,VORBIS_COMMENT"),
        ("flac.vorbis_album", "tone-001.flac", flac, "none"),
        ("class.major_version", "Probe-001.class", cls, "61"), ("class.minor_version", "Probe-001.class", cls, "0"),
        ("class.version", "Probe-001.class", cls, "61.0"), ("class.constant_pool_count", "Probe-001.class", cls, "7"),
        ("class.this_class", "Probe-001.class", cls, "com/example/Probe"),
        ("class.super_class", "Probe-001.class", cls, "java/lang/Object"),
        ("class.java_version", "Probe-001.class", cls, "17"), ("class.access_flags", "Probe-001.class", cls, "0x21"),
        ("dex.version", "classes-001.dex", dex, "035"), ("dex.header_checksum_valid", "classes-001.dex", dex, "true"),
        ("dex.method_ids_size", "classes-001.dex", dex, "3"), ("dex.class_count", "classes-001.dex", dex, "1"),
        ("dex.header_file_size", "classes-001.dex", dex, "128"),
        ("prefetch.header_version", "PROBE.EXE-001.pf", pf, "23"), ("prefetch.run_count", "PROBE.EXE-001.pf", pf, "5"),
        ("prefetch.executable_name", "PROBE.EXE-001.pf", pf, "PROBE.EXE"),
        ("prefetch.prefetch_hash", "PROBE.EXE-001.pf", pf, "0xdeadbeef"),
        ("prefetch.last_run_time", "PROBE.EXE-001.pf", pf, str(LNK_TIMES[0])),
        ("prefetch.run_count", "PROBE.EXE-001.pf", prefetch_of(17, 2), "2"),
        ("prefetch.run_count", "PROBE.EXE-001.pf", prefetch_of(30, 9), "9"),
        ("zip.eocd_disk_number", "bundle-001.zip", ZIP, "0"), ("zip.eocd_disk_entries", "bundle-001.zip", ZIP, "2"),
        ("zip.eocd_cd_offset", "bundle-001.zip", ZIP, str(cd_at)),
        ("zip.eocd_cd_size_bytes", "bundle-001.zip", ZIP, str(eocd - cd_at)), ("zip.eocd_offset", "bundle-001.zip", ZIP, str(eocd)),
        # a file of another type: the unsure `none`, never another type's value
        ("sqlite.header_page_size", "scan-001.png", PNG, "none"), ("tar.entry_count", "scan-001.png", PNG, "none"),
        ("macho.header_cputype", "tool-001.elf", elf64(), "none"), ("dex.version", "Probe-001.class", cls, "none"),
    ]
    # Three properties of this block are judged and sit in the tracked seed (promoted from the ledger,
    # challenges/_ledger/metadata.jsonl): under the seed they are plain and covered, every other field of the pack is still
    # unsure, and with those seed entries taken out every field is unsure, as this check first held it.
    #   evtx.record_count         `integer`. Day 24's base (attempt b04a16cf, events-001.evtx, kind integer, '3') and the
    #                             Time Trials and Mastery sets of Days 24 to 26 (30 more EVTX files of 7 to 118 records):
    #                             31 answers accepted, every one the plain decimal count.
    #   prefetch.executable_name  `raw`. Day 26's base (attempt 5f9783e7, trace-001.pf, a MAM version 30 file, kind
    #                             exact_text with this very syntax: 'CMD.EXE'), its Time Trial and its ten Mastery sets
    #                             (plain version 30 files): 12 answers accepted as the name stored in the header.
    #   pcap.packet_count         `integer`. Day 27's base (attempt 19329455, capture-001.pcap, kind integer, '2'):
    #                             accepted. A packet count is a byte-derived fact, so the plain decimal count is
    #                             never-wrong, and the seed was promoted after Day 27 from the ledger.
    # The seed keys a property, not a file version or a question kind: this block builds a version 23 header and asks
    # the count as exact_text (the Day 4 wording, as it asks every property), and the judged rendering is the same text.
    SEED_JUDGED = {"evtx.record_count": "metadata.format/evtx.record_count",
                   "prefetch.executable_name": "metadata.format/prefetch.executable_name",
                   "pcap.packet_count": "metadata.format/pcap.packet_count"}

    def read_cases(judged_plain):
        bad = []
        for prop, fname, data, want in cases:
            got, _, q = ask(prop, fname, data, prop.split(".")[0])
            if judged_plain and prop in SEED_JUDGED:
                if got != want or solver.covers([q]):
                    bad.append(f"{prop} for {fname}: {got!r}, expected the plain {want!r}, covered (judged in the seed)")
            elif is_plain(got) or values_of(got)[:1] != [want] or not solver.covers([q]):
                bad.append(f"{prop} for {fname}: {got!r}, expected first option {want!r}, unsure and not covered")
        return bad

    types = len({c[0].split('.')[0] for c in cases})
    bad = read_cases(True)
    check(f"reader pack: {len(cases)} header fields of {types} file types read from the bytes, every one unsure but "
          f"the two the seed judges (evtx.record_count, prefetch.executable_name: plain and covered)",
          not bad, "; ".join(bad[:6]))
    with seed_without(*SEED_JUDGED.values()):
        bad = read_cases(False)
    check(f"reader pack: {len(cases)} header fields of {types} file types read from the bytes, every one unsure "
          f"(the two judged seed entries taken out)", not bad, "; ".join(bad[:6]))

    offered = (values_of(ask("lnk.header_creation_time", "shortcut-001.lnk", lnk, "lnk")[0])
               + values_of(ask("tar.header_mode", "bundle-001.tar", tarx, "tar")[0])
               + values_of(ask("bz2.block_size", "notes-001.txt.bz2", bzx, "bz2")[0]))
    check("a FILETIME offers the number and its UTC date, a mode its octal forms, a bzip2 level its block size forms",
          offered == [str(LNK_TIMES[0]), "2023-10-05T17:20:00Z", "2023-10-05T17:20:00", "2023-10-05 17:20:00", "1696526400",
                      "0640", "640", "0o640", "416", "900000", "900k", "9"], f"{offered}")

    pax = tar_of(tarfile.PAX_FORMAT, names=("r\u00e4um/item.txt", "room-1/item.txt"))
    bad_sum = bytearray(tarx)
    bad_sum[0] ^= 1
    doubts = [  # (what, property, file, bytes, every value offered)
        ("a pax header before an entry", "tar.entry_count", "bundle-001.tar", pax, ["2", "3"]),
        ("a pax header changes the first entry", "tar.first_entry_name", "bundle-001.tar", pax, []),
        ("a tar with a directory entry", "tar.file_count", "bundle-001.tar", tar_of(folder=True), []),
        ("a tar cut inside an entry", "tar.entry_count", "bundle-001.tar", tarx[:3000], []),
        ("a tar cut between entries", "tar.entry_count", "bundle-001.tar", tarx[:2048], []),
        ("a first header whose checksum fails: not a tar", "tar.entry_count", "bundle-001.tar", bytes(bad_sum), ["none"]),
        ("a SQLite header cut short", "sqlite.header_page_size", "store-001.sqlite", sq[:40], []),
        ("a SQLite file longer than its header says", "sqlite.header_page_count", "store-001.sqlite", sq + bytes(4096),
         [str(len(sq) // 4096), str(len(sq) // 4096 + 1)]),
        ("a pcapng file asked as pcap", "pcap.packet_count", "capture-001.pcap", capng, []),
        ("a pcap file asked as pcapng", "pcapng.packet_count", "capture-001.pcapng", cap, []),
        ("a pcap cut inside a packet", "pcap.packet_count", "capture-001.pcap", cap[:-5], []),
        ("a pcapng block whose lengths disagree", "pcapng.packet_count", "capture-001.pcapng", capng[:-4] + bytes(4), []),
        ("the magic of a little-endian pcap", "pcap.header_magic", "capture-001.pcap", cap, ["0xa1b2c3d4", "d4c3b2a1"]),
        ("a shortcut with no times", "lnk.header_creation_time", "shortcut-001.lnk", lnk_of((0, 0, 0)), ["0", "none"]),
        ("a shortcut cut inside LinkInfo", "lnk.target_path", "shortcut-001.lnk", lnk[:90], []),
        ("a directory with an unused slot", "ole.directory_entry_count", "report-001.doc", cfb, ["3", "4"]),
        ("a directory chain that leaves the file", "ole.stream_count", "report-001.doc", cfb[:1024], []),
        ("a header that says 2 chunks for 1", "evtx.chunk_count", "security-001.evtx",
         ev[:42] + struct.pack("<H", 2) + ev[44:], ["2", "1"]),
        ("an event record cut short", "evtx.record_count", "security-001.evtx",
         ev[:4096 + 512 + 36] + bytes(len(ev) - 4096 - 512 - 36), []),
        ("a RAR 5 header whose CRC fails", "rar.file_count", "bundle-001.rar", rar[:12] + b"\x00" + rar[13:], []),
        ("RAR 4 file headers", "rar.file_count", "bundle-001.rar", b"Rar!\x1a\x07\x00" + bytes(20), []),
        ("a RAR 5 archive cut before its end header", "rar.file_count", "bundle-001.rar", rar[:-8], []),
        ("a box cut after the ftyp box", "mp4.box_types", "clip-001.mp4", mp4[:60], []),
        ("an icon with two images, asked as one", "ico.dimensions_pixels", "app-001.ico", ico, []),
        # Day 20 (row 375): a universal (fat) Mach-O answers cputype from its FIRST architecture, unsure (the
        # first arch's form first), where it was None before; a cut thin header is still no answer, and the
        # per-arch count stays macho.fat_arch_count (next line), not shadowed.
        ("a universal Mach-O's first arch", "macho.header_cputype", "tool-001.macho",
         b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + struct.pack(">IIIII", 0x01000007, 3, 0, 0, 0) + bytes(44),
         ["CPU_TYPE_X86_64", "16777223", "0x1000007"]),
        ("a thin Mach-O header cut before its cputype", "macho.header_cputype", "tool-001.macho", b"\xcf\xfa\xed\xfe" + bytes(4), []),
        ("a class file is not a universal Mach-O", "macho.fat_arch_count", "Probe-001.class", cls, ["none"]),
        ("a STREAMINFO without an MD5", "flac.streaminfo_md5", "tone-001.flac", flac_of(bytes(16)), ["0" * 32, "none"]),
        ("a compressed prefetch file", "prefetch.run_count", "PROBE.EXE-001.pf", b"MAM\x04" + bytes(60), []),
        ("a version 30 layout that is not one of the two known", "prefetch.run_count", "PROBE.EXE-001.pf",
         prefetch_of(30, 9, metrics=0x130), ["9", "0"]),
        ("a Java 8 class", "class.java_version", "Probe-001.class", class_of(52), ["8", "1.8"]),
        ("a big-endian DEX file", "dex.header_file_size", "classes-001.dex", dex[:40] + b"\x12\x34\x56\x78" + dex[44:], []),
        ("two gzip members, the second cut", "gzip.member_count", "notes-001.txt.gz", gzx + gzx[:-6], []),
        ("a zip comment that holds an end record", "zip.eocd_cd_offset", "bundle-001.zip",
         zip_comment_of(b"PK\x05\x06" + bytes(18)), []),
    ]
    wrong = []
    for what, prop, fname, data, want in doubts:
        got, _, _ = ask(prop, fname, data, prop.split(".")[0])
        if is_plain(got) or values_of(got) != want:
            wrong.append(f"{what} ({prop}): {got!r}, expected options {want}")
    check("reader pack: a field the bytes leave open is offered in each reading, a cut or packed one is no answer",
          not wrong, "; ".join(wrong[:6]))

    # The class's own format accepted on a base where the field was clear says nothing about a later
    # variant where the bytes leave it open: the readings of an ambiguous file are named apart.
    held = [  # (property, file, an ambiguous file, a clear file and its value)
        ("tar.entry_count", "bundle-001.tar", pax, tarx, "3"),
        ("sqlite.header_page_count", "store-001.sqlite", sq + bytes(4096), sq, str(len(sq) // 4096)),
        ("ole.directory_entry_count", "report-001.doc", cfb, None, None),
        ("evtx.chunk_count", "security-001.evtx", ev[:42] + struct.pack("<H", 2) + ev[44:], ev, "1"),
        ("flac.streaminfo_md5", "tone-001.flac", flac_of(bytes(16)), flac, hashlib.md5(b"pcm").hexdigest()),
    ]
    leaked = []
    for prop, fname, unclear, clear, want in held:
        p = solver.REG[solver.canon(prop)]
        os.environ["CTF_WORKDIR"] = str(TMP / f"held-{prop}")
        try:
            labels.learn(p.key, solver.FORMATS[p.fmt][0][0], "accepted", attempt_id="selftest", answer_ids=[prop])
            got, _, _ = ask(prop, fname, unclear, prop.split(".")[0])
            plain = ask(prop, fname, clear, prop.split(".")[0])[0] if clear is not None else want
        finally:
            os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
        if got is None or is_plain(got) or plain != want:
            leaked.append(f"{prop}: ambiguous {got!r}, clear {plain!r} (expected plain {want!r})")
    check("an accepted class format makes the clear file plain and leaves the ambiguous one unsure",
          not leaked, "; ".join(leaked))

    groups = {}
    for key, p in solver.REG.items():
        groups.setdefault(solver.words(key), set()).add(p.fn)
    clashes = sorted(f"{h}.{'_'.join(sorted(w))}" for (h, w), fns in groups.items()
                     if len(fns) > 1 and (h in solver.PACK_NAMESPACES or h in ("zip", "gzip")))
    check("row 43 stays exact: in the pack's namespaces, and in zip and gzip, no two readers share their words",
          not clashes, f"{clashes}")
    _, err, _ = ask("sqlite.header_wal_mode", "store-001.sqlite", sq, "sqlite")
    page = "UNKNOWN PROPERTY sqlite.header_wal_mode" in err and "sqlite.header_page_size = 4096" in err
    check("an unregistered SQLite property prints the file's SQLite facts for the agent who writes the reader",
          page, "" if page else err[-300:])
    big = tar_of(names=[f"f{i}.txt" for i in range(2000)])
    start = time.monotonic()
    for _ in range(3):
        ask("tar.entry_count", "bundle-001.tar", big, "tar")
    check("a tar of 2000 entries is counted in well under a second each", time.monotonic() - start < 3.0,
          f"{time.monotonic() - start:.2f} s for three runs")


# ------------------------------------------------------------------ the command line

def test_day21_round2():
    """Rows 401 and 405 (the Day 21 build, round 2): a collection name of a field a reader reads, asked as a JSON
    array, is an unsure one-element array, the padded hex first; a thin Mach-O's fat_architectures is one element."""
    e, _, _ = ask("elf.e_machine_set", "sample-001.bin", elf64(), "elf", day="21", fmt=JSON_ARRAY)
    check("row 401: elf.e_machine_set is unsure, ['0x003e'] first",
          not is_plain(e) and values_of(e)[:1] == ['["0x003e"]'], f"{e!r}")
    p, _, _ = ask("pe.machine_set", "agent-001.bin", pe64(), "pe", day="21", fmt=JSON_ARRAY)
    check("row 401: pe.machine_set is unsure, ['0x8664'] first", not is_plain(p) and values_of(p)[:1] == ['["0x8664"]'], f"{p!r}")
    n, _, _ = ask("elf.e_machine_set", "sample-001.bin", elf64(), "elf", day="21")
    check("row 401: the same name asked as text is None", n is None, f"{n!r}")
    thin = struct.pack("<IIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0) + bytes(4)
    m, _, _ = ask("macho.fat_architectures", "macos-001.bin", thin, "macho", day="21", fmt=JSON_ARRAY)
    check("row 405: a thin Mach-O's fat_architectures is one element, unsure",
          not is_plain(m) and values_of(m)[:1] == ['["CPU_TYPE_ARM64"]'] and '["0x0100000c"]' in values_of(m), f"{m!r}")


def test_cli():
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    tool = str(HERE / "properties_strict.py")
    sample = TMP / "camera-001.jpg"
    sample.write_bytes(J)
    facts = subprocess.run([sys.executable, tool, str(sample)], capture_output=True, text=True, env=env)
    usage = subprocess.run([sys.executable, tool], capture_output=True, text=True, env=env)
    missing = subprocess.run([sys.executable, tool, str(TMP / "no-such-file")], capture_output=True, text=True, env=env)
    contract = TMP / "status.json"
    contract.write_text(json.dumps({"questions": [question("exif.unknown_tag", "camera-001.jpg", "exif"),
                                                  question("png.ihdr_dimensions_pixels", "scan-001.png", "png")]}))
    cov = subprocess.run([sys.executable, tool, "--coverage", str(contract)], capture_output=True, text=True, env=env)
    check("the command line prints facts, and one-line errors without a traceback",
          facts.returncode == 0 and "jpeg.sof_dimensions_pixels = 257x146" in facts.stdout
          and usage.returncode == 2 and usage.stderr.startswith("usage:") and "Traceback" not in usage.stderr
          and missing.returncode == 2 and len(missing.stderr.strip().splitlines()) == 1
          and cov.returncode == 1 and "exif.unknown_tag is not registered" in cov.stdout
          and "d05-png-001-png-ihdr-dimensions-pixels: covered" in cov.stdout,
          f"exit codes {facts.returncode}, {usage.returncode}, {missing.returncode}, {cov.returncode}")

    # Saved responses that are JSON but not what the tool expects: a line each, never a traceback.
    runs = []
    for label, body, want in [("a question that is not an object", {"questions": ["x", 5]}, 1),
                              ("an empty question list", {"questions": []}, 2),
                              ("questions that is not a list", {"questions": {"a": 1}}, 2),
                              ("answer_ids of the wrong kind", {"questions": [question("sha256", "a-001.txt", "file")], "answer_ids": [7]}, 0),
                              ("a JSON list", [1, 2], 2)]:
        contract.write_text(json.dumps(body))
        r = subprocess.run([sys.executable, tool, "--coverage", str(contract)], capture_output=True, text=True, env=env)
        if r.returncode != want or "Traceback" in r.stderr:
            runs.append(f"{label}: exit {r.returncode}, expected {want}; {r.stderr.strip().splitlines()[-1:]}")
    check("--coverage on a malformed saved response: one line and no traceback", not runs, "; ".join(runs))


# ------------------------------------------------------------------ 21. an enum that names a code's meaning (row 53)

def enum_of(*values):
    return {"kind": "enum", "accepted_values": list(values)}


def test_enum_meanings():
    elfx, pex, gzx = elf64(), pe64(), gz()
    colour = enum_of("grayscale", "truecolor", "indexed", "grayscale_alpha", "truecolor_alpha")
    cases = [  # (label, property, file, bytes, answer format, the values offered: [] is no answer)
        ("PNG colour type 6 named", "png.ihdr_color_type", "chart-001.png", png(ct=6), colour, ["truecolor_alpha"]),
        ("PNG colour type 3 under its alias", "png.ihdr_colour_type", "chart-001.png", png(ct=3), colour, ["indexed"]),
        ("PE machine 0x8664", "pe.machine", "tool-001.exe", pex, enum_of("i386", "amd64", "arm64"), ["amd64"]),
        ("PE32+ from the optional header magic", "pe.optional_header_magic", "tool-001.exe", pex, enum_of("PE32", "PE32+"), ["PE32+"]),
        ("ELF data without case", "elf.endianness", "tool-001.elf", elfx, enum_of("lsb", "msb"), ["lsb"]),
        ("ELF class without case", "elf.class", "tool-001.elf", elfx, enum_of("elf32", "elf64"), ["elf64"]),
        ("ELF machine, underscore for hyphen", "elf.machine", "tool-001.elf", elfx, enum_of("i386", "x86_64", "aarch64"), ["x86_64"]),
        ("RFC 1952 OS 255", "gzip.os", "notes-001.txt.gz", gzx, enum_of("fat", "unix", "ntfs", "unknown"), ["unknown"]),
        ("TIFF II", "tiff.byte_order", "scan-001.tif", TIFF, enum_of("big_endian", "little_endian"), ["little_endian"]),
        ("two accepted values mean the code", "elf.machine", "tool-001.elf", elfx, enum_of("x86-64", "amd64", "i386"), []),
        ("no accepted value means the code", "png.ihdr_color_type", "chart-001.png", png(ct=6), enum_of("rgb", "palette"), []),
        ("a code no table lists", "png.ihdr_color_type", "chart-001.png", png(ct=5), colour, []),
        ("an enum of the stored form is as before", "png.ihdr_color_type", "chart-001.png", png(ct=6), enum_of("0", "2", "6"), ["6"]),
        ("an enum of words no table holds is as before", "png.ihdr_bit_depth", "chart-001.png", png(), enum_of("eight", "sixteen"), []),
    ]
    bad = []
    for label, prop, fname, data, fmt, want in cases:
        got, err, _ = ask(prop, fname, data, prop.split(".")[0], fmt=fmt)
        if is_plain(got) or values_of(got) != want or (not want and "FORMAT" not in err):
            bad.append(f"{label}: {prop} {got!r}, expected unsure {want}")
        elif want and want != ["6"] and labels.parse(got).options[0][0] != solver.SPEC_NAME:
            bad.append(f"{label}: offered under {labels.parse(got).options[0][0]!r}, not {solver.SPEC_NAME!r}")
    check("an enum of a code's meanings offers the one accepted value the spec table maps it to, unsure; none or two is no answer",
          not bad, "; ".join(bad))

    os.environ["CTF_WORKDIR"] = str(TMP / "enum-meaning")
    try:
        q = question("png.ihdr_color_type", "chart-001.png", "png", fmt=colour)
        before = solver.covers([q])
        labels.learn("metadata.format/png.ihdr_color_type", solver.SPEC_NAME, "accepted", attempt_id="selftest", answer_ids=[q["id"]])
        after = solver.covers([q])
        plain = [ask("png.ihdr_color_type", "chart-001.png", png(ct=ct), "png", fmt=colour)[0] for ct in (6, 0, 2)]
        stored = ask("png.ihdr_color_type", "chart-001.png", png(ct=6), "png", fmt=enum_of("0", "2", "6"))[0]
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    check("once 'enum_meaning' is accepted the property is covered and plain on the next variant",
          len(before) == 1 and after == [] and plain == ["truecolor_alpha", "grayscale", "truecolor"] and not is_plain(stored),
          f"covers {before} then {after}; answers {plain}; stored form {stored!r}")


# ------------------------------------------------------------------ 22. a member inside tar, gzip, bzip2 or xz (row 54)

def tar_with(members: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, body in members.items():
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime = len(body), 1790755200
            t.addfile(ti, io.BytesIO(body))
    return buf.getvalue()


def test_nested_containers():
    pic = jpeg(257, 146)
    inner = tar_with({"photos/camera-001.jpg": pic, "photos/readme.txt": b"field notes\n"})
    bad = []

    def expect(label, got, want):
        if got != want:
            bad.append(f"{label}: {got!r}, expected {want!r}")

    for wrapper, data in [("photos.tar.gz", gzip_of(inner)), ("photos.tar.bz2", bz2.compress(inner)),
                          ("photos.tar.xz", lzma.compress(inner)), ("photos.tar", inner),
                          ("camera-001.jpg.gz", gzip_of(pic)), ("camera-001.jpg.xz", lzma.compress(pic))]:
        got, err, _ = ask("jpeg.sof_dimensions_pixels", "camera-001.jpg", None, "jpeg", members={wrapper: data})
        expect(f"the named picture inside {wrapper}", got, "257x146")
    check("a member nested in tar, gzip, bzip2 or xz is read when the question names it exactly", not bad, "; ".join(bad))

    # Which file sha256, md5, file.size_bytes or magic.* means when the named picture sits only inside a
    # container has never been judged: those answers stay exactly what they were before row 54, the
    # container's, and never move to the member.
    bad = []
    tgz = gzip_of(inner)
    for wrapper, data, extra in [("camera-001.jpg.gz", gzip_of(pic), {}), ("pics.tar", tar_with({"camera-001.jpg": pic}), {}),
                                 ("photos.tar.gz", tgz, {}), ("camera-001.jpg.gz", gzip_of(pic), {"camera-002.jpg": jpeg(30, 40)})]:
        members = {wrapper: data, **extra}
        for typ in ("jpeg", "file"):
            for prop, want in [("sha256", hashlib.sha256(data).hexdigest()), ("md5", hashlib.md5(data).hexdigest()),
                               ("file.size_bytes", str(len(data))), ("magic.prefix_hex_16", data[:16].hex())]:
                expect(f"{prop} of camera-001.jpg ({typ} id) with only {sorted(members)}",
                       ask(prop, "camera-001.jpg", None, typ, members=members)[0], want)
    got = ask("sha256", "camera-001.jpg", None, "file",
              members={"pics.tar": tar_with({"camera-001.jpg": pic}), "camera-002.jpg": jpeg(30, 40)})[0]
    expect("sha256 of camera-001.jpg (file id) inside pics.tar beside camera-002.jpg", got, None)
    check("a property that is not about content keeps the container as its file: no plain answer moves to the member",
          not bad, "; ".join(bad))

    bad = []
    for label, members in [
            ("a picture the container does not hold", {"photos.tar.gz": gzip_of(tar_with({"other-001.jpg": pic}))}),
            ("a name that only starts like the member", {"photos.tar.gz": gzip_of(tar_with({"camera-001.jpg.bak": pic}))}),
            ("three layers, one more than is opened", {"deep.gz": gzip_of(tar_with({"camera-001.jpg.gz": gzip_of(pic)}))}),
            ("two different members under the name", {"a.tar": tar_with({"camera-001.jpg": pic}),
                                                     "b.tar": tar_with({"camera-001.jpg": jpeg(30, 40)})}),
            ("a stream that does not inflate", {"photos.tar.gz": gzip_of(inner)[:40]})]:
        got, err, _ = ask("jpeg.sof_dimensions_pixels", "camera-001.jpg", None, "jpeg", members=members)
        expect(label, got, None)
    got, err, _ = ask("text.utf8_bom_present", "notes-001.txt", None, "text", fmt=TRUE_FALSE,
                      members={"logs.tar.gz": gzip_of(tar_with({"other.txt": b"x"}))})
    expect("a text question about a container it was not named in", (got, "is not the file" in err), (None, True))
    check("an unnamed tar or compressed container is not the file of a picture or text question; no guess among members",
          not bad, "; ".join(bad))

    bad = []
    gzx = gz()
    expect("gzip.os of a lone .gz", values_of(ask("gzip.os", "notes-001.txt.gz", gzx, "gzip")[0]), ["255"])
    expect("gzip.os of a .gz the question names by its member's name",
           values_of(ask("gzip.os", "field-notes.txt", None, "gzip", members={"notes-001.txt.gz": gzx})[0]), ["255"])
    expect("tar.entry_count of a lone .tar.gz",
           values_of(ask("tar.entry_count", "photos.tar.gz", None, "tar", members={"photos.tar.gz": gzip_of(inner)})[0])[:1], ["2"])
    expect("the digest of a lone .gz under an identity id",
           ask("sha256", "notes-009.txt.gz", None, "file", item="009", members={"notes-001.txt.gz": gzx})[0],
           hashlib.sha256(gzx).hexdigest())
    os.environ["CTF_WORKDIR"] = str(TMP / "nested-gzip")
    try:
        labels.learn("metadata.format/gzip.mtime", "unix", "accepted", attempt_id="selftest", answer_ids=["selftest"])
        expect("gzip.mtime of a lone .gz, its format accepted", ask("gzip.mtime", "notes-001.txt.gz", gzx, "gzip")[0], "1790755200")
        expect("gzip.mtime of a .tar.gz, its format accepted",
               ask("gzip.mtime", "photos.tar.gz", None, "gzip", members={"photos.tar.gz": gzip_of(inner)})[0], "1790755200")
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    check("a container stays the target of its own namespace and of identity questions: gzip.mtime is still plain",
          not bad, "; ".join(bad))


# ------------------------------------------------------------------ 23 and 24. Day 8: rows 102, 103 and 112

JSON_ARRAY = {"kind": "json", "syntax": "compact valid JSON array with exact values and order; no Markdown or explanatory text"}
FILENAME_FORMAT = {"kind": "exact_text", "syntax": "exact base filename including its extension, with no directory path, quotes, "
                   "or explanatory text"}


def zip_at(members, when=(2026, 10, 1, 9, 0, 0), method=zipfile.ZIP_STORED, extra=None, comment=b"") -> bytes:
    """A zip whose entries all carry one DOS time; `extra` gives each entry's extra field by name."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        for n, d in members:
            info = zipfile.ZipInfo(n, when)
            info.compress_type = method
            if extra and n in extra:
                info.extra = extra[n]
            z.writestr(info, d)
        z.comment = comment
    return buf.getvalue()


def drop_central_header(data: bytes, index: int) -> bytes:
    """The archive with one central header taken out and the end record's counts and size corrected:
    the member's local header and data stay where they were, listed nowhere."""
    at = data.rfind(b"PK\x05\x06")
    total, size, off = struct.unpack("<HII", data[at + 10:at + 20])
    p, spans = off, []
    for _ in range(total):
        n, e, c = struct.unpack("<HHH", data[p + 28:p + 34])
        spans.append((p, p + 46 + n + e + c))
        p = spans[-1][1]
    a, b = spans[index]
    cd = data[off:a] + data[b:off + size]
    return data[:off] + cd + data[at:at + 8] + struct.pack("<HHII", total - 1, total - 1, len(cd), off) + data[at + 20:]


def day8_delivery(note=("evidence-note.txt",), inner=None):
    inner = inner if inner is not None else zip_at([("room-01/item-1.txt", b"a" * 48), ("room-02/item-1.txt", b"b" * 48)])
    members = [(n, b"Case A9706EAF1E5: first note.\n") for n in note]
    members += [("camera-001.jpg", J), ("panel-001.png", PNG), ("document-001.pdf", PDF), ("evidence-drop-001.zip", inner)]
    return zip_at(members, when=(2026, 1, 1, 0, 0, 0), method=zipfile.ZIP_DEFLATED), inner


def day8_question(suffix, text, fmt):
    return {"id": f"evidence-note-{suffix}", "question": text, "artifact": "metadata-day-08-evidence.zip", "answer_format": fmt,
            "normalization": "trim"}


def test_day8_rows():
    shipped, template = HERE / "day_patch.py", HERE / "day_patch_template.py"
    check("row 103: the shipped day_patch.py is the template again, with empty tables and no hand code",
          not shipped.exists() or shipped.read_bytes() == template.read_bytes())

    # row 103: the file of an id of the Day 1 form whose question names none
    delivery, inner = day8_delivery()
    q = day8_question("filename", "What is the exact filename of the first evidence note?", FILENAME_FORMAT)
    got, err = ask_prepared(q, delivery, "metadata-day-08-evidence.zip")
    check("row 103: among eight delivered files, 'evidence-note-filename' is the one file whose stem the id carries, plain and covered",
          got == "evidence-note.txt" and "the one delivered file with the id's stem" in err and solver.covers([q]) == [], f"{got!r} {err[-200:]}")
    q_sha = day8_question("sha256", "What is the SHA-256 digest of the first evidence note?", DAY4_FORMAT)
    sha, _ = ask_prepared(q_sha, delivery, "metadata-day-08-evidence.zip")
    check("the same file answers the id's other identity questions when their text names no file",
          sha == hashlib.sha256(b"Case A9706EAF1E5: first note.\n").hexdigest(), f"{sha!r}")
    two, err_two = ask_prepared(q, day8_delivery(note=("evidence-note.txt", "evidence-note.md"))[0], "metadata-day-08-evidence.zip")
    zero, err_zero = ask_prepared(q, day8_delivery(note=("field-note.txt",))[0], "metadata-day-08-evidence.zip")
    alike, _ = ask_prepared(q, day8_delivery(note=("evidence-note.txt", "evidence_note.txt"))[0], "metadata-day-08-evidence.zip")
    check("two files with that stem, a look-alike stem beside it, or none: no file is chosen and the answer is None",
          two is None and zero is None and alike is None and "NO TARGET FILE" in err_two and "NO TARGET FILE" in err_zero,
          f"{two!r} {zero!r} {alike!r}")

    # row 102: the JSON list form and the central directory reader
    names = '["room-01/item-1.txt","room-02/item-1.txt"]'
    cd, _, q_cd = ask("zip.central_directory_member_names", "evidence-drop-001.zip", inner, "zip", day="07", fmt=JSON_ARRAY)
    alias_, _, _ = ask("zip.cd_member_names", "evidence-drop-001.zip", inner, "zip", day="07", fmt=JSON_ARRAY)
    check("row 102: zip.central_directory_member_names is registered, plain as compact JSON from the seed, and covered without a day patch",
          cd == names and solver.covers([q_cd]) == [] and solver.lookup("zip.central_directory_member_names") is not None, f"{cd!r}")
    check("its alias zip.cd_member_names reads the same headers, unsure under its own key until judged",
          values_of(alias_) == [names] and not is_plain(alias_) and labels.parse(alias_).options[0][0] == "json_compact", f"{alias_!r}")
    chunk, _, _ = ask("png.chunk_types", "scan-001.png", PNG, "png", fmt=JSON_ARRAY)
    entries, _, _ = ask("zip.entry_names", "bundle-001.zip", inner, "zip", fmt=JSON_ARRAY)
    plain_fmt, _, _ = ask("png.chunk_types", "scan-001.png", PNG, "png")
    check("a json-kind question on png.chunk_types and zip.entry_names offers json_compact first (and only what is JSON)",
          labels.parse(chunk).options == [("json_compact", '["IHDR","pHYs","tEXt","tIME","IDAT","IEND"]')]
          and labels.parse(entries).options == [("json_compact", names)]
          and [n for n, _ in labels.parse(plain_fmt).options] == ["comma", "comma_space", "space", "json_compact"], f"{chunk!r} {entries!r}")
    eocd, _, q_eocd = ask("zip.eocd_total_entries", "evidence-drop-001.zip", inner, "zip", day="07",
                          fmt={"kind": "integer", "syntax": "base-10 integer with no units, separators, or explanatory text"})
    check("Day 7's zip.eocd_total_entries is plain through its alias (row 179) and the seed, with no day patch line", eocd == "2" and solver.covers([q_eocd]) == [],
          f"{eocd!r}")
    forged = zip_at([("a.txt", b"x")], comment=b"PK\x05\x06" + b"\x00" * 18)
    at = inner.rfind(b"PK\x05\x06")
    zip64 = inner[:at + 8] + b"\xff\xff\xff\xff" + inner[at + 12:]              # the end record defers to a ZIP64 record
    miscount = inner[:at + 8] + struct.pack("<HH", 3, 3) + inner[at + 12:]     # it states one header more than there is
    cd_at = struct.unpack("<I", inner[at + 16:at + 20])[0]
    far = inner[:cd_at + 42] + b"\xff\xff\xff\xff" + inner[cd_at + 46:]          # a central header whose offset is in a ZIP64 field
    refused = {n: ask("zip.central_directory_member_names", "bundle-001.zip", d, "zip", fmt=JSON_ARRAY)[0]
               for n, d in (("an end record inside the comment", forged), ("a ZIP64 end record", zip64),
                            ("a count that does not match", miscount), ("a ZIP64 offset", far))}
    check("the central directory reader fails closed: a signature inside the comment, ZIP64, or a count that does not match is no answer",
          all(v is None for v in refused.values()), f"{refused}")

    # row 112: names and provenance, all unsure

    def z(prop, data=inner, name="evidence-drop-001.zip", **kw):
        return ask(prop, name, data, "zip", **kw)[0]
    held, _ = ask_prepared(question("zip.entries_newer_than_container", "evidence-drop-001.zip", "zip", day="07", fmt=JSON_ARRAY),
                           delivery, "metadata-day-07-evidence.zip")
    held_bool, _ = ask_prepared(question("zip.entries_newer_than_container_present", "evidence-drop-001.zip", "zip", day="07"),
                                delivery, "metadata-day-07-evidence.zip")
    when, _ = ask_prepared(question("zip.container_entry_modified", "evidence-drop-001.zip", "zip", day="07"),
                           delivery, "metadata-day-07-evidence.zip")
    check("row 112: members dated after the entry that holds their archive (Day 8: 2026-10-01 inside an entry of 2026-01-01) are listed",
          values_of(held) == [names] and values_of(held_bool) == ["true"] and values_of(when)[0] == "2026-01-01T00:00:00"
          and not is_plain(held) and not is_plain(held_bool), f"{held!r} {held_bool!r} {when!r}")
    older = z("zip.entries_newer_than_container")  # ask() stores the archive in an evidence zip written now, after its members
    try:
        solver.lookup("zip.entries_newer_than_container").fn("evidence-drop-001.zip", inner)
        alone = "a value"
    except solver.Unknown:
        alone = None
    later_copy = zip_at([("evidence-drop-001.zip", inner)], when=(2027, 1, 1, 0, 0, 0))
    twice = zip_at([("evidence-drop-001.zip", inner), ("copies.zip", later_copy)], when=(2026, 1, 1, 0, 0, 0))
    both, _ = ask_prepared(question("zip.entries_newer_than_container", "evidence-drop-001.zip", "zip", day="07"), twice,
                           "metadata-day-07-evidence.zip")
    check("members older than their container are the unsure none; outside a delivery, or held under two different times, nothing is said",
          values_of(older) == ["none"] and alone is None and both is None, f"{older!r} {alone!r} {both!r}")
    got = {p: z(p) for p in ("zip.duplicate_basenames", "zip.duplicate_basenames_present", "zip.local_header_member_names",
                             "zip.local_central_name_mismatch", "zip.entry_modified_times", "zip.unsafe_paths", "zip.compression_methods",
                             "zip.member_directories", "zip.member_basenames", "zip.local_header_count", "zip.duplicate_member_names")}
    check("the Day 8 archive: one repeated base name under two rooms, local and central names agree, DOS times, no unsafe path",
          values_of(got["zip.duplicate_basenames"])[0] == "item-1.txt" and values_of(got["zip.duplicate_basenames_present"]) == ["true"]
          and values_of(got["zip.local_header_member_names"])[0] == "room-01/item-1.txt,room-02/item-1.txt"
          and values_of(got["zip.local_central_name_mismatch"]) == ["false"]
          and values_of(got["zip.entry_modified_times"])[0] == "2026-10-01T09:00:00,2026-10-01T09:00:00"
          and values_of(got["zip.unsafe_paths"]) == ["none"] and values_of(got["zip.compression_methods"])[0] == "0,0"
          and values_of(got["zip.member_directories"])[0] == "room-01,room-02"
          and values_of(got["zip.member_basenames"])[0] == "item-1.txt,item-1.txt" and values_of(got["zip.local_header_count"]) == ["2"]
          and values_of(got["zip.duplicate_member_names"]) == ["none"] and not any(is_plain(v) for v in got.values()),
          f"{ {k: values_of(v)[:1] for k, v in got.items()} }")
    renamed = inner.replace(b"room-01/item-1.txt", b"room-09/item-1.txt", 1)  # the first hit is the local header's name
    r = {p: values_of(z(p, renamed)) for p in ("zip.local_central_name_mismatch", "zip.local_central_name_mismatch_count",
                                               "zip.mismatched_local_header_names", "zip.mismatched_central_directory_names",
                                               "zip.local_header_member_names", "zip.central_directory_member_names")}
    check("a local header renamed after the fact: the mismatch is seen, both names are given, the central directory still says the old one",
          r["zip.local_central_name_mismatch"] == ["true"] and r["zip.local_central_name_mismatch_count"] == ["1"]
          and r["zip.mismatched_local_header_names"][0] == "room-09/item-1.txt"
          and r["zip.mismatched_central_directory_names"][0] == "room-01/item-1.txt"
          and r["zip.local_header_member_names"][0] == "room-09/item-1.txt,room-02/item-1.txt"
          and r["zip.central_directory_member_names"][-1] == names, f"{r}")
    hidden = drop_central_header(zip_at([("shown.txt", b"1"), ("hidden.txt", b"2"), ("last.txt", b"3")]), 1)
    h = {p: values_of(z(p, hidden)) for p in ("zip.unlisted_local_header_names", "zip.unlisted_local_header_count", "zip.local_header_count",
                                              "zip.entry_count", "zip.local_header_member_names", "zip.eocd_entry_count")}
    check("a member the central directory does not list is found between its neighbours, by its own local header",
          h["zip.unlisted_local_header_names"][0] == "hidden.txt" and h["zip.unlisted_local_header_count"] == ["1"]
          and h["zip.local_header_count"] == ["3"] and h["zip.entry_count"] == ["2"] and h["zip.eocd_entry_count"] == ["2"]
          and h["zip.local_header_member_names"][0] == "shown.txt,hidden.txt,last.txt", f"{h}")
    unsafe = zip_at([("ok/fine.txt", b"1"), ("../../etc/passwd", b"2"), ("/abs.txt", b"3"), ("C:\\x.txt", b"4"), ("a/../b.txt", b"5")])
    u = {p: values_of(z(p, unsafe)) for p in ("zip.unsafe_paths", "zip.unsafe_path_count", "zip.unsafe_paths_present", "zip.max_path_depth")}
    check("traversal, absolute and drive-letter names are the unsafe paths; an honest nested path is not",
          u["zip.unsafe_paths"][0] == "../../etc/passwd,/abs.txt,C:\\x.txt,a/../b.txt" and u["zip.unsafe_path_count"] == ["4"]
          and u["zip.unsafe_paths_present"] == ["true"] and u["zip.max_path_depth"] == ["4"], f"{u}")
    outer = zip_at([("first.txt", b"1"), ("evidence-drop-001.zip", inner), ("last.txt", b"3")])
    stream = io.BytesIO()
    with zipfile.ZipFile(type("Pipe", (), {"write": stream.write, "flush": lambda self=None: None, "tell": stream.tell})(), "w") as zf:
        zf.writestr(zipfile.ZipInfo("piped-a.txt", (2026, 10, 1, 9, 0, 0)), b"aaaa")
        zf.writestr(zipfile.ZipInfo("piped-b.txt", (2026, 10, 1, 9, 0, 0)), b"bb")
    piped = stream.getvalue()
    check("a stored member that is itself a zip is not walked into, and entries followed by data descriptors are stepped over",
          values_of(z("zip.local_header_member_names", outer))[0] == "first.txt,evidence-drop-001.zip,last.txt"
          and values_of(z("zip.local_header_count", outer)) == ["3"] and b"PK\x07\x08" in piped
          and values_of(z("zip.local_header_member_names", piped))[0] == "piped-a.txt,piped-b.txt", f"{z('zip.local_header_member_names', piped)!r}")
    ut = {n: struct.pack("<HHBi", 0x5455, 5, 1, t) for n, t in (("a.txt", 1790000000), ("b.txt", 1790000060))}
    timed = zip_at([("a.txt", b"1"), ("b.txt", b"2")], extra=ut)
    partly = zip_at([("a.txt", b"1"), ("b.txt", b"2")], extra={"a.txt": ut["a.txt"]})
    t = values_of(z("zip.entry_ut_mtimes", timed))
    check("the 0x5455 extended timestamps are read per entry; only some entries carrying one is no answer; none at all is the unsure none",
          t[0] == "1790000000,1790000060" and "[1790000000,1790000060]" in t and z("zip.entry_ut_mtimes", partly) is None
          and values_of(z("zip.entry_ut_mtimes")) == ["none"] and values_of(z("zip.first_entry_ut_mtime", timed))[0] == "1790000000", f"{t}")
    cut = [z(p, inner[:-30]) for p in ("zip.local_header_member_names", "zip.duplicate_basenames", "zip.central_directory_member_names")]
    check("a zip cut inside its central directory: the row 112 readers give no answer and no value", all(v is None or values_of(v) == ["none"] for v in cut),
          f"{cut}")
    looks = {}
    for prop, want in (("zip.local_header_member_names", "zip_local_header_member_names"), ("zip.member_names", "zip_member_names"),
                       ("zip.duplicate_basenames", "zip_duplicate_basenames"), ("zip.unsafe_paths", "zip_unsafe_paths")):
        key = solver.resolve(question(prop, "evidence-drop-001.zip", "zip", day="07"))[0]
        if key != want or solver.lookup(key) is None:
            looks[prop] = key
    fns = {solver.lookup(n).fn for n in ("zip.local_header_member_names", "zip.member_names", "zip.central_directory_member_names")}
    check("check 3 for the new words: each new zip name resolves to itself and to an extractor of its own",
          not looks and len(fns) == 3 and solver.lookup("zip.local_header_member_name") is None, f"{looks}")


HEX_0X = {"kind": "pattern", "syntax": "lowercase hexadecimal with a 0x prefix and no explanatory text"}
DAY9_BASE = "day-09/metadata-forensics-day-09-built-different/artifact/metadata-day-09-evidence.zip"


def pe32(machine=0x14C, flags=0x0102):
    """A PE32 header by hand: COFF machine and characteristics as given, optional-header magic 0x10b."""
    dos = b"MZ" + bytes(58) + struct.pack("<I", 0x80) + bytes(0x40)
    return dos + b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, 3, 1790755200, 0, 0, 224, flags) + struct.pack("<H", 0x10B) + bytes(222)


def day9_exe():
    """The PE of the saved Day 9 base, or None where no saved attempt is (a fresh clone)."""
    path = ATTEMPTS / DAY9_BASE
    if not path.is_file():
        return None
    with zipfile.ZipFile(path) as z:
        return z.read("telemetry-agent-001.exe")


def test_day9_rows():
    exe = "telemetry-agent-001.exe"
    text = b"Case 3BA9337684A: this note was renamed to look like a program.\n" * 2
    mz = b"MZ" + bytes(58) + struct.pack("<I", 0x80) + bytes(0x80)  # a DOS header whose e_lfanew points at no signature
    decoys = {"text under .exe": text, "MZ without PE\\0\\0": mz, "ELF under .exe": elf64(),
              "e_lfanew outside the file": b"MZ" + bytes(58) + struct.pack("<I", 0x7FFFFFF0) + bytes(0x40)}

    # row 179: Day 9's property is registered, with the judged key and format name
    p = solver.lookup("pe.coff_machine_u16_hex")
    i386, err, q = ask("pe.coff_machine_u16_hex", exe, pe32(), "pe", day="09", fmt=HEX_0X)
    amd64, _, _ = ask("pe.coff_machine_u16_hex", exe, pe64(), "pe", day="09", fmt=HEX_0X)
    check("row 179: pe.coff_machine_u16_hex is registered under its judged key and class, plain as 0x014c from the seed, and covered "
          "with no day patch", p is not None and not p.confirmed and p.key == "metadata.format/pe.coff_machine_u16_hex"
          and solver.FORMATS[p.fmt][0][0] == "0x_u16_4digits" and i386 == "0x014c" and amd64 == "0x8664"
          and solver.covers([q]) == [] and "UNKNOWN PROPERTY" not in err, f"{i386!r} {amd64!r} {solver.covers([q])}")
    got = {n: ask("pe.coff_machine_u16_hex", exe, d, "pe", day="09", fmt=HEX_0X)[0] for n, d in decoys.items()}
    check("row 179: a decoy under .exe (text, MZ without the signature, ELF, e_lfanew past the end) is never plain: the unsure `none`",
          all(v is not None and not is_plain(v) and labels.parse(v).options == [("absent", "none")] for v in got.values()), f"{got}")
    check("row 179: zip.eocd_total_entries is registered as an alias of zip.eocd_entry_count, unconfirmed",
          solver.lookup("zip.eocd_total_entries") is not None and not solver.lookup("zip.eocd_total_entries").confirmed
          and solver.lookup("zip.eocd_total_entries").fn is solver.lookup("zip.eocd_entry_count").fn)
    _, err_pe, _ = ask("pe.frobnication", exe, pe32(), "pe", day="09")
    _, err_mz, _ = ask("pe.frobnication", exe, mz, "pe", day="09")
    check("row 179: the file line of an UNKNOWN PROPERTY page names a PE, and not a file that only starts with MZ",
          f"file = {exe} (pe, " in err_pe and f"file = {exe} (unrecognised, " in err_mz,
          f"{[line.strip() for line in (err_pe + err_mz).splitlines() if line.strip().startswith('file = ')]}")

    # row 178: a typed header name is read without its type words, padded to the stated width, unsure
    flags, err, q = ask("pe.coff_characteristics_u16_hex", exe, pe32(), "pe", day="10", fmt=HEX_0X)
    parsed = labels.parse(flags) if flags else None
    check("row 178: pe.coff_characteristics_u16_hex is tried as pe.characteristics, unsure under the asked name, the padded form "
          "first, then the minimal one, the reader in every option's name",
          parsed is not None and parsed.key == "metadata.format/pe.coff_characteristics_u16_hex"
          and parsed.options[:2] == [("0x_u16_4digits~pe.characteristics", "0x0102"), ("0x_hex_lower~pe.characteristics", "0x102")]
          and all(n.endswith("~pe.characteristics") for n, _ in parsed.options) and "by type words" in err
          and len(solver.covers([q])) == 1, f"{flags!r} {err.strip().splitlines()[-1:]}")
    real = day9_exe()
    if real is None:
        skip("row 178 on the Day 9 exe", "no saved Day 9 base under the attempts folder")
    else:
        first = {}
        for prop, want in (("pe.coff_characteristics_u16_hex", "0x%04x" % struct.unpack("<H", real[0x80 + 22:0x80 + 24])[0]),
                           ("pe.coff_machine_u16_hex", "0x014c"), ("pe.machine_u16_hex", "0x014c"),
                           ("pe.optional_header_magic_u16_hex", "0x010b")):
            a, _, _ = ask(prop, exe, real, "pe", day="10", fmt=HEX_0X)
            vals = values_of(a)
            if not vals or vals[0] != want or len(want) != 6 or (is_plain(a) and prop != "pe.coff_machine_u16_hex"):
                first[prop] = a
        check("row 178: on the Day 9 exe an unjudged typed name is an unsure pick whose first value has the four digits of a u16, "
              "and only Day 9's own judged name is plain", struct.unpack("<I", real[0x3C:0x40])[0] == 0x80 and not first, f"{first}")
    wide, _, _ = ask("pe.optional_header_magic_u32_hex", exe, pe32(), "pe", day="10", fmt=HEX_0X)
    elf_m, _, _ = ask("elf.e_machine_u16_hex", "agent-001.elf", elf64(), "elf", day="10", fmt=HEX_0X)
    plainly, _, _ = ask("pe.coff_characteristics", exe, pe32(), "pe", day="10", fmt=HEX_0X)
    check("row 178: u32 pads to eight digits (unjudged PE typed name, unsure), the now-judged u16 typed name "
          "elf.e_machine is plain in its accepted 4-digit form, and words alone (pe.coff_characteristics) change no form",
          values_of(wide)[:2] == ["0x0000010b", "0x10b"] and not is_plain(wide)
          and is_plain(elf_m) and values_of(elf_m)[:1] == ["0x003e"]
          and values_of(plainly)[:1] == ["0x102"] and not is_plain(plainly),
          f"{wide!r} {elf_m!r} {plainly!r}")
    two, err_two, q_two = ask("tiff.width_image_u32_hex", "scan-001.tif", TIFF, "tiff", day="10", fmt=HEX_0X)
    check("row 178: a typed name with two matching extractors gives None, and the question stays open",
          two is None and solver.guess("tiff_width_image_u32_hex") == (None, None, None) and len(solver.covers([q_two])) == 1,
          f"{two!r}")
    not_pe = {n: ask("pe.coff_characteristics_u16_hex", exe, d, "pe", day="10", fmt=HEX_0X)[0] for n, d in decoys.items()}
    check("row 178: a non-PE under .exe gives None for a typed name (a guessed reader never says `none`)",
          all(v is None for v in not_pe.values()), f"{not_pe}")
    refused = {}
    for prop, fname, data in (("pe.is_dll_u16_hex", exe, pe32()),          # a width on a reader that reads no number
                              ("elf.entry_point_u16_hex", "agent-001.elf", elf64()),   # 0x401000 does not fit a u16
                              ("pe.timestamp_u32_u16_hex", exe, pe32()),   # two widths
                              ("pe.frobnication_u16_hex", exe, pe32())):   # no reader without the type words either
        a, _, _ = ask(prop, fname, data, prop.split(".")[0], day="10", fmt=HEX_0X)
        if a is not None:
            refused[prop] = a
    check("row 178: a width on a reader of no number, a value wider than the stated width, two widths, or no reader: None",
          not refused, f"{refused}")
    magic, err_magic, q_magic = ask("magic.prefix_hex_16", exe, pe32(), "pe", day="10")
    check("row 178: magic.prefix_hex_16 still resolves by lookup, plain, and its words are not taken for type words",
          magic == pe32()[:16].hex() and "NEAREST READER" not in err_magic and "UNKNOWN PROPERTY" not in err_magic
          and solver.typed("magic_prefix_hex_16") == ("magic_prefix_hex_16", None, False) and solver.covers([q_magic]) == []
          and solver.typed("pe_coff_machine_u16_hex") == ("pe_coff_machine", 16, True)
          and solver.typed("text_utf16_le") == ("text_utf16_le", None, False), f"{magic!r}")
    missing = [n for n in ("size_of_optional_header", "number_of_symbols", "pointer_to_symbol_table", "address_of_entry_point",
                           "image_base", "e_lfanew") if solver.lookup("pe." + n) is None or solver.lookup("pe." + n).confirmed]
    check("row 178: the PE header fields a typed name may ask are registered, none of them confirmed", not missing, f"{missing}")

    os.environ["CTF_WORKDIR"] = str(TMP / "typed-accepted")
    try:
        labels.learn("metadata.format/pe.coff_characteristics_u16_hex", "0x_u16_4digits~pe.characteristics", "accepted",
                     attempt_id="selftest", answer_ids=[q["id"]])
        after, _, q_after = ask("pe.coff_characteristics_u16_hex", exe, pe32(flags=0x2022), "pe", day="10", fmt=HEX_0X)
        covered = solver.covers([q_after])
    finally:
        os.environ["CTF_WORKDIR"] = str(TMP / "seed-only")
    check("row 178: once the judge accepts the padded form through that reader, the next variant is plain and covered",
          after == "0x2022" and covered == [], f"{after!r}; {covered}")


# ------------------------------------------------------------------ 25. row 203 (union-alias resolver)

def pe_full(entry=0x65BD0, machine=0x14C):
    """A whole PE32 (0 sections, a 96-byte optional header) so _pex reads its entry point: the
    hand-made pe32() above has three sections and is cut, which _pex cannot walk."""
    dos = b"MZ" + bytes(58) + struct.pack("<I", 0x80) + bytes(0x40)        # e_lfanew = 0x80
    coff = struct.pack("<HHIIIHH", machine, 0, 1790755200, 0, 0, 96, 0x0102)  # 0 sections, optsize 96
    opt = bytearray(96)
    opt[0:2] = struct.pack("<H", 0x10B)        # PE32 optional-header magic
    opt[16:20] = struct.pack("<I", entry)      # AddressOfEntryPoint
    opt[28:32] = struct.pack("<I", 0x400000)   # ImageBase (PE32)
    return dos + b"PE\x00\x00" + coff + bytes(opt)


def test_row203_union():
    exe, d = "telemetry-agent-001.exe", pe_full()
    # The entry reader is registered under 'address_of_entry_point' (no rva) and 'entry_point_rva'
    # (no address); the asked core {address,entry,point,rva} is in neither spelling but in their
    # union, so lookup() and synonym() both miss and only the union branch resolves it, unsure.
    bare, err_bare, q_bare = ask("pe.address_of_entry_point_rva", exe, d, "pe", day="10", fmt=HEX_0X)
    parsed = labels.parse(bare) if bare else None
    check("row 203: a name that unions two aliases of one reader resolves to that reader, unsure under the asked "
          "name, the entry reader in every option, with a probe left to settle it",
          parsed is not None and not is_plain(bare) and parsed.key == "metadata.format/pe.address_of_entry_point_rva"
          and values_of(bare)[0] == "0x65bd0" and all(n.endswith("~pe.entry_point") for n, _ in parsed.options)
          and "(by union)" in err_bare and len(solver.covers([q_bare])) == 1,
          f"{bare!r}; err {err_bare.strip().splitlines()[-1:]}")

    # Placing the branch in _nearest fixes the typed form too (guess() strips the width/hex and
    # reads the stem through _nearest), though this container is not @prop'd for u32.
    typedname, err_typed, q_typed = ask("pe.address_of_entry_point_rva_u32_hex", exe, d, "pe", day="10", fmt=HEX_0X)
    parsed_t = labels.parse(typedname) if typedname else None
    check("row 203: the typed form of the same union name is unsure too, padded to eight digits, the entry reader named",
          parsed_t is not None and not is_plain(typedname)
          and parsed_t.key == "metadata.format/pe.address_of_entry_point_rva_u32_hex"
          and parsed_t.options[0] == ("0x_u32_8digits~pe.entry_point", "0x00065bd0")
          and all(n.endswith("~pe.entry_point") for n, _ in parsed_t.options)
          and "(by type words)" in err_typed and len(solver.covers([q_typed])) == 1, f"{typedname!r}")

    # The @prop'd composed name is plain from the seed (row 195); the union must not shadow it.
    plain, _, q_plain = ask("pe.address_of_entry_point_rva_hex", exe, d, "pe", day="10", fmt=HEX_0X)
    check("row 203: the @prop'd composed name (pe.address_of_entry_point_rva_hex) stays plain and covered",
          plain == "0x00065bd0" and solver.covers([q_plain]) == [], f"{plain!r}")

    # The resolver itself and its exactly-one-reader guard.
    ur = solver._union_reader("pe", frozenset({"address", "entry", "point", "rva"}))
    check("row 203: _union_reader picks the one entry reader, guess() reports it 'by union'",
          ur is not None and ur.name == "pe.entry_point"
          and solver.guess("pe_address_of_entry_point_rva")[1:] == ("pe.entry_point", "union"))

    # Look-alikes stay None: two readers cover tiff.width_image (EXIF and TIFF widths), and a strict
    # superset is a different fact (zip.first_entry_uncompressed_size_bytes over the generic name).
    look = {
        "tiff_width_image_u32_hex": solver.guess("tiff_width_image_u32_hex"),
        "zip_entry_uncompressed_size_bytes": solver.guess("zip_entry_uncompressed_size_bytes"),
    }
    check("row 203: a word two readers' unions cover, or a name a single spelling already covers, stays None",
          all(v == (None, None, None) for v in look.values())
          and solver._union_reader("tiff", frozenset({"width", "image"})) is None
          and solver._union_reader("zip", frozenset({"entry", "uncompressed", "size"})) is None, f"{look}")


# ------------------------------------------------------------------ 26. row 204 (facts page skipped for a patch-handled id)

def test_row204_patch_skip():
    patched = patched_copy("row204", PATCH)  # PATCH.handles is True only for exif.unknown_tag
    handled, err_h, _ = ask("exif.unknown_tag", "camera-001.jpg", J, "exif", module=patched)
    other, err_o, _ = ask("exif.other_tag", "camera-001.jpg", J, "exif", module=patched)
    shipped, err_s, _ = ask("exif.unknown_tag", "camera-001.jpg", J, "exif")  # day_patch switched off
    check("row 204: an id day_patch.handles skips the UNKNOWN PROPERTY facts page yet still answers; an id it does "
          "not handle still re-derives it, and so does the shipped solver with no patch",
          handled == "patched-value" and "answered by day_patch.py" in err_h and "UNKNOWN PROPERTY" not in err_h
          and other is None and "UNKNOWN PROPERTY exif.other_tag" in err_o
          and "UNKNOWN PROPERTY exif.unknown_tag" in err_s,
          f"handled UNKNOWN={'UNKNOWN PROPERTY' in err_h}, other={other!r}, "
          f"shipped UNKNOWN={'UNKNOWN PROPERTY' in err_s}")


def test_row211_headers():
    # Row 211: the new PE/ELF/Mach-O header readers are registered, unsure (never confirmed), with the
    # field's spec width where the width is fixed (so a *_hex name offers the padded form first). A
    # field that is a u32 in PE32 and a u64 in PE32+ carries the file's own width ("own": a function
    # of the bytes, Day 12 look-ahead M1), so the width is in the option's name and never in the key.
    for name, fmt, bits in (("pe.size_of_code", "integer", 32), ("pe.base_of_code", "number", 32),
                            ("pe.size_of_initialized_data", "integer", 32), ("pe.base_of_data", "number", 32),
                            ("pe.number_of_rva_and_sizes", "integer", 32), ("pe.loader_flags", "number", 32),
                            ("pe.size_of_stack_reserve", "number", "own"), ("pe.size_of_heap_commit", "number", "own"),
                            ("pe.entry_point_section_name", "text", None), ("pe.entry_point_va", "number", "own"),
                            ("pe.coff_time_date_stamp", "number", 32)):
        p = solver.lookup(name)
        check(f"row 211: {name} registered unsure, fmt {fmt}, bits {bits}",
              p is not None and not p.confirmed and p.fmt == fmt and (callable(p.bits) if bits == "own" else p.bits == bits),
              f"{p and (p.fmt, p.bits, p.confirmed)}")
    # the ELF/Mach-O header fields the review listed already resolve (existing readers), unsure:
    for name in ("elf.e_machine", "elf.e_type", "elf.e_entry", "elf.ei_class", "macho.cputype", "macho.filetype"):
        check(f"row 211: {name} already has a reader (coverage present)", solver.lookup(name) is not None, name)
    real = day9_exe()
    if real is None:
        skip("row 211 value checks", "no saved Day 9 base under the attempts folder")
        return
    o = 0x80 + 24  # the Day 9 exe is PE32 with e_lfanew 0x80; the optional header starts here
    want_soc = struct.unpack("<I", real[o + 4:o + 8])[0]
    want_nrs = struct.unpack("<I", real[o + 92:o + 96])[0]
    exe = "telemetry-agent-001.exe"
    soc, err, q = ask("pe.size_of_code_hex", exe, real, "pe", day="11", fmt=HEX_0X)
    parsed = labels.parse(soc) if soc else None
    check("row 211: pe.size_of_code_hex (no width word) is unsure, the padded u32 form first with the field's value, reader named",
          parsed is not None and parsed.options[0] == ("0x_u32_8digits~pe.size_of_code", "0x%08x" % want_soc)
          and not is_plain(soc) and len(solver.covers([q])) == 1, f"{soc!r}")
    nrs, _, _ = ask("pe.number_of_rva_and_sizes", exe, real, "pe", day="11")
    check("row 211: pe.number_of_rva_and_sizes reads the field, unsure",
          values_of(nrs)[:1] == [str(want_nrs)] and not is_plain(nrs), f"{nrs!r} (want {want_nrs})")
    sect, _, _ = ask("pe.entry_point_section_name", exe, real, "pe", day="11")
    check("row 211: pe.entry_point_section_name is the section holding the entry RVA, unsure",
          values_of(sect)[:1] == [".text"] and not is_plain(sect), f"{sect!r}")
    rva, _, _ = ask("pe.base_of_code_rva_hex", exe, real, "pe", day="11", fmt=HEX_0X)
    check("row 211: an RVA field named with _rva resolves (the _rva alias), padded, unsure",
          not is_plain(rva) and values_of(rva) and values_of(rva)[0].startswith("0x") and len(values_of(rva)[0]) == 10, f"{rva!r}")
    em, _, _ = ask("pe.e_machine_u16_hex", exe, real, "pe", day="11", fmt=HEX_0X)
    check("row 211: an ELF field name on a PE reads nothing (no cross-container plain answer)", em is None, f"{em!r}")


def main() -> int:
    before = snapshot()
    solver_dir = sorted(p.name for p in HERE.iterdir())
    try:
        for test in (test_saved_attempts, test_probe, test_lookalikes, test_formats, test_none_is_learned, test_unknown,
                     test_targets,
                     test_covers_and_learning, test_day_patch, test_template, test_spellings, test_more_types,
                     test_robust, test_no_file_guess, test_stem_guard,
                     test_ambiguous_facts, test_hostile_questions, test_synonyms, test_reader_pack, test_enum_meanings,
                     test_nested_containers, test_day8_rows, test_day9_rows, test_row203_union,
                     test_row211_headers, test_row204_patch_skip, test_day21_round2, test_cli):
            try:
                test()
            except Exception as e:  # a crashed check is a failed check, with the rest still run
                check(test.__name__, False, f"raised {type(e).__name__}: {e}\n{traceback.format_exc()}")
        check("nothing under the saved attempts, the real ledger or the solver folder was written",
              snapshot() == before and sorted(p.name for p in HERE.iterdir()) == solver_dir)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    skipped = f" ({len(_skipped)} skipped, not run: {', '.join(_skipped)})" if _skipped else ""
    print(("SELFTEST ok" if not _failed else f"SELFTEST FAILED {len(_failed)}") + skipped)
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
