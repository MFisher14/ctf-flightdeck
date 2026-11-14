#!/usr/bin/env python3
"""Shared environment and independent encoders for the Mobile codec_search check suites.

Carried from the Huntress Day 20 / Day 21 mobile harnesses (tests/test_day20_mobile.py,
tests/day21_mobile_specimens.py, tests/day21r2_mobile_harness.py) without their day data: every package is
built here by encoders written in this file, so the truth of each is known by construction. Nothing reads
challenges/ or a saved Day 20 APK; the Day 21 template is always the synthetic one.

The environment is a private judge ledger under a temp folder ($CTF_WORKDIR, restored on exit), the judge
ledger on (the seed's judged names answer), no rehearsal mask. Use it as

    with isolated():
        ... solve(apk(doc("base64", b64(code.encode())))) ...

or through the `mobile_env` pytest fixture each suite defines on top of `isolated()`.

Used by: test_day20_mobile_gaps, test_nw_mobile_decoy, test_wave17_mobile_sub256,
test_wave124_mobile_container, test_day21fp_mobile.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import shutil
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
for _d in ("solvers/common", "solvers/mobile-android"):
    if str(REPO / _d) not in sys.path:
        sys.path.insert(0, str(REPO / _d))

import labels  # noqa: E402
import codec_search as C  # noqa: E402

C._patch = None   # the shipped solver only: never a day_patch.py beside it

TMP = Path(tempfile.mkdtemp(prefix="mobile_codec_env_"))
WORKDIR = TMP / "challenges"
FAILED = []
PASSED = []
PZ = C.PUZZLE
V1 = "huntress.mobile.puzzle.v1"
SYNTAX = "ANS- followed by exactly 16 uppercase hexadecimal characters; no spaces or explanatory text"
QUESTION = {"id": "answer", "qid": "answer", "answer_id": "answer", "answer_format": {"kind": "pattern", "syntax": SYNTAX},
            "question": "Recover the backend answer code for this case. Submit only the exact answer code."}

_ENV_SET = {"CTF_WORKDIR": str(WORKDIR)}
_ENV_DROP = ("CTF_JUDGE_LEDGER", "CTF_TESTING", "CTF_LEDGER_MASK")


@contextlib.contextmanager
def isolated():
    """A private ledger for the block: $CTF_WORKDIR under this module's temp folder, the judge ledger on, no mask.
    The previous values come back on exit, so the rest of a pytest process is untouched."""
    saved = {k: os.environ.get(k) for k in (*_ENV_SET, *_ENV_DROP)}
    os.environ.update(_ENV_SET)
    for k in _ENV_DROP:
        os.environ.pop(k, None)
    fresh()
    try:
        yield
    finally:
        fresh()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def reset_results():
    del FAILED[:]
    del PASSED[:]


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:600]}]"))
    (PASSED if ok else FAILED).append(label)


def fresh():
    shutil.rmtree(WORKDIR, ignore_errors=True)
    labels._cache.clear()


# ---------------------------------------------------------------------------- independent encoders (Day 20)

def code_for(name):
    return "ANS-" + hashlib.sha256(("day20:" + name).encode()).hexdigest()[:16].upper()


def decoy_for(name):
    return "ANS-" + hashlib.sha256(("decoy20:" + name).encode()).hexdigest()[:16].upper()


def b64(b):
    return base64.b64encode(b).decode()


def xor_b64(text, k):
    return b64(bytes(c ^ k for c in text.encode()))


def dex(*strings) -> bytes:
    """A dex with a real string-id table (string_ids_size and offset at 0x38), ULEB128 lengths, MUTF-8 bodies."""
    n = len(strings)
    head = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    struct.pack_into("<II", head, 0x38, n, 0x70)
    data, offs = b"", []
    base_off = 0x70 + 4 * n
    for s in strings:
        b = s.encode() if isinstance(s, str) else s
        ln, uleb = len(b), b""
        while True:
            byte = ln & 0x7F
            ln >>= 7
            uleb += bytes([byte | (0x80 if ln else 0)])
            if not ln:
                break
        offs.append(base_off + len(data))
        data += uleb + b + b"\x00"
    return bytes(head) + b"".join(struct.pack("<I", o) for o in offs) + data


def doc(codec, data, **more):
    return {"schema": V1, "day": 20, "codec": codec, "data": data, **more}


def apk(document, extra=None):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        if document is not None:
            z.writestr(PZ, document if isinstance(document, bytes) else json.dumps(document, separators=(",", ":")))
        for n, b in (extra or {}).items():
            z.writestr(n, b)
    return out.getvalue()


def solve(blob, deliveries=1, question=None):
    attempt = {"artifacts": [{} for _ in range(deliveries)]}
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = C.solve_set([dict(question or QUESTION)], {}, {"set": 1, "delivery": blob, "delivery_name": "d.apk",
                                                             "attempt": attempt})
    return out["answer"], err.getvalue(), dict(C.LAST)


def options(answer):
    got = labels.parse(answer) if isinstance(answer, str) and labels.is_unsure(answer) else None
    return (got["k"], [tuple(o) for o in got["o"]]) if got is not None else (None, [])


def unsure(label, blob, truth, key=None, first=None, rank=1):
    """Unsure under `key`, the truth at `rank` (named `first` there, when given), the same under a Mastery's budget;
    plain once that name is accepted."""
    fresh()
    out, err, last = solve(blob)
    k, opts = options(out)
    at = next((i + 1 for i, (_, v) in enumerate(opts) if v == truth), 0)
    name = opts[at - 1][0] if at else None
    ok = at == rank and (key is None or k == key) and (first is None or name == first)
    check("%s: unsure%s, the truth option %d%s" % (label, " under " + key if key else "", rank, " (%s)" % first if first else ""),
          ok, "%s %s | %s" % (k, opts, last.get("route")))
    short, _, _ = solve(blob, deliveries=5)
    check("%s: ... the same answer under a five-delivery Mastery's budget" % label, short == out, short)
    if ok:
        labels.learn(k, name, "accepted", attempt_id="t", answer_ids=["answer"])
        again, _, _ = solve(blob)
        check("%s: ... plain once the judge has accepted %s" % (label, name), again == truth, again)
    fresh()
    return out


def none(label, blob):
    fresh()
    out, _, last = solve(blob)
    check("%s: None" % label, out is None, "%s | %s" % (out, last.get("route")))


def plain(label, blob, truth):
    fresh()
    out, err, last = solve(blob)
    check("%s: plain, the truth" % label, out == truth, "%s | %s | %s" % (out, last.get("route"), options(out)))


# ---------------------------------------------------------------------------- Day 21 encoders (synthetic only)

def code21(name):
    return "ANS-" + hashlib.sha256(("day21r2:" + name).encode()).hexdigest()[:16].upper()


def decoy21(name):
    return "ANS-" + hashlib.sha256(("decoy21r2:" + name).encode()).hexdigest()[:16].upper()


def zip_of(members: dict) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in members.items():
            z.writestr(n, b)
    return out.getvalue()


def synthetic_classes(day=21, codec="dynamic", topic="dynamic loading", extra=()):
    long = ("Huntress Mobile Arena — Day %d\\nNext Stage\\n\\nCase reference: MOB-%d-6AE5A9BC36\\n\\n"
            "Analyze the public APK and cross the %s boundary." % (day, day, topic))
    return dex(*sorted(["&client_secret=SECRET-2A7DBD687C71133530CCC9&proof=", "<init>", "CODEC", "CONTROL", "DAY",
                        "DAY-%d:%s:%s" % (day, codec, topic), long, "Landroid/app/Activity;",
                        "Lcom/huntress/mobile/d21/v6ae5a9bc3622/MainActivity;", "Ljava/lang/String;",
                        "Missing challenge answer or case_id", "answer", "case_id", "describe", codec,
                        "getStringExtra", "http://127.0.0.1:19090/mobile/attempt/d21-58f87cca4defcc23/evidence?case_id=",
                        "loadUrl", "onCreate", "setText", *extra]))


def template21():
    """{name: bytes} of a synthetic Day 20-shaped APK without its document and payload."""
    return {"AndroidManifest.xml": b"\x03\x00\x08\x00" + b"\x00" * 60, "classes.dex": synthetic_classes(),
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n"}


def doc21(codec="dynamic", data="assets/payload.dex", **more):
    return {"schema": V1, "day": 21, "codec": codec, "data": data, **more}


def package(tmpl, document, members, drop=()):
    m = {n: b for n, b in tmpl.items() if n not in drop and n not in members}
    out = {"AndroidManifest.xml": m.pop("AndroidManifest.xml", b"")}
    if document is not None:
        out[PZ] = json.dumps(document, separators=(",", ":")).encode()
    out.update(members)
    out.update(m)
    return zip_of(out)


HERMES_MAGIC = 0x1F1903C103BC1FC6


def hermes(strings, version=94):
    """Hermes bytecode with a real string table: the 128-byte header (string count, overflow count, storage size), one
    16-byte function header, one string-kind entry, the 32-bit small-string entries (bit 0 is_utf16, 23 bits offset,
    8 bits length; 255 sends to the overflow table) and the storage, the strings back to back with nothing between
    them. A (text, True) item is stored UTF-16LE, its length in code units."""
    storage, small, over = b"", [], []
    for item in strings:
        text, wide = item if isinstance(item, tuple) else (item, False)
        raw = text.encode("utf-16-le") if wide else text.encode("latin-1")
        units = len(raw) // 2 if wide else len(raw)
        off = len(storage)
        storage += raw
        if units >= 255:
            small.append(int(wide) | (len(over) << 1) | (255 << 24))
            over.append((off, units))
        else:
            small.append(int(wide) | (off << 1) | (units << 24))

    def pad(b):
        return b + b"\0" * (-len(b) % 4)
    n = len(strings)
    body = struct.pack("<4I", 0x40000001, 0x40000002, 0x40000003, 0x40000004)      # one function header
    body += struct.pack("<I", n)                                                      # one kind run: n strings
    body += pad(struct.pack("<%dI" % n, *small)) + b"".join(struct.pack("<II", o, l) for o, l in over)
    body = pad(body) + pad(storage) + b"\0" * 64
    head = bytearray(128)
    struct.pack_into("<QI", head, 0, HERMES_MAGIC, version)
    struct.pack_into("<8I", head, 32, 128 + len(body), 0, 1, 1, 0, n, len(over), len(storage))
    return bytes(head) + body


def dotnet(us, names=("<Module>", "Huntress.Arena.dll", "AnswerProvider", "GetCode")):
    """A PE file holding a .NET metadata root (BSJB, version text, stream headers) with a #Strings and a #US heap;
    each #US entry is a length byte, the UTF-16LE text and one flag byte."""
    heap = b"\0"
    for t in us:
        b = t.encode("utf-16-le") + b"\0"
        assert len(b) < 128
        heap += bytes([len(b)]) + b
    heap += b"\0" * (-len(heap) % 4)
    strs = b"\0" + b"".join(x.encode() + b"\0" for x in names)
    strs += b"\0" * (-len(strs) % 4)
    version = b"v4.0.30319\0\0"

    def sh(off, size, name):
        nm = name + b"\0"
        return struct.pack("<II", off, size) + nm + b"\0" * (-len(nm) % 4)
    fixed = 4 + 8 + 4 + len(version) + 4
    first = fixed + len(sh(0, 0, b"#Strings")) + len(sh(0, 0, b"#US"))
    root = (b"BSJB" + struct.pack("<HHI", 1, 1, 0) + struct.pack("<I", len(version)) + version + struct.pack("<HH", 0, 2)
            + sh(first, len(strs), b"#Strings") + sh(first + len(strs), len(heap), b"#US") + strs + heap)
    mz = bytearray(0x80)
    mz[:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, 0x80)
    return bytes(mz) + b"PE\0\0" + b"\0" * 0x7C + root + b"\0" * 32


def axml(*strings):
    """Android binary XML: the RES_XML_TYPE header and a UTF-16 string pool."""
    count = len(strings)
    offs, data = [], b""
    for t in strings:
        offs.append(len(data))
        data += struct.pack("<H", len(t)) + t.encode("utf-16-le") + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    hsize = 28
    sstart = hsize + 4 * count
    pool = (struct.pack("<HHIIIIII", 0x0001, hsize, sstart + len(data), count, 0, 0, sstart, 0)
            + b"".join(struct.pack("<I", o) for o in offs) + data)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pool)) + pool


def rn_bundle(*exprs):
    """A React Native (Metro) bundle whose functions return the given JavaScript expressions."""
    body = "".join("function f%d(){return %s}e.f%d=f%d;" % (i, x, i, i) for i, x in enumerate(exprs))
    return ('__d(function(g,r,i,a,m,e,d){"use strict";Object.defineProperty(e,"__esModule",{value:!0});var t=r(d[0]);'
            '%se.CONTRACT="return the code to the backend"},420,[1,2]);' % body).encode()


def run_parts(parts):
    """Script mode: run every part under a private ledger, print the tally, return the exit code."""
    import time
    import traceback
    t0 = time.perf_counter()
    reset_results()
    with isolated():
        for part in parts:
            try:
                part()
            except Exception as e:
                traceback.print_exc()
                check("%s raised %s: %s" % (part.__name__, type(e).__name__, e), False)
    print("%s; %d passed (%.1f s)" % ("FAILED %d: %s" % (len(FAILED), "; ".join(FAILED)) if FAILED else "all checks passed",
                                      len(PASSED), time.perf_counter() - t0))
    return 1 if FAILED else 0


def run_part(part):
    """pytest mode: one part under a private ledger; AssertionError naming every failed check."""
    reset_results()
    with isolated():
        part()
    assert PASSED, "%s ran no checks" % part.__name__
    assert not FAILED, "%s: %d failed: %s" % (part.__name__, len(FAILED), "; ".join(FAILED))
