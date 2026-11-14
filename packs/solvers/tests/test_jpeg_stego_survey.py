#!/usr/bin/env python3
"""Offline tests of the JPEG-domain stego survey (research ticket #9): solvers/toolkits/jpeg_stego.survey.

  .venv/bin/python tests/test_jpeg_stego_survey.py

Synthetic fixtures only, built in memory; nothing is run, no network, no token. The invariant is the
never-wrong rule: a payload is PLAIN only when a stored length+CRC (or checksum-verified file) proves it;
a clean photo-like JPEG gives plain None; a corrupt carrier gives plain None.
"""
import io
import os
import random
import struct
import sys
import tempfile
import zlib
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
os.environ.setdefault("CTF_TESTING", "1")
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_jpeg_survey_")
sys.dont_write_bytecode = True
for p in ("tests", "solvers/toolkits", "solvers/common", "tools"):
    sys.path.insert(0, str(REPO / p))

import jpeg_stego as js                      # noqa: E402
import test_wave3_stego as w3                # noqa: E402  (its jsteg_encode builds a carrier)
from PIL import Image                        # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)


def enc(c, W=64, H=48):
    return w3.jsteg_encode(c, W=W, H=H)


def rev_bytes(b):
    return bytes(int(f"{x:08b}"[::-1], 2) for x in b)


def photo(seed, w=96, h=64, **save):
    rnd = random.Random(seed)
    im = Image.new("RGB", (w, h))
    px = im.load()
    kind = seed % 3
    for y in range(h):
        for x in range(w):
            if kind == 0:       # noise
                px[x, y] = (rnd.randrange(256), rnd.randrange(256), rnd.randrange(256))
            elif kind == 1:     # gradient + grain
                px[x, y] = ((x * 3 + rnd.randrange(8)) % 256, (y * 4 + rnd.randrange(8)) % 256, (x + y) % 256)
            else:               # blocks (a flat, synthetic-looking image)
                px[x, y] = (((x // 16) * 40) % 256, ((y // 16) * 60) % 256, 128)
    bb = io.BytesIO()
    im.save(bb, "JPEG", **save)
    return bb.getvalue()


def main():
    pl = b"flag{jpeg-survey-OK}"
    carrier = enc(w3.container_be(pl))
    r = js.survey(carrier)
    check("jsteg carrier (CRC container) -> plain == payload", r["plain"] == pl, r["notes"])
    check("the reading is named (dct ... msb-first)", "dct" in r["method"], r["method"])
    check("several readings found it (all/Y x rules), none contradicting",
          sum(1 for x in r["readings"] if x.startswith("PLAIN")) >= 2, r["readings"][:3])

    # bit order reversed inside every byte: the lsb-first reading proves it
    rc = enc(rev_bytes(w3.container_be(pl)))
    r = js.survey(rc)
    check("lsb-first bit order carrier -> plain", r["plain"] == pl and "lsb-first" in r["method"], r["method"])

    # a larger payload, multi block
    big = bytes((i * 37 + 11) & 0xFF for i in range(60))
    r = js.survey(enc(w3.container_be(big), W=48, H=48))
    check("multi-block payload -> plain", r["plain"] == big)

    # corrupt CRC -> never plain
    bad = bytearray(w3.container_be(pl))
    bad[9] ^= 1
    r = js.survey(enc(bytes(bad)))
    check("corrupt CRC carrier -> plain None", r["plain"] is None, r["notes"])

    # unproven printable text only (no CRC) -> unsure candidate or None, never plain
    txt = b"secret message with no checksum at all, just text\x00"
    r = js.survey(enc(txt))
    check("printable-but-unproven jsteg text -> not plain", r["plain"] is None, r["method"])

    # adversarial: ordinary photo-like JPEGs of many kinds -> no false plain, no candidates
    fp = []
    for seed in range(120):
        kw = {"quality": (50, 75, 90, 95)[seed % 4]}
        if seed % 5 == 0:
            kw["subsampling"] = 0
        if seed % 7 == 0:
            kw["optimize"] = True
        rr = js.survey(photo(seed, **kw))
        if rr["plain"] is not None or rr["candidates"]:
            fp.append((seed, rr["plain"], rr["candidates"][:1]))
    check("120 clean JPEGs (noise/gradient/flat, q50-95, 4:4:4, optimized): no plain, no candidate", not fp, fp[:2])

    # a tiny/degenerate checksum match (a flat plane) is never plain
    check("_provable refuses 1-byte and constant payloads",
          not js._provable(b"\xff") and not js._provable(b"AAAAAAAAAA") and js._provable(b"abcdefgh"))

    # progressive: coefficient domain declined with a note, pixel domain still read, nothing plain
    prog = photo(2, quality=85, progressive=True)
    r = js.survey(prog)
    check("progressive JPEG -> plain None, declines the DCT domain out loud",
          r["plain"] is None and any("coefficient domain not read" in n for n in r["notes"]), r["notes"])

    # non-JPEG / hostile
    check("non-JPEG -> None", js.survey(b"PK\x03\x04junk")["plain"] is None)
    check("truncated JPEG does not raise", js.survey(carrier[:90])["plain"] is None)
    check("empty -> None", js.survey(b"")["plain"] is None)

    # two different proven payloads would be ambiguous: pixel_survey/coefficient merge refuses
    # (merge rule exercised directly through the plains dict contract)
    a, b2 = w3.container_be(b"ABCDEFGHIJ"), w3.container_be(b"KLMNOPQRST")
    pa = js.coefficient_survey(enc(a))[0]
    pb = js.coefficient_survey(enc(b2))[0]
    check("each carrier proves exactly one distinct payload", len(pa) == 1 and len(pb) == 1, (pa, pb))

    import shutil
    shutil.rmtree(paths.workdir(), ignore_errors=True)
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED[:8]))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
