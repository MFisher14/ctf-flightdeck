#!/usr/bin/env python3
"""Day-26 stego coverage: F5 (matrix encoding, shrinkage) and extra LSB-matching orders (solvers/toolkits/f5_stego.py).

  .venv/bin/python -I tests/test_day26_stego_f5.py      # from the checkout root

Synthetic carriers built in memory. Invariant: PLAIN only for a payload a stored length+CRC proves; clean
covers, noise and near-miss (corrupted CRC) carriers give plain None.
"""
import io
import os
import random
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ.setdefault("CTF_TESTING", "1")
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_day26_f5_")
sys.dont_write_bytecode = True
for p in ("tests", "solvers/toolkits", "solvers/common", "tools"):
    sys.path.insert(0, str(REPO / p))

import f5_stego as f5                        # noqa: E402
import jpeg_stego as js                      # noqa: E402
import carve_stego as cs                     # noqa: E402
import test_wave3_stego as w3                # noqa: E402
from PIL import Image                        # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)


# ---- a tiny baseline grayscale JPEG writer that takes explicit AC coefficients ---------------------

def jpeg_from_blocks(blocks, W, H):
    """blocks: list of 63-int AC lists (index 1..63 of the zigzag block), DC fixed at 2."""
    bw = w3._BitWriter()
    pred = 0
    for ac in blocks:
        diff = 2 - pred
        pred = 2
        s = w3._size_of(diff)
        code, length = w3._DC[s]
        bw.put(code, length)
        if s:
            bw.put(w3._mant(diff, s), s)
        last = max((i for i, v in enumerate(ac) if v), default=-1)
        run = 0
        for i in range(last + 1):
            v = ac[i]
            if v == 0:
                run += 1
                continue
            while run > 15:
                code, length = w3._AC[0xF0]
                bw.put(code, length)
                run -= 16
            sz = w3._size_of(v)
            code, length = w3._AC[(run << 4) | sz]
            bw.put(code, length)
            bw.put(w3._mant(v, sz), sz)
            run = 0
        if last < 62:
            code, length = w3._AC[0x00]
            bw.put(code, length)
    bw.flush()
    out = bytearray(b"\xFF\xD8")
    out += w3._seg(0xDB, bytes([0]) + bytes([1] * 64))
    out += w3._seg(0xC0, struct.pack(">BHHB", 8, H, W, 1) + struct.pack(">BBB", 1, 0x11, 0))
    out += w3._seg(0xC4, bytes([0x00]) + bytes(w3._BITS_DC) + bytes(w3._VALS_DC))
    out += w3._seg(0xC4, bytes([0x10]) + bytes(w3._BITS_AC) + bytes(w3._VALS_AC))
    out += w3._seg(0xDA, bytes([1]) + struct.pack(">BB", 1, 0x00) + bytes([0, 63, 0]))
    out += bw.out
    out += b"\xFF\xD9"
    return bytes(out)


def cover_blocks(nb, rnd, density=0.5, ones=0.15):
    blocks = []
    for _ in range(nb):
        ac = [0] * 63
        for i in range(63):
            if rnd.random() < density * (1.0 if i < 20 else 0.3):
                m = 1 if rnd.random() < ones else rnd.randrange(2, 12)
                ac[i] = m if rnd.random() < 0.5 else -m
        blocks.append(ac)
    return blocks


def bit(c):
    return (c & 1) if c > 0 else 1 - (c & 1)


def f5_embed(blocks, msg_bits, k, header_bits=None):
    """F5 matrix embedding on the non-zero AC coefficients, un-permuted; shrinkage handled by re-forming
    the group from the same start. Returns True when everything fit."""
    refs = [(b, i) for b, ac in enumerate(blocks) for i in range(63) if ac[i] != 0]
    pos = 0

    def val(r):
        return blocks[r[0]][r[1]]

    def group(n, want):
        nonlocal refs, pos
        while True:
            if pos + n > len(refs):
                return False
            win = refs[pos:pos + n]
            h = 0
            for j, r in enumerate(win):
                if bit(val(r)):
                    h ^= j + 1
            d = h ^ want
            if d == 0:
                pos += n
                return True
            r = win[d - 1]
            b, i = r
            blocks[b][i] += -1 if blocks[b][i] > 0 else 1
            if blocks[b][i] == 0:       # shrinkage: the carrier drops out, the group is formed again
                refs = refs[:pos + d - 1] + refs[pos + d:]
                continue
            pos += n
            return True

    for hb in header_bits or []:
        if not group(1, hb):
            return False
    n = (1 << k) - 1
    for i in range(0, len(msg_bits), k):
        chunk = msg_bits[i:i + k]
        chunk = chunk + [0] * (k - len(chunk))
        want = 0
        for b in chunk:
            want = (want << 1) | b
        if not group(n, want):
            return False
    return True


def to_bits(data):
    return [(x >> (7 - i)) & 1 for x in data for i in range(8)]


def f5_carrier(container, k, header=False, seed=1, nb=900):
    rnd = random.Random(seed)
    blocks = cover_blocks(nb, rnd)
    hdr = [rnd.randrange(2) for _ in range(32)] if header else None
    ok = f5_embed(blocks, to_bits(container), k, hdr)
    assert ok, "cover too small"
    return jpeg_from_blocks(blocks, 8 * 30, 8 * 30)


# ---- LSB-matching (+-1) embedder in a chosen channel order and scan direction ----------------------

def lsb_matching_png(container, chans="GRB", direction="up", seed=2, W=64, H=48, bitpos=0):
    rnd = random.Random(seed)
    im = Image.new("RGB", (W, H))
    px = im.load()
    for y in range(H):
        for x in range(W):
            px[x, y] = tuple(rnd.randrange(30, 220) for _ in range(3))
    work = {"up": im.transpose(Image.FLIP_TOP_BOTTOM), "rev": im.transpose(Image.ROTATE_180), "fwd": im}[direction]
    data = bytearray(work.tobytes())
    idx = ["RGB".index(c) for c in chans]
    bits = to_bits(container)
    j = 0
    for p in range(W * H):
        for ci in idx:
            if j >= len(bits):
                break
            o = p * 3 + ci
            if ((data[o] >> bitpos) & 1) != bits[j]:
                data[o] += rnd.choice((-1, 1)) if bitpos == 0 else 0     # +-1 matching, never an overwrite
                if ((data[o] >> bitpos) & 1) != bits[j]:
                    data[o] ^= 1 << bitpos
            j += 1
    work = Image.frombytes("RGB", (W, H), bytes(data))
    back = {"up": lambda i: i.transpose(Image.FLIP_TOP_BOTTOM), "rev": lambda i: i.transpose(Image.ROTATE_180),
            "fwd": lambda i: i}[direction](work)
    bb = io.BytesIO()
    back.save(bb, "PNG")
    return bb.getvalue()


def main():
    pl = b"flag{f5-matrix-OK-payload}"
    cont = w3.container_be(pl)

    # F5 at several k, with and without the 32-carrier k=1 header, shrinkage in the cover (ones=0.15)
    for k in (1, 2, 3, 4, 5, 7):
        for header in (False, True):
            jpg = f5_carrier(cont, k, header)
            r = f5.survey(jpg)
            check(f"F5 k={k} header={header}: recovered, self-verified",
                  r["plain"] == pl and "f5" in r["method"], (r["method"], r["notes"]))
    jpg = f5_carrier(cont, 3)
    r = js.survey(jpg)
    check("jpeg_stego.survey reaches the F5 reading", r["plain"] == pl, r["notes"])
    # a gzip payload (checksum-verified file) via F5
    import gzip
    gz = gzip.compress(b"secret text of a gz payload " * 3)
    r = f5.survey(f5_carrier(gz, 2, seed=5))
    check("F5 gzip payload is recovered (checksum-verified)", r["plain"] == gz, r["notes"])

    # LSB matching in orders the shipped sweep omits
    for chans, direction in (("GRB", "fwd"), ("RB", "fwd"), ("RGB", "up"), ("GBR", "rev"), ("BG", "up")):
        png = lsb_matching_png(cont, chans, direction)
        r = f5.lsb_extra(png)
        got = list(r[0])
        check(f"LSB-matching {chans}/{direction}: recovered", got == [pl], (got, r[3]))
        im = cs._pillow(png)
        old = [h for h in cs.lsb_scan({"mode": im.mode, "channels": 3, "width": im.width, "height": im.height,
                                       "depth": 8, "data": im.tobytes(), "palette": None}) if h.get("data") == pl]
        print(f"     info: {chans}/{direction} found by the lsb_scan hook: {bool(old)}")
    im = cs._pillow(lsb_matching_png(cont, "GRB", "fwd"))
    px = {"mode": "RGB", "channels": 3, "width": im.width, "height": im.height, "depth": 8, "data": im.tobytes(), "palette": None}
    hits = cs.lsb_scan(px)
    check("carve_stego.lsb_scan hook returns the GRB payload", any(h["data"] == pl for h in hits), [h["method"] for h in hits])

    # never-wrong
    rnd = random.Random(99)
    jb = jpeg_from_blocks(cover_blocks(300, rnd), 8 * 30, 8 * 10)
    check("clean synthetic JPEG: plain None", f5.survey(jb)["plain"] is None)
    bad = bytearray(cont)
    bad[9] ^= 1
    r = f5.survey(f5_carrier(bytes(bad), 3))
    check("F5 carrier with a corrupt CRC: plain None", r["plain"] is None, r["method"])
    r = f5.lsb_extra(lsb_matching_png(bytes(bad), "GRB", "fwd"))
    check("LSB carrier with a corrupt CRC: no plain", not r[0], list(r[0]))
    check("non-image bytes: nothing, no raise", f5.survey(b"hello world" * 20)["plain"] is None)
    check("truncated JPEG: nothing, no raise", f5.survey(jb[:len(jb) // 2])["plain"] is None)

    # fuzz: clean/noise/near-miss images, PLAIN(bad) must be 0, never raise
    fz_bad = fz_n = 0
    for s in range(400):
        r2 = random.Random(1000 + s)
        kind = s % 3
        if kind == 0:
            data = jpeg_from_blocks(cover_blocks(120, r2, density=r2.random()), 8 * 12, 8 * 10)
        elif kind == 1:
            im = Image.new("RGB", (40, 32))
            im.putdata([tuple(r2.randrange(256) for _ in range(3)) for _ in range(40 * 32)])
            bb = io.BytesIO()
            im.save(bb, "PNG")
            data = bb.getvalue()
        else:       # near miss: a real carrier with one bit of the length field flipped
            b2 = bytearray(cont)
            b2[r2.randrange(0, 4)] ^= 1 << r2.randrange(8)
            data = lsb_matching_png(bytes(b2), "RGB", "fwd", seed=s)
        try:
            res = f5.survey(data)
        except Exception as e:
            check(f"fuzz {s} raised {type(e).__name__}", False)
            continue
        fz_n += 1
        if res["plain"] is not None:
            fz_bad += 1
    check(f"fuzz: {fz_n} clean/noise/near-miss inputs, PLAIN(bad)={fz_bad}", fz_bad == 0 and fz_n == 400)

    # cost on a larger image
    import time
    big = Image.new("RGB", (1200, 900))
    big.putdata([(random.Random(i).randrange(256),) * 3 for i in range(0, 1)] * 1 + [(i * 7 % 256, i * 13 % 256, i % 256) for i in range(1200 * 900 - 1)])
    bb = io.BytesIO()
    big.save(bb, "PNG")
    t = time.monotonic()
    r = f5.lsb_extra(bb.getvalue())
    dt = time.monotonic() - t
    print(f"     info: lsb_extra on 1200x900 took {dt:.1f}s")
    check("large image: no plain, bounded time (<60 s)", not r[0] and dt < 60, dt)

    print(f"\n{'FAILED: ' + ', '.join(FAILED) if FAILED else 'all passed'}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
