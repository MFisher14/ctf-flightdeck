#!/usr/bin/env python3
"""F5 (JPEG DCT, matrix encoding) and extra LSB-matching channel orders (Day-26 stego coverage, oracle-audit
honorable mention). Offline, stdlib + Pillow (already used by carve_stego). Nothing is executed.

What it adds, all judged ONLY by stego_containers.validate_container (the lane's existing oracle: a stored
length+CRC, or a checksum-verified gzip/zip). No new confidence path:

  f5_survey(data)    F5 read of a baseline JPEG. The usable carriers are the non-zero AC coefficients
                     (zeros are skipped, which is how F5's shrinkage reads back: a coefficient shrunk to 0 drops
                     out of the stream on both sides), the bit of a carrier is the coefficient's parity with
                     negative values inverted. For each matrix-encoding k = 1..7 (n = 2^k - 1 carriers per
                     group, k message bits = XOR of the 1-based positions of the group's set bits), at carrier
                     offsets 0 and 32 (a 32-bit header read at k=1), for component sets all and Y, both bit
                     orders.
  lsb_extra(data)    LSB-matching/plain-LSB reading of the channel orders the shipped sweep omits (the other
                     four RGB permutations, the six channel pairs) and the reversed scan directions
                     (bottom-up, fully reversed), bits 0 and 1, both bit orders. (+-1 matching changes the
                     LSB exactly as an overwrite does, so extraction is the plain LSB stream; the gap was
                     which orders are read.)

DECLINED, said out loud: F5's password-keyed permutation (java SHA1PRNG shuffle) is NOT implemented, because
there is no reference implementation here to prove it against and a half-correct permutation can only waste
time. Only the un-permuted order (an embedder run without a password, or a re-implementation that skips the
shuffle) is read. Progressive JPEGs (SOF2) are declined as in jpeg_stego.

Never-wrong: a payload is PLAIN only when validate_container proves it and jpeg_stego._provable accepts its
substance; two different proven payloads are ambiguous -> None. A structure-only file (png...) is an unsure
candidate; random bytes give nothing. Bounded: coefficient stream, output bytes, reading count and a deadline.
"""
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))

import stego_containers as sc      # noqa: E402
import carve_stego as cs           # noqa: E402
import jpeg_stego as js            # noqa: E402

MAX_CARRIERS = 1 << 19      # non-zero AC carriers read per component set
MAX_OUT_BYTES = 1 << 13     # output bytes judged per (k, offset) reading
HEADER_CARRIERS = 32        # the k=1 header some F5 writers put first
MAX_CANDIDATES = 8


def _bits_of(coeffs, tags, comp):
    bits = bytearray()
    nblocks = min(len(coeffs) // 64, len(tags))
    for b in range(nblocks):
        if comp is not None and tags[b] != comp:
            continue
        base = b * 64
        for k in range(1, 64):
            c = coeffs[base + k]
            if c:
                bits.append((c & 1) if c > 0 else 1 - (c & 1))
        if len(bits) >= MAX_CARRIERS:
            return bits[:MAX_CARRIERS]
    return bits


def matrix_decode(bits, k, offset=0, max_bytes=MAX_OUT_BYTES):
    """F5 matrix decoding: groups of n = 2^k - 1 carrier bits give k message bits, the XOR of the 1-based
    positions of the group's set bits. Returns the message bits packed MSB first, as bytes."""
    n = (1 << k) - 1
    need_bits = max_bytes * 8
    groups = min((len(bits) - offset) // n, (need_bits + k - 1) // k)
    if groups <= 0:
        return b""
    hashes = [0] * groups
    end = offset + groups * n
    for p in range(offset, end):
        if bits[p]:
            q = p - offset
            hashes[q // n] ^= (q % n) + 1
    out = bytearray()
    acc = nacc = 0
    for h in hashes:
        acc = (acc << k) | h
        nacc += k
        while nacc >= 8:
            nacc -= 8
            out.append((acc >> nacc) & 0xFF)
        acc &= (1 << nacc) - 1
        if len(out) >= max_bytes:
            break
    return bytes(out)


def _reverse_bits_in_bytes(b):
    return bytes(int(f"{x:08b}"[::-1], 2) for x in b)


def _judge(blob, tag, plains, cands, readings):
    if len(blob) < 8:
        return
    f = sc.validate_container(blob)
    if f.plain is not None and js._provable(f.plain):
        plains.setdefault(bytes(f.plain), []).append(f"{tag}; {f.method}")
        readings.append(f"PLAIN {tag}: {len(f.plain)} bytes ({f.method})")
    elif f.plain is None:
        for name, value in f.candidates or []:
            if name == "carved_file":       # a complete file structure only; never decoded_text noise
                cands.append((f"f5_{tag.replace(' ', '_')}", bytes(value)))
                readings.append(f"unsure {tag}: complete {cs.sniff(value)} structure, no checksum")


def f5_survey(data, deadline=None):
    plains, cands, readings, notes = {}, [], [], []
    if not data or data[:2] != b"\xff\xd8":
        return plains, cands, readings, ["not a JPEG"]
    tags = []
    try:
        coeffs = js._decode_coeffs(bytes(data), limit_bits=MAX_CARRIERS * 8, comp_out=tags)
    except Exception as e:
        return plains, cands, readings, [f"f5: coefficient domain not read: {type(e).__name__}"]
    if len(coeffs) < 64:
        return plains, cands, readings, ["f5: no decodable DCT blocks"]
    for cname, comp in (("all", None), ("Y", 0)):
        if comp is not None and len(set(tags)) <= 1:
            continue                        # grayscale: Y is the same stream as all
        bits = _bits_of(coeffs, tags, comp)
        for off in (0, HEADER_CARRIERS):
            for k in range(1, 8):
                if deadline and time.monotonic() > deadline:
                    notes.append("f5: out of time")
                    return plains, cands, readings, notes
                blob = matrix_decode(bits, k, off)
                for msb in (True, False):
                    b = blob if msb else _reverse_bits_in_bytes(blob)
                    _judge(b, f"f5 {cname} k{k} off{off} {'msb' if msb else 'lsb'}-first",
                           plains, cands, readings)
    notes.append(f"f5: {len(coeffs) // 64} blocks read, k=1..7, offsets 0/{HEADER_CARRIERS}")
    return plains, cands, readings, notes


def _px_dict(im):
    if im.mode not in ("L", "RGB"):
        im = im.convert("RGB" if len(im.getbands()) > 1 else "L")
    return im, {"width": im.width, "height": im.height, "mode": im.mode, "channels": len(im.getbands()),
                "depth": 8, "data": im.tobytes(), "palette": None}


def lsb_extra(data, deadline=None):
    """The reading orders carve_stego.lsb_scan omits (see module doc). Same (plains, cands, readings, notes)."""
    plains, cands, readings, notes = {}, [], [], []
    im = cs._pillow(bytes(data)) if data else None
    return _lsb_extra_im(im, deadline)


def lsb_extra_px(px, deadline=None):
    """carve_stego.lsb_scan's hook: the proven plains {payload: [methods]} of a pixel dict (no candidates)."""
    from PIL import Image
    try:
        im = Image.frombytes(px["mode"], (px["width"], px["height"]), bytes(px["data"]))
    except Exception:
        return {}
    return _lsb_extra_im(im, deadline)[0]


def _lsb_extra_im(im, deadline=None):
    plains, cands, readings, notes = {}, [], [], []
    if im is None:
        return plains, cands, readings, ["lsb_extra: image not decoded"]
    if im.width * im.height > cs.MAX_PIXELS:
        return plains, cands, readings, ["lsb_extra: image too large"]
    im, _ = _px_dict(im)
    from PIL import Image
    variants = {"up": im.transpose(Image.FLIP_TOP_BOTTOM), "rev": im.transpose(Image.ROTATE_180)}
    m = im.mode
    if len(m) == 3:
        extra = ["GRB", "GBR", "RBG", "BRG", m[0] + m[1], m[1] + m[0], m[0] + m[2], m[2] + m[0],
                 m[1] + m[2], m[2] + m[1]]
        base = [m, m[::-1], m[0], m[1], m[2]]
    else:
        extra, base = [], [m]
    jobs = [("fwd", im, c, o) for c in extra for o in ("xy", "yx")]
    for vname, vim in variants.items():
        jobs += [(vname, vim, c, o) for c in base + extra for o in ("xy", "yx")]
    cache = {}
    for dname, vim, chans, order in jobs:
        if deadline and time.monotonic() > deadline:
            notes.append("lsb_extra: out of time")
            break
        px = cache.get(dname)
        if px is None:
            px = cache[dname] = _px_dict(vim)[1]
        for bit in (0, 1):
            for msb in (True, False):
                blob = cs.lsb_extract(px, chans, bit, order, msb, max_bytes=js.SURVEY_BYTES)
                _judge(blob, f"lsb {dname} bit{bit} {chans} {order} {'msb' if msb else 'lsb'}-first",
                       plains, cands, readings)
    notes.append(f"lsb_extra: {len(jobs)} channel/direction sets x bits 0,1 x both bit orders")
    return plains, cands, readings, notes


def survey(data, deadline=None):
    """{plain, method, candidates, readings, notes}; plain only for exactly ONE distinct proven payload."""
    res = {"plain": None, "method": "", "channel": "f5-lsb-extra", "candidates": [], "readings": [], "notes": []}
    plains, cands, readings, notes = {}, [], [], []
    for fn in (f5_survey, lsb_extra):
        try:
            p, c, r, n = fn(data, deadline)
        except Exception as e:                  # never raise into a runner
            p, c, r, n = {}, [], [], [f"{fn.__name__}: {type(e).__name__}"]
        for k, v in p.items():
            plains.setdefault(k, []).extend(v)
        cands += c
        readings += r
        notes += n
    res["readings"], res["notes"] = readings, notes
    if len(plains) == 1:
        payload, methods = next(iter(plains.items()))
        res["plain"], res["method"] = payload, methods[0]
        return res
    if len(plains) > 1:
        res["notes"].append(f"ambiguous: {len(plains)} distinct proven payloads: none is plain")
        cands = [(f"f5_proven_{i}", k) for i, k in enumerate(plains)] + cands
    seen, out = set(), []
    for name, value in cands:
        if value in seen:
            continue
        seen.add(value)
        out.append((name, value))
    res["candidates"] = out[:MAX_CANDIDATES]
    return res


if __name__ == "__main__":
    if not sys.argv[1:] or any(a in ("-h", "--help") for a in sys.argv[1:]):
        print("usage: f5_stego.py <jpeg> [...]", file=sys.stderr if not sys.argv[1:] else sys.stdout)
        raise SystemExit(2 if not sys.argv[1:] else 0)
    for path in sys.argv[1:]:
        try:
            r = survey(Path(path).read_bytes())
        except (OSError, ValueError, TypeError, OverflowError) as exc:
            print(f"f5_stego.py: {exc}", file=sys.stderr)
            raise SystemExit(2)
        print(path, "PLAIN" if r["plain"] is not None else "none", r["method"], r["notes"])
