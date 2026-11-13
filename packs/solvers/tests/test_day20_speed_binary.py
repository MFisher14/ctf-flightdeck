#!/usr/bin/env python3
"""Pins the Day 20 speed build of the Binary lane, row 387: the bounded transform search of
solvers/binary/packed_tail.py for a config packed by two steps whose keys do not collapse, or by a byte map
before a decompression (asked by generic._choose_config through _packed_choice, only when the walk found no
CRC-valid container).

  .venv/bin/python tests/test_day20_speed_binary.py

1. Two-key compositions read whole: (b + k) ^ K and (b ^ K) + k, in a tag/k1/k2/length overlay and in a PK19-style
   overlay (tag, k1, k2, length, digest), as a separate .bin member, and byte-reversed.
2. A byte map before a stream: zlib, gzip, bz2, xz and LZMA-alone under one-key maps (rotation, xor-then-rotate,
   add-then-rotate) and under the two-key maps, at the length-pinned start of a PK19-style header and at the head.
3. A region up to TAIL_MAX (4 MiB since row 387): a config before a 2 MB random tail is read.
4. Decoys, never a config: random tails (4 KB to 4 MiB), a near-valid CRC (one payload bit), two differing configs
   (two-key beside two-key, beside one-key, a stream beside a two-key), another day's config alone.
5. Collapse: adding 0x80 is xor 0x80, so (b + 0x80) ^ 0x80 is the identity; a plain container is no layer of the
   two-key families.
6. Bounds and cost: TWO_KEY_HITS places a magic and family, START_HEADERS decompressions a region; a 2 MB random
   tail costs well under a second (measured; the check allows 1.0 s for a loaded machine).

Offline, no token, a few seconds. Prints one line per check and `ok N passed` at the end; exits 1 on a failure.
"""
import bz2
import contextlib
import gzip
import io
import json
import lzma
import os
import random
import struct
import sys
import tempfile
import time
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_day20_speed_binary_"))
sys.dont_write_bytecode = True
os.environ["CTF_STATE_DIR"] = str(TMP / "state")
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
for _n in ("CTF_PLATFORM_URL", "CTF_KINDS", "CTF_BINARY_FORMS"):
    os.environ.pop(_n, None)
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import generic       # noqa: E402
import packed_tail   # noqa: E402

FAILED, PASSED = [], []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"   [{str(detail)[:400]}]"))
    (PASSED if ok else FAILED).append(name)


def cfg_json(day=20, variant=0):
    return {"campaign": f"BR{day}-{variant:03d}", "domain": f"node-{variant:03d}.day{day}.example.invalid",
            "url": f"https://node-{variant:03d}.day{day}.example.invalid/api/BR{day}-{variant:03d}"}


def record(cfg, key=0x51):
    plain = json.dumps(cfg, separators=(",", ":")).encode()
    return b"HCFG" + struct.pack("<BBHI", 1, key, len(plain), zlib.crc32(plain)) + bytes(b ^ key for b in plain)


def elf(body_len=4096):
    """A minimal ELF64 x86-64 executable: one PT_LOAD covering the whole body, no section table."""
    eh = bytearray(64)
    eh[:4] = b"\x7fELF"
    eh[4:7] = bytes([2, 1, 1])
    struct.pack_into("<HHIQQQIHHHHHH", eh, 16, 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, body_len, body_len, 0x1000)
    body = bytes(eh) + ph
    return body + bytes((i * 7) & 0xFF for i in range(body_len - len(body)))


def rol(v, n):
    n &= 7
    return ((v << n) | (v >> (8 - n))) & 0xFF if n else v


def bmap(fn):
    return lambda r: bytes(fn(b) for b in r)


K1, K2 = 0x3C, 0xA7
# each is the PACKER, the inverse of the unpack its name says
PACK = {
    "add>xor": bmap(lambda b: ((b ^ K2) - K1) & 0xFF),      # unpack (p + K1) ^ K2
    "xor>add": bmap(lambda b: ((b - K1) & 0xFF) ^ K2),      # unpack (p ^ K2) + K1
    "add>xor_b": bmap(lambda b: ((b ^ 0x11) - 0xE5) & 0xFF),
    "xor>add_b": bmap(lambda b: ((b - 0x07) & 0xFF) ^ 0xC3),
    "rol3": bmap(lambda b: rol(b, 3)),
    "xor>rol": bmap(lambda b: rol(b ^ K1, 3) ^ K2),
    "add>rol": bmap(lambda b: rol((b - 0x21) & 0xFF, 2)),
}
STREAM = {
    "zlib": zlib.compress, "gzip": lambda r: gzip.compress(r, mtime=0), "bz2": bz2.compress,
    "xz": lzma.compress, "lzma": lambda r: lzma.compress(r, format=lzma.FORMAT_ALONE),
}


def overlay(packed, tag=b"RS20"):
    return tag + bytes([0, K1, K2]) + struct.pack("<I", len(packed)) + packed


def pk19(packed, tag=b"RS20"):
    """PK19-style: tag, version, k1, k2, pad, u32le length, a 32-byte digest (zeros: nothing checks it), packed."""
    return tag + bytes([1, K1, K2, 0]) + struct.pack("<I", len(packed)) + bytes(32) + packed


def choose(members, day=20):
    packed_tail._CACHE.clear()
    with contextlib.redirect_stderr(io.StringIO()):
        return generic._choose_config(members, day)


def campaign(got):
    return got[0]["json"].get("campaign") if got[0] else None


def main() -> int:
    rec, other, old = record(cfg_json()), record(cfg_json(variant=1)), record(cfg_json(day=19), key=0x41)
    shell = elf()
    rng = random.Random(387)

    # 1. two-key compositions
    for name in ("add>xor", "xor>add", "add>xor_b", "xor>add_b"):
        for lay_name, lay in (("overlay", overlay), ("pk19", pk19)):
            got = choose([("d20--variant-000.elf", shell + b"\0" * 16 + lay(PACK[name](rec)))])
            check(f"{name} {lay_name}: the config is read", campaign(got) == "BR20-000", got[2] or campaign(got))
        got = choose([("d20--variant-000.elf", shell), ("d20--variant-000.bin", overlay(PACK[name](rec)))])
        check(f"{name} .bin member: read from the member", campaign(got) == "BR20-000" and got[1] == 1, got[2])
        got = choose([("d20--variant-000.elf", shell + overlay(PACK[name](rec))[::-1])])
        check(f"{name} byte-reversed: read", campaign(got) == "BR20-000", got[2])
    layers = packed_tail.search_layers(shell + overlay(PACK["add>xor"](rec)))
    check("the layer names the family and both keys", any(f"add{K1:02x}>xor{K2:02x}@" in h for h, _ in layers),
          [h for h, _ in layers])

    # 2. a byte map before a stream
    for bname in ("rol3", "xor>rol", "add>rol", "add>xor", "xor>add"):
        for sname, sf in STREAM.items():
            for lay_name, lay in (("pk19", pk19), ("overlay", overlay)):
                got = choose([("d20--variant-000.elf", shell + b"\0" * 16 + lay(PACK[bname](sf(rec))))])
                check(f"{bname}>{sname} {lay_name}: read", campaign(got) == "BR20-000", got[2] or campaign(got))
    check("starts: a PK19 length pins its packed start first",
          packed_tail.starts(pk19(b"\x55" * 300))[0] == 44, packed_tail.starts(pk19(b"\x55" * 300))[:3])

    # 3. a larger region
    got = choose([("d20--variant-000.elf", shell + overlay(PACK["xor>add"](rec)) + rng.randbytes(2 << 20))])
    check("a config before a 2 MB random tail: read", campaign(got) == "BR20-000", got[2])
    check("TAIL_MAX is 4 MiB", packed_tail.TAIL_MAX == 4 << 20)

    # 4. decoys
    bad = rec[:20] + bytes([rec[20] ^ 1]) + rec[21:]
    decoys = [(f"random tail {n}", shell + rng.randbytes(n)) for n in (4096, 1 << 20, 4 << 20)]
    decoys += [
        ("near-valid CRC add>xor", shell + overlay(PACK["add>xor"](bad))),
        ("near-valid CRC xor>add>zlib", shell + pk19(PACK["xor>add"](zlib.compress(bad)))),
        ("two differing two-key", shell + overlay(PACK["add>xor"](rec)) + overlay(PACK["xor>add"](other))),
        ("two-key beside one-key", shell + overlay(PACK["add>xor"](rec)) + overlay(PACK["rol3"](other))),
        ("stream beside two-key", shell + pk19(PACK["xor>rol"](zlib.compress(rec))) + overlay(PACK["add>xor"](other))),
        ("another day's only", shell + overlay(PACK["xor>add"](old))),
    ]
    for name, data in decoys:
        got = choose([("d20--variant-000.elf", data)])
        check(f"decoy {name}: no config", got[0] is None, campaign(got))
        if "two" in name or "beside" in name:
            check(f"decoy {name}: the reason says two containers", "2 CRC-valid HCFG containers packed" in got[2], got[2])
    got = choose([("d20--variant-000.elf", shell + overlay(PACK["rol3"](rec)) + overlay(PACK["add>xor"](bad)))])
    check("a packed config beside a near-valid two-key decoy: read", campaign(got) == "BR20-000", got[2])

    # 5. collapse
    plain = shell + b"\0" * 16 + rec
    hows = [h for h, _ in packed_tail.search_layers(plain)]
    check("a plain container is no two-key layer (add 0x80 is xor 0x80)", not hows, hows)
    one = shell + overlay(bytes(b ^ 0x5A for b in rec))
    hows = [h for h, _ in packed_tail.search_layers(one)]
    check("a one-key xor is no two-key layer (no key 0x80 on either side)",
          not any("80>" in h or h.split("@")[0].endswith("80") for h in hows), hows)

    # 6. bounds and cost
    many = shell + b"".join(overlay(PACK["add>xor"](record(cfg_json(variant=v)))) for v in range(40))
    layers = [h for h, _ in packed_tail.search_layers(many) if ">xor" in h and "reversed" not in h]
    check("TWO_KEY_HITS bounds the places of one magic and family", len(layers) <= packed_tail.TWO_KEY_HITS, len(layers))
    tail = shell + rng.randbytes(2 << 20)
    packed_tail.search_layers(b"\x7fELF" + bytes(100))
    packed_tail._CACHE.clear()
    t = time.perf_counter()
    packed_tail.tail_layers(tail)
    dt = time.perf_counter() - t
    print(f"     (a 2 MB random tail: {dt * 1000:.0f} ms through every family of the module)")
    check("a 2 MB random tail costs well under a second", dt < 1.0, dt)

    print(f"ok {len(PASSED)} passed" if not FAILED else f"{len(FAILED)} check(s) failed, {len(PASSED)} passed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
