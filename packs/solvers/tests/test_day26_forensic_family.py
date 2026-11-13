#!/usr/bin/env python3
"""Day 26 forensic family: readers_winartifacts.py (thumbcache CMMM, jump lists).

  .venv/bin/python tests/test_day26_forensic_family.py

Offline. Held: valid synthesized containers give the truth as an UNSURE first option; a forged header count,
truncation, foreign bytes and junk never give a wrong PLAIN answer (None or unsure only); a fuzz of hundreds of
mutations gives PLAIN(bad)=0 and raises nothing. Nothing of this pack is ever plain.
"""
import io
import os
import random
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "metadata-forensics"))
os.environ.setdefault("CTF_TESTING", "1")
import labels  # noqa: E402
import properties_strict as M  # noqa: E402

FAILED = []
FMT = {"int": {"kind": "integer", "syntax": "base-10 integer with no units, separators, or explanatory text"},
       "value": {"kind": "exact_text", "syntax": "exact artifact-derived value only; use the literal none only when the requested field is absent"}}


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(name)


def ask(prop, member, data, kind="int"):
    ns = prop.split(".")[0]
    qid = f"d26-{ns}-001-" + prop.replace(".", "-").replace("_", "-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(zipfile.ZipInfo(member, (2026, 1, 1, 0, 0, 0)), data)
    blob = buf.getvalue()
    q = {"id": qid, "qid": qid, "answer_id": qid, "question": f"Determine {prop} for {member}.",
         "artifact": f"evidence.zip -> {member}", "member": member, "answer_format": dict(FMT[kind])}
    old, sys.stderr = sys.stderr, io.StringIO()
    try:
        out = M.solve_set([q], {"evidence.zip": blob, member: data},
                          {"set": 1, "delivery_name": "evidence.zip", "delivery": blob, "attempt": {}})
    finally:
        sys.stderr = old
    return out[qid]


def opts(a):
    u = labels.parse(a) if isinstance(a, str) else None
    return None if u is None else [v for _, v in u.options]


def plain(a):
    return isinstance(a, str) and not labels.is_unsure(a)


def tcache(n=3, version=0x14, ctype=2, hdr_count=None, sizes=None):
    sizes = sizes or [40 + 8 * i for i in range(n)]
    first = 24
    body = b""
    for i, s in enumerate(sizes):
        e = bytearray(s)
        e[:4] = b"CMMM"
        struct.pack_into("<IQ", e, 4, s, (0x1111111111111111 * (i + 1)) & (2**64 - 1))
        body += bytes(e)
    h = struct.pack("<4sIIIII", b"CMMM", version, ctype, first, first + len(body),
                    n if hdr_count is None else hdr_count)
    return h + body


def cfb(streams):
    """A minimal CFB v3: FAT (sector 0), directory (1), mini FAT (2), the ministream (3..); every stream < 4096."""
    END, FREE, NOST = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF
    mini, starts, mfat = b"", [], []
    for _, data in streams:
        assert len(data) < 4096
        k = max(1, -(-len(data) // 64))
        starts.append(len(mfat))
        mfat += [len(mfat) + i + 1 for i in range(k - 1)] + [END]
        mini += data + b"\0" * (k * 64 - len(data))
    mini += b"\0" * (-len(mini) % 512)
    msecs = len(mini) // 512
    mfat += [FREE] * (128 - len(mfat))
    assert len(mfat) == 128
    fat = [0xFFFFFFFD, END, END] + [4 + i for i in range(msecs - 1)] + [END]
    fat += [FREE] * (128 - len(fat))

    def ent(name, typ, left, right, child, start, size):
        e = bytearray(128)
        nm = (name + "\0").encode("utf-16-le")
        e[:len(nm)] = nm
        struct.pack_into("<HBB", e, 64, len(nm), typ, 1)
        struct.pack_into("<III", e, 68, left, right, child)
        struct.pack_into("<I", e, 116, start)
        struct.pack_into("<Q", e, 120, size)
        return bytes(e)
    total = sum(len(s) for _, s in streams)
    ents = [ent("Root Entry", 5, NOST, NOST, 1, 3, msecs * 512)]
    for i, (name, data) in enumerate(streams):
        ents.append(ent(name, 2, NOST, i + 2 if i + 1 < len(streams) else NOST, NOST, starts[i], len(data)))
    while len(ents) < 4:
        ents.append(b"\0" * 128)
    h = bytearray(512)
    h[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", h, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIII", h, 40, 0, 1, 1, 0)       # dir sectors, FAT sectors, first dir sector, txn
    struct.pack_into("<II", h, 56, 4096, 2)            # mini cutoff, first minifat sector
    struct.pack_into("<III", h, 64, 1, END, 0)         # num minifat, first difat, num difat
    h[76:76 + 436] = struct.pack("<109I", *([0] + [FREE] * 108))
    return bytes(h) + struct.pack("<128I", *fat) + b"".join(ents) + struct.pack("<128I", *mfat) + mini


def destlist(version, paths, count=None, pinned=0):
    out = struct.pack("<IIIIII", version, len(paths) if count is None else count, pinned, 7, 0, 0) + b"\0" * 8
    plen, trail = (108, 0) if version < 3 else (128, 4)
    for p in paths:
        e = bytearray(plen + 2)
        struct.pack_into("<H", e, plen, len(p))
        out += bytes(e) + p.encode("utf-16-le") + b"\0" * trail
    return out


LNK = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46" + b"\0" * 40


def custom(n):
    return struct.pack("<II", 2, 1) + b"\0\0\0\0" + (LNK + b"\0\0") * n + b"\xab\xfb\xbf\xba"


def main():
    d = tcache(3)
    a = ask("thumbcache.entry_count", "thumbcache_256.db", d)
    check("tc count truth first, unsure", opts(a) and opts(a)[0] == "3" and not plain(a), a)
    a = ask("thumbcache.entry_count", "thumbcache_256.db", tcache(3, hdr_count=9))
    check("tc forged count: unsure, walked first", opts(a) and opts(a)[0] == "3" and not plain(a), a)
    a = ask("thumbcache.cache_type_name", "thumbcache_256.db", tcache(2, version=0x14, ctype=2))
    check("tc type name unsure", opts(a) and opts(a)[0] == "256" and not plain(a), a)
    a = ask("thumbcache.first_entry_hash", "thumbcache_256.db", d, "value")
    check("tc first hash truth first", opts(a) and opts(a)[0] == "1111111111111111", a)
    a = ask("thumbcache.entry_count", "thumbcache_256.db", d[:-5])
    check("tc truncated not plain", not plain(a), a)
    bad = bytearray(d)
    struct.pack_into("<I", bad, 28, 10**7)
    a = ask("thumbcache.entry_count", "thumbcache_256.db", bytes(bad))
    check("tc forged entry size not plain", not plain(a), a)
    a = ask("thumbcache.entry_count", "x.db", b"SQLite format 3\0" + b"\0" * 200)
    check("tc foreign file not plain", not plain(a), a)
    for ver in (1, 3):
        j = cfb([("DestList", destlist(ver, ["C:\\a.txt", "C:\\bb.doc"])), ("1", b"x" * 80), ("2", b"y" * 80)])
        a = ask("jumplist.entry_count", "1b4dd67f29cb1962.automaticDestinations-ms", j)
        check(f"jl v{ver} entry_count truth first", opts(a) and opts(a)[0] == "2" and not plain(a), a)
        a = ask("jumplist.lnk_count", "1b4dd67f29cb1962.automaticDestinations-ms", j)
        check(f"jl v{ver} lnk_count", opts(a) and opts(a)[0] == "2" and not plain(a), a)
    j = cfb([("DestList", destlist(3, ["C:\\a.txt", "C:\\bb.doc"], count=5)), ("1", b"x" * 80)])
    a = ask("jumplist.entry_count", "a.automaticDestinations-ms", j)
    check("jl forged count: unsure, walked first", opts(a) and opts(a)[0] == "2" and not plain(a), a)
    j = cfb([("DestList", destlist(3, ["C:\\a.txt"]) + b"\0\0\0"), ("1", b"x" * 80)])
    a = ask("jumplist.entry_count", "a.automaticDestinations-ms", j)
    check("jl DestList that does not close not plain", not plain(a), a)
    a = ask("jumplist.lnk_count", "a.customDestinations-ms", custom(3))
    check("custom lnk_count", opts(a) and opts(a)[0] == "3" and not plain(a), a)
    a = ask("jumplist.lnk_count", "a.customDestinations-ms", custom(3)[:-4])
    check("custom without footer not plain", not plain(a), a)

    rng = random.Random(26)
    seeds = [(tcache(4), "thumbcache.entry_count"), (tcache(2, 0x20, 4), "thumbcache.cache_type_name"),
             (tcache(3), "thumbcache.entry_hashes"),
             (cfb([("DestList", destlist(3, ["C:\\a", "C:\\b"])), ("1", b"x" * 64)]), "jumplist.entry_count"),
             (custom(2), "jumplist.lnk_count")]
    badplain = raised = runs = 0
    for _ in range(600):
        s, prop = rng.choice(seeds)
        b = bytearray(s)
        m = rng.randrange(4)
        if m == 0:
            b = b[:rng.randrange(len(b))]
        elif m == 1:
            for _ in range(rng.randrange(1, 6)):
                b[rng.randrange(len(b))] = rng.randrange(256)
        elif m == 2:
            b = bytearray(rng.randbytes(rng.randrange(0, 600)))
        else:
            b += rng.randbytes(rng.randrange(1, 9))
        runs += 1
        try:
            a = ask(prop, "f.bin", bytes(b))
        except Exception as e:
            raised += 1
            print("RAISED", type(e).__name__, e)
            continue
        if plain(a):   # this pack answers nothing plain: any plain answer here is a violation
            badplain += 1
    check(f"fuzz {runs} runs: PLAIN(bad)=0", badplain == 0, badplain)
    check("fuzz raised nothing", raised == 0, raised)
    print("FAILED:", FAILED)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
