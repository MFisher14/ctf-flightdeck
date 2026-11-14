"""Day 26: HCFG payload under a repeating XOR key of 9..64 bytes, read only behind the header's CRC-32.

  .venv/bin/python -I tests/test_day26_binary_vigenere.py
"""
import json
import os
import random
import struct
import sys
import time
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "solvers", "binary"))
import hcfg  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "tests"))
import loadclock  # noqa: E402  (tests/loadclock.py)


def cfg(rng, extra=0):
    words = ["alpha", "bravo", "delta", "echo", "relay", "beacon", "stage", "node"]
    d = {"campaign": "BR26-" + rng.choice(words) + str(rng.randrange(100)),
         "c2_url": "https://%s.example.net/%s" % (rng.choice(words), rng.choice(words)),
         "mutex": "Global\\%s%d" % (rng.choice(words), rng.randrange(10**6)),
         "interval": rng.randrange(1000), "note": " ".join(rng.choice(words) for _ in range(extra))}
    s = json.dumps(d, separators=(",", ":"))
    assert s.startswith('{"campaign":"')
    return s.encode()


def blob(plain, key):
    enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(plain))
    return b"HCFG" + bytes([1, key[0]]) + struct.pack("<HI", len(enc), zlib.crc32(plain)) + enc


def read(data):
    """hcfg's reading, its search budgets (LONG_TIME, LONG_TOTAL, read from time.monotonic) counted in CPU
    seconds (tests/loadclock.cpu_clock): on a loaded machine the wall-clock 0.3 s per payload ran out
    before a 13-byte key was searched and the reading was [] (SH-10). Work over the budget still runs
    it out; the CRC-32 checks per length and per payload (LONG_PER_L, LONG_EVALS) are unchanged."""
    hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=0)   # each call is its own solve
    with loadclock.cpu_clock():
        return hcfg.containers(b"\x00" * 7 + data + b"\x00" * 5, others=True)


def test_lengths():
    rng = random.Random(26)
    stats = {}
    for L in (9, 12, 13, 14, 16, 24, 32, 48, 64):
        ok = tot = 0
        for extra in (4, 12, 40):
            for _ in range(15):
                plain = cfg(rng, extra)
                key = bytes(rng.randrange(256) for _ in range(L))
                got = read(blob(plain, key))
                tot += 1
                if L <= 13:
                    assert len(got) == 1 and got[0]["plain"] == plain, (L,)
                if got:
                    assert got[0]["plain"] == plain and got[0]["how"] == "repeating", L
                    assert zlib.crc32(got[0]["plain"]) == got[0]["crc32"]
                    ok += 1
        stats[L] = (ok, tot)
    print("random-byte keys recovered (ok/total) by length:", stats)
    for L in (9, 12, 13, 14, 16):
        assert stats[L][0] == stats[L][1], (L, stats[L])
    assert stats[24][0] >= 25 and stats[32][0] >= 12, stats
    for L in (24, 32):   # a realistic 350-byte payload
        hit = 0
        for _ in range(20):
            plain = cfg(rng, 40)
            key = bytes(rng.randrange(256) for _ in range(L))
            got = read(blob(plain, key))
            assert not got or got[0]["plain"] == plain
            hit += bool(got)
        assert hit >= 17, (L, hit)
    return stats


def test_text_keys():
    rng = random.Random(5)
    n = 0
    for L in (16, 24, 32):
        for _ in range(20):
            key = bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(L))
            plain = cfg(rng, 12)
            got = read(blob(plain, key))
            assert not got or got[0]["plain"] == plain
            n += bool(got)
    print("alnum keys recovered", n, "of 60")


def test_none_cases():
    rng = random.Random(9)
    plain = cfg(rng, 8)
    key = bytes(rng.randrange(256) for _ in range(16))
    data = blob(plain, key)
    assert read(data)
    bad = bytearray(data)
    bad[-3] ^= 1
    assert not read(bytes(bad))
    assert not read(data[:8] + struct.pack("<I", zlib.crc32(b"x")) + data[12:])
    roll = bytes(b ^ ((key[0] + i) & 0xFF) for i, b in enumerate(plain))
    d2 = b"HCFG" + bytes([1, key[0]]) + struct.pack("<HI", len(roll), zlib.crc32(plain)) + roll
    got = read(d2)
    assert not got or got[0]["how"] != "repeating"
    assert not read(data[:8] + struct.pack("<I", zlib.crc32(plain + b" ")) + data[12:])


def test_fuzz_never_wrong():
    rng = random.Random(1234)
    worst = 0
    for i in range(400):
        n = rng.choice([30, 80, 150, 300, 600, 2000])
        mode = i % 4
        if mode == 0:
            enc = bytes(rng.randrange(256) for _ in range(n))
        elif mode == 1:
            enc = bytes(rng.randrange(32, 127) for _ in range(n))
        elif mode == 2:
            p = cfg(rng, n // 8)
            k = bytes(rng.randrange(256) for _ in range(rng.randrange(9, 40)))
            enc = bytes(b ^ k[j % len(k)] for j, b in enumerate(p))
        else:
            p = cfg(rng, n // 8)
            enc = bytes(b ^ rng.randrange(256) for b in p)
        crc = rng.getrandbits(32) if mode != 2 else zlib.crc32(b"nope")
        # CPU seconds, not wall: read() runs hcfg's budgets on the CPU clock (SH-10), so under load a
        # payload's wall time is its CPU budget stretched by the wait for a core. The bound checks work.
        t = time.process_time()
        data = b"HCFG" + bytes([1, enc[0] ^ 0x7B]) + struct.pack("<HI", len(enc), crc) + enc
        got = [c for c in read(data) if c["how"] == "repeating"]
        worst = max(worst, time.process_time() - t)
        assert not got, i
    print("fuzz 400 payloads: PLAIN=0, worst %.3fs" % worst)
    assert worst < 1.0


def test_deadline():
    rng = random.Random(3)
    enc = bytes(rng.randrange(32, 127) for _ in range(900))
    hcfg.DEADLINE = time.monotonic() - 1
    try:
        assert list(hcfg._long_repeating(enc, 1)) == []
    finally:
        hcfg.DEADLINE = None


def test_budget():
    """64 constant-column decoy headers: the total search time is capped, not 0.28 s a header."""
    rng = random.Random(1)
    parts = []
    for i in range(64):
        key = bytes(rng.randrange(256) for _ in range(16))
        plain = b'{"campaign":"' + b"a" * (3000 + i)
        enc = bytes(b ^ key[j % 16] for j, b in enumerate(plain))
        parts.append(b"HCFG" + bytes([1, key[0]]) + struct.pack("<HI", len(enc), rng.getrandbits(32)) + enc + b"\0" * 8)
    hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=0)
    t0 = time.monotonic()
    got = hcfg.containers(b"".join(parts), others=True)
    dt = time.monotonic() - t0
    assert not [c for c in got if c["how"] == "repeating"]
    assert dt < 2.5, dt
    print("64 decoy headers: %.2fs" % dt)


if __name__ == "__main__":
    test_budget()
    test_lengths()
    test_text_keys()
    test_none_cases()
    test_fuzz_never_wrong()
    test_deadline()
    print("ok")
