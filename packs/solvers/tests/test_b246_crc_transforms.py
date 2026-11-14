"""B-246: CRC-gated transform widening of the HCFG reader and the binary lane's shape residuals.

solvers/binary/crc_transforms.py (behind hcfg._other_readings and hcfg._headers), the repeating-key fold in hcfg,
generic.xor_key_answer and the tagged trailer's CRC-32 / big-endian variants, judged_forms' role-prefixed config
ids (row 456), and the binary-hcfg opener replayed by the B-036 lane gate.

Every fixture is synthetic, built here or in ctf/openers/binary_fixtures.py. The encoders are independent of the
decoders: the PRNG generators are pinned to public reference outputs (glibc srand(1), MSVC srand(1), K&R rand,
java.util.Random(42), MT19937 seed 5489 via numpy's init_genrand), the LZNT1 decoder is checked against the
second implementation in solvers/toolkits/pe_emu.py, LZ4 against the lz4 package, the ciphers against Cryptodome.
Budgets run on the CPU clock (tests/loadclock.cpu_clock), never on wall time.
"""
from __future__ import annotations

import bz2
import importlib.util
import itertools
import json
import lzma
import random
import struct
import sys
import time
import zlib
from pathlib import Path

import pytest

import hcfg
import judged_forms
import labels
import loadclock
from ctf import openers, paths
from ctf.adapt import regress
from ctf.openers import binary_fixtures as bf

ct = hcfg.crc_transforms           # the module object hcfg itself calls (loaded by path under a private name)
ROOT = paths.repo_root()


def _generic():
    """solvers/binary/generic.py under binary_generic (never `import generic`: script-analysis has one too)."""
    mod = sys.modules.get("binary_generic")
    if mod is None or not callable(getattr(mod, "xor_key_answer", None)):
        spec = importlib.util.spec_from_file_location("binary_generic", ROOT / "solvers" / "binary" / "generic.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["binary_generic"] = mod
        spec.loader.exec_module(mod)
    return mod


def read(data: bytes) -> list:
    """hcfg's widened reading of one sample, its budgets on the CPU clock, as one fresh solve."""
    hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=0)
    with loadclock.cpu_clock():
        return hcfg.containers(bytes(bytearray(data)), others=True)   # a fresh bytes object: no kept reading


def one(data: bytes) -> dict:
    hits = [h for h in read(data) if h["crc_ok"]]
    assert len(hits) == 1, [(h["how"], h.get("json")) for h in hits]
    return hits[0]


def broken(rec: bytes) -> bytes:
    """The same record with one bit of its stored CRC-32 flipped."""
    b = bytearray(rec)
    b[8] ^= 0x01
    return bytes(b)


PLAIN = bf.config("B246-test", note="the quick brown fox jumps over the lazy dog")
PAD = b"\x00" * 24


# ---------------------------------------------------------------------------- PRNG reference outputs

def first(name, seed, n=3):
    gen = dict((nm, g) for nm, g, _ in ct.PRNGS)[name]
    return list(itertools.islice(gen(seed), n))


def test_prng_generators_match_public_reference_outputs():
    import numpy as np
    assert first("glibc", 1) == [1804289383 & 0xFF, 846930886 & 0xFF, 1681692777 & 0xFF]   # glibc srand(1)
    assert first("msvc", 1) == [41, 18467 & 0xFF, 6334 & 0xFF]                             # MSVC srand(1)
    assert first("ansi", 1, 1) == [16838 & 0xFF]                                          # K&R rand(), seed 1
    assert first("java_bytes", 42, 4) == list((-1170105035 & 0xFFFFFFFF).to_bytes(4, "little"))  # Random(42)
    # nextInt(256), a power-of-two bound: (256 * next(31)) >> 31, the top byte of next(32) = nextInt()
    assert first("java_int256", 42, 1) == [(-1170105035 & 0xFFFFFFFF) >> 24]
    assert first("xorshift32", 1, 1) == [270369 & 0xFF]                                  # 13/17/5, seed 1
    assert first("nr", 1, 1) == [(1664525 + 1013904223) >> 24]
    assert first("minstd", 1, 1) == [16807 & 0xFF]
    ref = np.random.RandomState(5489).randint(0, 2 ** 32, size=5, dtype=np.uint32)        # init_genrand(5489)
    assert first("mt19937", 5489, 5) == [int(v) & 0xFF for v in ref]
    assert int(ref[0]) == 3499211612
    r = random.Random(7)
    assert first("py_getrandbits8", 7, 3) == [r.getrandbits(8) for _ in range(3)]
    r = random.Random(9)
    assert first("py_randint", 9, 3) == [r.randint(0, 255) for _ in range(3)]
    assert first("xorshift32", 0, 1) == []             # xorshift32 has no zero state: no stream, not a stuck one


# ---------------------------------------------------------------------------- the repeating-key fold

def test_a_short_xor_key_not_starting_with_the_header_byte_is_read():
    # the old 2..8-byte loop only ran when the key began with the header byte (x[:1] == "{"); the folded reader
    # reads any key the OPENING crib fixes
    key = b"\x91\x22\x33\x44\x55"
    rec = bf.record(PLAIN, bf.repeat(PLAIN, key, "xor"), 0x07)
    h = one(PAD + rec + PAD)
    assert (h["how"], h["key_bytes"], h["plain"]) == ("repeating", key, PLAIN)
    assert not [c for c in read(PAD + broken(rec) + PAD) if c["crc_ok"]]


@pytest.mark.parametrize("size", [2, 7, 9, 13])
def test_crib_whole_keys_are_read_past_the_long_search_header_cap(size, monkeypatch):
    monkeypatch.setattr(hcfg, "LONG_TIME", 0.0)                # and with no search time left at all
    rng = random.Random(size)
    key = bytes(rng.randrange(256) for _ in range(size))
    rec = bf.record(PLAIN, bf.repeat(PLAIN, key, "xor"), key[0] ^ 0x80)
    hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=hcfg.LONG_HEADERS)    # the long search's cap is spent
    with loadclock.cpu_clock():
        got = [h for h in hcfg._headers(PAD + rec + PAD, others=True)]
    hcfg._LONG_STATE.update(headers=0)
    assert [(h["how"], h["key_bytes"]) for h in got] == [("repeating", key)]


@pytest.mark.parametrize("size", [3, 11, 16])
def test_a_repeating_added_key_is_read_and_a_subtracted_one_as_its_negation(size):
    rng = random.Random(100 + size)
    key = bytes(rng.randrange(1, 256) for _ in range(size))
    h = one(PAD + bf.record(PLAIN, bf.repeat(PLAIN, key, "add"), 0x11) + PAD)
    assert (h["how"], h["key_bytes"], h["json"]["campaign"]) == ("repeating_add", key, "B246-test")
    h = one(PAD + bf.record(PLAIN, bf.repeat(PLAIN, key, "sub"), 0x11) + PAD)
    assert h["how"] == "repeating_add" and h["key_bytes"] == bytes((-k) & 0xFF for k in key)
    assert h["plain"] == PLAIN
    assert not read(PAD + broken(bf.record(PLAIN, bf.repeat(PLAIN, key, "add"), 0x11)) + PAD)


def test_the_long_search_header_cap_counts_payloads_not_the_xor_and_add_searches(monkeypatch):
    # LONG_HEADERS payloads reach the long search, even when the XOR and the add search of each both cost enough to
    # count: a 16-byte ADD key is searched under XOR first (in vain) and then under add. One payload more than the
    # cap stays unread, so the cap itself still holds.
    monkeypatch.setattr(hcfg, "LONG_COSTLY", -1.0)             # every search counts against the cap
    monkeypatch.setattr(hcfg, "LONG_TOTAL", 1e9)               # and the shared time budget never runs out
    rng = random.Random(4600)
    recs = []
    for i in range(hcfg.LONG_HEADERS + 1):
        plain = bf.config(f"B246-cap-add-{i}")
        key = bytes(rng.randrange(1, 256) for _ in range(16))
        recs.append(bf.record(plain, bf.repeat(plain, key, "add"), 0x11))
    hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=0)
    with loadclock.cpu_clock():
        got = [(h["how"], h["json"]["campaign"]) for h in hcfg._headers(PAD + PAD.join(recs) + PAD, others=True)]
    assert got == [("repeating_add", f"B246-cap-add-{i}") for i in range(hcfg.LONG_HEADERS)]
    assert hcfg._LONG_STATE["headers"] == hcfg.LONG_HEADERS and hcfg._LONG_STATE["skipped"] is True
    list(hcfg._headers(PAD, others=True))                      # the next pass counts its own payloads afresh
    assert hcfg._LONG_STATE["headers"] == 0 and hcfg._LONG_STATE["counted"] == set()


# ---------------------------------------------------------------------------- cheap families

def _cheap_cases():
    p = PLAIN
    rle_p = bf.config("B246-rle-" + "a" * 30, fill="b" * 20)
    return [
        ("rotate_r1", bf.rotl(bf.xor1(p, 0x5A), 1), 0x5A, b"\x5a"),
        ("rotate_r5", bf.rotl(p, 5), 0x33, b"\x00"),                                    # rotation alone
        ("rotate_r7", bf.xor1(bf.rotl(p, 7), 0x5A), 0x5A, None),                        # rotate, then XOR
        ("rotate_r2", bf.rotl(bf.repeat(p, b"k3y!", "xor"), 2), 0x01, b"k3y!"),        # multi-byte key
        ("deflate_raw", bf.xor1(bf.raw_deflate(p), 0x29), 0x29, None),
        ("deflate_raw_outer", bf.raw_deflate(bf.xor1(p, 0x29)), 0x29, None),
        ("bz2", bf.xor1(bz2.compress(p), 0x13), 0x13, None),
        ("lzma", bf.xor1(lzma.compress(p), 0x14), 0x14, None),                          # xz
        ("lzma", bf.xor1(lzma.compress(p, format=lzma.FORMAT_ALONE), 0x15), 0x15, None),
        ("rle_cb", bf.xor1(bf.rle_cb(rle_p), 0x3C), 0x3C, None),
        ("rle_bc", bf.xor1(bytes(x for i in range(0, len(bf.rle_cb(rle_p)), 2)
                                 for x in bf.rle_cb(rle_p)[i:i + 2][::-1]), 0x3D), 0x3D, None),
        ("packbits", bf.xor1(bf.packbits(rle_p), 0x47), 0x47, None),
    ], rle_p


@pytest.mark.parametrize("i", range(12))
def test_each_cheap_family_reads_only_behind_the_crc(i):
    cases, rle_p = _cheap_cases()
    how, payload, key, key_bytes = cases[i]
    plain = rle_p if how in ("rle_cb", "rle_bc", "packbits") else PLAIN
    rec = bf.record(plain, payload, key)
    h = one(PAD + rec + PAD)
    assert h["how"] == how and h["plain"] == plain and h["json"] == json.loads(plain)
    if key_bytes is not None:
        assert h["key_bytes"] == key_bytes
    assert not [c for c in read(PAD + broken(rec) + PAD) if c["crc_ok"]]


def test_a_non_json_payload_rotated_then_xored_with_the_header_byte_is_read():
    # no OPENING crib here (key=value lines): only the header byte, rotated with the payload, can read it
    kv = b"campaign=B246-kv\nmutex=Global-kv\nsleep=30\n"
    rec = bf.record(kv, bf.xor1(bf.rotl(kv, 3), 0x5A), 0x5A)
    h = one(PAD + rec + PAD)
    assert (h["how"], h["key_bytes"], h["nonjson"]) == ("rotate_r3", bytes([((0x5A >> 3) | (0x5A << 5)) & 0xFF]),
                                                       "keyvalue")
    assert h["json"]["campaign"] == "B246-kv"


def test_lznt1_refuses_a_chunk_without_its_signature():
    good = bf.lznt1(b"signature check signature check")
    assert ct._run(ct.lznt1, good, 1 << 16) == b"signature check signature check"
    bad = bytearray(good)
    bad[1] ^= 0x10                                   # signature bits 0b011 -> 0b010
    assert ct._run(ct.lznt1, bytes(bad), 1 << 16) is None


def test_lz4_frame_from_the_lz4_package_is_read():
    lz4frame = pytest.importorskip("lz4.frame")
    for kw in ({}, {"block_checksum": True, "content_checksum": True, "store_size": True}):
        rec = bf.record(PLAIN, bf.xor1(lz4frame.compress(PLAIN, **kw), 0x21), 0x21)
        h = one(PAD + rec + PAD)
        assert (h["how"], h["plain"]) == ("lz4f", PLAIN)


def test_cheap_readings_never_yield_without_the_crc_on_random_payloads():
    rng = random.Random(246)
    for i in range(300):
        n = rng.choice([20, 64, 200, 900])
        enc = bytes(rng.randrange(256) for _ in range(n))
        if i % 3 == 0:          # a payload that really is one of the encodings, under a CRC of something else
            enc = bf.xor1(bf.raw_deflate(PLAIN), 0x29)
        assert list(ct.cheap_readings(enc, rng.randrange(256), rng.getrandbits(32))) == []


# ---------------------------------------------------------------------------- decoders against second implementations

def test_lznt1_decoder_agrees_with_pe_emu_on_a_compressing_stream():
    spec = importlib.util.spec_from_file_location("b246_pe_emu", ROOT / "solvers" / "toolkits" / "pe_emu.py")
    pe = importlib.util.module_from_spec(spec)
    sys.modules["b246_pe_emu"] = pe
    spec.loader.exec_module(pe)
    data = (b"abcabcabcabc-the quick brown fox-" * 200)[:5000]          # two chunks, real phrases
    comp = bf.lznt1(data)
    assert len(comp) < len(data) // 2
    assert pe.lznt1_decompress(comp) == data
    assert ct._run(ct.lznt1, comp, 1 << 16) == data


def test_lz4_block_decoder_agrees_with_the_lz4_package():
    block = pytest.importorskip("lz4.block")
    data = (b"0123456789abcdefABCDEF-" * 40) + b"tail-literals"
    assert ct._run(ct.lz4, block.compress(data, store_size=False), 1 << 16) == data
    assert ct._run(ct.lz4_sized, block.compress(data), 1 << 16) == data


def test_lzss_ring_fill_differs_between_the_two_readers():
    # a first token that copies three bytes from the ring before any output: the fill decides them
    assert ct._run(ct.lzss, b"\x00\x00\x00", 99) == b"   "
    assert ct._run(ct.lzss0, b"\x00\x00\x00", 99) == b"\x00\x00\x00"
    data = b"lzss round trip lzss round trip lzss!"
    assert ct._run(ct.lzss, bf.lzss(data), 1 << 16) == data


def test_decoders_stop_at_their_output_limit():
    assert ct._run(ct.rle_cb, b"\xff\x41" * 10, 100) == b"A" * 100
    assert ct._run(ct.packbits, bytes([129, 0x42]) * 10, 50) == b"B" * 50
    assert ct._run(ct.rle_cb, b"\x00\x41", 100) is None                 # a zero count is no RLE
    assert ct._run(ct.packbits, b"\x05ab", 100) is None                 # a literal run past the end


# ---------------------------------------------------------------------------- costly families

def _costly_cases():
    from Cryptodome.Cipher import ChaCha20, Salsa20
    p = PLAIN
    lz_p = bf.config("B246-lz-" + "x" * 40)
    hexkey = bytes(range(32))
    salsa_key = b"B246-salsa-k16!!"
    raw_key, raw_nonce = bytes(range(100, 132)), bytes(range(7, 15))
    msvc = bytes(a ^ b for a, b in zip(p, bf.msvc_stream(bf.PRNG_SEED, len(p))))
    win_key, nonce12, nonce8 = bytes(range(0x80, 0xA0)), bytes(range(0xC0, 0xCC)), bytes(range(0xD0, 0xD8))

    def ks(name, seed):
        return bytes(a ^ b for a, b in zip(p, first(name, seed, len(p))))

    def chacha(key, nonce, counter=0):
        c = ChaCha20.new(key=key, nonce=nonce)
        if counter:
            c.seek(64 * counter)
        return c.encrypt(p)

    lz4b = pytest.importorskip("lz4.block")
    return [
        # (how, before, payload, key byte, after, plain, extra field checks)
        ("lznt1", b"", bf.xor1(bf.lznt1(lz_p), 0x61), 0x61, b"", lz_p, {}),
        ("lzss_outer", b"", bf.lzss(bf.xor1(lz_p, 0x62)), 0x62, b"", lz_p, {}),
        ("aplib", b"", bf.xor1(bf.aplib_literals(p), 0x66), 0x66, b"", p, {}),
        ("lz4", b"", bf.xor1(lz4b.compress(lz_p, store_size=False), 0x67), 0x67, b"", lz_p, {}),
        ("lz4_sized", b"", bf.xor1(lz4b.compress(lz_p), 0x68), 0x68, b"", lz_p, {}),
        ("chacha20", bf.CHACHA_KEY + b"\x00" + bf.CHACHA_NONCE + PAD, chacha(bf.CHACHA_KEY, bf.CHACHA_NONCE), 0x63,
         b"", p, {"key_bytes": bf.CHACHA_KEY, "nonce": bf.CHACHA_NONCE, "counter": 0}),
        ("chacha20", hexkey.hex().encode() + b"\x00" + PAD, chacha(hexkey, bytes(8), 1), 0x01, b"", p,
         {"key_bytes": hexkey, "nonce": bytes(8), "counter": 1}),
        ("chacha20", PAD + raw_key + raw_nonce, chacha(raw_key, raw_nonce), 0x02, b"", p, {"key_bytes": raw_key}),
        ("salsa20", salsa_key + b"\x00" + PAD, Salsa20.new(key=salsa_key, nonce=bytes(8)).encrypt(p), 0x03, b"", p,
         {"key_bytes": salsa_key}),
        ("salsa20", b"", Salsa20.new(key=raw_key, nonce=raw_nonce).encrypt(p), 0x04, raw_key + raw_nonce + PAD, p,
         {"key_bytes": raw_key, "nonce": raw_nonce}),
        ("prng_msvc", b"", msvc, 0x64, struct.pack("<I", bf.PRNG_SEED), p, {"seed": bf.PRNG_SEED}),
        ("prng_glibc", b"", ks("glibc", 0x9C), 0x9C, b"", p, {"seed": 0x9C}),                 # the header byte
        ("prng_java_bytes", struct.pack(">I", 0xCAFE1234), ks("java_bytes", 0xCAFE1234), 0x05, b"", p,
         {"seed": 0xCAFE1234}),                                                             # a BE word before
        ("prng_mt19937", b"seed=31337\x00" + PAD, ks("mt19937", 31337), 0x06, b"", p, {"seed": 31337}),
        ("prng_py_randbytes", b"", bytes(a ^ b for a, b in zip(p, random.Random(200).randbytes(len(p)))), 0x07,
         b"", p, {"seed": 200}),
        # the raw-window layouts of stream_pairs, ChaCha20 and Salsa20 each. The key and nonce bytes are not
        # printable (no key string reads them) and JUNK, never zero, stands beside them, so no other window (a zero
        # nonce, the other order) holds the same pair: each case reads only through its own window.
        ("chacha20", JUNK + nonce12 + win_key, chacha(win_key, nonce12), 0x0A, b"", p,
         {"key_bytes": win_key, "nonce": nonce12}),                                      # nonce, key, header
        ("salsa20", JUNK + nonce8 + win_key, Salsa20.new(key=win_key, nonce=nonce8).encrypt(p), 0x0B, b"", p,
         {"key_bytes": win_key, "nonce": nonce8}),
        ("chacha20", b"", chacha(win_key, nonce12), 0x0C, nonce12 + win_key + JUNK, p,
         {"key_bytes": win_key, "nonce": nonce12}),                                      # payload, nonce, key
        ("salsa20", b"", Salsa20.new(key=win_key, nonce=nonce8).encrypt(p), 0x0D, nonce8 + win_key + JUNK, p,
         {"key_bytes": win_key, "nonce": nonce8}),
        ("chacha20", JUNK + win_key, chacha(win_key, bytes(12)), 0x0E, b"", p,
         {"key_bytes": win_key, "counter": 0}),                                          # key, header; zero nonce
        ("salsa20", b"", Salsa20.new(key=win_key, nonce=bytes(8)).encrypt(p), 0x0F, win_key + JUNK, p,
         {"key_bytes": win_key, "nonce": bytes(8)}),                                     # payload, key; zero nonce
    ]


JUNK = bytes(range(0xE0, 0xF8))           # 24 bytes, none zero, none printable
COSTLY_CASES = 21


def test_the_costly_case_list_is_the_parametrized_one():
    assert len(_costly_cases()) == COSTLY_CASES


@pytest.mark.parametrize("i", range(COSTLY_CASES))
def test_each_costly_family_reads_only_behind_the_crc(i):
    how, before, payload, key, after, plain, extra = _costly_cases()[i]
    rec = bf.record(plain, payload, key)
    h = one(PAD + before + rec + after + PAD)
    assert (h["how"], h["plain"]) == (how, plain)
    for k, v in extra.items():
        assert h[k] == v, k
    assert not [c for c in read(PAD + before + broken(rec) + after + PAD) if c["crc_ok"]]


def test_costly_readings_run_only_for_the_first_rc4_headers_tried():
    # five records nothing cheap opens: the fifth is past RC4_HEADERS and stays unread
    recs = [bf.record(bf.config(f"B246-cap-{i}"), bf.xor1(bf.lznt1(bf.config(f"B246-cap-{i}")), 0x61), 0x61)
            for i in range(hcfg.RC4_HEADERS + 1)]
    got = [h["json"]["campaign"] for h in read(PAD + PAD.join(recs) + PAD) if h["crc_ok"]]
    assert got == [f"B246-cap-{i}" for i in range(hcfg.RC4_HEADERS)]


def test_costly_readings_never_yield_without_the_crc_on_random_payloads():
    rng = random.Random(4096)
    for i in range(24):
        n = rng.choice([40, 120, 400])
        enc = bytes(rng.randrange(256) for _ in range(n))
        data = PAD + bytes(rng.randrange(256) for _ in range(40)) + b"HCFG" + bytes([1, rng.randrange(256)]) \
            + struct.pack("<HI", n, rng.getrandbits(32)) + enc + bytes(rng.randrange(256) for _ in range(40))
        with loadclock.cpu_clock():
            got, _ = ct.costly_reading(data, data.find(b"HCFG"), enc, data[data.find(b"HCFG") + 5],
                                       struct.unpack_from("<I", data, data.find(b"HCFG") + 8)[0])
        assert got is None, i


def test_a_cut_costly_pass_says_so_and_the_reading_is_not_kept():
    data = bf.costly_records()
    o = data.find(b"HCFG")
    enc = data[o + 12:o + 12 + struct.unpack_from("<H", data, o + 6)[0]]
    got, cut = ct.costly_reading(data, o, enc, data[o + 5], struct.unpack_from("<I", data, o + 8)[0],
                                 deadline=time.monotonic() - 1)
    assert (got, cut) == (None, True)
    # through hcfg: a runner deadline already past leaves the costly records unread and marks the pass skipped,
    # so containers() keeps nothing and the same bytes object reads in full once the deadline is gone
    sample = bytes(bytearray(data))
    hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=0)
    hcfg.DEADLINE = time.monotonic() - 1
    try:
        assert [h for h in hcfg.containers(sample, others=True) if h["crc_ok"]] == []
        assert hcfg._LONG_STATE["skipped"] is True
    finally:
        hcfg.DEADLINE = None
    hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=0)
    with loadclock.cpu_clock():
        hows = [h["how"] for h in hcfg.containers(sample, others=True) if h["crc_ok"]]
    assert hows == ["lznt1", "lzss", "chacha20", "prng_msvc"]


def _late_prng_record():
    """A sample whose one record only the last PRNG family (Python's randbytes) reads: the costly pass has tried
    every decoder, cipher pair and earlier generator first."""
    plain = bf.config("B246-late")
    seed = 0x7E57AB1E
    rec = bf.record(plain, bf.keyed(plain, random.Random(seed).randbytes(len(plain))), 0x0B)
    data = PAD + rec + struct.pack("<I", seed) + PAD
    o = data.find(b"HCFG")
    enc = data[o + 12:o + 12 + len(plain)]
    return data, o, enc, data[o + 5], struct.unpack_from("<I", data, o + 8)[0]


def test_the_costly_budget_is_cpu_time_so_a_waiting_wall_clock_does_not_cut_it(monkeypatch):
    # a loaded machine keeps the process waiting for a core: here each wall-clock read is 10 s after the last. No
    # runner deadline is set, so only WIDE_TIME bounds the pass, and it counts this thread's CPU seconds.
    data, o, enc, key, crc = _late_prng_record()
    wall = [time.monotonic()]

    def waiting():
        wall[0] += 10.0
        return wall[0]

    monkeypatch.setattr(time, "monotonic", waiting)
    got, cut = ct.costly_reading(data, o, enc, key, crc)
    assert cut is False and got["how"] == "prng_py_randbytes" and got["seed"] == 0x7E57AB1E


def test_the_costly_budget_still_cuts_on_cpu_time_and_on_a_runner_deadline(monkeypatch):
    data, o, enc, key, crc = _late_prng_record()
    monkeypatch.setattr(ct, "WIDE_TIME", -1.0)                  # no CPU time at all: cut before the first try
    assert ct.costly_reading(data, o, enc, key, crc) == (None, True)
    monkeypatch.setattr(ct, "WIDE_TIME", 1e9)
    assert ct.costly_reading(data, o, enc, key, crc, deadline=time.monotonic() - 1) == (None, True)
    got, cut = ct.costly_reading(data, o, enc, key, crc, deadline=time.monotonic() + 1e6)
    assert cut is False and got["how"] == "prng_py_randbytes"


def test_stream_ciphers_report_not_run_when_cryptodome_cannot_load(monkeypatch, capsys):
    monkeypatch.setattr(ct, "_CIPHERS", [])
    monkeypatch.setattr(ct, "NOT_RUN", {})
    monkeypatch.setitem(sys.modules, "Cryptodome.Cipher", None)        # import raises ImportError
    assert ct.stream_reading(b"x" * 40, 0, [(b"k" * 32, bytes(12))], float("inf")) is None
    assert "Cryptodome" in ct.NOT_RUN["chacha20"] and "Cryptodome" in ct.NOT_RUN["salsa20"]
    assert "chacha20/salsa20 readings not run" in capsys.readouterr().err


def test_plausible_head_admits_what_hcfg_reads_and_refuses_noise():
    for head in (b'{"', b"{}", b" {", b"\n{", b"<c", b"<?", b"ab", b"k=", b"\xa1\x63", b"\x82\xa4", b"\xde\x00"):
        assert ct.plausible_head(head), head
    for head in (b"{x", b"\x00\x01", b"<1", b"a\x00", b"\xa1\x01", b"\x82\x01", b"", b"{"):
        assert not ct.plausible_head(head), head
    assert ct.plausible_head((300).to_bytes(4, "little")[:2], 300)            # BSON: its own length first
    assert not ct.plausible_head((300).to_bytes(4, "little")[:2], 301)
    assert not ct.plausible_head((300).to_bytes(4, "little")[:2])


def test_plausible_head4_asks_text_after_the_opening_of_a_keystream_reading():
    assert ct.plausible_head4(b'{"ca', 50) and ct.plausible_head4(b"\xa2\x68ca", 50) and ct.plausible_head4(b"key=", 50)
    assert not ct.plausible_head4(b'{"\x00\x01', 50) and not ct.plausible_head4(b"\xa2\x68\x80\x81", 50)
    assert ct.plausible_head4((300).to_bytes(4, "little"), 300)         # BSON: the whole int32 length
    assert not ct.plausible_head4(b'{"c', 50)                            # three bytes are not four


def test_prng_seeds_are_bounded_and_skip_the_record_itself():
    data = b"A" * 40 + b"HCFG" + b"\x01\x02" + struct.pack("<HI", 4, 0) + b"7777" + b"x" * 40 + b" 4242 "
    seeds = ct.prng_seeds(data, 40, 56, 0x02)
    assert seeds[0] == 0x02 and 4242 in seeds and 7777 not in seeds
    assert len(seeds) == len(set(seeds)) <= ct.PRNG_SEEDS


# ---------------------------------------------------------------------------- the opener and the lane gate

def test_opener_fixtures_read_through_the_cli(tmp_path, capsys):
    B = bf.BUILDERS
    for name, hows in (("hcfg_crc_cheap", ["rotate_r3", "repeating_add", "repeating_add", "deflate_raw", "rle_cb",
                                           "packbits", "bz2", "lzma", "lz4f", "rle_bc", "deflate_raw_outer",
                                           "bz2_outer", "rle_cb_outer"]),
                       ("hcfg_crc_costly", ["lznt1", "lzss", "chacha20", "prng_msvc"]),
                       ("hcfg_crc_costly_lz", ["lz4", "lz4_sized", "aplib", "salsa20"]),
                       ("hcfg_crc_costly_lcg", ["prng_ansi", "prng_nr", "prng_minstd", "prng_glibc"]),
                       ("hcfg_crc_costly_java", ["prng_java_bytes", "prng_java_int256", "prng_xorshift32",
                                                 "prng_mt19937"]),
                       ("hcfg_crc_costly_py", ["prng_py_getrandbits8", "prng_py_randint", "prng_py_randbytes",
                                               "lznt1_outer"])):
        path = B[name](tmp_path / name)
        hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=0)
        with loadclock.cpu_clock():
            assert ct.main([str(path)]) == 0
        out = capsys.readouterr().out
        assert [line.split(" how=")[1].split()[0] for line in out.splitlines() if " how=" in line] == hows
    for name in ("hcfg_crc_broken", "hcfg_crc_broken_lz", "hcfg_crc_broken_lcg", "hcfg_crc_broken_java",
                 "hcfg_crc_broken_py"):
        path = B[name](tmp_path / name)
        hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=0)
        with loadclock.cpu_clock():
            assert ct.main([str(path)]) == 0
        assert "no CRC-valid container" in capsys.readouterr().out, name


def test_the_fixture_prng_encoders_match_the_public_reference_outputs():
    # binary_fixtures' encoders are a second implementation of each generator, pinned to the same public vectors
    import numpy as np
    assert bf.glibc_stream(1, 3) == bytes(v & 0xFF for v in (1804289383, 846930886, 1681692777))
    assert bf.lcg_stream(1, 1, 1103515245, 12345, 16) == bytes([16838 & 0xFF])
    assert bf.java_next32(42, 1) == [-1170105035 & 0xFFFFFFFF]
    assert bf.xorshift32_stream(1, 1) == bytes([270369 & 0xFF])
    assert bf.minstd_stream(1, 1) == bytes([16807 & 0xFF])
    ref = np.random.RandomState(5489).randint(0, 2 ** 32, size=700, dtype=np.uint32)   # past one twist
    assert bf.mt19937_stream(5489, 700) == bytes(int(v) & 0xFF for v in ref)


def test_the_binary_hcfg_opener_arms_and_the_lane_gate_replays_it_warm(tmp_path):
    o = openers.for_lane("binary-hcfg")
    assert o.engine == "binary.crc_transforms" and o.category == "Binary"
    r = openers.arm(o, guard="hook", timeout=240)
    assert r.status == openers.ARMED, (r.reason, r.output)
    g = regress.gate("binary-hcfg", workdir=tmp_path, guard="hook", record=False, cap=240)
    assert g.verdict == regress.YES, g.reason
    # six cases (cheap, costly, costly_lz, costly_lcg, costly_java, costly_py) and five controls: the gate replays a
    # record of every crc_transforms family but lzss0 (a ring-fill difference only the decoder test below shows)
    assert len(o.all_cases) == 6 and len(o.controls) == 5
    assert sorted(c.status for c in g.cases) == [regress.PASS] * 11
    g2 = regress.gate("binary-hcfg", workdir=tmp_path, guard="hook", record=False, cap=240)
    assert g2.verdict == regress.YES and [c.status for c in g2.cases] == [regress.WARM] * 11


# ---------------------------------------------------------------------------- generic: xor_key_answer, trailer

@pytest.mark.parametrize("how, kb", [("rotate_r3", b"\x5a"), ("repeating_add", b"\x01\x02"),
                                     ("chacha20", b"k" * 32), ("prng_msvc", None)])
def test_xor_key_is_unsure_where_the_header_byte_is_not_the_xor_key(how, kb):
    g = _generic()
    cfg = {"key": 0x5A, "how": how, "crc32": 1, "crc_ok": True, "json": {}}
    if kb is not None:
        cfg["key_bytes"] = kb
    got = g.xor_key_answer(cfg)
    assert got != "0x5a" and labels.is_unsure(got)


@pytest.mark.parametrize("how", ["deflate_raw", "lznt1_outer", "packbits", "xor"])
def test_xor_key_stays_plain_where_the_payload_is_xored_with_the_header_byte(how):
    assert _generic().xor_key_answer({"key": 0x5A, "how": how, "crc32": 1, "crc_ok": True, "json": {}}) == "0x5a"


def test_near_keyed_readings_are_the_stream_and_prng_ones():
    assert all(ct.near_keyed(h) for h in ("chacha20", "salsa20", "prng_msvc", "prng_mt19937"))
    assert not any(ct.near_keyed(h) for h in ("rotate_r3", "lznt1", "repeating_add", "rc4", None))


def test_a_near_keyed_record_has_its_members_layers_read_as_rc4s_are():
    # as for RC4 (the review of the Day 19 build): a record keyed from nearby bytes, read alone, hid a second
    # record of another reading, so the member's layers are read too and both enter the pool
    import base64
    from Cryptodome.Cipher import ChaCha20
    g = _generic()
    a = bf.config("B246-near-a")
    near = bf.CHACHA_KEY + b"\x00" + bf.CHACHA_NONCE + PAD + bf.record(
        a, ChaCha20.new(key=bf.CHACHA_KEY, nonce=bf.CHACHA_NONCE).encrypt(a), 0x63)
    b = bf.config("B246-layer-b")
    member = PAD + near + PAD + base64.b64encode(bf.record(b, bf.xor1(b, 0x2B), 0x2B)) + PAD
    hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=0)
    with loadclock.cpu_clock():
        pool, _, _ = g._build_pool([("m.bin", bytes(bytearray(member)))])
    assert sorted(c["json"]["campaign"] for _, c in pool) == ["B246-layer-b", "B246-near-a"]


def _trailer_member(order: str, proof: str, flip: bool = False) -> bytes:
    rec = bf.record(PLAIN, bf.xor1(PLAIN, 0x2B), 0x2B)
    trailing = b"scratch-bytes-after-the-record"
    body = rec if proof == "record" else trailing
    crc = zlib.crc32(body) & 0xFFFFFFFF
    head = b"TR46" + b"\x00\x01" + struct.pack(order + "I", crc ^ (1 if flip else 0)) \
        + struct.pack(order + "H", len(rec)) + struct.pack(order + "I", len(trailing)) + struct.pack(order + "H", 7)
    return b"\x7fELF" + b"\x00" * 200 + head + rec + trailing


@pytest.mark.parametrize("order, proof", [(">", "record"), ("<", "trailing"), (">", "trailing")])
def test_a_tagged_trailer_proved_by_crc32_with_either_byte_order_is_read(order, proof):
    g = _generic()
    data = _trailer_member(order, proof)
    ov, why = g.tagged_trailer(data)
    assert ov is not None, why
    f = ov["fields"]
    assert ov["offset"] == 204 and ov["record"]["json"] == json.loads(PLAIN)
    assert f["proof"] == ("crc32be" if order == ">" else "crc32le")
    assert f["byteorder"] == ("big" if order == ">" else "little") and f["digest_width"] == 4
    opts = dict(g.trailer_field_options(data, ov, "analysis_trailer_flags"))
    assert opts.get(f"u16{'b' if order == '>' else 'l'}e@+{ov['head'] - 2}") == "7"
    ov, _ = g.tagged_trailer(_trailer_member(order, proof, flip=True))
    assert ov is None


# ---------------------------------------------------------------------------- judged_forms: role-prefixed ids

def test_role_prefixed_config_ids_are_config_members():
    for f in ("d22_analysis_plugin_config_ipv4", "d27_analysis_gcc_config_campaign", "analysis_plugin_xor_key_hex",
              "d21_analysis_false_friend_config_campaign", "d20_analysis_config_ipv4", "analysis_compact_config_url"):
        assert judged_forms.is_config_member(f), f
    for f in ("d02_cpp_config_crc32", "analysis_configuration_name", "analysis_plugin_count", "analysis_config"):
        assert not judged_forms.is_config_member(f), f
    assert judged_forms.base_config_slot("d22_analysis_plugin_config_ipv4") == "analysis_config_ipv4"
    assert judged_forms.base_config_slot("analysis_plugin_xor_key_hex") == "analysis_xor_key_hex"
    assert judged_forms.base_config_slot("d20_analysis_config_ipv4") == ""


def test_a_role_prefixed_id_is_held_on_an_unjudged_text_and_judged_on_the_base_slots_text():
    table = judged_forms.judged_texts()
    base_text = sorted(table["analysis_config_ipv4"])[0]
    new = "d29_analysis_newrole_config_ipv4"                    # a role the judge never took
    assert judged_forms.text_judged(new, base_text)            # the house paragraph the base slot was judged under
    assert not judged_forms.text_judged(new, base_text + " give the address defanged with [.] in place of dots")
    # a judged role variant keeps its own judged texts
    own = sorted(table["analysis_plugin_config_domain"])[0]
    assert judged_forms.text_judged("d21_analysis_plugin_config_domain", own)


# ---------------------------------------------------------------------------- stated definitions (stated_define)

def _sd():
    import stated_define
    return stated_define


def _entropy(b: bytes) -> float:
    import math
    from collections import Counter
    return -sum(c / len(b) * math.log2(c / len(b)) for c in Counter(b).values())


def test_a_normalised_entropy_is_read_only_when_its_scale_is_stated():
    sd = _sd()
    blob = bytes(range(256)) * 3 + b"A" * 200 + b"zz"
    want = f"{_entropy(blob) / 8:.4f}"
    assert want != f"{_entropy(blob):.4f}"
    for text in ("What is the normalized Shannon entropy of the whole member (bits per byte divided by 8), rounded "
                 "to 4 decimal places?",
                 "Give the normalised Shannon entropy, in the range [0, 1], of the whole file rounded to 4 decimal "
                 "places."):
        key, opts, _, kind = sd.definition({"question": text}, [("m.bin", blob)])
        assert kind == "entropy" and "entropy_normalised+member+4dp+round" in key
        assert opts == [("shannon_bits_per_byte_over_8", want)]
    with pytest.raises(sd.Unread, match="normalised by"):
        sd.definition({"question": "What is the normalized Shannon entropy of the whole member, rounded to 4 "
                                   "decimal places?"}, [("m.bin", blob)])
    key, opts, _, _ = sd.definition({"question": "What is the Shannon entropy of the whole member in bits per byte, "
                                                 "rounded to 4 decimal places?"}, [("m.bin", blob)])
    assert opts == [("shannon_bits_per_byte", f"{_entropy(blob):.4f}")]


def _pe_with_exports(n_functions: int):
    import binary_lookahead as L
    import binfmt
    data = bytearray(L.pe64(sections=[(".text", b"\xc3" * 16, 0x60000020)], exports=["alpha", "beta", "gamma"]))
    info = binfmt.pe(bytes(data))
    at = binfmt.pe_offset(info["sections"], info["dirs"]["export"][0])
    struct.pack_into("<I", data, at + 20, n_functions)          # NumberOfFunctions (the EAT, gaps included)
    return bytes(data)


def test_a_pe_export_count_is_read_by_the_count_the_text_states():
    sd = _sd()
    members = [("lib.dll", _pe_with_exports(5))]
    key, opts, _, _ = sd.definition({"question": "How many exported functions does the DLL export by name?"}, members)
    assert "count+pe_exports+by_name" in key and opts == [("number_of_names", "3")]
    key, opts, _, _ = sd.definition({"question": "What is the number of entries in the export address table "
                                                 "(NumberOfFunctions) of the DLL?"}, members)
    assert "count+pe_exports+eat" in key and opts == [("number_of_functions", "5")]
    with pytest.raises(sd.Unread, match="by name or by the export address table"):
        sd.definition({"question": "How many exported functions does the DLL have?"}, members)


def _pe_with_delay_imports(n: int):
    import binary_lookahead as L
    descs = b"".join(struct.pack("<8I", 1, 0x1100 + 16 * i, 0x1200, 0x1300, 0x1400, 0, 0, 0) for i in range(n))
    payload = descs + bytes(32) + b"\x00" * 64
    data = bytearray(L.pe64(sections=[(".didat", payload, 0x40000040)]))
    opt = 0x58
    struct.pack_into("<II", data, opt + 112 + 8 * 13, 0x1000, len(descs) + 32)   # IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
    return bytes(data)


def test_a_delay_load_dll_count_is_read_and_a_delay_function_count_is_not():
    sd = _sd()
    members = [("app.exe", _pe_with_delay_imports(3))]
    key, opts, _, _ = sd.definition({"question": "How many DLLs are delay-loaded by the executable?"}, members)
    assert "count+pe_delay_import_descriptors" in key and opts == [("delay_import_descriptors", "3")]
    key, opts, _, _ = sd.definition({"question": "What is the number of delay-import descriptors in the PE?"},
                                    members)
    assert opts == [("delay_import_descriptors", "3")]
    with pytest.raises(sd.Unread):
        sd.definition({"question": "How many delay-load imported functions does the executable have?"}, members)
    with pytest.raises(sd.Unread, match="no delay-import directory"):
        sd.definition({"question": "How many DLLs are delay-loaded by the executable?"},
                      [("app.exe", _pe_with_exports(3))])
