#!/usr/bin/env python3
"""Edge/adversarial battery for the Day 23 Warmups modern-codec hardening
(solvers/warmups/layered_decode.py d_compress; notes docs/retro/warmups-codec-harden-notes.md).

  .venv/bin/python -m pytest tests/test_day23_warmups_edges.py   (or `python tests/test_day23_warmups_edges.py`)

No network and no token. Each per-codec check is one test per codec; a codec whose optional library
(zstandard, lz4, brotli, python-snappy) is absent is reported NOT RUN by the needs_tool marker, naming the
module, never left out and passed. This is a PERMANENT regression guard, not a one-off check.

Why it exists: the review of the modern-codec build flagged that the magic-less brotli/snappy
try-decode runs on every non-ASCII search state, and that any of the new decoders (zstd, brotli,
lz4 frame, snappy, the header-less LZMA "alone" format) could be handed a crafted decompression bomb.
d_compress now caps every decoder's output at _COMP_CAP (1 MiB) -- before the buffer is allocated
where the codec exposes the size first (zstd frame header, snappy length varint, LZMA dictionary via
memlimit), and otherwise with a bounded incremental read -- so a crafted input cannot make it allocate
gigabytes or stall a window. Rejecting fails CLOSED: a dropped stream is a clean None, never a wrong
plain slug (never-guess). The shipped gzip/zlib/bz2/xz paths share the same cap.

What is checked (every codec present on this machine):
  reads      the real codecs still decode to the exact payload (the cap did not break decoding); 0 WRONG.
  bomb       a 64 MiB-output bomb per codec is rejected (None) within the cap: peak memory stays far
             below the bomb size and the call returns fast -- measured, so no OOM and no hang.
  dict-bomb  a crafted gigabyte-dictionary xz/.lzma stream is rejected before anything is allocated.
  pipeline   a base64-wrapped bomb driven through the real solver (crib_decode.solve_blob, the search
             that feeds every non-ASCII state to d_compress) returns None, bounded and fast.
  truncated  a truncated stream of each codec is a clean None (or at worst <= cap), never a crash.
  wrong-magic a valid stream behind the wrong magic is not cross-decoded into anything.
  weak-crib  garbage (and an OVER-CAP but crib-matching decompression) never yields a wrong plain slug.
  empty/big  empty input, over-cap valid input, and a multi-megabyte garbage blob are all handled fast.
  hotpath    the magic-less brotli/snappy try-decode stays microsecond-cheap on random non-ASCII states.
"""
import base64
import bz2
import gzip
import lzma
import os
import sys
import time
import tracemalloc
import zlib
from pathlib import Path

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
VERBOSE = "-v" in sys.argv[1:]
for _p in (REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    sys.path.insert(0, str(_p))

import pytest               # noqa: E402

import layered_decode as L  # noqa: E402
import crib_decode as C     # noqa: E402
import labels               # noqa: E402

CAP = L._COMP_CAP                       # 1 MiB
BIGN = 64 << 20                         # bomb output size: if the cap failed this would be allocated
# The 64 MiB bomb input is built when a test needs it, never at import: every pytest worker imports this
# module during collection, and only the one that runs a test should hold it.
def big():
    return bytes(BIGN)


MEM_CEILING = BIGN // 4                 # 16 MiB: a capped reject stays far below the 64 MiB bomb
TIME_CEILING = 1.0                      # seconds: a reject is fast; a real 64 MiB decode is not
SENTENCE = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
SLUG = "tidy-cloud-tulip-70"
PAYLOAD = (SENTENCE + SLUG).encode()


def check(ok, name, detail=""):
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, (": " + str(detail)[:900]) if detail and (not ok or VERBOSE) else ""),
          flush=True)
    assert ok, "%s: %s" % (name, str(detail)[:900])
    return True


def measure(fn, *a, clock=time.perf_counter, **k):
    """(result, seconds on `clock`, peak MiB) with only this call's Python allocations traced."""
    tracemalloc.start()
    t0 = clock()
    try:
        out = fn(*a, **k)
    finally:
        dt = clock() - t0
        _cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    return out, dt, peak / 1048576.0


def readings_mib(kept):
    """MiB held by the readings dicts in `kept`, each text counted once (sys.getsizeof): the search's own
    working set, sized the same way whether its read finished in time or its deadline cut it."""
    seen, n = set(), 0
    for d in kept:
        n += sys.getsizeof(d)
        for t in d:
            if id(t) not in seen:
                seen.add(id(t))
                n += sys.getsizeof(t)
    return n / 1048576.0


def measure_search(blob, budget):
    """measure(C.solve_blob, blob, budget) plus the MiB of every reading its search made. Each dict
    crib_decode.readings() returns is kept alive until the call ends, so the call's own readings are counted
    whether its read finished or was cut (readings() memoises only a finished one), and _READ_MEMO is cleared
    first so every reading of this call is made, and traced, inside it. The solver is not changed.

    The seconds are this thread's CPU time (SH-09): the search is bounded by its budget, which is work, and a
    full-suite run on a loaded machine took 8.7 s of wall clock for it, waiting for a core. solve_blob's
    budget is wall clock, so under load it stops sooner in CPU, never later; work past it still shows."""
    kept = []
    real = C.readings

    def keep(payload, deadline):
        got = real(payload, deadline)
        kept.append(got)
        return got
    C._READ_MEMO.clear()
    C.readings = keep
    try:
        out, dt, peak = measure(C.solve_blob, blob, budget, clock=time.thread_time)
    finally:
        C.readings = real
    return out, dt, peak, readings_mib(kept)


# --------------------------------------------------------------------------- codec table
# name -> (the optional library it needs as a needs_tool name, or None for the standard library,
#          compress(bytes) -> bytes building a real stream of whatever is given).
# Every per-codec check is one test per codec; a codec whose library is absent is reported NOT RUN
# (needs_tool: py:<module>), never dropped from the table and passed.
def _zstd(b, **kw):
    import zstandard
    return zstandard.ZstdCompressor(**kw).compress(b)


def _lz4frame(b):
    import lz4.frame
    return lz4.frame.compress(b)


def _brotli(b):
    import brotli
    return brotli.compress(b)


def _snappy(b):
    import snappy
    return snappy.compress(b)


CODECS = {
    "gzip":  (None, lambda b: gzip.compress(b)),
    "zlib":  (None, lambda b: zlib.compress(b, 9)),
    "bz2":   (None, lambda b: bz2.compress(b)),
    "xz":    (None, lambda b: lzma.compress(b)),
    "lzma_alone": (None, lambda b: lzma.compress(b, format=lzma.FORMAT_ALONE)),
    "zstd":  ("py:zstandard", _zstd),
    "zstd_nocs": ("py:zstandard", lambda b: _zstd(b, write_content_size=False)),
    "lz4frame": ("py:lz4.frame", _lz4frame),
    "brotli": ("py:brotli", _brotli),
    "snappy": ("py:snappy", _snappy),
}


def codec_params():
    return [pytest.param(name, id=name, marks=[pytest.mark.needs_tool(need)] if need else [])
            for name, (need, _comp) in CODECS.items()]


def compress(name, data):
    return CODECS[name][1](data)


# --------------------------------------------------------------------------- reads (0 WRONG)
@pytest.mark.parametrize("name", codec_params())
def test_reads_0_wrong(name):
    out = L.d_compress(compress(name, PAYLOAD))
    check(out == PAYLOAD, "reads: %s decodes to the exact payload (cap did not break decoding)" % name,
          None if out == PAYLOAD else repr(out)[:80])


# --------------------------------------------------------------------------- decompression bombs
@pytest.mark.parametrize("name", codec_params())
def test_decompression_bombs(name):
    blob = compress(name, big())
    out, dt, peak = measure(L.d_compress, blob)
    check(out is None, "bomb %s: d_compress -> None" % name,
          None if out is None else "len=%d" % len(out))
    check(peak < MEM_CEILING / 1048576.0, "bomb %s: peak %.1f MiB (bomb is %d MiB, cap %d MiB)"
          % (name, peak, BIGN >> 20, CAP >> 20))
    check(dt < TIME_CEILING, "bomb %s: rejected in %.1f ms (no hang)" % (name, dt * 1000))


# snappy's "huge length varint, tiny data" craft: rejected at the varint, before any allocation.
@pytest.mark.needs_tool("py:snappy")
def test_snappy_huge_varint_craft():
    def _uvarint(n):
        o = bytearray()
        while True:
            x = n & 0x7f
            n >>= 7
            o.append(x | 0x80 if n else x)
            if not n:
                return bytes(o)
    craft = _uvarint(10_000_000_000) + b"\x00"
    out, dt, peak = measure(L.d_compress, craft)
    check(out is None and peak < 1.0 and dt < 0.1,
          "bomb snappy-craft: huge-varint rejected with no allocation (%.0f ms, %.1f MiB)" % (dt * 1000, peak))


def test_dictionary_bombs():
    # crafted gigabyte-DICTIONARY lzma/xz: the dictionary is a header-declared allocation the output cap
    # alone does not bound; memlimit rejects it before anything is allocated.
    for name, fmt, filt in [("xz", lzma.FORMAT_XZ, [{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 30}]),
                            ("alone", lzma.FORMAT_ALONE, [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 30, "preset": 6}])]:
        dblob = lzma.compress(big(), format=fmt, filters=filt)
        out, dt, peak = measure(L.d_compress, dblob)
        check(out is None and peak < 2.0 and dt < TIME_CEILING,
              "dict-bomb %s: gigabyte dictionary rejected with no allocation (%.0f ms, %.1f MiB)" % (name, dt * 1000, peak))


# --------------------------------------------------------------------------- pipeline (the flagged surface)
# The real solver's search base64-decodes a state and hands the bytes to d_compress on every non-ASCII
# step (the magic-less brotli/snappy try-decode runs on EVERY non-ASCII state). A base64-wrapped bomb
# must come back None, within its budget, and -- the real proof -- allocate no more than an equal-size
# ORDINARY blob beyond the search's own readings. Those readings are the pre-existing cost, and their size
# follows the clock, not the input: the 87 KB base64 text of the gzip bomb reads to 580 texts (about
# 48 MiB) when its read ends inside its deadline and to 4 (under 1 MiB) when the deadline cuts it, and
# the random baseline reads about twice as slowly. Raw peaks of two calls therefore differed by 48 MiB on
# a loaded machine whenever one read finished and the other was cut, with nothing decompressed (the memo
# changes only what is kept after a call, never its peak). So each call's own readings come off its own
# peak (measure_search): what is left is what the call allocated beyond them, the same whether either read
# finished or was cut, and a bomb decompressed anywhere in the pipeline would show there by its whole size.
# (The gzip stream, 65 KB, is above the 8 KB that crib_decode._safe hands to a decompressor at all; the
# brotli stream, 144 bytes, does reach the capped d_compress.)
@pytest.mark.parametrize("name", [p for p in codec_params() if p.values[0] in ("gzip", "brotli")])
def test_pipeline_the_flagged_surface(name):
    cb = compress(name, big())
    wrapped = base64.b64encode(cb)
    baseline = base64.b64encode(os.urandom(len(cb)))        # same input size, decompresses to nothing
    out, dt, peak, held = measure_search(wrapped, 1.5)
    _b, _dtb, peak_base, held_base = measure_search(baseline, 1.5)
    ok = out is None or labels.parse(out[0]) is not None    # None, or at worst unsure -- never a plain slug
    check(ok, "pipeline b64+%s bomb: solve_blob never emits a plain slug" % name,
          None if ok else repr(out)[:80])
    check(dt < 3.0, "pipeline b64+%s bomb: finishes within its budget, no hang (%.0f ms of CPU)" % (name, dt * 1000))
    check(peak - held <= peak_base - held_base + 16.0,
          "pipeline b64+%s bomb: no extra allocation over same-size data -> never decompressed "
          "(beyond its own readings: bomb %.1f MiB vs baseline %.1f MiB; raw peaks %.1f / %.1f MiB)"
          % (name, peak - held, peak_base - held_base, peak, peak_base))


# --------------------------------------------------------------------------- truncated streams
@pytest.mark.parametrize("name", codec_params())
def test_truncated_streams(name):
    full = compress(name, big())
    trunc = full[:max(3, len(full) // 3)]
    out, dt, peak = measure(L.d_compress, trunc)
    check((out is None or len(out) <= CAP) and peak < MEM_CEILING / 1048576.0 and dt < TIME_CEILING,
          "truncated %s: clean None/<=cap, no crash or hang (%.0f ms, %.1f MiB)" % (name, dt * 1000, peak),
          None if out is None else "len=%d" % len(out))


# --------------------------------------------------------------------------- wrong-magic-but-valid-decode
# A valid stream of one codec placed behind ANOTHER codec's magic must not be cross-decoded. zstd's
# magic routes to the zstd branch, which must reject a gzip body (and the gzip branch never runs,
# because the bytes no longer start with the gzip magic).
@pytest.mark.needs_tool("py:zstandard")
def test_wrong_magic_gzip_body_behind_zstd_magic():
    mixed = b"\x28\xb5\x2f\xfd" + gzip.compress(PAYLOAD)   # zstd magic, gzip body
    out = L.d_compress(mixed)
    check(out is None, "wrong-magic: gzip body behind zstd magic is not cross-decoded", repr(out)[:60])


def test_wrong_decode_junk_is_no_slug():
    # A VALID stream whose decoded content is NOT the sentence (slug-shaped junk) must not yield a plain slug.
    junk_text = b"zzzz zzzz zzzz zzzz " + b"zxqv-wrtx-plmk-88"
    out = C.solve_blob(base64.b64encode(gzip.compress(junk_text)), 1.0)
    ok = out is None or labels.parse(out[0]) is not None
    check(ok, "wrong-decode: a valid gzip of non-sentence junk never yields a plain slug", repr(out)[:80])


# --------------------------------------------------------------------------- garbage passes a weak crib
# An OVER-CAP decompression that WOULD match the crib (the real sentence repeated past 1 MiB) must be
# rejected by the cap, not emitted: the cap is a real never-guess gate even for crib-matching content.
def test_garbage_passes_a_weak_crib():
    over = (SENTENCE + SLUG + "\n").encode() * 20000          # ~2.3 MiB of valid, crib-matching text
    check(len(over) > CAP, "weak-crib setup: the crib-matching payload is over the cap", "%d bytes" % len(over))
    out = L.d_compress(gzip.compress(over))
    check(out is None, "weak-crib: an over-cap crib-matching gzip is rejected (None), not emitted", repr(out)[:40])
    out2 = C.solve_blob(base64.b64encode(gzip.compress(over)), 1.5)
    ok2 = out2 is None or labels.parse(out2[0]) is not None
    check(ok2, "weak-crib: solve_blob does not emit a slug from the over-cap crib-matching bomb", repr(out2)[:80])
    # Pure garbage: random bytes handed to d_compress (which tries every codec's magic and the magic-less
    # brotli/snappy reads) -> None or at most the cap, never more.
    for i in range(len(CODECS)):
        rnd = os.urandom(4096)
        out = L.d_compress(rnd)
        check(out is None or len(out) <= CAP, "weak-crib: random bytes #%d -> None/<=cap" % i)


# --------------------------------------------------------------------------- empty / oversized input
def test_empty_oversized_input():
    out, dt, _p = measure(L.d_compress, b"")
    check(out is None and dt < 0.05, "empty: d_compress(b'') -> None, instant")
    out, dt, _p = measure(C.solve_blob, b"", 0.5)
    check(out is None, "empty: solve_blob(b'') -> None")
    # just-UNDER the cap still decodes (the cap is a ceiling, not a floor)
    justunder = b"\x00" * (CAP - 8192)
    check(L.d_compress(gzip.compress(justunder)) == justunder, "oversized: just-under-cap gzip still decodes")
    # a multi-megabyte garbage blob is handled fast by the solver's own input guard
    out, dt, peak = measure(C.solve_blob, os.urandom(4 << 20), 1.5)
    check(out is None and dt < 1.5 and peak < MEM_CEILING / 1048576.0,
          "oversized: a 4 MiB garbage blob is handled fast (%.0f ms, %.1f MiB)" % (dt * 1000, peak))


@pytest.mark.parametrize("name", codec_params())
def test_just_over_cap_valid_stream_is_rejected(name):
    justover = b"\x00" * (CAP + 65536)
    out = L.d_compress(compress(name, justover))
    check(out is None, "oversized: just-over-cap valid %s is rejected (None)" % name)


# --------------------------------------------------------------------------- hot-path cost
# The magic-less brotli/snappy try-decode runs on every non-ASCII state; it must stay microsecond-cheap.
def test_hot_path_cost():
    states = [bytes([0x80 | (i & 0x3f)]) + os.urandom(8191) for i in range(500)]   # non-ASCII, no known magic
    t0 = time.perf_counter()
    emitted = 0
    for s in states:
        if L.d_compress(s):
            emitted += 1
    per = (time.perf_counter() - t0) / len(states) * 1000
    check(per < 1.0 and emitted == 0,
          "hotpath: magic-less try-decode is %.3f ms/state on random non-ASCII input, 0 false decodes" % per)


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
