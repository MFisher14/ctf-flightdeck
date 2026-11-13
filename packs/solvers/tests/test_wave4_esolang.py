#!/usr/bin/env python3
"""Permanent battery for the wave 4 Warmups esolang build (2026-10-23):

  .venv/bin/python -m pytest tests/test_wave4_esolang.py   (or `python tests/test_wave4_esolang.py`)

  vm        the sandboxed brainfuck VM: a round-trip of the four dialects' encoders; a non-halting
            program, an executed input command, unbalanced brackets, a pointer off the tape, Spoon's
            DEBUG command and over-long output all yield None; Spoon's END halts; garbage yields None.
  wired     esolang.py is imported by crib_decode.py with the base_extra guard pattern: ESL is live,
            its names are strict, _step_fn resolves them, and an alphuck / pikalang / blub / spoon
            program that prints the sentence is answered PLAIN and right through the real solve_blob
            (3 fresh slugs each), including under an outer base64 layer.
  wrong     decoys and noise (random text over each dialect's alphabet, random bytes) never give a
            wrong plain slug.
  regress   plain / hex / base64 / base32 / rot13 of the sentence still read right and their chains
            name no esolang step; the common path is not slowed and no VM runs on a non-dialect blob.
  saved     no saved Warmups payload (whole blob or numbered record) is read by any esolang reader
            (not run unless $CTF_REAL_CHALLENGES names the saved attempts).
"""
import base64
import codecs
import glob
import json
import os
import random
import sys
import time
from pathlib import Path

import pytest

from ctf import paths

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
for _p in (REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    sys.path.insert(0, str(_p))

import crib_decode as C  # noqa: E402
import esolang as E  # noqa: E402

sys.path.insert(0, str(REPO / "tests"))
from sh09_clocks import cpu_clock  # noqa: E402

SENT = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
rnd = random.Random(4)
def check(ok, name, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + str(detail)) if detail and not ok else ""))
    assert ok, name + ((" :: " + str(detail)) if detail else "")


def slug():
    # The lane's slug shape: three words and a two-digit suffix (as the saved attempts use).
    a = ["brave", "crisp", "nimble", "dainty", "quick", "jolly"]
    b = ["blanket", "compass", "canyon", "quill", "zephyr", "castle"]
    c = ["clover", "coral", "birch", "laurel", "pine", "fjord"]
    return "%s-%s-%s-%02d" % (rnd.choice(a), rnd.choice(b), rnd.choice(c), rnd.randint(10, 99))


def solve(blob, budget=None):
    kw = {} if budget is None else {"budget": budget}
    got = C.solve_blob(blob if isinstance(blob, bytes) else blob.encode(), day=25, **kw)
    return (got[0] if got else None), (got[1] if got else None)

# The wired reads are correctness checks (a dialect program is answered PLAIN and right), not timing
# checks: solve_blob's budget is wall-clock, and under a loaded full-suite run (xdist workers beside other
# jobs) the default budget occasionally ran out before the dialect step and the read came back None
# (R-01; the same reasoning as tests/test_warmups_day16.py). The regress test still times the common path.
# The raised budget was not enough: the readers' own backstops (esolang.READER_TIME, 50 ms, and the other
# per-reader caps crib_decode keeps) are wall clock too, and a full-suite run cut a Spoon read with them
# (SH-09). So the wired reads run on the CPU clock (sh09_clocks.cpu_clock): every budget and cap keeps its
# number, counted in seconds of this process's work, which waiting for a core does not spend.
WIRED_BUDGET = 5.0


def solve_wired(blob):
    with cpu_clock():
        return solve(blob, budget=WIRED_BUDGET)


def plain_ok(ans, truth):
    """Plain and right, or unsure with the truth among its options (the digit rule the ledger has not
    judged for a fresh slug)."""
    if ans == truth:
        return True
    return isinstance(ans, str) and ans.startswith("??") and (json.dumps(truth) in ans or truth in ans)


def wrong_plain(ans, truth):
    return isinstance(ans, str) and not ans.startswith("??") and ans != truth


# ---- vm ------------------------------------------------------------------------------------------
# A round-trip of each dialect's own encoder through its reader (the VM + the token map).
def test_vm():
    for name, enc in E.ENCODERS.items():
        data = (SENT + slug()).encode()
        check(E.BY_NAME[name](enc(data)) == data, "vm: %s encode/decode round-trip" % name)

    # A concatenated (white-space-free) alphuck program decodes too (alphuck ignores white space).
    data = (SENT + slug()).encode()
    spaced = E.enc_alphuck(data)
    check(E.d_alphuck(spaced) == data and E.d_alphuck(spaced.replace(b"j", b"j ")) == data,
          "vm: alphuck white space is ignored")

    check(E.run_bf("+" * 20 + "[]", deadline=time.perf_counter() + 0.05) is None, "vm: non-halting -> None")
    check(E.run_bf(",.") is None, "vm: executed input command -> None")
    check(E.run_bf("+[.") is None, "vm: unbalanced brackets -> None")
    check(E.run_bf(">" * (E.CELLS + 1) + ".") is None, "vm: pointer off the tape -> None")
    check(E.run_bf("+.", out_cap=0) is None, "vm: output over the cap -> None")
    check(E.run_bf("++") is None, "vm: a program with no output instruction -> None")
    check(E.run_bf("++.") == b"\x02", "vm: a simple program prints")
    # Spoon: END halts (so trailing bits after it are ignored), DEBUG has no deterministic text (refused).
    _spoon_data = (SENT + slug()).encode()
    _spoon_prog = E.enc_spoon(_spoon_data)              # already ends in END (00101111)
    check(E.d_spoon(_spoon_prog + b"1111") == _spoon_data, "vm: spoon END halts (trailing bits ignored)")
    check(E.d_spoon(("1" * 16 + "00101110").encode()) is None, "vm: spoon DEBUG command -> None")
    check(E.steps(bytes(rnd.randrange(256) for _ in range(200))) == [], "vm: random bytes -> no reading")


# ---- wired ---------------------------------------------------------------------------------------
def test_wired():
    check(C.ESL is E and set(E.NAMES) <= C._STRICT_NAMES, "wired: ESL live and strict")
    check(all(C._step_fn(n) is not None for n in E.NAMES), "wired: _step_fn resolves esolang names")
    for name, enc in E.ENCODERS.items():
        res = []
        for _ in range(3):
            s = slug()
            ans, chain = solve_wired(enc((SENT + s).encode()))
            flat = [x for c in (chain or ()) for x in (c if isinstance(c, (list, tuple)) else [c])]
            res.append((ans == s, name in flat, chain))
        check(all(a and named for a, named, _ in res), "wired: %s plain, right and chain-named" % name, res)

    # layered: base64 of a dialect program
    s = slug()
    ans, chain = solve_wired(base64.b64encode(E.enc_alphuck((SENT + s).encode())))
    flat = [x for c in (chain or ()) for x in (c if isinstance(c, (list, tuple)) else [c])]
    check(ans == s and "alphuck" in flat and "b64" in flat, "wired: base64(alphuck) read through both layers", (ans, chain))


# ---- wrong ---------------------------------------------------------------------------------------
def test_wrong():
    bad = 0
    for _ in range(20):
        s = slug()
        noise = [
            "".join(rnd.choice("aceijops ") for _ in range(140)),            # alphuck alphabet, random
            "".join(rnd.choice("pikachu ") for _ in range(140)),             # pikalang alphabet, random
            " ".join("Blub" + rnd.choice(".?!") for _ in range(90)),          # blub tokens, random (fishfood too)
            "".join(rnd.choice("01") for _ in range(260)),                    # spoon bits, random
            bytes(rnd.randrange(256) for _ in range(100)),
        ]
        for blob in noise:
            ans, _ = solve(blob)
            bad += wrong_plain(ans, s) or (isinstance(ans, str) and not ans.startswith("??") and ans != s)
    check(bad == 0, "wrong: no plain answer on decoys / noise", bad)


# ---- regress -------------------------------------------------------------------------------------
def test_regress():
    for label, fn in (("plain", lambda b: b), ("hex", lambda b: b.hex().encode()), ("b64", base64.b64encode),
                      ("b32", base64.b32encode), ("rot13", lambda b: codecs.encode(b.decode(), "rot13").encode())):
        s = slug()
        t0 = time.perf_counter()
        ans, chain = solve(fn((SENT + s).encode()))
        dt = time.perf_counter() - t0
        flat = [x for c in (chain or ()) for x in (c if isinstance(c, (list, tuple)) else [c])]
        named = [x for x in flat if x in E.NAMES]
        check(plain_ok(ans, s) and not named and dt < 3.0, "regress: %s" % label, (ans, chain, round(dt, 3)))

    # the common path is not slowed: _which rejects a base64 / hex payload with no VM run, in microseconds
    pay = base64.b64encode((SENT + slug()).encode())
    t0 = time.perf_counter()
    for _ in range(2000):
        E._which(pay)
    dt = (time.perf_counter() - t0) / 2000
    check(E._which(pay) == () and E.steps(pay) == [] and dt < 5e-5,
          "regress: _which on a base64 payload is a cheap no-op (%.1f us)" % (dt * 1e6), dt)


# ---- saved ---------------------------------------------------------------------------------------
def saved_warmups_files():
    """Every saved Warmups artifact file under $CTF_REAL_CHALLENGES (the saved Huntress attempts, read only);
    the test does not run when that is unset or holds fewer than 50 files. Resolved through
    ctf.paths.saved_challenges_root(): set to a missing folder, it raises FileNotFoundError (the test fails)."""
    root = paths.saved_challenges_root()
    if root is None:
        pytest.skip("not run: CTF_REAL_CHALLENGES is not set (the saved past-event attempts)")
    files = sorted(f for f in glob.glob(str(root / "day-*" / "warmups*" / "**" / "artifact" / "**" / "*"),
                                        recursive=True) if os.path.isfile(f))
    if len(files) < 50:
        pytest.skip(f"fewer than 50 saved Warmups artifact files under {root} ({len(files)})")
    return files


def test_saved():
    files = saved_warmups_files()
    whole = recs = 0
    read_by = []
    for f in files:
        try:
            raw = open(f, "rb").read()
        except OSError:
            continue
        whole += 1
        if E.steps(raw):
            read_by.append((f, "whole"))
        try:
            parts = C.numbered(raw)
        except Exception:
            parts = None
        for i, rec in enumerate(parts or ()):
            rb = rec if isinstance(rec, (bytes, bytearray)) else str(rec).encode()
            recs += 1
            if E.steps(rb):
                read_by.append((f, "record %d" % i))
    check(not read_by, "saved: no saved Warmups payload is read by any esolang reader (%d whole + %d records)"
          % (whole, recs), read_by[:10])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
