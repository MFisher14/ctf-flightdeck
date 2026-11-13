#!/usr/bin/env python3
"""Permanent battery for the wave 15 Warmups esolang build (2026-10-24): Chef and Shakespeare.

  .venv/bin/python -m pytest tests/test_wave15_esolang2.py   (or `python tests/test_wave15_esolang2.py`)

  interp    each interpreter's own encoder round-trips through its reader; Chef arithmetic and dry
            (number) output; strict refusals (input, a loop, a non-halting program, a bad code point,
            a missing Serves, Chef "Mix well", SPL three-on-stage, an unknown line) all yield None;
            determinism (the same bytes twice).
  wired     esolang2.py is imported by crib_decode.py with the esolang guard pattern: ESL2 is live,
            its names are strict, _step_fn resolves them, and a Chef / Shakespeare program that prints
            the sentence is answered PLAIN and right through the real solve_blob (3 fresh slugs each),
            including under an outer base64 layer.
  wrong     decoys (a Chef / SPL program that prints something other than the sentence) and noise
            (random bytes under each language's structure) never give a wrong plain slug.
  regress   plain / hex / base64 / base32 / rot13 of the sentence still read right and their chains
            name no esolang2 step; _which on a base64 payload is a cheap no-op (no interpreter runs).
  saved     no saved Warmups payload (whole blob or numbered record) is read by any esolang2 reader
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
import esolang2 as E  # noqa: E402

sys.path.insert(0, str(REPO / "tests"))
from sh09_clocks import cpu_clock  # noqa: E402

SENT = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
rnd = random.Random(15)
def check(ok, name, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + str(detail)) if detail and not ok else ""))
    assert ok, name + ((" :: " + str(detail)) if detail else "")


def slug():
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
# The raised budget was not enough: the readers' own backstops (esolang2.READER_TIME, 50 ms, and the other
# per-reader caps crib_decode keeps) are wall clock too, and a full-suite run cut a Shakespeare read with them
# (SH-09). So the wired reads run on the CPU clock (sh09_clocks.cpu_clock): every budget and cap keeps its
# number, counted in seconds of this process's work, which waiting for a core does not spend.
WIRED_BUDGET = 5.0


def solve_wired(blob):
    with cpu_clock():
        return solve(blob, budget=WIRED_BUDGET)


def plain_ok(ans, truth):
    if ans == truth:
        return True
    return isinstance(ans, str) and ans.startswith("??") and (json.dumps(truth) in ans or truth in ans)


def wrong_plain(ans, truth):
    return isinstance(ans, str) and not ans.startswith("??") and ans != truth


# ---- interp --------------------------------------------------------------------------------------
def test_interp():
    for name, enc in E.ENCODERS.items():
        data = (SENT + slug()).encode()
        check(E.BY_NAME[name](enc(data)) == data, "interp: %s encode/decode round-trip" % name)

    # Chef arithmetic and dry (number) output.
    chef_num = b"""Num.

Ingredients.
2 g a
3 g b

Method.
Put a into the mixing bowl.
Combine b into the mixing bowl.
Pour contents of the mixing bowl into the baking dish.

Serves 1.
"""
    check(E.d_chef(chef_num) == b"6", "interp: chef arithmetic (2*3) prints the dry number")

    # Chef strict refusals.
    check(E.d_chef(chef_num.replace(b"Serves 1.", b"")) is None, "interp: chef without Serves -> None")
    chef_input = chef_num.replace(b"Put a into the mixing bowl.", b"Take a from refrigerator.")
    check(E.d_chef(chef_input) is None, "interp: chef input (Take from refrigerator) -> None")
    chef_mix = chef_num.replace(b"Combine b into the mixing bowl.", b"Mix the mixing bowl well.")
    check(E.d_chef(chef_mix) is None, "interp: chef Mix well (non-deterministic) -> None")
    chef_loop = chef_num.replace(b"Combine b into the mixing bowl.",
                                 b"Cook the a. Combine b into the mixing bowl. Serve until cooked.")
    check(E.d_chef(chef_loop) is None, "interp: chef loop (... until ...) -> None")
    chef_aux = chef_num.replace(b"Pour contents of the mixing bowl into the baking dish.",
                                b"Serve with sauce. Pour contents of the mixing bowl into the baking dish.")
    check(E.d_chef(chef_aux) is None, "interp: chef auxiliary-recipe call (Serve with) in the method -> None")
    chef_bad = b"""Bad.

Ingredients.
1114112 ml a

Method.
Put a into the mixing bowl.
Pour contents of the mixing bowl into the baking dish.

Serves 1.
"""
    check(E.d_chef(chef_bad) is None, "interp: chef out-of-range code point -> None")

    # Shakespeare strict refusals.
    spl = E.shakespeare_encode((SENT + slug()).encode()).decode()
    spl_input = spl.replace("Speak your mind.", "Listen to your heart.", 1)
    check(E.d_shakespeare(spl_input.encode()) is None, "interp: SPL input (Listen to your heart) -> None")
    spl_three = spl.replace("[Enter Romeo and Juliet]", "[Enter Romeo and Juliet and Hamlet]")
    # add Hamlet to the personae so the parser knows the name
    spl_three = spl_three.replace("Juliet, a young woman.", "Juliet, a young woman.\nHamlet, a prince.")
    check(E.d_shakespeare(spl_three.encode()) is None, "interp: SPL three on stage -> None")
    spl_junk = spl.replace("[Exeunt]", "Romeo: Flibbertigibbet wobble zonk.\n\n[Exeunt]")
    check(E.d_shakespeare(spl_junk.encode()) is None, "interp: SPL unparseable line -> None")

    # SPL non-halting: a scene that gotos itself forever and prints nothing -> step/time cap -> None.
    spl_loop = """The Loop.

Romeo, a man.
Juliet, a woman.

Act I: Spin.

Scene I: Forever.

[Enter Romeo and Juliet]

Romeo: You are nothing. Let us proceed to scene I.

[Exeunt]
"""
    # Bounded in this thread's CPU time: the caps bound work, and a process waiting for a core on a loaded
    # machine does none (SH-09). The reader's own backstop is wall time, so under load it stops sooner.
    t0 = time.thread_time()
    check(E.d_shakespeare(spl_loop.encode()) is None and time.thread_time() - t0 < 1.0,
          "interp: SPL non-halting goto -> None (bounded, under 1 s of CPU)")

    # Determinism: the same program gives the same bytes twice.
    data = (SENT + slug()).encode()
    cp = E.chef_encode(data)
    check(E.d_chef(cp) == E.d_chef(cp) == data, "interp: chef is deterministic")


# ---- wired ---------------------------------------------------------------------------------------
def test_wired():
    check(C.ESL2 is E and set(E.NAMES) <= C._STRICT_NAMES, "wired: ESL2 live and strict")
    check(all(C._step_fn(n) is not None for n in E.NAMES), "wired: _step_fn resolves esolang2 names")
    for name, enc in E.ENCODERS.items():
        res = []
        for _ in range(3):
            s = slug()
            ans, chain = solve_wired(enc((SENT + s).encode()))
            flat = [x for c in (chain or ()) for x in (c if isinstance(c, (list, tuple)) else [c])]
            res.append((ans == s, name in flat, chain))
        check(all(a and named for a, named, _ in res), "wired: %s plain, right and chain-named" % name, res)

    # layered: base64 of a Chef program read through both layers.
    s = slug()
    ans, chain = solve_wired(base64.b64encode(E.chef_encode((SENT + s).encode())))
    flat = [x for c in (chain or ()) for x in (c if isinstance(c, (list, tuple)) else [c])]
    check(ans == s and "chef" in flat and "b64" in flat, "wired: base64(chef) read through both layers", (ans, chain))


# ---- wrong ---------------------------------------------------------------------------------------
def test_wrong():
    bad = 0
    for _ in range(12):
        s = slug()
        decoys = [
            E.chef_encode(("totally wrong text %d" % rnd.randint(0, 9999)).encode()),
            E.shakespeare_encode(("another wrong string %d" % rnd.randint(0, 9999)).encode()),
            # Chef/SPL structure wrapped around random noise.
            (b"Noise.\n\nIngredients.\n%d g x\n\nMethod.\nPut x into the mixing bowl.\n"
             b"Pour contents of the mixing bowl into the baking dish.\n\nServes 1.\n" % rnd.randint(0, 255)),
            bytes(rnd.randrange(256) for _ in range(120)),
        ]
        for blob in decoys:
            ans, _ = solve(blob)
            bad += wrong_plain(ans, s)
    check(bad == 0, "wrong: no wrong plain answer on decoys / noise", bad)


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
    check(not read_by, "saved: no saved Warmups payload is read by any esolang2 reader (%d whole + %d records)"
          % (whole, recs), read_by[:10])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
