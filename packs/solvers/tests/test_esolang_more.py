#!/usr/bin/env python3
"""Permanent battery for solvers/warmups/esolang_more.py (Shakespeare / Rockstar / Chef / Befunge-98):

  .venv/bin/python -m pytest tests/test_esolang_more.py   (or `python tests/test_esolang_more.py`)

No network and no token; this tests the module directly (crib_decode.py wires its Rockstar and Befunge-98 readers since row 547; tests/test_warmups_esolang_sweep.py checks that wiring), so this tests it
directly, the way the Warmups day_patch.py override calls it as a late whole-blob attempt.

  roundtrip  each language's own encoder round-trips through its reader, and read()'s crib gate
             recovers the exact slug (digits and all) for 10 fresh slugs each -- the information-
             complete-transform property that makes a crib-matched reading PLAIN.
  ambiguous  THE never-wrong case (the recurring hole is tests that only cover the easy decode):
             a program that PARSES and HALTS but prints something OTHER than the crib (a different
             sentence, or a bare prefix of the crib) decodes fine yet read() offers NOTHING -- never
             a wrong plain slug. Also: crib + a DIFFERENT slug recovers that other slug, not the first.
  refuse     a program that executes an input instruction, a nondeterministic one, that does not halt
             within the caps, or that does not parse cleanly yields None, for every language.
  gate       _which fires on each real program and is a cheap no-op on base64 / plain English /
             random bytes, so no VM runs on an obvious non-program.
  super98    Befunge-98 is read by its OWN interpreter here (stack-stack, ; comment, ' fetch, k
             iterate) -- not esolangs.py's Befunge-93, which does not have those instructions.
  noise      random text over each language's surface never yields a wrong plain slug.
"""
import base64
import os
import random
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "warmups"))

import esolang_more as E  # noqa: E402

CRIB = E.CRIB
rnd = random.Random(7)
VERBOSE = "-v" in sys.argv


def check(ok, name, detail=""):
    if not ok or VERBOSE:
        print(("PASS " if ok else "FAIL ") + name + ((" :: " + str(detail)) if detail and not ok else ""))
    assert ok, name + ((" :: " + str(detail)) if detail else "")


def slug():
    a = ["brave", "crisp", "nimble", "dainty", "quick", "jolly", "amber", "silent"]
    b = ["blanket", "compass", "canyon", "quill", "zephyr", "castle", "harbor", "meadow"]
    c = ["clover", "coral", "birch", "laurel", "pine", "fjord", "willow", "ember"]
    return "%s-%s-%s-%02d" % (rnd.choice(a), rnd.choice(b), rnd.choice(c), rnd.randint(10, 99))


def recovered(prog):
    """The slug read() recovers from a program, or None if it offers nothing."""
    hits = E.read(prog)
    if not hits:
        return None
    _name, text = hits[0]
    return text[len(CRIB):].strip()


# ---- roundtrip -----------------------------------------------------------------------------------
def test_roundtrip():
    for name, enc in E.ENCODERS.items():
        ok_all = True
        detail = None
        for _ in range(10):
            s = slug()
            data = (CRIB + s).encode()
            prog = enc(data)
            out = E.BY_NAME[name](prog)
            # exact bytes (Rockstar's Shout adds one trailing newline; the crib gate tolerates it)
            exact = out is not None and out.rstrip(b"\n") == data
            got = recovered(prog)
            if not (exact and got == s):
                ok_all = False
                detail = (name, s, got, out[:80] if out else out)
                break
        check(ok_all, "roundtrip: %s encode -> read recovers the exact slug (10 fresh)" % name, detail)

    # the slug's two digits survive (information-complete): a slug whose digits matter
    for name, enc in E.ENCODERS.items():
        s = "amber-harbor-willow-90"
        got = recovered(enc((CRIB + s).encode()))
        check(got == s, "roundtrip: %s pins the slug digits" % name, got)


# ---- ambiguous / never-wrong ---------------------------------------------------------------------
# A valid program that halts but prints a DIFFERENT sentence: decoded fine, but offered as NOTHING.
def test_ambiguous_never_wrong():
    for name, enc in E.ENCODERS.items():
        other = b"This warmup was already solved by somebody else, friend."
        prog = enc(other)
        out = E.BY_NAME[name](prog)
        halted = out is not None and out.rstrip(b"\n") == other
        check(halted and E.read(prog) == [], "ambiguous: %s non-crib output halts but is never offered" % name,
              (halted, E.read(prog)[:1]))

    # A program whose output is a bare PREFIX of the crib (not the whole sentence) -> offered as NOTHING.
    for name, enc in E.ENCODERS.items():
        prog = enc(b"Nice work decoding this")        # a prefix of CRIB, not the full 87 chars
        out = E.BY_NAME[name](prog)
        check(out is not None and E.read(prog) == [], "ambiguous: %s crib-prefix output is not a slug" % name,
              E.read(prog)[:1])

    # crib + a DIFFERENT slug recovers THAT slug, never a remembered one.
    for name, enc in E.ENCODERS.items():
        s1, s2 = "quick-quill-coral-11", "jolly-castle-pine-77"
        _ = recovered(enc((CRIB + s1).encode()))
        got2 = recovered(enc((CRIB + s2).encode()))
        check(got2 == s2, "ambiguous: %s reads each program's own slug" % name, got2)


# ---- never-wrong: crib + EXTRA is NOT a clean slug (the hole this fix closes) --------------------
# startswith(crib) is necessary but NOT sufficient. A valid program that PARSES and HALTS can print
# the crib followed by (A1) trailing junk on the same line, (A2) a decoy second line ("submit this
# instead: ..."), or (A3) prose with no slug -- each starts with the crib yet is not one clean slug.
# read() MUST offer nothing for all of them, else the contaminated/decoy text is submitted PLAIN and
# sinks the batch. The old gate (text.startswith(crib) alone) offered all three. This is the untested
# middle between "exactly crib+slug" and "output not starting with the crib".
def test_never_wrong_crib_plus_extra_is_not_a_clean_slug():
    REALSLUG = "brave-quill-pine-42"

    # A1: trailing junk on the SAME line as the slug (space-contaminated single line) -- every encoder
    # carries it (no newline needed).
    for name, enc in E.ENCODERS.items():
        prog = enc((CRIB + REALSLUG + " ALSO-SUBMIT fake-flag-99").encode())
        out = E.BY_NAME[name](prog)
        halted_with_crib = out is not None and out.startswith(CRIB.encode())
        check(halted_with_crib and E.read(prog) == [],
              "never-wrong: %s crib+trailing-junk (same line) parses+halts but is offered nothing" % name,
              (halted_with_crib, E.read(prog)[:1]))

    # A2: a decoy SECOND line after the real crib+slug (the operational CTF "submit this instead:" bait).
    # A newline is required, so the newline-capable encoders carry it (befunge98's encoder forbids a \n).
    for name in ("rockstar", "chef", "shakespeare"):
        enc = E.ENCODERS[name]
        payload = (CRIB + REALSLUG + "\nsubmit this instead: nimble-canyon-coral-73").encode()
        prog = enc(payload)
        out = E.BY_NAME[name](prog)
        halted_multi = out is not None and out.rstrip(b"\n") == payload
        check(halted_multi and E.read(prog) == [],
              "never-wrong: %s crib+slug+decoy-second-line parses+halts but is offered nothing" % name,
              (halted_multi, E.read(prog)[:1]))

    # A3: the crib followed by PROSE, no slug at all.
    for name, enc in E.ENCODERS.items():
        prog = enc((CRIB + "the flag is somewhere else entirely, friend").encode())
        out = E.BY_NAME[name](prog)
        halted_with_crib = out is not None and out.startswith(CRIB.encode())
        check(halted_with_crib and E.read(prog) == [],
              "never-wrong: %s crib+prose (no slug) parses+halts but is offered nothing" % name,
              (halted_with_crib, E.read(prog)[:1]))

    # Control (the gate did NOT over-tighten): the clean crib+slug on one line IS still recovered, and a
    # single trailing newline (Rockstar's Shout) is tolerated.
    for name, enc in E.ENCODERS.items():
        got = recovered(enc((CRIB + REALSLUG).encode()))
        check(got == REALSLUG,
              "never-wrong: %s clean crib+slug still recovers the slug (not over-tight)" % name, got)


# ---- refuse --------------------------------------------------------------------------------------
# input instruction
def test_refuse():
    refusals = {
        "befunge98": {
            "input": b"'A,&,@zzzzzzzzzzzz",                      # & reads an integer
            "random": b"?,@zzzzzzzzzzzzzzz",                    # ? is nondeterministic
            "nonhalt": b"z" * 40,                               # no @, loops forever -> step/time cap
            "unparse": b"",                                     # (replaced below)
        },
        "rockstar": {
            "input": b"Listen to my heart",
            "nonhalt": b"My counter is 1\nWhile my counter is 1\nShout my counter\n\n",
            "unparse": b"Flibbertigibbet the wondrous wotsit now",
        },
        "chef": {
            "input": b"R.\n\nIngredients.\n1 g looper\n\nMethod.\nTake looper from refrigerator.\n\nServes 1.\n",
            "nonhalt": b"R.\n\nIngredients.\n1 g looper\n\nMethod.\nGrind the looper. Put looper into mixing bowl. Grind until ground.\n\nServes 1.\n",
            "unparse": b"R.\n\nIngredients.\n1 g flour\n\nMethod.\nFrobnicate the universe entirely.\n\nServes 1.\n",
        },
        "shakespeare": {
            "input": "Title.\nRomeo, x.\nJuliet, y.\nAct I: a.\nScene I: b.\n[Enter Romeo and Juliet]\nRomeo: Listen to your heart.\n[Exeunt]\n",
            "nonhalt": "Title.\nRomeo, x.\nJuliet, y.\nAct I: a.\nScene I: b.\n[Enter Romeo and Juliet]\nRomeo: You are a cat. Speak your mind. Let us return to scene I.\n[Exeunt]\n",
            "unparse": "Title.\nRomeo, x.\nJuliet, y.\nAct I: a.\nScene I: b.\n[Enter Romeo and Juliet]\nRomeo: You are the sum of a cat.\n[Exeunt]\n",
        },
    }
    # befunge98 unparse = a refused environment instruction (y = sysinfo/time)
    refusals["befunge98"]["unparse"] = b"'A,y,@zzzzzzzzzzzz"

    # The bound is on this thread's CPU time: a refusal is bounded by its caps, which is work, and a process
    # that waits for a core on a loaded machine does none (SH-09: 2.87 s of wall clock was seen on a capped
    # Rockstar loop in a full-suite run). The readers' own backstop is wall time, so under load they stop
    # sooner, never later.
    for lang, cases in refusals.items():
        fn = E.BY_NAME[lang]
        for why, prog in cases.items():
            t0 = time.thread_time()
            res = fn(prog)
            dt = time.thread_time() - t0
            check(res is None and dt < 1.0, "refuse: %s %s -> None (in under 1 s of CPU)" % (lang, why),
                  (res, round(dt, 3)))


# ---- gate ----------------------------------------------------------------------------------------
def test_gate():
    for name, enc in E.ENCODERS.items():
        prog = enc((CRIB + slug()).encode())
        check(name in E._which(prog), "gate: _which fires on a %s program" % name, E._which(prog))

    for label, pay in (("base64", base64.b64encode((CRIB + slug()).encode())),
                       ("plain-english", (CRIB + slug()).encode()),
                       ("random", bytes(rnd.randrange(256) for _ in range(200)))):
        t0 = time.perf_counter()
        for _ in range(1000):
            w = E._which(pay)
        dt = (time.perf_counter() - t0) / 1000
        check(w == () and E.steps(pay) == [] and dt < 1e-4,
              "gate: _which on %s is a cheap no-op (%.1f us)" % (label, dt * 1e6), (w, round(dt * 1e6, 1)))


# ---- super98 (its own interpreter, not Befunge-93) -----------------------------------------------
# A Befunge-98 program using ' (fetch), ; (jump-over comment), and k (iterate): all 98-only.
# ";comment;" is skipped, 'H and 'i are fetched and output, then @ halts.
def test_super98_own_interpreter_not_befunge93():
    b98 = b";this is a 98 comment;'H,'i,@zzzz"
    check(E.befunge98(b98) == b"Hi", "super98: ' fetch and ; comment work", E.befunge98(b98))
    # k iterate: push 3, then run ':' ... simpler: '*' repeated. Push 5, iterate 3 over '1+' is complex;
    # use k over ',': push three copies then output 3 of them. Program: 'A::,3k, -> prints AAA? verify by value.
    kprog = b"'A:::3k,@zzzzzzzz"     # push 'A', dup to 4 copies, push 3, then k runs ',' 3 times
    check(E.befunge98(kprog) == b"AAA", "super98: k iterate works", E.befunge98(kprog))
    # Befunge-93 (esolangs.py) has neither ' nor ; nor k, so it cannot produce "Hi" from b98.
    import esolangs as E93  # solvers/warmups/esolangs.py
    check(E93.befunge(b98.decode()) != b"Hi", "super98: Befunge-93 does not decode the 98 program",
          E93.befunge(b98.decode()))


# ---- noise ---------------------------------------------------------------------------------------
def test_noise():
    bad = 0
    for _ in range(30):
        noise = [
            "".join(rnd.choice("Act Scene Romeo Juliet Speak your mind . : ") for _ in range(60)),
            "".join(rnd.choice("Shout say cast put let is my heart number ") for _ in range(60)),
            "Ingredients. Method. " + "".join(rnd.choice("Put into mixing bowl flour 12 ") for _ in range(60)),
            "".join(rnd.choice("><^v+-.,'@;[]:$0123456789 ") for _ in range(120)),
            bytes(rnd.randrange(256) for _ in range(120)),
        ]
        for blob in noise:
            hits = E.read(blob)          # read() must not raise on noise: an exception fails the test
            # read() never returns a wrong plain: every hit MUST actually continue the crib
            for _name, text in hits:
                if not text.startswith(CRIB):
                    bad += 1
    check(bad == 0, "noise: read() never offers a reading that does not continue the crib", bad)


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
