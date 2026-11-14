#!/usr/bin/env python3
"""Offline test of the Day 16 Warmups look-ahead (docs/retro/day-16/predictions-simple.md).

The one shipped change is a new esolang reader, Deadfish, in solvers/warmups/esolangs.py, wired as a
strict step in solvers/warmups/formats_more.py (BY_NAME 'deadfish', gated in _which on the i/d/s/o
alphabet). A Deadfish program that prints the crib sentence and a slug is read PLAIN, exactly as the
shipped COW / Whitespace / Befunge readers are: the crib is the proof, the whole 87-character sentence
is reproduced, and there is no letter cipher, so no digit is left unsure. Everything else staged for
Day 16 was already covered by the armed tree (the decoder space is saturated); this test pins the new
reader and, as the regression guard the look-ahead needs, that the Deadfish gate does NOT fire on any
older encoding's blob (its only risk is a wrong plain answer from a mis-fire).

No Game Master request is made. Run: .venv/bin/python -m pytest tests/test_warmups_day16.py
(or `python tests/test_warmups_day16.py`)
"""
import base64
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "solvers" / "warmups", ROOT / "solvers" / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import labels            # noqa: E402
import esolangs as E     # noqa: E402
import formats_more as M  # noqa: E402
import crib_decode as C  # noqa: E402

CRIB = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
SLUG = "sunny-castle-opal-96"
TEXT = CRIB + SLUG


def check(ok, name, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (("  -- " + detail) if detail and not ok else ""))
    assert ok, name + (("  -- " + detail) if detail else "")


# ---- 1. the interpreter itself -------------------------------------------------------------------
def test_1_the_interpreter_itself():
    prog = E.deadfish_encode(b"Hi!")
    check(E.deadfish(prog) == b"Hi!", "deadfish encode/decode roundtrip", repr(prog))
    check(E.deadfish(E.deadfish_encode(TEXT.encode())) == TEXT.encode(), "deadfish roundtrips the whole crib")
    check(E.deadfish("iiiiiiiio") == b"\x08", "deadfish counts then outputs a byte")
    check(E.deadfish("iiso") == b"\x04", "deadfish squares (2*2 = 4)")
    # the language's reset rule: 255 +1 -> 256 -> 0, so one 'i' past 255 then output is a NUL
    check(E.deadfish("i" * 256 + "o") == b"\x00", "deadfish resets 256 to 0")
    check(E.deadfish("") is None, "deadfish refuses the empty text")
    check(E.deadfish("iiii") is None, "deadfish refuses a program with no output")
    check(E.deadfish("hello world") is None, "deadfish refuses text outside its alphabet")
    # step / output caps: a program that would print past the output cap gives None, never a prefix
    big = ("i" * 65 + "o") * (E.OUTPUT + 10)
    check(E.deadfish(big) is None, "deadfish refuses a program that prints past the output cap")


# ---- 2. read plain through the solver ------------------------------------------------------------
def test_2_read_plain_through_the_solver():
    blob = E.deadfish_encode(TEXT.encode())
    # A generous wall-clock budget, not the 0.35 s default: this is a correctness check (the deadfish
    # reader yields a PLAIN slug), not a timing check. The deadfish read needs well under a millisecond
    # of CPU, but solve_blob's budget is wall-clock, and under the 24-at-once accept.sh item-3p batch
    # CPU contention occasionally stretched the search past 0.35 s before the deadfish step finished, so
    # the blob was budget-cut to None (note "the time budget ran out") and this assertion flaked. The
    # amount of time the search spends before reaching deadfish also varies with PYTHONHASHSEED (which -I
    # does not pin), which is why it was intermittent rather than a hard fail. A large budget makes the
    # correctness check robust to both without touching any solver logic (cf. test_envelope_peel.py).
    r = C.solve_blob(blob.encode(), budget=5.0)
    check(r is not None and r[0] == SLUG, "a deadfish crib blob is read PLAIN", repr(r))
    # plain, not an unsure labels.pick (the whole sentence is reproduced, no cipher, no open digits)
    check(r is not None and labels.parse(r[0]) is None, "the deadfish answer is plain, not unsure")


# ---- 3. the reader is reachable as a named strict step ------------------------------------------
def test_3_the_reader_is_reachable_as_a_named_strict_step():
    blob = E.deadfish_encode(TEXT.encode())
    check("deadfish" in M.NAMES, "formats_more exposes 'deadfish'")
    names = M._which(blob.encode())
    check("deadfish" in names, "_which gates deadfish onto an i/d/s/o blob", repr(names))


# ---- 4. regression guard: the gate does NOT fire on older encodings -----------------------------
def test_4_regression_guard_the_gate_does_not_fire_on_older_encodings():
    others = {
        "base64": base64.b64encode(TEXT.encode()).decode(),
        "base64url": base64.urlsafe_b64encode(TEXT.encode()).decode(),
        "hex": TEXT.encode().hex(),
        "binary": " ".join(format(b, "08b") for b in TEXT.encode()),
        "decimal": " ".join(str(b) for b in TEXT.encode()),
        "morse": ".... . .-.. .-.. ---",
        "cow": E.cow_encode(b"Hi there friends"),
        "rot13": TEXT.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")),
        # a text that happens to be only i/d/s/o letters but is NOT a program: still only 'o' gate matters,
        # and without an 'o' the gate must refuse
        "idsnoout": "iiddss iiddss",
    }
    for name, enc in others.items():
        b = enc.encode()
        fired = "deadfish" in M._which(b)
        check(not fired, "deadfish does NOT fire on %s" % name, "fired on %s" % name)

    # and a real deadfish blob among them must still be readable (sanity that the guard is not too tight)
    check("deadfish" in M._which(E.deadfish_encode(b"hello").encode()),
          "deadfish still fires on a genuine deadfish blob")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
