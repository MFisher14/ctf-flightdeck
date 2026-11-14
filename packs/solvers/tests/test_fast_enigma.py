#!/usr/bin/env python3
"""Crib-first, multiprocessed Enigma break + the parallel-search helper it rides on.

  CTF_WORKDIR=/tmp/ctfws .venv/bin/python tests/test_fast_enigma.py      # -> 'ok', exit 0

All inputs are synthetic: we encipher known plaintext with the engine's own enigma(), then show
that enigma_crib_break() recovers the wheels, ring/start, plugboard and the whole plaintext from
a known-plaintext crib -- in seconds, not the ~40 minutes an IoC-every-candidate scan cost at the
rehearsal. Also a small unit check of solvers/common/psearch (parallel_map / parallel_search) and
that the fast internal decode matches the authoritative enigma().

Both pytest (test_* functions) and the standalone runner work; the standalone path prints 'ok'.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "solvers", "common"))

import classical as C          # noqa: E402
import psearch                 # noqa: E402

# A comfortable ceiling: the real break runs in ~1-3 s on a laptop; 40 min was the thing we killed.
TIME_BUDGET = 25.0

sys.path.insert(0, HERE)
import loadclock               # noqa: E402  (tests/loadclock.py)


def timed_break(*args, **kw):
    """(enigma_crib_break(...), its time on free cores). The break fans the 60 rotor orders out to
    psearch.cpu_count() worker processes, so its wall time is the time TIME_BUDGET was set for only on
    an unloaded machine; under the suite's load (SH-10: 25.9 s seen) it is mostly waiting for cores.
    This counts work instead: the parent's CPU plus the reaped workers' CPU spread over the workers
    (tests/loadclock.pool_seconds), which is the wall time on that many free cores. Same budget."""
    return loadclock.pool_seconds(C.enigma_crib_break, min(psearch.cpu_count(), 60), *args, **kw)


# ---------------------------------------------------------------------------- psearch

def _square(x):
    return x * x


def _hit_7(x):
    return x if x % 7 == 0 and x else 0


def test_psearch():
    assert psearch.cpu_count() >= 1
    # map, parallel and serial, agree with the plain map
    want = [i * i for i in range(50)]
    assert psearch.parallel_map(_square, range(50), workers=4) == want
    assert psearch.parallel_map(_square, range(50), workers=1) == want          # serial path
    assert psearch.parallel_map(_square, range(50), workers=4, ordered=False, chunksize=3) \
        and sorted(psearch.parallel_map(_square, range(50), workers=4, ordered=False)) == want
    assert psearch.parallel_map(_square, [], workers=4) == []
    # best by score
    cand, sc = psearch.parallel_search(range(200), _square, workers=4)
    assert (cand, sc) == (199, 199 * 199), (cand, sc)
    cand, sc = psearch.parallel_search(range(200), _square, workers=4, maximize=False)
    assert cand == 0 and sc == 0, (cand, sc)
    # first match short-circuits
    hit, val = psearch.parallel_search(range(1, 100), _hit_7, workers=4, first_match=True)
    assert hit == 7 and val == 7, (hit, val)
    miss = psearch.parallel_search([1, 2, 3, 4, 5, 6], _hit_7, workers=4, first_match=True)
    assert miss == (None, None), miss
    assert psearch.parallel_search([], _square) == (None, None)
    print("psearch ok (cpus=%d)" % psearch.cpu_count())


# ---------------------------------------------------------------------------- fast decode == engine

def test_decode_matches_engine():
    """The precomputed-array decode used in the sweep must agree with enigma() letter for letter."""
    rotors, refl, rings, start = ("IV", "I", "V"), "C", "BQD", "MLK"
    pt = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGNEARTHERIVERBANKATDAWN"
    ct = C.enigma(pt, rotors=rotors, reflector=refl, rings=rings, start=start)
    arrays = C._enigma_arrays(rotors, refl)
    ring = tuple(ord(c) - 65 for c in rings)
    st = tuple(ord(c) - 65 for c in start)
    pc = C._letter_codes(ct)
    dec = C._enigma_decode_codes(pc, arrays, ring, st, 0, len(pc))
    assert "".join(chr(c + 65) for c in dec) == pt, "fast decode disagrees with enigma()"
    print("fast decode matches enigma()")


# ---------------------------------------------------------------------------- the break

def _check(res, rotors, refl, start, plugpairs, plaintext, label):
    assert res is not None, "%s: breaker returned nothing" % label
    assert res["rotors"] == rotors, "%s: rotors %s != %s" % (label, res["rotors"], rotors)
    assert res["reflector"] == refl, "%s: reflector %s" % (label, res["reflector"])
    assert res["start"] == start, "%s: start %s != %s" % (label, res["start"], start)
    got_plug = set(frozenset(p) for p in res["plugboard"].split())
    want_plug = set(frozenset(p) for p in plugpairs.split())
    assert got_plug == want_plug, "%s: plugboard %r != %r" % (label, res["plugboard"], plugpairs)
    assert res["plaintext"] == plaintext, "%s: plaintext mismatch:\n  %s\n  %s" % (
        label, res["plaintext"], plaintext)


def test_fast_enigma_no_plugboard():
    """The easy, common case: a flag at the head of the message, no plugboard, the bare CSCTF{
    crib. Recovered exactly, and fast."""
    rotors, refl, start = ("II", "V", "III"), "B", "KDB"
    pt = "CSCTFTHEENIGMAKEYROTATESATDAWNHOLDTHEGRIDDEFENDTOTALWARFARE"
    ct = C.enigma(pt, rotors=rotors, reflector=refl, rings="AAA", start=start)
    res, dt = timed_break(ct, crib="CSCTF")
    # The empty plugboard is the point: a short crib must not tempt the hill climb into inventing
    # a spurious pair that keeps CSCTF intact while corrupting the rest of the message.
    _check(res, rotors, refl, start, "", pt, "no-plugboard")
    assert dt < TIME_BUDGET, "no-plugboard break took %.1fs" % dt
    print("no-plugboard break: %s start=%s in %.2fs" % ("-".join(res["rotors"]), res["start"], dt))


def test_fast_enigma_with_plugboard():
    """The hard case: a 3-pair plugboard, recovered from a known-plaintext crib and an n-gram
    plugboard hill-climb. The plaintext carries a CSCTF{...} flag (its braces/digits ride through
    the machine unchanged) and must come back verbatim. Timed against the budget."""
    rotors, refl, start, plug = ("IV", "I", "V"), "B", "QXM", "AF TR QZ"
    # The Enigma engine upper-cases all letter output (its documented behavior), so a genuine
    # Enigma flag is all caps; the braces/digits/underscore are non-letters and ride through.
    pt = ("WEDEFENDTHEGRIDATALLCOSTSTHEENIGMAROTORSTURNEACHDAWNANDTHEDUTY"
          "OPERATORMUSTTRANSMITCSCTF{3N1GM4_CR4CK3D}BEFORETHEBATTLEBEGINS")
    ct = C.enigma(pt, rotors=rotors, reflector=refl, rings="AAA", start=start, plugboard=plug)
    assert "{" in ct and "}" in ct                         # non-letters pass through unchanged
    crib = "WEDEFENDTHEGRIDATALL"                          # a known-plaintext run at the head
    res, dt = timed_break(ct, crib=crib)
    _check(res, rotors, refl, start, plug, pt, "plugboard")
    assert "CSCTF{3N1GM4_CR4CK3D}" in res["plaintext"], "flag not in recovered plaintext"
    assert dt < TIME_BUDGET, "plugboard break took %.1fs (budget %.0fs)" % (dt, TIME_BUDGET)
    print("plugboard break: %s start=%s plug=%s in %.2fs"
          % ("-".join(res["rotors"]), res["start"], res["plugboard"], dt))


def test_fast_enigma_offset_search():
    """The crib need not sit at position zero: a small offset window is searched."""
    rotors, refl, start = ("I", "II", "III"), "B", "AAA"
    pt = "PREAMBLEXXCSCTFSIGNALINTERCEPTEDONTHEEASTERNFRONTSENDHELPNOW"
    ct = C.enigma(pt, rotors=rotors, reflector=refl, rings="AAA", start=start)
    res = C.enigma_crib_break(ct, crib="CSCTF", offsets=range(0, 12))
    assert res is not None and res["plaintext"] == pt, "offset-searched break failed"
    assert "CSCTF" in res["plaintext"]
    print("offset-search break: start=%s ok" % res["start"])


def main():
    test_psearch()
    test_decode_matches_engine()
    test_fast_enigma_no_plugboard()
    test_fast_enigma_with_plugboard()
    test_fast_enigma_offset_search()
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
