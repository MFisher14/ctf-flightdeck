#!/usr/bin/env python3
"""Offline test of the Day 28 look-ahead Warmups readers: solvers/warmups/esolang4.py's `boolfuck` (bit-level
brainfuck) and `bfdialect` (a brainfuck TOKEN-dialect whose eight commands are whitespace-separated word tokens;
the token->command map is LEARNED from the crib and the program is run on the sandboxed brainfuck VM).

  .venv/bin/python -m pytest tests/test_day28_warmups.py   (or `python tests/test_day28_warmups.py`)

No network and no token. Both readers are strict (information-complete transforms whose output is confirmed to
continue the exact crib), so each is answered PLAIN with the full slug (digits and all) and needs no day-rule
ledger. The never-wrong property is the point of the test: a decoy that merely shares a reader's shape but does
not reproduce the crib yields NOTHING, never a wrong slug.

What is checked:

  boolfuck   the sentence + a slug (incl. the digits 5,6) encoded as boolfuck: PLAIN, chain `boolfuck`; a faithful
             boolfuck decode of a DIFFERENT text, a corrupted program and random `+;` garbage: None; a faithful
             decode of a mangled slug returns the MANGLED slug (it decodes faithfully, never the test slug).
  bfdialect  the sentence + slug as a Pogaack-style word dialect (3- and 8-token programs): PLAIN, chain
             `bfdialect`; a dialect of a different text, random word garbage and an inconsistent token stream: None.
  vm         run_boolfuck / run_bf round-trip their encoders; `,` (input), unbalanced brackets and a pointer off
             the tape are refusals (None).
  regress    no saved Warmups payload (whole blob or numbered record) under $CTF_REAL_CHALLENGES is read by
             either esolang4 reader (not run when $CTF_REAL_CHALLENGES is unset or holds no saved payload).
"""
import atexit
import glob
import os
import random
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from ctf import paths

sys.dont_write_bytecode = True
VERBOSE = "-v" in sys.argv[1:]
REPO = Path(__file__).resolve().parent.parent

ROOT = Path(tempfile.mkdtemp(prefix="warmups-day28-"))
# CTF_WORKDIR is set at import and may outlive this module in a pytest worker: remove the folder at exit only.
atexit.register(shutil.rmtree, ROOT, True)
(ROOT / "_ledger").mkdir(parents=True)
os.environ["CTF_WORKDIR"] = str(ROOT)
os.environ["CTF_TESTING"] = "1"
os.environ.pop("CTF_TOKEN", None)
for _p in (REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    sys.path.insert(0, str(_p))

import crib_decode as C   # noqa: E402
import esolang4 as E      # noqa: E402

CRIB = C.CRIB
SLUGS = ["brisk-clock-onyx-56", "amber-forest-lantern-47", "quick-zephyr-banner-09"]
OTHER = "Completely unrelated content, nothing like the warmup banner at all 12345"


def check(ok, name, detail=None):
    ok = bool(ok)
    if VERBOSE or not ok:
        print(("ok   " if ok else "FAIL ") + name + ("" if ok or detail is None else "  " + repr(detail)[:300]))
    assert ok, name + ("" if detail is None else "  " + repr(detail)[:300])


# The "solves plain" reads are correctness checks, not timing checks: solve_blob's budget is wall-clock,
# and under a loaded full-suite run the default budget occasionally ran out before the reader's step and
# the read came back None (R-01; the same reasoning as tests/test_warmups_day16.py).
SOLVE_BUDGET = 5.0


def answer(blob, budget=None):
    if isinstance(blob, str):
        blob = blob.encode()
    got = C.solve_blob(blob) if budget is None else C.solve_blob(blob, budget=budget)
    if got is None:
        return None
    return got[0] if isinstance(got, tuple) else got


# A Pogaack-style dialect: eight word tokens, one per brainfuck command (whitespace-separated).
POGAACK = {">": "pogaack!", "<": "poock", "+": "pogaack.", "-": "pogaack?", ".": "pogaack",
           "[": "pogack?", "]": "pogack!", ",": "poogg"}
# A second, 8-token-exercising dialect (Hodor-style), so the map search faces all eight commands.
HODOR = {">": "Hodor.", "<": "Hodor?", "+": "Hodor!", "-": "Hodor,", ".": "HODOR",
         "[": "hodor.", "]": "hodor?", ",": "hodor!"}


# ---- boolfuck: solves plain, incl. digits -------------------------------------------------------
def test_boolfuck_solves_plain_incl_digits():
    for slug in SLUGS:
        plain = CRIB + slug
        a = answer(E.boolfuck_encode(plain.encode()), SOLVE_BUDGET)
        check(a == slug, "boolfuck plain %s" % slug, a)

    # chain is `boolfuck`
    _got = C.solve_blob(E.boolfuck_encode((CRIB + SLUGS[0]).encode()).encode(), budget=SOLVE_BUDGET)
    check(_got is not None and any("boolfuck" in ch for ch in _got[1]), "boolfuck chain name", _got and _got[1])


# ---- boolfuck: never wrong ----------------------------------------------------------------------
def test_boolfuck_never_wrong():
    check(answer(E.boolfuck_encode(OTHER.encode())) is None, "boolfuck other-text is None")
    _bf = E.boolfuck_encode((CRIB + SLUGS[0]).encode())
    check(answer(_bf[:200] + _bf[260:]) is None, "boolfuck corrupted sentence is None")
    check(answer("".join(random.Random(1).choice("+;") for _ in range(2000))) is None, "boolfuck random +; is None")
    _mangled = CRIB + "zzzzz-zzzzz-zzzzz-00"
    check(answer(E.boolfuck_encode(_mangled.encode())) == "zzzzz-zzzzz-zzzzz-00", "boolfuck faithful mangled slug")


# ---- bfdialect: solves plain, incl. digits ------------------------------------------------------
def test_bfdialect_solves_plain_incl_digits():
    for toks, label in ((POGAACK, "pogaack"), (HODOR, "hodor")):
        for slug in SLUGS[:2]:
            plain = CRIB + slug
            a = answer(E.dialect_encode(plain.encode(), toks), SOLVE_BUDGET)
            check(a == slug, "bfdialect %s plain %s" % (label, slug), a)

    _got = C.solve_blob(E.dialect_encode((CRIB + SLUGS[0]).encode(), POGAACK), budget=SOLVE_BUDGET)
    check(_got is not None and any("bfdialect" in ch for ch in _got[1]), "bfdialect chain name", _got and _got[1])


# ---- bfdialect: never wrong ---------------------------------------------------------------------
def test_bfdialect_never_wrong():
    check(answer(E.dialect_encode(OTHER.encode(), POGAACK)) is None, "bfdialect other-text is None")
    _words = ["Hodor", "hodor", "HODOR", "Hodor.", "hodor?"]
    check(answer(" ".join(random.Random(2).choice(_words) for _ in range(400))) is None, "bfdialect word garbage is None")
    # an inconsistent token stream (no single bijection reproduces the crib)
    _prog = E.bf_encode((CRIB + SLUGS[0]).encode())
    _r = random.Random(3)
    _toks = [(POGAACK["+"] if (POGAACK[op] == POGAACK["."] and _r.random() < 0.05) else POGAACK[op]) for op in _prog]
    check(answer(" ".join(_toks).encode()) is None, "bfdialect inconsistent stream is None")


# ---- the sandboxed VMs round-trip and refuse ----------------------------------------------------
def test_the_sandboxed_vms_round_trip_and_refuse():
    _data = b"Hello, warmup! 56"
    check(E.run_boolfuck(E.boolfuck_encode(_data)) == _data, "run_boolfuck round-trip")
    check(E.run_bf(E.bf_encode(_data)) == _data, "run_bf round-trip")
    check(E.run_bf("+.,.") is None, "run_bf refuses input ,")
    check(E.run_bf("+.[") is None, "run_bf refuses unbalanced [")
    check(E.run_boolfuck("<;") is None, "run_boolfuck refuses pointer underflow")
    check(E.run_bf("+++") is None, "run_bf refuses no-output program")
    check(E.run_boolfuck("+++") is None, "run_boolfuck refuses no-output program")


# ---- no saved Warmups payload is read by the new readers ----------------------------------------
def test_no_saved_warmups_payload_is_read_by_esolang4():
    # The saved Huntress attempts (read only), only through ctf.paths: None when $CTF_REAL_CHALLENGES is
    # unset (not run); set to a missing folder, FileNotFoundError fails this test.
    REAL = paths.saved_challenges_root()
    if REAL is None:
        pytest.skip("not run: CTF_REAL_CHALLENGES is not set (the saved past-event attempts)")
    _scanned = 0
    _read = []
    for path in glob.glob(str(REAL / "day-*" / "warmups-*" / "**" / "*.txt"), recursive=True) + \
            glob.glob(str(REAL / "day-*" / "warmups-*" / "**" / "artifact" / "*"), recursive=True):
        try:
            raw = Path(path).read_bytes()
        except OSError:
            continue
        if not (16 <= len(raw) <= E.MAX_PROG):
            continue
        _scanned += 1
        if E.steps(raw):
            _read.append(path)
    if not _scanned:
        pytest.skip(f"no saved Warmups payloads found under {REAL}")
    check(not _read, "no saved Warmups payload read by esolang4 (%d scanned)" % _scanned, _read[:5])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
