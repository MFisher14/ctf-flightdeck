#!/usr/bin/env python3
"""Sweep of every esolang a Warmups module claims crib_decode reads (backlog rows 546, 547 and 548).

  .venv/bin/python -m pytest tests/test_warmups_esolang_sweep.py   (or `python tests/test_warmups_esolang_sweep.py`)

No network and no token. The Day 27 review found four esolang forms that a module docstring or a shipped reader
says are covered, but that crib_decode answered None: Short Ook, lowercase ook, Rockstar and Befunge-98. Nobody saw
it because each battery (test_wave4_esolang, test_wave15_esolang2, test_wave122_esolang3, test_esolang_more) tests
only its own module, never crib_decode's solve_set at full payload size. This test closes that gap.

  sweep    (row 548) the Day 27 sentence plus slug, encoded with every ENCODERS entry of esolang.py, esolang2.py,
           esolang3.py, esolang4.py and esolang_more.py, every *_encode of esolangs.py (COW, Whitespace,
           Befunge-93, Deadfish), and Ook! in four forms. Each is run through crib_decode.solve_set as a delivery
           ({artifact: bytes}) and must give the slug. A new ENCODERS entry is swept automatically, so a reader
           that is shipped but not wired fails here.
  ook      (row 546) Short Ook with and without spaces, and lowercase and uppercase Ook, give the slug. A random
           string of `.?!` of the same length, an odd-length Short Ook, and Short Ook of a different text give None.
  more     (row 547) Rockstar and Befunge-98 give the slug and carry their own step name. Programs of either
           language that print a different text give None. Prose that only looks like Rockstar, base85 with an
           `@` in it, and junk over Befunge characters give None quickly.
  saved    (row 547) no saved Warmups payload (a whole blob or a numbered record) under $CTF_REAL_CHALLENGES
           is taken by the Rockstar or Befunge-98 signature, or read by either reader. Not run when $CTF_REAL_CHALLENGES is
           unset or holds no saved payload.
"""
import atexit
import glob
import os
import random
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

from ctf import paths

sys.dont_write_bytecode = True
VERBOSE = "-v" in sys.argv[1:]
REPO = Path(__file__).resolve().parent.parent

ROOT = Path(tempfile.mkdtemp(prefix="warmups-esosweep-"))
# CTF_WORKDIR is set at import and may outlive this module in a pytest worker: remove the folder at exit only.
atexit.register(shutil.rmtree, ROOT, True)
(ROOT / "_ledger").mkdir(parents=True)
os.environ["CTF_WORKDIR"] = str(ROOT)
os.environ["CTF_TESTING"] = "1"
os.environ.pop("CTF_TOKEN", None)
for _p in (REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    sys.path.insert(0, str(_p))

import crib_decode as C   # noqa: E402
import esolang            # noqa: E402
import esolang2           # noqa: E402
import esolang3           # noqa: E402
import esolang4           # noqa: E402
import esolang_more       # noqa: E402
import esolangs           # noqa: E402

SLUG = "hearty-castle-fern-71"     # Day 27's
PLAIN = (C.CRIB + SLUG).encode()


def check(ok, name, detail=None):
    ok = bool(ok)
    if VERBOSE or not ok:
        print(("ok   " if ok else "FAIL ") + name + ("" if ok or detail is None else "  " + repr(detail)[:300]))
    assert ok, name + ("" if detail is None else "  " + repr(detail)[:300])


QUESTION = {"qid": "message", "answer_id": "message", "member": None, "question": "message",
            "answer_format": "exact_text"}


def solve(blob):
    """crib_decode.solve_set on one delivery, as tools/run.py calls it: (answer, seconds)."""
    if isinstance(blob, str):
        blob = blob.encode()
    t0 = time.perf_counter()
    out = C.solve_set([dict(QUESTION)], {"blob.txt": blob},
                      {"set": 1, "delivery_name": "blob.txt", "delivery": blob, "attempt": {}})
    return (out or {}).get("message"), time.perf_counter() - t0


# The sweep and the large-Pikalang reads are correctness checks (each encoder's program is read to the
# slug), not timing checks. solve_set gives an attempt with no clock crib_decode.BUDGET (0.35 s) of wall
# clock per blob, and under a loaded full-suite run that ran out before the reader for the larger forms
# (ook_lower, large Pikalang) and the read came back None (R-01). Those two tests raise the per-blob
# budget to CORRECT_BUDGET through crib_decode's own constant, the precedent of test_wave4_esolang and
# test_warmups_day16. The None checks (Ook junk, other texts, prose) keep the default budget.
CORRECT_BUDGET = 5.0


@pytest.fixture
def correctness_budget(monkeypatch):
    monkeypatch.setattr(C, "BUDGET", CORRECT_BUDGET)
    assert C.budget_for({"set": 1, "attempt": {}}) == CORRECT_BUDGET      # solve_set reads it
    return CORRECT_BUDGET


def chain(blob, budget=None):
    """solve_blob's chains of one blob. solve_blob's own default budget is bound when it is defined, so a
    raised C.BUDGET reaches it only through `budget`."""
    got = C.solve_blob(blob if isinstance(blob, bytes) else blob.encode(), **({} if budget is None else {"budget": budget}))
    return got[1] if isinstance(got, tuple) and len(got) > 1 else None


OOK = {">": ("Ook.", "Ook?"), "<": ("Ook?", "Ook."), "+": ("Ook.", "Ook."), "-": ("Ook!", "Ook!"),
       ".": ("Ook!", "Ook."), ",": ("Ook.", "Ook!"), "[": ("Ook!", "Ook?"), "]": ("Ook?", "Ook!")}


def ook_forms(data: bytes) -> dict:
    pairs = [OOK[c] for c in esolang.bf_encode(data)]
    std = " ".join(a + " " + b for a, b in pairs)
    return {"ook": std,
            "ook_lower": std.lower(),
            "ook_upper": std.upper(),
            "short_ook": "".join(a[3] + b[3] for a, b in pairs),
            "short_ook_spaced": " ".join(a[3] + " " + b[3] for a, b in pairs)}


# ---- sweep (row 548) -----------------------------------------------------------------------------
FORMS = dict(ook_forms(PLAIN))
for _mod in (esolang, esolang2, esolang3, esolang4, esolang_more):
    for _name, _enc in _mod.ENCODERS.items():
        FORMS["%s.%s" % (_mod.__name__, _name)] = _enc(PLAIN)
for _name in sorted(n for n in dir(esolangs) if n.endswith("_encode") and callable(getattr(esolangs, n))):
    FORMS["esolangs.%s" % _name[:-len("_encode")]] = getattr(esolangs, _name)(PLAIN)


def test_sweep_every_encoder_reads_the_slug(correctness_budget):
    check(len(FORMS) >= 22, "sweep has every encoder (%d forms)" % len(FORMS), sorted(FORMS))
    for _name, _blob in FORMS.items():
        _got, _s = solve(_blob)
        check(_got == SLUG, "sweep %s (%d B, %.2f s)" % (_name, len(_blob), _s), _got)


def test_pikalang_large_blob_keeps_its_named_vm_and_the_strict_graph(correctness_budget):
    # Pikalang's eight official tokens also look like an unknown whitespace-token Brainfuck dialect.  Under acceptance
    # load that later generic reader used to consume the 0.21 s crib share and turn the proved named-language answer
    # into None.  Instrument the real solve_set call: Pikalang's VM and the ordinary strict graph must both run, while
    # only the overlapping generic learned-dialect reader is excluded.  Recording the strict graph's non-Pikalang
    # outputs also guards against an optimization that hides other valid interpretations or their ambiguity evidence.
    _fast_slug = "hearty-castle-fern-72"
    _fast_blob = esolang.ENCODERS["pikalang"]((C.CRIB + _fast_slug).encode())
    check(len(_fast_blob) > C.BIG, "Pikalang scheduler regression exercises the large-blob path")
    check("bfdialect" not in C.ESL4._which(_fast_blob)
          and "bfdialect" not in C.ESL4._which(FORMS["esolang.blub"]),
          "named Pikalang and Blub vocabularies are not generic learned dialects")
    C._READ_MEMO.pop(_fast_blob, None)
    _vm_payloads, _strict_payloads, _strict_hits, _generic_calls = [], [], [], []
    _real_esl_steps, _real_strict_steps = C.ESL.steps, C._strict_steps
    _real_bfdialect = C.ESL4.BY_NAME["bfdialect"]

    def _watched_esl_steps(payload):
        _vm_payloads.append(bytes(payload))
        return _real_esl_steps(payload)

    def _watched_strict_steps(payload):
        raw = bytes(payload)
        _strict_payloads.append(raw)
        for name, value in _real_strict_steps(payload):
            if raw == _fast_blob and value:
                _strict_hits.append(name)
            yield name, value

    def _watched_bfdialect(payload):
        _generic_calls.append(bytes(payload))
        return _real_bfdialect(payload)

    try:
        C.ESL.steps = _watched_esl_steps
        C._strict_steps = _watched_strict_steps
        C.ESL4.BY_NAME["bfdialect"] = _watched_bfdialect
        _fast_got, _fast_s = solve(_fast_blob)
    finally:
        C.ESL.steps = _real_esl_steps
        C._strict_steps = _real_strict_steps
        C.ESL4.BY_NAME["bfdialect"] = _real_bfdialect
    check(_fast_got == _fast_slug and _fast_blob in _vm_payloads,
          "large Pikalang solves through its named VM (%.3f s)" % _fast_s, _fast_got)
    check(_fast_blob in _strict_payloads, "large Pikalang retains the ordinary strict graph")
    check(_fast_blob not in _generic_calls,
          "known Pikalang tokens bypass only their generic learned-dialect reading", _generic_calls)
    check(any(name != "pikalang" for name in _strict_hits),
          "overlapping strict readings remain reachable", _strict_hits)


# ---- Ook forms (row 546) -------------------------------------------------------------------------
# The None checks below run on the default per-blob budget. The reads that must give a slug (a different
# slug, the step name) run on CORRECT_BUDGET, as the sweep does: on the default 0.35 s wall clock a
# loaded full-suite run cut the 10 KB Rockstar program's ~40 ms read and it came back None (SH-08).
def test_ook_forms_row_546_then_rockstar_and_befunge98_row_547(monkeypatch):
    def correct(fn, *args):
        with monkeypatch.context() as mp:
            mp.setattr(C, "BUDGET", CORRECT_BUDGET)
            return fn(*args)

    _short = FORMS["short_ook"]
    _rnd = random.Random(546)
    _junk = "".join(_rnd.choice(".?!") for _ in range(len(_short)))
    check(solve(_junk)[0] is None, "random .?! string of Short Ook's length is None")
    _junk_sp = " ".join(_rnd.choice(".?!") for _ in range(len(_short)))
    check(solve(_junk_sp)[0] is None, "random spaced .?! string is None")
    check(solve(_short[:-1])[0] is None, "Short Ook with an odd count of marks is None")
    _other = ook_forms(b"Completely unrelated text, not the warmup sentence at all, 12345")
    for _k in ("short_ook", "ook_lower"):
        check(solve(_other[_k])[0] is None, "%s of a different text is None" % _k)
    check(solve("book. book? " * 200)[0] is None, "words ending in ook. are no Ook tokens")
    _mangled = ook_forms((C.CRIB + "zzzzz-zzzzz-zzzzz-00").encode())["short_ook"]
    check(correct(solve, _mangled)[0] == "zzzzz-zzzzz-zzzzz-00", "Short Ook decodes faithfully (a different slug)")

    # ---- Rockstar and Befunge-98 (row 547) -------------------------------------------------------------
    for _name in ("rockstar", "befunge98"):
        _blob = esolang_more.ENCODERS[_name](PLAIN)
        _c = chain(_blob, CORRECT_BUDGET)
        check(_c is not None and any(_name in list(x) for x in _c), "%s chain carries its step name" % _name, _c)
        _ot = esolang_more.ENCODERS[_name](b"Completely unrelated text, not the warmup sentence, 98765")
        check(solve(_ot)[0] is None, "%s of a different text is None" % _name)
        _mg = esolang_more.ENCODERS[_name]((C.CRIB + "zzzzz-zzzzz-zzzzz-00").encode())
        check(correct(solve, _mg)[0] == "zzzzz-zzzzz-zzzzz-00", "%s decodes faithfully (a different slug)" % _name)

    _c93 = chain(esolangs.befunge_encode(PLAIN).encode(), CORRECT_BUDGET)
    check(_c93 is not None and not any("befunge98" in list(x) for x in _c93),
          "a Befunge-93 program keeps its own reading, not befunge98", _c93)

    _prose = ("Say what you will about the storm\nLet it be known that the river is wide\n"
              "Put your hand on my heart and shout\nCast away the night\n") * 20
    check(not C._eslm_sig("befunge98", _prose.encode()), "prose is not Befunge-98")
    _t0 = time.perf_counter()
    _got = solve(_prose)[0]
    check(_got is None, "Rockstar-looking prose is None (%.2f s)" % (time.perf_counter() - _t0), _got)
    _b85 = bytes(_rnd.choice(b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu")
                 for _ in range(800))
    check(not C._eslm_sig("befunge98", _b85), "base85-like text holding @ is refused by the Befunge-98 signature")
    _bj = "".join(_rnd.choice("><^v_|:\\$.,#0123456789+-*/") for _ in range(400)) + "@"
    # CPU time: the wall time of this ~0.55 s read passed 1 s on a loaded machine (SH-08)
    _t0 = time.thread_time()
    check(solve(_bj)[0] is None, "junk over Befunge characters is None (%.2f s CPU)" % (time.thread_time() - _t0))
    check(time.thread_time() - _t0 < 1.0, "junk over Befunge characters costs under 1 s of CPU (ESLM_TIME per settle)")


# ---- no saved Warmups payload is taken by the two new readers (row 547) -----------------------------
def test_no_saved_warmups_payload_is_taken_by_the_two_new_readers():
    # The saved Huntress attempts (read only), only through ctf.paths: None when $CTF_REAL_CHALLENGES is
    # unset (not run); set to a missing folder, FileNotFoundError fails this test.
    REAL = paths.saved_challenges_root()
    if REAL is None:
        pytest.skip("not run: CTF_REAL_CHALLENGES is not set (the saved past-event attempts)")
    _scanned = 0
    _sig = []
    _read = []
    _paths = set(glob.glob(str(REAL / "day-*" / "warmups-*" / "**" / "artifact" / "*"), recursive=True))
    _paths |= set(glob.glob(str(REAL / "day-*" / "warmups-*" / "**" / "*.txt"), recursive=True))
    for _path in sorted(_paths):
        try:
            _raw = Path(_path).read_bytes()
        except OSError:
            continue
        _parts = [_raw] + [p for p in re.split(rb"\r?\n", _raw) if len(p) >= 16]
        for _p in _parts:
            _scanned += 1
            for _name in sorted(C.ESLM_NAMES):
                if C._eslm_sig(_name, _p):
                    _sig.append((_path, _name))
                    if C._eslm_run(_name, _p):
                        _read.append((_path, _name))
    if not _scanned:
        pytest.skip(f"no saved Warmups payloads found under {REAL}")
    check(not _read, "no saved Warmups payload read by rockstar/befunge98 (%d scanned)" % _scanned, _read[:5])
    check(not _sig, "no saved Warmups payload passes their signatures", _sig[:5])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
