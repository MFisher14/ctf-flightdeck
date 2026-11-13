#!/usr/bin/env python3
"""Permanent break-it battery for the Warmups base-N breadth module
(solvers/warmups/base_extra.py, breadth build 2026-10-23).

  .venv/bin/python -m pytest tests/test_day24_warmups_ciphers.py   (or `python tests/test_day24_warmups_ciphers.py`)

No network and no token. Builds an empty challenges root under a scratch folder (for the base
reads), registers base_extra's readers into crib_decode with add_strict (the same hook
crib_decode.add_strict is built for, and the way the day_patch template adds a reader), and
drives the real crib_decode.solve_blob so the crib gate and the labels kind-classification run
exactly as on a release morning. Mirrors tests/test_day23_warmups.py.

base_extra adds the DETERMINISTIC encodings confirmed genuinely missing from crib_decode /
layered_decode / formats_more (the rest of the target list -- base32hex, base45, base58
bitcoin/flickr/ripple, base62 in four alphabets, base91/92, base64url, uuencode, xxencode,
yEnc, Crockford base32, z-base-32, ... -- were all found shipped and are not duplicated):

  b58check   Base58Check (bitcoin alphabet, trailing double-SHA256 checksum verified)
  gray       reflected-binary (Gray code) byte bijection

What is checked:

  reads     each added codec, round-tripped from a known slug, is answered PLAIN with the
            right slug (3 fresh slugs each), and the chain names that codec.
  wrong     across every added codec and three slugs, no wrong plain slug anywhere (WRONG 0).
  decoy-A/B a ciphertext valid in more than one alphabet (b62alt is all-alnum, so the shipped
            base62/base36/base58 can read it too; the b58 variants share one 58-char set) is
            never answered with a wrong plain slug: the wrong codec decodes to different bytes
            that do not reproduce the sentence, so it is plain-and-correct or none/unsure.
  noise     a codec-shaped payload that is NOT an encoding of the sentence (random text in the
            alphabet, random binary) is a safe None/unsure, never a wrong plain slug.
  gray      Gray code is a byte bijection with no signature: it round-trips, preserves digits
            (plain, never digit-unsure), decodes the plain sentence to non-crib garbage (so it
            never steals a read), and refuses a non-printable decode.
  pure      base_extra.read() (the standalone crib gate) reports ONLY the true codec for each
            ciphertext and nothing for any decoy -- 0 wrong plain answers without wiring.
  regress   after the readers are registered, the shipped encodings (plain, hex, base64,
            base32, rot13) still read to the same slug: the new readers move no earlier shape.
  isolation no saved-day shape (hex / base64 / base32 / rot13 of the sentence, and the plain
            sentence) is read THROUGH a base_extra reader -- their chains never name one.
"""
import atexit
import os
import random
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
VERBOSE = "-v" in sys.argv[1:]
SENTENCE = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
WORDS = (["brave", "crisp", "deft", "jaunty", "zesty", "quick", "fancy", "jolly", "clever", "nimble", "dainty"],
         ["blanket", "compass", "canyon", "quill", "puzzle", "forest", "zephyr", "castle", "crater", "banner"],
         ["clover", "coral", "birch", "laurel", "jasmine", "fjord", "ember", "waterfall"])

for _p in (REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    sys.path.insert(0, str(_p))

ROOT = Path(tempfile.mkdtemp(prefix="warmups-day24-"))
# CTF_WORKDIR is set at import and may outlive this module in a pytest worker: remove the folder at exit only.
atexit.register(shutil.rmtree, ROOT, True)
(ROOT / "_ledger").mkdir(parents=True)
os.environ["CTF_WORKDIR"] = str(ROOT)
os.environ["CTF_TESTING"] = "1"
os.environ.pop("CTF_TOKEN", None)

import labels            # noqa: E402
import crib_decode as C  # noqa: E402
import base_extra as BE  # noqa: E402


def check(ok, name, detail=""):
    print("%s %s%s" % ("PASS" if ok else "FAIL", name,
                       (": " + str(detail)[:900]) if detail and (not ok or VERBOSE) else ""), flush=True)
    assert ok, "%s: %s" % (name, str(detail)[:900])
    return True


def forget():
    for attr in ("_DAY_CHAINS", "_DAY_DATA", "_RECONCILED", "_CONSENSUS", "_SECOND", "_READ_MEMO",
                 "_DELIVERIES", "_ATTEMPT_DAYS", "_JUDGED"):
        memo = getattr(C, attr, None)
        if memo is not None:
            memo.clear()
    labels._cache.clear()


def kind(answer, truth):
    if answer is None:
        return "none"
    parsed = labels.parse(answer)
    if parsed is None:
        return "plain" if answer == truth else "WRONG"
    return "unsure" if truth in [value for _, value in parsed.options] else "BAD"


def solve(blob, day=24):
    forget()
    got = C.solve_blob(blob.encode() if isinstance(blob, str) else blob, day=day)
    return (got[0] if got else None), (got[1] if got else None)


rnd = random.Random(2024)


def slug():
    return "%s-%s-%s-%02d" % (rnd.choice(WORDS[0]), rnd.choice(WORDS[1]), rnd.choice(WORDS[2]), rnd.randint(10, 99))


ADDED = dict(BE.ENCODERS)   # name -> encoder(bytes) -> bytes


@pytest.fixture(scope="module", autouse=True)
def _base_extra_registered():
    """Register every base_extra reader as a strict decoder, exactly as crib_decode.add_strict is
    built for (and as the day_patch template registers a new reader). This is the minimal form
    of the build-lead's byte_order-style wiring; both _strict_steps and _step_fn then honour it.
    crib_decode is shared by every test module in a pytest worker, so the readers are registered
    for this module's tests only and taken back out afterwards."""
    names_before = set(C._STRICT_NAMES)
    added = []
    for _name, _fn in BE.BY_NAME.items():
        added.append((_fn, _fn.__name__))
        C.add_strict(_fn, _name)
    forget()
    yield
    for _fn, _orig_name in added:
        C.STRICT.remove(_fn)
        _fn.__name__ = _orig_name
    C._STRICT_NAMES.clear()
    C._STRICT_NAMES.update(names_before)
    C._rank.cache_clear()
    forget()


# ---------------------------------------------------------------------------- reads (plain + right chain)
def test_reads_plain_right_chain():
    for name, enc in ADDED.items():
        kinds, chains = [], []
        for _ in range(3):
            s = slug()
            ans, chain = solve(enc((SENTENCE + s).encode()))
            kinds.append(kind(ans, s))
            chains.append(chain)
        named = all(any(name in (ch or []) for ch in (cs or [])) for cs in chains)
        check(kinds == ["plain"] * 3 and named, f"reads: {name} is plain and its chain names it", (kinds, chains[0]))


# ---------------------------------------------------------------------------- wrong (never a wrong plain slug)
def test_wrong_never_a_wrong_plain_slug():
    all_kinds = []
    for name, enc in ADDED.items():
        for _ in range(3):
            s = slug()
            ans, _c = solve(enc((SENTENCE + s).encode()))
            all_kinds.append(kind(ans, s))
    check("WRONG" not in all_kinds and "BAD" not in all_kinds,
          "wrong: no WRONG/BAD plain slug across every added codec", sorted(set(all_kinds)))


# ---------------------------------------------------------------------------- decoy A-looks-like-B
# A ciphertext valid in several alphabets must never produce a WRONG plain slug: the wrong
# codec decodes to different bytes that the crib rejects.
def test_decoy_a_looks_like_b():
    decoy_kinds = []
    for name, enc in ADDED.items():
        if name == "gray":
            continue
        for _ in range(3):
            s = slug()
            ct = enc((SENTENCE + s).encode())
            ans, _c = solve(ct)                 # the search tries every registered + shipped reader
            decoy_kinds.append(kind(ans, s))    # must be the correct slug (plain) or none/unsure
    check(set(decoy_kinds) <= {"plain", "none", "unsure"},
          "decoy: alphabet-overlapping ciphertext never gives a wrong plain slug", sorted(set(decoy_kinds)))


# ---------------------------------------------------------------------------- noise (not an encoding of the sentence)
def test_noise_not_an_encoding_of_the_sentence():
    noise_rnd = random.Random(99)
    noise_kinds = []
    for name, enc in ADDED.items():
        if name == "gray":
            # random binary of a length that Gray-decodes somewhere
            for _ in range(3):
                blob = bytes(noise_rnd.randrange(256) for _ in range(80))
                ans, _c = solve(blob)
                noise_kinds.append("plain" if (ans is not None and labels.parse(ans) is None) else "safe")
        else:
            for _ in range(3):
                junk = ("the quick brown fox jumps over %d lazy dogs today" % noise_rnd.randint(0, 999)).encode()
                ct = enc(junk)                  # a well-formed codec payload, but NOT the sentence
                ans, _c = solve(ct)
                noise_kinds.append("plain" if (ans is not None and labels.parse(ans) is None) else "safe")
    check(set(noise_kinds) == {"safe"},
          "noise: a non-sentence payload is a safe None/unsure, never plain", sorted(set(noise_kinds)))


# ---------------------------------------------------------------------------- gray specifics
def test_gray_specifics():
    g_ok = True
    g_detail = []
    for _ in range(4):
        s = slug()
        msg = (SENTENCE + s).encode()
        ct = BE.enc_gray(msg)
        ans, chains = solve(ct)
        if not (kind(ans, s) == "plain" and any("gray" in (ch or []) for ch in (chains or []))):
            g_ok = False
            g_detail.append((kind(ans, s), chains))
    # digits preserved (a bijection): slug "...-07" must come back "...-07", never digit-unsure
    check(g_ok, "gray: round-trips plain with digits intact and names gray", g_detail)
    _gp = BE.d_gray(SENTENCE.encode())
    check(_gp is None or not _gp.decode("latin1").startswith(SENTENCE),
          "gray: decodes the plain sentence to non-crib garbage (never steals a read)")
    check(BE.d_gray(b"\x00\x01\xff\xfe") is None, "gray: refuses a non-printable decode")


# ---------------------------------------------------------------------------- pure read() gate
def test_pure_read_gate():
    pure_ok = True
    pure_detail = []
    for name, enc in ADDED.items():
        s = slug()
        ct = enc((SENTENCE + s).encode())
        names = [n for n, _ in BE.read(ct)]
        # the true codec must appear; no OTHER codec may report the crib for this ciphertext
        if name not in names or any(n != name for n in names):
            pure_ok = False
            pure_detail.append((name, names))
    check(pure_ok, "pure: base_extra.read() reports only the true codec, 0 wrong plain", pure_detail)


# ---------------------------------------------------------------------------- regression + isolation
# Strict shipped encodings carry the digits, so they read PLAIN; a no-encoding blob and the
# letter cipher rot13 leave the slug's DIGITS unsure (warmups.digits/plain, /rot13) until a base
# probe -- pre-existing crib_decode behaviour. Either way the slug read is correct (plain, or
# unsure WITH the right slug), and the shipped shape must still read to it after registration.
def test_regression_isolation():
    SHIPPED = {
        "hex": (lambda m: m.hex().encode(), "plain"),
        "base64": (lambda m: __import__("base64").b64encode(m), "plain"),
        "base32": (lambda m: __import__("base64").b32encode(m), "plain"),
        "plain": (lambda m: m, "unsure"),
        "rot13": (lambda m: __import__("codecs").encode(m.decode(), "rot13").encode(), "unsure"),
    }
    reg_ok, iso_ok, reg_detail = True, True, []
    for sname, (enc, want) in SHIPPED.items():
        s = slug()
        msg = (SENTENCE + s).encode()
        ans, chains = solve(enc(msg))
        k = kind(ans, s)                      # "unsure" means the right slug is among the options
        if k != want:
            reg_ok = False
            reg_detail.append(("read", sname, k, "want " + want, chains))
        steps_used = {step for ch in (chains or []) for step in (ch or [])}
        if steps_used & BE.NAMES:
            iso_ok = False
            reg_detail.append(("isolated", sname, chains))
    check(reg_ok, "regress: shipped encodings still read to the right slug after registration", reg_detail)
    check(iso_ok, "isolation: no shipped/plain shape is read through a base_extra reader", reg_detail)


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
