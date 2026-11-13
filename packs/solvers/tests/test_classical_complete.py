#!/usr/bin/env python3
"""The classical ciphers added to complete the toolkit: trifid, nihilist, four-square, Hill
(2x2 and 3x3), mirror lines, and the turning (Fleissner) grille.

  CTF_WORKDIR=/tmp/ctfws .venv/bin/python tests/test_classical_complete.py   # -> 'ok', exit 0

Every input is synthetic and built in the test: each cipher is driven forward with its own
encrypt, then the decrypt is shown to recover the plaintext, and the known-plaintext breaks
(Hill by linear algebra, the nihilist additive key by subtraction, the turning grille by its
orbit search through crack()) are shown to recover the key/reading from a crib alone. No network,
no judge: the module returns candidate readings and keys for a human to read.

Both pytest (test_* functions) and the standalone runner work; the standalone path prints 'ok'.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "solvers", "common"))

import classical as C          # noqa: E402


# --------------------------------------------------------------------------- fractionation round-trips

def test_trifid_roundtrip():
    pt = "attackatdawnatdusk"
    for period in (0, 5, 7):
        ct = C.trifid_encrypt(pt, "secret", period)
        assert ct != pt
        assert C.trifid_decrypt(ct, "secret", period) == pt
    # The period matters: the same text under two periods gives two different cipher texts.
    assert C.trifid_encrypt(pt, "secret", 5) != C.trifid_encrypt(pt, "secret", 7)


def test_bifid_period_variant():
    pt = "defendtheeastwallofthecastle"
    for period in (0, 5, 7):
        ct = C.bifid_encrypt(pt, "keyword", period)
        assert C.bifid_decrypt(ct, "keyword", period) == pt
    assert C.bifid_encrypt(pt, "keyword", 5) != C.bifid_encrypt(pt, "keyword", 0)


def test_nihilist_roundtrip_and_crib():
    pt = "dynamitewinterpalace"
    ct = C.nihilist_encrypt(pt, "zebra", "russian")
    # The cipher is space-separated two/three-digit sums.
    assert all(tok.isdigit() for tok in ct.split())
    assert C.nihilist_decrypt(ct, "zebra", "russian") == pt.replace("j", "i")
    # Wrong key does not read back to the plaintext.
    assert C.nihilist_decrypt(ct, "zebra", "german") != pt.replace("j", "i")
    # Crib break: given the square and a known plaintext prefix, recover the additive key stream.
    key = C.crib_nihilist(ct, "dynamite", "zebra")
    assert key is not None
    # "russian" over 8 letters -> r u s s i a n r
    assert key == "russianr"


def test_four_square_roundtrip():
    pt = "helpmeobiwankenobi"
    ct = C.four_square_encrypt(pt, "example", "keyword")
    assert ct != pt
    assert C.four_square_decrypt(ct, "example", "keyword") == pt.replace("j", "i")
    # A different second key gives a different cipher text.
    assert C.four_square_encrypt(pt, "example", "other") != ct


# --------------------------------------------------------------------------- Hill

def test_hill_2x2_roundtrip_and_crib():
    key = [[3, 3], [2, 5]]          # det = 9, invertible mod 26
    pt = "thefoxranfast"
    ct = C.hill_encrypt(pt, key)
    dec = C.hill_decrypt(ct, key)
    assert dec is not None and dec.startswith("thefoxranfast")
    # Known-plaintext break from four letters recovers the exact matrix.
    assert C.crib_hill(ct, "thef", 2) == key


def test_hill_3x3_roundtrip_and_crib():
    key = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]     # the classic invertible 3x3
    pt = "actnowpleaseandwin"
    ct = C.hill_encrypt(pt, key)
    dec = C.hill_decrypt(ct, key)
    assert dec is not None and dec.startswith("actnowplease")
    assert C.crib_hill(ct, "actnowple", 3) == key


def test_hill_key_from_keyword():
    # A keyword spells the matrix row-major (a=0..z=25).
    km = C.hill_key_matrix("ddcf", 2)      # d d c f -> [[3,3],[2,5]]
    assert km == [[3, 3], [2, 5]]
    assert C.hill_decrypt(C.hill_encrypt("message", km), km).startswith("message")


def test_hill_noninvertible_key_is_none():
    assert C._mat_mod_inv([[2, 4], [6, 8]]) is None     # det even -> not invertible mod 26
    assert C.hill_decrypt("abcd", [[2, 4], [6, 8]]) is None


# --------------------------------------------------------------------------- transposition additions

def test_mirror_lines():
    assert C.mirror_lines("abc\ndef") == "cba\nfed"
    # Its own inverse.
    text = "the quick brown\nfox jumps over"
    assert C.mirror_lines(C.mirror_lines(text)) == text


def test_turning_grille_roundtrip():
    for n in (4, 6):
        orbits = C._grille_orbits(n)
        assert len(orbits) == n * n // 4 and all(len(o) == 4 for o in orbits)
        holes = [o[0] for o in orbits]          # one hole per orbit -> a valid grille
        pt = "".join(chr(97 + i % 26) for i in range(n * n))
        ct = C.turning_grille_encrypt(pt, holes, n)
        assert C.turning_grille_decrypt(ct, holes, n) == pt


def test_turning_grille_rejects_bad_grille():
    # Two holes in one orbit (an invalid grille) is refused.
    orbits = C._grille_orbits(4)
    bad = [orbits[0][0], orbits[0][1]] + [o[0] for o in orbits[2:]]
    assert C.turning_grille_decrypt("x" * 16, bad, 4) is None


# --------------------------------------------------------------------------- crack() auto-surfacing

def test_crack_surfaces_hill_from_crib():
    key = [[3, 3], [2, 5]]
    ct = C.hill_encrypt("retreatatdawn", key)
    hits = [(name, plain) for how, name, plain in C.crack(ct, crib="retreat") if name.startswith("hill")]
    assert hits, "crack() should recover the Hill key from the crib"
    assert hits[0][1].startswith("retreat")


def test_crack_surfaces_grille_from_crib():
    orbits = C._grille_orbits(4)
    holes = [o[0] for o in orbits]
    ct = C.turning_grille_encrypt("meetatdawnbridge", holes, 4)
    readings = [plain for how, name, plain in C.crack(ct, crib="meetat") if name.startswith("grille")]
    assert any("meetat" in r for r in readings), "crack() should find a turning grille that reads the crib"


# --------------------------------------------------------------------------- existing exports intact

def test_existing_exports_intact():
    # crib_decode.py imports this module by file path and calls these; keep them callable.
    for fn in ("crib_keys", "crib_late", "decode_named", "crack", "keyless", "enigma", "playfair_decrypt"):
        assert callable(getattr(C, fn))
    # crib_keys still reads a Vigenere key off a crib (unchanged contract): it needs two full key
    # periods of known plaintext to fix a length-5 key.
    ct = C.vigenere_encrypt("thesecretmessage", "lemon")
    names = [n for n, _ in C.crib_keys(ct, "thesecretmess")]
    assert any(n.startswith("vigenere:lemon") for n in names)


def _run():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
