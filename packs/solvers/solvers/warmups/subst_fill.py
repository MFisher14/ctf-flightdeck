"""Day 21 look-ahead build (2026-10-20): a random monoalphabetic substitution whose slug holds letters the
sentence lacks.

The sentence's 68 letters give the cipher image of 21 plain letters; f, j, q, y and z are not in it, and four
slugs in five hold one of them (docs/retro/day-19-predictions-warmups.md). classical.crib_keys reads such a
text only when the slug's letters are all known (`subst:`) or the known pairs leave one keyword alphabet
(`kwfill:`, W3). Here every way to give the slug's unknown cipher letters distinct plain letters that no
sentence letter took is tried (at most 5! = 120), and a reading is kept when its three words are known: all
three words of saved slugs (`saved_words`), else all three in the word list (`vocabulary`). One reading is
offered unsure under its method; two to four are a candidate pick of the blob's own readings; none or more,
nothing. The digits pass a substitution of letters as they are. Never plain: the slug's filled letters come
from the word lists, not from the bytes (row 171's rule).

crib_decode._lattice asks it last, for a whole blob every other reader left None; the result has the shape
lossy_codes.read gives: (code, method, slugs, exact). Loaded by name: a copy of the folder without this file
reads as before.
"""
import itertools
import re

A = "abcdefghijklmnopqrstuvwxyz"
SLUG = re.compile(r"([a-z]+)-([a-z]+)-([a-z]+)-([0-9]{2})")
MAX_UNKNOWN = 5
READINGS = 4
MIN_PAIRS = 15     # distinct sentence letters the substitution must map (the sentence has 21)


def _table(cipher: str, plain: str):
    """{cipher letter: plain letter} that maps `plain` onto the start of `cipher`, one to one, every other
    character in place; None when the texts do not line up that way."""
    if len(cipher) < len(plain):
        return None
    fwd, back = {}, {}
    for c, p in zip(cipher, plain):
        if p.isalpha():
            if not (c.isascii() and c.isalpha()) or c.isupper() != p.isupper():
                return None
            c, p = c.lower(), p.lower()
            if fwd.setdefault(c, p) != p or back.setdefault(p, c) != c:
                return None
        elif c != p:
            return None
    return fwd if len(fwd) >= MIN_PAIRS else None


def _affine(table: dict) -> bool:
    """True when the known pairs fit one affine map (a shift, atbash, rot13, an affine cipher): those are read,
    digits and all, by the keyless steps and classical.crib_keys, and their unknown letters are no guess."""
    pairs = [(ord(c) - 97, ord(p) - 97) for c, p in table.items()]
    for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        for b in range(26):
            if all((a * p + b) % 26 == c for c, p in pairs):
                return True
    return False


def read(text: str, crib: str, words: set, saved: set):
    table = _table(text, crib)
    if table is None or _affine(table):
        return None
    rest = text[len(crib):].strip()
    if "\n" in rest or not rest:
        return None
    cipher = rest.lower()
    if not re.fullmatch(r"[a-z]+-[a-z]+-[a-z]+-[0-9]{2}", cipher):
        return None
    unknown = sorted({c for c in cipher if c.isalpha() and c not in table})
    if not unknown:
        return None            # every letter known: classical.crib_keys' subst: reads it
    free = [p for p in A if p not in table.values()]
    if len(unknown) > MAX_UNKNOWN or len(unknown) > len(free):
        return None
    by = {"saved_words": [], "vocabulary": []}
    for perm in itertools.permutations(free, len(unknown)):
        full = dict(table)
        full.update(zip(unknown, perm))
        slug = "".join(full.get(c, c) for c in cipher)
        m = SLUG.fullmatch(slug)
        if not m:
            continue
        ws = m.groups()[:3]
        if all(w in saved for w in ws):
            by["saved_words"].append(slug)
        elif all(w in words for w in ws):
            by["vocabulary"].append(slug)
    for method in ("saved_words", "vocabulary"):
        slugs = sorted(set(by[method]))
        if len(slugs) == 1:
            return "subst_fill", method, slugs, False
        if 2 <= len(slugs) <= READINGS:
            return "subst_fill", "readings", slugs, False
        if slugs:
            return None        # more readings than can be told apart
    return None
