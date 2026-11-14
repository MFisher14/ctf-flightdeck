#!/usr/bin/env python3
"""Classical ciphers: encoders, decoders, known-plaintext key recovery, and cracking by English scoring.

Backlog row 88. Shared by the Warmups solver (solvers/warmups/crib_decode.py, which uses the
known-plaintext part on its 87-character sentence) and open to the Mobile codec search and to an
agent on a crypto day.

  .venv/bin/python solvers/common/classical.py <file> [--crib TEXT] [--pattern REGEX] [--seconds S]
  .venv/bin/python solvers/common/classical.py <prompt or cipher file> --enigma [SETTINGS file or text]

prints what the file is most likely enciphered with and the best readings, each marked with how
it was established:

  crib      the reading contains the known plaintext, and the key was derived from it or checked
            by it over enough letters (the caller says how many). This is a proof.
  pattern   the reading holds exactly one match of the answer pattern (flag{...}) and reads as
            English. Evidence, not proof: an answer taken from it is unsure (labels.pick).
  score     English statistics only. Never an answer by itself.

Never-guess, for callers (AGENTS.md, "Uncertain answers"): a keyless transform that reproduces a
crib is a fact; a key recovered from a crib is a fact for the letters the crib covers; a reading
ranked by letter statistics is a hint for a person, and solve_set here answers it only as an
unsure pick, and only for a question that is not the Warmups sentence (crib_decode.py owns that).

Contents:

  alphabets    caesar, rot5/rot18/rot47, atbash, affine, keyword and full substitution,
               keyboard shift (QWERTY one key left or right), A1Z26, leetspeak (detect only)
  polyalpha    vigenere, beaufort, variant beaufort, autokey, gronsfeld, running xor with a key
  fractions    polybius (5x5 and 6x6, keyed), tap code, bacon (24 and 26 letters), playfair
               (decrypt with a key, and the checks that say whether a text can be playfair),
               bifid (with a period), trifid (3x3x3, with a period), nihilist (keyed square plus a
               repeating additive key), four-square, ADFGX/ADFGVX with a key
  matrix       Hill (n x n over Z/26, 2x2 and 3x3; modular-inverse key; known-plaintext key break)
  moving       rail fence (with an offset), columnar (complete and irregular), scytale, route
               by blocks, reversals, mirror lines, the turning (Fleissner) grille with a small-grid
               crib search
  machines     Enigma I / M3 (rotors I to VIII, reflectors B and C, rings, plugboard)
  machines     enigma_settings(text): the rotors, positions, rings, reflector and plugboard a prompt states
               (`--enigma` deciphers with them; Huntress 2024 'Mystery')
  esolangs     Brainfuck, Ook!, COW (Huntress 2024 'Cattle'), and a step limit for each
  statistics   letter counts, index of coincidence, chi-squared against English, an n-gram
               model built from the system dictionary, word coverage, kasiski and IoC key length
  known text   crib_* functions: the key that turns the cipher text into the known plaintext
  cracking     crack_caesar, crack_affine, crack_vigenere, crack_railfence, crack_columnar,
               crack_substitution (hill climbing), and crack(), which tries them all
  polish       polish_substitution (swap confusable plain-letter pairs while dictionary coverage
               rises), instruction_lines (decoded lines that match the flag template or say how to
               wrap the answer); solvers/common/classical_open.py runs it all at intake (B-125)

Everything is plain Python and the standard library. The crib functions are a few milliseconds;
crack_substitution takes its `seconds` and is never for a clock.
"""
import functools
import itertools
import math
import os
import re
import string
import sys
import time
from collections import Counter
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

A = string.ascii_lowercase
AU = string.ascii_uppercase
ENGLISH = {"e": 12.70, "t": 9.06, "a": 8.17, "o": 7.51, "i": 6.97, "n": 6.75, "s": 6.33, "h": 6.09, "r": 5.99,
           "d": 4.25, "l": 4.03, "c": 2.78, "u": 2.76, "m": 2.41, "w": 2.36, "f": 2.23, "g": 2.02, "y": 1.97,
           "p": 1.93, "b": 1.29, "v": 0.98, "k": 0.77, "j": 0.15, "x": 0.15, "q": 0.10, "z": 0.07}
IOC_ENGLISH, IOC_RANDOM = 0.0667, 0.0385
COMMON_WORDS = """the of and to a in is it you that he was for on are with as i his they be at one have this from or
had by not word but what some we can out other were all there when up use your how said an each she which do their
time if will way about many then them write would like so these her long make thing see him two has look more day
could go come did number sound no most people my over know water than call first who may down side been now find any
new work part take get place made live where after back little only round man year came show every good me give our
under name very through just form sentence great think say help low line differ turn cause much mean before move
right boy old too same tell does set three want air well also play small end put home read hand port large spell add
even land here must big high such follow act why ask men change went light kind off need house picture try us again
animal point mother world near build self earth father flag secret message answer key cipher code hidden submit
solve decode exact nice warmup game master password congratulations correct challenge""".split()

_DICT = None
_MODEL = None


# ---------------------------------------------------------------------------- statistics

def letters(text: str) -> str:
    """The letters of a text, lower case, nothing else."""
    return "".join(c for c in text.lower() if "a" <= c <= "z")


def counts(text: str) -> Counter:
    return Counter(letters(text))


def ioc(text: str) -> float:
    """Index of coincidence of the letters: about 0.067 for English and any monoalphabetic or
    transposition cipher of it, 0.038 for random letters, in between for a periodic key."""
    t = letters(text)
    n = len(t)
    if n < 2:
        return 0.0
    return sum(v * (v - 1) for v in Counter(t).values()) / (n * (n - 1))


def chi2(text: str) -> float:
    """Chi-squared of the letter counts against English: lower is more English."""
    t = letters(text)
    n = len(t)
    if not n:
        return float("inf")
    got = Counter(t)
    return sum((got.get(c, 0) - n * p / 100) ** 2 / (n * p / 100) for c, p in ENGLISH.items())


def dictionary() -> set:
    """/usr/share/dict/words in lower case (three letters and more), plus COMMON_WORDS."""
    global _DICT
    if _DICT is None:
        words = set(COMMON_WORDS)
        path = "/usr/share/dict/words"
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="ignore") as fh:
                words.update(w for w in (x.strip().lower() for x in fh) if len(w) >= 3 and w.isascii() and w.isalpha())
        _DICT = words
    return _DICT


def _model():
    """Log-probabilities of letter quadgrams, from the common words (weighted as running text
    would have them) and the dictionary. Built once, in about half a second, on first use."""
    global _MODEL
    if _MODEL is None:
        grams = Counter()
        weight = len(COMMON_WORDS) * 40
        text = []
        for i, w in enumerate(COMMON_WORDS):
            text += [w] * max(1, weight // (40 * (i + 1)))
        # Running text without spaces: neighbours in the list stand in for neighbours in a sentence.
        stream = "".join(text[i * 7919 % len(text)] for i in range(len(text)))
        for i in range(len(stream) - 3):
            grams[stream[i:i + 4]] += 6
        for w in dictionary():
            if len(w) >= 4:
                for i in range(len(w) - 3):
                    grams[w[i:i + 4]] += 1
        total = sum(grams.values())
        floor = math.log10(0.01 / total)
        _MODEL = ({g: math.log10(v / total) for g, v in grams.items()}, floor)
    return _MODEL


def fitness(text: str) -> float:
    """Mean quadgram log-probability of the letters: about -3.6 to -4.2 for English, -5.5 and
    lower for scrambled letters. Only for ranking readings against each other."""
    t = letters(text)
    if len(t) < 4:
        return -9.0
    table, floor = _model()
    return sum(table.get(t[i:i + 4], floor) for i in range(len(t) - 3)) / (len(t) - 3)


def word_coverage(text: str) -> float:
    """The share of a text's letters that sit in dictionary words (split on anything that is not
    a letter). 1.0 for prose in known words, near 0 for cipher text. Needs word breaks."""
    words = re.findall(r"[A-Za-z]+", text)
    total = sum(map(len, words))
    if not total:
        return 0.0
    known = dictionary()
    return sum(len(w) for w in words if w.lower() in known or w.lower() in ("a", "i")) / total


def segment_coverage(text: str, cap: int = 400) -> float:
    """The same for text without word breaks: the largest share of the first `cap` letters that
    can be covered by dictionary words of three letters and more, laid end to end."""
    t = letters(text)[:cap]
    if not t:
        return 0.0
    known = dictionary()
    best = [0] * (len(t) + 1)
    for i in range(1, len(t) + 1):
        best[i] = best[i - 1]
        for n in range(3, min(i, 14) + 1):
            if t[i - n:i] in known and best[i - n] + n > best[i]:
                best[i] = best[i - n] + n
    return best[-1] / len(t)


def kasiski(text: str, low: int = 2, high: int = 24) -> list:
    """Key lengths by repeated trigrams: [(length, repeats whose distance it divides)], best first."""
    t = letters(text)
    seen, votes = {}, Counter()
    for i in range(len(t) - 2):
        g = t[i:i + 3]
        if g in seen:
            d = i - seen[g]
            for n in range(low, high + 1):
                if d % n == 0:
                    votes[n] += 1
        seen[g] = i
    return votes.most_common()


def key_lengths(text: str, low: int = 1, high: int = 24) -> list:
    """Key lengths by the mean index of coincidence of the columns: [(length, ioc)], best first;
    a multiple of the true length scores as well, so the caller prefers the shortest good one."""
    t = letters(text)
    out = []
    for n in range(low, min(high, max(low, len(t) // 4)) + 1):
        cols = [t[i::n] for i in range(n)]
        out.append((n, sum(ioc(c) for c in cols) / n))
    return sorted(out, key=lambda x: -x[1])


# ---------------------------------------------------------------------------- alphabets

def _shift(c: str, n: int) -> str:
    if "a" <= c <= "z":
        return chr((ord(c) - 97 + n) % 26 + 97)
    if "A" <= c <= "Z":
        return chr((ord(c) - 65 + n) % 26 + 65)
    return c


def caesar(text: str, n: int) -> str:
    """Every letter moved n places forward (decrypt with -n)."""
    return "".join(_shift(c, n) for c in text)


def rot5(text: str) -> str:
    return "".join(chr((ord(c) - 48 + 5) % 10 + 48) if "0" <= c <= "9" else c for c in text)


def rot13(text: str) -> str:
    return caesar(text, 13)


def rot18(text: str) -> str:
    """rot13 on the letters and rot5 on the digits."""
    return rot5(caesar(text, 13))


def rot47(text: str) -> str:
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)


def atbash(text: str) -> str:
    return "".join(chr(219 - ord(c)) if "a" <= c <= "z" else chr(155 - ord(c)) if "A" <= c <= "Z" else c for c in text)


def affine_encrypt(text: str, a: int, b: int) -> str:
    if math.gcd(a, 26) != 1:
        raise ValueError("a must be coprime with 26")
    return "".join(chr((a * (ord(c) - 97) + b) % 26 + 97) if "a" <= c <= "z" else
                   chr((a * (ord(c) - 65) + b) % 26 + 65) if "A" <= c <= "Z" else c for c in text)


def affine_decrypt(text: str, a: int, b: int) -> str:
    inv = pow(a, -1, 26)
    return "".join(chr(inv * (ord(c) - 97 - b) % 26 + 97) if "a" <= c <= "z" else
                   chr(inv * (ord(c) - 65 - b) % 26 + 65) if "A" <= c <= "Z" else c for c in text)


def keyword_alphabet(keyword: str, alphabet: str = A) -> str:
    """The cipher alphabet of a keyword cipher: the keyword's letters once each, then the rest."""
    out = []
    for c in keyword.lower() + alphabet:
        if c in alphabet and c not in out:
            out.append(c)
    return "".join(out)


def substitute(text: str, table: dict) -> str:
    """Letters replaced by `table` (lower-case keys and values; case kept). A letter the table
    lacks is left as it is."""
    out = []
    for c in text:
        low = c.lower()
        if low in table:
            out.append(table[low].upper() if c.isupper() else table[low])
        else:
            out.append(c)
    return "".join(out)


def substitution_encrypt(text: str, cipher_alphabet: str) -> str:
    return substitute(text, dict(zip(A, cipher_alphabet.lower())))


def substitution_decrypt(text: str, cipher_alphabet: str) -> str:
    return substitute(text, dict(zip(cipher_alphabet.lower(), A)))


_QWERTY_ROWS = ("`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./",
                "~!@#$%^&*()_+", "QWERTYUIOP{}|", 'ASDFGHJKL:"', "ZXCVBNM<>?")
KEYBOARD_RIGHT = {}     # the key one place to the right of each key, with and without shift held
for _row in _QWERTY_ROWS:
    for _a, _b in zip(_row, _row[1:]):
        KEYBOARD_RIGHT[_a] = _b
KEYBOARD_LEFT = {v: k for k, v in KEYBOARD_RIGHT.items()}
_LETTER_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")


def keyboard_shift(text: str, right: bool = True):
    """Each character replaced by its QWERTY neighbour, one key to the right (or left). None when
    a character has no such neighbour (the last key of a row): the shift cannot have written it."""
    table = KEYBOARD_RIGHT if right else KEYBOARD_LEFT
    out = []
    for c in text:
        if c in " \t\r\n":
            out.append(c)
        elif c in table:
            out.append(table[c])
        else:
            return None
    return "".join(out)


def keyboard_wrap(text: str, n: int = 1) -> str:
    """Letters only: each replaced by the letter n keys to its right in its own QWERTY row, the
    row's end wrapping to its start (n = -1 undoes n = 1). Everything else stays."""
    table = {}
    for row in _LETTER_ROWS:
        for i, c in enumerate(row):
            table[c] = row[(i + n) % len(row)]
            table[c.upper()] = row[(i + n) % len(row)].upper()
    return "".join(table.get(c, c) for c in text)


def a1z26_encode(text: str, sep: str = "-", word_sep: str = " ") -> str:
    return word_sep.join(sep.join(str(ord(c) - 96) for c in w) for w in re.findall(r"[a-z]+", text.lower()))


def a1z26_decode(text: str):
    """Numbers 1 to 26 as letters. Runs of numbers joined by '-', ',' or '.' are words; white
    space or '/' separates words. None for anything else. Case, digits and marks of the plain
    text are not in this code, so its reading is never the whole of a text that had them."""
    t = text.strip()
    if not t:
        return None
    if "/" in t or re.search(r"\s{2,}", t):
        words = [w for w in re.split(r"\s*/\s*|\s{2,}", t) if w]
    elif re.search(r"[-,.]", t):
        words = t.split()
    else:
        words = [t]
    out = []
    for w in words:
        nums = [x for x in re.split(r"[-,.\s]+", w) if x]
        if not nums or not all(re.fullmatch(r"\d{1,2}", x) and 1 <= int(x) <= 26 for x in nums):
            return None
        out.append("".join(chr(96 + int(x)) for x in nums))
    return " ".join(out)


SPELLING = dict(zip(A, ("alfa bravo charlie delta echo foxtrot golf hotel india juliett kilo lima mike november oscar"
                        " papa quebec romeo sierra tango uniform victor whiskey xray yankee zulu").split()))
_SPELLED = {w: c for c, w in SPELLING.items()}
_SPELLED.update({"alpha": "a", "juliet": "j", "x-ray": "x", "zero": "0", "one": "1", "two": "2", "three": "3",
                 "four": "4", "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9", "niner": "9",
                 "dash": "-", "hyphen": "-", "minus": "-"})
_FIGURES = "zero one two three four five six seven eight nine".split()


def spelling_encode(text: str, sep: str = " ") -> str:
    """Letters as ICAO spelling words, digits as figures, '-' as dash; a space as '/'. Other marks stay."""
    return sep.join(SPELLING[c] if c in SPELLING else _FIGURES[int(c)] if c.isdigit() else "dash" if c == "-"
                    else "/" if c == " " else c for c in text.lower())


def spelling_decode(text: str):
    """ICAO spelling words, figures and dash as their characters, in upper case (the alphabet has no
    case); '/' between words is a space, a '-' standing alone is itself. Tokens are separated by
    white space or commas. None when a token is anything else or fewer than three words are there."""
    out, hits = [], 0
    for tok in re.split(r"[\s,]+", text.strip().lower()):
        if not tok:
            continue
        if tok in _SPELLED:
            out.append(_SPELLED[tok].upper())
            hits += 1
        elif tok == "/":
            out.append(" ")
        elif tok == "-":
            out.append("-")
        else:
            return None
    return "".join(out) if hits >= 3 else None


LEET = {"4": "a", "@": "a", "8": "b", "3": "e", "6": "g", "1": "il", "!": "i", "0": "o", "5": "s", "$": "s",
        "7": "t", "2": "z", "9": "g"}


def looks_leet(text: str) -> bool:
    """True when a text reads as leetspeak: words in which digits stand where letters would. It
    is never decoded to an answer: '1' is i or l, and a digit may be a digit."""
    words = re.findall(r"[A-Za-z0-9@$!]+", text)
    mixed = [w for w in words if re.search(r"[A-Za-z]", w) and re.search(r"[0-9@$]", w)]
    return len(words) >= 3 and len(mixed) >= max(2, len(words) // 3)


# ---------------------------------------------------------------------------- polyalphabetic

VIGENERE_KINDS = ("vigenere", "beaufort", "variant")


def _poly(text: str, key: str, kind: str, decrypt: bool, every: bool = False) -> str:
    """One pass of a periodic-key cipher. kind: vigenere (c = p + k), beaufort (c = k - p, its own
    inverse), variant (c = p - k). `every`: the key also advances on characters that are not
    letters (some tools do that)."""
    ks = [ord(c) - 97 for c in key.lower() if "a" <= c <= "z"]
    if not ks:
        raise ValueError("the key has no letter")
    out, i = [], 0
    for c in text:
        if c.isascii() and c.isalpha():
            base = 65 if c.isupper() else 97
            x, k = ord(c) - base, ks[i % len(ks)]
            if kind == "beaufort":
                y = k - x
            elif (kind == "vigenere") != decrypt:
                y = x + k
            else:
                y = x - k
            out.append(chr(y % 26 + base))
            i += 1
        else:
            out.append(c)
            i += every
    return "".join(out)


def vigenere_encrypt(text, key, kind="vigenere", every=False):
    return _poly(text, key, kind, False, every)


def vigenere_decrypt(text, key, kind="vigenere", every=False):
    return _poly(text, key, kind, True, every)


def gronsfeld_decrypt(text: str, digits: str) -> str:
    """Vigenere with a key of digits (0 to 9 as shifts)."""
    return vigenere_decrypt(text, "".join(chr(97 + int(d)) for d in digits if d.isdigit()))


def autokey_encrypt(text: str, primer: str) -> str:
    key = [ord(c) - 97 for c in primer.lower() if "a" <= c <= "z"]
    out = []
    for c in text:
        if c.isascii() and c.isalpha():
            base = 65 if c.isupper() else 97
            x = ord(c) - base
            out.append(chr((x + key.pop(0)) % 26 + base))
            key.append(x)
        else:
            out.append(c)
    return "".join(out)


def autokey_decrypt(text: str, primer: str) -> str:
    key = [ord(c) - 97 for c in primer.lower() if "a" <= c <= "z"]
    if not key:
        raise ValueError("the primer has no letter")
    out = []
    for c in text:
        if c.isascii() and c.isalpha():
            base = 65 if c.isupper() else 97
            x = (ord(c) - base - key.pop(0)) % 26
            out.append(chr(x + base))
            key.append(x)
        else:
            out.append(c)
    return "".join(out)


def xor_key(data: bytes, key: bytes) -> bytes:
    return bytes(x ^ key[i % len(key)] for i, x in enumerate(data)) if key else data


# ---------------------------------------------------------------------------- fractionating

def polybius_square(key: str = "", size: int = 5) -> str:
    """The letters of a Polybius square row by row: 5x5 without j (i and j share a cell), or 6x6
    with the digits after the letters. A key puts its letters first."""
    alphabet = A.replace("j", "") if size == 5 else A + string.digits
    seen = []
    for c in (key.lower().replace("j", "i") if size == 5 else key.lower()) + alphabet:
        if c in alphabet and c not in seen:
            seen.append(c)
    return "".join(seen)


def polybius_encode(text: str, key: str = "", size: int = 5, labels: str = "123456", sep: str = " ") -> str:
    sq = polybius_square(key, size)
    out = []
    for c in text.lower().replace("j", "i") if size == 5 else text.lower():
        if c in sq:
            i = sq.index(c)
            out.append(labels[i // size] + labels[i % size])
        elif c == " ":
            out.append("/")
    return sep.join(out)


def polybius_decode(text: str, key: str = "", size: int = 5, labels: str = "123456"):
    """Pairs of row and column labels as letters. Pairs may be packed or separated; '/' or two
    spaces is a word break. None when a character is not a label. In a 5x5 square j is read as i:
    the reading is lossy and never a proof of a word that could hold a j."""
    sq = polybius_square(key, size)
    labels = labels[:size]
    words = re.split(r"\s*/\s*|\s{2,}", text.strip())
    out = []
    for w in words:
        cells = re.sub(r"[\s,.\-]", "", w)
        if not all(c in labels for c in cells):
            cells = cells.upper()
        if not cells or len(cells) % 2 or not all(c in labels for c in cells):
            return None
        out.append("".join(sq[labels.index(cells[i]) * size + labels.index(cells[i + 1])]
                           for i in range(0, len(cells), 2)))
    return " ".join(out)


TAP = "abcdefghijlmnopqrstuvwxyz"   # the tap code's square: no k (c stands for it)


def tap_encode(text: str) -> str:
    out = []
    for w in re.findall(r"[a-z]+", text.lower()):
        cells = []
        for c in w.replace("k", "c"):
            i = TAP.index(c)
            cells.append("." * (i // 5 + 1) + " " + "." * (i % 5 + 1))
        out.append("  ".join(cells))
    return " / ".join(out)


def tap_decode(text: str):
    """Tap code: each letter is two groups of 1 to 5 dots (or the two numbers), row then column.
    None for anything else. k is read as c: lossy, like the 5x5 square."""
    t = text.strip()
    if not t:
        return None
    words = re.split(r"\s*/\s*", t)
    out = []
    for w in words:
        groups = re.findall(r"\.{1,5}|[1-5]", w)
        if not groups or len(groups) % 2 or re.sub(r"[.\s1-5,]", "", w):
            return None
        if re.search(r"\.{6,}", w):
            return None
        vals = [len(g) if g[0] == "." else int(g) for g in groups]
        out.append("".join(TAP[(vals[i] - 1) * 5 + vals[i + 1] - 1] for i in range(0, len(vals), 2)))
    return " ".join(out)


BACON26 = {c: format(i, "05b").replace("0", "a").replace("1", "b") for i, c in enumerate(A)}
_B24 = "abcdefghiklmnopqrstuwxyz"    # the 24-letter table: i=j and u=v
BACON24 = {c: format(i, "05b").replace("0", "a").replace("1", "b") for i, c in enumerate(_B24)}
BACON24.update(j=BACON24["i"], v=BACON24["u"])


def bacon_encode(text: str, table=None, sep: str = " ") -> str:
    table = table or BACON26
    return sep.join(table[c] for c in letters(text))


def bacon_decode(text: str, variant: int = 26):
    """Groups of five symbols from a two-symbol alphabet (a/b, 0/1, or upper and lower case of
    any letters) as letters. None for anything else. The 24-letter table is lossy (i=j, u=v)."""
    t = re.sub(r"[\s,/|\-]", "", text)
    if set(t.lower()) <= set("ab") and len(set(t.lower())) == 2:
        bits = t.lower().replace("a", "0").replace("b", "1")
    elif set(t) <= set("01") and len(set(t)) == 2:
        bits = t
    elif t.isalpha() and not t.islower() and not t.isupper() and len(t) >= 10:
        bits = "".join("1" if c.isupper() else "0" for c in t)
    else:
        return None
    if len(bits) < 5 or len(bits) % 5:
        return None
    alphabet = A if variant == 26 else _B24
    out = []
    for i in range(0, len(bits), 5):
        v = int(bits[i:i + 5], 2)
        if v >= len(alphabet):
            return None
        out.append(alphabet[v])
    return "".join(out)


def playfair_square(key: str = "") -> str:
    return polybius_square(key, 5)


def playfair_decrypt(text: str, key: str) -> str:
    sq = playfair_square(key)
    t = letters(text).replace("j", "i")
    out = []
    for i in range(0, len(t) - 1, 2):
        a, b = sq.index(t[i]), sq.index(t[i + 1])
        ra, ca, rb, cb = a // 5, a % 5, b // 5, b % 5
        if ra == rb:
            out += [sq[ra * 5 + (ca - 1) % 5], sq[rb * 5 + (cb - 1) % 5]]
        elif ca == cb:
            out += [sq[(ra - 1) % 5 * 5 + ca], sq[(rb - 1) % 5 * 5 + cb]]
        else:
            out += [sq[ra * 5 + cb], sq[rb * 5 + ca]]
    return "".join(out)


def playfair_encrypt(text: str, key: str) -> str:
    sq = playfair_square(key)
    t = letters(text).replace("j", "i")
    pairs, i = [], 0
    while i < len(t):
        a = t[i]
        b = t[i + 1] if i + 1 < len(t) else "x"
        if a == b:
            b = "x" if a != "x" else "q"
            i += 1
        else:
            i += 2
        pairs.append((a, b))
    out = []
    for a, b in pairs:
        x, y = sq.index(a), sq.index(b)
        ra, ca, rb, cb = x // 5, x % 5, y // 5, y % 5
        if ra == rb:
            out += [sq[ra * 5 + (ca + 1) % 5], sq[rb * 5 + (cb + 1) % 5]]
        elif ca == cb:
            out += [sq[(ra + 1) % 5 * 5 + ca], sq[(rb + 1) % 5 * 5 + cb]]
        else:
            out += [sq[ra * 5 + cb], sq[rb * 5 + ca]]
    return "".join(out)


def playfair_checks(text: str) -> dict:
    """What must hold for a text to be Playfair cipher text: an even number of letters, no j, no
    digraph of one letter twice, at most 25 different letters. `possible` is their conjunction;
    it says the text can be Playfair, never that it is."""
    t = letters(text)
    pairs = [t[i:i + 2] for i in range(0, len(t) - 1, 2)]
    res = {"letters": len(t), "even": len(t) % 2 == 0 and len(t) > 0, "no_j": "j" not in t,
           "no_double_digraph": all(p[0] != p[1] for p in pairs), "distinct": len(set(t)), "ioc": round(ioc(t), 4)}
    res["possible"] = bool(res["even"] and res["no_j"] and res["no_double_digraph"] and res["distinct"] <= 25)
    return res


def bifid_decrypt(text: str, key: str = "", period: int = 0) -> str:
    sq = polybius_square(key, 5)
    t = letters(text).replace("j", "i")
    period = period or len(t) or 1
    out = []
    for s in range(0, len(t), period):
        block = t[s:s + period]
        coords = []
        for c in block:
            i = sq.index(c)
            coords += [i // 5, i % 5]
        rows, cols = coords[:len(block)], coords[len(block):]
        out.append("".join(sq[r * 5 + c] for r, c in zip(rows, cols)))
    return "".join(out)


def bifid_encrypt(text: str, key: str = "", period: int = 0) -> str:
    sq = polybius_square(key, 5)
    t = letters(text).replace("j", "i")
    period = period or len(t) or 1
    out = []
    for s in range(0, len(t), period):
        block = t[s:s + period]
        idx = [sq.index(c) for c in block]
        coords = [i // 5 for i in idx] + [i % 5 for i in idx]
        out.append("".join(sq[coords[i] * 5 + coords[i + 1]] for i in range(0, len(coords), 2)))
    return "".join(out)


def adfgvx_decrypt(text: str, square_key: str, column_key: str):
    """ADFGX (25 cells) or ADFGVX (36): undo the columnar transposition by column_key, then read
    pairs of labels in the keyed square. Explicit squares determine the alphabet; a plain
    keyword without digits retains the legacy ciphertext-based inference. None on invalid input."""
    if not isinstance(text, str) or not isinstance(square_key, str):
        return None
    t = re.sub(r"\s", "", text.upper())
    square = square_key.lower()
    if len(square) == 25 and set(square) == set(A.replace("j", "")):
        labels = "ADFGX"
    elif (len(square) == 36 and set(square) == set(A + string.digits)) or any(c in string.digits for c in square):
        labels = "ADFGVX"
    else:
        labels = "ADFGVX" if "V" in t else "ADFGX"
    if not t or set(t) - set(labels) or len(t) % 2:
        return None
    size = len(labels)
    mid = columnar_decrypt(t, column_key)
    return polybius_decode(mid, square_key, size, labels) if mid is not None else None


# ---------------------------------------------------------------------------- transposition

def _rail_pattern(n: int, rails: int, offset: int = 0) -> list:
    if rails < 2:
        return [0] * n
    period = 2 * (rails - 1)
    out = []
    for i in range(n):
        k = (i + offset) % period
        out.append(k if k < rails else period - k)
    return out


def railfence_encrypt(text: str, rails: int, offset: int = 0) -> str:
    rows = _rail_pattern(len(text), rails, offset)
    return "".join(text[i] for r in range(rails) for i in range(len(text)) if rows[i] == r)


def railfence_decrypt(text: str, rails: int, offset: int = 0) -> str:
    rows = _rail_pattern(len(text), rails, offset)
    order = [i for r in range(rails) for i in range(len(text)) if rows[i] == r]
    out = [""] * len(text)
    for src, dst in enumerate(order):
        out[dst] = text[src]
    return "".join(out)


def _column_order(key) -> list:
    """The order in which columns are read out, from a keyword (alphabetical, ties left to right)
    or a sequence of numbers (the rank of each column; a string of digits is one digit a column)."""
    if isinstance(key, str) and not key.replace(",", "").replace(" ", "").isdigit():
        ranks = sorted(range(len(key)), key=lambda i: (key[i].lower(), i))
        return ranks
    if isinstance(key, str):       # "31524" is one digit per column; "3,1,10,2" is a list
        key = list(key.strip()) if key.strip().isdigit() else re.findall(r"\d+", key)
    nums = [int(x) for x in key]
    return sorted(range(len(nums)), key=lambda i: (nums[i], i))


def columnar_encrypt(text: str, key) -> str:
    """Rows of len(key) characters written under the key, the columns read out in key order. The
    last row may be short (irregular columnar): nothing is padded."""
    order = _column_order(key)
    n = len(order)
    return "".join(text[c::n] for c in order)


def columnar_decrypt(text: str, key) -> str:
    if not isinstance(text, str):
        return None
    try:
        order = _column_order(key)
    except (TypeError, ValueError, OverflowError):
        return None
    n = len(order)
    if not n:
        return None
    full, extra = divmod(len(text), n)
    out = [""] * len(text)
    at = 0
    for c in order:
        size = full + (c < extra)
        for r in range(size):
            out[r * n + c] = text[at + r]
        at += size
    return "".join(out)


def scytale_decrypt(text: str, turns: int) -> str:
    """A scytale of `turns` columns is a columnar transposition with the columns in order."""
    return columnar_decrypt(text, list(range(turns)))


def scytale_encrypt(text: str, turns: int) -> str:
    return columnar_encrypt(text, list(range(turns)))


def block_reverse(text: str, size: int) -> str:
    """Every block of `size` characters reversed (its own inverse)."""
    return "".join(text[i:i + size][::-1] for i in range(0, len(text), size))


def swap_pairs(text: str) -> str:
    return block_reverse(text, 2)


def interleave_split(text: str, parts: int = 2) -> str:
    """Undo a text written as its 1st, 3rd, 5th.. characters followed by the 2nd, 4th.. (a rail
    fence without the zigzag): the scytale with `parts` rows read the other way."""
    n = len(text)
    sizes = [(n - i + parts - 1) // parts for i in range(parts)]
    chunks, at = [], 0
    for s in sizes:
        chunks.append(text[at:at + s])
        at += s
    return "".join(chunks[i % parts][i // parts] for i in range(n))


# ---------------------------------------------------------------------------- Enigma

ROTORS = {"I": ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"), "II": ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
          "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"), "IV": ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
          "V": ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"), "VI": ("JPGVOUMFYQBENHZRDKASXLICTW", "ZM"),
          "VII": ("NZJHGRCXMYSWBOUFAIVLPEKQDT", "ZM"), "VIII": ("FKQHTLXOCBJSPDZRAMEWNIUYGV", "ZM")}
REFLECTORS = {"A": "EJMZALYXVBWFCRQUONTSPIKHGD", "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
              "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL"}
# B-250: the Kriegsmarine M4. A fourth, thin wheel (Beta or Gamma) sits left of the three stepping
# rotors and never steps; a thin reflector (UKW-B "Bruno", UKW-C "Caesar") takes the place of B or C.
# Beta at A with ring A in front of thin B is the M3's reflector B, and Gamma likewise with thin C is
# C (the M4 was built so: tests/test_b250_warmups_residuals.py checks it), so a stated M4 key with the
# thin wheel at A reads an M3 message.
THIN_ROTORS = {"BETA": "LEYJVCNIXWPBQMDRTAKZGFUHOS", "GAMMA": "FSOKANUERHMBTIYCWLQPZXVGJD"}
THIN_REFLECTORS = {"B": "ENKQAUYWJICOPBLMDXZVFTHRGS", "C": "RDOBJNTKVEHMLFCWZAXGYIPSUQ"}


def _enigma_num(x):
    return [(int(v) - 1) % 26 if str(v).isdigit() else ord(str(v).upper()) - 65
            for v in (x.split() if isinstance(x, str) and " " in x.strip() else list(x))]


def enigma_m4(text: str, rotors=("Beta", "II", "IV", "I"), reflector: str = "B", rings="AAAA",
              start="AAAA", plugboard: str = "") -> str:
    """Enigma M4: four wheels left to right, the leftmost a thin Beta or Gamma that never steps, the
    reflector the thin B or C (named 'B', 'C', 'B-thin', 'UKW-B', ...). Rings and starts are four
    letters (or numbers 1 to 26). Its own inverse; non-letters pass through and do not step. Upper case.
    A wheel, reflector or setting the M4 does not have raises ValueError (no silent stand-in)."""
    if len(rotors) != 4:
        raise ValueError("enigma_m4 needs four wheels (thin wheel first), got %d" % len(rotors))
    thin = str(rotors[0]).upper()
    if thin not in THIN_ROTORS:
        raise ValueError("the M4's leftmost wheel must be Beta or Gamma, not %r" % rotors[0])
    refl_key = re.sub(r"(?i)^ukw[\s-]*|[\s-]*thin$|[\s-]*\(?(?:bruno|caesar)\)?$", "", str(reflector)).upper()
    if refl_key not in THIN_REFLECTORS:
        raise ValueError("the M4 reflector must be thin B or thin C, not %r" % reflector)
    for r in rotors[1:]:
        if r not in ROTORS:
            raise ValueError("unknown Enigma rotor %r" % r)
    ring, pos = _enigma_num(rings), _enigma_num(start)
    if len(ring) != 4 or len(pos) != 4:
        raise ValueError("enigma_m4 needs four ring settings and four start positions")
    wiring = [[ord(c) - 65 for c in THIN_ROTORS[thin]]] + [[ord(c) - 65 for c in ROTORS[r][0]] for r in rotors[1:]]
    inverse = [[w.index(i) for i in range(26)] for w in wiring]
    notches = [[]] + [[ord(c) - 65 for c in ROTORS[r][1]] for r in rotors[1:]]
    refl = [ord(c) - 65 for c in THIN_REFLECTORS[refl_key]]
    plug = list(range(26))
    for pair in re.findall(r"[A-Za-z]{2}", plugboard):
        a, b = ord(pair[0].upper()) - 65, ord(pair[1].upper()) - 65
        plug[a], plug[b] = b, a
    out = []
    for ch in text:
        if not (ch.isascii() and ch.isalpha()):
            out.append(ch)
            continue
        # stepping of the three right wheels only (index 1..3), with the middle rotor's double step
        if pos[2] in notches[2]:
            pos[1] = (pos[1] + 1) % 26
            pos[2] = (pos[2] + 1) % 26
        elif pos[3] in notches[3]:
            pos[2] = (pos[2] + 1) % 26
        pos[3] = (pos[3] + 1) % 26
        c = plug[ord(ch.upper()) - 65]
        for i in (3, 2, 1, 0):
            c = (wiring[i][(c + pos[i] - ring[i]) % 26] - pos[i] + ring[i]) % 26
        c = refl[c]
        for i in (0, 1, 2, 3):
            c = (inverse[i][(c + pos[i] - ring[i]) % 26] - pos[i] + ring[i]) % 26
        out.append(chr(plug[c] + 65))
    return "".join(out)


def enigma(text: str, rotors=("I", "II", "III"), reflector: str = "B", rings="AAA", start="AAA",
           plugboard: str = "") -> str:
    """Enigma I / M3: rotors left to right, ring settings and start positions as letters (or
    numbers 1 to 26 for the rings), plugboard as pairs ('AB CD'). Its own inverse; characters
    that are not letters pass through and do not step the rotors. Output in upper case.
    Four wheels (B-250) are the M4: enigma_m4."""
    if len(rotors) == 4:
        return enigma_m4(text, rotors, reflector, rings, start, plugboard)
    num = _enigma_num
    wiring = [[ord(c) - 65 for c in ROTORS[r][0]] for r in rotors]
    inverse = [[w.index(i) for i in range(26)] for w in wiring]
    notches = [[ord(c) - 65 for c in ROTORS[r][1]] for r in rotors]
    ring, pos = num(rings), num(start)
    refl = [ord(c) - 65 for c in REFLECTORS[reflector]]
    plug = list(range(26))
    for pair in re.findall(r"[A-Za-z]{2}", plugboard):
        a, b = ord(pair[0].upper()) - 65, ord(pair[1].upper()) - 65
        plug[a], plug[b] = b, a
    out = []
    for ch in text:
        if not (ch.isascii() and ch.isalpha()):
            out.append(ch)
            continue
        # stepping, with the middle rotor's double step
        if pos[1] in notches[1]:
            pos[0] = (pos[0] + 1) % 26
            pos[1] = (pos[1] + 1) % 26
        elif pos[2] in notches[2]:
            pos[1] = (pos[1] + 1) % 26
        pos[2] = (pos[2] + 1) % 26
        c = plug[ord(ch.upper()) - 65]
        for i in (2, 1, 0):
            c = (wiring[i][(c + pos[i] - ring[i]) % 26] - pos[i] + ring[i]) % 26
        c = refl[c]
        for i in (0, 1, 2):
            c = (inverse[i][(c + pos[i] - ring[i]) % 26] - pos[i] + ring[i]) % 26
        out.append(chr(plug[c] + 65))
    return "".join(out)


# -------------------------------------------------------------- Enigma: crib-first fast break
#
# The naive break scores the index of coincidence of the WHOLE message for every candidate
# (rotor order x ring x start) -- the rehearsal's ~40-minute job. Two changes turn it into
# seconds: (1) with a known plaintext fragment ("crib", by default the event's flag lead), a candidate is judged by
# decrypting only the crib region and counting matches -- ~100x less work than a full-message
# score, and tolerant of an unknown plugboard (a 3-pair board leaves most crib letters
# unsteckered, so the right wheels still score far above the rest); (2) the ~60 three-rotor
# orders are fanned across CPU cores (solvers/common/psearch). The plugboard is recovered only
# on the handful of survivors, by an n-gram hill climb, and the full decrypt is returned.
#
# Ring settings are held at AAA during the sweep: for a message with no wheel turnover inside it
# only (start - ring) per rotor affects the wiring, so an AAA-ring start stands in for the whole
# equivalence class. A caller that needs other rings can pass them in `rings`.

ENIGMA_ROTOR_SET = ("I", "II", "III", "IV", "V")   # the Enigma I wheels: perm(5,3) = 60 orders


def _enigma_arrays(rotors, reflector):
    """Precompute the integer wiring for a (rotor order, reflector): forward and inverse
    permutations of each rotor, the two stepping rotors' notches, and the reflector."""
    wiring = [[ord(c) - 65 for c in ROTORS[r][0]] for r in rotors]
    inverse = [[w.index(i) for i in range(26)] for w in wiring]
    notches = [[ord(c) - 65 for c in ROTORS[r][1]] for r in rotors]
    refl = [ord(c) - 65 for c in REFLECTORS[reflector]]
    return wiring, inverse, notches, refl


def _enigma_decode_codes(pc, arrays, ring, start, lo, hi, plug=None):
    """Decode cipher letter-codes `pc` over the index range [lo, hi) with ring/start (int
    triples) and optional plugboard permutation `plug` (len-26 list). Returns the output
    letter-codes for that range. Stepping matches enigma() exactly (middle-rotor double step)."""
    (w0, w1, w2), (i0, i1, i2), notches, refl = arrays
    n1, n2 = notches[1], notches[2]
    p0, p1, p2 = start
    r0, r1, r2 = ring
    out = []
    for idx in range(hi):
        if p1 in n1:
            p0 = (p0 + 1) % 26
            p1 = (p1 + 1) % 26
        elif p2 in n2:
            p1 = (p1 + 1) % 26
        p2 = (p2 + 1) % 26
        if idx < lo:
            continue
        c = pc[idx]
        if plug is not None:
            c = plug[c]
        c = (w2[(c + p2 - r2) % 26] - p2 + r2) % 26
        c = (w1[(c + p1 - r1) % 26] - p1 + r1) % 26
        c = (w0[(c + p0 - r0) % 26] - p0 + r0) % 26
        c = refl[c]
        c = (i0[(c + p0 - r0) % 26] - p0 + r0) % 26
        c = (i1[(c + p1 - r1) % 26] - p1 + r1) % 26
        c = (i2[(c + p2 - r2) % 26] - p2 + r2) % 26
        if plug is not None:
            c = plug[c]
        out.append(c)
    return out


def _crib_sweep(job):
    """One worker: over a fixed rotor order and reflector, sweep every start position and ring in
    `ring_triples` and every candidate crib offset, decrypting ONLY the crib region (no
    plugboard) and scoring it by (number of crib letters that match, fitness of the region). The
    crib-match count is the primary key -- the whole point of a crib -- and the region fitness is
    a tie-break among equal counts (it decides between the true wheels and their chaff when the
    crib is fully recovered). Decrypting only the ~crib-length region, not the whole message, is
    what makes this ~100x cheaper per candidate than a full-message IoC scan. Returns the best few
    as (matches, fit, rotors, reflector, ring, start, offset). Module-level and pickle-clean.

    A bare crib of a few letters is a weak signal once a plugboard is present (it can stecker the
    very crib letters); a longer known-plaintext crib separates the true wheels cleanly. The
    driver keeps a generous pool of survivors and re-ranks them by full-message fitness, so a
    short crib still works whenever the true setting surfaces in that pool."""
    import heapq
    pc, rotors, reflector, crib_codes, offsets, ring_triples, window, keep = job
    arrays = _enigma_arrays(rotors, reflector)
    clen = len(crib_codes)
    hi_span = max(clen, window)
    best = []
    for ring in ring_triples:
        for a in range(26):
            for b in range(26):
                for c in range(26):
                    start = (a, b, c)
                    for off in offsets:
                        hi = min(len(pc), off + hi_span)
                        dec = _enigma_decode_codes(pc, arrays, ring, start, off, hi)
                        m = sum(dec[i] == crib_codes[i] for i in range(clen))
                        key = (m, fitness("".join(chr(x + 97) for x in dec)))
                        if len(best) < keep:
                            heapq.heappush(best, (key, rotors, reflector, ring, start, off))
                        elif key > best[0][0]:
                            heapq.heapreplace(best, (key, rotors, reflector, ring, start, off))
    return best


def _letter_codes(text):
    """The alphabetic letters of a text as 0..25 codes (upper-cased), order preserved."""
    return [ord(c) - 65 for c in text.upper() if "A" <= c <= "Z"]


def _plug_toggle(plug, x, y):
    """A copy of involution `plug` in which x is paired with y, keeping it a valid involution.
    Whichever partners x and y already had (if any) are re-paired with each other (or left
    self-mapped). This single move can therefore dismantle one or two existing pairs, which is what
    lets the climb back out of a wrong early pair -- a plain 'set plug[x],plug[y]' that permanently
    locks letters cannot. If x and y are already paired, the move instead unpairs them."""
    q = list(plug)
    if q[x] == y:                       # already paired -> remove the pair
        q[x], q[y] = x, y
        return q
    a, b = q[x], q[y]                   # their current partners (a==x / b==y means unpaired)
    q[x], q[y] = y, x
    if a != x and b != y:               # both had partners: pair the two orphans together
        q[a], q[b] = b, a
    elif a != x:                        # only x had a partner: it becomes self-mapped
        q[a] = a
    elif b != y:
        q[b] = b
    return q


def _plugboard_hillclimb(pc, arrays, ring, start, max_pairs=13, min_gain=1e-9):
    """Recover a plugboard by n-gram hill climbing: repeatedly apply the single letter-pair toggle
    that most improves the quadgram fitness of the full decrypt. Returns a list of snapshots
    [(fitness, plug_tuple)] -- the identity board first, then the board after each accepted move.

    Each round reconsiders ALL 325 letter pairs over the current involution (via _plug_toggle, which
    re-pairs orphaned letters), so a pair added early can be undone later; a plain greedy climb that
    permanently locks each chosen letter gets trapped when its first pick is wrong (e.g. it grabs AG
    before it can find the true GE, and G is then spent). Reconsidering every pair each round escapes
    that local optimum -- the known hill-climb for Enigma plugboard recovery.

    The caller does NOT simply take the last (highest-fitness) snapshot: on a short message the climb
    will happily add a pair or two that nudge the quadgram score while corrupting real words (a
    plugboard swap touches every occurrence of two letters). The caller instead keeps the
    highest-fitness snapshot whose decrypt still contains the known crib -- a correct pair only ever
    repairs the plaintext, so the crib anchors the climb to the right number of pairs."""
    plug = list(range(26))
    n = len(pc)

    def score(pl):
        dec = _enigma_decode_codes(pc, arrays, ring, start, 0, n, pl)
        return fitness("".join(chr(c + 97) for c in dec))

    base = score(plug)
    snapshots = [(base, tuple(plug))]
    # A generous round budget: each accepted move changes at most two pairs, so allow re-optimisation
    # beyond the final pair count rather than one round per pair.
    for _ in range(max_pairs * 3):
        best_gain, best_plug = 0.0, None
        for x in range(26):
            for y in range(x + 1, 26):
                cand = _plug_toggle(plug, x, y)
                s = score(cand)
                if s - base > best_gain + min_gain:
                    best_gain, best_plug = s - base, cand
        if best_plug is None:
            break
        plug = best_plug
        base += best_gain
        snapshots.append((base, tuple(plug)))
    return snapshots


def _plug_pairs(plug):
    """The plugboard as a space-separated 'AB CD' string, from a plug permutation."""
    return " ".join("%c%c" % (a + 65, plug[a] + 65) for a in range(26) if a < plug[a])


def enigma_crib_break(cipher, crib=None, offsets=None, rotor_set=ENIGMA_ROTOR_SET,
                      reflectors=("B",), rings=("AAA",), workers=None, window=8, survivors=200,
                      finalists=12):
    """Crack an Enigma I / M3 message from a known plaintext fragment, fast.

    cipher      the cipher text (non-letters are ignored for the search and passed through in the
                returned decrypt).
    crib        the known plaintext fragment; only its letters are matched. Default: the active
                event's flag leads (ctf.flagfmt.cribs(): `CSCTF{`, `chronos{`, `CTF{`, `flag{` under
                CSCTF; `PINK{` under Pink), each tried in turn, the best reading kept. A lead with
                fewer than three letters is not a usable crib and is left out; ValueError when no
                lead is usable, LookupError when the event's format has no known prefix.
    offsets     letter offsets in the plaintext where the crib may begin (default: position 0 --
                a flag fragment usually starts the message). Pass a range to search.
    rotor_set   the wheels available (default the five Enigma I rotors -> 60 three-rotor orders).
    reflectors  reflectors to try (default B; add 'C' to widen).
    rings       ring settings to try (default AAA; see the section note on why that suffices).
    window      letters decrypted per candidate: max(len(crib), window). A small cushion past the
                crib sharpens the fitness tie-break between candidates with equal crib-match
                counts; it stays tiny for speed.

    Returns the best reading as a dict {rotors, reflector, rings, start, plugboard, plaintext,
    fitness, crib_matches, crib}, or None when nothing containing the crib was found. The rotor
    orders are fanned across CPU cores; only the crib region is decrypted per candidate; the
    plugboard is hill-climbed on the few survivors. Across several cribs the reading with the best
    (word coverage, fitness) wins, the same key that picks a plugboard within one crib.
    """
    if crib is None:
        cribs = [c for c in flagfmt.cribs() if len(_letter_codes(c)) >= 3]
        if not cribs:
            raise ValueError("no flag lead of the active event has three letters (%s): pass crib="
                             % ", ".join(flagfmt.cribs()))
    else:
        cribs = [crib]
    best, best_key = None, None
    for one in cribs:
        key, res = _enigma_crib_break_one(cipher, one, offsets, rotor_set, reflectors, rings, workers,
                                          window, survivors, finalists)
        if res is not None and (best_key is None or key > best_key):
            best_key, best = key, dict(res, crib=one)
    return best


def _enigma_crib_break_one(cipher, crib, offsets, rotor_set, reflectors, rings, workers, window,
                           survivors, finalists):
    """enigma_crib_break for one crib: (best (coverage, fitness) key, reading) or (None, None)."""
    try:
        import psearch
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import psearch
    crib_codes = _letter_codes(crib)
    if len(crib_codes) < 3:
        raise ValueError("the crib needs at least three letters")
    pc = _letter_codes(cipher)
    if len(pc) < len(crib_codes):
        return None, None
    if offsets is None:
        offsets = (0,)
    offsets = tuple(o for o in offsets if 0 <= o <= len(pc) - len(crib_codes))
    if not offsets:
        return None, None
    def _triple(r):     # 'AAA' or 'A A A' or '1 1 1' -> (int, int, int)
        parts = r.split() if " " in r else list(r)
        return tuple((int(x) - 1) % 26 if x.isdigit() else ord(x.upper()) - 65 for x in parts)

    ring_triples = [_triple(r) for r in rings]
    orders = [tuple(p) for p in itertools.permutations(rotor_set, 3)]
    keep = max(40, survivors // max(1, len(orders) * len(reflectors)) + 8)
    _model()        # warm the quadgram model in the parent so forked workers inherit it
    jobs = [(pc, order, refl, crib_codes, offsets, ring_triples, window, keep)
            for order in orders for refl in reflectors]
    results = psearch.parallel_map(_crib_sweep, jobs, workers=workers)

    merged = []
    for lst in results:
        merged.extend(lst)
    if not merged:
        return None, None
    # Rank survivors by the crib-region signal itself -- (matches, region fitness). This is the
    # reliable ordering: a full-message fitness re-rank would bury the true wheels, whose
    # plugboard-less decrypt is poor when a plugboard is in play, while the true wheels sit at the
    # top here (a wrong setting matches each crib letter only ~1/26 of the time). The plugboard is
    # recovered on the top `finalists` by hill climb.
    merged.sort(key=lambda t: t[0], reverse=True)
    arrays_cache = {}

    def arrays_for(rotors, refl):
        key = (rotors, refl)
        if key not in arrays_cache:
            arrays_cache[key] = _enigma_arrays(rotors, refl)
        return arrays_cache[key]

    crib_upper = "".join(chr(c + 65) for c in crib_codes)
    best, best_key = None, None
    for (m, _rf), rotors, refl, ring, start, _off in merged[:finalists]:
        arr = arrays_for(rotors, refl)
        start_str = "".join(chr(c + 65) for c in start)
        ring_str = "".join(chr(c + 65) for c in ring)
        snapshots = _plugboard_hillclimb(pc, arr, ring, start)
        # Among plugboards whose decrypt still holds the crib, keep the one whose plaintext reads
        # as the most real English -- scored by dictionary word coverage, then quadgram fitness.
        # Coverage resists the hill climb's habit of adding a spurious pair that nudges the
        # quadgram score while breaking real words: a bogus swap lowers coverage, a real plug pair
        # raises it. (Raw fitness alone would accept the bogus pair on a short message.)
        for _fit, plug in snapshots:
            pairs = _plug_pairs(list(plug))
            plain = enigma(cipher, rotors=rotors, reflector=refl, rings=ring_str,
                           start=start_str, plugboard=pairs)
            body = letters(plain)
            if crib_upper not in body.upper():
                continue
            key = (round(segment_coverage(body), 4), round(fitness(body), 4))
            if best_key is None or key > best_key:
                best_key = key
                best = {"rotors": rotors, "reflector": refl, "rings": ring_str, "start": start_str,
                        "plugboard": pairs, "plaintext": plain, "fitness": key[1], "crib_matches": m}
    return best_key, best


# ---------------------------------------------------------------------------- esolangs

def brainfuck(code: str, stdin: bytes = b"", steps: int = 2_000_000):
    """The output of a Brainfuck program as bytes, or None when it is not a program, its brackets
    do not match, or it runs longer than `steps`."""
    if not isinstance(code, str):
        return None
    prog = [c for c in code if c in "+-<>[].,"]
    if len(prog) < 8 or "." not in prog:
        return None
    jump, stack = {}, []
    for i, c in enumerate(prog):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                return None
            j = stack.pop()
            jump[i], jump[j] = j, i
    if stack:
        return None
    tape, ptr, pc, out, inp, n = [0] * 30000, 0, 0, bytearray(), 0, 0
    while pc < len(prog):
        n += 1
        if n > steps or len(out) > 65536:
            return None
        c = prog[pc]
        if c == "+":
            tape[ptr] = (tape[ptr] + 1) & 255
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 255
        elif c == ">":
            ptr += 1
            if ptr >= len(tape):
                return None
        elif c == "<":
            ptr -= 1
            if ptr < 0:
                return None
        elif c == ".":
            out.append(tape[ptr])
            if len(out) > 65536:
                return None
        elif c == ",":
            tape[ptr] = stdin[inp] if inp < len(stdin) else 0
            inp += 1
        elif c == "[" and not tape[ptr]:
            pc = jump[pc]
        elif c == "]" and tape[ptr]:
            pc = jump[pc]
        pc += 1
    return bytes(out)


_OOK = {("Ook.", "Ook?"): ">", ("Ook?", "Ook."): "<", ("Ook.", "Ook."): "+", ("Ook!", "Ook!"): "-",
        ("Ook!", "Ook."): ".", ("Ook.", "Ook!"): ",", ("Ook!", "Ook?"): "[", ("Ook?", "Ook!"): "]"}


def ook_to_brainfuck(code: str):
    """An Ook! program as Brainfuck, or None. The short form (only . ? !) is read too."""
    if not isinstance(code, str):
        return None
    tokens = re.findall(r"Ook[.?!]", code)
    if not tokens:
        marks = re.sub(r"\s", "", code)
        if len(marks) < 16 or set(marks) - set(".?!"):
            return None
        tokens = ["Ook" + m for m in marks]
    elif re.sub(r"Ook[.?!]|\s", "", code):
        return None
    if len(tokens) % 2:
        return None
    try:
        return "".join(_OOK[(tokens[i], tokens[i + 1])] for i in range(0, len(tokens), 2))
    except KeyError:
        return None


_COW = ("moo", "mOo", "moO", "mOO", "Moo", "MOo", "MoO", "MOO", "OOO", "MMM", "OOM", "oom")


def cow(code: str, stdin: bytes = b"", steps: int = 2_000_000):
    """The output of a COW program as bytes, or None when it is not one, its loops do not match or
    it runs longer than `steps`. The twelve instructions are the case variants of `moo` (Huntress
    2024's warmup "Cattle" is one); `OOM` prints the cell as a number and `Moo` as a character."""
    prog = [t for t in re.findall(r"[mMoO]{3}", " ".join(code.split())) if t in _COW]
    words = code.split()
    if len(prog) < 8 or len(prog) < 0.9 * len(words):
        return None
    prog = [_COW.index(t) for t in prog]
    mem, ptr, pc, reg, out, used, inp = [0] * 30000, 0, 0, None, bytearray(), 0, 0

    def run(op):
        nonlocal ptr, reg, inp
        if op == 1:
            ptr -= 1
        elif op == 2:
            ptr += 1
        elif op == 4:
            if mem[ptr]:
                out.append(mem[ptr] & 0xFF)
            else:
                mem[ptr] = stdin[inp] if inp < len(stdin) else 0
                inp += 1
        elif op == 5:
            mem[ptr] -= 1
        elif op == 6:
            mem[ptr] += 1
        elif op == 8:
            mem[ptr] = 0
        elif op == 9:
            if reg is None:
                reg = mem[ptr]
            else:
                mem[ptr], reg = reg, None
        elif op == 10:
            out.extend(str(mem[ptr]).encode())
        elif op == 11:
            mem[ptr] = 0
        return 0 <= ptr < len(mem)

    while pc < len(prog):
        used += 1
        if used > steps or len(out) > 1_000_000:
            return None
        op = prog[pc]
        if op == 7:                         # MOO: skip to after the matching moo when the cell is zero
            if not mem[ptr]:
                depth, pc, at = 1, pc + 2, pc       # the instruction right after MOO is skipped as well
                while pc < len(prog) and depth:
                    depth += 1 if prog[pc] == 7 else -1 if prog[pc] == 0 else 0
                    pc += 1
                used += (pc - at) >> 3      # a skip is work too: a long loop skipped in a loop ran for minutes uncounted
                if depth:
                    return None
                continue
        elif op == 0:                       # moo: back to the matching MOO
            depth, pc, at = 1, pc - 2, pc
            while pc >= 0 and depth:
                depth += 1 if prog[pc] == 0 else -1 if prog[pc] == 7 else 0
                pc -= 1
            used += (at - pc) >> 3
            if depth:
                return None
            pc += 1
            continue
        elif op == 3:                       # mOO: run the instruction whose number is in the cell
            if mem[ptr] == 3 or not 0 <= mem[ptr] < 12 or mem[ptr] in (0, 7):
                return None
            if not run(mem[ptr]):
                return None
        elif not run(op):
            return None
        pc += 1
    return bytes(out) if out else None


_ROMAN = {"I": 1, "II": 2, "III": 3, "IV": 4, "V": 5, "VI": 6, "VII": 7, "VIII": 8}


def enigma_settings(text: str):
    """The Enigma settings a prompt states, as the keyword arguments of enigma(), or None when it
    does not state three rotors: rotors in the order written (left to right), their start
    positions and rings, the reflector and the plugboard pairs. Read from lines such as
    'Rotor 1: VI, Initial: A, Ring A' / 'Reflector: UKW B' / 'Plugboard: BQ CR DI'. What is not
    stated keeps enigma()'s default (rings AAA, reflector B, no plugboard) and is listed in `assumed`.
    B-250: an M4 key (a thin Beta or Gamma wheel first, then three rotors; four starts and rings) is read
    too; its reflector letter is then the thin B or C, and enigma() runs it as enigma_m4."""
    rotors, start, rings, assumed = [], [], [], []
    # One blank between words and one line end between lines, and a line's lead-in stays on its line:
    # the patterns below have several optional blanks in a row, and a prompt of half a megabyte of
    # blanks after the word "rotors" kept them busy for minutes (review, 2026-10-08).
    text = re.sub(r" ?\n[ \n]*", "\n", re.sub(r"[ \t\f\v\r]+", " ", str(text)))
    # B-250: an M4 key names a thin wheel (Beta or Gamma) first and four wheels in all.
    for m in re.finditer(r"(?im)^[^\w\n]*rotor\s*\d*\s*[:=-]?\s*(VIII|VII|VI|IV|V|III|II|I|beta|gamma)\b(.*)$", text):
        rotors.append(m.group(1).upper() if m.group(1).upper() not in THIN_ROTORS else m.group(1).capitalize())
        rest = m.group(2)
        pos = re.search(r"(?i)\b(?:initial|start(?:ing)?|position|pos|message key|ground)\w*\s*(?:value|setting|position)?\s*[:=]?\s*([A-Za-z]|\d{1,2})\b", rest)
        ring = re.search(r"(?i)\bring\w*\s*(?:setting)?\s*[:=]?\s*([A-Za-z]|\d{1,2})\b", rest)
        start.append(pos.group(1) if pos else None)
        rings.append(ring.group(1) if ring else None)
    def _thin(r):
        return str(r).upper() in THIN_ROTORS

    m4 = len(rotors) == 4 and _thin(rotors[0]) and not any(_thin(r) for r in rotors[1:])
    if not m4 and (len(rotors) != 3 or any(_thin(r) for r in rotors)):
        m = re.search(r"(?i)\brotors?\s*(?:order)?\s*[:=]\s*((?:VIII|VII|VI|IV|V|III|II|I)(?:[\s,/-]+(?:VIII|VII|VI|IV|V|III|II|I)){2})\b", text)
        # B-250: 'Rotors: Beta II IV I' (thin wheel first, three more) is an M4.
        m4m = re.search(r"(?i)\b(?:rotors?|wheels?|walzen(?:lage)?)\s*(?:order)?\s*[:=]\s*((?:beta|gamma)(?:[\s,/-]+(?:VIII|VII|VI|IV|V|III|II|I)){3})\b",
                        text)
        if m4m:
            names = re.findall(r"(?i)beta|gamma|VIII|VII|VI|IV|V|III|II|I", m4m.group(1))
            rotors = [names[0].capitalize()] + [n.upper() for n in names[1:]]
            m4 = True
            start, rings = [None] * 4, [None] * 4
        elif not m:
            return None
        else:
            rotors = re.findall(r"VIII|VII|VI|IV|V|III|II|I", m.group(1).upper())
            start, rings = [None] * 3, [None] * 3
    width = 4 if m4 else 3
    for label, into in ((r"(?:initial|start(?:ing)?)\s*(?:positions?|values?|settings?)?|positions?|message key|grundstellung", start),
                        (r"ring\s*(?:settings?|stellung)?|ringstellung", rings)):
        if any(v is None for v in into):
            m = re.search(r"(?im)^[^\w\n]*(?:" + label + r")\s*[:=]\s*([A-Za-z]{%d}|[A-Za-z](?:[\s,/-]+[A-Za-z]){%d}|"
                          r"\d{1,2}(?:[\s,/-]+\d{1,2}){%d})\s*$" % (width, width - 1, width - 1), text)
            if m:
                into[:] = re.findall(r"[A-Za-z]|\d{1,2}", m.group(1))

    def conv(vals, name):
        if any(v is None for v in vals):
            assumed.append(name + "=" + "A" * width)
            return "A" * width
        return "".join(chr(64 + int(v)) if str(v).isdigit() and 1 <= int(v) <= 26 else str(v).upper() for v in vals)

    ref = re.search(r"(?i)\b(?:reflector|ukw|umkehrwalze)\s*[:=-]?\s*(?:ukw[\s-]*)?([BC])\b", text)
    if not ref:
        assumed.append("reflector=B")
    plug = re.search(r"(?im)^[^\w\n]*(?:plug\s*board|plugs?|stecker\w*)\s*[:=-]?\s*((?:[A-Za-z]{2}(?:[\s,/-]+|$)){1,13})", text)
    pairs = " ".join(re.findall(r"[A-Za-z]{2}", plug.group(1).upper())) if plug else ""
    if not plug:
        assumed.append("plugboard=none")
    return {"rotors": tuple(rotors), "reflector": ref.group(1).upper() if ref else "B", "rings": conv(rings, "rings"),
            "start": conv(start, "start"), "plugboard": pairs, "assumed": assumed}


def brainfuck_encode(data: bytes) -> str:
    """A simple Brainfuck program that prints `data` (for tests)."""
    out, cur = [], 0
    for b in data:
        d = b - cur
        out.append(("+" * d if d >= 0 else "-" * -d) + ".")
        cur = b
    return "".join(out)


# ---------------------------------------------------------------------------- known plaintext

def _pairs(cipher: str, plain: str):
    """(cipher letter, plain letter) positions for a cipher that keeps every character that is
    not a letter in place, or None when the two texts do not line up that way."""
    if len(cipher) < len(plain):
        return None
    out = []
    for c, p in zip(cipher, plain):
        if p.isascii() and p.isalpha():
            if not (c.isascii() and c.isalpha()):
                return None
            out.append((ord(c.lower()) - 97, ord(p.lower()) - 97))
        elif c != p:
            return None
    return out


def crib_caesar(cipher: str, plain: str):
    """The shift n with caesar(cipher, -n) == plain over the crib, or None."""
    pairs = _pairs(cipher, plain)
    if not pairs:
        return None
    n = (pairs[0][0] - pairs[0][1]) % 26
    return n if all((c - p) % 26 == n for c, p in pairs) else None


def crib_affine(cipher: str, plain: str):
    """(a, b) with c = a*p + b over the crib, or None. Needs two different plain letters whose
    difference is coprime with 26, which any sentence has."""
    pairs = _pairs(cipher, plain)
    if not pairs or len({p for _, p in pairs}) < 2:
        return None
    for a in (x for x in range(1, 26) if math.gcd(x, 26) == 1):
        b = (pairs[0][0] - a * pairs[0][1]) % 26
        if all((a * p + b) % 26 == c for c, p in pairs):
            return a, b
    return None


def crib_substitution(cipher: str, plain: str):
    """{cipher letter: plain letter} for a monoalphabetic substitution that maps the crib, or None
    when the texts do not line up or the letters are not one-to-one. Only the letters the crib
    holds are in it: a cipher letter outside it is not known, and no rule here fills it in."""
    pairs = _pairs(cipher, plain)
    if not pairs:
        return None
    fwd, back = {}, {}
    for c, p in pairs:
        if fwd.setdefault(c, p) != p or back.setdefault(p, c) != c:
            return None
    return {chr(c + 97): chr(p + 97) for c, p in fwd.items()}


def complete_keyword_alphabet(table: dict):
    """A full table from a partial one when the cipher alphabet is a keyword alphabet (keyword,
    then the unused letters in order) or any alphabet that leaves exactly one way to place the
    missing letters in ascending runs. Returns the full {cipher: plain} dict, or None when the
    partial table does not pin it. (26 known pairs are returned as they are.)"""
    if len(table) == 26:
        return dict(table)
    inv = {p: c for c, p in table.items()}          # plain -> cipher
    missing_plain = [p for p in A if p not in inv]
    missing_cipher = [c for c in A if c not in table]
    if len(missing_plain) != len(missing_cipher) or len(missing_plain) > 8:
        return None
    fits = []
    for perm in itertools.permutations(missing_cipher):
        full = dict(inv)
        full.update(zip(missing_plain, perm))
        alphabet = "".join(full[p] for p in A)
        # a keyword alphabet: after the keyword, the rest ascends. Find the shortest keyword.
        for k in range(0, 26):
            tail = alphabet[k:]
            if list(tail) == sorted(tail) and keyword_alphabet(alphabet[:k]) == alphabet:
                fits.append((k, alphabet))
                break
    if not fits:
        return None
    best = min(k for k, _ in fits)
    winners = {a for k, a in fits if k == best}
    if len(winners) != 1 or best > 14:
        return None
    alphabet = winners.pop()
    return {c: p for p, c in zip(A, alphabet)}


def _period(stream: list, low: int, high: int, cover: int):
    """The shortest period (low..high) the stream of (index, value) pairs is consistent with, when
    every residue is seen at least `cover` times: (period, key values), or None."""
    for n in range(low, high + 1):
        key, seen, ok = [None] * n, [0] * n, True
        for i, v in stream:
            r = i % n
            if key[r] is None:
                key[r] = v
            elif key[r] != v:
                ok = False
                break
            seen[r] += 1
        if ok and min(seen) >= cover:
            return n, key
    return None


def crib_vigenere(cipher: str, plain: str, max_period: int = 26, cover: int = 2):
    """A periodic key that turns the cipher text into the crib: (kind, key, every) or None.
    kind is vigenere or beaufort (a variant beaufort is a vigenere with the inverse key, and is
    reported as that); `every` says the key advanced on characters that are not letters. The key's period must be at least 2 (one is a caesar shift or an affine cipher) and
    every key letter must be confirmed by `cover` letters of the crib, so that the key is known,
    not extrapolated."""
    pairs = _pairs(cipher, plain)
    if not pairs:
        return None
    letter_at = [i for i, p in enumerate(plain) if p.isascii() and p.isalpha()]
    for kind in ("vigenere", "beaufort"):
        if kind == "vigenere":
            values = [(c - p) % 26 for c, p in pairs]
        else:
            values = [(c + p) % 26 for c, p in pairs]
        for every in (False, True):
            index = letter_at if every else range(len(values))
            got = _period(list(zip(index, values)), 2, max_period, cover)
            if got:
                return kind, "".join(chr(97 + v) for v in got[1]), every
    return None


def crib_autokey(cipher: str, plain: str, max_primer: int = 24, confirm: int = 20):
    """The primer of an autokey cipher that maps onto the crib, or None. Past the primer the key
    is the plain text itself, and `confirm` letters must agree with that."""
    pairs = _pairs(cipher, plain)
    if not pairs:
        return None
    ks = [(c - p) % 26 for c, p in pairs]
    ps = [p for _, p in pairs]
    for n in range(1, max_primer + 1):
        if len(ks) - n >= confirm and all(ks[i] == ps[i - n] for i in range(n, len(ks))):
            return "".join(chr(97 + v) for v in ks[:n])
    return None


def crib_xor(cipher: bytes, plain: bytes, max_period: int = 32, cover: int = 2):
    """The repeating key (bytes) with xor_key(cipher, key) starting with the crib, or None. A key
    of one byte is returned too (period 1)."""
    if len(cipher) < len(plain) or not plain:
        return None
    stream = [(i, c ^ p) for i, (c, p) in enumerate(zip(cipher, plain))]
    got = _period(stream, 1, max_period, cover)
    return bytes(got[1]) if got else None


def crib_railfence(cipher: str, plain: str, max_rails: int = 16, contains: bool = False, fold: bool = False):
    """(rails, offset) with railfence_decrypt(cipher, rails, offset) starting with the crib; None
    when no setting or more than one reading gives it.

    contains=True takes a crib anywhere in the reading (a flag wrapper in the middle of a sentence:
    'Enjoy ... inside: spooky{...}'), fold=True compares without case. A crib in the middle is often
    held by more than one setting (another start offset scrambles only the ends of the text): then
    this is None too, and railfence_holding lists them all."""
    if not contains:
        if not plain:
            return None
        want = plain.lower() if fold else plain
        hits = {}
        for rails in range(2, min(max_rails, max(2, len(cipher) - 1)) + 1):
            for offset in range(2 * (rails - 1)):
                text = railfence_decrypt(cipher, rails, offset)
                if (text.lower() if fold else text).startswith(want):
                    hits.setdefault(text, (rails, offset))
        return next(iter(hits.values())) if len(hits) == 1 else None
    got = railfence_holding(cipher, plain, max_rails, fold)
    return got[0][:2] if len(got) == 1 else None


def railfence_holding(cipher: str, plain: str, max_rails: int = 16, fold: bool = False) -> list:
    """[(rails, offset, reading)] of every distinct rail fence reading that holds the crib anywhere,
    best quadgram fitness first (B-125). A rail fence only moves characters, so a cipher text that
    lacks a character of the crib gives [] at once."""
    if not plain:
        return []
    want = plain.lower() if fold else plain
    if not holds_crib(cipher.lower() if fold else cipher, want):
        return []
    hits = {}
    for rails in range(2, min(max_rails, max(2, len(cipher) - 1)) + 1):
        for offset in range(2 * (rails - 1)):
            text = railfence_decrypt(cipher, rails, offset)
            if want in (text.lower() if fold else text):
                hits.setdefault(text, (rails, offset))
    return sorted(((r, o, t) for t, (r, o) in hits.items()), key=lambda x: (-fitness(x[2]), x[0], x[1]))


RAIL_CONTAINS_MIN = 5           # crack() asks a rail fence for a crib anywhere only from this many characters
RAIL_HOLDERS_MAX = 4            # ... and reports its readings only when at most this many settings hold it


COLUMNAR_MAX = 21               # columns crib_columnar searches (it needs four known characters a column)


def crib_columnar(cipher: str, plain: str, max_columns: int = COLUMNAR_MAX):
    """The column order (a tuple of column indexes in read-out order) of a columnar transposition
    whose plain text starts with the crib, or None. The plain text's columns are known wherever
    the crib reaches, and each is matched against the cipher text where it must begin. Every
    number of columns that leaves four known characters per column is tried, and all the orders
    that fit must give one and the same reading."""
    n_text = len(cipher)
    readings = {}
    for n in range(2, min(max_columns, n_text // 2) + 1):
        full, extra = divmod(n_text, n)
        sizes = [full + (c < extra) for c in range(n)]
        known = [plain[c::n] for c in range(n)]
        if min(map(len, known)) < 4:
            break
        found = []

        def walk(at, used, order):
            if len(found) > 2:
                return
            if len(order) == n:
                found.append(tuple(order))
                return
            for c in range(n):
                if c in used:
                    continue
                k = min(len(known[c]), sizes[c])
                if cipher[at:at + k] == known[c][:k]:
                    walk(at + sizes[c], used | {c}, order + [c])

        walk(0, frozenset(), [])
        for order in found:
            readings.setdefault(columnar_decrypt(cipher, _ranks(order)), order)
        if len(readings) > 1:
            return None
    return next(iter(readings.values())) if len(readings) == 1 else None


def crib_block_reverse(cipher: str, plain: str, max_size: int = 64):
    """The block size with block_reverse(cipher, size) starting with the crib (2 and more; the
    whole text reversed is a plain reversal and is not reported), or None."""
    hits = [n for n in range(2, min(max_size, len(cipher) - 1) + 1) if block_reverse(cipher, n).startswith(plain)]
    return hits[0] if len(hits) == 1 else None


# ---------------------------------------------------------------------------- Day 19 build (W1, W2, W3)
# Transpositions the crib reads with no key to search for, or with a key the crib itself spells: a
# scytale counted by its rows, a faro shuffle, a redefence (a rail fence whose rails are read in
# another order), and route reads of a grid (spirals and snakes). Every one of them reports a reading
# only when exactly one text of its family starts with the crib; when several names give that one text,
# the name is agree:<name>|<name>..., a step that reads another text (a Mastery record of another
# length) only where all of them give the same characters. Each is asked only by crib_keys, and only for
# a cipher text that holds every character of the crib (a transposition moves characters, it changes
# none), so a blob of another kind pays one Counter.

SCYTALE_ROWS = range(2, 13)     # rows of a scytale counted by rows: its columns are ceil(len / rows)
REDEF_RAILS = range(2, 9)       # rails of a redefence
ROUTE_WIDTHS = range(2, 21)     # the row width of a grid read by a route
ROUTE_KINDS = ("spiral-cw-tl", "spiral-ccw-tr", "spiral-ccw-bl", "spiral-cw-br",
               "spiral-ccw-tl", "spiral-cw-tr", "spiral-cw-bl", "spiral-ccw-br",
               "snake-rows-l", "snake-rows-r", "snake-cols-d", "snake-cols-u")


def holds_crib(cipher: str, plain: str) -> bool:
    """True when every character of `plain` is in `cipher` as many times at least: what a
    transposition of a text that starts with `plain` must hold."""
    return len(cipher) >= len(plain) and not (Counter(plain) - Counter(cipher))


def scytale_rows_decrypt(text: str, rows: int) -> str:
    """A scytale counted by its rows: the text was written in rows of ceil(len / rows) characters and
    read column by column, so the column count follows each text's own length."""
    return scytale_decrypt(text, max(1, -(-len(text) // rows))) if text else text


def crib_scytale(cipher: str, plain: str):
    """([rows], reading) for the one text a scytale of 2 to 12 rows gives that starts with the crib,
    with every row count that gives it; None when none does or two different texts do."""
    readings = {}
    for rows in SCYTALE_ROWS:
        if rows >= len(cipher):
            break
        text = scytale_rows_decrypt(cipher, rows)
        if text.startswith(plain):
            readings.setdefault(text, []).append(rows)
    if len(readings) != 1:
        return None
    (text, rows), = readings.items()
    return rows, text


def faro_decrypt(text: str, way: str) -> str:
    """Undo a perfect shuffle of the text's two halves: `out` kept the first character first (the
    first half is the longer), `in` put the second half's first character first."""
    if way == "out":
        return text[0::2] + text[1::2]
    if way == "in":
        return text[1::2] + text[0::2]
    raise ValueError(way)


def faro_encrypt(text: str, way: str) -> str:
    h = (len(text) + 1) // 2 if way == "out" else len(text) // 2
    a, b = (text[:h], text[h:]) if way == "out" else (text[h:], text[:h])
    return "".join(x + y for x, y in itertools.zip_longest(a, b, fillvalue=""))


def crib_faro(cipher: str, plain: str):
    """The one way ('out' or 'in') whose unshuffled text starts with the crib, or None."""
    hits = {}
    for way in ("out", "in"):
        text = faro_decrypt(cipher, way)
        if text.startswith(plain):
            hits.setdefault(text, way)
    return next(iter(hits.values())) if len(hits) == 1 else None


def _rails(n: int, rails: int) -> list:
    """The positions of each rail of a rail fence of `rails` rails over n characters, in order."""
    rows = _rail_pattern(n, rails, 0)
    out = [[] for _ in range(rails)]
    for i, r in enumerate(rows):
        out[r].append(i)
    return out


def redefence_encrypt(text: str, rails: int, order) -> str:
    pos = _rails(len(text), rails)
    return "".join(text[i] for r in order for i in pos[r])


def redefence_decrypt(text: str, rails: int, order) -> str:
    """A rail fence of `rails` rails (offset 0) whose rails were read out in `order` (rail numbers,
    top rail 0)."""
    pos = _rails(len(text), rails)
    out = [""] * len(text)
    at = 0
    for r in order:
        for i in pos[r]:
            out[i] = text[at]
            at += 1
    return "".join(out)


def crib_redefence(cipher: str, plain: str):
    """[(rails, order)] of the one redefence reading (rails 2 to 8, the rails read in any order but
    their own) that starts with the crib, with every setting that gives it, and the reading; None
    when none does or two texts do. The crib holds the first characters of every rail, so the order
    is walked rail by rail: the next rail must start where its known characters stand."""
    n = len(cipher)
    readings = {}
    for rails in REDEF_RAILS:
        if rails >= n:
            break
        pos = _rails(n, rails)
        known = ["".join(plain[i] for i in p if i < len(plain)) for p in pos]
        if min(map(len, known)) < 2:
            continue
        found = []

        def walk(at, used, order):
            if len(found) > 4:
                return
            if len(order) == rails:
                found.append(tuple(order))
                return
            for r in range(rails):
                if r not in used and cipher.startswith(known[r], at):
                    walk(at + len(pos[r]), used | {r}, order + [r])

        walk(0, frozenset(), [])
        for order in found:
            if order != tuple(range(rails)):        # the rails in their own order: a rail fence, read by crib_railfence
                readings.setdefault(redefence_decrypt(cipher, rails, order), []).append((rails, order))
        if len(readings) > 1:
            return None
    if len(readings) != 1:
        return None
    (text, settings), = readings.items()
    return settings, text


def _spiral(h: int, w: int) -> list:
    """The cells (row, column) of an h x w grid, clockwise from the top left corner, inward."""
    top, bot, left, right, out = 0, h - 1, 0, w - 1, []
    while top <= bot and left <= right:
        out += [(top, c) for c in range(left, right + 1)]
        top += 1
        out += [(r, right) for r in range(top, bot + 1)]
        right -= 1
        if top <= bot:
            out += [(bot, c) for c in range(right, left - 1, -1)]
            bot -= 1
        if left <= right:
            out += [(r, left) for r in range(bot, top - 1, -1)]
            left += 1
    return out


@functools.lru_cache(maxsize=4096)
def route_order(n: int, width: int, kind: str) -> tuple:
    """The positions of a text of n characters, written in rows of `width`, in the order the route
    `kind` reads them (ROUTE_KINDS). The last row may be short: its missing cells are skipped."""
    h = -(-n // width)
    if kind.startswith("spiral-"):
        _, turn, corner = kind.split("-")
        # clockwise from the top left, or (turn and corner of the transposed grid) counterclockwise
        transposed = (turn, corner) in (("ccw", "tl"), ("cw", "tr"), ("cw", "bl"), ("ccw", "br"))
        cells = [(c, r) for r, c in _spiral(width, h)] if transposed else _spiral(h, width)
        flip_c = corner in ("tr", "br")
        flip_r = corner in ("bl", "br")
        cells = [(h - 1 - r if flip_r else r, width - 1 - c if flip_c else c) for r, c in cells]
    elif kind.startswith("snake-rows-"):
        first_left = kind.endswith("-l")
        cells = [(r, c) for r in range(h)
                 for c in (range(width) if (r % 2 == 0) == first_left else range(width - 1, -1, -1))]
    elif kind.startswith("snake-cols-"):
        first_down = kind.endswith("-d")
        cells = [(r, c) for c in range(width)
                 for r in (range(h) if (c % 2 == 0) == first_down else range(h - 1, -1, -1))]
    else:
        raise ValueError(kind)
    return tuple(i for i in (r * width + c for r, c in cells) if i < n)


def route_encrypt(text: str, width: int, kind: str) -> str:
    return "".join(text[i] for i in route_order(len(text), width, kind))


def route_decrypt(text: str, width: int, kind: str) -> str:
    out = [""] * len(text)
    for ch, i in zip(text, route_order(len(text), width, kind)):
        out[i] = ch
    return "".join(out)


def crib_route(cipher: str, plain: str):
    """[(width, kind)] of the one route reading (rows of 2 to 20, the spirals from the four corners
    both ways, the snakes by rows and by columns) that starts with the crib, with every setting that
    gives it, and the reading; None when none does or two texts do."""
    n, k = len(cipher), len(plain)
    readings = {}
    for width in ROUTE_WIDTHS:
        if width >= n:
            break
        for kind in ROUTE_KINDS:
            order = route_order(n, width, kind)
            if all(cipher[j] == plain[i] for j, i in enumerate(order) if i < k):
                readings.setdefault(route_decrypt(cipher, width, kind), []).append((width, kind))
                if len(readings) > 1:
                    return None
    if len(readings) != 1:
        return None
    (text, settings), = readings.items()
    return settings, text


ASCII_LOW, ASCII_SPAN = 32, 95      # printable ASCII, the space to the tilde


def vigascii_decrypt(text: str, shifts) -> str:
    """Vigenere over the 95 printable ASCII characters, the key advancing on every character: each
    character moved back by its shift. None when a character is not printable ASCII."""
    if not shifts or any(not ASCII_LOW <= ord(c) < ASCII_LOW + ASCII_SPAN for c in text):
        return None
    return "".join(chr(ASCII_LOW + (ord(c) - ASCII_LOW - shifts[i % len(shifts)]) % ASCII_SPAN)
                   for i, c in enumerate(text))


def crib_vigascii(cipher: str, plain: str, max_period: int = 32, cover: int = 2):
    """The shifts (a list, period 2 to max_period) of a Vigenere over printable ASCII that turns the
    cipher text into the crib, every shift seen `cover` times; None otherwise. A period of 1 is a
    rotation of the printable characters (rot94, add), which the caller has."""
    if len(cipher) < len(plain) or not plain:
        return None
    if any(not ASCII_LOW <= ord(c) < ASCII_LOW + ASCII_SPAN for c in cipher[:len(plain)] + plain):
        return None
    stream = [(i, (ord(c) - ord(p)) % ASCII_SPAN) for i, (c, p) in enumerate(zip(cipher, plain))]
    got = _period(stream, 2, max_period, cover)
    if not got or len(set(got[1])) < 2:      # one shift throughout is a rotation (rot94, add), not a key
        return None
    return list(got[1])


def _porta_pair(x: int, k: int) -> int:
    """Porta's tableau k (0 to 12) for letter x (0 to 25); the table is its own inverse."""
    return (x + k) % 13 + 13 if x < 13 else (x - 13 - k) % 13


def porta(text: str, key: str, every: bool = False) -> str:
    """The Porta cipher (its own inverse). Key letters pair up: a and b are tableau 0, c and d 1, ...
    The key advances on letters, or on every character with `every`."""
    ks = [(ord(c) - 97) // 2 for c in key.lower() if "a" <= c <= "z"]
    if not ks:
        raise ValueError("the key has no letter")
    out, i = [], 0
    for c in text:
        if c.isascii() and c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr(base + _porta_pair(ord(c) - base, ks[i % len(ks)])))
            i += 1
        else:
            out.append(c)
            i += every
    return "".join(out)


def crib_porta(cipher: str, plain: str, max_period: int = 26, cover: int = 2):
    """(key, every) of a Porta cipher that maps onto the crib (period 1 to max_period, each key letter
    confirmed by `cover` letters), or None. The key is written with the first letter of each pair."""
    pairs = _pairs(cipher, plain)
    if not pairs:
        return None
    ks = []
    for c, p in pairs:
        if (p < 13) == (c < 13):     # Porta always moves a letter to the other half of the alphabet
            return None
        ks.append((c - 13 - p) % 13 if p < 13 else (p - 13 - c) % 13)
    letter_at = [i for i, p in enumerate(plain) if p.isascii() and p.isalpha()]
    for every in (False, True):
        index = letter_at if every else range(len(ks))
        got = _period(list(zip(index, ks)), 1, max_period, cover)
        if got:
            return "".join(chr(97 + 2 * v) for v in got[1]), every
    return None


# ---------------------------------------------------------------------------- Day 20 build (warmups item 1)
# Myszkowski: a keyword with repeated letters. Columns under one letter are read together, row by row,
# left to right; columns under different letters as in a columnar transposition. The key is the rank of
# each column's letter ("tomato" is 3.2.1.0.3.2), so a key learned from the base reads a record of any
# length. The crib holds the first row whole, so the groups are walked as crib_columnar walks columns:
# the next group's columns are the ones whose row-0 characters stand where the group must begin.
# Decimation: every k-th character, cyclically, k moved on to the next number coprime with the length.
# On one text that IS a columnar transposition of k columns (crib_columnar names it by its order, which
# follows len mod k), so it is not searched here: crib_decode's reconcile (_step_names) offers decim:<k>
# where the day's two blobs are read by columnar orders that one decimation explains.

MYSZ_COLUMNS = range(3, 13)     # columns of a Myszkowski key
MYSZ_GROUP = 4                  # columns under one key letter at most
MYSZ_NODES = 20000              # group trials per text: past it nothing is reported (uniqueness unproved)
DECIM_STEPS = range(2, 13)      # the k of a decimation offered by the reconcile


def _mysz_positions(n_text: int, n: int, group) -> list:
    """The positions a group of columns (one key letter) reads: row by row, its columns left to right."""
    return [r + c for r in range(0, n_text, n) for c in group if r + c < n_text]


def _mysz_groups(ranks) -> list:
    return [[c for c in range(len(ranks)) if ranks[c] == rank] for rank in sorted(set(ranks))]


def myszkowski_encrypt(text: str, ranks) -> str:
    n = len(ranks)
    return "".join(text[i] for g in _mysz_groups(ranks) for i in _mysz_positions(len(text), n, g))


def myszkowski_decrypt(text: str, ranks) -> str:
    n, out, at = len(ranks), [""] * len(text), 0
    for g in _mysz_groups(ranks):
        for i in _mysz_positions(len(text), n, g):
            out[i] = text[at]
            at += 1
    return "".join(out)


def crib_myszkowski(cipher: str, plain: str):
    """([ranks], reading) of the one Myszkowski reading (3 to 12 columns, at least two columns under one
    letter, at most MYSZ_GROUP a letter) that starts with the crib, with every key that gives it; None when
    none does, two texts do, or the walk passed MYSZ_NODES trials (then nothing is proved unique)."""
    n_text, k = len(cipher), len(plain)
    readings = {}
    nodes = [0]
    for n in MYSZ_COLUMNS:
        if 2 * n > n_text or n > k:
            break
        found = []

        def walk(at, used, groups):
            if len(found) > 2 or nodes[0] > MYSZ_NODES:
                return
            if len(used) == n:
                found.append(tuple(groups))
                return
            for c in range(n):
                if c not in used and plain[c] == cipher[at]:
                    grow(at, used, groups, (c,))

        def grow(at, used, groups, group):
            nodes[0] += 1
            if nodes[0] > MYSZ_NODES:
                return
            pos = _mysz_positions(n_text, n, group)
            if all(cipher[at + j] == plain[p] for j, p in enumerate(pos) if p < k):
                walk(at + len(pos), used | set(group), groups + [group])
            nxt = at + len(group)
            if len(group) < MYSZ_GROUP and nxt < n_text:
                for c in range(group[-1] + 1, n):
                    if c not in used and plain[c] == cipher[nxt]:
                        grow(at, used, groups, group + (c,))

        walk(0, frozenset(), [])
        if nodes[0] > MYSZ_NODES:
            return None
        for groups in found:
            if max(map(len, groups)) < 2 or len(groups) < 2:   # no letter repeated: a columnar transposition,
                continue                                        # crib_columnar's; one letter only: the text itself
            ranks = [0] * n
            for rank, g in enumerate(groups):
                for c in g:
                    ranks[c] = rank
            text = myszkowski_decrypt(cipher, ranks)
            if text.startswith(plain):
                readings.setdefault(text, []).append(tuple(ranks))
        if len(readings) > 1:
            return None
    if len(readings) != 1:
        return None
    (text, keys), = readings.items()
    return keys, text


# Double columnar: a columnar transposition of n1 columns, then one of n2 columns over its result. No key is
# searched as such. The inner columns are placed slot by slot (as crib_columnar walks them), and every crib
# character of a placed column stands at a known place of the intermediate text, so it names the row of an
# outer column it must be read at; each outer column keeps only the starts in the cipher text where every such
# character stands. A wrong inner column leaves some outer column no start within a few characters, so the
# walk stays narrow; it is bounded by DCOL_NODES all the same (past it nothing is reported).
DCOL_COLUMNS = range(2, 11)     # columns of each of the two keys
DCOL_NODES = 30000              # inner column trials per text at most
DCOL_FOUND = 64                 # key pairs at most per pair of widths before the text is given up
DCOL_NAMES = 8                  # key pairs that may name the one reading (an agree step of all of them)


def double_columnar_decrypt(text: str, order1, order2) -> str:
    """Undo columnar(order2) over columnar(order1): each order lists the columns in read-out order."""
    return columnar_decrypt(columnar_decrypt(text, _ranks(order2)), _ranks(order1))


def _column_starts(n_text: int, n: int) -> list:
    """Every place a column of a columnar transposition of n columns may start in the cipher text."""
    full, extra = divmod(n_text, n)
    return sorted({t * full + m for t in range(n) for m in range(max(0, t - (n - extra)), min(t, extra) + 1)})


def crib_double_columnar(cipher: str, plain: str):
    """([(order1, order2)], reading) of the one double columnar reading (2 to 10 columns each) that starts
    with the crib, with every key pair that gives it; None when none does, two texts do, more than
    DCOL_NAMES key pairs give it, or the walk passed DCOL_NODES trials."""
    n_text, k = len(cipher), len(plain)
    readings = {}
    nodes = [0]
    for n1 in DCOL_COLUMNS:
        if 2 * n1 > n_text:
            break
        f1, e1 = divmod(n_text, n1)
        size1 = [f1 + (c < e1) for c in range(n1)]
        for n2 in DCOL_COLUMNS:
            if 2 * n2 > n_text:
                break
            f2, e2 = divmod(n_text, n2)
            size2 = [f2 + (c < e2) for c in range(n2)]
            starts = _column_starts(n_text, n2)
            first = {c2: tuple(s for s in starts if s + size2[c2] <= n_text) for c2 in range(n2)}
            found = []

            def outer(cand):
                def walk(at, used, order):
                    if len(found) > DCOL_FOUND:
                        return
                    if len(order) == n2:
                        found.append((tuple(order1), tuple(order)))
                        return
                    for c2 in range(n2):
                        if c2 not in used and at in cand[c2]:
                            walk(at + size2[c2], used | {c2}, order + [c2])
                walk(0, frozenset(), [])

            order1 = []

            def place(at, used, cand):
                if len(found) > DCOL_FOUND or nodes[0] > DCOL_NODES:
                    return
                if len(order1) == n1:
                    outer(cand)
                    return
                for c1 in range(n1):
                    if c1 in used:
                        continue
                    nodes[0] += 1
                    touched = {}
                    for r in range(size1[c1]):
                        p = c1 + n1 * r
                        if p >= k:
                            break
                        i = at + r
                        touched.setdefault(i % n2, []).append((i // n2, plain[p]))
                    new = dict(cand)
                    for c2, cons in touched.items():
                        keep = tuple(s for s in new[c2] if all(cipher[s + r2] == ch for r2, ch in cons))
                        if not keep:
                            break
                        new[c2] = keep
                    else:
                        order1.append(c1)
                        place(at + size1[c1], used | {c1}, new)
                        order1.pop()

            place(0, frozenset(), first)
            if nodes[0] > DCOL_NODES or len(found) > DCOL_FOUND:
                return None
            for o1, o2 in found:
                text = double_columnar_decrypt(cipher, o1, o2)
                if text.startswith(plain):
                    readings.setdefault(text, []).append((o1, o2))
            if len(readings) > 1:
                return None
    if len(readings) != 1:
        return None
    (text, keys), = readings.items()
    return (keys, text) if len(keys) <= DCOL_NAMES else None


def decimation_step(n: int, k: int) -> int:
    """The step a decimation of k uses on a text of n characters: k, moved on until it is coprime with n."""
    while n > 1 and math.gcd(k, n) != 1:
        k += 1
    return k


def decimation_decrypt(text: str, k: int) -> str:
    """Undo a decimation: the cipher text's i-th character is the plain text's (i * step) mod n-th."""
    n = len(text)
    if n < 2:
        return text
    step, out = decimation_step(n, k), [""] * n
    for i, ch in enumerate(text):
        out[(i * step) % n] = ch
    return "".join(out)


def _named_agree(names: list) -> str:
    """One step name for a reading several settings give: the name itself, or agree:<a>|<b>..."""
    return names[0] if len(names) == 1 else "agree:" + "|".join(names)


def crib_transpositions(cipher: str, plain: str) -> list:
    """[(name, reading)] of the Day 19 transposition readers (scytale by rows, faro, redefence,
    routes), each one reading or nothing; [] at once for a cipher text that does not hold every
    character of the crib."""
    out = []
    if not plain or not holds_crib(cipher, plain):
        return out
    got = crib_scytale(cipher, plain)
    if got:
        out.append((_named_agree(["scytale:%d" % r for r in got[0]]), got[1]))
    way = crib_faro(cipher, plain)
    if way:
        out.append(("faro:" + way, faro_decrypt(cipher, way)))
    got = crib_redefence(cipher, plain)
    if got:
        out.append((_named_agree(["redef:%d.%s" % (r, ".".join(map(str, o))) for r, o in got[0]]), got[1]))
    got = crib_route(cipher, plain)
    if got:
        out.append((_named_agree(["route:%s.%d" % (kind, w) for w, kind in got[0]]), got[1]))
    got = crib_myszkowski(cipher, plain)
    if got:
        out.append((_named_agree(["mysz:" + ".".join(map(str, r)) for r in got[0]]), got[1]))
    got = None if out else crib_double_columnar(cipher, plain)
    if got:
        out.append((_named_agree(["dcol:%s/%s" % (".".join(map(str, o1)), ".".join(map(str, o2)))
                                  for o1, o2 in got[0]]), got[1]))
    return out


# One name per keyed step: "<cipher>:<key>". decode_named() turns the name back into the decoder,
# so a key learned from one text (a day's saved blob) reads another (a Mastery record).
LETTER_CIPHERS = ("affine", "vigenere", "beaufort", "variant", "autokey", "subst", "kbdw",
                  "porta", "kwfill")                   # digits pass through
MOVING = ("rail", "columnar", "blockrev", "split",
          "scytale", "faro", "redef", "route", "agree",
          "mysz", "decim", "dcol")                     # characters only move: every digit is where the key puts it
FIXED = ("kbd",)                                       # a fixed table over letters, digits and marks alike
EACH = ("vigascii",)                                   # one printable character for one, digits included


def crib_keys(cipher: str, plain: str, late: bool = True) -> list:
    """Every keyed reading of `cipher` (text) that starts with `plain`: [(name, decoded text)].
    The name carries the key. Caesar shifts, atbash, rot47 and a whole reversal are not
    reported: the caller has them as keyless steps. An affine cipher is reported only when it is
    neither a shift nor atbash, a substitution only when it is not affine.

    `late=False` leaves out the Day 19 readers (crib_late), for a caller that asks them on its own
    only once no text of its gave a reading: crib_decode.py's keyed stage, which must not get slower
    on a blob an earlier reader reads (the Day 18 rail fence)."""
    out = []
    if len(cipher) < len(plain) or not plain:
        return out
    low_plain = plain.lower()

    def add(name, text):
        if text is not None and text[:len(plain)].lower() == low_plain and all(text != t for _, t in out):
            out.append((name, text))

    aff = crib_affine(cipher, plain)
    shift = aff is not None and aff[0] == 1
    if aff and not shift and aff != (25, 25):
        add("affine:%d.%d" % aff, affine_decrypt(cipher, *aff))
    if not aff:
        vig = crib_vigenere(cipher, plain)
        if vig:
            kind, key, every = vig
            add("%s:%s%s" % (kind, key, "+" if every else ""), vigenere_decrypt(cipher, key, kind, every))
        auto = None if vig else crib_autokey(cipher, plain)
        if auto:
            add("autokey:" + auto, autokey_decrypt(cipher, auto))
        # Day 19 build (W2): Porta, a reciprocal cipher of thirteen tableaux, its key read off the crib.
        pk = None if (vig or auto) else crib_porta(cipher, plain)
        if pk:
            add("porta:%s%s" % (pk[0], "+" if pk[1] else ""), porta(cipher, pk[0], pk[1]))
        table = None if (vig or auto or pk) else crib_substitution(cipher, plain)
        if table:
            for n in (1, -1, 2, -2):
                if keyboard_wrap(cipher, -n)[:len(plain)] == plain:
                    add("kbdw:%d" % n, keyboard_wrap(cipher, -n))
                    table = None
                    break
        if table:
            add("subst:" + "".join(table.get(c, "?") for c in A), _subst_strict(cipher, table))
            if _subst_strict(cipher, table) is None:
                # Day 19 build (W3): a letter the sentence lacks (f, j, q, y, z) is not in the table. When the
                # known pairs leave exactly one keyword alphabet (complete_keyword_alphabet), its reading is
                # offered under its own step kind, kwfill: the caller never answers it plain on this word.
                full = complete_keyword_alphabet(table)
                if full:
                    add("kwfill:" + "".join(full[c] for c in A), substitute(cipher, full))
    for right in (True, False):
        moved = None if out else keyboard_shift(cipher, not right)     # a shift to the right is undone to the left
        if moved is not None:
            add("kbd:" + ("right" if right else "left"), moved)
    if not out:
        rail = crib_railfence(cipher, plain)
        if rail:
            add("rail:%d.%d" % rail, railfence_decrypt(cipher, *rail))
        order = crib_columnar(cipher, plain)
        if order:
            add("columnar:" + ".".join(map(str, order)), columnar_decrypt(cipher, _ranks(order)))
        size = crib_block_reverse(cipher, plain)
        if size:
            add("blockrev:%d" % size, block_reverse(cipher, size))
        for parts in (2, 3, 4):
            if len(cipher) > parts * 2:
                text = interleave_split(cipher, parts)
                if text.startswith(plain) and not any(n.startswith(("rail", "columnar")) for n, _ in out):
                    add("split:%d" % parts, text)
    if not out and late:
        # Asked only when nothing above read the text, so no earlier reading changes its name.
        for name, text in crib_late(cipher, plain):
            add(name, text)
    return out


def crib_late(cipher: str, plain: str) -> list:
    """The Day 19 readers, for a text crib_keys' others do not read: the transpositions (W1: a scytale
    counted by rows, a faro shuffle, a redefence, a route over a grid) and, when none of them reads it, a
    Vigenere over the 95 printable characters (W2, digits and marks moved too). [(name, reading)]."""
    out = crib_transpositions(cipher, plain)
    if not out:
        shifts = crib_vigascii(cipher, plain)
        text = vigascii_decrypt(cipher, shifts) if shifts else None
        if text is not None and text.startswith(plain):
            out.append(("vigascii:" + bytes(shifts).hex(), text))
    return out


def _kind_of(name: str) -> str:
    return name.partition(":")[0]


def _ranks(order) -> list:
    """The key (rank of each column) for a read-out order of columns."""
    ranks = [0] * len(order)
    for rank, c in enumerate(order):
        ranks[c] = rank
    return ranks


def _subst_strict(text: str, table: dict):
    """substitute(), or None when the text holds a letter the table does not: what that letter
    stands for is not known."""
    if any(c.isascii() and c.isalpha() and c.lower() not in table for c in text):
        return None
    return substitute(text, table)


def decode_named(name: str):
    """The decoder (text -> text or None) of a keyed step named by crib_keys, or None for a name
    that is not one."""
    kind, _, key = name.partition(":")
    try:
        if kind == "affine":
            a, b = map(int, key.split("."))
            return lambda t: affine_decrypt(t, a, b)
        if kind in VIGENERE_KINDS:
            every = key.endswith("+")
            k = key.rstrip("+")
            return lambda t: vigenere_decrypt(t, k, kind, every) if k else None
        if kind == "autokey":
            return lambda t: autokey_decrypt(t, key)
        if kind == "kbd":
            return lambda t: keyboard_shift(t, key != "right")
        if kind == "kbdw":
            n = int(key)
            return lambda t: keyboard_wrap(t, -n)
        if kind == "subst" and len(key) == 26:
            table = {c: p for c, p in zip(A, key) if p != "?"}
            return lambda t: _subst_strict(t, table)
        if kind == "rail":
            rails, offset = map(int, key.split("."))
            return lambda t: railfence_decrypt(t, rails, offset)
        if kind == "columnar":
            ranks = _ranks([int(x) for x in key.split(".")])
            return lambda t: columnar_decrypt(t, ranks)
        if kind == "blockrev":
            size = int(key)
            return lambda t: block_reverse(t, size)
        if kind == "split":
            parts = int(key)
            return lambda t: interleave_split(t, parts)
        # Day 19 build (W1, W2, W3)
        if kind == "scytale":
            rows = int(key)
            if rows < 2:
                return None
            return lambda t: scytale_rows_decrypt(t, rows)
        if kind == "faro" and key in ("out", "in"):
            return lambda t: faro_decrypt(t, key)
        if kind == "redef":
            nums = [int(x) for x in key.split(".")]
            rails, order = nums[0], tuple(nums[1:])
            if rails < 2 or sorted(order) != list(range(rails)):
                return None
            return lambda t: redefence_decrypt(t, rails, order)
        if kind == "route":
            how, _, width = key.rpartition(".")
            w = int(width)
            if how not in ROUTE_KINDS or w < 2:
                return None
            return lambda t: route_decrypt(t, w, how)
        # Day 20 build (warmups item 1)
        if kind == "mysz":
            ranks = [int(x) for x in key.split(".")]
            if (not 2 <= len(ranks) or sorted(set(ranks)) != list(range(len(set(ranks))))
                    or len(set(ranks)) in (1, len(ranks))):
                return None
            return lambda t: myszkowski_decrypt(t, ranks)
        if kind == "dcol":
            a, _, b = key.partition("/")
            o1, o2 = [int(x) for x in a.split(".")], [int(x) for x in b.split(".")]
            if sorted(o1) != list(range(len(o1))) or sorted(o2) != list(range(len(o2))) or len(o1) < 2 or len(o2) < 2:
                return None
            return lambda t: double_columnar_decrypt(t, o1, o2)
        if kind == "decim":
            k = int(key)
            if k < 2:
                return None
            return lambda t: decimation_decrypt(t, k)
        if kind == "agree":
            fns = [decode_named(part) for part in key.split("|")]
            if len(fns) < 2 or any(f is None or _kind_of(part) not in MOVING or _kind_of(part) == "agree"
                                   for f, part in zip(fns, key.split("|"))):
                return None

            def agreed(t):
                got = {f(t) for f in fns}
                return got.pop() if len(got) == 1 else None
            return agreed
        if kind == "porta":
            every = key.endswith("+")
            k = key.rstrip("+")
            return (lambda t: porta(t, k, every)) if k.isalpha() else None
        if kind == "kwfill" and len(key) == 26 and sorted(key) == list(A):
            table = dict(zip(A, key))
            return lambda t: substitute(t, table)
        if kind == "vigascii":
            shifts = list(bytes.fromhex(key))
            if not shifts or any(x >= ASCII_SPAN for x in shifts):
                return None
            return lambda t: vigascii_decrypt(t, shifts)
    except (ValueError, IndexError):
        return None
    return None


# ---------------------------------------------------------------------------- more fractionation
#
# Ciphers that recur in CTF crypto rounds but were missing: trifid (a 3x3x3 bifid), the nihilist
# (a keyed Polybius square plus a repeating additive key), the four-square digraph cipher, and the
# Hill cipher (a matrix over Z/26). Each is encrypt+decrypt; where a known-plaintext break is clean
# (Hill: linear algebra; nihilist additive key: subtraction; turning grille: a small orbit search)
# it is exposed as a crib_* helper and, for Hill and the grille, wired into crack() so a crib
# surfaces it automatically. Everything is plain Python and lossy readings say so (a 5x5 square has
# no j; trifid's 27th cell is a padding mark).

TRIFID_PAD = "."                 # the 27th symbol of a trifid square (26 letters + one mark)


def trifid_square(key: str = "", pad: str = TRIFID_PAD) -> str:
    """The 27 symbols of a trifid cube, row by row: the keyword's letters once each, then the rest
    of the alphabet, then the padding mark. Unlike the 5x5 square, j keeps its own cell."""
    alphabet = A + pad
    seen = []
    for c in (key.lower() + alphabet):
        if c in alphabet and c not in seen:
            seen.append(c)
    return "".join(seen)


def trifid_encrypt(text: str, key: str = "", period: int = 0, pad: str = TRIFID_PAD) -> str:
    """Trifid: each symbol becomes three base-3 coordinates; within each period block the three
    coordinate rows are read off and re-grouped into triples. period=0 is the whole message."""
    sq = trifid_square(key, pad)
    t = [c for c in text.lower() if c in sq]
    period = period or len(t) or 1
    out = []
    for s in range(0, len(t), period):
        block = t[s:s + period]
        idx = [sq.index(c) for c in block]
        rows = [i // 9 for i in idx] + [(i // 3) % 3 for i in idx] + [i % 3 for i in idx]
        out.append("".join(sq[rows[i] * 9 + rows[i + 1] * 3 + rows[i + 2]] for i in range(0, len(rows), 3)))
    return "".join(out)


def trifid_decrypt(text: str, key: str = "", period: int = 0, pad: str = TRIFID_PAD) -> str:
    sq = trifid_square(key, pad)
    t = [c for c in text.lower() if c in sq]
    period = period or len(t) or 1
    out = []
    for s in range(0, len(t), period):
        block = t[s:s + period]
        digits = []
        for c in block:
            i = sq.index(c)
            digits += [i // 9, (i // 3) % 3, i % 3]
        L = len(block)
        a, b, d = digits[:L], digits[L:2 * L], digits[2 * L:]
        out.append("".join(sq[a[i] * 9 + b[i] * 3 + d[i]] for i in range(L)))
    return "".join(out)


def _nihilist_square(square_key: str):
    sq = polybius_square(square_key, 5)
    pos = {c: (i // 5 + 1, i % 5 + 1) for i, c in enumerate(sq)}
    return sq, pos


def nihilist_encrypt(text: str, square_key: str, add_key: str) -> str:
    """Nihilist: plaintext and a repeating additive key are each turned into two-digit Polybius
    numbers (row,col in 1..5) through a keyed 5x5 square; the cipher is their sums, space-joined.
    i and j share a cell. Returns space-separated numbers."""
    _, pos = _nihilist_square(square_key)
    key = [c for c in add_key.lower().replace("j", "i") if c in pos]
    if not key:
        raise ValueError("the additive key has no square letter")
    knums = [pos[c][0] * 10 + pos[c][1] for c in key]
    out, i = [], 0
    for c in text.lower().replace("j", "i"):
        if c not in pos:
            continue
        pn = pos[c][0] * 10 + pos[c][1]
        out.append(str(pn + knums[i % len(knums)]))
        i += 1
    return " ".join(out)


def nihilist_decrypt(cipher, square_key: str, add_key: str):
    """Undo a nihilist cipher: subtract the additive-key numbers and read each two-digit result in
    the square. `cipher` is a string or iterable of the sum numbers. None when a result is not a
    valid (row,col) pair in 1..5 (wrong key/square)."""
    sq, pos = _nihilist_square(square_key)
    key = [c for c in add_key.lower().replace("j", "i") if c in pos]
    if not key:
        raise ValueError("the additive key has no square letter")
    knums = [pos[c][0] * 10 + pos[c][1] for c in key]
    nums = re.findall(r"\d+", cipher) if isinstance(cipher, str) else [str(x) for x in cipher]
    out = []
    for i, token in enumerate(nums):
        v = int(token) - knums[i % len(knums)]
        r, col = divmod(v, 10)
        if not (1 <= r <= 5 and 1 <= col <= 5):
            return None
        out.append(sq[(r - 1) * 5 + (col - 1)])
    return "".join(out)


def crib_nihilist(cipher, plain: str, square_key: str = ""):
    """The additive key letters that turn `cipher` (nihilist numbers) into `plain` under the given
    square, or None. A proof over the crib letters: cipher_number - plain_number is the key number,
    read back in the square. The returned key is as long as the crib (one period if the crib is a
    whole key's worth)."""
    sq, pos = _nihilist_square(square_key)
    nums = re.findall(r"\d+", cipher) if isinstance(cipher, str) else [str(x) for x in cipher]
    p = [c for c in plain.lower().replace("j", "i") if c in pos]
    if len(nums) < len(p) or not p:
        return None
    key = []
    for i, c in enumerate(p):
        pn = pos[c][0] * 10 + pos[c][1]
        # Ignore zero padding, and refuse tokens that exceed Python's decimal
        # conversion limit instead of leaking its ValueError to the caller.
        token = nums[i].lstrip("0") or "0"
        try:
            kn = int(token) - pn
        except ValueError:
            return None
        r, col = divmod(kn, 10)
        if not (1 <= r <= 5 and 1 <= col <= 5):
            return None
        key.append(sq[(r - 1) * 5 + (col - 1)])
    return "".join(key)


_FS_PLAIN = A.replace("j", "")        # the two plaintext squares: the alphabet in order, no j


def _four_square_squares(key1: str, key2: str):
    return playfair_square(key1), playfair_square(key2)


def four_square_encrypt(text: str, key1: str, key2: str) -> str:
    """Four-square digraph cipher. Two keyed squares (top-right, bottom-left) and two plain squares
    (top-left, bottom-right). i and j share a cell; an odd final letter is padded with x."""
    c1, c2 = _four_square_squares(key1, key2)
    t = letters(text).replace("j", "i")
    if len(t) % 2:
        t += "x"
    out = []
    for i in range(0, len(t), 2):
        a, b = _FS_PLAIN.index(t[i]), _FS_PLAIN.index(t[i + 1])
        ra, ca, rb, cb = a // 5, a % 5, b // 5, b % 5
        out.append(c1[ra * 5 + cb])
        out.append(c2[rb * 5 + ca])
    return "".join(out)


def four_square_decrypt(text: str, key1: str, key2: str) -> str:
    c1, c2 = _four_square_squares(key1, key2)
    t = letters(text).replace("j", "i")
    out = []
    for i in range(0, len(t) - 1, 2):
        a, b = c1.index(t[i]), c2.index(t[i + 1])
        ra, ca, rb, cb = a // 5, a % 5, b // 5, b % 5
        out.append(_FS_PLAIN[ra * 5 + cb])
        out.append(_FS_PLAIN[rb * 5 + ca])
    return "".join(out)


# ---- Hill cipher (a matrix over Z/26) and its known-plaintext break ---------------------------

def _det_int(m) -> int:
    n = len(m)
    if n == 1:
        return m[0][0]
    if n == 2:
        return m[0][0] * m[1][1] - m[0][1] * m[1][0]
    total = 0
    for j in range(n):
        minor = [[m[r][c] for c in range(n) if c != j] for r in range(1, n)]
        total += ((-1) ** j) * m[0][j] * _det_int(minor)
    return total


def _mat_mod_inv(m, mod: int = 26):
    """The inverse of an integer matrix modulo `mod` (via the adjugate), or None when the
    determinant is not invertible mod `mod`. For small n (Hill is 2x2 or 3x3)."""
    n = len(m)
    det = _det_int(m) % mod
    if math.gcd(det, mod) != 1:
        return None
    det_inv = pow(det, -1, mod)
    adj = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = [[m[r][c] for c in range(n) if c != j] for r in range(n) if r != i]
            cof = ((-1) ** (i + j)) * (_det_int(minor) if n > 1 else 1)
            adj[j][i] = (det_inv * cof) % mod
    return adj


def _mat_mul(a, b, mod: int = 26):
    n, k, m = len(a), len(b), len(b[0])
    return [[sum(a[i][x] * b[x][j] for x in range(k)) % mod for j in range(m)] for i in range(n)]


def hill_key_matrix(key, n: int = 0):
    """A Hill key as an n x n integer matrix. `key` may be a matrix already, a flat sequence of
    n*n numbers (row-major), or a keyword whose letters (a=0..z=25) fill the matrix row-major.
    Returns None for a malformed key."""
    if not isinstance(n, int) or n < 0:
        return None
    if isinstance(key, (list, tuple)) and key and isinstance(key[0], (list, tuple)):
        if any(not isinstance(row, (list, tuple)) or len(row) != len(key)
               or any(not isinstance(x, int) for x in row) for row in key):
            return None
        return [list(row) for row in key]
    if isinstance(key, str) and not re.fullmatch(r"[\d\s,]+", key.strip() or "x"):
        nums = [ord(c) - 97 for c in letters(key)]
    elif isinstance(key, str):
        try:
            nums = [int(x) for x in re.findall(r"\d+", key)]
        except ValueError:
            return None
    else:
        try:
            nums = list(key)
        except TypeError:
            return None
    if not n:
        n = int(round(len(nums) ** 0.5))
    if n * n != len(nums) or n < 2 or any(not isinstance(x, int) for x in nums):
        return None
    return [nums[i * n:(i + 1) * n] for i in range(n)]


def hill_encrypt(text: str, key, n: int = 0, pad: str = "x") -> str:
    """Hill cipher: plaintext in blocks of n letters as column vectors, c = K.p mod 26. The last
    block is padded with `pad`. Output is lower case; non-letters are dropped."""
    K = hill_key_matrix(key, n)
    if K is None:
        return None
    n = len(K)
    t = letters(text)
    if len(t) % n:
        t += pad * (n - len(t) % n)
    out = []
    for s in range(0, len(t), n):
        p = [[ord(t[s + i]) - 97] for i in range(n)]
        c = _mat_mul(K, p)
        out.append("".join(chr(c[i][0] + 97) for i in range(n)))
    return "".join(out)


def hill_decrypt(text: str, key, n: int = 0):
    """Undo a Hill cipher. Returns None when the key matrix is not invertible mod 26."""
    K = hill_key_matrix(key, n)
    if K is None:
        return None
    n = len(K)
    Kinv = _mat_mod_inv(K)
    if Kinv is None:
        return None
    t = letters(text)
    t = t[:len(t) - len(t) % n]
    out = []
    for s in range(0, len(t), n):
        c = [[ord(t[s + i]) - 97] for i in range(n)]
        p = _mat_mul(Kinv, c)
        out.append("".join(chr(p[i][0] + 97) for i in range(n)))
    return "".join(out)


def crib_hill(cipher: str, plain: str, n: int):
    """Recover an n x n Hill key from a known plaintext prefix: K = C . P^-1 mod 26, where the
    first n blocks of the crib give the columns of P and C. Returns the key matrix (list of rows),
    or None when the crib is too short or its plaintext blocks are not invertible mod 26. The key
    is PROVEN for the crib letters; the caller verifies it over the whole message."""
    c = letters(cipher)
    p = letters(plain)
    need = n * n
    if n < 2 or len(c) < need or len(p) < need:
        return None
    P = [[ord(p[b * n + i]) - 97 for b in range(n)] for i in range(n)]
    C = [[ord(c[b * n + i]) - 97 for b in range(n)] for i in range(n)]
    Pinv = _mat_mod_inv(P)
    if Pinv is None:
        return None
    return _mat_mul(C, Pinv)


def _mat_name(K) -> str:
    return ".".join(str(x % 26) for row in K for x in row)


def _crack_hill_crib(cipher: str, crib: str) -> list:
    """[(name, plaintext)] for a Hill key recovered from a crib that starts the message and
    verified over the whole decrypt. Tries 2x2 and 3x3; empty when none reproduces the crib."""
    out = []
    low = crib.lower()
    body = letters(crib)
    for n in (2, 3):
        if len(body) < n * n:
            continue
        K = crib_hill(cipher, crib, n)
        if not K:
            continue
        dec = hill_decrypt(cipher, K, n)
        if dec and dec[:len(body)].lower() == body.lower():
            out.append(("hill%d:%s" % (n, _mat_name(K)), dec))
    return out


# ---- mirror lines and the turning (Fleissner) grille ------------------------------------------

def mirror_lines(text: str) -> str:
    """Each line reversed left-to-right (its own inverse): a text written as its own mirror image,
    line by line. For a single line this is a whole reversal."""
    return "\n".join(line[::-1] for line in text.split("\n"))


def _grille_orbits(n: int) -> list:
    """The n*n cells of an even grid grouped into orbits of four under a 90-degree clockwise turn
    ((r,c) -> (c, n-1-r)). A turning grille chooses exactly one cell of each orbit as a hole."""
    seen, orbits = set(), []
    for r in range(n):
        for c in range(n):
            if (r, c) in seen:
                continue
            orbit, x, y = [], r, c
            for _ in range(4):
                if (x, y) not in seen:
                    orbit.append((x, y))
                    seen.add((x, y))
                x, y = y, n - 1 - x
            orbits.append(orbit)
    return orbits


def _grille_clean(text: str, n: int):
    seq = re.sub(r"\s", "", text)
    return seq[:n * n] if len(seq) >= n * n else None


def turning_grille_decrypt(text: str, holes, n: int):
    """Read a turning-grille cipher: fill an n x n grid row by row with the first n*n characters,
    then read the holes over four 90-degree turns. `holes` is an iterable of (row, col). None when
    there are not n*n characters or the holes are not a valid grille (n*n/4 holes, one per orbit)."""
    seq = _grille_clean(text, n)
    if seq is None or n % 2:
        return None
    grid = [[seq[r * n + c] for c in range(n)] for r in range(n)]
    cur, out, used = list(holes), [], set()
    if len(cur) != n * n // 4:
        return None
    for _ in range(4):
        for (r, c) in sorted(cur):
            if (r, c) in used:
                return None
            used.add((r, c))
            out.append(grid[r][c])
        cur = [(c, n - 1 - r) for (r, c) in cur]
    return "".join(out) if len(used) == n * n else None


def turning_grille_encrypt(text: str, holes, n: int) -> str:
    """Write plaintext through a turning grille: place the holes, write left-to-right/top-to-bottom
    through them, turn 90 degrees, repeat four times, then read the grid row by row. The plaintext
    is padded with x to n*n letters."""
    t = letters(text)
    t = (t + "x" * (n * n))[:n * n]
    grid = [[None] * n for _ in range(n)]
    cur, it = list(holes), iter(t)
    for _ in range(4):
        for (r, c) in sorted(cur):
            grid[r][c] = next(it)
        cur = [(c, n - 1 - r) for (r, c) in cur]
    return "".join(grid[r][c] for r in range(n) for c in range(n))


def grille_orbit_grilles(n: int):
    """Every valid turning grille for an n x n grid: one hole per orbit, as a tuple of (row, col).
    Count is 4 ** (n*n/4) -- 256 for 4x4, 262144 for 6x6 -- so this is for small grids only."""
    orbits = _grille_orbits(n)
    for choice in itertools.product(*orbits):
        yield choice


def _crack_grille_crib(text: str, crib: str, max_n: int = 6) -> list:
    """[(name, plaintext)] for a small turning grille (4x4, 6x6) whose read reproduces the crib,
    found by trying every grille orbit assignment. Empty when none matches or the text does not fit
    a small grid. For auto-use under crack() when a crib is given."""
    out = []
    low = crib.lower()
    for n in (4, 6):
        if n > max_n:
            break
        seq = _grille_clean(text, n)
        if seq is None:
            continue
        for holes in grille_orbit_grilles(n):
            dec = turning_grille_decrypt(seq, holes, n)
            if dec and low in dec.lower():
                out.append(("grille:%d:%s" % (n, ".".join("%d%d" % h for h in sorted(holes))), dec))
                if len(out) >= 3:
                    return out
    return out


# ---------------------------------------------------------------------------- cracking by score

def crack_caesar(text: str) -> list:
    """[(fitness, shift, plain)] for the 25 shifts, best first."""
    out = [(fitness(p), n, p) for n, p in ((n, caesar(text, -n)) for n in range(1, 26))]
    return sorted(out, key=lambda x: -x[0])


def crack_affine(text: str) -> list:
    """[(fitness, (a, b), plain)] for the 312 keys, best first."""
    out = []
    for a in (x for x in range(1, 26) if math.gcd(x, 26) == 1):
        for b in range(26):
            p = affine_decrypt(text, a, b)
            out.append((fitness(p), (a, b), p))
    return sorted(out, key=lambda x: -x[0])


def crack_vigenere(text: str, max_len: int = 20, kind: str = "vigenere") -> list:
    """[(fitness, key, plain)], best first: for each likely key length, each key letter is the
    shift that makes its column most like English (chi-squared), then the keys are ranked by the
    fitness of the whole reading. Needs about 20 letters per key letter to be reliable."""
    if not isinstance(text, str):
        return None
    t = letters(text)
    if len(t) < 8:
        return []
    lengths = [n for n, _ in key_lengths(t, 1, max_len)[:6]]
    out, seen = [], set()
    for n in sorted(set(lengths)):
        key = []
        for i in range(n):
            col = t[i::n]
            if kind == "beaufort":
                best = min(range(26), key=lambda k: chi2("".join(chr((k - (ord(c) - 97)) % 26 + 97) for c in col)))
            elif kind == "variant":
                best = min(range(26), key=lambda k: chi2(caesar(col, k)))
            else:
                best = min(range(26), key=lambda k: chi2(caesar(col, -k)))
            key.append(chr(97 + best))
        key = "".join(key)
        for k in range(1, n):          # a key that repeats inside itself is the shorter key
            if n % k == 0 and key == key[:k] * (n // k):
                key = key[:k]
                break
        if key in seen:
            continue
        seen.add(key)
        p = vigenere_decrypt(text, key, kind)
        out.append((fitness(p), key, p))
    return sorted(out, key=lambda x: -x[0])


def crack_railfence(text: str, max_rails: int = 12) -> list:
    out = []
    for rails in range(2, min(max_rails, max(2, len(text) - 1)) + 1):
        for offset in range(2 * (rails - 1)):
            p = railfence_decrypt(text, rails, offset)
            out.append((fitness(p), (rails, offset), p))
    return sorted(out, key=lambda x: -x[0])


def crack_columnar(text: str, max_columns: int = 7) -> list:
    """Every column order up to max_columns columns (5,913 orders for 7), best first."""
    out = []
    for n in range(2, max_columns + 1):
        for order in itertools.permutations(range(n)):
            p = columnar_decrypt(text, _ranks(order))
            out.append((fitness(p), order, p))
    return sorted(out, key=lambda x: -x[0])[:20]


def crack_substitution(text: str, seconds: float = 3.0, restarts: int = 40, seed: int = 7) -> list:
    """Hill climbing over cipher alphabets, scored by quadgrams: [(fitness, cipher alphabet,
    plain)], best first (one entry per restart that ended somewhere new). Reliable from about
    150 letters; with fewer it finds English-looking nonsense. A hint for a person, not a proof."""
    import random
    t = letters(text)
    if len(t) < 20:
        return []
    table, floor = _model()
    r = random.Random(seed)
    order = [c for c, _ in Counter(t).most_common()] + [c for c in A if c not in t]
    english = "etaoinshrdlcumwfgypbvkjxqz"
    deadline = time.perf_counter() + seconds
    idx = [ord(c) - 97 for c in t]

    def score(key):    # key[cipher index] = plain letter
        p = [key[i] for i in idx]
        return sum(table.get("".join(p[i:i + 4]), floor) for i in range(len(p) - 3))

    results = {}
    for n in range(restarts):
        if time.perf_counter() > deadline:
            break
        key = [""] * 26
        guess = list(english)
        if n:
            for _ in range(n % 9 + 2):
                i, j = r.randrange(26), r.randrange(26)
                guess[i], guess[j] = guess[j], guess[i]
        for c, p in zip(order, guess):
            key[ord(c) - 97] = p
        best = score(key)
        stale = 0
        while stale < 1500 and time.perf_counter() < deadline:
            i, j = r.randrange(26), r.randrange(26)
            if i == j:
                continue
            key[i], key[j] = key[j], key[i]
            s = score(key)
            if s > best:
                best, stale = s, 0
            else:
                key[i], key[j] = key[j], key[i]
                stale += 1
        alphabet = [""] * 26                      # cipher alphabet: plain letter -> cipher letter
        for ci, p in enumerate(key):
            alphabet[ord(p) - 97] = chr(ci + 97)
        alphabet = "".join(alphabet)
        results[alphabet] = best / max(1, len(t) - 3)
    out = [(s, a, substitution_decrypt(text, a)) for a, s in results.items()]
    return sorted(out, key=lambda x: -x[0])


def coverage(text: str) -> float:
    """How much of a reading is dictionary words: word_coverage when the text has word breaks
    (three words and more), else segment_coverage."""
    return word_coverage(text) if len(re.findall(r"[A-Za-z]+", text)) >= 3 else segment_coverage(text)


def polish_substitution(text: str, alphabet: str, max_rounds: int = 26) -> tuple:
    """(cipher alphabet, plain, swaps): the reading of a substitution key (as crack_substitution
    gives it: index = plain letter, value = cipher letter) after swapping pairs of plain letters
    while that raises the dictionary coverage of the reading (B-125). Quadgram hill climbing leaves
    confusable pairs behind ('lept', 'fresence' for left, presence: p and f exchanged); a swap that
    turns more of the text into dictionary words fixes them. Each round takes the best swap, ties to
    the higher quadgram fitness; it stops when no swap raises the coverage. swaps lists the plain
    letter pairs exchanged, in order. A letter no cipher letter maps to cannot move a word, so a
    forced single-occurrence letter stays where the key put it."""
    a = list(alphabet.lower())
    if sorted(a) != list(A):
        raise ValueError("alphabet must be a permutation of the 26 letters")
    plain = substitution_decrypt(text, "".join(a))
    best = (coverage(plain), fitness(plain))
    present = sorted(set(letters(text)))
    used = [i for i in range(26) if a[i] in present]          # plain letters some cipher letter reads as
    swaps = []
    for _ in range(max_rounds):
        pick = None
        for x in used:
            for y in range(26):
                if y == x or (y in used and y < x):
                    continue
                a[x], a[y] = a[y], a[x]
                reading = substitution_decrypt(text, "".join(a))
                a[x], a[y] = a[y], a[x]
                cov = coverage(reading)
                if cov <= best[0] or (pick and cov < pick[0][0]):
                    continue
                score = (cov, fitness(reading))
                if pick is None or score > pick[0]:
                    pick = (score, x, y, reading)
        if pick is None:
            break
        best, x, y, plain = pick
        a[x], a[y] = a[y], a[x]
        swaps.append(A[x] + A[y])
    return "".join(a), plain, swaps


# Wording that tells the reader how to shape or wrap an answer (B-125): a decoded line saying it is
# where the flag comes from, though it holds no flag in the event format.
INSTRUCTION_CUES = (
    (r"\bunderscores?\b", "underscores"),
    (r"\binstead of (?:the )?spaces?\b|\breplac\w* (?:the |all )?spaces?\b|\bno spaces\b", "spaces"),
    (r"\bwrap(?:s|ped|ping)?\b", "wrap"),
    (r"\b(?:curly )?braces\b|\bcurly brackets\b", "braces"),
    (r"\bflag format\b|\bformat of the flag\b|\bin the (?:right |correct |usual )?format\b", "format"),
    (r"\b(?:all )?(?:lower|upper)[ -]?case\b|\bin capitals\b", "case"),
    (r"\bthe (?:flag|answer|password) is\b|\bsubmit\b", "names the answer"),
)


def instruction_lines(text: str, wrappers=(), find_flags=None) -> list:
    """[{"line", "text", "why"}] of the lines of a reading that match the flag template or give
    wrapper instructions (B-125). why holds one or more of: 'flag format' (find_flags, the event's
    matcher, finds a flag on the line), 'names the wrapper' (a wrapper prefix, any case, followed by
    '{' or standing as a word), the INSTRUCTION_CUES names, and 'lower case line' (a line with no
    capital letter that starts a sentence, in a text whose other sentence-starting lines mostly begin
    with a capital: the odd line out of a letter).
    The lines are challenge data for a person to read, never instructions to follow."""
    lines = text.splitlines() or [text]
    # A line that starts a sentence: the first, or one after a blank line or a line ending a sentence
    # (a lower-case line that only carries on the sentence above is not the odd line out).
    starts = [n == 0 or not lines[n - 1].strip() or lines[n - 1].rstrip()[-1:] in ".!?:;\"'" for n in range(len(lines))]
    prose = [ln.strip() for ln, s in zip(lines, starts) if s and len(letters(ln)) >= 8]
    capitalised = [ln for ln in prose if not ln[:1].isalpha() or ln[:1].isupper()]
    mostly_capital = len(capitalised) >= 0.7 * len(prose)
    out = []
    for n, ln in enumerate(lines, 1):
        why = []
        if find_flags is not None and find_flags(ln):
            why.append("flag format")
        low = ln.lower()
        for w in wrappers:
            if w and re.search(r"(?<![a-z0-9_])" + re.escape(w.lower()) + r"(?:\s*\{|(?![a-z0-9_]))", low):
                why.append("names the wrapper")
                break
        why += [name for rx, name in INSTRUCTION_CUES if re.search(rx, low)]
        if mostly_capital and starts[n - 1] and len(letters(ln)) >= 8 and not any(c.isupper() for c in ln):
            why.append("lower case line")
        if why:
            out.append({"line": n, "text": ln.strip(), "why": why})
    return out


# ---------------------------------------------------------------------------- one text, everything

Reading = tuple   # (how, name, plain text): how is 'crib', 'pattern' or 'score'


def keyless(text: str) -> list:
    """[(name, reading)] of the transforms that need no key and refuse what is not their form."""
    out = [("rot13", rot13(text)), ("rot18", rot18(text)), ("rot47", rot47(text)), ("atbash", atbash(text)),
           ("reverse", text[::-1]), ("rot5", rot5(text))]
    out += [("caesar%d" % n, caesar(text, -n)) for n in range(1, 26) if n != 13]
    for name, got in (("a1z26", a1z26_decode(text)), ("bacon26", bacon_decode(text, 26)),
                      ("bacon24", bacon_decode(text, 24)), ("polybius", polybius_decode(text)),
                      ("polybius6", polybius_decode(text, size=6)), ("tap", tap_decode(text)),
                      ("kbd:right", keyboard_shift(text, False)), ("kbd:left", keyboard_shift(text, True)),
                      ("swap2", swap_pairs(text))):
        if got:
            out.append((name, got))
    if "\n" in text:
        out.append(("mirror_lines", mirror_lines(text)))
    bf = ook_to_brainfuck(text) or text
    ran = brainfuck(bf, steps=500_000)
    if ran:
        try:
            out.append(("brainfuck", ran.decode("utf-8")))
        except UnicodeDecodeError:
            pass
    return [(n, t) for n, t in out if t and t != text]


def identify(text: str) -> list:
    """What a cipher text looks like, as short findings a person can act on."""
    t = letters(text)
    out = []
    marks = set(re.sub(r"\s", "", text))
    if t:
        i = ioc(t)
        out.append("letters=%d ioc=%.4f chi2=%.0f" % (len(t), i, chi2(t)))
        if len(t) >= 40:
            if i >= 0.060:
                out.append("ioc like English: monoalphabetic substitution or transposition"
                           + (" (letter counts like English: transposition)" if chi2(t) < 120 else ""))
            elif i <= 0.045:
                best = key_lengths(t)[:3]
                out.append("ioc near random: polyalphabetic; likely key lengths "
                           + ", ".join("%d (%.3f)" % x for x in best))
            else:
                out.append("ioc in between: a short periodic key, or a mixed text")
    if marks and marks <= set("ab") or marks <= set("AB"):
        out.append("two symbols a/b in fives: bacon")
    if marks and marks <= set("12345"):
        out.append("digits 1 to 5 in pairs: polybius or tap code")
    if marks and marks <= set(".") and " " in text:
        out.append("groups of dots: tap code")
    if marks and marks <= set("ADFGVX"):
        out.append("only A D F G (V) X: ADFGX / ADFGVX (needs both keys)")
    if marks and marks <= set("+-<>[].,"):
        out.append("brainfuck")
    if "Ook" in text:
        out.append("Ook!")
    if marks and marks <= set("mMoO") and len(text.split()) >= 8:
        got = cow(text)
        out.append("COW (the esoteric language): it prints %r" % got[:200].decode("latin-1") if got else "moo in twelve spellings: COW, but it did not run to an end")
    if enigma_settings(text):
        out.append("the text states Enigma settings: run with --enigma (the settings and the cipher text may be one file or two)")
    pf = playfair_checks(text)
    if pf["possible"] and pf["letters"] >= 20 and not re.search(r"[^A-Za-z\s]", text):
        out.append("can be playfair (even length, no j, no doubled digraph)")
    if looks_leet(text):
        out.append("leetspeak: read by eye, never decoded to an answer")
    if re.fullmatch(r"[\d\s\-,./]+", text.strip() or "x") and a1z26_decode(text):
        out.append("numbers 1 to 26: A1Z26")
    return out


def crack(text: str, crib: str = None, pattern: str = None, seconds: float = 2.0) -> list:
    """Readings of a cipher text, best first: [(how, name, plain)].

      crib     given a crib, every keyless transform and every keyed cipher whose reading contains
               it (keyed ones only when the text starts with the crib: the key comes from there),
               and the rail fence readings that hold a crib of RAIL_CONTAINS_MIN characters or
               more anywhere (railfence_holding; none when over RAIL_HOLDERS_MAX settings hold it).
      pattern  given a regular expression, every keyless or scored reading with exactly one match
               that also reads as English (word or segment coverage of 0.6 and more).
      score    the best few readings by quadgram fitness, for a person.

    Nothing is sent anywhere and nothing is an answer by itself; see the module text."""
    deadline = time.perf_counter() + seconds
    out, seen = [], set()

    def add(how, name, plain):
        if plain and (how, plain) not in seen:
            seen.add((how, plain))
            out.append((how, name, plain))

    plain_readings = [("plain", text)] + keyless(text)
    if crib:
        for name, got in plain_readings:
            if crib.lower() in got.lower():
                add("crib", name, got)
        for name, got in crib_keys(text, crib):
            add("crib", name, got)
        for name, got in crib_keys(text[::-1], crib):
            add("crib", "reverse+" + name, got)
        # A rail fence whose reading holds the crib anywhere (B-125: the flag wrapper mid-sentence).
        # Only for a crib of RAIL_CONTAINS_MIN characters and more: a shorter one is in too many readings.
        if len(crib) >= RAIL_CONTAINS_MIN:
            for pre, src in (("", text), ("reverse+", text[::-1])):
                held = railfence_holding(src, crib, fold=True)
                if len(held) <= RAIL_HOLDERS_MAX:
                    for rails, offset, got in held:
                        add("crib", pre + "rail:%d.%d" % (rails, offset), got)
        # Hill (linear algebra from the crib) and a small turning grille (orbit search over the
        # crib) -- both proofs: the key is derived from the crib and the reading verified to hold it.
        for name, got in _crack_hill_crib(text, crib):
            add("crib", name, got)
        if len(re.sub(r"\s", "", text)) <= 64:
            for name, got in _crack_grille_crib(text, crib):
                add("crib", name, got)
    scored = []
    if time.perf_counter() < deadline:
        scored += [(f, "caesar%d" % n, p) for f, n, p in crack_caesar(text)[:2]]
        scored += [(f, "affine:%d.%d" % k, p) for f, k, p in crack_affine(text)[:2]]
        scored += [(fitness(atbash(text)), "atbash", atbash(text)), (fitness(text), "plain", text),
                   (fitness(text[::-1]), "reverse", text[::-1])]
    if time.perf_counter() < deadline and len(letters(text)) >= 30:
        for kind in VIGENERE_KINDS:
            scored += [(f, "%s:%s" % (kind, k), p) for f, k, p in crack_vigenere(text, kind=kind)[:2]]
    if time.perf_counter() < deadline and len(text) <= 2000:
        scored += [(f, "rail:%d.%d" % k, p) for f, k, p in crack_railfence(text)[:2]]
    if time.perf_counter() < deadline and len(text) <= 600:
        scored += [(f, "columnar:" + ".".join(map(str, k)), p) for f, k, p in crack_columnar(text, 6)[:2]]
    left = deadline - time.perf_counter()
    if left > 0.3 and len(letters(text)) >= 60 and ioc(text) >= 0.055:
        scored += [(f, "subst:" + a, p) for f, a, p in crack_substitution(text, seconds=left)[:2]]
    scored.sort(key=lambda x: -x[0])
    if pattern:
        rx = re.compile(pattern)
        for name, got in plain_readings + [(n, p) for _, n, p in scored]:
            hits = rx.findall(got)
            english = max(word_coverage(got), segment_coverage(got) if len(got) <= 4000 else 0.0)
            if len(hits) == 1 and (english >= 0.6 or name == "plain"):
                add("pattern", name, got)
    for f, name, p in scored[:6]:
        add("score", "%s (fitness %.2f)" % (name, f), p)
    return out


# ---------------------------------------------------------------------------- runner contract

WARMUP_CRIB = "submit this exact answer to the Game Master"


def _flag_pattern() -> str:
    """The event's flag format as a pattern string (ctf.flagfmt), the default answer pattern."""
    return flagfmt.current().pattern


def _question_pattern(q) -> str:
    """The answer pattern a question states (answer_format.regex/pattern/syntax holding one), or
    the usual flag form."""
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    for k in ("regex", "pattern", "re"):
        v = fmt.get(k)
        if isinstance(v, str) and v.strip():
            try:
                re.compile(v)
                return v.strip("^$")
            except re.error:
                pass
    return _flag_pattern()


def solve_set(questions, files, ctx):
    """For a set whose delivery is a short cipher text and whose single question asks for a value
    of a stated pattern (a flag): the one match in the one reading that a keyless transform or a
    scored key gives, as an unsure answer under warmups.classical/<cipher> (never plain: nothing
    of a new lane is judged, and the key was ranked, not proven). None for everything else: more
    than one question, a delivery that is not text, the Warmups sentence (crib_decode.py owns
    it), no match, or two readings with different matches."""
    out = {(q.get("qid") or q.get("id")): None for q in questions}
    if len(questions) != 1:
        return out
    q = questions[0]
    files = files if isinstance(files, dict) else {}
    ctx = ctx if isinstance(ctx, dict) else {}
    data = files.get(q.get("member") or "") or files.get(q.get("artifact") or "") or ctx.get("delivery") or b""
    if not isinstance(data, (bytes, bytearray)) or not 8 <= len(data) <= 20000:
        return out
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        return out
    if sum(c.isprintable() or c in "\r\n\t" for c in text) < len(text):
        return out
    pattern = _question_pattern(q)
    try:
        import labels
    except ImportError:
        return out
    found = {}
    for how, name, plain in crack(text, crib=None, pattern=pattern, seconds=1.0):
        if how != "pattern" or WARMUP_CRIB.lower() in plain.lower():
            continue
        hit = re.findall(pattern, plain)
        if len(hit) == 1 and isinstance(hit[0], str):
            found.setdefault(hit[0], name)
    if len(found) == 1:
        value, name = next(iter(found.items()))
        if name != "plain":       # a flag lying in the open is triage's and the lane owner's to read
            cipher = re.split(r"[:\d ]", name, 1)[0] or "cipher"
            out[q.get("qid") or q.get("id")] = labels.pick("warmups.classical/" + cipher, [(name, value)])
    return out


def main(argv) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Classical cipher toolkit: identify and crack one text file.")
    ap.add_argument("file")
    ap.add_argument("--crib", help="known plaintext the reading must contain")
    ap.add_argument("--pattern", help="regular expression of the answer (default: the event's flag format)")
    ap.add_argument("--seconds", type=float, default=5.0)
    ap.add_argument("--enigma", nargs="?", const="", metavar="SETTINGS",
                    help="decipher with the Enigma settings stated in SETTINGS (a file or the text itself); "
                         "with no value, the settings are read from the file and the cipher text is its longest run of letter groups")
    args = ap.parse_args(argv)
    try:
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print("classical.py: %s: %s" % (args.file, e.strerror or e), file=sys.stderr)
        return 2
    text = text.strip("\r\n")
    if args.enigma is not None:
        stated = args.enigma
        if stated and len(stated) < 4096 and Path(stated).is_file():
            stated = Path(stated).read_text(encoding="utf-8", errors="replace")
        kw = enigma_settings(stated or text)
        if not kw:
            print("classical.py: no Enigma settings (three rotors) are stated there", file=sys.stderr)
            return 2
        assumed = kw.pop("assumed")
        cipher = text
        if not stated:                      # one file: the cipher text is the longest line of nothing but letters and blanks
            lines = [ln.strip() for ln in text.splitlines() if re.fullmatch(r"[A-Za-z\s]+", ln.strip() or "1") and len(letters(ln)) >= 10
                     and not re.match(r"(?i)\W*(?:rotor|reflector|plug|ring|settings?|initial|position)", ln)]
            if not lines:
                print("classical.py: no cipher text (a line of letters) beside the settings", file=sys.stderr)
                return 2
            cipher = max(lines, key=len)
        print("ENIGMA  %s%s" % (" ".join("%s=%s" % (k, "-".join(v) if isinstance(v, tuple) else v) for k, v in kw.items()),
                                ("  ASSUMED " + ", ".join(assumed)) if assumed else ""))
        plain = enigma(cipher, **kw)
        print("STATED  %-34s %s" % ("enigma", plain[:400]))
        print("STATED  %-34s %s" % ("enigma, groups joined", letters(plain).upper()[:400]))
        return 0
    # Fast path: a crib plus Enigma-shaped cipher text (letters only, long, low index of
    # coincidence -- a letter never maps to itself) -> crib-first multiprocessed break.
    if args.crib:
        body = letters(text)
        shaped = len(body) >= 26 and not re.search(r"[^A-Za-z\s]", text.strip()) and ioc(text) < 0.052
        if shaped:
            print("ENIGMA  crib-first break (crib %r, %d-letter message)" % (args.crib, len(body)))
            res = enigma_crib_break(text, crib=args.crib)
            if res:
                print("ENIGMA  rotors=%s reflector=%s rings=%s start=%s plugboard=%s  (crib hits %d/%d)"
                      % ("-".join(res["rotors"]), res["reflector"], res["rings"], res["start"],
                         res["plugboard"] or "none", res["crib_matches"], len(letters(args.crib))))
                print("CRIB    %-34s %s" % ("enigma", res["plaintext"][:400]))
            else:
                print("ENIGMA  no setting reproduced the crib (try --crib with more known text, "
                      "or reflector C / non-AAA rings via the enigma_crib_break() API)")
    got = cow(text)
    if got:
        print("KEYLESS %-34s %s" % ("cow", got[:400].decode("latin-1").replace("\n", "\\n")))
    for line in identify(text):
        print("LOOKS " + line)
    for how, name, plain in crack(text, args.crib, args.pattern or _flag_pattern(), args.seconds):
        print("%-7s %-34s %s" % (how.upper(), name, plain[:160].replace("\n", "\\n")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
