"""Exotic Warmups readers (Day 26 build): multi-tap, Pig Latin, wide triple columnar, extra running-key texts.

Everything here is crib-anchored and never wrong:

* multi-tap (phone keypad) and Pig Latin are LOSSY (case, spaces, marks and digits are not all carried), so they are
  lossy_codes lattice codes (`multitap`, `piglatin`): the 68 letters of the sentence must come out of the first items,
  then the slug is parsed. They are registered NOT fixed, so the reading is only ever labels.unsure
  (warmups.lossy/<code>), never plain, accepted or not. A random blob reproduces no crib: None.
* triple columnar with an outer order of 5 columns: transposition.crib_triple_columnar stops at 4 (cost). `wide_readings`
  goes to 5 when the caller has the time (>= WIDE_MIN_LEFT s to the deadline); the reading must reproduce the whole
  sentence and be the only full text, as the narrow reader requires (information-preserving: plain by crib proof).
* long running keys: EXTRA_RUNKEY_TEXTS are public-domain passages longer than the crib; lossy_ciphers adds them to its
  key texts. The key stream the sentence proves must be a stretch of the passage (68+ letters), the slug's letters
  come from the passage; digits stay open (warmups.digits/runkey) as for every running-key reading.
"""
import itertools
import re
import time

try:
    from _shadowed import common_module
    K = common_module("classical")  # common/classical.py by file: toolkits/classical.py wins a flat import
except Exception:        # pragma: no cover
    K = None
try:
    import transposition as TR
except Exception:        # pragma: no cover
    TR = None

# ---------------------------------------------------------------------------- multi-tap

_KEYS = {"2": "abc", "3": "def", "4": "ghi", "5": "jkl", "6": "mno", "7": "pqrs", "8": "tuv", "9": "wxyz"}
_MARK_OPTS = (".", ",", "!", "")
_PUNCT = set(":!,.;'\"?-")


def multitap_items(text):
    """Multi-tap keypad: a token is one key pressed k times (66 = n); `0` is a space; the key's own digit is one
    press more than it has letters (4444 = 4). Tokens are separated by blanks, a word break by `/`, `|` or two
    blanks. The `1` key's marks differ by phone, so it stands for any mark or nothing. Anything else is no
    multi-tap text."""
    from lossy_codes import _pass   # loaded lazily (lossy_codes imports this module)
    t = text.strip()
    if not re.search(r"\d", t) or re.search(r"[A-Za-z]", t):
        return None
    items, letters = [], 0
    for tok in t.split():           # a blank only separates keys: the `0` key and `/` are the word breaks
        if tok in ("/", "|"):
            items.append((" ",))
            continue
        if tok.isdigit() and len(set(tok)) == 1:
            d, k = tok[0], len(tok)
            if d in _KEYS:
                ks = _KEYS[d]
                if k <= len(ks):
                    items.append((ks[k - 1],))
                    letters += 1
                elif k == len(ks) + 1:
                    items.append((d,))
                else:
                    return None
            elif d == "0":
                if k == 1:
                    items.append((" ",))
                elif k == 2:
                    items.append(("0",))
                else:
                    return None
            else:                                   # the 1 key
                items.append(_MARK_OPTS)
            continue
        if len(tok) == 1 and tok in _PUNCT or tok in ("*", "#"):
            items.append((tok if tok not in "*#" else "",))
            continue
        p = _pass(tok)
        if p is None:
            return None
        items += p
    return items if letters >= 20 else None


# ---------------------------------------------------------------------------- Pig Latin

_VOW = "aeiou"


def _pig_options(w):
    """The original words a Pig Latin word (lower case letters) can stand for."""
    out = []
    if len(w) < 3 or not w.endswith("ay") and not w.endswith("way"):
        return None
    if w.endswith("way") and len(w) > 3:
        out.append(w[:-3])                              # a vowel-start word
    if w.endswith("yay") and len(w) > 3:
        out.append(w[:-3])
    if w.endswith("ay"):
        base = w[:-2]
        if len(base) >= 1 and base[0] in _VOW:
            out.append(base)                            # vowel-start word with a bare `ay`
        for k in range(1, min(4, len(base) - 1) + 1):
            cluster, rest = base[-k:], base[:-k]
            if not rest or rest[0] not in _VOW + "y":
                continue
            body = cluster[:-1] if cluster.endswith("q") and rest[0] == "u" else cluster
            if any(c in _VOW for c in cluster.replace("qu", "q")) or not cluster.replace("qu", "q"):
                continue
            if body.endswith("q") and rest[0] != "u":
                continue
            out.append(cluster + rest)
    seen, uniq = set(), []
    for o in out:
        if o not in seen:
            seen.add(o)
            uniq.append(o)
    return uniq or None


def piglatin_items(text):
    """Pig Latin, per word: consonant cluster moved to the end plus `ay`; a vowel-start word takes `way`, `yay` or
    `ay`. Trailing marks stay, a hyphenated token is read part by part, digits stand as they are."""
    from lossy_codes import _words
    t = text.strip()
    if not re.search(r"[A-Za-z]{3}", t) or re.search(r"[^A-Za-z0-9\s\-/|:!,.;'\"?]", t):
        return None
    items, hits = [], 0
    for tok in _words(t):
        if tok is None:
            items.append((" ",))
            continue
        for part in re.findall(r"[A-Za-z]+|\d+|[^A-Za-z\d]", tok):
            if part[0].isalpha():
                opts = _pig_options(part.lower())
                slugish = "-" in tok or any(c.isdigit() for c in tok)
                if slugish:     # an encoder that skips tokens with a hyphen or digit leaves the slug as it is
                    opts = list(opts or ()) + [part.lower()]
                if not opts:
                    return None
                items.append(tuple(opts))
                hits += 1
            elif part.isdigit():
                items += [(c,) for c in part]
            elif part in "/|":
                items.append((" ",))
            else:
                items.append((part,))
    return items if hits >= 12 else None


# ---------------------------------------------------------------------------- wide triple columnar

WIDE_MIN_LEFT = 0.6        # seconds a caller must still have to ask for the 5-column outer layer
WIDE_COLUMNS = range(2, 6)
WIDE_ORDER_CAP = 160       # 2+6+24+120 = 152 outer orders


def wide_readings(cipher, plain, deadline):
    """[(name, reading)] for a triple columnar whose OUTER order has up to 5 columns: unique full-sentence reading
    or []. Cut by the deadline or the order cap: [] (never a guess)."""
    if K is None or TR is None or not hasattr(K, "crib_double_columnar"):
        return []
    if deadline is None or deadline - time.perf_counter() < WIDE_MIN_LEFT:
        return []
    n = len(cipher)
    if n > TR.MAX_LEN or n < len(plain) or not K.holds_crib(cipher, plain):
        return []
    stop = deadline - 0.05
    readings, tried = {}, 0
    for n3 in WIDE_COLUMNS:
        if 2 * n3 > n:
            break
        for o3 in itertools.permutations(range(n3)):
            if time.perf_counter() > stop:
                return []
            tried += 1
            if tried > WIDE_ORDER_CAP:
                return []
            t2 = K.columnar_decrypt(cipher, K._ranks(o3))
            got = K.crib_double_columnar(t2, plain)
            if not got:
                continue
            keys, text = got
            if not text.startswith(plain):
                continue
            if text not in readings:
                o1, o2 = keys[0]
                readings[text] = (tuple(o1), tuple(o2), tuple(o3))
            if len(readings) > 1:
                return []
    if len(readings) != 1:
        return []
    (text, (o1, o2, o3)), = readings.items()
    if TR.triple_columnar_decrypt(cipher, o1, o2, o3) != text:
        return []
    return [(TR._name(o1, o2, o3), text)]


# ---------------------------------------------------------------------------- extra running-key texts

EXTRA_RUNKEY_TEXTS = {
    "pride": "it is a truth universally acknowledged that a single man in possession of a good fortune must be in want "
             "of a wife however little known the feelings or views of such a man may be on his first entering a "
             "neighbourhood this truth is so well fixed in the minds of the surrounding families that he is considered "
             "the rightful property of some one or other of their daughters",
    "alice": "alice was beginning to get very tired of sitting by her sister on the bank and of having nothing to do "
             "once or twice she had peeped into the book her sister was reading but it had no pictures or "
             "conversations in it and what is the use of a book thought alice without pictures or conversations",
    "twocities": "it was the best of times it was the worst of times it was the age of wisdom it was the age of "
                 "foolishness it was the epoch of belief it was the epoch of incredulity it was the season of light "
                 "it was the season of darkness it was the spring of hope it was the winter of despair we had "
                 "everything before us we had nothing before us",
    "moby": "call me ishmael some years ago never mind how long precisely having little or no money in my purse and "
            "nothing particular to interest me on shore i thought i would sail about a little and see the watery part "
            "of the world it is a way i have of driving off the spleen and regulating the circulation",
    "genesis": "in the beginning god created the heaven and the earth and the earth was without form and void and "
               "darkness was upon the face of the deep and the spirit of god moved upon the face of the waters and "
               "god said let there be light and there was light and god saw the light that it was good",
    "gettysburg_full": "four score and seven years ago our fathers brought forth on this continent a new nation "
                       "conceived in liberty and dedicated to the proposition that all men are created equal now we "
                       "are engaged in a great civil war testing whether that nation or any nation so conceived and "
                       "so dedicated can long endure",
    "declaration_full": "when in the course of human events it becomes necessary for one people to dissolve the "
                        "political bands which have connected them with another and to assume among the powers of the "
                        "earth the separate and equal station to which the laws of nature and of nature's god entitle "
                        "them a decent respect to the opinions of mankind requires that they should declare the causes "
                        "which impel them to the separation",
    "lorem_long": "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore "
                  "et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut "
                  "aliquip ex ea commodo consequat duis aute irure dolor in reprehenderit in voluptate velit esse "
                  "cillum dolore eu fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt in "
                  "culpa qui officia deserunt mollit anim id est laborum",
    "hamlet_long": "to be or not to be that is the question whether tis nobler in the mind to suffer the slings and "
                   "arrows of outrageous fortune or to take arms against a sea of troubles and by opposing end them "
                   "to die to sleep no more and by a sleep to say we end the heartache and the thousand natural "
                   "shocks that flesh is heir to",
    "preamble_long": "we the people of the united states in order to form a more perfect union establish justice "
                     "insure domestic tranquility provide for the common defence promote the general welfare and "
                     "secure the blessings of liberty to ourselves and our posterity do ordain and establish this "
                     "constitution for the united states of america",
    "raven": "once upon a midnight dreary while i pondered weak and weary over many a quaint and curious volume of "
             "forgotten lore while i nodded nearly napping suddenly there came a tapping as of some one gently rapping "
             "rapping at my chamber door",
    "frankenstein": "it was on a dreary night of november that i beheld the accomplishment of my toils with an anxiety "
                    "that almost amounted to agony i collected the instruments of life around me that i might infuse a "
                    "spark of being into the lifeless thing that lay at my feet",
}
