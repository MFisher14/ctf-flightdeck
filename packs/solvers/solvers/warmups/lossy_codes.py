"""Lossy codes read off the sentence (Day 20 coverage build, 2026-10-19).

The Warmups blob is always the fixed sentence (crib_decode.CRIB) followed by the slug
(`word-word-word-NN`). A lossy code (Polybius, tap code, A1Z26, Bacon of letters, Braille
without the number sign, leetspeak) maps several characters to one symbol, so no strict
decoder reads it: the strict readers want one reading of every symbol. Here each symbol of
the blob becomes an ITEM, the tuple of every string it can stand for (Polybius 24 is `i` or
`j`; the Braille cell for `a` is `a` or `1`; an A1Z26 number 4 is `d` or `4`). The sentence's
68 letters must come out of the first items in order (marks may be dropped), which proves the
code and its table; what follows must parse as a slug, `[a-z]+-[a-z]+-[a-z]+-[0-9]{2}`, with
separators collapsed. One parse is the slug as read (`as_read`); several, of which exactly one
has three known words, is that one (`vocabulary`); anything else is nothing.

Nothing here is plain on its own word: crib_decode._lattice files the slug under
`warmups.lossy/<code>` (never plain for `vocabulary` and for the learned leetspeak table; for a
fixed table read `as_read`, plain only once the judge accepted `as_read` there, in the slot of
the day it was judged on, crib_decode._day_key). Every count is bounded (ITEMS, PARSES, STEPS),
never a clock, so a base, its gate replay and a clock read a blob alike.

Asked by crib_decode only for a whole blob (one payload) that every other reader left None, so no
blob any other reader reads, and no saved blob of Days 1 to 19, reaches it.

Also here: the ciphertext autokey (`autokey_ct`), whose primer length is read off the sentence
(the key of each letter after the primer is the cipher letter that many places back): letters
proven by the sentence, digits open like every Vigenere-family reading (warmups.digits/autokey_ct).
"""
import bisect
import re

ITEMS = 1200      # items read from a blob (the sentence and a slug are about 110 symbols)
PARSES = 64       # slug parses collected before the reading is given up (too many is no reading)
STEPS = 60000     # DFS steps of the crib match and the slug parse together, per code
MAX_TEXT = 6000   # characters of the blob looked at

_LETTERS = "abcdefghijklmnopqrstuvwxyz"
WEAK = "\x02"      # a joiner that may also be a hyphen of the slug's words, never the one before its digits
_SEPS = set(" -/_|" + WEAK)
_MARKS = set(":!,.;'\"?")


def _crib_letters(crib):
    return "".join(c for c in crib.lower() if c.isalpha())


class _Budget:
    def __init__(self):
        self.left = STEPS

    def step(self):
        self.left -= 1
        return self.left > 0


def _crib_ends(items, letters, budget):
    """The item indices at which the sentence's letters end, read in order from items[0]. An option
    with letters must give the next letters of the sentence (any case); one with a digit cannot stand
    in the sentence; marks, blanks and the empty option stand anywhere."""
    want = len(letters)
    ends, seen, stack = set(), set(), [(0, 0)]
    while stack:
        if not budget.step():
            return None
        i, pos = stack.pop()
        if (i, pos) in seen:
            continue
        seen.add((i, pos))
        if pos == want:
            ends.add(i)
            continue
        if i >= len(items):
            continue
        for opt in items[i]:
            low = opt.lower()
            if any(c.isdigit() for c in low):
                continue
            got = "".join(c for c in low if c.isalpha())
            if got and letters[pos:pos + len(got)] != got:
                continue
            stack.append((i + 1, pos + len(got)))
    return ends


def _feed(state, c):
    """The slug automaton: state (part, length, done). None when c cannot come next."""
    part, n, done = state
    if done:
        return state if (c in _SEPS or c in _MARKS) else None
    if "a" <= c <= "z":
        return (part, n + 1, False) if part < 3 else None
    if c.isdigit():
        return (part, n + 1, n + 1 == 2) if part == 3 and n < 2 else None
    if c in _SEPS:
        if c == WEAK and part == 2 and n > 0:
            return None                         # the digits follow a separator that is only a joiner
        if part == 0 and n == 0:
            return state
        if n == 0:
            return state                        # a run of separators is one
        return (part + 1, 0, False) if part < 3 else None
    if c in _MARKS and part == 0 and n == 0:
        return state                            # the ':' and blank after the sentence
    return None


class _Words:
    """Prefix and word checks on the known words, by bisection in one sorted list made once a process."""
    _cache = {}

    def __init__(self, words):
        # The vocabulary is mutable in tests and when a fresh challenges root is loaded.  `(id, len)`
        # reused a stale sorted list after a same-size mutation (and could reuse it after object-id
        # recycling), hiding a valid slug prefix.  One exact immutable snapshot keeps this small cache
        # content scoped; `self.words` remains the caller's current collection for final membership.
        key = frozenset(w for w in words if w.isascii() and w.isalpha() and w.islower())
        got = self._cache.get(key)
        if got is None:
            got = sorted(key)
            self._cache.clear()
            self._cache[key] = got
        self.sorted, self.words = got, words

    def prefix(self, p):
        i = bisect.bisect_left(self.sorted, p)
        return i < len(self.sorted) and self.sorted[i].startswith(p)

    def word(self, w):
        return w in self.words


def _slugs(tail, budget, known=None):
    """The slugs the items after the sentence can be read as, separators collapsed to one hyphen: (set,
    overflow). The set is None when there are more than PARSES or the work ran out (overflow says which).
    With `known` (_Words) every word must be a known word, checked as it grows."""
    out = set()
    stack = [(0, (0, 0, False), "")]
    while stack:
        if not budget.step():
            return None, False
        i, state, acc = stack.pop()
        if i == len(tail):
            if state[2]:
                out.add(acc)
                if len(out) > PARSES:
                    return None, True
            continue
        for opt in tail[i]:
            st, a = state, acc
            for c in opt:
                nxt = _feed(st, c)
                if nxt is None:
                    break
                if not st[2]:
                    if "a" <= c <= "z":
                        a += c
                        if known is not None and not known.prefix(a.rsplit("-", 1)[-1]):
                            break
                    elif c.isdigit():
                        a += c
                    elif c in _SEPS and st[1] > 0 and nxt[0] > st[0]:
                        if known is not None and not known.word(a.rsplit("-", 1)[-1]):
                            break
                        a += "-"
                st = nxt
            else:
                stack.append((i + 1, st, a))
    return out, False


READINGS = 4      # readings of one blob offered together as candidates (labels.candidates), at most


def _choose(found, words, saved):
    """(method, slugs) among several slugs: the one whose three words are known (`vocabulary`); else the
    one whose three words are words of saved slugs (`saved_words`); else up to READINGS slugs whose words
    are all known, those with more saved words first (`readings`, candidates); else None."""
    known = sorted(s for s in found if all(w in words for w in s.split("-")[:3]))
    if len(known) == 1:
        return "vocabulary", known
    if not known:
        return None
    strong = [s for s in known if all(w in saved for w in s.split("-")[:3])]
    if len(strong) == 1:
        return "saved_words", strong
    if len(known) > READINGS:
        return None
    return "readings", sorted(known, key=lambda s: (-sum(w in saved for w in s.split("-")[:3]), s))


def read_items(items, crib, words, saved=frozenset()):
    """(method, [slug, ...]) for a lattice of items, or None. One slug but for `readings`."""
    if not items or len(items) > ITEMS:
        return None
    budget = _Budget()
    ends = _crib_ends(items, _crib_letters(crib), budget)
    if not ends or len(ends) != 1:
        return None
    end = next(iter(ends))
    found, overflow = _slugs(items[end:], budget)
    if found and len(found) == 1:
        return "as_read", [next(iter(found))]
    if found:
        return _choose(found, words, saved)
    if not overflow or not words:
        return None
    # more readings than PARSES: only those whose three words are known words, each checked as it grows
    found, _ = _slugs(items[end:], _Budget(), _Words(words))
    return _choose(found, words, saved) if found else None


# ---------------------------------------------------------------------------- the codes

_SQ_IJ = "abcdefghiklmnopqrstuvwxyz"     # Polybius: i and j share 24
_SQ_CK = "abcdefghijlmnopqrstuvwxyz"     # tap code: k is written as c
_MERGED = {"ij": {"i": ("i", "j")}, "ck": {"c": ("c", "k")}}


def _square(kind, r, c):
    sq = _SQ_IJ if kind == "ij" else _SQ_CK
    letter = sq[(r - 1) * 5 + (c - 1)]
    return _MERGED[kind].get(letter, (letter,))


def _pass(tok):
    """The items of a token that is no symbol of the code: digits, marks and separators as they are."""
    out = []
    for ch in tok:
        if ch == "/" or ch == "|":
            out.append((" ",))
        elif ch.isdigit() or ch in _SEPS or ch in _MARKS:
            out.append((ch,))
        else:
            return None
    return out


def _words(text):
    """Whitespace tokens, with a word break item where the text marks one: ' / ' or a run of two or more
    blanks when there is one, else every blank."""
    t = text.strip()
    if "/" in t or "|" in t or re.search(r" {2,}|\n", t):
        parts = re.split(r"\s*[/|]\s*| {2,}|\s*\n\s*", t)
        out = []
        for k, p in enumerate(parts):
            if k:
                out.append(None)
            out += p.split()
        return out
    out = []
    for k, p in enumerate(t.split()):
        if k:
            out.append(None)
        out.append(p)
    return out


def polybius_items(text, kind="ij", order="rc"):
    """Coordinates of a 5 x 5 square, `rc` or `r,c` per letter; anything else as it stands."""
    if not re.search(r"\b[1-5],?[1-5]\b", text):
        return None
    items = []
    for tok in _words(text):
        if tok is None:
            items.append((" ",))
            continue
        m = re.fullmatch(r"([1-5]),?([1-5])", tok)
        if m:
            r, c = int(m.group(1)), int(m.group(2))
            if order == "cr":
                r, c = c, r
            opts = _square(kind, r, c)
            items.append(opts + ((m.group(1) + m.group(2)),) if "," not in tok else opts)
            continue
        p = _pass(tok)
        if p is None:
            return None
        items += p
    return items


_DOTS = re.compile(r"[.•*·]+")


def tap_items(text, kind="ck"):
    """Tap code written as runs of knocks (dots), two runs a letter; anything else as it stands."""
    if not _DOTS.search(text) or re.search(r"[A-Za-z]", text):
        return None
    items, half = [], None
    for tok in _words(text):
        if tok is None:
            if half is not None:
                return None
            items.append((" ",))
            continue
        if _DOTS.fullmatch(tok):
            n = len(tok)
            if n > 5:
                return None
            if half is None:
                half = n
            else:
                items.append(_square(kind, half, n))
                half = None
            continue
        if half is not None:
            return None
        p = _pass(tok)
        if p is None:
            return None
        items += p
    return items if half is None else None


def a1z26_items(text):
    """A1Z26: a number 1 to 26 is its letter or itself; a hyphen, comma or period between two numbers
    is a joiner or itself."""
    if not re.fullmatch(r"[0-9\s/|,.:!\-]+", text.strip()) or not re.search(r"\b(?:1[0-9]|2[0-6])\b", text):
        return None
    items = []
    for tok in _words(text):
        if tok is None:
            items.append((" ",))
            continue
        pieces = re.findall(r"\d+|-{2,}|\D", tok)
        for k, x in enumerate(pieces):
            if len(x) > 1 and set(x) == {"-"}:
                items.append(("-",))            # a run of hyphens: joiners around the slug's own hyphen
            elif x.isdigit():
                v = int(x)
                if len(x) > 2:
                    return None
                items.append(((chr(96 + v), x) if 1 <= v <= 26 else (x,)))
            elif x in "-,." and 0 < k < len(pieces) - 1 and pieces[k - 1].isdigit() and pieces[k + 1].isdigit():
                items.append(("", WEAK if x == "-" else ""))
            else:
                p = _pass(x)
                if p is None:
                    return None
                items += p
    return items


_B24 = "abcdefghiklmnopqrstuwxyz"
_B24_MERGED = {"i": ("i", "j"), "u": ("u", "v")}


def bacon_items(text, variant=26, invert=False):
    """Bacon of the letters: five symbols of one pair a letter (a/b, A/B, 0/1); anything else as it
    stands. 26 letters, or 24 with i = j and u = v."""
    toks = [t for t in _words(text) if t]
    pair = None
    for a, b in (("a", "b"), ("A", "B"), ("0", "1")):
        if sum(1 for t in toks if len(t) == 5 and set(t) <= {a, b}) >= 20:
            pair = (a, b)
            break
    if pair is None:
        return None
    zero, one = (pair[1], pair[0]) if invert else pair
    items = []
    for tok in _words(text):
        if tok is None:
            items.append((" ",))
            continue
        if set(tok) <= set(pair) and len(tok) % 5 == 0 and (len(tok) == 5 or pair != ("0", "1")):
            for k in range(0, len(tok), 5):
                v = int(tok[k:k + 5].replace(zero, "0").replace(one, "1"), 2)
                if variant == 26:
                    if v > 25:
                        return None
                    items.append((_LETTERS[v],))
                else:
                    if v > 23:
                        return None
                    items.append(_B24_MERGED.get(_B24[v], (_B24[v],)))
            continue
        p = _pass(tok)
        if p is None:
            return None
        items += p
    return items


_BR = {"⠁": "a", "⠃": "b", "⠉": "c", "⠙": "d", "⠑": "e", "⠋": "f", "⠛": "g", "⠓": "h", "⠊": "i", "⠚": "j",
       "⠅": "k", "⠇": "l", "⠍": "m", "⠝": "n", "⠕": "o", "⠏": "p", "⠟": "q", "⠗": "r", "⠎": "s", "⠞": "t",
       "⠥": "u", "⠧": "v", "⠺": "w", "⠭": "x", "⠽": "y", "⠵": "z"}
_BR_MARK = {"⠖": "!", "⠂": ",", "⠒": ":", "⠤": "-", "⠲": ".", "⠆": ";"}
_BR_DIGIT = dict(zip("abcdefghij", "1234567890"))
_BR_CAP = "⠠"
_BR_NUM = "⠼"


def braille_items(text):
    """Grade-1 Braille of the text with its digits written as the letters a to j and NO number sign:
    a cell a to j is that letter or its digit."""
    if _BR_NUM in text or sum(c in _BR for c in text) < 40:
        return None
    items = []
    for ch in text.strip():
        if ch in _BR:
            letter = _BR[ch]
            items.append((letter, _BR_DIGIT[letter]) if letter in _BR_DIGIT else (letter,))
        elif ch in _BR_MARK:
            items.append((_BR_MARK[ch],))
        elif ch == _BR_CAP:
            items.append(("",))
        elif ch.isspace() or ch == "⠀":
            items.append((" ",))
        else:
            return None
    return items


def _bytes_items(nibbles):
    """Items of characters from a list of nibble options, two a byte: every printable ASCII byte the
    options allow."""
    if len(nibbles) % 2:
        return None
    items = []
    for k in range(0, len(nibbles), 2):
        opts = tuple(sorted({chr(h * 16 + l) for h in nibbles[k] for l in nibbles[k + 1] if 32 <= h * 16 + l < 127}))
        if not opts:
            return None
        items.append(opts)
    return items


def braille_hex_items(text):
    """The text as hex, each hex digit a Braille cell with NO number sign: the cells a to f are the hex
    letters or the digits 1 to 6, g to j the digits 7, 8, 9, 0."""
    cells = [c for c in text if not c.isspace()]
    if _BR_NUM in text or len(cells) < 160 or any(c not in _BR or _BR[c] not in _BR_DIGIT for c in cells):
        return None
    nib = []
    for c in cells:
        letter = _BR[c]
        digit = int(_BR_DIGIT[letter])
        nib.append((digit, 10 + "abcdef".index(letter)) if letter in "abcdef" else (digit,))
    return _bytes_items(nib)


def tap_hex_items(text):
    """The text as hex, each hex digit as the letters a to p (0 = a), in the 5 x 5 tap code where k is
    written as c: the cell c is the hex digit 2 or a (10)."""
    if not _DOTS.search(text) or re.search(r"[A-Za-z0-9]", text):
        return None
    runs = [len(t) for t in _DOTS.findall(text)]
    if len(runs) % 2 or len(runs) < 320 or max(runs) > 5:
        return None
    nib = []
    for k in range(0, len(runs), 2):
        letter = _SQ_CK[(runs[k] - 1) * 5 + runs[k + 1] - 1]
        if letter > "p":
            return None
        nib.append((2, 10) if letter == "c" else ("abcdefghijklmnop".index(letter),))
    return _bytes_items(nib)


def leet_items(text, crib):
    """Leetspeak: some letters written as digits or symbols, one character for one. The table is
    learned from the sentence (a letter written as a non-letter); a character of the slug is what the
    table says it stands for, or itself."""
    t = text.strip()
    if len(t) < len(crib) + 9:
        return None
    sub, count = {}, 0
    for b, c in zip(t, crib):
        if b.lower() == c.lower():
            continue
        if not c.isalpha() or b.isalpha() or b.isspace():
            return None
        sub.setdefault(b, set()).add(c.lower())
        count += 1
    if count < 6 or len(sub) < 3:
        return None
    items = [(c,) for c in crib]
    for ch in t[len(crib):]:
        opts = set(sub.get(ch, ()))
        low = ch.lower()
        if low.isalpha() and low.isascii():
            opts.add(low)
        elif ch.isdigit() or ch in _SEPS or ch in _MARKS:
            opts.add(ch)
        elif ch.isspace():
            opts.add(" ")
        if not opts:
            return None
        items.append(tuple(sorted(opts)))
    return items


# code name, item builder, whether its table is a fixed standard one (a reading `as_read` may become
# plain once judged) or learned from the sentence (never plain)
def _codes(crib):
    yield "polybius5", lambda t: polybius_items(t, "ij", "rc"), True
    yield "polybius5_cr", lambda t: polybius_items(t, "ij", "cr"), True
    yield "polybius5_ck", lambda t: polybius_items(t, "ck", "rc"), True
    yield "tap5", lambda t: tap_items(t, "ck"), True
    yield "tap5_ij", lambda t: tap_items(t, "ij"), True
    yield "a1z26_tokens", a1z26_items, True
    yield "bacon26", lambda t: bacon_items(t, 26), True
    yield "bacon24", lambda t: bacon_items(t, 24), True
    yield "bacon26_inv", lambda t: bacon_items(t, 26, True), True
    yield "bacon24_inv", lambda t: bacon_items(t, 24, True), True
    yield "braille_nosign", braille_items, True
    yield "braille_hex_nosign", braille_hex_items, True
    yield "tap5_hex", tap_hex_items, True
    yield "leet", lambda t: leet_items(t, crib), False
    try:   # Day 26 build: multi-tap and Pig Latin, lossy, so never fixed (never plain)
        import exotic as _EX
        yield "multitap", _EX.multitap_items, False
        yield "piglatin", _EX.piglatin_items, False
    except Exception:
        pass


def read(text, crib, words, saved=frozenset()):
    """(code, method, slugs, fixed) when exactly one code reads the text, else None. `slugs` holds one
    slug, or for the method `readings` up to READINGS of them, best first."""
    if not text or len(text) > MAX_TEXT:
        return None
    found = {}
    for code, build, fixed in _codes(crib):
        try:
            items = build(text)
        except Exception:
            items = None
        if not items:
            continue
        got = read_items(items, crib, words, saved)
        if got:
            found.setdefault(tuple(got[1]), (code, got[0], fixed))
    if not found:
        try:
            pf = playfair_read(text, crib, words, saved)
        except Exception:
            pf = None
        if pf:
            return "playfair", pf[1], list(pf[2]), False
    if len(found) != 1:
        return None
    slugs, (code, method, fixed) = next(iter(found.items()))
    return code, method, list(slugs), fixed


# ---------------------------------------------------------------------------- ciphertext autokey

AUTOKEY_PRIMER = 16   # longest primer looked for


def autokey_ct(text, crib):
    """The slug's letters of a ciphertext-autokey Vigenere, or None: (primer length, slug text as read,
    digits as they stand). The primer length k is the one for which every letter of the sentence after
    the k-th satisfies cipher[i] = plain[i] + cipher[i - k] (letters only, case kept); the slug's letters
    then decode with no key at all. A length that fits is proof only with 40 or more letters checked."""
    t = text.strip()
    if len(t) > MAX_TEXT:
        return None
    letters = [(i, c) for i, c in enumerate(t) if c.isalpha() and c.isascii()]
    pl = _crib_letters(crib)
    if len(letters) < len(pl) + 3:
        return None
    ct = [c.lower() for _, c in letters]
    # the sentence's marks and blanks must stand where they stand in the plain text
    if [c for c in t[:len(crib)] if not c.isalpha()] != [c for c in crib if not c.isalpha()]:
        return None
    fits = []
    for k in range(1, AUTOKEY_PRIMER + 1):
        if len(pl) - k < 40:
            break
        if all((ord(ct[i]) - ord(ct[i - k])) % 26 == ord(pl[i]) - 97 for i in range(k, len(pl))):
            fits.append(k)
    if len(fits) != 1:
        return None
    k = fits[0]
    out = list(t)
    for n, (i, c) in enumerate(letters):
        if n < len(pl):
            continue
        out[i] = chr((ord(ct[n]) - ord(ct[n - k])) % 26 + 97)
    return k, "".join(out[len(crib):]).strip()


# ---------------------------------------------------------------------------- Playfair

PLAYFAIR_KEYS = ("playfair", "huntress", "monarchy", "keyword", "secret", "cipher", "warmup", "warmups",
                 "huntressctf", "example", "password", "wheatstone", "playfaircipher", "decoding", "master",
                 "gamemaster", "answer", "solve", "submit", "ctf", "key")
PLAYFAIR_MAX_KEYS = 400   # keys tried: the list above and the saved slugs' words
PLAYFAIR_FILLERS = 6      # filler x's whose place is open, at most (2 ** this readings)


def _pf_square(key):
    seen = []
    for ch in (key.lower() + "abcdefghiklmnopqrstuvwxyz").replace("j", "i"):
        if ch.isalpha() and ch.isascii() and ch not in seen:
            seen.append(ch)
    return "".join(seen), {ch: divmod(i, 5) for i, ch in enumerate(seen)}


def _pf_decrypt(letters, key):
    sq, pos = _pf_square(key)
    out = []
    for k in range(0, len(letters) - 1, 2):
        a, b = letters[k], letters[k + 1]
        if a == b or a not in pos or b not in pos:
            return None
        (ra, ca), (rb, cb) = pos[a], pos[b]
        if ra == rb:
            out += [sq[ra * 5 + (ca - 1) % 5], sq[rb * 5 + (cb - 1) % 5]]
        elif ca == cb:
            out += [sq[((ra - 1) % 5) * 5 + ca], sq[((rb - 1) % 5) * 5 + cb]]
        else:
            out += [sq[ra * 5 + cb], sq[rb * 5 + ca]]
    return "".join(out)


def _pf_prep(letters):
    """Playfair's preparation of plain letters (j as i, x between a double in one pair), without the
    filler at the end."""
    t = letters.replace("j", "i")
    out, i = [], 0
    while i < len(t):
        a = t[i]
        b = t[i + 1] if i + 1 < len(t) else None
        if b is None:
            out.append(a)
            break
        if a == b:
            out += [a, "x"]
            i += 1
        else:
            out += [a, b]
            i += 2
    return "".join(out)


def _pf_unprep(p, budget):
    """Every plain letter string the prepared text p can come from: an x in the second place of a pair
    whose letters around it are equal, and an x at the end, may be fillers."""
    places = [k for k in range(1, len(p), 2) if p[k] == "x" and k + 1 < len(p) and p[k - 1] == p[k + 1]]
    if p.endswith("x") and len(p) % 2 == 0:
        places.append(len(p) - 1)
    if len(places) > PLAYFAIR_FILLERS:
        return None
    outs = set()
    for mask in range(1 << len(places)):
        if not budget.step():
            return None
        drop = {places[b] for b in range(len(places)) if mask >> b & 1}
        outs.add("".join(c for k, c in enumerate(p) if k not in drop))
    return outs


def _ij(word, words):
    """The known words a Playfair word (j read as i) can be: each i may be a j."""
    spots = [k for k, c in enumerate(word) if c == "i"]
    if len(spots) > 4:
        return [word] if word in words else []
    out = []
    for mask in range(1 << len(spots)):
        w = list(word)
        for b in range(len(spots)):
            if mask >> b & 1:
                w[spots[b]] = "j"
        w = "".join(w)
        if w in words:
            out.append(w)
    return out


def playfair_read(text, crib, words, saved=frozenset()):
    """(key, method, slugs) for a Playfair text, or None. The cipher letters (case and every non-letter
    left out) are deciphered under each key of PLAYFAIR_KEYS and of the saved slugs' words; a key is the
    key only when the deciphered text, its fillers taken out, starts with the sentence's 68 letters (which
    proves it), and exactly one key does. The slug's letters run together with no word breaks, so its three
    words are the known words they can be split into; its digits are the text's own two digits. One slug is
    `vocabulary`, two to READINGS are `readings`."""
    t = text.strip()
    if len(t) > MAX_TEXT or re.search(r"[^A-Za-z0-9\s\-:,.!]", t):
        return None
    letters = "".join(c.lower() for c in t if c.isalpha() and c.isascii())
    digits = "".join(c for c in t if c.isdigit())
    cl = _crib_letters(crib)
    if len(digits) != 2 or len(letters) % 2 or len(letters) < len(cl) + 6 or "j" in letters:
        return None
    want = _pf_prep(cl)[:len(cl) - 2]
    keys = list(dict.fromkeys(list(PLAYFAIR_KEYS) + sorted(w for w in saved if w.isalpha())))[:PLAYFAIR_MAX_KEYS]
    hits = []
    for key in keys:
        p = _pf_decrypt(letters, key)
        if p is not None and p.startswith(want):
            hits.append((key, p))
    if len(hits) != 1:
        return None
    key, p = hits[0]
    budget = _Budget()
    plains = _pf_unprep(p, budget)
    if not plains:
        return None
    slugs = set()
    ci = cl.replace("j", "i")
    for plain in plains:
        if not plain.startswith(ci):
            continue
        tail = plain[len(ci):]
        for i in range(3, len(tail) - 5):
            for j in range(i + 3, len(tail) - 2):
                if not budget.step():
                    return None
                ws = [_ij(tail[:i], words), _ij(tail[i:j], words), _ij(tail[j:], words)]
                for a in ws[0]:
                    for b in ws[1]:
                        for c in ws[2]:
                            slugs.add(f"{a}-{b}-{c}-{digits}")
                            if len(slugs) > PARSES:
                                return None
    if not slugs:
        return None
    got = _choose(slugs, words, saved) if len(slugs) > 1 else ("vocabulary", sorted(slugs))
    return (key,) + got if got else None
