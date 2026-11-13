"""Keyed classical ciphers read off the sentence (Day 20 coverage build, second round, 2026-10-20).

The Warmups blob is the fixed sentence (crib_decode.CRIB) and the slug. The sentence gives 68 known plain
letters, and each cipher here is broken with them: its key (or square, or matrix) is whatever makes the cipher
text the sentence, found by a known-plaintext attack, never by a word list of keys:

  runkey     a running key (Vigenere, Beaufort or variant Beaufort over letters, case and the rest kept): the
             key stream the sentence gives repeats with one period of 27 to 52 letters (16 or more letters
             checked; 26 and fewer are crib_vigenere's), or is a stretch of a well-known text (RUNKEY_TEXTS, 68
             letters matched) that still has letters for the whole slug (a key past the text's end is no
             reading), and then all three slug words must be known words (an author's copy may go on otherwise).
  hill2/3   a Hill cipher of 2 x 2 or 3 x 3 over the letters (c = K p mod 26, a = 0): each row of K is the one
             vector mod 2 and the one mod 13 that every known block fits (22 to 34 blocks: a fit is proof).
  bifid5/6   a bifid over a 5 x 5 (i = j) or 6 x 6 (letters and digits) square, the whole text or a period of
             2 to 20: the square's rows and columns are unknowns tied together by the fractionation; the
             sentence ties them into classes, and every way (at most BIFID_GROUPINGS) to give the classes 5 (6)
             values with no two symbols in one cell is read; one way and every cell held is `exact`. A 6 x 6
             square is often left open by the sentence (its digits are no sentence symbols): mostly None.
  adfgx/vx   ADFGX and ADFGVX: the coordinate letters under a columnar transposition of 2 to 12 columns, the
             column order walked from the sentence; the square's cells the sentence fills are proven.
  nihilist5  a Nihilist cipher (square value plus the key letter's value, 5 x 5): the key period of 1 to 20
             and the rows and columns of the square and the key, each tied to the sentence by differences;
             only when every one of them is pinned.

A plain cell no sentence letter holds (f, j, q, y, z and the digits are not in the sentence) is filled where
the square is a keyword square (the keyword's letters, then the rest of a standard alphabet in order:
`_kw_cells`); a reading that needed that, or a cell left open (every unplaced symbol is an option), is never
`exact`. What follows the sentence must parse as one slug (lossy_codes.read_items for a text that keeps its
blanks and hyphens; the slug's letters split into three known words for one that keeps only letters, the
digits being the text's own two or the stream's last two).

Nothing here is plain on its own word: crib_decode._lattice files a reading under `warmups.lossy/<code>` and
picks it under the day rule only when it is `exact` and `as_read` (every slug character read through a cell
the sentence proved); anything else stays unsure. The running key's digits are open, as every Vigenere-family
reading's: `warmups.digits/runkey` (as_is, rot5).

Asked by crib_decode only for a whole blob (one payload) that every other reader, lossy_codes included, left
None. Bounded by counts (STEPS) and by the blob's deadline: a read the deadline stopped returns CUT, and
crib_decode says so in its note so that solve_blob reads the blob a second time.
"""
import itertools
import re
import time

import lossy_codes as LC

CUT = "cut"
STEPS = 400000        # inner steps of all the attacks on one blob together
MAX_TEXT = 4000       # characters of a blob looked at
MIN_SLUG = 8          # plain symbols after the sentence at least (three words of 3 and two digits, run together)
MAX_SLUG = 64         # plain symbols after the sentence at most (the longest saved slug has 30 characters)

A25 = "abcdefghiklmnopqrstuvwxyz"            # i and j share a cell
A36 = "abcdefghijklmnopqrstuvwxyz0123456789"
A36I = "a1b2c3d4e5f6g7h8i9j0klmnopqrstuvwxyz"  # the ADFGVX textbook order
A36D = "0123456789abcdefghijklmnopqrstuvwxyz"
KW_MAX = 15           # keyword letters (after removing repeats) a keyword square may start with
KW_OPTIONS = 4000     # completions looked at, at most, before a cell is left open


class _Cut(Exception):
    pass


class _Over(Exception):
    pass


class _Clock:
    def __init__(self, deadline):
        self.deadline, self.left = deadline, STEPS

    def tick(self, n=1):
        self.left -= n
        if self.left < 0:
            raise _Over()
        if self.deadline is not None and (self.left & 255) < n and time.perf_counter() > self.deadline:
            raise _Cut()


def _crib_letters(crib):
    return "".join(c.lower() for c in crib if c.isalpha())


class Reading:
    """One way a family reads the blob. `keep`: items for the whole text, blanks and marks as they stand
    (lossy_codes.read_items reads it). `run`: items of the plain symbols after the sentence, run together."""

    def __init__(self, code, chain, layout, items, exact, digits=None, pad=0, digits_open=False, words=0):
        self.code, self.chain, self.layout, self.items, self.exact = code, chain, layout, items, exact
        self.digits, self.pad, self.digits_open, self.words = digits, pad, digits_open, words


# ---------------------------------------------------------------------------- layouts

def _keeps(t, crib, sym):
    """True when t starts as the sentence does, every letter of the sentence a cipher symbol (`sym`) and
    every other character the sentence's own."""
    if len(t) < len(crib) + MIN_SLUG:
        return False
    for a, b in zip(t, crib):
        if b.isalpha():
            if not sym(a):
                return False
        elif a != b:
            return False
    return True


def _alpha(c):
    return c.isascii() and c.isalpha()


def _alnum(c):
    return c.isascii() and c.isalnum()


def _letters_only(t):
    """(letters, digits) of a text of letters in blocks (white space anywhere) and at most a few digits, or None."""
    if re.search(r"[^A-Za-z0-9\s]", t):
        return None
    letters = "".join(c.lower() for c in t if c.isalpha())
    digits = "".join(c for c in t if c.isdigit())
    return letters, digits


def _ij(c, merged):
    return ("i", "j") if merged and c == "i" else (c,)


# ---------------------------------------------------------------------------- running key

RUNKEY_PERIOD = 60       # longest key period looked for (Day 26: was 52; 68 - 60 = 8 letters checked at least)
RUNKEY_SHORT = 26       # periods crib_vigenere reads (Caesar, Vigenere, Beaufort, Trithemius): not this reader's
RUNKEY_TEXTS = {
    "lorem": "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et "
             "dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip "
             "ex ea commodo consequat duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore "
             "eu fugiat nulla pariatur",
    "fox": "the quick brown fox jumps over the lazy dog",
    "constitution": "we the people of the united states in order to form a more perfect union establish justice insure "
                    "domestic tranquility provide for the common defence promote the general welfare",
    "declaration": "when in the course of human events it becomes necessary for one people to dissolve the political "
                   "bands which have connected them with another",
    "gettysburg": "four score and seven years ago our fathers brought forth on this continent a new nation conceived "
                  "in liberty and dedicated to the proposition that all men are created equal",
    "dickens": "it was the best of times it was the worst of times it was the age of wisdom it was the age of "
               "foolishness it was the epoch of belief",
    "melville": "call me ishmael some years ago never mind how long precisely having little or no money in my purse "
                "and nothing particular to interest me on shore",
    "hamlet": "to be or not to be that is the question whether tis nobler in the mind to suffer the slings and "
              "arrows of outrageous fortune",
}
try:   # Day 26 build: longer public-domain key texts (exotic.py)
    import exotic as _EX
    for _k, _v in _EX.EXTRA_RUNKEY_TEXTS.items():
        RUNKEY_TEXTS.setdefault(_k, _v)
except Exception:
    pass
_MODES = {"vig": (lambda c, p: (c - p) % 26, lambda c, k: (c - k) % 26),
          "beau": (lambda c, p: (c + p) % 26, lambda c, k: (k - c) % 26),
          "var": (lambda c, p: (p - c) % 26, lambda c, k: (c + k) % 26)}


def _runkey(t, crib, clock):
    if not _keeps(t, crib, _alpha):
        return []
    pl = [ord(c) - 97 for c in _crib_letters(crib)]
    pos = [i for i, c in enumerate(t) if _alpha(c)]
    ct = [ord(t[i].lower()) - 97 for i in pos]
    if not len(pl) + 3 <= len(ct) <= len(pl) + MAX_SLUG:
        return []
    out, texts = [], {}
    for mode, (key_of, plain_of) in _MODES.items():
        ks = [key_of(c, p) for c, p in zip(ct, pl)]
        keys = []
        for period in range(1, RUNKEY_PERIOD + 1):
            clock.tick(len(pl) - period)
            if all(ks[i] == ks[i + period] for i in range(len(pl) - period)):
                if period <= RUNKEY_SHORT:
                    break       # a key of 26 letters or fewer: crib_vigenere's (and Caesar's), read before this
                keys.append(("%s.p%d" % (mode, period), lambda n, period=period, ks=ks: ks[n % period]))
                break
        else:
            period = 0
        if period and period <= RUNKEY_SHORT:
            continue
        if not keys:
            word = "".join(chr(k + 97) for k in ks)
            for name, body in RUNKEY_TEXTS.items():
                letters = "".join(c for c in body if c.isalpha())
                clock.tick(len(letters))
                at = letters.find(word)
                # the slug's key letters must be the text's own: a key that ran past the text's end went on with
                # something the text does not say (its start again, another text), which nothing here proves
                if 0 <= at and at + len(ct) <= len(letters):
                    keys.append(("%s.%s@%d" % (mode, name, at),
                                 lambda n, at=at, letters=letters: ord(letters[at + n]) - 97))
        for name, key in keys:
            chars = list(t)
            for n, i in enumerate(pos):
                v = plain_of(ct[n], key(n))
                chars[i] = chr(v + (65 if t[i].isupper() else 97))
            text = "".join(chars)
            if text not in texts:
                texts[text] = name
                # a stretch of a known text is the author's copy of it: its three words must all be known
                # words, so a copy that goes on otherwise than ours gives nothing (a period is proven: two)
                out.append(Reading("runkey", "runkey:" + name, "keep", [(c.lower(),) for c in text], True,
                                   digits_open=True, words=3 if "@" in name else 2))
    return out


# ---------------------------------------------------------------------------- Hill

def _hill_inverse(K):
    n = len(K)
    if n == 2:
        (a, b), (c, d) = K
        det, adj = a * d - b * c, [[d, -b], [-c, a]]
    else:
        def cof(r, c):
            m = [[K[i][j] for j in range(3) if j != c] for i in range(3) if i != r]
            return (-1) ** (r + c) * (m[0][0] * m[1][1] - m[0][1] * m[1][0])
        det = sum(K[0][j] * cof(0, j) for j in range(3))
        adj = [[cof(j, i) for j in range(3)] for i in range(3)]
    try:
        inv = pow(det % 26, -1, 26)
    except ValueError:
        return None
    return [[(inv * x) % 26 for x in row] for row in adj]


def _hill_key(ct, pl, n, clock):
    """The one n x n matrix (c = K p mod 26) that every known block fits, or None."""
    nb = len(pl) // n
    if nb < 3 * n:
        return None
    rows = []
    for r in range(n):
        parts = []
        for mod in (2, 13):
            sols = []
            for k in itertools.product(range(mod), repeat=n):
                clock.tick()
                for b in range(nb):
                    at = b * n
                    if (sum(k[j] * pl[at + j] for j in range(n)) - ct[at + r]) % mod:
                        break
                else:
                    sols.append(k)
                    if len(sols) > 1:
                        return None
            if len(sols) != 1:
                return None
            parts.append(sols[0])
        rows.append([b13 + 13 * ((b2 - b13) % 2) for b2, b13 in zip(*parts)])
    return rows


def _hill(t, crib, clock):
    out = []
    pl = [ord(c) - 97 for c in _crib_letters(crib)]
    keep = _keeps(t, crib, _alpha)
    if keep:
        pos = [i for i, c in enumerate(t) if _alpha(c)]
        ct = [ord(t[i].lower()) - 97 for i in pos]
        digits = None
    else:
        got = _letters_only(t)
        if got is None:
            return out
        ct = [ord(c) - 97 for c in got[0]]
        digits = got[1]
    if not len(pl) + MIN_SLUG - 2 <= len(ct) <= len(pl) + MAX_SLUG:
        return out
    for n in (2, 3):
        if len(ct) % n:
            continue
        K = _hill_key(ct, pl, n, clock)
        inv = _hill_inverse(K) if K else None
        if inv is None:
            continue
        plain = []
        for at in range(0, len(ct), n):
            block = ct[at:at + n]
            plain += [sum(inv[r][j] * block[j] for j in range(n)) % 26 for r in range(n)]
        if plain[:len(pl)] != pl:
            continue
        name = "hill%d" % n
        chain = "%s:%s" % (name, ".".join(str(x) for row in K for x in row))
        if keep:
            chars = list(t)
            for m, i in enumerate(pos):
                chars[i] = chr(plain[m] + 97)
            text = "".join(chars).lower()
            # pad letters after the slug's digits (the text's letters were not a multiple of n)
            tail = re.match(r"(.*\d)([a-z]{1,%d})\s*$" % (n - 1), text, re.S)
            if tail:
                text = tail.group(1)
            out.append(Reading(name, chain, "keep", [(c,) for c in text], True))
        else:
            tail = [(chr(x + 97),) for x in plain[len(pl):]]
            out.append(Reading(name, chain, "run", tail, True, digits=digits, pad=n - 1))
    return out


# ---------------------------------------------------------------------------- keyword squares

def _kw_cells(cells, alphas, clock):
    """(keyword length, {cell index: set of symbols}) for the empty cells of a square (row-major list, None where
    open) that is a keyword square in one of `alphas` (the keyword's symbols, then the rest of the alphabet in
    order) with the SHORTEST keyword that fits (up to KW_MAX), the union over the alphabets and over every way
    the open symbols can sit at that length (W3's rule: the shortest keyword alphabet); None when it is none."""
    n = len(cells)
    placed = {c for c in cells if c is not None}
    ways = []
    for alpha in alphas:
        if len(alpha) != n or not placed <= set(alpha):
            continue
        rank = {s: i for i, s in enumerate(alpha)}
        last, m0 = n + 1, 0
        for i in range(n - 1, -1, -1):
            s = cells[i]
            if s is not None:
                if rank[s] > last:
                    m0 = i + 1
                    break
                last = rank[s]
        ways.append((alpha, [s for s in alpha if s not in placed], m0))
    if not ways:
        return None
    seen = 0
    for m in range(min(w[2] for w in ways), min(KW_MAX, n) + 1):     # the shortest keyword first
        found = {}
        prefix = cells[:m]
        u = prefix.count(None)
        pre = {s for s in prefix if s is not None}
        for alpha, unseen, m0 in ways:
            if m < m0:
                continue
            rest = [s for s in alpha if s not in pre]
            for take in itertools.combinations(unseen, u):
                seen += 1
                clock.tick()
                if seen > KW_OPTIONS:
                    return None
                drop = set(take)
                suffix = [s for s in rest if s not in drop]
                if len(suffix) != n - m:
                    continue
                if any(c is not None and c != s for c, s in zip(cells[m:], suffix)):
                    continue
                for k, c in enumerate(cells):
                    if c is None:
                        found.setdefault(k, set()).update(drop if k < m else {suffix[k - m]})
        if found:
            return m, found
    return None


# ---------------------------------------------------------------------------- bifid

BIFID_PERIODS = tuple(range(2, 21))


class _UF:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        p = self.p
        while p[x] != x:
            p[x] = p[p[x]]
            x = p[x]
        return x

    def union(self, a, b):
        a, b = self.find(a), self.find(b)
        if a != b:
            self.p[a] = b


BIFID_GROUPINGS = 8   # ways to number the square's classes that fit, at most, before a period is given up
BIFID_FILLED = 2      # groupings at most whose open cells are filled as a keyword square (720 numberings each at 6 x 6)


def _groupings(cell, classes, size, clock):
    """Every way (up to renaming the values, at most BIFID_GROUPINGS) to give the classes values 0 to size-1
    so that no two symbols share a cell: [{class: value}], or None when there are more."""
    touch = {c: [] for c in classes}
    for key, s in cell.items():
        for c in set(key):
            touch[c].append(key)
    order = sorted(classes, key=lambda c: -len(touch[c]))
    out, g, held = [], {}, set()

    def walk(i, groups):
        if len(out) > BIFID_GROUPINGS:
            return
        if i == len(order):
            out.append(dict(g))
            return
        c = order[i]
        for v in range(min(groups + 1, size)):
            clock.tick()
            g[c] = v
            added = []
            for x, y in touch[c]:
                if x in g and y in g:
                    k = (g[x], g[y])
                    if k in held:
                        break
                    held.add(k)
                    added.append(k)
            else:
                walk(i + 1, max(groups, v + 1))
            for k in added:
                held.discard(k)
            del g[c]

    walk(0, 0)
    return out if 0 < len(out) <= BIFID_GROUPINGS else None


def _bifid_solve(cs, pl, alpha, period, clock):
    """(plain cells after the sentence as (row class, col class), {cell: symbol}, groupings) or None. The
    classes are the coordinates the fractionation ties together; a grouping gives them values (_groupings)."""
    N, K, size = len(cs), len(pl), 5 if len(alpha) == 25 else 6
    idx = {s: i for i, s in enumerate(alpha)}
    base = 2 * len(alpha)
    uf = _UF(base + 2 * (N - K))

    def rowv(i):
        return 2 * idx[pl[i]] if i < K else base + 2 * (i - K)

    for b in range(0, N, period):
        L = min(period, N - b)
        seq = [rowv(i) for i in range(b, b + L)] + [rowv(i) + 1 for i in range(b, b + L)]
        clock.tick(L)
        for k in range(L):
            c = 2 * idx[cs[b + k]]
            uf.union(c, seq[2 * k])
            uf.union(c + 1, seq[2 * k + 1])
    seen = set(pl) | set(cs)
    cell = {}
    for s in seen:
        key = (uf.find(2 * idx[s]), uf.find(2 * idx[s] + 1))
        if cell.setdefault(key, s) != s:
            return None
    plain = [(uf.find(rowv(i)), uf.find(rowv(i) + 1)) for i in range(K, N)]
    classes = {x for key in cell for x in key} | {x for key in plain for x in key}
    if len(classes) > 2 * size:
        return None
    groups = _groupings(cell, classes, size, clock)
    return (plain, cell, groups) if groups else None


def _bifid_fill(plain, cell, groups, alpha, alphas, clock):
    """Items for the plain cells, over every grouping: the symbol a cell holds; for an open cell, what a
    keyword square with the shortest keyword puts there (over every numbering of the values), else every
    symbol not placed. (items, exact): exact when there is one grouping and every cell is held."""
    size = 5 if len(alpha) == 25 else 6
    merged = len(alpha) == 25
    unseen = sorted(set(alpha) - set(cell.values()))
    opts = [set() for _ in plain]
    exact = len(groups) == 1
    for g in groups:
        held = {(g[x], g[y]): s for (x, y), s in cell.items()}
        keys = [(g[x], g[y]) for x, y in plain]
        open_cells = {k for k in keys if k not in held}
        values = sorted(set(g.values()))
        fills, best = {}, None
        if open_cells and unseen and len(groups) <= BIFID_FILLED:
            for perm in itertools.permutations(range(size), len(values)):
                clock.tick(4)
                num = dict(zip(values, perm))
                sq = [None] * (size * size)
                for (x, y), s in held.items():
                    sq[num[x] * size + num[y]] = s
                got = _kw_cells(sq, alphas, clock)
                if not got or (best is not None and got[0] > best):
                    continue
                if best is None or got[0] < best:
                    best, fills = got[0], {}
                for k in open_cells:
                    fills.setdefault(k, set()).update(got[1].get(num[k[0]] * size + num[k[1]], ()))
        for n, k in enumerate(keys):
            s = held.get(k)
            if s is not None:
                opts[n].add(s)
            else:
                exact = False
                opts[n].update(fills.get(k) or unseen)
    items = [tuple(sorted({o for s in o_ for o in _ij(s, merged)})) for o_ in opts]
    exact = exact and all(len(o) == 1 for o in opts)
    return items, exact


def _bifid(t, crib, clock):
    out = []
    pl = _crib_letters(crib)
    for alpha in (A25, A36):
        size = 5 if alpha is A25 else 6
        is_sym = (lambda c: _alpha(c) and c.lower() != "j") if size == 5 else _alnum
        keep = _keeps(t, crib, is_sym)
        if keep:
            pos = [i for i, c in enumerate(t) if is_sym(c)]
            cs = [t[i].lower() for i in pos]
            digits = None
        else:
            got = _letters_only(t)
            if got is None:
                continue
            if size == 5:
                cs, digits = list(got[0]), got[1]
                if "j" in cs:
                    continue
            else:
                cs, digits = [c.lower() for c in t if _alnum(c)], None
        if not len(pl) + MIN_SLUG - 2 <= len(cs) <= len(pl) + MAX_SLUG or any(c not in alpha for c in cs):
            continue
        alphas = (A25,) if size == 5 else (A36, A36D, A36I)
        found = []
        for period in (len(cs),) + BIFID_PERIODS:
            if period >= len(cs) and found:
                continue
            got = _bifid_solve(cs, pl, alpha, period, clock)
            if got:
                found.append((period, got))
        for period, (plain, cell, groups) in found:
            items, exact = _bifid_fill(plain, cell, groups, alpha, alphas, clock)
            name = "bifid%d" % size
            chain = "%s:%s" % (name, "all" if period >= len(cs) else period)
            if keep:
                full = [(c.lower(),) for c in t]
                for m, i in enumerate(pos):
                    full[i] = (pl[m],) if m < len(pl) else items[m - len(pl)]
                out.append(Reading(name, chain, "keep", full, exact))
            else:
                out.append(Reading(name, chain, "run", items, exact, digits=digits))
    return out


# ---------------------------------------------------------------------------- ADFGX and ADFGVX

ADFGX_COLUMNS = range(2, 13)
ADFGX_ORDERS = 4          # column orders of one width that fit, at most, before the width is given up


def _adfgx_orders(ct, pl, w, lbl, clock):
    """Column orders (read-out order of the columns) of width w under which the sentence's coordinates fit
    one square, each with that square's part ({letter: (row, col)})."""
    N, K = len(ct), len(pl)
    full, extra = divmod(N, w)
    size = [full + (c < extra) for c in range(w)]
    coord, cellof, order, sols = {}, {}, [], []

    def place(at, used):
        if len(sols) > ADFGX_ORDERS:
            return
        if len(order) == w:
            sols.append((tuple(order), {s: (coord[(s, 0)], coord[(s, 1)]) for s in set(pl)}))
            return
        for c in range(w):
            if c in used:
                continue
            clock.tick()
            log, cells, ok = [], [], True
            for r in range(size[c]):
                f = c + w * r
                if f >= 2 * K:
                    break
                s, kind, x = pl[f // 2], f % 2, ct[at + r]
                have = coord.get((s, kind))
                if have is None:
                    coord[(s, kind)] = x
                    log.append((s, kind))
                    other = coord.get((s, 1 - kind))
                    if other is not None:
                        key = (x, other) if kind == 0 else (other, x)
                        if cellof.setdefault(key, s) != s:
                            ok = False
                            break
                        cells.append(key)
                elif have != x:
                    ok = False
                    break
            if ok:
                order.append(c)
                place(at + size[c], used | {c})
                order.pop()
            for key in cells:
                del cellof[key]
            for k in log:
                del coord[k]

    place(0, frozenset())
    return sols if len(sols) <= ADFGX_ORDERS else None


def _adfgx(t, crib, clock):
    out = []
    s = re.sub(r"\s+", "", t)
    if not s or re.search(r"[^ADFGVXadfgvx]", s) or len(s) % 2:
        return out
    ct = s.upper()
    v = "V" in ct
    for lbl in (("ADFGVX",) if v else ("ADFGX", "ADFGVX")):
        alpha = A36 if len(lbl) == 6 else A25
        merged = alpha is A25
        pl = _crib_letters(crib)
        if not len(pl) + MIN_SLUG - 2 <= len(ct) // 2 <= len(pl) + MAX_SLUG:
            return out
        for w in ADFGX_COLUMNS:
            if 2 * w > len(ct):
                break
            sols = _adfgx_orders(ct, pl, w, lbl, clock)
            for order, part in sols or ():
                full, extra = divmod(len(ct), w)
                frac, at = [None] * len(ct), 0
                for c in order:
                    n = full + (c < extra)
                    for r in range(n):
                        frac[c + w * r] = ct[at + r]
                    at += n
                cellof = {rc: sym for sym, rc in part.items()}
                size = len(lbl)
                sq = [None] * (size * size)
                for (r, c), sym in cellof.items():
                    sq[lbl.index(r) * size + lbl.index(c)] = sym
                unseen = sorted(set(alpha) - set(part))
                fills = None
                items, exact = [], True
                for i in range(len(pl), len(ct) // 2):
                    rc = (frac[2 * i], frac[2 * i + 1])
                    sym = cellof.get(rc)
                    if sym is not None:
                        items.append(_ij(sym, merged))
                        continue
                    exact = False
                    if fills is None:
                        fills = (_kw_cells(sq, (A25,) if merged else (A36, A36D, A36I), clock) or (0, {}))[1]
                    opts = fills.get(lbl.index(rc[0]) * size + lbl.index(rc[1])) or unseen
                    items.append(tuple(sorted({o for x in opts for o in _ij(x, merged)})))
                code = lbl.lower()
                chain = "%s:%s" % (code, ".".join(map(str, order)))
                digits = None if len(lbl) == 6 else "".join(c for c in t if c.isdigit())
                out.append(Reading(code, chain, "run", items, exact, digits=digits))
    return out


# ---------------------------------------------------------------------------- Nihilist

NIHILIST_PERIODS = range(1, 21)


class _WUF:
    """Union-find with differences: value[x] - value[root] = pot[x]."""

    def __init__(self, n):
        self.p, self.d = list(range(n)), [0] * n

    def find(self, x):
        path = []
        while self.p[x] != x:
            path.append(x)
            x = self.p[x]
        for y in reversed(path):
            if self.p[y] != x:
                self.d[y] += self.d[self.p[y]]
                self.p[y] = x
        return x

    def pot(self, x):
        self.find(x)
        return self.d[x]

    def union(self, a, b, diff):
        """value[a] - value[b] = diff; False on a contradiction."""
        ra, rb = self.find(a), self.find(b)
        da, db = self.d[a], self.d[b]
        if ra == rb:
            return da - db == diff
        self.p[ra] = rb
        self.d[ra] = diff - da + db
        return True


def _nihilist_axis(sums, pl, n_plain, period, clock):
    """Absolute values (1 to 5) of the square's rows (or columns) of the sentence's letters and of the plain
    symbols after it, from one coordinate of every number; None unless every one is pinned."""
    K = len(pl)
    letters = sorted(set(pl))
    li = {s: i for i, s in enumerate(letters)}
    nl = len(letters)
    # variables: letters, then the plain symbols after the sentence, then -key value per period place
    uf = _WUF(nl + (n_plain - K) + period)

    def pv(i):
        return li[pl[i]] if i < K else nl + (i - K)

    for i, s in enumerate(sums):
        clock.tick()
        if not uf.union(pv(i), nl + (n_plain - K) + i % period, s):
            return None
    span = {}
    for v in range(nl + (n_plain - K) + period):
        r = uf.find(v)
        lo, hi = (1, 5) if v < nl + (n_plain - K) else (-5, -1)
        a, b = span.get(r, (-99, 99))
        p = uf.pot(v)
        span[r] = (max(a, lo - p), min(b, hi - p))
    if any(a > b for a, b in span.values()) or any(a != b for a, b in span.values()):
        return None
    val = [span[uf.find(v)][0] + uf.pot(v) for v in range(nl + (n_plain - K))]
    return {s: val[li[s]] for s in letters}, [val[nl + j] for j in range(n_plain - K)]


def _nihilist(t, crib, clock):
    out = []
    toks = t.split()
    if len(toks) < 70:
        return out
    nums, items_at = [], []
    for k, tok in enumerate(toks):
        if re.fullmatch(r"\d{2,3}", tok) and 22 <= int(tok) <= 110:
            nums.append(int(tok))
            items_at.append(k)
        elif len(tok) > 1 and not re.fullmatch(r"[-!,:./|]+", tok):
            return out
    pl = _crib_letters(crib).replace("j", "i")
    if not len(pl) + 6 <= len(nums) <= len(pl) + MAX_SLUG or len(nums) < 0.7 * len(toks):
        return out
    rows, cols = [], []
    for n in nums:
        c = n % 10 or 10
        r = (n - c) // 10
        if c < 2 or not 2 <= r <= 10:
            return out
        rows.append(r)
        cols.append(c)
    readings = {}
    for period in NIHILIST_PERIODS:
        R = _nihilist_axis(rows, pl, len(nums), period, clock)
        C = _nihilist_axis(cols, pl, len(nums), period, clock) if R else None
        if not C:
            continue
        cellof = {}
        for s in set(pl):
            if cellof.setdefault((R[0][s], C[0][s]), s) != s:
                break
        else:
            sq = [None] * 25
            for (r, c), s in cellof.items():
                sq[(r - 1) * 5 + (c - 1)] = s
            fills, exact, plain = None, True, []
            for r, c in zip(R[1], C[1]):
                s = cellof.get((r, c))
                if s is not None:
                    plain.append(_ij(s, True))
                    continue
                exact = False
                if fills is None:
                    fills = (_kw_cells(sq, (A25,), clock) or (0, {}))[1]
                opts = fills.get((r - 1) * 5 + (c - 1)) or sorted(set(A25) - set(cellof.values()))
                plain.append(tuple(sorted({o for x in opts for o in _ij(x, True)})))
            items = [(tok,) for tok in toks]
            for m, k in enumerate(items_at):
                items[k] = plain[m - len(pl)] if m >= len(pl) else (pl[m],)
            key = tuple(items[items_at[len(pl)]:])
            if key not in readings:
                readings[key] = Reading("nihilist5", "nihilist5:p%d" % period, "keep", items, exact)
    return list(readings.values())


# ---------------------------------------------------------------------------- the slug

def _run_slugs(rd, words, saved, clock):
    """(method, slugs) for plain symbols run together: the letters split into three known words, the digits the
    stream's last two (or the text's own two)."""
    items = list(rd.items)
    digits = []
    while items and all(o.isdigit() for o in items[-1]) and len(digits) < 2:
        digits.insert(0, items.pop())
    if not digits:
        if not rd.digits or len(rd.digits) != 2:
            return None
        digits = [(d,) for d in rd.digits]
    if len(digits) != 2 or any(all(o.isdigit() for o in it) for it in items):
        return None
    tails = [""]
    for it in items:
        it = [o for o in it if o.isalpha()]
        if not it:
            return None
        tails = [a + o for a in tails for o in it]
        clock.tick(len(tails))
        if len(tails) > LC.PARSES:
            return None
    nums = ["".join(p) for p in itertools.product(*digits)]
    if len(nums) > 4:
        return None
    slugs = set()
    for tail in tails:
        for trim in range(0, rd.pad + 1):
            s = tail[:len(tail) - trim] if trim else tail
            for i in range(3, len(s) - 5):
                if s[:i] not in words:
                    continue
                for j in range(i + 3, len(s) - 2):
                    clock.tick()
                    if s[i:j] in words and s[j:] in words:
                        for d in nums:
                            slugs.add(f"{s[:i]}-{s[i:j]}-{s[j:]}-{d}")
                            if len(slugs) > LC.PARSES:
                                return None
    if not slugs:
        return None
    if len(slugs) == 1 and len(tails) == 1 and len(nums) == 1:
        return "vocabulary", sorted(slugs)
    return LC._choose(slugs, words, saved)


FAMILIES = (_runkey, _hill, _bifid, _adfgx, _nihilist)


def read(text, crib, words, saved=frozenset(), deadline=None):
    """{code, chain, method, slugs, exact, digits_open} when the blob's readings agree on one slug (or one set of
    candidate slugs), None when nothing reads it or two readings differ, CUT when the deadline stopped the work."""
    t = (text or "").strip()
    if not t or len(t) > MAX_TEXT:
        return None
    clock = _Clock(deadline)
    found = {}
    try:
        for family in FAMILIES:
            for rd in family(t, crib, clock):
                if rd.layout == "keep":
                    got = LC.read_items(rd.items, crib, words, saved)
                else:
                    got = _run_slugs(rd, words, saved, clock)
                if not got:
                    continue
                method, slugs = got
                found.setdefault(tuple(slugs), (rd, method))
    except _Cut:
        return CUT
    except _Over:
        return None
    if len(found) != 1:
        return None
    slugs, (rd, method) = next(iter(found.items()))
    return {"code": rd.code, "chain": rd.chain, "method": method, "slugs": list(slugs),
            "exact": bool(rd.exact) and method == "as_read", "digits_open": rd.digits_open, "words": rd.words}
