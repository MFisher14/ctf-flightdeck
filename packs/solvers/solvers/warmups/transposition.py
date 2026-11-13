"""Triple columnar transposition for Warmups (wave 2 breadth build, 2026-10-23).

Why this file exists
--------------------
solvers/common/classical.py reads single, double, Myszkowski, scytale, faro, redefence, route and
decimation transpositions off the sentence, but NOT triple columnar: three unknown column orders do
not fit the 0.35 s blob budget by brute force, so the lane rule listed it "Still None". This module
adds a crib-driven reader for it.

NEVER WRONG
-----------
A columnar transposition is information-preserving: a reading that reproduces the ENTIRE crib sentence
is the unique correct permutation, and the characters after the sentence (the slug) are then pinned too.
So `crib_triple_columnar` is answered PLAIN by the solver only when:

  * decrypting the cipher under some (o1, o2, o3) reproduces the full crib, AND
  * exactly ONE distinct full plaintext survives over every column triple searched.

If two column triples give two different full texts (the slug would be ambiguous), or the bounded search
is cut by its node/order cap or the deadline before it can prove uniqueness, it returns None -- never a
guessed permutation. The crib_decode search applies the crib a second time.

Method (bounded)
----------------
A triple columnar enciphers plaintext --E(o1)--> T1 --E(o2)--> T2 --E(o3)--> cipher. Decrypting is
D(o1)(D(o2)(D(o3)(cipher))). The two inner layers (o1, o2) are exactly what solvers/common/classical's
`crib_double_columnar` already solves with its own crib-walk and node cap, so this module enumerates only
the OUTERMOST order o3 (small column counts) and hands D(o3)(cipher) to crib_double_columnar as the
"double" to break. The outer enumeration is bounded by a hard order cap and, when a deadline is given, by
the clock; a cut returns None. This keeps the common path untouched (it is asked last, only for a whole
blob nothing else read that holds every crib character) and the worst case bounded.

No I/O, no global mutable state, no clock of its own (the deadline is passed in). Safe under warm().
"""

import itertools
import time

try:
    from _shadowed import common_module
    K = common_module("classical")  # common/classical.py by file: toolkits/classical.py wins a flat import
except Exception:                    # pragma: no cover - without it there is nothing to build on
    K = None

# crib_double_columnar costs ~3 ms per call, so proving uniqueness means that many outer orders fit the
# blob budget. Outer column counts 2..4 (sum k! = 32 orders, ~0.1 s worst case) are affordable; a wider
# outer keyword cannot be proved unique within the budget and is left None (cost, not correctness). The
# inner two layers still use crib_double_columnar's full 2..10 walk, so only the OUTERMOST keyword is
# length-limited.
OUTER_COLUMNS = range(2, 5)          # outermost column count tried (2..4)
ORDER_CAP = 40                       # outer orders tried before the search gives up (then None); 32 is the max
TIME_CAP = 0.15                      # hard internal wall-clock backstop (s): a run past it returns None
MAX_LEN = 4096                       # a warmup blob is a few hundred chars; never asked on anything larger


def triple_columnar_encrypt(text: str, o1, o2, o3) -> str:
    """Encipher under three columnar transpositions, inner order first (for tests and round-trips)."""
    t = K.columnar_encrypt(text, K._ranks(o1))
    t = K.columnar_encrypt(t, K._ranks(o2))
    return K.columnar_encrypt(t, K._ranks(o3))


def triple_columnar_decrypt(cipher: str, o1, o2, o3) -> str:
    """Undo triple_columnar_encrypt: strip the outer order first, then the inner double."""
    t = K.columnar_decrypt(cipher, K._ranks(o3))
    return K.double_columnar_decrypt(t, o1, o2)


def _name(o1, o2, o3) -> str:
    """The step name carrying the three column orders, so a triple read off a day's base reads that day's
    Mastery records too: "tricol:<o1>/<o2>/<o3>", each order a dot-joined read-out order."""
    return "tricol:" + "/".join(".".join(map(str, o)) for o in (o1, o2, o3))


def decode_named(name: str):
    """The decoder (text -> text or None) of a 'tricol:<o1>/<o2>/<o3>' step, or None for any other name.
    The orders are in the name, so a key learned from one blob reads another (a Mastery record)."""
    if K is None or not name.startswith("tricol:"):
        return None
    try:
        o1, o2, o3 = (tuple(int(x) for x in part.split(".")) for part in name[len("tricol:"):].split("/"))
    except (ValueError, TypeError):
        return None
    if not (o1 and o2 and o3):
        return None

    def f(t):
        try:
            return triple_columnar_decrypt(t, o1, o2, o3)
        except Exception:
            return None
    return f


def crib_triple_columnar(cipher: str, plain: str, deadline=None):
    """The one triple columnar reading of `cipher` that starts with `plain`, or None.

    None when no column triple reproduces the crib, when two triples give two DIFFERENT full texts
    (the slug is ambiguous), or when the bounded outer enumeration is cut by its order cap or the
    deadline before uniqueness is proven. Returns (o1, o2, o3, full text) for the one reading.
    """
    if K is None or not plain or not hasattr(K, "crib_double_columnar"):
        return None
    n = len(cipher)
    if n > MAX_LEN or n < len(plain) or not K.holds_crib(cipher, plain):
        return None
    stop = time.perf_counter() + TIME_CAP
    if deadline is not None:
        stop = min(stop, deadline)
    readings = {}                        # full text -> (o1, o2, o3) representative
    tried = 0
    for n3 in OUTER_COLUMNS:
        if 2 * n3 > n:
            break
        for o3 in itertools.permutations(range(n3)):
            if time.perf_counter() > stop:
                return None                       # cut (budget or deadline): cannot prove uniqueness
            tried += 1
            if tried > ORDER_CAP:
                return None                       # order budget spent: safe None, never a guess
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
                return None                       # two distinct full texts -> ambiguous slug -> None
    if len(readings) != 1:
        return None
    (text, (o1, o2, o3)), = readings.items()
    # The representative triple must itself reproduce the reading (a guard against an agree set whose first
    # pair decodes differently): otherwise there is no single name to carry, so None.
    if triple_columnar_decrypt(cipher, o1, o2, o3) != text:
        return None
    return o1, o2, o3, text


def crib_readings(cipher: str, plain: str, deadline=None):
    """[(name, reading)] in the shape crib_decode's late stage consumes: the single triple reading or []."""
    got = crib_triple_columnar(cipher, plain, deadline)
    if got is None:
        return []
    o1, o2, o3, text = got
    return [(_name(o1, o2, o3), text)]
