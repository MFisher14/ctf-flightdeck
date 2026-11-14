"""Where many literal byte strings stand in one large sample, in one pass (the Day 19 look-ahead, B4).

Why. field_catalog.py's language, runtime, compiler and toolchain readers asked the whole file for each of
some sixty literal marks and fifteen version-string patterns, one `in` or one regex at a time. On the 67 MB
Swift d08, which is in every Binary delivery, that was +5.1 s for `toolchain`, +2.0 s for `compiler` and
+0.7 s for `language` or `runtime`, on every solve (the base gate and every Mastery set), because a literal
search of Python's bytes runs 12 to 280 ms over 67 MB and the patterns' alternatives defeat the regex
engine's literal scan (docs/retro/day-19-predictions-binary.md, section 5, S12).

How. index(data, needles) reads every two-byte pair of the data once with numpy (in 4 MiB chunks, so the
memory it takes is a few chunks' worth), counts the pairs, picks for each needle its pair that is rarest IN
THIS FILE, and checks each place that pair stands with bytes.startswith. The result is exact: every place
each needle stands (overlapping places too), the same places `data.find` gives in a loop. About 0.25 s for
50 needles over 67 MB. A file under BIG is not indexed (the caller searches it as before), and without
numpy the index is built with bytes.find (the same answer, the old cost).

The last few indexes are kept for the process, keyed by the data's length and SHA-256 and the exact needle set:
the same d08 bytes in the base gate's replay and in every Mastery set cost one pass.
"""
import hashlib

BIG = 2 << 20            # bytes from which a sample is indexed rather than searched needle by needle
CHUNK = 4 << 20
KEEP = 4096              # places kept per needle (presence and the first places are what readers use)
_CACHE = {}
_CACHE_MAX = 4


def _by_find(data: bytes, needles) -> dict:
    out = {}
    for nd in needles:
        places, at = [], data.find(nd)
        while at >= 0 and len(places) < KEEP:
            places.append(at)
            at = data.find(nd, at + 1)
        out[nd] = places
    return out


def _by_pairs(data: bytes, needles) -> dict:
    import numpy as np
    arr = np.frombuffer(data, np.uint8)
    n = len(arr)
    counts = np.zeros(65536, np.int64)
    for s in range(0, n - 1, CHUNK):
        a = arr[s:s + CHUNK + 1]
        counts += np.bincount((a[:-1].astype(np.uint16) << 8) | a[1:], minlength=65536)
    keys = {}
    for nd in needles:
        best = min(range(len(nd) - 1), key=lambda i: (counts[(nd[i] << 8) | nd[i + 1]], i))
        keys.setdefault((nd[best] << 8) | nd[best + 1], []).append((nd, best))
    table = np.zeros(65536, bool)
    table[list(keys)] = True
    out = {nd: [] for nd in needles}
    for s in range(0, n - 1, CHUNK):
        a = arr[s:s + CHUNK + 1]
        k = (a[:-1].astype(np.uint16) << 8) | a[1:]
        idx = np.flatnonzero(table[k])
        if not len(idx):
            continue
        for p, key in zip(idx.tolist(), k[idx].tolist()):
            at = s + p
            for nd, off in keys[key]:
                start = at - off
                if start >= 0 and len(out[nd]) < KEEP and data.startswith(nd, start):
                    out[nd].append(start)
    for nd in out:
        out[nd].sort()
    return out


def index(data: bytes, needles) -> dict:
    """{needle: [every place it stands in data, ascending, at most KEEP]} for each needle (bytes, two or
    more long; a shorter one is found with bytes.find)."""
    needles = tuple(dict.fromkeys(nd for nd in needles if isinstance(nd, (bytes, bytearray)) and nd))
    # Neither CRC-32 nor hash(needles) is an identity: both admit collisions, and a stale place list can
    # answer a fact about different bytes.  The index already scans the whole large member; one SHA-256
    # pass and the exact (small) tuple make the process-global reuse content scoped.
    key = (len(data), hashlib.sha256(data).digest(), needles)
    got = _CACHE.get(key)
    if got is not None:
        return got
    long = tuple(nd for nd in needles if len(nd) >= 2)
    try:
        got = _by_pairs(data, long)
    except ImportError:
        got = _by_find(data, long)
    got.update(_by_find(data, tuple(nd for nd in needles if len(nd) < 2)))
    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.pop(next(iter(_CACHE)))
    _CACHE[key] = got
    return got


def windows(data: bytes, pattern, places, back: int = 64, ahead: int = 640, limit: int = 64) -> list:
    """The matches of `pattern` (compiled, over bytes) at the given anchor places, in file order and not
    overlapping: for each place p, the first match that finditer over [p - back, p + ahead] gives with
    start <= p < end. Equal to finditer over the whole file for a pattern whose every match contains one
    of its anchors, begins at most `back` bytes before it and is shorter than `ahead` (every pattern the
    callers pass: a literal anchor with a bounded tail, field_catalog.TOOLCHAIN_ANCHORS). At most `limit`."""
    out, end = [], 0
    for p in sorted(set(places)):
        if p < end:
            continue                    # inside the match already taken: finditer would not see it either
        for m in pattern.finditer(data, max(0, p - back, end), min(len(data), p + ahead)):
            if m.end() <= p:
                continue
            if m.start() <= p:
                out.append(m)
                end = m.end()
            break
        if len(out) >= limit:
            break
    return out
