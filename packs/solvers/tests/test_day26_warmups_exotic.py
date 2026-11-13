#!/usr/bin/env python3
"""Battery for solvers/warmups/exotic.py (Day 26 build): multi-tap, Pig Latin, 5-column outer triple columnar,
long running keys (period 53 to 60, passages past the crib).

  .venv/bin/python -m pytest tests/test_day26_warmups_exotic.py   (or `python tests/test_day26_warmups_exotic.py`)

No network, no token. Drives the real crib_decode.solve_blob. Never wrong: multi-tap and Pig Latin are lossy and
must come out unsure (never plain) with the right slug among the options; a transposition is crib-proof plain;
a running key's digits are open (unsure). A random blob and a near-miss (crib altered) are None or unsure-free.
"""
import atexit
import os
import random
import re
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
ROOT = Path(tempfile.mkdtemp(prefix="warmups-day26-"))
(ROOT / "_ledger").mkdir(parents=True)
# CTF_WORKDIR is set at import and may outlive this module in a pytest worker: remove the folder at exit only.
atexit.register(shutil.rmtree, ROOT, True)
os.environ["CTF_WORKDIR"] = str(ROOT)
os.environ["CTF_TESTING"] = "1"
os.environ.pop("CTF_TOKEN", None)
for _p in (REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    sys.path.insert(0, str(_p))

import labels            # noqa: E402
import crib_decode as C  # noqa: E402
import exotic as EX      # noqa: E402

CRIB = C.CRIB
SLUGS = ["amber-forest-lantern-47", "brave-castle-puzzle-09", "quick-zephyr-banner-62"]


def check(ok, name, detail=None):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or detail is None else "  " + repr(detail)[:300]))
    assert ok, name + ("" if detail is None else "  " + repr(detail)[:300])


KEYS = {"2": "abc", "3": "def", "4": "ghi", "5": "jkl", "6": "mno", "7": "pqrs", "8": "tuv", "9": "wxyz"}
L2K = {c: (d, i + 1) for d, l in KEYS.items() for i, c in enumerate(l)}


def multitap(t):
    out = []
    for ch in t.lower():
        if ch in L2K:
            d, n = L2K[ch]; out.append(d * n)
        elif ch == " ":
            out.append("0")
        elif ch.isdigit():
            out.append(ch * (len(KEYS[ch]) + 1) if ch in KEYS else ch * 2 if ch == "0" else ch)
        else:
            out.append(ch)
    return " ".join(out)


def pig_word(w, way="way"):
    m = re.match(r"^([A-Za-z]+)(.*)$", w)
    if not m:
        return w
    c, tail = m.groups(); lw = c.lower()
    if lw[0] in "aeiou":
        r = lw + way
    else:
        i = 0
        while i < len(lw) and lw[i] not in "aeiou":
            i += 1
        r = lw[i:] + lw[:i] + "ay"
    return (r.capitalize() if c[0].isupper() else r) + tail


def pig(sentence, slug, way="way"):
    return " ".join(pig_word(w, way) for w in sentence.split()) + " " + "-".join(
        pig_word(w, way) for w in slug.split("-")[:3]) + "-" + slug.split("-")[3]


def colenc(t, o):
    n = len(o)
    return "".join(t[k::n] for k in o)


def vig(t, k, p):
    out, n = [], 0
    for c in t:
        if c.isalpha():
            b = 65 if c.isupper() else 97
            out.append(chr((ord(c) - b + ord(k[n % p]) - 97) % 26 + b)); n += 1
        else:
            out.append(c)
    return "".join(out)


def slug_in(ans, slug):
    """The slug is among an unsure answer's options (any value of any option)."""
    p = labels.parse(ans) if isinstance(ans, str) else None
    return p is not None and any(slug in str(o[1]) for o in p["o"])


def read(blob, **kw):
    return C.solve_blob(blob.encode() if isinstance(blob, str) else blob, **kw)


# ---- multi-tap and Pig Latin: unsure, never plain
def test_multi_tap_and_pig_latin_unsure_never_plain():
    for name, make in (("multitap", lambda s: multitap(CRIB + s)),
                       ("piglatin", lambda s: pig(CRIB.strip(), s)),
                       ("piglatin_yay", lambda s: pig(CRIB.strip(), s, "yay"))):
        ok, det = True, []
        for s in SLUGS:
            r = read(make(s))
            good = r is not None and labels.is_unsure(r[0]) and slug_in(r[0], s)
            ok &= good
            if not good:
                det.append((s, r))
        check(ok, name + ": recovered as an unsure pick with the right slug (never plain)", det)


# ---- 5-column outer triple columnar (needs time: a bigger budget, as the retry read gives)
def test_5_column_outer_triple_columnar():
    ok, det = True, []
    for s, orders in ((SLUGS[0], ([2, 0, 4, 3, 1], [1, 3, 0, 2, 4], [3, 1, 2, 0, 4])),
                      (SLUGS[1], ([4, 2, 0, 1, 3], [2, 0, 3, 1, 4], [1, 4, 2, 3, 0]))):
        r = read(colenc(colenc(colenc(CRIB + s, orders[0]), orders[1]), orders[2]), budget=3.0)
        good = r is not None and r[0] == s
        ok &= good
        if not good:
            det.append((s, r))
    check(ok, "triple columnar, outer order of 5 columns: plain, right slug", det)


# ---- long running keys
def test_long_running_keys():
    txt = "".join(c for c in EX.EXTRA_RUNKEY_TEXTS["pride"] if c.isalpha())
    ok, det = True, []
    for at in (0, 7):
        k = txt[at:]
        r = read(vig(CRIB + SLUGS[0], k, len(k)), budget=3.0)
        good = r is not None and slug_in(r[0], SLUGS[0])
        ok &= good
        if not good:
            det.append((at, r))
    check(ok, "running key from a passage past the crib: recovered (digits open)", det)
    r = read(vig(CRIB + SLUGS[1], txt[:58], 58), budget=3.0)
    check(r is not None and slug_in(r[0], SLUGS[1]), "periodic key of 58 letters: recovered (digits open)", r)


# ---- never wrong: noise and near-misses give no plain
def test_never_wrong_noise_and_near_misses_give_no_plain():
    rnd = random.Random(26)
    noise = [bytes(rnd.randrange(256) for _ in range(150)),
             " ".join(rnd.choice(["2", "22", "222", "3", "33", "444", "7777", "0"]) for _ in range(120)),
             " ".join(rnd.choice(["otay", "isthay", "amberay", "orestfay", "eway"]) for _ in range(30)),
             "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(111))]
    bad = []
    for b in noise:
        r = read(b, budget=1.0)
        if r is not None:
            bad.append(r)
    check(not bad, "random / crib-less blobs: None (no false plain, no false unsure)", bad)
    near = multitap(CRIB.replace("Nice", "Mice") + SLUGS[0])
    r = read(near)
    check(r is None, "multitap with a corrupted crib: None", r)
    near = pig(CRIB.strip().replace("Nice", "Mice"), SLUGS[0])
    check(read(near) is None, "pig latin with a corrupted crib: None")
    check(read(colenc(CRIB.replace("Nice", "Mice") + SLUGS[0], [2, 0, 4, 3, 1]), budget=3.0) is None,
          "columnar with a corrupted crib: None")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
