#!/usr/bin/env python3
"""Offline self-test of solvers/mobile-android/codec_search.py.

  .venv/bin/python solvers/mobile-android/selftest.py [-v]

No network and no token. Saved attempts are only read, from the challenges folder that
labels.challenges_root() resolves ($CTF_WORKDIR, else the main checkout's challenges/).
Everything written goes under one tempfile.mkdtemp() folder that is removed at the end:
the runtime ledger of the synthetic checks, attempt copies for tools/run.py, and a copy of
the solver folder with a day_patch.py in it.

What is checked:

  saved      every mobile APK and attempt saved on Days 1 to 4 comes back identical to its
             key.json (or golden.json) and plain, and equal to what puzzle_asset_codec.py
             says; one NOTE line per set. Read with the real ledger, as tools/preflight.py
             would. The Day 5 attempts come back plain with the seed and an empty ledger.
             Later days are not replayed here: see FROZEN_DAYS.
  synthetic  79 puzzle documents (the 73 of prototypes/mobtest/synth.py, the 5 of
             run_proto.py and Day 5's judged shape), 25 answers each, every one inside a
             small APK: at least 73 solved, no wrong plain answer, no wrong unsure answer,
             and the two documents the prototype got wrong come back None.
  arranged   pieces listed beside an order: every listing of 2, 3 and 4 pieces is plain
             under codec split and unsure, right value first, under a new name; each
             difference from the judged shape is a tag and stays unsure; an order that fits
             neither reading is None at once and no join is offered, nor beside any other
             number (the pieces' lengths are no order); one string under an ascending order
             is not offered as it stands; an order written as text costs one pass; joined
             pieces with no order are searched briefly; with the name masked the Day 5 base
             has the one option split:by-order.
  moves      position moves on a 20-character `data` and bit moves proven by the ANS-
             prefix: unsure, the right value first.
  keyed      keyed shifts with a key of several characters (row 47): vigenere over letters
             (the key index on letters or on every character), bytes and printable text,
             beaufort, a repeating add proven by the ANS- prefix, caesar and shift with a key
             list: unsure under a route of their own, the right value offered every time and
             first nearly always; Day 7's caesar shape stays plain.
  pack       row 72: rail fence (rails from a field, another field, a reference, or searched
             and proved by the prefix), affine (letters and bytes, a and b from fields, a key
             pair, searched), keyed substitution (alphabet, keyword, map, plain/cipher pair),
             chains listed in `steps`, step1/step2 or outer/inner, a key read from another
             field: unsure under a route of their own, the right value first; judged shapes
             stay plain; near misses are None; work that multiplies stays inside the budget.
  hostile    documents whose transform works inside the answer's alphabet: never a wrong
             plain answer.
  rot5/rot18 solved when the document names them, and not otherwise.
  codecs     the likely next codecs, one document each (base32 and its hex and Crockford
             alphabets, ROT-N and Caesar spelled several ways, rot47, atbash, gzip, zlib,
             raw deflate, bzip2 and xz under base64 or hex, ascii85, base85, Z85, URL-safe
             base64, chains of them as a list or 'a+b'): applied by name, unsure under
             mobile.codec/<name> with every option the right code; a near miss (it decodes,
             but not to ANS-[0-9A-F]{16}) and garbage are None; base32hex, Crockford and Z85
             are never search moves; an accepted name is plain on the next variant and for
             no other codec name.
  ledger     a route accepted with labels.learn is answered plain afterwards, also on the
             next variant; a rejected route is None.
  apk        Day 4's APK rebuilt with the document moved, wrapped, encoded or removed, and
             with keys that only the dex holds.
  budget     documents whose work multiplies (chains of keyed steps over many keys) are
             misses inside the budget, and never a hang.
  archives   an APK with thousands of members, a long puzzle document, an APK inside a zip:
             what the Day 4 solver answers is not turned into a miss.
  names      the seed's accepted names answer only the Day 4 solver's named route: a search
             hit or a look-alike codec name ('xor!') under the same key stays unsure.
  questions  a single question that states another answer format is not given the code; the
             NOTE says "rejected by the judge" only when the ledger does.
  day 9      selftest_day9.py (its own text lists the checks): the codecs of codec_more.py, a
             schema other than v1, object steps and fragment documents, the puzzle's fields in
             other containers (asset_docs.py), keys and strings from the resources, compiled XML
             and native libraries (apk_resources.py), the one code a package holds outside any
             document, the facts of apk_facts.py, a Mastery of eight deliveries, broken bytes.
  time       the worst miss stays under 0.45 s, also in a fresh process that still has to
             import `cryptography`.
  runner     tools/run.py --offline drives the wrapper on a judged and on an unknown codec.
  day_patch  a day_patch.py beside the module is asked for a miss and for an unsure answer,
             and its answer is used unless it declines; a plain answer is never offered to
             it, so a careless patch changes no judged answer; a broken one costs nothing.
             day_patch_template.py, copied and filled in, works under that contract.

A day_patch.py beside the solver is switched off for the checks made in this process: what
is under test is the shipped module, and the day_patch check loads a patch of its own from a
copy of the folder. (The checks that start a process of their own run the folder as it is:
their plain answers are never offered to a patch, and the one unsure answer among them, the
runner's base85 document, is one a patch written for the day's codec declines.) So the
result does not depend on a live fix, and a live fix is checked with
`tools/preflight.py --replay <attempt dir>`, not here.

Prints one line per check and a last line `SELFTEST mobile: <passed>/<checks> ...`; exits 1
if any check failed.
"""
import base64
import binascii
import codecs
import contextlib
import gzip
import hashlib
import io
import itertools
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
TMP = Path(tempfile.mkdtemp(prefix="mobile_selftest_"))
VERBOSE = "-v" in sys.argv[1:]

# Offline, whatever the shell had set: no rehearsal knobs but our own, and the judged (seed +
# ledger) behaviour of labels.py, which is what these checks are about.
for _name in ("CTF_LEDGER_MASK", "CTF_TESTING", "CTF_JUDGE_LEDGER"):
    os.environ.pop(_name, None)
# mobile.codec/apk-string:dex was promoted after Day 20 (Day 21 build): masked so these checks read the seed
# they were written against; the blocks that mask a name of their own add it to this one.
BASE_MASK = "mobile.codec/apk-string:dex"
os.environ["CTF_TESTING"] = "1"
os.environ["CTF_LEDGER_MASK"] = BASE_MASK

sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(HERE.parent / "common"))
sys.path.insert(0, str(HERE))
import run  # noqa: E402
import labels  # noqa: E402
import puzzle_asset_codec as base  # noqa: E402
import codec_search as C  # noqa: E402

# The saved attempts (read only): labels.challenges_root(), i.e. $CTF_WORKDIR, else the main
# checkout's challenges/. The folder is untracked, so a fresh clone has none: every check that
# replays a saved attempt is then reported as SKIP (not run, never a pass).
REAL = labels.challenges_root()
skipped = []   # names of the checks that could not run here


def skip(name, why):
    skipped.append(name)
    print(f"SKIP {name}: {why}")


def no_attempts() -> bool:
    """True when no saved attempt is on disk: the folder is absent (a fresh clone: challenges/ is untracked)
    or holds no day-* folder (only a scratch _ledger). Any day-* folder makes every replay check strict."""
    return not (REAL.is_dir() and any(REAL.glob("day-*")))
# The days whose saved attempts are replayed against the Day 4 solver: the ones it was built
# and judged on. A later day's attempts are left to tools/preflight.py (--replay, --regress):
# once such a base is CORRECT on a codec that only codec_search.py or a day_patch.py reads, it
# can never equal what puzzle_asset_codec.py says, and this test would fail on the day
# whatever the live fix does. Day 5's codec is in codec_search.py now, so saved_day5() replays
# that day against its keys alone.
FROZEN_DAYS = "day-0[1-4]"
if C._patch is not None or C.PATCH.exists():
    print("note: day_patch.py is present beside the solver; the checks run with it switched off")
C._patch = None   # the shipped module is what is under test; the day_patch check loads its own on a copy
PZ = base.PUZZLE
HEX = "0123456789ABCDEF"
H = {"schema": "huntress.mobile.puzzle.v1", "day": 5}
TRIALS = 25
# The per-blob solve budget, in CPU time (time.process_time), not wall-clock (row 170): a loaded
# machine inflates wall time and would trip this threshold on a solve that is still cheap, while a
# true 10x solver regression burns the CPU and fails it. solve() and capped() measure in CPU time.
MISS_LIMIT = 0.45

checks = []   # (ok, name, detail)
worst = {"seconds": 0.0, "what": ""}
rnd = random.Random(5)


def check(ok, name, detail=""):
    checks.append((bool(ok), name, detail))
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, (": " + detail) if detail else ""))
    return bool(ok)


def quiet():
    """Capture the solver's stderr inside a `with` block: `with quiet() as err`."""
    return contextlib.redirect_stderr(io.StringIO())


def scratch_ledger(name) -> Path:
    """Point the runtime ledger at a new, empty challenges folder under the temp dir."""
    path = TMP / name
    os.environ["CTF_WORKDIR"] = str(path)
    return path


# ---------------------------------------------------------------------------- encoders

def ans():
    return "ANS-" + "".join(rnd.choice(HEX) for _ in range(16))


def b64(b):
    return base64.b64encode(b).decode()


def xor(b, k):
    return bytes(c ^ k[i % len(k)] for i, c in enumerate(b))


def caesar(s, n):
    return "".join(chr((ord(c) - 65 + n) % 26 + 65) if c.isupper() else chr((ord(c) - 97 + n) % 26 + 97)
                   if c.islower() else c for c in s)


def rot47(s):
    return "".join(chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c for c in s)


def rot5(s):
    return "".join(chr((ord(c) - 48 + 5) % 10 + 48) if c.isdigit() else c for c in s)


def rot18(s):
    return rot5(codecs.encode(s, "rot13"))


def atbash(s):
    return "".join(chr(155 - ord(c)) if c.isupper() else c for c in s)


def _pad(pt):
    n = 16 - len(pt) % 16
    return pt + bytes([n]) * n


def aes_cbc(key, iv, pt):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(_pad(pt)) + e.finalize()


def aes_ecb(key, pt):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(_pad(pt)) + e.finalize()


def rc4(key, data):
    s, j = list(range(256)), 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(b):
    n, s = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return s


def vig(a, key):
    out, i = "", 0
    for c in a:
        if c.isupper():
            out += chr((ord(c) - 65 + ord(key[i % len(key)]) - 65) % 26 + 65)
            i += 1
        else:
            out += c
    return out


def doc(codec, data, **kw):
    d = dict(H)
    d["codec"] = codec
    d["data"] = data
    d.update(kw)
    return d


def cut(a, cuts):
    edges = [0] + list(cuts) + [len(a)]
    return [a[x:y] for x, y in zip(edges, edges[1:])]


def split_doc(a, order, cuts=(5, 11), codec="split", pieces="parts", field="order", keys=None, **kw):
    """The Day 5 shape: the answer cut at `cuts`, piece number order[i] listed at place i."""
    p = cut(a, cuts)
    d = {**H, "codec": codec, "data": "", pieces: [p[i] for i in order], field: list(keys or order)}
    d.update(kw)
    return d


def cases():
    """The 79 documents: (name, builder). The builder takes the answer and returns the document."""
    c = []
    add = lambda name, f: c.append((name, f))
    # --- the four codecs judged on Days 1 to 4
    add("plain", lambda a: doc("plain", a))
    add("reverse", lambda a: doc("reverse", a[::-1]))
    add("base64", lambda a: doc("base64", b64(a.encode())))
    add("xor int key (day4 shape)", lambda a: doc("xor", b64(xor(a.encode(), b"\x1d")), key=29))
    # --- the codec judged on Day 5, in the shape the judge saw
    add(DAY5, lambda a: split_doc(a, (2, 0, 1)))
    # --- single text encodings
    add("hex", lambda a: doc("hex", a.encode().hex()))
    add("hex upper", lambda a: doc("hex", a.encode().hex().upper()))
    add("rot13", lambda a: doc("rot13", codecs.encode(a, "rot13")))
    add("base32", lambda a: doc("base32", base64.b32encode(a.encode()).decode()))
    add("base32 lower no pad", lambda a: doc("base32", base64.b32encode(a.encode()).decode().lower().rstrip("=")))
    add("base85 (b85)", lambda a: doc("base85", base64.b85encode(a.encode()).decode()))
    add("ascii85 (a85)", lambda a: doc("ascii85", base64.a85encode(a.encode()).decode()))
    add("base58", lambda a: doc("base58", b58(a.encode())))
    add("base64url no pad", lambda a: doc("base64url", base64.urlsafe_b64encode(a.encode()).decode().rstrip("=")))
    add("binary bits", lambda a: doc("binary", " ".join(f"{x:08b}" for x in a.encode())))
    add("decimal list in data", lambda a: doc("decimal", list(a.encode())))
    add("decimal string", lambda a: doc("decimal", " ".join(str(x) for x in a.encode())))
    add("octal string", lambda a: doc("octal", " ".join(f"{x:o}" for x in a.encode())))
    add("url percent", lambda a: doc("url", "".join(f"%{x:02X}" for x in a.encode())))
    add("utf-16le base64", lambda a: doc("base64", b64(a.encode("utf-16le"))))
    add("atbash", lambda a: doc("atbash", atbash(a)))
    add("rot47", lambda a: doc("rot47", rot47(a)))
    add("rot18 (rot13+rot5)", lambda a: doc("rot18", rot18(a)))
    add("uuencode", lambda a: doc("uu", binascii.b2a_uu(a.encode()).decode().strip()))
    # --- caesar / shift
    add("caesar +3 with shift field", lambda a: doc("caesar", caesar(a, 3), shift=3))
    add("caesar +7 no parameter", lambda a: doc("caesar", caesar(a, 7)))
    add("caesar named rot7 no parameter", lambda a: doc("rot7", caesar(a, 7)))
    add("byte add +5 with key (base64)", lambda a: doc("add", b64(bytes((x + 5) % 256 for x in a.encode())), key=5))
    add("byte sub no parameter (base64)", lambda a: doc("shift", b64(bytes((x + 9) % 256 for x in a.encode()))))
    # --- xor variants
    add("xor string key", lambda a: doc("xor", b64(xor(a.encode(), b"huntress")), key="huntress"))
    add("xor hex-string key", lambda a: doc("xor", b64(xor(a.encode(), bytes.fromhex("1d2fa0"))), key="1d2fa0"))
    add("xor int-list key", lambda a: doc("xor", b64(xor(a.encode(), bytes([1, 200, 33]))), key=[1, 200, 33]))
    add("xor key as decimal string '29'", lambda a: doc("xor", b64(xor(a.encode(), b"\x1d")), key="29"))
    add("xor key '0x1d' string", lambda a: doc("xor", b64(xor(a.encode(), b"\x1d")), key="0x1d"))
    add("xor hex data", lambda a: doc("xor", xor(a.encode(), b"\x55").hex(), key=85))
    add("xor int key >255 big-endian", lambda a: doc("xor", b64(xor(a.encode(), (0xBEEF).to_bytes(2, "big"))), key=0xBEEF))
    add("xor int key >255 little-endian",
        lambda a: doc("xor", b64(xor(a.encode(), (0xBEEF).to_bytes(2, "little"))), key=0xBEEF))
    add("xor 1-byte, key field absent", lambda a: doc("xor", b64(xor(a.encode(), b"\x4c"))))
    add("xor 4-byte key, key absent", lambda a: doc("xor", b64(xor(a.encode(), b"\x10\x99\x42\x07"))))
    add("xor 8-byte key, key absent (key in dex)", lambda a: doc("xor", b64(xor(a.encode(), b"SECRETK!"))))
    add("xor rolling key (k+i)",
        lambda a: doc("xor-rolling", b64(bytes(x ^ ((29 + i) & 255) for i, x in enumerate(a.encode()))), key=29))
    add("xor then reverse then base64", lambda a: doc("xor", b64(xor(a.encode(), b"\x1d")[::-1]), key=29))
    add("xor key = the 'day' field", lambda a: doc("xor", b64(xor(a.encode(), b"\x05"))))
    add("xor 'key' nested in params obj", lambda a: doc("xor", b64(xor(a.encode(), b"\x1d")), params={"key": 29}))
    add("rc4 with key", lambda a: doc("rc4", b64(rc4(b"huntress", a.encode())), key="huntress"))
    # --- chains
    add("chain 'reverse+base64' (enc order)", lambda a: doc("reverse+base64", b64(a[::-1].encode())))
    add("chain list ['base64','reverse'] (dec order)", lambda a: doc(["base64", "reverse"], b64(a[::-1].encode())))
    add("chain 'base64-reverse' hyphen", lambda a: doc("base64-reverse", b64(a.encode())[::-1]))
    add("chain 'reverse_base64' underscore", lambda a: doc("reverse_base64", b64(a[::-1].encode())))
    add("chain 'base64 reverse' space", lambda a: doc("base64 reverse", b64(a.encode())[::-1]))
    add("chain 'base64/xor' slash + key", lambda a: doc("base64/xor", b64(xor(a.encode(), b"\x33")), key=51))
    add("chain 'rot13+hex+base64'",
        lambda a: doc("rot13+hex+base64", b64(codecs.encode(a, "rot13").encode().hex().encode())))
    add("unknown name 'double-base64'", lambda a: doc("double-base64", b64(b64(a.encode()).encode())))
    add("5-deep chain, opaque name 'layered'",
        lambda a: doc("layered", b64(b64(b64(b64(b64(a.encode()).encode()).encode()).encode()).encode())))
    add("opaque name 'v2': xor+reverse+hex", lambda a: doc("v2", xor(a.encode(), b"\x21")[::-1].hex(), key=33))
    # --- compression
    add("zlib+base64", lambda a: doc("zlib", b64(zlib.compress(a.encode()))))
    add("gzip+base64", lambda a: doc("gzip", b64(gzip.compress(a.encode()))))
    add("raw deflate+base64", lambda a: doc("deflate", b64(zlib.compress(a.encode())[2:-4])))
    # --- split / restructured fields
    add("data is list of 2 parts", lambda a: doc("split", [a[:10], a[10:]]))
    add("parts[] field, no data", lambda a: {**H, "codec": "split", "parts": [a[:7], a[7:14], a[14:]]})
    add("data1/data2 keys", lambda a: {**H, "codec": "concat", "data1": a[:10], "data2": a[10:]})
    add("prefix + data(hex tail only)", lambda a: doc("plain", a[4:], prefix="ANS-"))
    add("data is tail only, no prefix", lambda a: doc("plain", a[4:]))
    add("field renamed payload", lambda a: {**H, "codec": "base64", "payload": b64(a.encode())})
    add("field renamed ciphertext+xor",
        lambda a: {**H, "codec": "xor", "ciphertext": b64(xor(a.encode(), b"\x1d")), "key": 29})
    add("nested data object", lambda a: doc("base64", {"value": b64(a.encode())}))
    add("interleaved even/odd fields", lambda a: {**H, "codec": "interleave", "even": a[0::2], "odd": a[1::2]})
    add("plain with wrapper text", lambda a: doc("plain", "answer=" + a))
    add("base64 of JSON {'answer':..}", lambda a: doc("base64", b64(json.dumps({"answer": a}).encode())))
    add("lowercase hex answer body (base64)", lambda a: doc("base64", b64(a.lower().replace("ans", "ANS").encode())))
    add("schema v2 with steps[] list",
        lambda a: {"schema": "huntress.mobile.puzzle.v2", "day": 5, "steps": ["base64", "reverse"],
                   "data": b64(a[::-1].encode())})
    # --- real crypto
    k16, iv = hashlib.md5(b"k").digest(), hashlib.md5(b"iv").digest()
    add("aes-128-cbc key+iv in JSON (hex)",
        lambda a: doc("aes", b64(aes_cbc(k16, iv, a.encode())), key=k16.hex(), iv=iv.hex()))
    add("aes-128-ecb key in JSON (base64)", lambda a: doc("aes-ecb", b64(aes_ecb(k16, a.encode())), key=b64(k16)))
    add("aes key NOT in JSON (in dex)", lambda a: doc("aes", b64(aes_cbc(k16, iv, a.encode())), iv=iv.hex()))
    # --- the five of run_proto.py
    add("rot5 digits only (prefix kept)", lambda a: doc("rot5", rot5(a)))
    add(RESIDUAL[0], lambda a: doc("reverse-body", a[:4] + a[4:][::-1]))
    add(RESIDUAL[1], lambda a: {**H, "codec": "relay", "data": "ANS-0000000000000000", "payload": b64(a.encode())})
    add("base64 of rot5'd answer 'base64+rot5'", lambda a: doc("base64+rot5", b64(rot5(a).encode())))
    add("vigenere with key", lambda a: doc("vigenere", vig(a, "HUNT"), key="HUNT"))
    return c


# The two documents the prototype answered wrongly (at confidence low). Here they must be None.
RESIDUAL = ("body reversed, prefix kept", "decoy data, real in 'payload' b64, codec unknown")
DAY5 = "split parts + order (day5 shape)"
# The synthetic documents in the shape a judged codec name answers, each with the (codec, accepted
# name) pairs of the seed it needs: a chain needs each of its steps. Which of them must come back
# plain is read from the seed (conventions.json), not written here, so a codec the judge accepts
# joins JUDGED when `labels.py promote mobile` writes it, and a name the judge stops accepting
# (split, or another name accepted) leaves it. A shape that is not listed is never plain: caesar
# with no parameter (its shift recovered from the ANS- prefix) and rot7 stay unsure.
SHAPES = {
    "plain": (("plain", "plain"),),
    "reverse": (("reverse", "reverse"),),
    "base64": (("base64", "base64"),),
    "xor int key (day4 shape)": (("xor", "xor"),),
    DAY5: (("split", "split:by-order"),),
    "chain 'reverse+base64' (enc order)": (("reverse", "reverse"), ("base64", "base64")),
    "chain list ['base64','reverse'] (dec order)": (("reverse", "reverse"), ("base64", "base64")),
    "hex": (("hex", "hex"),),          # the Day 6 codec, judged 2026-10-06 (either case of the digits)
    "hex upper": (("hex", "hex"),),
    "caesar +3 with shift field": (("caesar", "caesar"),),   # the Day 7 codec, judged 2026-10-07
}
NEVER_PLAIN = ("caesar +7 no parameter", "caesar named rot7 no parameter")


def seed_accepted() -> dict:
    """{codec: accepted name} for every key of the seed that is accepted and not split."""
    seed = json.loads((HERE / "conventions.json").read_text())
    return {k[len(C.KEY):]: v["accepted"] for k, v in seed.items()
            if k.startswith(C.KEY) and v.get("accepted") and not v.get("split")}


SEED = seed_accepted()
JUDGED = tuple(n for n, needs in SHAPES.items() if all(SEED.get(codec) == name for codec, name in needs))

HOSTILE = [
    ("hex complement of body (F-h)", lambda a: doc("complement", a[:4] + "".join(HEX[15 - HEX.index(x)] for x in a[4:]))),
    ("adjacent pair swap of body", lambda a: doc("swap", a[:4] + "".join(a[4:][i + 1] + a[4:][i] for i in range(0, 16, 2)))),
    ("body rotated left by key", lambda a: doc("rotate", a[:4] + a[4 + 5:] + a[4:4 + 5], key=5)),
    ("xor with key, then body reversed, opaque name", lambda a: doc("v3", b64(xor((a[:4] + a[4:][::-1]).encode(), b"\x1d")), key=29)),
    ("rot5 under an opaque name", lambda a: doc("mystery", rot5(a))),
    ("rot5 with no codec field", lambda a: {**H, "data": rot5(a)}),
    ("rot18 under an opaque name", lambda a: doc("mystery", rot18(a))),
    ("answer-shaped data, codec missing", lambda a: {**H, "data": a[:4] + a[4:][::-1]}),
    ("answer-shaped data under a layout name", lambda a: doc("split", a[:4] + a[4:][::-1])),
    ("two different answers in one field", lambda a: doc("mystery", "ANS-0000000000000000 " + a)),
    ("base64 under an opaque name, decoy field beside it", lambda a: doc("mystery", b64(a.encode()), decoy="ANS-0000000000000000")),
    ("whole string rotated, digits also rot5", lambda a: doc("twist", rot5(a)[7:] + rot5(a)[:7])),
    ("scrambled data, an answer-shaped decoy beside it", lambda a: doc("rotate", a[7:] + a[:7], decoy="ANS-0000000000000000")),
]


# ---------------------------------------------------------------------------- helpers

def mini_apk(document) -> bytes:
    """A small APK that holds only the puzzle document, at its usual path."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        zo.writestr(PZ, json.dumps(document, separators=(",", ":")))
    return out.getvalue()


def build(members) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for k, v in members.items():
            zo.writestr(k, v)
    return out.getvalue()


def solve(apk, what=""):
    """(answer, seconds) from the wrapper, with its stderr kept out of the report.

    Row 170: `seconds` is CPU time (time.process_time), not wall-clock, so the budget checks that
    read it (MISS_LIMIT, the "work that multiplies" misses) are not tripped by machine load. The
    solver is single-threaded Python, so CPU time tracks its real work and a regression still fails."""
    with quiet():
        t = time.process_time()
        got = C.solve_apk(apk)
        dt = time.process_time() - t
    if got is None and dt > worst["seconds"]:
        worst.update(seconds=dt, what=what)
    return got, dt


def kind(got, truth) -> str:
    """plain-ok, unsure-ok, unsure-first, unsure-later, none, plain-wrong or unsure-wrong.

    unsure-ok: every option carries the right value (one option, or the names of one
    arrangement whose readings agree). unsure-first: the right value is the first option
    and another value follows it. unsure-later: the right value is offered, not first."""
    if got is None:
        return "none"
    parsed = labels.parse(got)
    if parsed is None:
        return "plain-ok" if got == truth else "plain-wrong"
    values = [v for _, v in parsed.options]
    if not parsed.key.startswith("mobile.codec/") or truth not in values:
        return "unsure-wrong"
    return "unsure-ok" if set(values) == {truth} else "unsure-first" if values[0] == truth else "unsure-later"


def options_of(got) -> list:
    """The option names of an unsure answer, in order; [] for a plain answer or None."""
    parsed = labels.parse(got) if got else None
    return [n for n, _ in parsed.options] if parsed else []


def tally(builder, name):
    """Counts of each kind over TRIALS random answers, and the last route seen."""
    counts, route = {}, ""
    for _ in range(TRIALS):
        a = ans()
        got, _ = solve(mini_apk(builder(a)), name)
        k = kind(got, a)
        counts[k] = counts.get(k, 0) + 1
        route = C.LAST.get("route", "")
    return counts, route


def expected_answers(d: Path):
    for name in ("key.json", "golden.json"):
        p = d / name
        if p.exists():
            return json.loads(p.read_text()).get("answers"), name
    return None, None


# ---------------------------------------------------------------------------- the checks

def saved_attempts():
    """Every saved mobile attempt, replayed the way the runner feeds a solver."""
    if no_attempts():
        for name in ("saved APKs identical to the saved answers and plain", "saved attempts identical to the saved answers",
                     "one NOTE line per set"):
            skip(name, f"no saved attempts under {REAL}")
        return
    dirs = sorted(p.parent for p in REAL.glob(f"{FROZEN_DAYS}/mobile-android-*/**/attempt.json"))
    apks = apks_ok = attempts_ok = notes = keyed = 0
    problems = []
    for d in dirs:
        want, source = expected_answers(d)
        if want is None:
            continue
        keyed += 1
        rel = d.relative_to(REAL)
        try:
            attempt, blobs, _ = run.load_offline(str(rel), str(d))
            sets = run.split_sets(attempt, blobs)
        except SystemExit as e:
            problems.append(f"{rel}: {e.code}")
            continue
        answers = {}
        with quiet() as err:
            for n, qs, files, ctx in sets:
                got = C.solve_set(qs, files, ctx)
                apks += 1
                for q in qs:
                    v = got.get(q["qid"])
                    if v is not None:
                        answers[q["answer_id"]] = v
                    old = base.solve_apk(ctx["delivery"])
                    if v == want.get(q["answer_id"]) and not labels.is_unsure(v) and v == old:
                        apks_ok += 1
                    else:
                        problems.append(f"{rel} {q['answer_id']}: got {str(v)[:60]!r}, {source} has "
                                        f"{want.get(q['answer_id'])!r}, puzzle_asset_codec says {old!r}")
        notes += sum(1 for line in err.getvalue().splitlines() if line.startswith("NOTE mobile set"))
        if answers == want:
            attempts_ok += 1
        if VERBOSE:
            print(f"   {rel}: {answers == want} ({source})")
    check(apks >= 20 and apks_ok == apks, "saved APKs identical to the saved answers and plain",
          f"{apks_ok} of {apks} under {REAL}" + ("; " + "; ".join(problems[:3]) if problems else ""))
    check(keyed >= 12 and attempts_ok == keyed, "saved attempts identical to the saved answers",
          f"{attempts_ok} of {keyed}")
    check(notes == apks, "one NOTE line per set", f"{notes} lines for {apks} sets")


DAY5_LANE = "mobile-android-day-05-backup-spill"


def saved_day5():
    """The saved Day 5 attempts, read with the seed and an empty ledger: codec_search.py alone
    answers them plain, through the seed's accepted name. (No comparison with the Day 4
    solver, which does not read an order.)"""
    if no_attempts():
        skip("saved Day 5 APKs are plain and identical to the saved answers, by the seed alone",
             f"no saved attempts under {REAL}")
        return
    apks = apks_ok = 0
    problems = []
    for d in sorted(p.parent for p in REAL.glob(f"day-05/{DAY5_LANE}/**/attempt.json")):
        want, source = expected_answers(d)
        if want is None:
            continue
        try:
            attempt, blobs, _ = run.load_offline(str(d.relative_to(REAL)), str(d))
            sets = run.split_sets(attempt, blobs)
        except SystemExit as e:
            problems.append(f"{d.relative_to(REAL)}: {e.code}")
            continue
        for n, qs, files, ctx in sets:
            with quiet():
                got = C.solve_set(qs, files, ctx)
            for q in qs:
                apks += 1
                if got.get(q["qid"]) == want.get(q["answer_id"]):
                    apks_ok += 1
                else:
                    problems.append(f"{d.relative_to(REAL)} {q['answer_id']}: got {str(got.get(q['qid']))[:60]!r}")
    check(apks >= 5 and apks_ok == apks, "saved Day 5 APKs are plain and identical to the saved answers, by the seed alone",
          f"{apks_ok} of {apks}" + ("; " + "; ".join(problems[:3]) if problems else ""))


def arrangements():
    """Pieces listed beside an order: Day 5's judged shape, and what the family reads around it."""
    listings = [(cuts, order) for cuts in ((9,), (5, 11), (5, 10, 15))
                for order in itertools.permutations(range(len(cuts) + 1))]
    bad = []
    for cuts, order in listings:
        a = ans()
        got, _ = solve(mini_apk(split_doc(a, order, cuts)))
        if got != a:
            bad.append(f"{list(order)}: {kind(got, a)}")
    check(not bad, f"every listing of 2, 3 and 4 pieces under codec split is plain and right: {len(listings)} listings",
          "; ".join(bad[:4]))
    # a codec nobody has judged: the right value first, and an order that is its own inverse named as such
    bad = []
    either = ["shuffle:%s-index:@chunks" % r for r in ("either", "by", "take")]
    for cuts, order in listings:
        a = ans()
        got, _ = solve(mini_apk(split_doc(a, order, cuts, codec="shuffle", pieces="chunks", field="index")))
        names = options_of(got)
        own_inverse = all(order[order[i]] == i for i in range(len(order)))
        if (kind(got, a) not in ("unsure-ok", "unsure-first") or labels.parse(got).key != "mobile.codec/shuffle"
                or (names != either if own_inverse else names[0] != either[1] or either[0] in names)):
            bad.append(f"{list(order)}: {kind(got, a)} {names}")
    check(not bad, "the same listings under an unjudged name are unsure, the right value first", "; ".join(bad[:4]))

    a = ans()
    p = cut(a, (5, 11))
    t = b64(a.encode())
    judged = split_doc(a, (2, 0, 1))
    block = [a[i:i + 5] for i in range(0, 20, 5)]
    scramble = list(range(20))
    rnd.shuffle(scramble)
    shapes = [
        ("the other reading: piece i is parts[order[i]]", {**judged, "order": [1, 2, 0]}, "split:take-order"),
        ("order written 1-based", split_doc(a, (2, 0, 1), keys=[3, 1, 2]), "split:by-order:order-keys"),
        ("order with sparse keys", split_doc(a, (2, 0, 1), keys=[30, 10, 20]), "split:by-order:order-keys"),
        ("order written as text", {**judged, "order": "2,0,1"}, "split:by-order:order-text"),
        ("order field index", split_doc(a, (2, 0, 1), field="index"), "split:by-index"),
        ("order field ORDER", split_doc(a, (2, 0, 1), field="ORDER"), "split:by-order:order-renamed"),
        ("pieces field chunks", split_doc(a, (2, 0, 1), pieces="chunks"), "split:by-order:@chunks"),
        ("data not empty", {**judged, "data": "x"}, "split:by-order:data-present"),
        ("a further field", {**judged, "hint": "x"}, "split:by-order:extra-fields"),
        ("an empty piece", {**judged, "parts": [p[2], "", p[0], p[1]], "order": [3, 1, 0, 2]}, "split:by-order:empty-piece"),
        ("pieces as {i, v} objects", {**H, "codec": "split", "data": "", "parts": [{"i": i, "v": p[i]} for i in (2, 0, 1)]},
         "split:by-i:objects"),
        ("objects numbered `order`", {**H, "codec": "split", "data": "", "parts": [{"order": i, "v": p[i]} for i in (2, 0, 1)]},
         "split:by-order:objects"),
        ("the document one level down", {**H, "puzzle": judged}, "split:by-order:doc-nested"),
        ("codec written split!", {**judged, "codec": "split!"}, "split:by-order:renamed"),
        ("the base64 text cut, under the bare name", {**judged, "parts": [cut(t, (9, 19))[i] for i in (2, 0, 1)]},
         "split:by-order:then"),
        ("split+base64, the base64 text cut", {**judged, "codec": "split+base64", "parts": [cut(t, (9, 19))[i] for i in (2, 0, 1)]},
         "split+base64:by-order:then"),
        ("split+base64, each piece encoded", {**judged, "codec": "split+base64", "parts": [b64(p[i].encode()) for i in (2, 0, 1)]},
         "split+base64:by-order:pieces-decoded"),
        ("split+xor, the base64 text cut", {**judged, "codec": "split+xor", "key": 29,
                                           "parts": [cut(b64(xor(a.encode(), b"\x1d")), (9, 19))[i] for i in (2, 0, 1)]},
         "split+xor:by-order:extra-fields:then"),
        ("the characters of data, an order of 20", doc("permute", "".join(a[i] for i in scramble),
                                                      order=[scramble.index(i) for i in range(20)]), None),
        ("data cut evenly in four", doc("blocks", "".join(block[i] for i in (3, 0, 2, 1)), order=[3, 0, 2, 1]),
         "blocks:by-order:@data:chunks"),
    ]
    bad = []
    for name, d, route in shapes:
        got, _ = solve(mini_apk(d))
        names = options_of(got)
        if kind(got, a) != "unsure-ok" or (names != [route] if route else not names[0].endswith(":@data:chars")):
            bad.append(f"{name}: {kind(got, a)} {names}")
        if VERBOSE:
            print(f"   {name:46} {kind(got, a):12} {names}")
    check(not bad, f"a difference from the judged shape is named in the route and stays unsure: {len(shapes)} shapes",
          "; ".join(bad[:4]))
    # an order that fits neither reading: None, at once, and never the fields joined as listed
    bad = []
    for name, d in (("split", {**judged, "parts": p, "order": [1, 2, 0]}),
                    ("chunks", {**H, "codec": "chunks", "data": "", "chunks": p, "index": [1, 2, 0]}),
                    ("split+base64", {**judged, "codec": "split+base64", "parts": cut(t, (9, 19)), "order": [1, 2, 0]})):
        got, dt = solve(mini_apk(d))
        if got is not None or dt > 0.05:
            bad.append(f"{name}: {kind(got, a)} {options_of(got)} in {dt * 1000:.0f} ms")
    check(not bad, "pieces listed in order beside an order that fits neither reading: None at once, no join offered",
          "; ".join(bad))
    # a number the family does not read as an order: the fields joined as listed ignore it and are
    # not offered, whether they make the code (listed in order) or another one (the ANS- piece first)
    q = [p[0], p[2], p[1]]
    numbered = [
        ("the order one level down", lambda ps, ns: {**H, "codec": "chunks", "data": "", "payload": {"chunks": ps, "index": ns}}),
        ("two integers in each object", lambda ps, ns: {**H, "codec": "chunks", "data": "",
                                                        "chunks": [{"i": n, "len": len(x), "v": x} for x, n in zip(ps, ns)]}),
        ("separate fields beside an order", lambda ps, ns: {**H, "codec": "concat", "p0": ps[0], "p1": ps[1], "p2": ps[2], "order": ns}),
        ("a list of one-number lists", lambda ps, ns: {**H, "codec": "chunks", "data": "", "chunks": ps, "index": [[n] for n in ns]}),
        ("an order with a repeat", lambda ps, ns: {**judged, "parts": ps, "order": [0, 0, 1]}),
        ("an order of floats", lambda ps, ns: {**judged, "parts": ps, "order": [float(n) for n in ns]}),
        ("an order with a boolean", lambda ps, ns: {**judged, "parts": ps, "order": [True, 2, 0]}),
        ("an order one longer", lambda ps, ns: {**judged, "parts": ps, "order": ns + [3]}),
        ("an order written as an object", lambda ps, ns: {**judged, "parts": ps, "order": {str(i): n for i, n in enumerate(ns)}}),
        ("one number", lambda ps, ns: {**H, "codec": "concat", "data": "", "parts": ps, "count": 3}),
        ("the pieces' lengths", lambda ps, ns: {**H, "codec": "concat", "data": "", "parts": ps, "lengths": [len(x) for x in ps]}),
        ("the pieces' lengths in each object", lambda ps, ns: {**H, "codec": "chunks", "data": "",
                                                             "chunks": [{"len": len(x), "v": x} for x in ps]}),
        ("codec plain, fields beside an order", lambda ps, ns: {**H, "codec": "plain", "data": "", "a": ps[0], "b": ps[1],
                                                              "c": ps[2], "seq": ns}),
    ]
    listings = [(p, [0, 1, 2]), (q, [0, 2, 1])] + [(cut(a, cuts), [0, 1, 2]) for cuts in ((4, 14), (9, 14), (6, 9), (4, 12))]
    bad = []
    for name, f in numbered:
        for ps, ns in listings:
            got, dt = solve(mini_apk(f(ps, ns)))
            if got is not None or dt > 0.05:
                bad.append(f"{name} {[len(x) for x in ps]}: {kind(got, a)} {options_of(got)} in {dt * 1000:.0f} ms")
    check(not bad, f"beside a number that is not read as an order no join is offered, and lengths are no order: {len(numbered)} shapes",
          "; ".join(bad[:4]))
    body = cut(a[4:], (5, 10))
    got, _ = solve(mini_apk({**judged, "parts": [body[i] for i in (2, 0, 1)]}))
    check(got is None, "pieces that arrange to a body without its ANS- prefix are no reading", f"{kind(got, a)} {options_of(got)}")
    # one string that an ascending order leaves as it stands is no reading of a new codec: the codec
    # the document names is applied, and under a name that was not applied the string stays a candidate
    named, _ = solve(mini_apk(doc("rot5", rot5(a), key=[1, 2])))
    twenty, _ = solve(mini_apk(doc("rot5", rot5(a), positions=list(range(20)))))
    opaque, _ = solve(mini_apk(doc("mystery", a[:4] + a[4:][::-1], levels=[1, 2, 3, 4])))
    check(kind(named, a) == "unsure-ok" and options_of(named) == ["rot5"] == options_of(twenty) and opaque is None,
          "an answer-shaped `data` beside an ascending integer list is not offered as it stands",
          f"{kind(named, a)} {options_of(named)} {options_of(twenty)} {kind(opaque, a)} {options_of(opaque)}")
    # an order written as text is cut into tokens: numbers in a note cost one pass, whatever follows them
    noted, dt = capped(mini_apk({**judged, "note": "  ".join(str(i) for i in range(60)) + "."}), "a note of 60 numbers", 3.0)
    table, dt2 = capped(mini_apk(doc("mystery", t, table="\t ".join(str(i) for i in range(24)) + " end")), "a table of 24 numbers", 3.0)
    texts = [C._order(x) for x in ("2,0,1", " 2 0\t1 ", "2;0 , 1", "1,,2", "1 2.", "12345,1", "7", "1,1")]
    check(options_of(noted) == ["split:by-order:extra-fields"] and options_of(table) == ["search:base64"] and max(dt, dt2) < 0.05
          and texts == [[2, 0, 1]] * 3 + [None] * 5,
          "an order written as text is read token by token: a long run of numbers costs no time",
          f"{str(noted)[:40]} in {dt * 1000:.0f} ms, {str(table)[:40]} in {dt2 * 1000:.0f} ms, {texts}")
    # a layout codec with no order list: pieces that give no code by name are not searched either
    real = REAL / "day-05" / DAY5_LANE
    saved = sorted((real / "artifact").glob("*.apk")) if (real / "artifact").is_dir() else []
    members = {}
    if saved:
        with zipfile.ZipFile(saved[0]) as zf:
            members = {i.filename: zf.read(i) for i in zf.infolist()}
    in_apk = lambda d: build({**members, PZ: json.dumps(d).encode()})
    misses = [("three fields under concat", mini_apk({**H, "codec": "concat", "x": p[2], "y": p[0], "z": p[1]})),
              ("two fields under interleave", mini_apk({**H, "codec": "interleave", "odd": a[1::2], "even": a[0::2]})),
              ("the Day 5 APK, parts in order beside an order that fits neither reading",
               in_apk({**judged, "parts": p, "order": [1, 2, 0]}))]
    bad = []
    for name, blob in misses:
        got, dt = solve(blob, name)
        if got is not None or dt > 0.05 or "lays out pieces" not in C.LAST.get("route", ""):
            bad.append(f"{name}: {kind(got, a)} in {dt * 1000:.0f} ms ({C.LAST.get('route', '')[:60]})")
    searched, _ = solve(mini_apk(doc("split", t)))
    if no_attempts():   # the third miss then runs in a bare APK, not inside the saved Day 5 one
        skip("the layout miss inside the saved Day 5 APK (it runs in a bare APK instead)", f"no saved attempts under {REAL}")
    check((bool(members) or no_attempts()) and not bad and kind(searched, a) == "unsure-ok"
          and options_of(searched) == ["search:base64"],
          "a layout codec whose pieces give no code is None at once; a layout name with nothing to lay out is still searched",
          "; ".join(bad) or f"{options_of(searched)}")
    # with no order beside them, pieces under a layout name may sit under one more transform: a short
    # search reads that much and no more; a chain that names more than layouts is searched in full
    deep = base64.b85encode(base64.b85encode(a[::-1].encode())).decode()
    two = lambda codec, text: mini_apk({**H, "codec": codec, "x": text[:len(text) // 2], "y": text[len(text) // 2:]})
    rows = [("concat, the reversed text in two fields", two("concat", a[::-1]), ["search:reverse@join"]),
            ("split, the rot13 text in two fields", two("split", codecs.encode(a, "rot13")), ["search:prefix-caesar@join"]),
            ("split+rot13, three transforms deep", two("split+rot13", deep), ["search:base85>base85>reverse@join"]),
            ("split, three transforms deep", two("split", deep), [])]
    bad = []
    for name, blob, want in rows:
        got, dt = solve(blob, name)
        if options_of(got) != want or (kind(got, a) != "unsure-ok" if want else got is not None or dt > 0.05):
            bad.append(f"{name}: {kind(got, a)} {options_of(got)} in {dt * 1000:.0f} ms")
    check(not bad, "joined pieces under one more transform are found by a short search; a mixed chain is searched in full",
          "; ".join(bad))
    key4 = bytes([7, 99, 150, 33])
    got, _ = solve(mini_apk(doc("xor", b64(xor(a.encode(), key4)), key=list(key4))))
    check(got == a, "xor with an integer-list key that divides the data's length stays on the judged route", kind(got, a))
    # what the ledger learns: a reading's name answers plain; either- says nothing about which reading
    scratch_ledger("challenges-arranged")
    try:
        new = lambda x, order, cuts=(5, 11): mini_apk(split_doc(x, order, cuts, codec="shuffle", pieces="chunks", field="index"))
        first, _ = solve(new(a, (0, 2, 1)))
        labels.learn("mobile.codec/shuffle", either[0], "accepted", scope="key", attempt_id="selftest", answer_ids=["answer"])
        same, _ = solve(new(a, (0, 2, 1)))
        b = ans()
        other, _ = solve(new(b, (2, 0, 1)))
        labels.learn("mobile.codec/shuffle", either[1], "accepted", scope="key", attempt_id="selftest", answer_ids=["answer"])
        after, _ = solve(new(b, (2, 0, 1)))
        both, _ = solve(new(b, (0, 2, 3, 1), (5, 10, 15)))
        check(options_of(first) == either and same == a and options_of(other) == [either[1]] and after == b and both == b,
              "an accepted either- name answers an order that is its own inverse; a reading's name answers the rest",
              f"{options_of(first)} {same == a} {options_of(other)} {after == b} {both == b}")
        # a judged chunk order whose variant has an ascending order: the string as it stands, under the accepted name
        c = ans()
        stands = mini_apk(doc("blocks", c, order=[0, 1, 2, 3]))
        before, _ = solve(stands)
        labels.learn("mobile.codec/blocks", "blocks:by-order:@data:chunks", "accepted", scope="key", attempt_id="selftest",
                     answer_ids=["answer"])
        check(before is None and solve(stands)[0] == c,
              "one string under an ascending order: None for a new codec, plain once the judge has accepted its chunk order",
              f"{kind(before, c)} {options_of(before)} -> {solve(stands)[0] == c}")
    finally:
        scratch_ledger("challenges-synthetic")
    # Layer 1 on the morning of Day 5: the name not yet judged, so one option to probe
    scratch_ledger("challenges-masked-split")
    os.environ.update(CTF_TESTING="1", CTF_LEDGER_MASK="mobile.codec/split," + BASE_MASK)
    try:
        masked, _ = solve(mini_apk(judged))
        want, _ = expected_answers(real)
        base5, _ = solve(saved[0].read_bytes()) if saved else (None, 0)
    finally:
        os.environ.update(CTF_TESTING="1", CTF_LEDGER_MASK=BASE_MASK)
        scratch_ledger("challenges-synthetic")
    parsed = labels.parse(base5) if base5 else None
    if no_attempts():
        check(kind(masked, a) == "unsure-ok" and options_of(masked) == ["split:by-order"],
              "with the name masked, the Day 5 shape is unsure with the one option split:by-order", f"{options_of(masked)}")
        skip("with the name masked, the saved Day 5 base is unsure with the one option split:by-order",
             f"no saved attempts under {REAL}")
        return
    check(kind(masked, a) == "unsure-ok" and options_of(masked) == ["split:by-order"] and parsed is not None and want
          and parsed.key == "mobile.codec/split" and parsed.options == [("split:by-order", want.get("answer"))],
          "with the name masked, the Day 5 shape and the saved Day 5 base are unsure with the one option split:by-order",
          f"{options_of(masked)} {str(base5)[:90]}")


def moves():
    """Position moves on a 20-character `data` and bit moves proven by the known start: unsure, the right value first."""
    chunks = lambda a, n: [a[i:i + n] for i in range(0, 20, n)]
    ror = lambda b, r: bytes(((x >> r) | (x << (8 - r))) & 255 for x in b)
    rows = [
        ("evens then odds in one string", lambda a: doc("interleave", a[0::2] + a[1::2]), "interleave:weave"),
        ("rotated left by `shift`", lambda a: doc("rotate", a[7:] + a[:7], shift=7), "rotate:rotate"),
        ("4-character chunks, each reversed", lambda a: doc("chunk-reverse", "".join(c[::-1] for c in chunks(a, 4)), size=4),
         "chunk-reverse:chunks4-reversed"),
        ("4-character chunks in reverse order", lambda a: doc("blocks-reversed", "".join(chunks(a, 4)[::-1]), size=4),
         "blocks-reversed:blocks4-reversed"),
        ("halves swapped", lambda a: doc("swap", a[10:] + a[:10]), "swap:rotate"),
        ("adjacent characters swapped", lambda a: doc("swap-pairs", "".join(a[i + 1] + a[i] for i in range(0, 20, 2))),
         "swap-pairs:chunks2-reversed"),
        ("no codec named, rotated", lambda a: {**H, "data": a[13:] + a[:13]}, "unnamed:rotate"),
        ("nibble swap", lambda a: doc("nibble-swap", b64(ror(a.encode(), 4))), "search:base64>prefix-rol"),
        ("bit order reversed", lambda a: doc("mirror", b64(bytes(int(f"{x:08b}"[::-1], 2) for x in a.encode()))),
         "search:base64>prefix-bitrev"),
    ] + [(f"every byte rotated by {r} bits", lambda a, r=r: doc("rol", ror(a.encode(), r).hex()), "search:hex>prefix-rol")
         for r in (1, 2, 3, 5, 6, 7)]
    bad = []
    for name, f, route in rows:
        firsts, kinds = set(), {}
        for _ in range(TRIALS):
            a = ans()
            got, _ = solve(mini_apk(f(a)), name)
            kinds[kind(got, a)] = kinds.get(kind(got, a), 0) + 1
            firsts.update(options_of(got)[:1])
        if kinds.get("unsure-ok", 0) + kinds.get("unsure-first", 0) != TRIALS or firsts != {route}:
            bad.append(f"{name}: {kinds} {sorted(firsts)}")
        if VERBOSE:
            print(f"   {name:40} {kinds} {sorted(firsts)}")
    check(not bad, f"position moves and bit moves are unsure with the right value first: {len(rows)} documents", "; ".join(bad[:4]))
    a = ans()
    got, _ = solve(mini_apk(doc("blocks-reversed", "".join(chunks(a, 4)[::-1]))))
    check(kind(got, a) == "unsure-first" and options_of(got) == ["blocks-reversed:blocks4-reversed", "blocks-reversed:rotate"],
          "two position moves that fit with different values are two options, the one the codec names first",
          f"{kind(got, a)} {options_of(got)}")
    still = [C.positional(d, "") for d in (doc("x", a), doc("x", a[:4] + a[4:][::-1]), doc("x", a[1:] + "G"), doc("x", a[3:] + a[:2]))]
    bits = [t for t, _ in C.keyless(a.encode()) if re.fullmatch(r"prefix-(rol|bitrev)", t)]
    check(still == [[], [], [], []] and not bits,
          "an answer-shaped `data` is moved by nothing, and text that is no scrambled code is left alone", f"{still} {bits}")


def keyed():
    """Keyed shifts with a key of several characters: unsure under a route of their own, the right value offered."""
    # the key index advancing on every character: vigenere adds the key letter, beaufort is key minus letter
    every = lambda a, key: "".join(chr((ord(c) + ord(key[i % len(key)]) - 130) % 26 + 65) if c.isupper() else c
                                   for i, c in enumerate(a))
    beau_every = lambda a, key: "".join(chr((ord(key[i % len(key)]) - ord(c)) % 26 + 65) if c.isupper() else c
                                        for i, c in enumerate(a))

    def beau(a, key):
        out, j = "", 0
        for c in a:
            out += chr((ord(key[j % len(key)]) - ord(c)) % 26 + 65) if c.isupper() else c
            j += c.isupper()
        return out

    add = lambda b, k: bytes((x + k[i % len(k)]) % 256 for i, x in enumerate(b))
    p95 = lambda a, ks: "".join(chr((ord(c) - 32 + ks[i % len(ks)]) % 95 + 32) for i, c in enumerate(a))
    rows = [
        ("vigenere, the key index on letters", lambda a: doc("vigenere", vig(a, "HUNTRESS"), key="HUNTRESS"), "vigenere"),
        ("vigenere, the key index on every character", lambda a: doc("vigenere", every(a, "HUNT"), key="HUNT"),
         "vigenere:letters-every"),
        ("vig, bytes under an integer-list key", lambda a: doc("vig", add(a.encode(), [3, 1, 4, 1, 5]).decode("latin-1"),
                                                               key=[3, 1, 4, 1, 5]), "vig:bytes"),
        ("vigenere, bytes under base64", lambda a: doc("vigenere", b64(add(a.encode(), b"KEY")), key="KEY"), "vigenere:bytes"),
        ("vigenere, printable (key less 32)", lambda a: doc("vigenere", p95(a, [ord(c) - 32 for c in "KEY"]), key="KEY"),
         "vigenere:printable"),
        ("vigenere, printable (key as it stands)", lambda a: doc("vigenere", p95(a, [40, 70, 90]), key=[40, 70, 90]),
         "vigenere:printable-raw"),
        ("vigenere, no key: a 3-byte add from the prefix", lambda a: doc("vigenere", b64(add(a.encode(), [5, 9, 2]))),
         "vigenere:prefix-add3"),
        ("beaufort, the key index on letters", lambda a: doc("beaufort", beau(a, "HUNT"), key="HUNT"), "beaufort"),
        ("beaufort, the key index on every character", lambda a: doc("beaufort", beau_every(a, "HUNT"), key="HUNT"),
         "beaufort:letters-every"),
        ("shift with a list of shifts", lambda a: doc("shift", p95(a, [1, 2, 3]), shifts=[1, 2, 3]), "shift:bytes"),
        ("caesar with a key list, base64", lambda a: doc("caesar", b64(add(a.encode(), [4, 9])), key=[4, 9]), "caesar:bytes"),
    ]
    bad, firsts = [], 0
    for name, f, route in rows:
        kinds = {}
        for _ in range(TRIALS):
            a = ans()
            got, _ = solve(mini_apk(f(a)), name)
            parsed = labels.parse(got) if got else None
            k = kind(got, a)
            kinds[k] = kinds.get(k, 0) + 1
            if parsed is None or (route, a) not in parsed.options:
                bad.append(f"{name}: {k} {options_of(got)}")
                break
            firsts += parsed.options[0] == (route, a)
        if VERBOSE:
            print(f"   {name:50} {kinds}")
    check(not bad, f"keyed shifts are unsure with the right value under their own route: {len(rows)} documents",
          "; ".join(bad[:4]))
    check(firsts >= 0.9 * TRIALS * len(rows), "keyed shifts: the right value is the first option nearly always",
          f"{firsts} of {TRIALS * len(rows)}")
    day7, _ = tally(lambda a: doc("caesar", "".join(chr(ord(c) + 10) for c in a), key=10), "caesar day 7 shape")
    check(day7.get("plain-ok") == TRIALS or SEED.get("caesar") != "caesar",
          "Day 7's caesar shape (a one-byte key, bytes shifted) is still plain", str(day7))
    a = ans().encode()
    tags = [t for t, _ in C.keyless(add(a, [7]))] + [t for t, _ in C.keyless(add(a, [7, 7, 7, 7]))]
    check(not any(re.fullmatch(r"prefix-add\d", t) for t in tags) and "prefix-add2" in [t for t, _ in C.keyless(add(a, [7, 3]))],
          "a repeating add of one byte stays prefix-add, and two bytes are prefix-add2", str(tags))


def rail(s, n):
    """s written out by a rail fence of n rails (the encoder)."""
    rows, r, step = [[] for _ in range(n)], 0, 1
    for c in s:
        rows[r].append(c)
        step = 1 if r == 0 else -1 if r == n - 1 else step
        r += step
    return "".join("".join(x) for x in rows)


def affine_letters(s, a, b):
    return "".join(chr((a * (ord(c) - 65) + b) % 26 + 65) if c.isupper() else c for c in s)


def affine_bytes(bs, a, b):
    return bytes((a * c + b) % 256 for c in bs)


def substitute(s, plain, cipher):
    return s.translate(str.maketrans(plain, cipher))


LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CIPHER = "QWERTYUIOPASDFGHJKLZXCVBNM"
ALNUM = "0123456789" + LETTERS


def codec_pack():
    """Row 72: rail fence, affine, keyed substitution, chains of named steps, a key read from another field.

    Every document is unsure under its own route with the right value, first nearly always;
    a judged codec in its judged shape stays plain; near misses and documents with nothing to
    read are None; work that multiplies stays inside the budget."""
    def kw_alpha(word):
        letters = "".join(dict.fromkeys(c for c in word.upper() if c.isalpha()))
        return letters + "".join(c for c in LETTERS if c not in letters)

    alnum_cipher = "".join(random.Random(72).sample(ALNUM, len(ALNUM)))
    vig_every = lambda a, key: "".join(chr((ord(c) + ord(key[i % len(key)]) - 130) % 26 + 65) if c.isupper() else c
                                       for i, c in enumerate(a))
    rows = [
        # rail fence: the count from a field, another field, a reference, or searched and proved by ANS-
        ("railfence, rails field", lambda a: doc("railfence", rail(a, 3), rails=3), "railfence"),
        ("rail_fence, rails under key", lambda a: doc("rail_fence", rail(a, 4), key=4), "rail_fence:rails=key"),
        ("rail-fence, rails as text", lambda a: doc("rail-fence", rail(a, 5), rails="5"), "rail-fence"),
        ("railfence, rails named by rails_from", lambda a: doc("railfence", rail(a, 6), rails_from="seed", seed=6),
         "railfence:rails=seed"),
        ("railfence, no rails: searched", lambda a: doc("railfence", rail(a, rnd.randrange(2, 7))), "railfence:rails-searched"),
        ("railfence, 7 rails searched: 8 moves the prefix alike", lambda a: doc("railfence", rail(a, 7)),
         "railfence:rails-searched:7"),
        ("zigzag under base64, searched", lambda a: doc("zigzag", b64(rail(a, 3).encode())), "zigzag:rails-searched"),
        ("railfence then base64 as a chain", lambda a: doc("railfence+base64", b64(rail(a, 4).encode()), rails=4),
         "railfence+base64"),
        # affine: letters mod 26, bytes mod 256, a and b from fields, a key pair, references, searched
        ("affine, a and b", lambda a: doc("affine", affine_letters(a, 5, 8), a=5, b=8), "affine"),
        ("affine, multiplier and shift", lambda a: doc("affine", affine_letters(a, 7, 3), multiplier=7, shift=3),
         "affine:a=multiplier:b=shift"),
        ("affine, key [a, b]", lambda a: doc("affine", affine_letters(a, 11, 20), key=[11, 20]), "affine:ab=key"),
        ("affine, bytes mod 256 under base64", lambda a: doc("affine", b64(affine_bytes(a.encode(), 37, 11)), a=37, b=11),
         "affine:bytes"),
        ("affine, no parameters: searched", lambda a: doc("affine", affine_letters(a, rnd.choice([3, 5, 9, 15, 25]),
                                                                                    rnd.randrange(26))), "affine:prefix-ab"),
        ("affine, a given, b searched", lambda a: doc("affine", affine_letters(a, 9, 14), a=9), "affine:prefix-b"),
        ("affine bytes, no parameters: searched", lambda a: doc("affine", b64(affine_bytes(a.encode(), 2 * rnd.randrange(128) + 1,
                                                                                          rnd.randrange(256)))),
         "affine:bytes:prefix-ab"),
        ("affine, a by reference", lambda a: doc("affine", affine_letters(a, 21, 2), a="$mult", mult=21, b=2), "affine:a=mult"),
        # keyed substitution: a cipher alphabet, a keyword, a map, a pair of fields, alphanumeric
        ("substitution, alphabet", lambda a: doc("substitution", substitute(a, LETTERS, CIPHER), alphabet=CIPHER),
         "substitution"),
        ("substitution, keyword under key", lambda a: doc("substitution", substitute(a, LETTERS, kw_alpha("HUNTRESS")),
                                                          key="HUNTRESS"), "substitution:keyword:alphabet=key"),
        ("keyword, keyword field", lambda a: doc("keyword", substitute(a, LETTERS, kw_alpha("MOBILE")), keyword="MOBILE"),
         "keyword:keyword:alphabet=keyword"),
        ("substitution, alphanumeric alphabet", lambda a: doc("substitution", substitute(a, ALNUM, alnum_cipher),
                                                              alphabet=alnum_cipher), "substitution"),
        ("substitution, a map", lambda a: doc("substitution", substitute(a, LETTERS, CIPHER),
                                              map=dict(zip(CIPHER, LETTERS))), "substitution:map:alphabet=map"),
        ("substitution, plain and cipher fields", lambda a: doc("subst", substitute(a, LETTERS, CIPHER), plain=LETTERS,
                                                                cipher=CIPHER), "subst:pair=plain"),
        ("substitution, alphabet by alphabet_field", lambda a: doc("substitution", substitute(a, LETTERS, CIPHER),
                                                                   alphabet_field="table2", table2=CIPHER),
         "substitution:alphabet=table2"),
        # chains of two named steps, in the order the document names them or reversed
        ("reverse then caesar", lambda a: doc("reverse+caesar", caesar(a[::-1], 3), key=3), "reverse+caesar"),
        ("base64 then vigenere, decode order", lambda a: doc("base64>vigenere", b64(vig(a, "KEY").encode()), key="KEY"),
         "base64+vigenere"),
        ("chain with a steps list", lambda a: doc("chain", b64(a[::-1].encode()), steps=["reverse", "base64"]),
         "reverse+base64:steps=steps"),
        ("pipeline with step1 and step2", lambda a: {**doc("pipeline", rail(caesar(a, 4), 3)), "step1": "caesar",
                                                     "step2": "railfence", "key": 4, "rails": 3},
         "caesar+railfence:steps=stepn"),
        ("chain with outer and inner", lambda a: {**doc("chain", b64(affine_letters(a, 5, 1).encode())), "outer": "base64",
                                                  "inner": "affine", "a": 5, "b": 1}, "base64+affine:steps=outer"),
        # a key read from another named field
        ("vigenere, key_field names the field", lambda a: doc("vigenere", vig_every(a, "SALT"), key_field="secret",
                                                              secret="SALT"), "vigenere:letters-every"),
        ("vigenere, key_from names the field", lambda a: doc("vigenere", vig(a, "PEPPER"), key_from="nonce",
                                                             nonce="PEPPER"), "vigenere"),
        ("railfence then xor, key named by key_field", lambda a: doc("xor+railfence", b64(xor(rail(a, 3).encode(), b"\x2a")),
                                                                     rails=3, key_field="nonce", nonce=42),
         "xor+railfence"),
    ]
    bad, firsts, plain = [], 0, []
    for name, f, route in rows:
        kinds = {}
        for _ in range(TRIALS):
            a = ans()
            got, _ = solve(mini_apk(f(a)), name)
            parsed = labels.parse(got) if got else None
            k = kind(got, a)
            kinds[k] = kinds.get(k, 0) + 1
            if k.startswith("plain"):
                plain.append(f"{name}: {k}")
                break
            if parsed is None or (route, a) not in parsed.options or k in ("unsure-wrong", "unsure-later"):
                bad.append(f"{name}: {k} {options_of(got)[:3]}")
                break
            firsts += parsed.options[0] == (route, a)
        if VERBOSE:
            print(f"   {name:50} {kinds}")
    check(not bad, f"row 72: every new reading is unsure with the right value under its own route: {len(rows)} documents",
          "; ".join(bad[:4]))
    check(not plain, "row 72: no new reading is answered plain before the judge accepts it", "; ".join(plain[:4]))
    check(firsts >= 0.95 * TRIALS * len(rows), "row 72: the right value is the first option nearly always",
          f"{firsts} of {TRIALS * len(rows)}")
    # a judged codec in its judged shape is still plain, also next to the new fields
    judged = [tally(lambda a: doc("caesar", "".join(chr(ord(c) + 18) for c in a), key=18), "caesar day 7 shape")[0],
              tally(lambda a: doc("xor", b64(xor(a.encode(), b"\x67")), key=103), "xor day 4 shape")[0],
              tally(lambda a: doc("base64+xor", b64(xor(a.encode(), b"\x07")), key=7), "base64+xor judged chain")[0]]
    want = [SEED.get("caesar") == "caesar", SEED.get("xor") == "xor", SEED.get("xor") == "xor"]
    check(all(j.get("plain-ok") == TRIALS for j, w in zip(judged, want) if w), "row 72: judged shapes stay plain", str(judged))
    # near misses and documents with nothing to read: None, never a wrong answer
    misses = [
        ("railfence, the wrong rails", lambda a: doc("railfence", rail(a, 3), rails=5)),
        ("railfence of something else", lambda a: doc("railfence", rail("NOT-AN-ANSWER-AT-ALL", 3))),
        ("affine, the wrong b", lambda a: doc("affine", affine_letters(a, 5, 8), a=5, b=9)),
        ("affine, a with no inverse", lambda a: doc("affine", affine_letters(a, 5, 8), a=13, b=8)),
        ("substitution, the wrong alphabet", lambda a: doc("substitution", substitute(a, LETTERS, CIPHER),
                                                           alphabet=CIPHER[::-1])),
        ("chain, no steps listed", lambda a: doc("chain", b64(a[::-1].encode()), steps=[])),
    ]
    wrong = []
    for name, f in misses:
        for _ in range(TRIALS):
            a = ans()
            got, _ = solve(mini_apk(f(a)), name)
            k = kind(got, a)
            # the general search may still offer a code through other moves, unsure; a reading of row 72 may not
            if k.startswith("plain") or (k != "none" and not all(n.startswith("search:") for n in options_of(got))):
                wrong.append(f"{name}: {k} {options_of(got)[:2]}")
                break
    check(not wrong, f"row 72: near misses are None (or a general search's unsure offer), never plain: {len(misses)} documents",
          "; ".join(wrong))
    # with no table a substitution has no reading of its own: never plain (the general search may still offer one, unsure)
    counts, _ = tally(lambda a: doc("substitution", substitute(a, LETTERS, CIPHER)), "substitution, no table")
    check(not counts.get("plain-ok") and not counts.get("plain-wrong"), "row 72: a substitution with no table is never plain",
          str(counts))
    # 8 rails searched: 7 proves a code too, so both are offered under their counts, 7 first
    x = ans()
    got, _ = solve(mini_apk(doc("railfence", rail(x, 8))), "railfence, 8 rails searched")
    check(options_of(got) == ["railfence:rails-searched:7", "railfence:rails-searched:8"]
          and labels.parse(got).options[1][1] == x, "row 72: two searched rail counts that prove different codes are both offered",
          str(got)[:160])
    # helpers: a searched parameter that proves two answers offers neither; a reference is followed
    a1, a2 = ans().encode(), ans().encode()
    check(C._one([(a1, "x"), (a2, "x")]) == [] and C._one([(a1, "x"), (a1, "y")]) == [(a1, "x")],
          "row 72: a search that proves two different answers offers neither")
    p = {"codec": "railfence", "rails": "seed", "seed": 7, "a_from": "m", "m": 5, "b": "$n", "n": 3}
    check(C.params(p, C.RAILS)[:1] == [(7, "rails=seed")] and C.params(p, C.AFFINE_A) == [(5, "a=m")]
          and C.params(p, C.AFFINE_B) == [(3, "b=n")], "row 72: a parameter that names another field reads that field",
          str([C.params(p, C.RAILS), C.params(p, C.AFFINE_A), C.params(p, C.AFFINE_B)]))
    # both orders when unclear: the reversed order's different code follows the first, tagged order-reversed
    x, y = ans(), ans()
    saved = dict(C.KEYED)
    try:
        C.KEYED["t1"] = lambda d, p, clock: [({b"S": b"T", b"U": y.encode()}.get(d, b""), "")]
        C.KEYED["t2"] = lambda d, p, clock: [({b"S": b"U", b"T": x.encode()}.get(d, b""), "")]
        got = C.by_name(["t1", "t2"], [("data", b"S")], [], [], C.Clock(), {})
    finally:
        C.KEYED.clear()
        C.KEYED.update(saved)
    check(got is not None and got[0] == x and got[3] == ((y, ("order-reversed",)),),
          "row 72: a chain whose two orders give different codes offers the listed order first, then order-reversed",
          str(got))
    # work that multiplies: a miss inside the budget
    junk = lambda n: bytes(rnd.randrange(256) for _ in range(n))
    attacks = [
        ("railfence over 4000 characters with 2000 integer fields", doc("railfence", "Q" * 4000,
                                                                       **{f"k{i}": 2 + i % 60 for i in range(2000)})),
        ("eight railfence steps, no rails", doc(["railfence"] * 8, b64(junk(3000)))),
        ("eight affine steps over 4000 bytes", doc(["affine"] * 8, b64(junk(3000)), a=5, b=7)),
        ("substitution with 40 alphabets, eight steps", doc(["substitution"] * 8, "ABCD" * 1000,
                                                            **{f"alphabet{i}": "".join(random.Random(i).sample(LETTERS, 26))
                                                               for i in range(40)}, alphabet=CIPHER)),
        ("a chain of eight listed steps", doc("chain", b64(junk(3000)), steps=["railfence", "affine", "substitution", "xor",
                                                                              "vigenere", "caesar", "railfence", "affine"],
                                              key="KEY", alphabet=CIPHER, a=3, b=1, rails=3)),
    ]
    slow = []
    for name, d in attacks:
        got, dt = capped(mini_apk(d), name)
        if VERBOSE:
            print(f"   {name:52} {dt * 1000:6.0f} ms -> {str(got)[:40]!r}")
        if got is not None or dt >= MISS_LIMIT:
            slow.append(f"{name}: {str(got)[:30]!r} after {dt * 1000:.0f} ms")
    check(not slow, f"row 72: work that multiplies is a miss inside the budget: {len(attacks)} documents", "; ".join(slow))


def synthetic():
    rows = []
    for name, f in cases():
        counts, route = tally(f, name)
        rows.append((name, counts, route))
        if VERBOSE:
            print(f"   {name:50} {counts} {route[:60]}")
    full = lambda counts, kinds: sum(counts.get(k, 0) for k in kinds) == TRIALS
    solved = [n for n, c, _ in rows if full(c, ("plain-ok", "unsure-ok"))]
    wrong_plain = [n for n, c, _ in rows if c.get("plain-wrong")]
    wrong_unsure = [n for n, c, _ in rows if c.get("unsure-wrong") or c.get("unsure-later")]  # a wrong value first is wrong
    unsolved = [n for n, c, _ in rows if n not in solved]
    check(len(rows) == 79, "the synthetic suite has 79 documents", str(len(rows)))
    check(len(solved) >= 73, "synthetic: at least 73 of 79 solved", f"{len(solved)} solved; not solved: {unsolved}")
    check(not wrong_plain, "synthetic: no wrong plain answer", str(wrong_plain))
    check(not wrong_unsure, "synthetic: no wrong unsure answer", str(wrong_unsure))
    by = {n: c for n, c, _ in rows}
    check(all(by[n].get("none") == TRIALS for n in RESIDUAL), "the prototype's two wrong documents come back None",
          str({n: by[n] for n in RESIDUAL}))
    check(all(by[n].get("plain-ok") == TRIALS for n in JUDGED),
          f"the seed's judged codecs are plain in their judged shape: {len(JUDGED)} documents",
          str({n: by[n] for n in JUDGED if by[n].get("plain-ok") != TRIALS}))
    check(not any(by[n].get("plain-ok") or by[n].get("plain-wrong") for n in NEVER_PLAIN),
          "caesar with no parameter and rot7 are never plain", str({n: by[n] for n in NEVER_PLAIN}))
    unshaped = sorted(set(SEED) - {codec for needs in SHAPES.values() for codec, _ in needs})
    if unshaped:  # not a failure: the codec's day replays it (tools/preflight.py); add its shape to SHAPES
        print(f"INFO seed codecs with no synthetic shape here: {unshaped}")
    plain_others = [n for n, c, _ in rows if c.get("plain-ok") and not _judged_shape(n)]
    check(not plain_others, "nothing but a judged codec is answered plain", str(plain_others))


def _judged_shape(name) -> bool:
    """Is this synthetic document one a judged codec name answers?

    The shapes in JUDGED (read from the seed), and while the seed accepts the names the Day 4
    solver applies (xor, and base64, reverse and xor for a chain) the other documents of those names in
    the `codec` field, with the text in `data`: what puzzle_asset_codec.by_codec solves."""
    xor_ok = SEED.get("xor") == "xor"
    chain_ok = xor_ok and SEED.get("base64") == "base64" and SEED.get("reverse") == "reverse"
    return name in JUDGED or xor_ok and name.startswith("xor ") and name not in (
        "xor 4-byte key, key absent", "xor 8-byte key, key absent (key in dex)", "xor rolling key (k+i)",
        "xor then reverse then base64", "xor key = the 'day' field", "xor 'key' nested in params obj",
        "xor 1-byte, key field absent") or chain_ok and name.startswith("chain") and "rot13" not in name


def hostile():
    bad, report = [], {}
    for name, f in HOSTILE:
        counts, _ = tally(f, name)
        report[name] = counts
        if counts.get("plain-wrong") or counts.get("plain-ok"):
            bad.append(name)
    check(not bad, "hostile documents: never a plain answer", str(bad))
    closed = [n for n in ("hex complement of body (F-h)", "adjacent pair swap of body", "body rotated left by key",
                          "rot5 under an opaque name", "rot5 with no codec field", "answer-shaped data, codec missing",
                          "answer-shaped data under a layout name", "two different answers in one field",
                          "base64 under an opaque name, decoy field beside it",
                          "scrambled data, an answer-shaped decoy beside it")
              if report[n].get("none") != TRIALS]
    check(not closed, "answer-shaped text under a codec that was not applied is None", str({n: report[n] for n in closed}))
    # Not a failure, and not hidden: a search hit under an opaque codec name is unsure by
    # the contract, and for these documents the candidate is wrong. It costs one probe on
    # the untimed base, where the judge rejects the route, and is never sent on a clock.
    wrong = [n for n, c in report.items() if c.get("unsure-wrong") or c.get("unsure-later")]
    print(f"INFO hostile documents whose unsure candidate is wrong (one base probe each): {wrong}")
    if VERBOSE:
        for n, c in report.items():
            print(f"   {n:50} {c}")
    return report


def rot_only_when_named(report):
    named = {}
    for name, f in (("rot5", lambda a: doc("rot5", rot5(a))), ("rot18", lambda a: doc("rot18", rot18(a)))):
        named[name], _ = tally(f, name)
    check(all(c.get("unsure-ok") == TRIALS for c in named.values()), "rot5 and rot18 are solved when named", str(named))
    unnamed = {n: report[n] for n in ("rot5 under an opaque name", "rot5 with no codec field", "rot18 under an opaque name")}
    check(not any(c.get("plain-ok") or c.get("unsure-ok") or c.get("plain-wrong") for c in unnamed.values()),
          "rot5 and rot18 are not solved when not named", str(unnamed))
    a = ans()
    got, _ = solve(mini_apk(doc("rot18", rot18(a))))
    parsed = labels.parse(got)
    check(parsed is not None and parsed.key == "mobile.codec/rot18" and parsed.options == [("rot18", a)],
          "a named new codec is unsure under mobile.codec/<codec>, the route as its name", str(got)[:100])


B32STD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def b32alt(b, alphabet, pad=True):
    s = base64.b32encode(b).translate(bytes.maketrans(B32STD, alphabet)).decode()
    return s if pad else s.rstrip("=")


def z85(b):
    return base64.b85encode(b).decode().translate(str.maketrans(
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~",
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"))


def near_miss():
    """ANS- and sixteen letters past F: what a decode that worked but found no answer code gives."""
    return "ANS-" + "".join(rnd.choice("GHIJKLMNOPQRSTUVWXYZ") for _ in range(16))


def next_codecs():
    """The likely next codecs: (codec name in the document, encoder from the answer text to `data`)."""
    import bz2
    import lzma
    B32HEX, CROCK = b"0123456789ABCDEFGHIJKLMNOPQRSTUV", b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    e = lambda f: (lambda a: f(a.encode()))
    return [
        ("base32", e(lambda b: base64.b32encode(b).decode())),
        ("base32hex", e(lambda b: b32alt(b, B32HEX))),
        ("base32-hex", e(lambda b: b32alt(b, B32HEX, pad=False))),
        ("crockford", e(lambda b: b32alt(b, CROCK, pad=False))),
        ("rot13", lambda a: codecs.encode(a, "rot13")),
        ("rot_13", lambda a: codecs.encode(a, "rot13")),
        ("rot7", lambda a: caesar(a, 7)),
        ("rot-7", lambda a: caesar(a, 7)),
        ("rot_7", lambda a: caesar(a, 7)),
        ("caesar_3", lambda a: caesar(a, 3)),
        ("rot47", rot47),
        ("rot-47", rot47),
        ("atbash", atbash),
        ("gzip", e(lambda b: b64(gzip.compress(b)))),
        ("zlib", e(lambda b: b64(zlib.compress(b)))),
        ("deflate", e(lambda b: b64(zlib.compress(b)[2:-4]))),
        ("bzip2", e(lambda b: b64(bz2.compress(b)))),
        ("xz", e(lambda b: b64(lzma.compress(b)))),
        ("lzma", e(lambda b: lzma.compress(b, format=lzma.FORMAT_ALONE).hex())),
        ("ascii85", e(lambda b: base64.a85encode(b).decode())),
        ("base85", e(lambda b: base64.b85encode(b).decode())),
        ("z85", e(z85)),
        ("urlsafe_base64", e(lambda b: base64.urlsafe_b64encode(b).decode().rstrip("="))),
        ("base64url+xor", e(lambda b: base64.urlsafe_b64encode(xor(b, b"\xff")).decode())),
        ("base32+rot13", e(lambda b: codecs.encode(base64.b32encode(b).decode(), "rot13"))),
        ("gzip+base64", e(lambda b: b64(gzip.compress(b)))),
        ("reverse|rot47", lambda a: rot47(a)[::-1]),
        ("atbash>base64", lambda a: b64(atbash(a).encode())),
        (["base64", "bz2"], e(lambda b: b64(bz2.compress(b)))),
    ]


def codecs_next():
    scratch_ledger("challenges-codecs")
    trials, bad, missed, keys = 5, {}, {}, {}
    for name, enc in next_codecs():
        extra = {"key": 255} if "xor" in name else {}
        label = "+".join(name) if isinstance(name, list) else name
        counts = {}
        for _ in range(trials):
            a = ans()
            got, _ = solve(mini_apk(doc(name, enc(a), **extra)), label)
            k = kind(got, a)
            counts[k] = counts.get(k, 0) + 1
            parsed = labels.parse(got) if got else None
            if parsed:
                keys[label] = parsed.key
        if counts.get("unsure-ok") != trials:
            bad[label] = counts
        # a near miss decodes under the named codec but gives no answer code; garbage does not decode
        for what, data in (("near miss", enc(near_miss())), ("garbage", "!!" + enc(ans())[::-1][2:] + "~|")):
            got, _ = solve(mini_apk(doc(name, data, **extra)), f"{label} {what}")
            if got is not None:
                missed[f"{label} {what}"] = str(got)[:80]
    check(not bad, "the likely next codecs are applied by name, unsure, every option the right code",
          str(bad) if bad else f"{len(next_codecs())} documents x {trials}")
    wrong_key = {n: k for n, k in keys.items() if k != "mobile.codec/" + re.sub(r"[|>]", "+", n)}
    check(not wrong_key, "each is offered under mobile.codec/<the document's codec name>, a chain's steps joined by +",
          str(wrong_key))
    check(not missed, "a near miss and garbage under each of them are None", str(missed))
    # an alphabet that reads most upper-case text is applied only by name, never by the search
    a = ans()
    got, _ = solve(mini_apk(doc("mystery", b32alt(a.encode(), b"0123456789ABCDEFGHIJKLMNOPQRSTUV"))), "base32hex unnamed")
    z, _ = solve(mini_apk(doc("mystery", z85(a.encode()))), "z85 unnamed")
    check(got is None and z is None, "base32hex and Z85 are not search moves: under an opaque name they are None",
          f"{str(got)[:40]} {str(z)[:40]}")
    # once the judge accepts a new codec's route it is plain, on this variant and the next, and only for that name
    a = ans()
    first, _ = solve(mini_apk(doc("base32", base64.b32encode(a.encode()).decode())))
    parsed = labels.parse(first)
    if parsed and parsed.options:
        labels.learn(parsed.key, parsed.options[0][0], "accepted", scope="key", attempt_id="selftest",
                     answer_ids=["answer"], left=None)
    b = ans()
    nxt, _ = solve(mini_apk(doc("base32", base64.b32encode(b.encode()).decode())))
    other, _ = solve(mini_apk(doc("base32hex", b32alt(b.encode(), b"0123456789ABCDEFGHIJKLMNOPQRSTUV"))))
    check(parsed is not None and parsed.options == [("base32", a)] and nxt == b and kind(other, b) == "unsure-ok",
          "an accepted base32 is plain on the next variant; base32hex stays unsure",
          f"{str(first)[:50]} next={nxt == b} base32hex={kind(other, b)}")
    scratch_ledger("challenges-synthetic")


def ledger():
    scratch_ledger("challenges-ledger")
    a = ans()
    first, _ = solve(mini_apk(doc("base85", base64.b85encode(a.encode()).decode())))
    parsed = labels.parse(first)
    ok = parsed is not None and parsed.options == [("base85", a)]
    if ok:
        labels.learn(parsed.key, parsed.options[0][0], "accepted", scope="key", attempt_id="selftest",
                     answer_ids=["answer"], left=None)
    again, _ = solve(mini_apk(doc("base85", base64.b85encode(a.encode()).decode())))
    b = ans()
    nxt, _ = solve(mini_apk(doc("base85", base64.b85encode(b.encode()).decode())))
    check(ok and again == a and nxt == b, "an accepted route is plain afterwards, on this variant and the next",
          f"before={str(first)[:50]!r} after={again!r} next variant={nxt == b}")
    # the acceptance is for that route only: the same codec name reached another way stays unsure
    c = ans()
    other, _ = solve(mini_apk({**H, "codec": "base85", "payload": base64.b85encode(c.encode()).decode()}))
    check(kind(other, c) == "unsure-ok", "another route under an accepted codec name stays unsure", str(other)[:90])
    # a search route, accepted under the document's opaque codec name
    d = ans()
    layered = lambda x: doc("layered", b64(b64(x.encode()).encode()))
    first, _ = solve(mini_apk(layered(d)))
    parsed = labels.parse(first)
    if parsed and parsed.options:
        labels.learn(parsed.key, parsed.options[0][0], "accepted", attempt_id="selftest", answer_ids=["answer"])
    e = ans()
    nxt, _ = solve(mini_apk(layered(e)))
    check(parsed is not None and parsed.key == "mobile.codec/layered" and nxt == e,
          "an accepted search route is plain on the next variant", f"{parsed} -> {nxt == e}")
    # a rejected route is no answer at all
    f = ans()
    first, _ = solve(mini_apk(doc("rot13", codecs.encode(f, "rot13"))))
    parsed = labels.parse(first)
    if parsed and parsed.options:
        labels.learn(parsed.key, parsed.options[0][0], "rejected", scope="key", attempt_id="selftest",
                     answer_ids=["answer"], left=None)
    again, _ = solve(mini_apk(doc("rot13", codecs.encode(f, "rot13"))))
    check(parsed is not None and again is None, "a rejected route is None", f"{str(first)[:50]!r} -> {again!r}")
    # a judged codec that the judge later rejects is no longer plain
    g = ans()
    labels.learn("mobile.codec/reverse", "reverse", "rejected", scope="key", attempt_id="selftest",
                 answer_ids=["answer"], left=None)
    got, _ = solve(mini_apk(doc("reverse", g[::-1])))
    chain, _ = solve(mini_apk(doc("reverse+base64", b64(g[::-1].encode()))))
    check(kind(got, g) == "unsure-ok" and kind(chain, g) == "unsure-ok",
          "a judged codec the judge then rejects goes back to unsure, and so do its chains",
          f"{kind(got, g)}, {kind(chain, g)}")
    # the rehearsal knob: a masked seed name has to be found again by probing
    scratch_ledger("challenges-masked")
    os.environ.update(CTF_TESTING="1", CTF_LEDGER_MASK="mobile.codec/xor," + BASE_MASK)
    try:
        h = ans()
        masked, _ = solve(mini_apk(doc("xor", b64(xor(h.encode(), b"\x1d")), key=29)))
        other, _ = solve(mini_apk(doc("base64", b64(h.encode()))))
    finally:
        os.environ.update(CTF_TESTING="1", CTF_LEDGER_MASK=BASE_MASK)
    check(kind(masked, h) == "unsure-ok" and other == h, "a codec masked for a rehearsal is unsure; the others stay plain",
          f"{kind(masked, h)}, {kind(other, h)}")
    scratch_ledger("challenges-synthetic")


def day4_apk():
    """(members, truth, secret, package) of the saved Day 4 base APK, or None when it is not on disk."""
    d = REAL / "day-04" / "mobile-android-day-04-pending-intent-relay"
    want, _ = expected_answers(d)
    apks = sorted((d / "artifact").glob("*.apk")) if (d / "artifact").is_dir() else []
    if not want or not apks:
        return None
    with zipfile.ZipFile(apks[0]) as zf:
        members = {i.filename: zf.read(i) for i in zf.infolist()}
    strings = C.app_strings(members)
    secret = next((m.group(0) for s in strings for m in [re.search(rb"SECRET-[0-9A-F]{8,}", s)] if m), None)
    package = next((s for s in strings if re.fullmatch(rb"com\.huntress\.[\w.]+", s)), None)
    return members, want["answer"], secret, package


def apk_variants():
    if no_attempts():
        skip("the saved Day 4 APK variants (moved, wrapped, encoded, removed; dex-only keys)",
             f"no saved attempts under {REAL}")
        return None
    got = day4_apk()
    if not check(got is not None and got[2] and got[3], "the saved Day 4 APK is on disk, with its dex secret and package",
                 "" if got else f"not found under {REAL}"):
        return
    members, truth, secret, package = got
    rest = {k: v for k, v in members.items() if k != PZ}
    with_doc = lambda d, name=PZ: {**rest, name: json.dumps(d).encode()}
    moved = lambda name: {**rest, name: members[PZ]}
    hexkey = bytes.fromhex(secret.split(b"-", 1)[1].decode()) if len(secret.split(b"-", 1)[1]) % 2 == 0 else None
    hidden = base64.b64encode(truth.encode()).hex().encode()
    carrier = min((s for s in C.dex_strings(members["classes.dex"]) if secret not in s and len(hidden) <= len(s) <= 256),
                  key=len, default=b"")
    table = [
        ("control (Day 4 as delivered)", members, "plain-ok"),
        ("asset renamed assets/huntress_puzzle.dat", moved("assets/huntress_puzzle.dat"), "unsure-ok"),
        ("moved to res/raw/huntress_puzzle.json", moved("res/raw/huntress_puzzle.json"), "unsure-ok"),
        ("whole document base64'd in assets/puzzle.b64", {**rest, "assets/puzzle.b64": base64.b64encode(members[PZ])}, "unsure-ok"),
        ("document wrapped {'puzzle': {...}}", with_doc({"puzzle": json.loads(members[PZ])}), "unsure-ok"),
        ("document is a list [{...}]", with_doc([json.loads(members[PZ])]), "unsure-ok"),
        ("codec base85, same place", with_doc({**H, "codec": "base85", "data": base64.b85encode(truth.encode()).decode()}), "unsure-ok"),
        ("xor, key = the dex secret string", with_doc({**H, "codec": "xor", "data": b64(xor(truth.encode(), secret)), "key_ref": "client_secret"}), "unsure-ok"),
        ("aes-cbc, key = md5(dex secret), iv in JSON", with_doc({**H, "codec": "aes", "data": b64(aes_cbc(hashlib.md5(secret).digest(), b"\x07" * 16, truth.encode())), "iv": (b"\x07" * 16).hex()}), "unsure-ok"),
        ("aes-ecb, key = sha256(dex secret)", with_doc({**H, "codec": "aes-256-ecb", "data": b64(aes_ecb(hashlib.sha256(secret).digest(), truth.encode()))}), "unsure-ok"),
        ("aes-cbc, key = sha256(package name), iv first", with_doc({**H, "codec": "aes", "data": b64(b"\x09" * 16 + aes_cbc(hashlib.sha256(package).digest(), b"\x09" * 16, truth.encode()))}), "unsure-ok"),
        ("no asset, nothing encoded anywhere (backend only)", rest, "none"),
        # Day 9 hardening: the one answer code the whole package holds, outside any document, is offered
        # unsure under apk-string:<where>:<how> (it was a NOTE-only candidate before); two codes are not
        ("the document is not JSON: base64 of the answer", {**rest, PZ: base64.b64encode(truth.encode())}, "unsure-ok"),
        ("not JSON, and a second, different code in another asset",
         {**rest, PZ: base64.b64encode(truth.encode()), "assets/other.txt": b"ANS-0000000000000000"}, "low"),
    ]
    if hexkey:
        table.append(("xor, key = the hex part of the dex secret", with_doc({**H, "codec": "xor", "data": b64(xor(truth.encode(), hexkey))}), "unsure-ok"))
    if carrier:
        dex = members["classes.dex"].replace(carrier, hidden.ljust(len(carrier)))
        table.append(("no asset; the answer as hex(base64) in a dex string", {**{k: v for k, v in rest.items() if k != "classes.dex"}, "classes.dex": dex}, "unsure-ok"))
    bad = []
    for name, m, want in table:
        got, dt = solve(build(m), name)
        k = kind(got, truth)
        if k == "none" and C.LAST.get("confidence") == "low" and truth in (C.LAST.get("candidate"), *re.findall(
                r"ANS-[0-9A-F]{16}", C.LAST.get("route", ""))):
            k = "low"  # found, judged too weak to return, and left in the NOTE for a person
        if VERBOSE:
            print(f"   {name:52} {k:12} {dt * 1000:5.0f} ms  {C.LAST.get('route', '')[:70]}")
        if k != want:
            bad.append(f"{name}: {k}, expected {want} ({C.LAST.get('route', '')[:60]})")
    check(not bad, f"APK variants: {len(table)} shapes of the Day 4 APK", "; ".join(bad))
    # the candidate of a low-confidence hit is in the NOTE, never in the answer
    with quiet() as err:
        out = C.solve_set([{"qid": "answer"}], {}, {"set": 0, "delivery": build({
            **rest, PZ: base64.b64encode(truth.encode()), "assets/other.txt": b"ANS-0000000000000000"})})
    line = err.getvalue().strip()
    check(out == {"answer": None} and line.count("\n") == 0 and truth in line and '"confidence": "low"' in line,
          "a low-confidence candidate is reported in the NOTE and not returned", line[:160])
    return members, truth


def fail_closed_inputs():
    """Bytes that are not what the lane expects: no exception, no answer."""
    a = ans()
    deep = "[" * 400 + "]" * 400
    inputs = [
        ("not a zip", b"not an archive"),
        ("empty zip", build({})),
        ("puzzle is not UTF-8", build({PZ: b"\xff\xfe\x00{"})),
        ("puzzle is deeply nested JSON", build({PZ: deep.encode()})),
        ("codec is a number", mini_apk({**H, "codec": 7, "data": 12})),
        ("codec is an object with no name", mini_apk({**H, "codec": {"key": 3}, "data": 12})),
        ("data is a number", mini_apk({**H, "codec": "plain", "data": 12})),
        ("document is a string that is no code", build({PZ: json.dumps(a[:-1]).encode()})),
        ("codec name is 5000 characters", mini_apk(doc("x" * 5000, a))),
    ]
    bad = []
    for name, blob in inputs:
        try:
            with quiet():
                out = C.solve_set([{"qid": "answer"}], {}, {"set": 1, "delivery": blob})
        except Exception as e:
            bad.append(f"{name}: raised {type(e).__name__}")
            continue
        if out != {"answer": None}:
            bad.append(f"{name}: {str(out)[:80]}")
    check(not bad, "unexpected bytes give None and no exception", "; ".join(bad))
    # nested past the recursion limit: json.loads still reads it, the walk over it raises, the answer is None
    depth = sys.getrecursionlimit() + 500
    nest = lambda opener, closer, core="": (opener * depth + core + closer * depth).encode()
    deeper = [
        ("lists", build({PZ: nest("[", "]")})),
        ("objects", build({PZ: nest('{"data":', "}", '"x"')})),
        ("parts beside an order", build({PZ: b'{"codec":"split","data":"","parts":' + nest("[", "]", '"x"') + b',"order":[1,0]}'})),
        ("a key", build({PZ: b'{"codec":"xor","data":"QUJD","key":' + nest("[", "]", "1") + b"}"})),
    ]
    bad, raised = [], 0
    for name, blob in deeper:
        try:
            with quiet():
                out = C.solve_set([{"qid": "answer"}], {}, {"set": 1, "delivery": blob})
                alone = C.solve_apk(blob)
        except BaseException as e:
            bad.append(f"{name}: raised {type(e).__name__}")
            continue
        raised += "RecursionError" in C.LAST.get("route", "")
        if out != {"answer": None} or alone is not None:
            bad.append(f"{name}: {str(out)[:60]}")
    check(not bad and raised == len(deeper), "a document nested past the recursion limit raises inside the solver only: None",
          "; ".join(bad) or f"{raised} of {len(deeper)} raised inside")
    with quiet():
        two = C.solve_set([{"qid": "answer"}, {"qid": "codec"}], {}, {"set": 1, "delivery": mini_apk(doc("plain", a))})
    check(two == {"answer": a, "codec": None}, "in a set of several questions only `answer` is given the code", str(two))
    # two entries under the puzzle's name: the same one is read as by zipfile and the Day 4 solver
    import warnings
    b, out = ans(), io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(out, "w") as zo:
            zo.writestr(PZ, json.dumps(doc("plain", a)))
            zo.writestr(PZ, json.dumps(doc("reverse", b[::-1])))
    twice, _ = solve(out.getvalue())
    # Day 14 look-ahead (item 1): the last entry is still the one that is read, and the earlier one, which
    # gives another code, makes the answer unsure with both, the last entry's first.
    got = labels.parse(twice) if labels.is_unsure(twice) else None
    check(base.solve_apk(out.getvalue()) == b and got is not None and got["k"] == "mobile.codec/reverse:second-code"
          and [tuple(o) for o in got["o"]] == [("reverse", b), ("twin-entry", a)],
          "of two entries with the puzzle's name the last one is read, and an earlier one that differs is the second option",
          str(twice))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        same = io.BytesIO()
        with zipfile.ZipFile(same, "w") as zo:
            zo.writestr(PZ, json.dumps(doc("reverse", b[::-1])))
            zo.writestr(PZ, json.dumps(doc("reverse", b[::-1])))
    check(solve(same.getvalue())[0] == b, "two entries of the puzzle's name with one body are one document: plain", "")
    # not a zip: the members the runner unpacked are used
    with quiet():
        unpacked = C.solve_set([{"qid": "answer"}], {"bundle.7z": b"7z", PZ: json.dumps(doc("plain", a)).encode(),
                                                    "bundle.7z -> " + PZ: b"{}"},
                               {"set": 1, "delivery": b"7z\xbc\xaf\x27\x1c", "delivery_name": "bundle.7z"})
    check(unpacked == {"answer": a}, "a delivery that is not a zip is read from the runner's unpacked members", str(unpacked))
    partial = {}
    with quiet():
        C.solve_set([{"qid": "answer"}], {}, {"set": 1, "delivery": mini_apk(doc("plain", a)), "partial": partial})
    check(partial == {"answer": a}, "ctx['partial'] is filled when the runner passes one", str(partial))


class Overrun(BaseException):
    """A solve ran far past its budget. A BaseException, so the solver cannot swallow it."""


def capped(blob, what, seconds=6.0):
    """solve(), stopped by an alarm after `seconds`: (answer, seconds), or ('overrun', seconds).

    For documents that made the solver run for minutes before it checked its deadline in
    every loop. A regression must fail this self-test, not hang it. The alarm stays wall-clock
    (ITIMER_REAL): it is a coarse hang catch, generous against the 0.45 s budget, so load does not
    fire it. The measured `seconds` is CPU time (time.process_time), like solve() (row 170)."""
    import signal

    def fire(signum, frame):
        raise Overrun()

    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds, 0.5)
    t = time.process_time()
    try:
        return solve(blob, what)
    except Overrun:
        dt = time.process_time() - t
        if dt > worst["seconds"]:
            worst.update(seconds=dt, what=what)
        return "overrun", dt
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def budget_attacks():
    """Documents whose work multiplies: chains of keyed steps over many keys, a move per key.

    Each must be a miss inside the budget. Before the deadline was checked for every key
    and every state (and before puzzle_asset_codec.by_codec, which checks none, was kept
    away from such chains) the first of these ran for more than ten minutes."""
    junk = lambda n: bytes(rnd.randrange(256) for _ in range(n))
    keys = {f"key{i}": b64(junk(8)) for i in range(40)}
    ivs = {f"iv{i}": junk(16).hex() for i in range(30)}
    bytekeys = {f"k{i}": i % 256 for i in range(2000)}
    attacks = [
        ("four xor steps over 40 keys", doc("xor+xor+xor+xor", b64(junk(3000)), **keys)),
        ("eight vigenere steps over 40 keys", doc(["vigenere"] * 8, "ABCD" * 1000, **{f"key{i}": "K%dEYZ" % i for i in range(40)})),
        ("four rc4 steps over 40 keys", doc(["rc4"] * 4, b64(junk(3000)), **keys)),
        ("three cipher steps over 40 keys and 30 ivs", doc(["cipher"] * 3, b64(junk(64)), **keys, **ivs)),
        ("an opaque codec with 2000 one-byte keys", doc("mystery", b64(junk(2200)), **bytekeys)),
        ("caesar named with 2000 one-byte keys", doc("caesar", "Q" * 4000, **bytekeys)),
        ("eight judged steps (the Day 4 solver's states multiply)", doc(["base64"] * 8, b64(junk(40)))),
        ("64 long pieces beside an order, under keyed steps over 40 keys",
         {**H, "codec": "split+xor+xor", "data": "", "parts": [b64(junk(3000)) for _ in range(64)], "order": list(range(64))[::-1], **keys}),
        ("64 short pieces beside an order, under keyed steps over 40 keys",
         {**H, "codec": "split+xor+xor", "data": "", "parts": [b64(junk(48)) for _ in range(64)], "order": list(range(64))[::-1], **keys}),
        ("sixteen orders beside sixteen long strings",
         {**H, "codec": "chunks+xor", **{f"o{i}": list(range(i + 2, 66)) for i in range(16)},
          **{f"s{i}": b64(junk(3024)) for i in range(16)}, **keys}),
    ]
    bad = []
    for name, d in attacks:
        got, dt = capped(mini_apk(d), name)
        if VERBOSE:
            print(f"   {name:52} {dt * 1000:6.0f} ms -> {str(got)[:40]!r}")
        if got is not None or dt >= MISS_LIMIT:
            bad.append(f"{name}: {str(got)[:30]!r} after {dt * 1000:.0f} ms")
    check(not bad, f"documents whose work multiplies are misses inside the budget: {len(attacks)} documents", "; ".join(bad))
    # the guard in front of by_codec must not touch what the judge has seen
    a = ans()
    day4 = doc("xor", b64(xor(a.encode(), b"\x1d")), key=29)
    chain = doc("base64+xor+reverse", b64(xor(a.encode(), b"\x1d")[::-1]), key=29)
    costs = [C.base_cost(d, C.base_steps(d)) for d in (day4, chain)]
    check(max(costs) * 20 < C.BASE_COST and C.base_cost(attacks[0][1], C.base_steps(attacks[0][1])) > C.BASE_COST,
          "the Day 4 solver is asked for judged documents and not for an unbounded chain", f"costs {costs} of {C.BASE_COST}")
    # out of time, a weaker reading is not returned in place of an exact one that was not reached
    body = [("data", a[4:].encode())]
    late = C.Clock(0)
    check(C.by_name(["plain"], body, [], [], late) is None
          and C.by_name(["plain"], body, [], [], C.Clock()) == (a, ("prefix-added",), "data", ()),
          "past the deadline a weaker reading (prefix added) is not returned")


def big_archives(day4):
    """Shapes the Day 4 solver answers and the wrapper used to miss: they must not become a None."""
    a = ans()
    judged = json.dumps(doc("xor", b64(xor(a.encode(), b"\x1d")), key=29)).encode()
    filler = bytes(rnd.randrange(256) for _ in range(64))
    many = {f"res/drawable/i{i}.png": filler for i in range(2500)}
    many[PZ] = judged  # the last entry of 2501: past the cap on members that are read
    blob = build(many)
    got, dt = solve(blob, "2500 resources before the puzzle")
    check(got == a == base.solve_apk(blob) and dt < MISS_LIMIT,
          "an APK with 2500 resources ahead of the puzzle is answered plain, as by the Day 4 solver", f"{got!r} in {dt * 1000:.0f} ms")
    long_doc = build({PZ: json.dumps({**doc("xor", b64(xor(a.encode(), b"\x1d")), key=29), "note": "x" * 70000}).encode()})
    got, _ = solve(long_doc, "a 70 KiB puzzle document")
    check(got == a == base.solve_apk(long_doc), "a puzzle document over 64 KiB is answered plain, as by the Day 4 solver", f"{got!r}")
    # the APK inside another archive: found, and unsure (it is not where the judge has seen it)
    wrapped = build({"app.apk": mini_apk(json.loads(judged)), "readme.txt": b"case notes"})
    got, _ = solve(wrapped, "the APK inside a zip")
    parsed = labels.parse(got)
    check(kind(got, a) == "unsure-ok" and parsed.options[0][0] == "xor:doc-inner", "an APK inside a zip is unsure, route xor:doc-inner", str(got)[:90])
    # the runner unpacked the document from an archive this module does not open (an APK over 1 MiB inside a zip)
    with quiet():
        out = C.solve_set([{"qid": "answer"}], {"evidence.zip": b"", PZ: judged, "evidence.zip -> " + PZ: judged},
                          {"set": 1, "delivery": build({"readme.txt": b"case notes"}), "delivery_name": "evidence.zip"})
    check(kind(out.get("answer"), a) == "unsure-ok", "a puzzle only the runner unpacked is used, and unsure", str(out)[:90])


def judged_names():
    """The seed's accepted names (plain, reverse, base64, xor) answer the Day 4 solver's named route only.

    A search that ends after the one move `reverse`, in a document that names no codec, used
    to be offered as ('reverse') under mobile.codec/reverse, and a codec called 'xor!' as
    ('xor') under mobile.codec/xor: the seed accepted both and they came back plain."""
    rows = [
        ("no codec, data reversed", lambda a: {**H, "data": a[::-1]}),
        ("no codec, data base64", lambda a: {**H, "data": b64(a.encode())}),
        ("codec is a number, data reversed", lambda a: doc(32865, a[::-1])),
        ("codec is an empty list, data base64", lambda a: doc([], b64(a.encode()))),
        ("codec '!!!', data base64", lambda a: doc("!!!", b64(a.encode()))),
        ("codec 'base64?', data base64", lambda a: doc("base64?", b64(a.encode()))),
        ("codec 'reverse!', data reversed", lambda a: doc("reverse!", a[::-1])),
        ("codec 'xor!', the Day 4 shape", lambda a: doc("xor!", b64(xor(a.encode(), b"\x1d")), key=29)),
        ("codec 'xor]', key as text", lambda a: doc("xor]", b64(xor(a.encode(), b"huntress")), key="huntress")),
    ]
    bad = {}
    for name, f in rows:
        counts, route = tally(f, name)
        if counts.get("unsure-ok") != TRIALS:
            bad[name] = (counts, route)
        if VERBOSE:
            print(f"   {name:50} {counts} {route[:60]}")
    check(not bad, "a judged codec's name reached by search or by a look-alike name is unsure, never plain", str(bad)[:300])
    a = ans()
    loose_hit = C.Hit(a, "medium", "reverse", "", ())
    named_hit = C.Hit(a, "high", "reverse", "reverse", ("reverse",))
    got, key = C.decide(loose_hit)
    check(kind(got, a) == "unsure-ok" and key == "mobile.codec/reverse" and C.decide(named_hit) == (a, "mobile.codec/reverse"),
          "decide() gives the seed's plain answer only to the Day 4 solver's own route", f"{str(got)[:80]} {key}")
    # a Hit with several readings: all of them reach labels.pick, and none under a judged codec's bare name
    several = C.Hit(a, "high", "reverse:either-order", "reverse", (), (("reverse:by-order", a), ("reverse", a[::-1])))
    got, key = C.decide(several)
    check(options_of(got) == ["reverse:either-order", "reverse:by-order", "reverse:not-by-name"] and key == "mobile.codec/reverse",
          "decide() offers every reading a Hit carries, and a further option never has a judged codec's bare name",
          f"{options_of(got)} {key}")


def questions_and_notes():
    """Which question is given the code, and what the NOTE says about an answer that was withheld."""
    a = ans()
    apk = mini_apk(doc("plain", a))
    code = {"kind": "pattern", "syntax": "ANS- followed by exactly 16 uppercase hexadecimal characters; no spaces or explanatory text"}
    asked = [
        ("the usual question", [{"qid": "answer", "answer_format": code}], {"answer": a}),
        ("another id, the same format", [{"qid": "code", "answer_format": code}], {"code": a}),
        ("another id, another format", [{"qid": "package", "answer_format": {"kind": "text", "syntax": "the package name"}}], {"package": None}),
        # Day 14 look-ahead (item 3): a stated format that is not the code's, no word of the code and no fact
        # read: the code is offered unsure under <the codec's key>:unasked, no longer plain.
        ("`answer` with another format", [{"qid": "answer", "answer_format": {"kind": "text", "syntax": "the code"}}],
         {"answer": labels.unsure("mobile.codec/plain:unasked", [("code", a)])}),
        # Row 270 and its review: the id `answer` keeps the code unless its answer kind cannot hold one.
        ("`answer` with a number format and the code's sentence",
         [{"qid": "answer", "question": "Submit only the exact backend answer code returned for this case.",
           "answer_format": {"kind": "integer", "syntax": "base-10 integer"}}], {"answer": None}),
        ("another id, no format given", [{"qid": "other"}], {"other": a}),
    ]
    bad = []
    for name, qs, want in asked:
        with quiet():
            out = C.solve_set(qs, {}, {"set": 1, "delivery": apk})
        if out != want:
            bad.append(f"{name}: {out}")
    check(not bad, "a single question that states another answer format is not given the code", "; ".join(bad))
    # no codec named: the data as it stands is a candidate only, and the NOTE must not blame the judge
    with quiet() as err:
        out = C.solve_set([{"qid": "answer"}], {}, {"set": 1, "delivery": mini_apk({**H, "data": a})})
    line = err.getvalue()
    check(out == {"answer": None} and '"confidence": "low"' in line and a in line and "rejected by the judge" not in line,
          "answer-shaped data with no codec named: None, and the NOTE does not say the judge rejected it", line[:140])
    scratch_ledger("challenges-notes")
    try:
        apk = mini_apk(doc("rot13", codecs.encode(a, "rot13")))
        first, _ = solve(apk)
        parsed = labels.parse(first)
        if parsed and parsed.options:
            labels.learn(parsed.key, parsed.options[0][0], "rejected", scope="key", attempt_id="selftest", answer_ids=["answer"])
        with quiet() as err:
            out = C.solve_set([{"qid": "answer"}], {}, {"set": 1, "delivery": apk})
        check(parsed is not None and out == {"answer": None} and "rejected by the judge" in err.getvalue(),
              "a route the judge rejected: None, and the NOTE says so", err.getvalue()[:140])
    finally:
        scratch_ledger("challenges-synthetic")


def timing(day4):
    # misses that have to use the whole budget
    junk = bytes(rnd.randrange(256) for _ in range(2400))
    heavy = [
        ("random bytes under an opaque codec, with keys", mini_apk(doc("mystery", b64(junk), key="huntress", shift=7, k2=[1, 2, 3]))),
        ("40 random text members", build({f"assets/blob{i}.txt": base64.b64encode(bytes(rnd.randrange(256) for _ in range(300))) for i in range(40)})),
        ("16 text fields under an opaque codec", mini_apk({**H, "codec": "mystery", **{f"p{i}": b64(bytes(rnd.randrange(256) for _ in range(60))) for i in range(16)}})),
        ("aes named, the wrong key in the document", mini_apk(doc("aes", b64(bytes(rnd.randrange(256) for _ in range(64))), key="huntress", iv="07" * 16))),
    ]
    if day4:
        members, _ = day4
        rest = {k: v for k, v in members.items() if k != PZ}
        heavy.append(("aes named, no key in the document, in a real APK",
                      build({**rest, PZ: json.dumps(doc("aes", b64(bytes(rnd.randrange(256) for _ in range(64))), iv="07" * 16)).encode()})))
    for name, blob in heavy:
        got, dt = solve(blob, name)
        if VERBOSE:
            print(f"   {name:52} {dt * 1000:5.0f} ms -> {got!r}")
        if got is not None:
            check(False, "a heavy miss stays a miss", f"{name}: {str(got)[:80]}")
    check(worst["seconds"] < MISS_LIMIT, "the worst miss takes under 0.45 s",
          f"{worst['seconds'] * 1000:.0f} ms ({worst['what']})")
    # the same in a fresh process, where the first cipher attempt also pays for the import
    cold = TMP / "cold.apk"
    cold.write_bytes(heavy[-1][1])
    # Row 170: measure the cold solve in CPU time (process_time), including the cipher import, so a
    # loaded machine does not inflate it past the budget; a real regression still burns the CPU.
    code = ("import sys, time; sys.dont_write_bytecode = True; sys.path.insert(0, %r); import codec_search as C; "
            "b = open(%r, 'rb').read(); t = time.process_time(); a = C.solve_apk(b); "
            "print(repr(a), time.process_time() - t, 'cryptography' in sys.modules)" % (str(HERE), str(cold)))
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    parts = p.stdout.split()
    ok = (p.returncode == 0 and len(parts) == 3 and parts[0] == "None" and float(parts[1]) < MISS_LIMIT
          and parts[2] == "True")
    check(ok, "a cold miss (fresh process, cipher import included) takes under 0.45 s",
          (p.stdout.strip() or p.stderr.strip())[:200])
    code = ("import sys; sys.dont_write_bytecode = True; sys.path.insert(0, %r); import codec_search as C; "
            "a = C.solve_apk(open(%r, 'rb').read()); print('cryptography' in sys.modules)" % (str(HERE), str(TMP / "plain.apk")))
    (TMP / "plain.apk").write_bytes(mini_apk(doc("xor", b64(xor(ans().encode(), b"\x1d")), key=29)))
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    check(p.returncode == 0 and p.stdout.strip() == "False", "`cryptography` is not imported on the judged path",
          (p.stdout.strip() or p.stderr.strip())[:200])


def runner(day4):
    """tools/run.py --offline on scratch copies: a judged codec, then one the judge has not seen."""
    if no_attempts():
        skip("run.py --offline on the saved Day 4 time trial", f"no saved attempts under {REAL}")
        return
    src = REAL / "day-04" / "mobile-android-day-04-pending-intent-relay" / "time_trial"
    want, _ = expected_answers(src)
    if not check(day4 is not None and want is not None and (src / "attempt.json").exists(),
                 "the saved Day 4 time trial is on disk for the runner check"):
        return
    members, truth = day4
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "CTF_WORKDIR": str(TMP / "challenges-runner")}
    cid = "mobile-android-day-05-selftest/time_trial"

    def replay(name, apk):
        d = TMP / name
        (d / "artifact").mkdir(parents=True)
        (d / "artifact" / "day5.apk").write_bytes(apk)
        att = json.loads((src / "attempt.json").read_text())
        att["artifacts"] = [{"filename": "day5.apk", "sha256": hashlib.sha256(apk).hexdigest()}]
        att.pop("download", None)
        att.pop("downloads", None)
        att["sha256"] = att["artifacts"][0]["sha256"]
        att["questions"][0]["artifact"] = "day5.apk"
        (d / "attempt.json").write_text(json.dumps(att))
        return subprocess.run([sys.executable, str(REPO / "tools" / "run.py"), cid, str(HERE / "codec_search.py"),
                               "--offline", str(d)], capture_output=True, text=True, env=env, timeout=120)

    saved = sorted((src / "artifact").glob("*.apk"))[0].read_bytes()
    p = replay("replay-judged", saved)
    check(p.returncode == 0 and re.search(r"^\s*answer = %s\s*$" % re.escape(want["answer"]), p.stdout, re.M) is not None
          and "NOTE mobile set" in p.stderr, "run.py --offline: a judged codec is answered plain",
          (p.stdout[-300:] + p.stderr[-200:]).replace("\n", " | ")[:300] if p.returncode else "")
    rest = {k: v for k, v in members.items() if k != PZ}
    new = build({**rest, PZ: json.dumps({**H, "codec": "base85", "data": base64.b85encode(truth.encode()).decode()}).encode()})
    p = replay("replay-unknown", new)
    plain = re.search(r"^\s*answer = ANS-", p.stdout, re.M)
    check(p.returncode == 0 and plain is None and "mobile.codec/base85" in p.stdout + p.stderr,
          "run.py --offline: an unknown codec is never shown as a plain answer",
          (p.stdout[-300:] + p.stderr[-200:]).replace("\n", " | ")[:300] if p.returncode or plain else "")


def day_patch():
    """A copy of the solver folder with a day_patch.py beside the module, loaded from there.

    The contract under test: the patch is asked where the shipped answer is None or
    unsure, never for a plain answer, and what it returns is used unless it is None."""
    import importlib.util
    root = TMP / "copy" / "solvers"
    (root / "common").mkdir(parents=True)
    (root / "mobile-android").mkdir()
    for rel in ("common/labels.py", "mobile-android/codec_search.py", "mobile-android/puzzle_asset_codec.py",
                "mobile-android/conventions.json"):
        shutil.copy(HERE.parent / rel, root / rel)
    patch = root / "mobile-android" / "day_patch.py"

    def load(name, text):
        patch.write_text(text)
        spec = importlib.util.spec_from_file_location(name, root / "mobile-android" / "codec_search.py")
        mod = importlib.util.module_from_spec(spec)
        with quiet() as err:
            spec.loader.exec_module(mod)
        return mod, err.getvalue()

    def ask(module, document):
        with quiet() as err:
            out = module.solve_set([{"qid": "answer"}], {}, {"set": 0, "delivery": mini_apk(document)})
        return out["answer"], err.getvalue()

    # the patch reads two codecs: one the shipped module misses, one it answers unsure and wrong
    good = (
        "import io, json, zipfile\n"
        "asked = []\n"
        "def answer(q, files, ctx):\n"
        "    p = json.loads(zipfile.ZipFile(io.BytesIO(ctx['delivery'])).read('assets/huntress_puzzle.json'))\n"
        "    asked.append(p.get('codec'))\n"
        "    d = p.get('data')\n"
        "    if p.get('codec') == 'reverse-body':\n"
        "        return d[:4] + d[4:][::-1]\n"
        "    if p.get('codec') == 'twist':\n"
        "        d = (d + d)[(d + d).index('ANS-'):][:20]\n"
        "        return ''.join(chr((ord(c) - 48 + 5) % 10 + 48) if c.isdigit() else c for c in d)\n"
        "    return None\n")
    mod, _ = load("codec_search_patched", good)
    a = ans()
    miss = doc("reverse-body", a[:4] + a[4:][::-1])
    twist = doc("twist", rot5(a)[7:] + rot5(a)[:7])
    unjudged = doc("base85", base64.b85encode(a.encode()).decode())
    judged = [doc("plain", a), doc("reverse", a[::-1]), doc("base64", b64(a.encode())),
              doc("xor", b64(xor(a.encode(), b"\x1d")), key=29), split_doc(a, (2, 0, 1))]
    fixed, said = ask(mod, miss)
    check(fixed == a and '"day_patch": ["answer"]' in said and ask(C, miss)[0] is None,
          "day_patch.answer is asked for a miss, and its answer is used", f"{fixed!r}")
    shipped, replaced = ask(C, twist)[0], ask(mod, twist)[0]
    check(kind(shipped, a) == "unsure-wrong" and replaced == a,
          "day_patch.answer is asked for an unsure answer, and its answer is used in its place", f"{kind(shipped, a)} -> {replaced!r}")
    declined, _ = ask(mod, unjudged)
    check(labels.is_unsure(declined) and declined == ask(C, unjudged)[0] and "base85" in mod._patch.asked,
          "a patch that declines leaves the shipped unsure answer in place", str(declined)[:80])
    del mod._patch.asked[:]
    kept = [ask(mod, d)[0] for d in judged]
    check(kept == [a] * len(judged) and mod._patch.asked == [],
          "a plain answer is never offered to the patch", f"{kept} asked={mod._patch.asked}")
    # a careless patch (one fixed code for everything) cannot change a judged answer
    zero = "ANS-0000000000000000"
    mod, _ = load("codec_search_careless", "def answer(q, files, ctx):\n    return %r\n" % zero)
    kept = [ask(mod, d)[0] for d in judged]
    apks = same = 0
    for d in sorted(p.parent for p in REAL.glob("day-0[1-5]/mobile-android-*/**/attempt.json")):
        want, _ = expected_answers(d)
        if want is None:
            continue
        attempt, blobs, _ = run.load_offline(str(d.relative_to(REAL)), str(d))
        for n, qs, files, ctx in run.split_sets(attempt, blobs):
            with quiet():
                got = mod.solve_set(qs, files, ctx)
            apks += len(qs)
            same += sum(1 for q in qs if got.get(q["qid"]) == want.get(q["answer_id"]))
    if no_attempts():
        check(kept == [a] * len(judged) and ask(mod, miss)[0] == zero,
              "a careless patch changes no judged answer: the judged shapes",
              f"{kept.count(a)} of {len(judged)} shapes, a miss -> {ask(mod, miss)[0]!r}")
        skip("a careless patch changes no judged answer: the saved APKs of Days 1 to 5", f"no saved attempts under {REAL}")
    else:
        check(kept == [a] * len(judged) and apks >= 25 and same == apks and ask(mod, miss)[0] == zero,
              "a careless patch changes no judged answer: the judged shapes and the saved APKs of Days 1 to 5",
              f"{kept.count(a)} of {len(judged)} shapes, {same} of {apks} saved APKs, a miss -> {ask(mod, miss)[0]!r}")
    # the skeleton a standby agent copies: nothing loads it under its own name, empty it declines, filled in it works
    template = (HERE / "day_patch_template.py").read_text()
    patch.unlink()
    shutil.copy(HERE / "day_patch_template.py", root / "mobile-android" / "day_patch_template.py")
    spec = importlib.util.spec_from_file_location("codec_search_template_only", root / "mobile-android" / "codec_search.py")
    alone = importlib.util.module_from_spec(spec)
    with quiet():
        spec.loader.exec_module(alone)
    mod, _ = load("codec_search_template_empty", template)
    empty = [ask(mod, d)[0] for d in (miss, unjudged, judged[0])]
    check(alone._patch is None and mod._patch is not None and empty == [None, ask(C, unjudged)[0], a],
          "day_patch_template.py is not loaded by its own name, and copied as it is it declines everything", str(empty)[:120])
    edits = (('CODEC = "<name>"', 'CODEC = "reverse-body"'), ('HOW = "<how>"', 'HOW = "body-reversed"'),
             ("    return None  # <- write the decoding here", "    return p['data'][:4] + p['data'][4:][::-1]"))
    filled = template
    for old, new in edits:
        filled = filled.replace(old, new)
    scratch_ledger("challenges-template")
    try:
        mod, _ = load("codec_search_template", filled)
        first, _ = ask(mod, miss)
        parsed = labels.parse(first)
        wrong_shape, _ = ask(mod, doc("reverse-body", "not a code"))
        other, _ = ask(mod, unjudged)
        plain = [ask(mod, d)[0] for d in judged]
        if parsed and parsed.options:
            labels.learn(parsed.key, parsed.options[0][0], "accepted", scope="key", attempt_id="selftest", answer_ids=["answer"])
        b = ans()
        nxt, _ = ask(mod, doc("reverse-body", b[:4] + b[4:][::-1]))
    finally:
        scratch_ledger("challenges-synthetic")
    check(all(template.count(old) == 1 for old, _ in edits) and parsed is not None
          and parsed.key == "mobile.codec/reverse-body" and parsed.options == [("reverse-body:body-reversed", a)]
          and wrong_shape is None and other == ask(C, unjudged)[0] and plain == [a] * len(judged) and nxt == b,
          "the template with a decode filled in: unsure for its codec, plain once accepted, silent for the rest",
          f"{str(first)[:80]} next variant={nxt == b}")
    for label, text in (("raises", "def answer(q, files, ctx):\n    raise RuntimeError('boom')\n"),
                        ("does not import", "import no_such_module_for_the_selftest\n"),
                        ("has no answer()", "x = 1\n"),
                        ("calls sys.exit", "import sys\ndef answer(q, files, ctx):\n    sys.exit(3)\n")):
        try:
            mod, loaded = load("codec_search_broken", text)
            out, said = ask(mod, miss)
            unsure, more = ask(mod, unjudged)
            ok, _ = ask(mod, judged[0])
            good_run = (out is None and unsure == ask(C, unjudged)[0] and ok == a
                        and "day_patch" in loaded + said and "day_patch" in loaded + more)
        except BaseException as e:
            good_run, out = False, f"raised {type(e).__name__}"
        check(good_run, f"a day_patch.py that {label} costs nothing and is reported", "" if good_run else str(out))


def command_line():
    apk = TMP / "cli.apk"
    a = ans()
    apk.write_bytes(mini_apk(doc("base64", b64(a.encode()))))
    run_cli = lambda *args: subprocess.run([sys.executable, str(HERE / "codec_search.py"), *args], capture_output=True,
                                           text=True, timeout=60, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    p = run_cli(str(apk))
    q = run_cli()
    r = run_cli(str(TMP / "missing.apk"))
    check(p.returncode == 0 and a in p.stdout and q.returncode == 2 and q.stderr.startswith("usage:")
          and r.returncode == 2 and "Traceback" not in q.stderr + r.stderr and len(r.stderr.strip().splitlines()) == 1,
          "command line: an answer, a one-line usage error, a one-line file error",
          f"{p.returncode} {q.returncode} {r.returncode} {r.stderr.strip()[:80]}")


def main() -> int:
    before = sorted(p.name for p in HERE.iterdir())
    try:
        saved_attempts()                       # with the real ledger, read only
        scratch_ledger("challenges-synthetic")  # from here on: the seed and an empty ledger
        saved_day5()
        synthetic()
        arrangements()
        moves()
        keyed()
        codec_pack()
        report = hostile()
        rot_only_when_named(report)
        codecs_next()
        ledger()
        day4 = apk_variants()
        fail_closed_inputs()
        budget_attacks()
        big_archives(day4)
        judged_names()
        questions_and_notes()
        import selftest_day9                   # Day 9 hardening: more codecs, shapes, documents, keys, facts
        selftest_day9.checks(sys.modules[__name__])
        timing(day4)
        runner(day4)
        day_patch()
        command_line()
        after = sorted(p.name for p in HERE.iterdir() if p.name != "__pycache__")
        check(after == [n for n in before if n != "__pycache__"], "nothing was written beside the solver", str(after))
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    passed = sum(1 for ok, _, _ in checks if ok)
    print(f"SELFTEST mobile: {passed}/{len(checks)} checks passed, worst miss {worst['seconds'] * 1000:.0f} ms"
          + (f", {len(skipped)} skipped (not run: no saved attempts)" if skipped else ""))
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
