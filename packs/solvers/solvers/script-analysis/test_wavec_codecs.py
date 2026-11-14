#!/usr/bin/env python3
"""Row 79 (wave C, group codecs): label_plan.py's new transforms and representations, offline.

Every specimen here is synthetic and made by this file's own encoders (nothing is read from a saved
attempt): a plan, encoded by a transform or two stacked ones, written in a representation, stored
in `Material_<id>` with its `Codec_<id>` label. Each form is read twice: under its label (several
spellings in the author's style, rep|transform|key in snake_case), and under a label the module does
not know (the every-reading fallback). Also: two different plans are still no plan, what row 79
reads must carry a steps field, and the fallback stays bounded on 100 KB of labelled material.

    .venv/bin/python solvers/script-analysis/test_wavec_codecs.py [-v]

Last line: TEST_WAVEC_CODECS passed=N failed=M
"""
import base64
import bz2
import codecs
import contextlib
import gzip
import io
import itertools
import lzma
import random
import sys
import time
import urllib.parse
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import generic      # noqa: E402
import label_plan   # noqa: E402

VERBOSE = "-v" in sys.argv[1:]
results = []

PLAN = ("v=1|steps=acquire_remote,dispatch_memory|adapter=Lab.Adapter|stage_count=2|campaign_id=campaign-4242424242|"
        "url=https://lab.invalid/stage-4242424242.bin")
ADV = "v=1|feature=indirect_expansion|primitive=pointer|campaign_id=campaign-7777777777|stage_count=1|steps=recognize_syntax,reconstruct_intent"


def check(name: str, ok: bool, detail: str = ""):
    results.append((name, bool(ok)))
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail and (VERBOSE or not ok) else ""))


# ---------------------------------------------------------------- this file's own encoders

def rc4(key: bytes, data: bytes) -> bytes:
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


def vigenere(key: str, data: bytes, every: bool = False) -> bytes:
    """Encrypt the letters (case kept); the key advances per letter, or with `every` per byte."""
    shifts = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    out, j = bytearray(), 0
    for c in data:
        if 65 <= c <= 90 or 97 <= c <= 122:
            base = 65 if c <= 90 else 97
            out.append((c - base + shifts[j % len(shifts)]) % 26 + base)
            j += 1
        else:
            out.append(c)
            j += every
    return bytes(out)


def rot(n: int, data: bytes) -> bytes:
    return bytes((c - 65 + n) % 26 + 65 if 65 <= c <= 90 else (c - 97 + n) % 26 + 97 if 97 <= c <= 122 else c for c in data)


def b58encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b91encode(data: bytes) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
    b = n = 0
    out = []
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out += [alphabet[v % 91], alphabet[v // 91]]
    if n:
        out.append(alphabet[b % 91])
        if n > 7 or b > 90:
            out.append(alphabet[b // 91])
    return "".join(out)


def lzma_alone(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_ALONE)


# The transforms, as the specimen applies them (encode). (name in the label, key, function, key spelled)
def enc(kind: str, key, data: bytes) -> bytes:
    if kind == "single_byte_xor":
        return bytes(b ^ key for b in data)
    if kind == "add_modulo_256":
        return bytes((b + key) % 256 for b in data)
    if kind == "subtract_modulo_256":
        return bytes((b - key) % 256 for b in data)
    if kind == "rotate_left":
        r = key % 8
        return bytes(((b << r) | (b >> (8 - r))) & 255 for b in data)
    if kind == "rotate_right":
        r = key % 8
        return bytes(((b >> r) | (b << (8 - r))) & 255 for b in data)
    if kind == "repeating_key_xor":
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    if kind == "rolling_xor":
        out, k = bytearray(), key
        for b in data:
            out.append(b ^ k)
            k = out[-1]
        return bytes(out)
    if kind == "nibble_swap":
        return bytes(((b << 4) | (b >> 4)) & 255 for b in data)
    if kind == "bit_reverse":
        return bytes(int(f"{b:08b}"[::-1], 2) for b in data)
    if kind == "rc4":
        return rc4(key, data)
    if kind == "vigenere":
        return vigenere(key, data)
    if kind == "rot13":
        return rot(13, data)
    if kind == "rot_n":
        return rot(key, data)
    if kind == "reverse_bytes":
        return data[::-1]
    if kind == "zlib":
        return zlib.compress(data)
    if kind == "gzip":
        return gzip.compress(data, mtime=0)
    if kind == "bz2":
        return bz2.compress(data)
    if kind == "xz":
        return lzma.compress(data)
    if kind == "lzma":
        return lzma_alone(data)
    raise ValueError(kind)


# kind: (key, key as the label spells it)
KEYS = {"single_byte_xor": (0x5A, "5a"), "add_modulo_256": (0x13, "13"), "subtract_modulo_256": (0x2B, "2b"),
        "rotate_left": (3, "03"), "rotate_right": (5, "05"), "repeating_key_xor": (bytes([0xAF, 0x9E, 0xF2]), "af,9e,f2"),
        "rolling_xor": (0xC7, "c7"), "rc4": (b"huntress", "huntress"), "vigenere": ("lemon", "lemon"), "rot_n": (7, "7")}


def specimen(literal: str, label: str, ident: str = "5a17c0de") -> str:
    """A Node-style specimen: the material literal (with its quotes) and its label."""
    return (f"// Huntress Script Triage -- inert static-analysis fixture\nconst Material_{ident} = {literal};\n"
            f"const Codec_{ident} = \"{label}\";\nfunction Load_{ident}() {{ return decode(Material_{ident}); }}\n")


def hexlit(data: bytes) -> str:
    return f'"{data.hex()}"'


def read(text):
    with contextlib.redirect_stderr(io.StringIO()):
        return label_plan.read_text(text)


# ---------------------------------------------------------------- one form at a time

def test_forms():
    plan = PLAN.encode()
    cases = []      # (form, literal, labels that name it, fallback key field)
    for key, spelled in ((b"huntress", "huntress"), (bytes.fromhex("6b65792d3031"), "6b65792d3031"),
                         (bytes.fromhex("6b65792d3031"), "0x6b65792d3031"), (bytes([107, 101, 121]), "107,101,121"),
                         (bytes([0x6B, 0x65, 0x79]), "6b,65,79")):
        cases.append((f"rc4 key {spelled}", hexlit(rc4(key, plan)), [f"hex_compact|rc4|{spelled}", f"hex_compact|arc4|{spelled}",
                                                                      f"hex_compact|rc4_stream|{spelled}"], spelled))
    cases.append(("rc4 in base64", f'"{base64.b64encode(rc4(b"k3y!", plan)).decode()}"', ["base64_literal|rc4|k3y!"], "k3y!"))
    for every in (False, True):
        v = vigenere("lemon", plan, every)
        names = ["text|vigenere_every|lemon"] if every else ["text|vigenere|lemon", "plain_text|vigenere_cipher|lemon"]
        cases.append((f"vigenere on the text{' (key per byte)' if every else ''}", f'"{v.decode()}"', names, "lemon"))
        cases.append((f"vigenere, hex{' (key per byte)' if every else ''}", hexlit(v),
                      ["hex_compact|vigenere_every|lemon" if every else "hex_compact|vigenere|lemon"], "lemon"))
    cases.append(("rot13 on the text", f'"{rot(13, plan).decode()}"', ["text|rot13|", "plain_text|rot_13|", "text|rot_n|13"], ""))
    for n in (1, 7, 25):
        cases.append((f"rot-{n} on the text", f'"{rot(n, plan).decode()}"', [f"text|rot_n|{n}", f"text|caesar|{n}"], str(n)))
    cases.append(("rot13 in hex", hexlit(rot(13, plan)), ["hex_compact|rot13|"], ""))
    cases.append(("rot13 on base64 text", f'"{codecs.encode(base64.b64encode(plan).decode(), "rot13")}"',
                  ["rot13_base64|identity|"], ""))
    cases.append(("nibble swap", hexlit(enc("nibble_swap", None, plan)), ["hex_compact|nibble_swap|", "hex_compact|swap_nibbles|"], ""))
    cases.append(("bit reversal", hexlit(enc("bit_reverse", None, plan)), ["hex_compact|bit_reverse|", "hex_compact|reverse_bits|"], ""))
    for kind in ("bz2", "xz", "lzma", "zlib", "gzip"):
        z = enc(kind, None, plan)
        names = {"bz2": ["base64_literal|bz2|", "base64_literal|bzip2|"], "xz": ["base64_literal|xz|", "base64_literal|lzma_xz|"],
                 "lzma": ["base64_literal|lzma|"], "zlib": ["base64_literal|zlib|"], "gzip": ["base64_literal|gzip|"]}[kind]
        cases.append((f"{kind} stream in base64", f'"{base64.b64encode(z).decode()}"', names, ""))
        cases.append((f"{kind} stream in hex", hexlit(z), [n.replace("base64_literal", "hex_compact") for n in names], ""))
    pct = urllib.parse.quote(PLAN, safe="")
    cases.append(("percent-encoding", f'"{pct}"', ["percent_encoded|identity|", "url_encoded|identity|", "percent|identity|"], ""))
    pct_x = urllib.parse.quote(bytes(b ^ 0x21 for b in plan), safe="")
    cases.append(("percent-encoding of xor bytes", f'"{pct_x}"', ["url_encoded|single_byte_xor|21"], "21"))
    for enc16 in ("utf-16-le", "utf-16-be", "utf-16"):
        w = PLAN.encode(enc16)
        cases.append((f"{enc16} text in base64", f'"{base64.b64encode(w).decode()}"',
                      ["base64_literal|identity|", f"base64_literal|{enc16.replace('-', '')}|"], ""))
        cases.append((f"{enc16} text in hex", hexlit(w), ["hex_compact|identity|"], ""))
    cases.append(("base58", f'"{b58encode(plan)}"', ["base58|identity|", "base58_text|identity|", "b58|identity|"], ""))
    cases.append(("base58 of xor bytes", f'"{b58encode(enc("single_byte_xor", 0x5A, plan))}"', ["base58|single_byte_xor|5a"], "5a"))
    cases.append(("base91", f"'{b91encode(plan)}'", ["base91|identity|", "base91_text|identity|", "b91|identity|"], ""))
    cases.append(("base91 of xor bytes", f"'{b91encode(enc('single_byte_xor', 0x5A, plan))}'", ["base91|single_byte_xor|5a"], "5a"))
    labelled = fallback = 0
    bad_l, bad_f = [], []
    for form, lit, names, key in cases:
        for name in names:
            labelled += 1
            got = read(specimen(lit, name))
            if got != PLAN:
                bad_l.append(f"{form} as {name}: {str(got)[:50]}")
        fallback += 1
        got = read(specimen(lit, f"unknown_form_v9|{key}"))
        if got != PLAN:
            bad_f.append(f"{form}: {str(got)[:50]}")
    check(f"forms: {labelled - len(bad_l)} of {labelled} labelled specimens ({len(cases)} forms, each under 1 to 3 spellings: "
          f"RC4 keys as text, hex, 0x, decimal and a hex list; Vigenere, ROT13 and ROT-N; nibble swap; bit reversal; bz2, xz, "
          f"lzma, zlib, gzip; percent-encoding; UTF-16LE/BE; base58; base91) read to the plan", not bad_l, "; ".join(bad_l[:6]))
    check(f"forms: {fallback - len(bad_f)} of {fallback} under a label in no known form (the key alone) read by the fallback",
          not bad_f, "; ".join(bad_f[:6]))
    return len(cases), labelled, fallback, len(bad_l), len(bad_f)


# ---------------------------------------------------------------- two stacked transforms

PAIR_KINDS = ("single_byte_xor", "add_modulo_256", "subtract_modulo_256", "rotate_left", "repeating_key_xor", "rolling_xor",
              "nibble_swap", "bit_reverse", "rc4", "vigenere", "rot13", "reverse_bytes", "zlib", "bz2", "xz")
COMPRESS = {"zlib", "bz2", "xz"}


def test_pairs():
    """Every ordered pair of PAIR_KINDS (two compressions excepted), applied in that order, in hex:
    under `first_then_second` with each key in its own field (and, for two one-byte keys, both in
    one field), and under an unknown label holding the same key fields."""
    plan = PLAN.encode()
    n_lab = n_fb = 0
    bad_lab, bad_fb, slow = [], [], 0.0
    for a, b in itertools.permutations(PAIR_KINDS, 2):
        if a in COMPRESS and b in COMPRESS:
            continue
        ka, sa = KEYS.get(a, (None, ""))
        kb, sb = KEYS.get(b, (None, ""))
        if a == b:
            continue
        data = enc(b, kb, enc(a, ka, plan))
        lit = hexlit(data)
        fields = [s for s in (sa, sb) if s]
        labels_ = [f"hex_compact|{a}_then_{b}|" + "|".join(fields)]
        if len(fields) == 2 and all(len(s) == 2 for s in fields):
            labels_.append(f"hex_compact|{a}_then_{b}|{fields[0]},{fields[1]}")
        for label in labels_:
            n_lab += 1
            got = read(specimen(lit, label))
            if got != PLAN:
                bad_lab.append(f"{label}: {str(got)[:40]}")
        n_fb += 1
        t0 = time.perf_counter()
        got = read(specimen(lit, "stacked_v2|" + "|".join(fields)))
        slow = max(slow, time.perf_counter() - t0)
        if got != PLAN:
            bad_fb.append(f"{a} then {b}")
    check(f"pairs: {n_lab - len(bad_lab)} of {n_lab} labelled pairs (`first_then_second`, keys in their own fields or one) "
          f"read to the plan", not bad_lab, "; ".join(bad_lab[:6]))
    # By design the fallback does not stack ROT13 with a stream cipher (RC4, repeating, rolling xor,
    # Vigenere): those are read under their label only (see _Kit.pair_maps).
    streams = {"repeating_key_xor", "rolling_xor", "rc4", "vigenere"}
    allowed = {f"{a} then {b}" for a, b in itertools.permutations(PAIR_KINDS, 2)
               if {a, b} & {"rot13"} and {a, b} & streams}
    unexpected = [x for x in bad_fb if x not in allowed]
    check(f"pairs: {n_fb - len(bad_fb)} of {n_fb} pairs under an unknown label read by the fallback (slowest {slow:.3f} s); "
          f"what it leaves is ROT13 stacked with a stream cipher, read under their label only ({', '.join(bad_fb)})",
          not unexpected, "; ".join(unexpected[:8]))
    # A key both hex and decimal (`10`): a reversed rolling xor undone with 0x10 and with 10 differs in its
    # last byte only ('n' and 't'), and both are plans. Two plans are no plan, under an unknown label and
    # under its own (the labelled path never picks one reading of a key); with the key as `0x10` the plan.
    data = enc("rolling_xor", 0x10, plan[::-1])
    got = [read(specimen(hexlit(data), lab)) for lab in
           ("stacked_v2|10", "hex_compact|reverse_bytes_then_rolling_xor|10", "stacked_v2|0x10",
            "hex_compact|reverse_bytes_then_rolling_xor|0x10")]
    check("pairs: a reversed rolling xor whose key `10` reads as hex and as decimal (two plans, one byte apart): no plan "
          "under an unknown label or under `reverse_bytes_then_rolling_xor|10`; the plan with the key as `0x10`",
          got == [None, None, PLAN, PLAN], str([str(g)[-12:] for g in got]))
    # Fused names and other separators
    data = enc("add_modulo_256", 0x13, enc("single_byte_xor", 0x5A, plan))
    forms = ["hex_compact|xor_add|5a,13", "hex_compact|xor+add|5a|13", "hex_compact|single_byte_xor>add_modulo_256|5a:13",
             "hex_compact|add_xor|13,5a", "hex_compact|xor_and_then_add|5a|13"]
    got = [read(specimen(hexlit(data), f)) for f in forms]
    check("pairs: other spellings of a pair (fused `xor_add`, `+`, `>`, `_and_then_`; a fused name either order)",
          got == [PLAN] * len(forms), str([str(g)[:20] for g in got]))
    # A reversal stacked with a pair: reverse, then xor, then rc4 (three steps), in base64
    data = rc4(b"huntress", enc("single_byte_xor", 0x5A, plan[::-1]))
    got = read(specimen(f'"{base64.b64encode(data).decode()}"', "mystery|5a|huntress"))
    check("pairs: a reversal under a pair of a map and a stream (three steps), unknown label", got == PLAN, str(got)[:60])
    # compress then base64, then xor of the base64 text's bytes (the base64 as a reading, the compression as a stream)
    data = enc("single_byte_xor", 0x33, zlib.compress(plan))
    got = read(specimen(f'"{base64.b64encode(data).decode()}"', "mystery|33"))
    check("pairs: compress then xor, written in base64, unknown label", got == PLAN, str(got)[:60])
    return n_lab, len(bad_lab), n_fb, len(bad_fb)


# ---------------------------------------------------------------- what is never accepted

def test_never():
    plan = PLAN.encode()
    other = PLAN.replace("4242424242", "9999999999")
    two = specimen(hexlit(rc4(b"huntress", plan)), "hex_compact|rc4|huntress") + \
        specimen(f'"{b58encode(other.encode())}"', "base58|identity|", ident="0b0b0b0b")
    check("never: two labelled materials with different plans under row 79's codecs are no plan", read(two) is None)
    two_fb = specimen(hexlit(rc4(b"huntress", plan)), "mystery|huntress") + \
        specimen(hexlit(enc("bit_reverse", None, other.encode())), "mystery|", ident="0b0b0b0b")
    check("never: the same under unknown labels (the fallback for both) is no plan", read(two_fb) is None)
    # The plain plan, and a key whose first letter is `a`: Vigenere would keep `v=` and garble the rest,
    # which the plan grammar alone takes. _strict keeps that out, so the one plan stands.
    body = specimen(hexlit(plan), "plain_v9|abc")
    check("never: a Vigenere reading that keeps `v=` and garbles the rest is no second plan (the plan stands)",
          read(body) == PLAN, str(read(body))[:60])
    no_steps = "v=1|feature=indirect_expansion|primitive=pointer|campaign_id=campaign-7777777777|stage_count=1"
    body = specimen(f'"{rot(13, no_steps.encode()).decode()}"', "mystery|")
    check("never: a plan without a steps field that only a row 79 reading gives (ROT13, unknown label) is not taken",
          read(body) is None, str(read(body)))
    body = specimen(f'"{rot(13, ADV.encode()).decode()}"', "mystery|")
    check("never: the same advanced plan with its steps field is taken", read(body) == ADV, str(read(body)))
    blob = '{"a": 1, "b": "settings"}'
    body = specimen(hexlit(rc4(b"huntress", blob.encode())), "hex_compact|rc4|huntress")
    check("never: a JSON object without steps under RC4 is no plan", read(body) is None)
    junk = specimen(hexlit(bytes(random.Random(5).randrange(256) for _ in range(300))), "mystery|rc4|huntress|5a,13")
    check("never: random bytes under every key are no plan", read(junk) is None)
    # A row 79 name never changes what an old label reads (the old name goes to _undo alone).
    old = specimen(hexlit(enc("single_byte_xor", 0xCD, plan)), "hex_compact|single_byte_xor|cd")
    check("never: an old label reads as before", read(old) == PLAN)


# ---------------------------------------------------------------- review fixes (2026-10-07)

def test_review():
    """The four review blockers: a garbled plan from a near-miss pair, a stream cut short, the
    fallback's cost for an unseen transform name, and a compressed stream that grows large."""
    plan = PLAN.encode()
    # 1. A transform whose key is not in the label: a pair of the label's maps that matches it on most bytes
    # gives a plan with a garbled value. No plan, as before row 79.
    js = b'{"steps":["decode_embedded","write_file"],"adapter":"X.Y","campaign_id":"c-1"}'
    short = b"v=1|steps=acquire_remote,dispatch_memory|adapter=Lab.Adapter|stage_count=2|campaign_id=campaign-4242424242"
    got = [read(specimen(hexlit(bytes((c + 2) % 256 for c in js)), "hex|mystery|a8|32")),
           read(specimen(hexlit(bytes((c + 32) % 256 for c in short)), "hex|mystery|31|bc"))]
    check("review: a plan under a key the label does not hold, which a pair of the label's maps nearly undoes "
          "(JSON +2 under a8|32; k=v +32 under 31|bc): no plan, as before row 79", got == [None, None], str(got)[:120])
    garbled = '{"steps":["dec\x7fdeoembedded","writeofile"],"adapter":"X>Y","campaig~oid":"c-1"}'
    check("review: _strict refuses JSON whose steps or keys are not names (and takes a clean JSON plan)",
          not label_plan._strict(garbled) and label_plan._strict(js.decode())
          and not label_plan._strict('{"steps":["a b"],"x":1}') and not label_plan._strict('{"steps":["ok"],"x":"\u0001"}'))
    # 2. A stream cut short: no plan (a cut plan would answer its last value cut, under cut=False).
    bad = []
    for kind, names in (("lzma", ("hex_compact|lzma|", "hex_compact|mystery|")), ("xz", ("hex_compact|xz|", "hex_compact|mystery|")),
                        ("bz2", ("hex_compact|bz2|", "hex_compact|mystery|")), ("zlib", ("hex_compact|zlib|", "hex_compact|mystery|")),
                        ("gzip", ("hex_compact|gzip|", "hex_compact|mystery|"))):
        z = enc(kind, None, plan)
        for cut in (4, 12, 30, 40):
            for name in names:
                got = read(specimen(hexlit(z[:-cut]), name))
                if got is not None:
                    bad.append(f"{kind}[:-{cut}] as {name}: {got[-30:]}")
        for name in names:
            if read(specimen(hexlit(z), name)) != PLAN:
                bad.append(f"{kind} whole as {name}")
    check("review: lzma, xz, bz2, zlib and gzip streams cut by 4 to 40 bytes give no plan (labelled and fallback); "
          "whole, the plan", not bad, "; ".join(bad[:4]))
    # 3. An unseen transform name over a Day 7-sized Mastery: 78 specimens under a label whose transform no
    # table knows, each key in the label. The fallback's first pass (the search before row 79) reads them.
    rng = random.Random(79)
    bodies = []
    for i in range(78):
        k = rng.randrange(1, 256)
        kind = rng.choice(("single_byte_xor", "add_modulo_256", "subtract_modulo_256", "rolling_xor"))
        lit = enc(kind, k, plan)
        lit = f'"{base64.b64encode(lit).decode()}"' if i % 2 else hexlit(lit)
        rep_ = "base64_literal" if i % 2 else "hex_compact"
        bodies.append((specimen(lit, f"{rep_}|mystery_{kind}|{k:02x}", ident=f"{i:08x}"), PLAN))
    t0 = time.perf_counter()
    ok = sum(read(b) == want for b, want in bodies)
    dt = time.perf_counter() - t0
    check(f"review: 78 specimens under an unseen transform name read by the fallback's first pass: {ok}/78 in {dt:.3f} s "
          f"(limit 0.5 s)", ok == 78 and dt < 0.5)
    # 4. Compressed streams that grow large, under 100 KB of material: bounded (no stream past MAX_INFLATE counts).
    worst, where = 0.0, ""
    heavy = "b64x|wt|" + ",".join(str(i) for i in range(1, 26)) + "|huntress|secretkey|abcdef|ghijkl|mnopqr|stuvwx"
    for pn, payload in (("zeros", b"\0" * (64 << 20)), ("letters", b"v=1|" + b"abcdefghij" * (6 << 20))):
        for cn, z in (("bz2", bz2.compress(payload, 9)), ("xz", lzma.compress(payload))):
            m = base64.b64encode(z).decode()
            for label in ("base64_weird|weird_tr|5a", heavy):
                label_plan._KITS.clear()
                t0 = time.perf_counter()
                got = label_plan.fallback([m], label)
                dt = time.perf_counter() - t0
                if dt > worst:
                    worst, where = dt, f"{cn} of 64 MB {pn}, {len(m)} chars"
                if got:
                    check(f"review: {cn} of {pn} gives no plan", False, str(got)[:60])
    check(f"review: bz2 and xz streams of 64 MB in under 15 KB of material: worst {worst:.3f} s ({where}); limit 0.3 s",
          worst < 0.3)


# ---------------------------------------------------------------- the general path, end to end

def test_generic_path():
    member = "remote-stage.zz9"

    def question(qid, text):
        return {"qid": qid, "id": qid, "answer_id": qid, "member": member, "artifact": f"evidence.zip -> {member}",
                "question": text, "answer_format": {"type": "exact_text"}}
    qs = [question("zz9-stager-campaign", "Recover the exact synthetic campaign identifier."),
          question("zz9-stager-adapter", "Recover the exact adapter named by the reconstructed plan."),
          question("zz9-stager-url", "Recover the exact url indicator."),
          question("zz9-stager-role", f"Classify {member} by its ordered behavior graph.")]
    body = specimen(f'"{base64.b64encode(rc4(b"huntress", PLAN.encode())).decode()}"', "base64_literal|rc4|huntress")
    with contextlib.redirect_stderr(io.StringIO()):
        out = generic.answers(qs, {member: body.encode()}, {})
    check("generic: a language no day has seen, its plan under RC4 with a text key: the plan's answers",
          out == {"zz9-stager-campaign": "campaign-4242424242", "zz9-stager-adapter": "Lab.Adapter",
                  "zz9-stager-url": "https://lab.invalid/stage-4242424242.bin", "zz9-stager-role": "stager"}, str(out))


# ---------------------------------------------------------------- bounded

def test_bounded():
    rng = random.Random(7)
    raw = bytes(rng.randrange(256) for _ in range(50_000))
    mats = {"hex": raw.hex(), "base64": base64.b64encode(raw + raw[:25_000]).decode(),
            "decimal": ",".join(str(b) for b in raw[:28_000]),
            "hex text": "".join(rng.choice("0123456789abcdef") for _ in range(100_000)),
            "letters": "".join(rng.choice("abcdefghijklmnopqrstuvwxyz =|") for _ in range(100_000))}
    worst, where = 0.0, ""
    for name, m in mats.items():
        for label in ("mystery|cd", "x|xor_then_rc4|af,9e,f2,0a,9b,13,77,01|longsecretkey|another|0x6b6579"):
            t0 = time.perf_counter()
            got = read(specimen(f'"{m}"', label))
            dt = time.perf_counter() - t0
            if dt > worst:
                worst, where = dt, f"{name} under {label.split('|')[0]}"
            if got is not None:
                check(f"bounded: random {name} is no plan", False, str(got)[:60])
    check(f"bounded: the fallback on 100 KB of labelled random material: worst {worst:.2f} s ({where}); limit 3 s", worst < 3.0)
    # A plan inside 100 KB: the plan's own bytes, rc4 under a text key, padded by spaces before the base64.
    pad = PLAN + "|pad=" + "x" * 70_000
    body = specimen(f'"{base64.b64encode(rc4(b"huntress", pad.encode())).decode()}"', "mystery|huntress")
    t0 = time.perf_counter()
    got = read(body)
    dt = time.perf_counter() - t0
    check(f"bounded: a 94 KB RC4 material under an unknown label is read ({dt:.2f} s)", got == pad and dt < 3.0, str(got)[:40])


def main() -> int:
    t0 = time.perf_counter()
    n_forms, n_lab, n_fb, bad_l, bad_f = test_forms()
    p_lab, p_bad_lab, p_fb, p_bad_fb = test_pairs()
    test_never()
    test_review()
    test_generic_path()
    test_bounded()
    print(f"coverage: forms {n_forms}, labelled {n_lab - bad_l}/{n_lab}, fallback {n_fb - bad_f}/{n_fb}; "
          f"pairs labelled {p_lab - p_bad_lab}/{p_lab}, pairs fallback {p_fb - p_bad_fb}/{p_fb}; {time.perf_counter() - t0:.1f} s")
    failed = sum(1 for _, ok in results if not ok)
    print(f"TEST_WAVEC_CODECS passed={len(results) - failed} failed={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
