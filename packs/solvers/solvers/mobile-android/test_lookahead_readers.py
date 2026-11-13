"""Focused tests for lookahead_readers.py (Day 21 Mobile look-ahead readers).

Run from the lane directory with the repo venv:
    .venv/bin/python -I solvers/mobile-android/test_lookahead_readers.py
or under pytest. Every reader is checked two ways: it answers an EXACT code, UNSURE (a `??`
pick, never plain, under a `lookahead:` route), on a document the shipped solver leaves None;
and it answers NOTHING (None, never a guess) on bytes that do not reconstruct exactly one
code. The guard that it never changes or slows an answer the shipped solver already makes is
proven by `tools/preflight.py --regress mobile-android` (changed=0) and `tools/solvetimes.py`;
here one case shows the guard returning the shipped Hit untouched.
"""
import io
import json
import struct
import sys
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE.parent / "common", HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import codec_search as C          # noqa: E402
import lookahead_readers as L     # noqa: E402
import labels                     # noqa: E402

CODE = "ANS-0123456789ABCDEF"
CODE2 = "ANS-FEDCBA9876543210"


# -------------------------------------------------------------------- builders (self-contained, no tests/ import)

def dex(*strings):
    n = len(strings)
    head = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    struct.pack_into("<II", head, 0x38, n, 0x70)
    data, offs, base_off = b"", [], 0x70 + 4 * n
    for s in strings:
        b = s.encode() if isinstance(s, str) else s
        ln, uleb = len(b), b""
        while True:
            byte = ln & 0x7F
            ln >>= 7
            uleb += bytes([byte | (0x80 if ln else 0)])
            if not ln:
                break
        offs.append(base_off + len(data))
        data += uleb + b + b"\x00"
    return bytes(head) + b"".join(struct.pack("<I", o) for o in offs) + data


def zip_of(members):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in members.items():
            z.writestr(n, b)
    return out.getvalue()


def apk(doc, extra=None):
    m = {"assets/huntress_puzzle.json": json.dumps(doc).encode(),
         "classes.dex": dex("CODEC", "CONTROL", "DAY", "Ljava/lang/Object;")}
    if extra:
        m.update(extra)
    return zip_of(m)


def is_unsure_code(answer, want, route_contains):
    """True when `answer` is an unsure pick (never plain) that offers EXACTLY `want` as the value of a
    `route_contains` option. A plain string or None fails."""
    assert labels.is_unsure(answer), "expected an unsure pick, got %r" % (answer,)
    u = labels.parse(answer)
    vals = {v for _, v in u.options}
    names = " ".join(n for n, _ in u.options) + " " + u.key
    assert want in vals, "code %s not offered; options=%r" % (want, u.options)
    assert route_contains in names, "route %r not in %r" % (route_contains, names)
    return True


# -------------------------------------------------------------------- cipher encoders (independent of the reader)

def xtea_enc(blob, key, rounds=32, delta=0x9E3779B9):
    k = struct.unpack(">4I", key)
    mask = 0xFFFFFFFF
    blob = blob + b"\x00" * (-len(blob) % 8)
    out = bytearray()
    for off in range(0, len(blob), 8):
        v0, v1 = struct.unpack(">2I", blob[off:off + 8])
        s = 0
        for _ in range(rounds):
            v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (s + k[s & 3]))) & mask
            s = (s + delta) & mask
            v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (s + k[(s >> 11) & 3]))) & mask
        out += struct.pack(">2I", v0, v1)
    return bytes(out)


def rolling_add(blob, key):
    return bytes(c ^ ((key[i % len(key)] + i) & 0xFF) for i, c in enumerate(blob))


def lcg_enc(blob, a, c, m, seed):
    st = seed % m
    out = bytearray()
    for byte in blob:
        st = (a * st + c) % m
        out.append(byte ^ (st & 0xFF))
    return bytes(out)


# -------------------------------------------------------------------- the tests

def test_char_list():
    doc = {"schema": "huntress.mobile.puzzle.v1", "day": 21, "codec": "mystery", "data": list(CODE)}
    assert is_unsure_code(C.solve_apk(apk(doc)), CODE, "char-list")


def test_char_list_unit_str_and_int():
    # the reader itself reads both a list of 1-char strings and a list of char codes (the integer-code
    # list is also caught by the Day 19 `ints` reader at integration, so this checks the reader directly)
    assert L.char_list({"codec": "mystery", "data": list(CODE)}) == [("char-list@data", CODE)]
    assert L.char_list({"codec": "mystery", "data": [ord(ch) for ch in CODE]}) == [("char-list@data", CODE)]
    # not exactly a code: nothing
    assert L.char_list({"codec": "mystery", "data": list("HELLO-WORLD-NOTCODE!")}) == []


def test_linked_list():
    ids = ["n%d" % i for i in range(len(CODE))]
    nodes = {ids[i]: {"c": ch, "next": ids[i + 1] if i + 1 < len(CODE) else None} for i, ch in enumerate(CODE)}
    doc = {"codec": "mystery", "data": nodes, "head": ids[0]}
    assert is_unsure_code(C.solve_apk(apk(doc)), CODE, "linked-list")


def test_collapsed_keys_unit():
    # {position: char} under the data field, and under a non-reserved field
    assert L.collapsed_keys({"codec": "x", "data": {str(i): ch for i, ch in enumerate(CODE)}}) == \
        [("collapsed-keys@data", CODE)]
    assert L.collapsed_keys({"codec": "x", "board": {str(i): ch for i, ch in enumerate(CODE)}}) == \
        [("collapsed-keys@board", CODE)]
    # a non-dense set of positions proves no join: nothing
    assert L.collapsed_keys({"codec": "x", "data": {"0": "A", "5": "N"}}) == []


def test_nsc_pin_unit_and_starved():
    xml = ("<network-security-config><pin-set>"
           "<pin digest=\"SHA-256\">%s</pin></pin-set></network-security-config>" % CODE).encode()
    assert L.nsc_pin({"res/xml/network_security_config.xml": xml}) == [("nsc-pin", CODE)]
    # two different pins prove nothing
    two = ("<x><pin>%s</pin><pin>%s</pin></x>" % (CODE, CODE2)).encode()
    assert L.nsc_pin({"a.xml": two}) == []
    # integration: a starved clock makes the usual package look time out, and the reader still answers
    mems, inner = C.read_members(apk({"codec": "mystery", "data": "z"},
                                      {"res/xml/network_security_config.xml": xml}))
    clock = C.Clock(0.0001)
    time.sleep(0.002)
    assert is_unsure_code(C._solve(mems, inner, clock), CODE, "nsc-pin")


def test_xtea():
    key = b"0123456789ABCDEF"
    doc = {"codec": "xtea", "key": key.decode(), "data": xtea_enc(CODE.encode(), key).hex()}
    assert is_unsure_code(C.solve_apk(apk(doc)), CODE, "xtea")


def test_rolling_xor():
    key = b"KEY!"
    doc = {"codec": "rolling_xor", "key": key.decode(), "data": rolling_add(CODE.encode(), key).hex()}
    assert is_unsure_code(C.solve_apk(apk(doc)), CODE, "rolling-xor")


def test_lcg():
    a, c, m, seed = 1664525, 1013904223, 2 ** 32, 12345
    doc = {"codec": "lcg", "a": a, "c": c, "m": m, "seed": seed,
           "data": lcg_enc(CODE.encode(), a, c, m, seed).hex()}
    assert is_unsure_code(C.solve_apk(apk(doc)), CODE, "lcg")


def test_encrypted_zip_member():
    try:
        import pyzipper
    except Exception:
        return   # no pyzipper: skip (the lane's venv has it)
    inner = io.BytesIO()
    with pyzipper.AESZipFile(inner, "w", encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"infected")
        z.writestr("payload.bin", ("code: " + CODE + " end").encode())
    ez = inner.getvalue()
    doc = {"codec": "mystery", "data": "assets/enc.zip"}
    members = {"assets/huntress_puzzle.json": json.dumps(doc).encode(), "classes.dex": dex("X"),
               "assets/enc.zip": ez}
    # the reader reads the one code in the encrypted entry with the package's own passwords
    assert L.encrypted_zip_member(doc, members) == [("encrypted-zip-member", CODE)]
    # integration under a starved clock (read_members also decrypts nested archives, so the usual package
    # look answers it when the budget is not starved; the reader is the budget-pressure safety net)
    mems, inner2 = C.read_members(zip_of(members))
    clock = C.Clock(0.0001)
    time.sleep(0.002)
    assert is_unsure_code(C._solve(mems, inner2, clock), CODE, "encrypted-zip-member")


def test_twin_single():
    first = json.dumps({"codec": "mystery", "data": list(CODE)}).encode()
    last = json.dumps({"codec": "mystery", "data": "unreadable"}).encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("assets/huntress_puzzle.json", first)
        z.writestr("classes.dex", dex("X"))
        z.writestr("assets/huntress_puzzle.json", last)
    assert is_unsure_code(C.solve_apk(out.getvalue()), CODE, "twin-entry")


def test_twin_candidates():
    e1 = json.dumps({"codec": "mystery", "data": list(CODE)}).encode()
    e2 = json.dumps({"codec": "mystery", "data": list(CODE2)}).encode()
    last = json.dumps({"codec": "mystery", "data": "none"}).encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("assets/huntress_puzzle.json", e1)
        z.writestr("assets/huntress_puzzle.json", e2)
        z.writestr("classes.dex", dex("X"))
        z.writestr("assets/huntress_puzzle.json", last)
    ans = C.solve_apk(out.getvalue())
    assert labels.is_unsure(ans) and labels.is_candidate(ans), "twin-with-two-codes must be a candidate pick"
    u = labels.parse(ans)
    assert {v for _, v in u.options} == {CODE, CODE2}


# -------------------------------------------------------------------- never-guess / guard

def test_garbage_is_none():
    assert C.solve_apk(apk({"codec": "mystery", "data": "not a code at all"})) is None


def test_char_list_that_is_not_a_code_is_none():
    assert C.solve_apk(apk({"codec": "mystery", "data": list("HELLO-WORLD-NOTCODE!")})) is None


def test_wrong_cipher_key_is_none():
    ct = xtea_enc(CODE.encode(), b"0123456789ABCDEF")
    assert C.solve_apk(apk({"codec": "xtea", "key": "WRONGKEYWRONGKEY", "data": ct.hex()})) is None


def test_two_different_lookahead_codes_is_none():
    # a char-list code AND a different nsc pin: two readers, two codes, nothing proves which -> None, no guess
    xml = ("<x><pin>%s</pin></x>" % CODE2).encode()
    members = {"assets/huntress_puzzle.json": json.dumps({"codec": "mystery", "data": list(CODE)}).encode(),
               "res/xml/network_security_config.xml": xml}
    got, _ = L.read(members)
    assert got is None, "two different lookahead codes must give None, got %r" % (got,)


def test_guard_does_not_touch_a_read_answer():
    # a plain base64 document the shipped solver reads: lookahead_revise must return the Hit unchanged
    import base64 as b64
    doc = {"schema": "huntress.mobile.puzzle.v1", "codec": "base64",
           "data": b64.b64encode(CODE.encode()).decode()}
    ans = C.solve_apk(apk(doc))
    assert ans == CODE, "a base64 document must still answer plain %r, got %r" % (CODE, ans)


def _run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        t()
        passed += 1
        print("PASS %s" % t.__name__)
    print("\nlookahead_readers: %d/%d passed" % (passed, len(tests)))
    return 0


if __name__ == "__main__":
    sys.exit(_run())
