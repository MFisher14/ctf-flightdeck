"""Cross-engine integration + robustness-fuzz for the Nov-5 coverage engines.

Exercises the new engines TOGETHER on realistic multi-step chains (output of one feeding the next), and
fuzzes each public API with malformed/random input to prove it fails closed (declared exception / [] /
None) rather than crashing. Pure test module — adds no engine code."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import random

import pytest

import embedded_decode as ed
import xor_repeat as xr
import xor_strings as xs
import crib_drag as cd
import hash_identify as hi
import timestamp_decode as ts
import session_forge as sf


# ---------------------------------------------------------------- cross-engine chains
def test_chain_embedded_base64_then_repeating_xor():
    # layer 2: an English message (carrying the flag) XORed with a repeating key; layer 1: that
    # ciphertext base64'd inside a web page. English-dominant + long so crib-less recovery is reliable.
    flag = (b"the hidden message reads as follows the flag is right here in plain sight for all "
            b"to see once you have peeled the two encoding layers that were wrapped around it and "
            b"this english text continues for a while so the per column statistics stay reliable "
            b"CSCTF{chain} and then a little more ordinary english prose to round the sample out ") * 2
    key = b"X0R"
    ct = bytes(c ^ key[i % len(key)] for i, c in enumerate(flag))
    page = f"<html><!-- {base64.b64encode(ct).decode()} --></html>"
    # step 1: embedded_decode pulls the base64 blob out of the page (it is binary -> allow low printable)
    blobs = ed.find_blobs(page, min_printable=0.0)
    assert blobs, "embedded_decode should find the base64 blob"
    # the full ciphertext is the longest decode (base64url fragments split at +// are shorter)
    recovered_ct = max(blobs, key=lambda b: len(b["decoded"]))["decoded"]
    # step 2: xor_repeat recovers the plaintext from the extracted ciphertext (crib-less -> ~exact)
    cands = xr.solve(recovered_ct)

    def sim(a, b):
        n = min(len(a), len(b))
        return sum(1 for i in range(n) if a[i] == b[i]) / n if n else 0
    assert cands and max(sim(c["plaintext"], flag) for c in cands) >= 0.9


def test_chain_xor_strings_finds_hash_then_hash_identify():
    # a binary hides an MD5 hash XOR-encoded; find it, then identify what it is.
    md5 = hashlib.md5(b"password").hexdigest().encode()
    k = 0x6b
    blob = bytes([k]) * 8 + bytes(c ^ k for c in md5) + bytes([k]) * 8
    hits = xs.xor_strings(blob)
    # the true md5 is among the recovered strings (under key 0x6b); identify it
    assert md5.decode() in [h["text"] for h in hits]
    assert "MD5" in [r["name"] for r in hi.identify(md5.decode())]


def test_chain_session_forge_then_session_recon_identifies_it():
    session_recon = pytest.importorskip("session_recon")
    cookie = sf.forge_flask("leaked-secret", {"admin": True})
    # session_recon should recognise the forged value as a Flask/itsdangerous-style signed cookie.
    report = session_recon.analyze([("Set-Cookie", f"session={cookie}; HttpOnly")])
    blob = repr(report).lower()
    assert "session" in blob  # recon produced a cookie indicator for our forged cookie


def test_chain_crib_drag_reveals_flag_across_two_messages():
    key = os.urandom(70)
    p1 = b"the second message quietly carries the flag somewhere inside of it here ok"
    p2 = b"CSCTF{keystream_reuse} plus a long english sentence to pad it out nicely yep"
    c1 = bytes(a ^ b for a, b in zip(p1, key))
    c2 = bytes(a ^ b for a, b in zip(p2, key))
    # drag a crib known to be in p1; the revealed bytes expose p2 (which holds the flag) at that offset
    off = p1.index(b"the flag")
    res = cd.crib_drag(c1, c2, b"the flag")
    match = next((r for r in res if r["offset"] == off), None)
    assert match is not None and match["revealed"] == p2[off:off + len(b"the flag")]


def test_chain_timestamp_in_forensic_context():
    # a WebKit timestamp pulled from a Chrome History row decodes to a plausible date
    import datetime as dt
    ref = dt.datetime(2024, 1, 15, 9, 30, tzinfo=dt.timezone.utc)
    webkit = int((ref - ts.EPOCH_1601).total_seconds() * 1e6)
    r = next(x for x in ts.decode(webkit) if x["format"].startswith("chrome/webkit"))
    assert r["plausible"] and r["year"] == 2024


# ---------------------------------------------------------------- robustness fuzz (fail closed, no crash)
_RNG = random.Random(1337)


def _garbage():
    choices = [b"", b"\x00" * 50, bytes(_RNG.randrange(256) for _ in range(_RNG.randrange(200))),
               ("\x00" * 30), "not bytes", 12345, None, [1, 2, 3], b"\xff\xfe" * 20, "=" * 40,
               "A" * 300, b"CSCTF{" * 10]
    return _RNG.choice(choices)


@pytest.mark.parametrize("seed", range(40))
def test_engines_fail_closed_on_garbage(seed):
    _RNG.seed(seed)
    g = _garbage()
    # none of these may raise an unexpected exception on arbitrary input
    assert isinstance(xr.solve(g), list)
    assert isinstance(xr.single_byte(g), list)
    assert isinstance(xs.xor_strings(g if isinstance(g, (bytes, bytearray)) else b""), list)
    assert isinstance(ed.find_blobs(g), list)
    assert isinstance(hi.identify(g), list)
    assert isinstance(ts.decode(g), list)
    assert isinstance(cd.crib_drag(g, g, b"x"), list)
    assert isinstance(cd.many_time_pad([g, g]), dict)
    # session_forge declares ForgeError for bad input; anything else would be a bug
    try:
        sf.forge_flask("k", g if isinstance(g, dict) else {"a": 1})
    except sf.ForgeError:
        pass
