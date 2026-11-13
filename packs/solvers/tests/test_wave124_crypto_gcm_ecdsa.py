#!/usr/bin/env python3
"""Offline tests of wave124: AES-GCM nonce-reuse forgery and ECDSA biased-nonce
key recovery (the Hidden Number Problem).

  .venv/bin/python tests/test_wave124_crypto_gcm_ecdsa.py

Covers the primitives in solvers/common/crypto_depth.py (GF(2^128)/GHASH against
pycryptodome's own AES-GCM, the forbidden attack, the LLL lattice and HNP) and
the wiring in solvers/toolkits/modern_crypto.py (the GCM auth-key / forged-tag
answers are UNSURE only; the HNP private scalar is plain ONLY after d*G==pubkey).
Each attack has a near-miss beside it (different nonce, corrupted tag, a full-size
nonce, a wrong public key, too few signatures) that must give None/[]. Prints one
line per check and `ok` at the end; exits 1 when a check fails.

No network and no token. Fixtures are synthesized here from a fixed seed.
"""
import importlib.util
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_wave124_")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "common"))

import crypto_depth as cd                                       # noqa: E402

spec = importlib.util.spec_from_file_location("tk_modern_crypto", REPO / "solvers" / "toolkits" / "modern_crypto.py")
tk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tk)

from Crypto.Cipher import AES                                   # noqa: E402

RND = random.Random(20261024)
FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)


def q(question, aid="answer", kind="exact_text", pattern=None):
    fmt = {"kind": kind}
    if pattern:
        fmt["pattern"] = pattern
    return {"id": aid, "qid": aid, "answer_id": aid, "question": question, "answer_format": fmt}


# The toolkit's budgets (BUDGET, HNP_BUDGET, the LLL deadline) counted in this process's CPU time (SH-08).
# Every deadline the toolkit and crypto_depth set or check is read from time.monotonic (or
# time.perf_counter), so inside cpu_clock() both read time.process_time: the same budgets, in seconds of
# work. A process that waits for a core on a loaded machine accrues none, so a full-suite run under load no
# longer runs the HNP's 2.5 s out before its ~0.5 s of work and leaves the answer None. Work over a budget
# still runs it out. The helper is shared with SH-09's checks (tests/sh09_clocks.py).
sys.path.append(str(REPO / "tests"))                            # last: tests/ shadows no solver module
from sh09_clocks import cpu_clock                               # noqa: E402


def cpu_seconds(fn, *args):
    """(fn(*args), the CPU seconds of this process it took). A bound on it is a bound on work, which a
    loaded machine does not stretch the way it stretches wall time (SH-08)."""
    t0 = time.process_time()
    out = fn(*args)
    return out, time.process_time() - t0


def solve(question, files):
    with cpu_clock():
        return tk.solve_set([question], files, {})[question["qid"]]


def unsure(v, key=None):
    if not (isinstance(v, str) and v.startswith("??")):
        return False
    body = json.loads(v[2:])
    return key is None or body["k"] == key


def opts(v):
    return [o[1] for o in json.loads(v[2:])["o"]]


def gcm(key, iv, aad, pt):
    c = AES.new(key, AES.MODE_GCM, nonce=iv)
    if aad:
        c.update(aad)
    return c.encrypt_and_digest(pt)


def subkey(key):
    return int.from_bytes(AES.new(key, AES.MODE_ECB).encrypt(b"\x00" * 16), "big")


# ---- the field and GHASH --------------------------------------------------------------------------------

def test_field():
    o = cd.GF_ONE
    check("GF(2^128) identity is 1<<127", cd.gf_mul(0x1234567, o) == 0x1234567)
    check("GF(2^128) inverse", all(cd.gf_mul(cd.gf_inv(x), x) == o for x in (1, o, 0xABCDEF, (1 << 120) | 7)))
    # GHASH reproduces pycryptodome's own AES-GCM tag on random inputs
    ok = True
    for _ in range(40):
        key = bytes(RND.getrandbits(8) for _ in range(16))
        iv = bytes(RND.getrandbits(8) for _ in range(12))
        aad = bytes(RND.getrandbits(8) for _ in range(RND.randint(0, 40)))
        pt = bytes(RND.getrandbits(8) for _ in range(RND.randint(0, 64)))
        ct, tag = gcm(key, iv, aad, pt)
        S = int.from_bytes(AES.new(key, AES.MODE_ECB).encrypt(iv + b"\x00\x00\x00\x01"), "big")
        if cd.gcm_tag(subkey(key), S, aad, ct) != tag:
            ok = False
            break
    check("GHASH/gcm_tag match pycryptodome AES-GCM on 40 random (key, iv, aad, pt)", ok)
    check("poly_roots finds all roots of a product of linear factors",
          sorted(cd.poly_roots(cd._p_mul(cd._p_mul([7, cd.GF_ONE], [99, cd.GF_ONE]), [0x5555, cd.GF_ONE])))
          == sorted([7, 99, 0x5555]))


# ---- the forbidden attack -------------------------------------------------------------------------------

def _gcm_pairs(key, iv, npairs, size=40, aad_len=0):
    out = []
    for _ in range(npairs):
        aad = bytes(RND.getrandbits(8) for _ in range(aad_len))
        ct, tag = gcm(key, iv, aad, bytes(RND.getrandbits(8) for _ in range(size)))
        out.append((aad, ct, tag))
    return out


def test_forbidden_attack():
    key = bytes(RND.getrandbits(8) for _ in range(16))
    iv = bytes(RND.getrandbits(8) for _ in range(12))
    H = subkey(key)
    pairs = _gcm_pairs(key, iv, 3)
    got, secs = cpu_seconds(cd.gcm_recover_subkey, pairs)
    check("forbidden attack: 3 pairs pin a unique H that reproduces every tag, in under 3 s of CPU",
          [h for h, _ in got] == [H] and secs < 3.0, (len(got), round(secs, 2)))
    got2 = cd.gcm_recover_subkey(_gcm_pairs(key, iv, 2, size=48))
    check("forbidden attack: 2 pairs give candidates with the true H among them (never unique)",
          H in [h for h, _ in got2] and len(got2) >= 1)
    # longer messages + aad still recover
    got3 = cd.gcm_recover_subkey(_gcm_pairs(key, iv, 3, size=96, aad_len=19))
    check("forbidden attack: longer messages with AAD still recover H", H in [h for h, _ in got3])
    # forge a tag for a chosen message and confirm against real GCM
    H2 = got[0][0]
    S2 = got[0][1]
    fct, ftag = gcm(key, iv, b"chosen aad", b"the attacker's forged message body")
    check("forbidden attack: a forged tag for a chosen message verifies against real AES-GCM",
          cd.gcm_tag(H2, S2, b"chosen aad", fct) == ftag)
    # near-misses -> nothing is claimed
    diff = [(_gcm_pairs(key, bytes(RND.getrandbits(8) for _ in range(12)), 1)[0]) for _ in range(3)]
    check("near-miss: three pairs under DIFFERENT nonces recover no H", cd.gcm_recover_subkey(diff) == [])
    bad = _gcm_pairs(key, iv, 3)
    corrupt = bytearray(bad[2][2]); corrupt[0] ^= 1
    bad[2] = (bad[2][0], bad[2][1], bytes(corrupt))
    check("near-miss: one corrupted tag -> the true H is never claimed", H not in [h for h, _ in cd.gcm_recover_subkey(bad)])
    check("near-miss: a single pair recovers nothing", cd.gcm_recover_subkey(_gcm_pairs(key, iv, 1)) == [])


# ---- the toolkit's GCM answers (unsure only) ------------------------------------------------------------

def _gcm_delivery(key, iv, npairs, forge_ct=None):
    d = {"nonce": iv.hex()}
    for i in range(1, npairs + 1):
        ct, tag = gcm(key, iv, b"", bytes(RND.getrandbits(8) for _ in range(32)))
        d[f"ciphertext{i}"] = ct.hex()
        d[f"tag{i}"] = tag.hex()
    if forge_ct is not None:
        d["forge_ciphertext"] = forge_ct.hex()
    return {"gcm.json": json.dumps(d).encode()}


def test_toolkit_gcm():
    key = bytes(RND.getrandbits(8) for _ in range(16))
    iv = bytes(RND.getrandbits(8) for _ in range(12))
    H = subkey(key)
    Hhex = H.to_bytes(16, "big").hex()
    files = _gcm_delivery(key, iv, 3)
    v = solve(q("The same nonce was reused. Recover the AES-GCM authentication key H.", "gcm-h"), files)
    check("toolkit GCM: auth key H is an UNSURE pick under modern_crypto.gcm/auth_key, true H present",
          unsure(v, "modern_crypto.gcm/auth_key") and Hhex in opts(v), v[:70] if v else v)
    v2 = solve(q("Nonce reused in GCM. What is the GHASH subkey H?", "gcm-h2"), _gcm_delivery(key, iv, 2))
    check("toolkit GCM: two pairs give an UNSURE candidates key (#candidates), true H among options",
          unsure(v2) and json.loads(v2[2:])["k"].endswith("#candidates") and Hhex in opts(v2))
    # forged tag
    key2 = bytes(RND.getrandbits(8) for _ in range(16)); iv2 = bytes(RND.getrandbits(8) for _ in range(12))
    tct, ttag = gcm(key2, iv2, b"", b"attacker chosen message!")
    v3 = solve(q("Forge a valid GCM tag for the chosen ciphertext (nonce reuse / GHASH).", "gcm-f"),
               _gcm_delivery(key2, iv2, 3, forge_ct=tct))
    check("toolkit GCM: a forged tag is an UNSURE pick under modern_crypto.gcm/forged_tag, correct value present",
          unsure(v3, "modern_crypto.gcm/forged_tag") and ttag.hex() in opts(v3), v3[:70] if v3 else v3)
    # never plain, and a normal GCM decrypt-with-key is NOT intercepted
    check("toolkit GCM: the H answer is never a plain string (always ??)", isinstance(v, str) and v.startswith("??"))
    key3 = bytes(range(16)); iv3 = bytes(range(16, 28))
    ct, tag = gcm(key3, iv3, b"", b"flag{gcm_decrypt_ok}")
    dec = {"key": key3.hex(), "nonce": iv3.hex(), "ciphertext": ct.hex(), "tag": tag.hex()}
    v4 = solve(q("Decrypt this AES-GCM ciphertext with the given key and submit the plaintext.", "dec",
                 pattern=r"flag\{[^}]+\}"), {"d.json": json.dumps(dec).encode()})
    check("toolkit GCM: a normal GCM decrypt-with-key question is NOT intercepted (still decrypts)",
          v4 == "flag{gcm_decrypt_ok}", v4)
    # a GCM auth-key question with no reuse material -> None
    one = {"nonce": iv.hex(), "ciphertext1": gcm(key, iv, b"", b"only one")[0].hex(), "tag1": gcm(key, iv, b"", b"only one")[1].hex()}
    v5 = solve(q("Recover the GCM authentication subkey H.", "gcm-none"), {"x.json": json.dumps(one).encode()})
    check("toolkit GCM: no reuse material -> None", v5 is None)


# ---- ECDSA biased-nonce recovery (HNP) ------------------------------------------------------------------

def _hnp_sigs(curve, d, L, m):
    cv = cd.CURVES[curve]; n = cv["n"]
    rs, ss, zs = [], [], []
    for _ in range(m):
        k = RND.getrandbits(L)
        z = RND.randrange(1, n)
        r = cd.ec_mul(k, cv)[0] % n
        s = (pow(k, -1, n) * (z + r * d)) % n
        rs.append(str(r)); ss.append(str(s)); zs.append(str(z))
    return rs, ss, zs


def test_hnp_primitive():
    for curve in ("secp256k1", "secp256r1"):
        cv = cd.CURVES[curve]; n = cv["n"]
        d = RND.randrange(1, n); Q = cd.ec_mul(d, cv)
        rs, ss, zs = _hnp_sigs(curve, d, 128, 8)
        triples = [(int(rs[i]), int(ss[i]), int(zs[i])) for i in range(8)]
        got, secs = cpu_seconds(cd.ecdsa_hnp_recover, curve, Q, triples, 128)
        check(f"HNP {curve}: d recovered from 8 sigs with 128-bit nonces, verified d*G==Q, in under 3 s of CPU",
              got == d and secs < 3.0, (got == d, round(secs, 2)))
        check(f"HNP {curve} near-miss: a wrong public key -> None",
              cd.ecdsa_hnp_recover(curve, cd.ec_mul(d + 1, cv), triples, 128) is None)
        # full-size (unbiased) nonces: cannot recover, must NOT lie
        rf, sf, zf = [], [], []
        for _ in range(8):
            k = RND.randrange(1, n); z = RND.randrange(1, n)
            r = cd.ec_mul(k, cv)[0] % n; s = (pow(k, -1, n) * (z + r * d)) % n
            rf.append(r); sf.append(s); zf.append(z)
        full = list(zip(rf, sf, zf))
        check(f"HNP {curve} near-miss: full-size nonces claimed short -> None (never a wrong d)",
              cd.ecdsa_hnp_recover(curve, Q, full, 128) is None)
    check("HNP: no public key -> None", cd.ecdsa_hnp_recover("secp256k1", None, [(1, 2, 3)] * 4, 128) is None)
    check("HNP: an unsupported curve -> None",
          cd.ecdsa_hnp_recover("curve25519", (1, 2), [(1, 2, 3)] * 4, 128) is None)
    check("HNP: too few signatures -> None", cd.ecdsa_hnp_recover("secp256k1", (1, 2), [(1, 2, 3)], 128) is None)


def test_toolkit_hnp():
    for curve in ("secp256k1", "secp256r1"):
        cv = cd.CURVES[curve]; n = cv["n"]
        d = RND.randrange(1, n); Q = cd.ec_mul(d, cv)
        rs, ss, zs = _hnp_sigs(curve, d, 128, 8)
        body = {"curve": curve, "x": str(Q[0]), "y": str(Q[1]), "r": rs, "s": ss, "z": zs}
        files = {"sigs.json": json.dumps(body).encode()}
        v = solve(q(f"The ECDSA nonces are biased: only 128 bits each ({curve}). Recover the private key d.",
                    "hnp-d", kind="integer"), files)
        check(f"toolkit HNP {curve}: the private scalar d is PLAIN once d*G==Q is proven", v == str(d), v)
        # wrong public key in the delivery -> None (the verification refuses it)
        Qb = cd.ec_mul(d + 1, cv)
        body2 = dict(body, x=str(Qb[0]), y=str(Qb[1]))
        v2 = solve(q(f"The ECDSA nonces are biased: only 128 bits each ({curve}). Recover the private key d.",
                     "hnp-d2", kind="integer"), {"s.json": json.dumps(body2).encode()})
        check(f"toolkit HNP {curve}: a wrong public key -> None", v2 is None)
    # a derived-value question (even with the nonce-bit phrasing) is not answered
    curve = "secp256k1"; cv = cd.CURVES[curve]; n = cv["n"]
    d = RND.randrange(1, n); Q = cd.ec_mul(d, cv)
    rs, ss, zs = _hnp_sigs(curve, d, 128, 8)
    body = {"curve": curve, "x": str(Q[0]), "y": str(Q[1]), "r": rs, "s": ss, "z": zs}
    v3 = solve(q("The nonces are 128 bits. What is the sum of the digits of the private key d?", "hnp-der", kind="integer"),
               {"s.json": json.dumps(body).encode()})
    check("toolkit HNP: a derived-value question (sum of digits) is NOT answered", v3 is None, v3)


def main():
    test_field()
    test_forbidden_attack()
    test_toolkit_gcm()
    test_hnp_primitive()
    test_toolkit_hnp()
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED))
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
