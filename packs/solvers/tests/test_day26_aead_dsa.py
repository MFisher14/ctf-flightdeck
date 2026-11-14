#!/usr/bin/env python3
"""Offline tests of the Day-26 crypto coverage (oracle-audit row 5): ChaCha20-Poly1305 and
XChaCha20-Poly1305 AEAD (the plaintext only when the Poly1305 tag verifies), Salsa20 (stream, named
only), and finite-field DSA reused-nonce key recovery (x only when g^x == y).

  .venv/bin/python tests/test_day26_aead_dsa.py

Vectors: RFC 8439 sections 2.5.2 and 2.8.2, the XChaCha20-Poly1305 draft's A.3.1 vector, and
cryptography's own ChaCha20Poly1305 as an independent oracle. Every attack has a near miss (flipped
tag, wrong aad, wrong key, unrelated signatures, wrong y) that must give None, and a fuzz at the end
asserts no plain answer for junk. No network, no token. Prints `ok` and exits 1 on a failure.
"""
import hashlib
import importlib.util
import json
import os
import random
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_day26_aead_")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "common"))

spec = importlib.util.spec_from_file_location("tk_modern_crypto", REPO / "solvers" / "toolkits" / "modern_crypto.py")
tk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tk)
mc = tk.lib

from Crypto.Util.number import getPrime, isPrime              # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305   # noqa: E402

RND = random.Random(20261025)
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


def solve(question, files):
    return tk.solve_set([question], files, {})[question["qid"]]


def rb(n):
    return bytes(RND.getrandbits(8) for _ in range(n))


def flip(b: bytes) -> bytes:
    return bytes([b[0] ^ 1]) + b[1:]


# ---- Poly1305 and ChaCha20-Poly1305 vectors ---------------------------------------------------------------

def test_vectors():
    # RFC 8439 2.5.2
    key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    tag = mc.poly1305_mac(key, b"Cryptographic Forum Research Group")
    check("Poly1305 RFC 8439 2.5.2", tag.hex() == "a8061dc1305136c6c22b8baf0c0127a9")
    # RFC 8439 2.8.2
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
          b"sunscreen would be it.")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    k = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    ct = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116")
    tg = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
    check("RFC 8439 2.8.2 decrypts", mc.chacha_poly_open(k, nonce, ct, tg, aad) == pt)
    check("RFC 8439 2.8.2 flipped tag -> None", mc.chacha_poly_open(k, nonce, ct, flip(tg), aad) is None)
    check("RFC 8439 2.8.2 last tag bit flipped -> None", mc.chacha_poly_open(k, nonce, ct, tg[:-1] + bytes([tg[-1] ^ 0x80]), aad) is None)
    check("RFC 8439 2.8.2 wrong aad -> None", mc.chacha_poly_open(k, nonce, ct, tg, aad + b"x") is None)
    check("RFC 8439 2.8.2 flipped ciphertext -> None", mc.chacha_poly_open(k, nonce, flip(ct), tg, aad) is None)
    check("RFC 8439 2.8.2 wrong key -> None", mc.chacha_poly_open(flip(k), nonce, ct, tg, aad) is None)
    check("RFC 8439 2.8.2 wrong nonce -> None", mc.chacha_poly_open(k, flip(nonce), ct, tg, aad) is None)
    check("bad sizes -> None", mc.chacha_poly_open(k[:31], nonce, ct, tg, aad) is None
          and mc.chacha_poly_open(k, nonce[:11], ct, tg, aad) is None and mc.chacha_poly_open(k, nonce, ct, tg[:15], aad) is None)
    # XChaCha20-Poly1305, draft-irtf-cfrg-xchacha A.3.1
    xk = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    xn = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    xaad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    xpt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
           b"sunscreen would be it.")
    xct = bytes.fromhex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39"
        "ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e")
    xtag = bytes.fromhex("c0875924c1c7987947deafd8780acf49")
    check("XChaCha20-Poly1305 draft A.3.1 decrypts", mc.chacha_poly_open(xk, xn, xct, xtag, xaad) == xpt)
    check("XChaCha20-Poly1305 flipped tag -> None", mc.chacha_poly_open(xk, xn, xct, flip(xtag), xaad) is None)
    # an independent oracle: cryptography's ChaCha20Poly1305 on random inputs
    ok = True
    for _ in range(40):
        kk, nn, ad, m = rb(32), rb(12), rb(RND.randint(0, 40)), rb(RND.randint(0, 150))
        sealed = ChaCha20Poly1305(kk).encrypt(nn, m, ad or None)
        c, t = sealed[:-16], sealed[-16:]
        if mc.chacha_poly_open(kk, nn, c, t, ad) != m or mc.chacha_poly_open(kk, nn, c, flip(t), ad) is not None:
            ok = False
            break
    check("40 random messages agree with cryptography's ChaCha20Poly1305, flipped tag None", ok)


# ---- the toolkit's auto dispatch --------------------------------------------------------------------------

def test_dispatch():
    key, nonce, aad = rb(32), rb(12), b"header-v1"
    msg = b"flag{chacha_poly_tag_verified_ok}"
    sealed = ChaCha20Poly1305(key).encrypt(nonce, msg, aad)
    ct, tag = sealed[:-16], sealed[-16:]
    quest = q("The message is encrypted with ChaCha20-Poly1305. Decrypt it and give the flag.", pattern=r"flag\{[a-z_]+\}")

    def files(tag_, aad_=aad):
        t = (f"key = {key.hex()}\nnonce = {nonce.hex()}\naad = {aad_.hex()}\nciphertext = {ct.hex()}\ntag = {tag_.hex()}\n").encode()
        return {"params.txt": t}

    got = solve(quest, files(tag))
    check("dispatch: ChaCha20-Poly1305 valid (key, nonce, aad, ct, tag) decrypts to the flag", got == msg.decode(), got)
    check("dispatch: flipped tag -> None", solve(quest, files(flip(tag))) is None)
    check("dispatch: wrong aad -> None", solve(quest, files(tag, b"header-v2")) is None)
    # tag appended to the ciphertext, no tag field
    t2 = f"key = {key.hex()}\nnonce = {nonce.hex()}\naad = {aad.hex()}\nciphertext = {sealed.hex()}\n".encode()
    check("dispatch: tag appended to the ciphertext decrypts", solve(quest, {"p.txt": t2}) == msg.decode())
    t3 = f"key = {key.hex()}\nnonce = {nonce.hex()}\naad = {aad.hex()}\nciphertext = {flip(sealed).hex()}\n".encode()
    check("dispatch: appended-tag ciphertext with a flipped byte -> None", solve(quest, {"p.txt": t3}) is None)
    # XChaCha: pycryptodome seals with a 24-byte nonce
    from Crypto.Cipher import ChaCha20_Poly1305
    xn = rb(24)
    c = ChaCha20_Poly1305.new(key=key, nonce=xn)
    c.update(aad)
    xct, xtag = c.encrypt_and_digest(msg)
    xq = q("The service uses XChaCha20-Poly1305. Decrypt the message for the flag.", pattern=r"flag\{[a-z_]+\}")
    xf = lambda tg: {"p.txt": (f"key = {key.hex()}\nnonce = {xn.hex()}\naad = {aad.hex()}\nciphertext = {xct.hex()}\ntag = {tg.hex()}\n").encode()}
    check("dispatch: XChaCha20-Poly1305 valid decrypts", solve(xq, xf(xtag)) == msg.decode())
    check("dispatch: XChaCha20-Poly1305 flipped tag -> None", solve(xq, xf(flip(xtag))) is None)
    # Salsa20 named by the artifact: a stream, the readable-text proof only
    from Crypto.Cipher import Salsa20
    sn = rb(8)
    sct = Salsa20.new(key=key, nonce=sn).encrypt(msg)
    sq = q("The flag was encrypted with Salsa20. Decrypt it.", pattern=r"flag\{[a-z_]+\}")
    check("dispatch: Salsa20 with a stated key and nonce decrypts",
          solve(sq, {"p.txt": f"key = {key.hex()}\nnonce = {sn.hex()}\nciphertext = {sct.hex()}\n".encode()}) == msg.decode())
    check("dispatch: Salsa20 wrong key -> None",
          solve(sq, {"p.txt": f"key = {flip(key).hex()}\nnonce = {sn.hex()}\nciphertext = {sct.hex()}\n".encode()}) is None)


# ---- DSA reused nonce -------------------------------------------------------------------------------------

def dsa_domain():
    qq = getPrime(160, randfunc=RND.randbytes)
    while True:
        kk = RND.getrandbits(352) | (1 << 351)
        pp = kk * qq + 1
        if pp.bit_length() == 512 and isPrime(pp):
            break
    while True:
        h = RND.randrange(2, pp - 1)
        g = pow(h, (pp - 1) // qq, pp)
        if g > 1:
            return pp, qq, g


def dsa_sign(pp, qq, g, x, z, k):
    r = pow(g, k, pp) % qq
    return r, pow(k, -1, qq) * (z + x * r) % qq


def zof(m: bytes, qq):
    dg = hashlib.sha256(m).digest()
    return int.from_bytes(dg, "big") >> max(0, 256 - qq.bit_length())


def test_dsa():
    pp, qq, g = dsa_domain()
    x = RND.randrange(2, qq)
    y = pow(g, x, pp)
    k = RND.randrange(2, qq)
    m1, m2 = b"alpha", b"bravo"
    z1, z2 = zof(m1, qq), zof(m2, qq)
    r, s1 = dsa_sign(pp, qq, g, x, z1, k)
    _, s2 = dsa_sign(pp, qq, g, x, z2, k)
    check("lib.dsa_nonce_reuse recovers x, g^x == y", mc.dsa_nonce_reuse(pp, qq, g, y, (r, s1, z1), (r, s2, z2)) == x)
    check("lib: wrong public key -> None", mc.dsa_nonce_reuse(pp, qq, g, pow(g, x + 1, pp), (r, s1, z1), (r, s2, z2)) is None)
    check("lib: wrong hash -> None", mc.dsa_nonce_reuse(pp, qq, g, y, (r, s1, z1 + 1), (r, s2, z2)) is None)
    k3 = RND.randrange(2, qq)
    r3, s3 = dsa_sign(pp, qq, g, x, z2, k3)
    check("lib: different nonces under one claimed r -> None", mc.dsa_nonce_reuse(pp, qq, g, y, (r, s1, z1), (r, s3, z2)) is None)
    check("lib: g of the wrong order -> None", mc.dsa_nonce_reuse(pp, qq, 2 if pow(2, qq, pp) != 1 else 3, y, (r, s1, z1), (r, s2, z2)) is None)
    check("lib: identical signatures -> None", mc.dsa_nonce_reuse(pp, qq, g, y, (r, s1, z1), (r, s1, z1)) is None)

    quest = q("Two DSA signatures were made with the same nonce. Recover the DSA private key x.", kind="integer")

    def files(sigs, yy=y):
        d = {"p": str(pp), "q": str(qq), "g": str(g), "y": str(yy), "r": [str(sg[0]) for sg in sigs], "s": [str(sg[1]) for sg in sigs]}
        t = f"p = {pp}\nq = {qq}\ng = {g}\ny = {yy}\n"
        for i, (rr, ss) in enumerate(sigs, 1):
            t += f"r{i} = {rr}\ns{i} = {ss}\nmsg{i} = {[m1, m2][i - 1].decode()}\n"
        return {"sigs.txt": t.encode()}

    got = solve(quest, files([(r, s1), (r, s2)]))
    check("dispatch: DSA reused nonce -> x (plain, kind integer), g^x == y", got == str(x), got)
    check("dispatch: DSA with the wrong y -> None", solve(quest, files([(r, s1), (r, s2)], pow(g, x + 1, pp))) is None)
    check("dispatch: DSA sigs that do not share k -> None", solve(quest, files([(r, s1), (r3, s3)])) is None)


# ---- fuzz -------------------------------------------------------------------------------------------------

def test_fuzz():
    bad = 0
    errs = 0
    for _ in range(300):
        kk, nn, ct, tg, ad = rb(32), rb(RND.choice((12, 24))), rb(RND.randint(0, 80)), rb(16), rb(RND.randint(0, 20))
        try:
            if mc.chacha_poly_open(kk, nn, ct, tg, ad) is not None:
                bad += 1
            for name, pt in mc.sym_candidates(kk, ct, nn, tg, {"chacha20"}, None, aad=ad):
                if "poly1305" in name:
                    bad += 1
        except Exception:
            errs += 1
    pp, qq, g = dsa_domain()
    y = pow(g, RND.randrange(2, qq), pp)
    for _ in range(300):
        sg = lambda: (RND.randrange(1, qq), RND.randrange(1, qq), RND.getrandbits(160))
        a, b = sg(), sg()
        b = (a[0], b[1], b[2])
        try:
            if mc.dsa_nonce_reuse(pp, qq, g, y, a, b) is not None:
                bad += 1
            mc.dsa_nonce_reuse(0, 0, 0, 0, (0, 0, 0), (0, 0, 0))
            mc.dsa_nonce_reuse(pp, qq, g, y, ("x", 1, 2), None)
        except Exception:
            errs += 1
    check("fuzz: wrong tags and unrelated signatures give PLAIN(bad)=0", bad == 0, bad)
    check("fuzz: no exception", errs == 0, errs)
    junk = [q("Decrypt the ChaCha20-Poly1305 message."), q("Recover the DSA private key from the reused nonce.", kind="integer")]
    ok = True
    for qu in junk:
        for files in ({"a.txt": rb(200)}, {"a.txt": b"key = " + rb(16).hex().encode() + b"\ntag = " + rb(16).hex().encode()}):
            try:
                v = solve(qu, files)
                if v is not None and not str(v).startswith("??"):
                    ok = False
            except Exception as e:
                ok = False
                print(e)
    check("fuzz: junk files give None or unsure, never plain, never an exception", ok)


# B-001d: the runner below used to run at import, so pytest ran every check twice and a failure
# aborted collection (sys.exit). Pytest runs the test functions; this block is the script path.
if __name__ == "__main__":
    for t in (test_vectors, test_dispatch, test_dsa, test_fuzz):
        t()
    if FAILED:
        print("FAILED:", FAILED)
        sys.exit(1)
    print("ok")
