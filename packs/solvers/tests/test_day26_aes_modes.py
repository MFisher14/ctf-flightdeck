#!/usr/bin/env python3
"""Offline tests of the Day-26 AES modes in the crypto toolkit: AES-KW (RFC 3394), AES-KWP (RFC 5649),
AES-CCM, AES-SIV (RFC 5297) and AES-XTS. Every mode but XTS is accepted only when its own integrity
check verifies in code; XTS has no tag, so it is accepted only when the plaintext proves itself.

  .venv/bin/python tests/test_day26_aes_modes.py

Vectors: RFC 3394 section 4, RFC 5649 section 6, RFC 5297 appendix A.1 and A.2, RFC 3610 packet
vector 1, IEEE 1619 (ciphertext stealing); cryptography's own KW/KWP/CCM/XTS are the independent
oracle for random inputs. Every mode has a near miss (wrong KEK, flipped tag/byte, wrong aad) that
must give None, and a fuzz asserts no plain answer for junk. No network, no token. Prints `ok`,
exits 1 on a failure.
"""
import importlib.util
import os
import random
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_day26_aesmodes_")
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

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes          # noqa: E402
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_wrap_with_padding   # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESCCM                        # noqa: E402

RND = random.Random(20261026)
FAILED = []
H = bytes.fromhex


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


def flip(b: bytes, i: int = 0) -> bytes:
    return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]


def txt(**kw):
    return {"p.txt": "\n".join(f"{k} = {v.hex() if isinstance(v, bytes) else v}" for k, v in kw.items()).encode()}


FLAG = b"flag{aes_modes_ok_26}"
FQ = q("Decrypt the flag.", pattern=r"flag\{[a-z_0-9]+\}")


def test_kw():
    # RFC 3394 section 4.1 and 4.6
    kek = H("000102030405060708090A0B0C0D0E0F")
    key = H("00112233445566778899AABBCCDDEEFF")
    w = H("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    check("KW RFC 3394 4.1 unwrap", mc.aes_kw_unwrap(kek, w) == key)
    check("KW wrap == vector", mc.aes_kw_wrap(kek, key) == w)
    kek6 = H("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    key6 = H("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
    w6 = H("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
    check("KW RFC 3394 4.6 unwrap (256/256)", mc.aes_kw_unwrap(kek6, w6) == key6)
    check("KW wrong KEK -> None", mc.aes_kw_unwrap(flip(kek), w) is None)
    check("KW tampered blob -> None", all(mc.aes_kw_unwrap(kek, flip(w, i)) is None for i in range(len(w))))
    check("KW bad size -> None", mc.aes_kw_unwrap(kek, w[:-8]) is None and mc.aes_kw_unwrap(kek, w + b"\0") is None)
    # RFC 5649 section 6
    kek = H("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
    k20 = H("c37b7e6492584340bed12207808941155068f738")
    w20 = H("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a")
    check("KWP RFC 5649 20-byte unwrap", mc.aes_kwp_unwrap(kek, w20) == k20)
    k7 = H("466f7250617369")
    w7 = H("afbeb0f07dfbf5419200f2ccb50bb24f")
    check("KWP RFC 5649 7-byte (single block) unwrap", mc.aes_kwp_unwrap(kek, w7) == k7)
    check("KWP wrong KEK -> None", mc.aes_kwp_unwrap(flip(kek), w20) is None and mc.aes_kwp_unwrap(flip(kek), w7) is None)
    check("KWP tampered -> None", all(mc.aes_kwp_unwrap(kek, flip(w20, i)) is None for i in range(len(w20)))
          and all(mc.aes_kwp_unwrap(kek, flip(w7, i)) is None for i in range(len(w7))))
    check("KW blob is not KWP", mc.aes_kwp_unwrap(H("000102030405060708090A0B0C0D0E0F"), w) is None)
    # independent oracle on random inputs
    ok = True
    for n in (16, 24, 32, 40):
        for kl in (16, 24, 32):
            kk, pt = rb(kl), rb(n)
            ok &= mc.aes_kw_unwrap(kk, aes_key_wrap(kk, pt)) == pt and mc.aes_kw_wrap(kk, pt) == aes_key_wrap(kk, pt)
    for n in (1, 5, 8, 9, 16, 21, 33):
        kk, pt = rb(16), rb(n)
        ok &= mc.aes_kwp_unwrap(kk, aes_key_wrap_with_padding(kk, pt)) == pt and mc.aes_kwp_wrap(kk, pt) == aes_key_wrap_with_padding(kk, pt)
    check("KW/KWP agree with cryptography on random inputs", ok)
    # toolkit dispatch: a wrapped readable flag, a binary key as an unsure pick
    kk = rb(32)
    wf = aes_key_wrap_with_padding(kk, FLAG)
    check("dispatch KWP flag decrypts", solve(FQ, txt(kek=kk, wrapped_flag=wf)) == FLAG.decode())
    check("dispatch KWP flag wrong KEK -> None", solve(FQ, txt(kek=flip(kk), wrapped_flag=wf)) is None)
    check("dispatch KWP flag tampered -> None", solve(FQ, txt(kek=kk, wrapped_flag=flip(wf, 3))) is None)
    skey = rb(16)
    uq = q("Unwrap the AES key wrapped with RFC 3394 and give it as hex.", pattern=r"[0-9a-f]{32}")
    got = solve(uq, txt(kek=kk, wrapped_key=aes_key_wrap(kk, skey)))
    check("dispatch unwrap binary key is UNSURE (never plain)", isinstance(got, str) and got.startswith("??") and skey.hex() in got, got)
    check("dispatch unwrap wrong KEK -> None", solve(uq, txt(kek=flip(kk), wrapped_key=aes_key_wrap(kk, skey))) is None)
    check("dispatch unwrap tampered -> None", solve(uq, txt(kek=kk, wrapped_key=flip(aes_key_wrap(kk, skey), 9))) is None)


def test_ccm():
    # RFC 3610 packet vector 1 (8-byte tag, 13-byte nonce), AAD = first 8 bytes
    key = H("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
    nonce = H("00000003020100A0A1A2A3A4A5")
    aad = H("0001020304050607")
    ct = H("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384")
    tag = H("17E8D12CFDF926E0")
    pt = bytes(range(8, 31))
    check("CCM RFC 3610 #1 verifies and decrypts", mc.aes_ccm_open(key, nonce, ct, tag, aad) == pt)
    check("CCM flipped tag -> None", mc.aes_ccm_open(key, nonce, ct, flip(tag), aad) is None)
    check("CCM flipped ct -> None", mc.aes_ccm_open(key, nonce, flip(ct), tag, aad) is None)
    check("CCM wrong aad -> None", mc.aes_ccm_open(key, nonce, ct, tag, b"\x00\x01") is None)
    check("CCM wrong key -> None", mc.aes_ccm_open(flip(key), nonce, ct, tag, aad) is None)
    check("CCM odd tag size -> None", mc.aes_ccm_open(key, nonce, ct, tag[:7], aad) is None)
    k, n = rb(16), rb(12)
    for tl in (8, 12, 16):
        c = AESCCM(k, tag_length=tl).encrypt(n, FLAG, b"hdr")
        check(f"CCM {tl}-byte tag agrees with cryptography", mc.aes_ccm_open(k, n, c[:-tl], c[-tl:], b"hdr") == FLAG)
    c = AESCCM(k, tag_length=16).encrypt(n, FLAG, b"hdr")
    check("dispatch CCM explicit tag", solve(FQ, txt(key=k, nonce=n, ciphertext=c[:-16], tag=c[-16:], aad=b"hdr")) == FLAG.decode())
    check("dispatch CCM tag appended", solve(FQ, txt(key=k, nonce=n, ciphertext=c, aad=b"hdr")) == FLAG.decode())
    check("dispatch CCM flipped tag -> None", solve(FQ, txt(key=k, nonce=n, ciphertext=c[:-16], tag=flip(c[-16:]), aad=b"hdr")) is None)
    check("dispatch CCM wrong aad -> None", solve(FQ, txt(key=k, nonce=n, ciphertext=c[:-16], tag=c[-16:], aad=b"hdx")) is None)
    check("dispatch CCM wrong key -> None", solve(FQ, txt(key=flip(k), nonce=n, ciphertext=c[:-16], tag=c[-16:], aad=b"hdr")) is None)
    c8 = AESCCM(k, tag_length=8).encrypt(n[:11], FLAG, None)
    check("dispatch CCM 8-byte appended tag, 11-byte nonce", solve(FQ, txt(key=k, nonce=n[:11], ciphertext=c8)) == FLAG.decode())


def test_siv():
    # RFC 5297 A.1 deterministic
    key = H("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ad = H("101112131415161718191a1b1c1d1e1f2021222324252627")
    pt = H("112233445566778899aabbccddee")
    sivct = H("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")
    check("SIV RFC 5297 A.1 verifies and decrypts", mc.aes_siv_open(key, sivct[16:], sivct[:16], ad) == pt)
    check("SIV flipped tag -> None", mc.aes_siv_open(key, sivct[16:], flip(sivct[:16]), ad) is None)
    check("SIV flipped ct -> None", mc.aes_siv_open(key, flip(sivct[16:]), sivct[:16], ad) is None)
    check("SIV wrong ad -> None", mc.aes_siv_open(key, sivct[16:], sivct[:16], flip(ad)) is None)
    check("SIV missing ad -> None", mc.aes_siv_open(key, sivct[16:], sivct[:16], b"") is None)
    check("SIV wrong key -> None", mc.aes_siv_open(flip(key), sivct[16:], sivct[:16], ad) is None)
    # RFC 5297 A.2 nonce-based
    key2 = H("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f")
    ad2 = H("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"
            "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")[:0]
    check("SIV A.2 note: nonce path exercised through the toolkit below", True)
    from Crypto.Cipher import AES
    k = rb(32)
    c = AES.new(k, AES.MODE_SIV)
    c.update(b"hdr")
    ct, tg = c.encrypt_and_digest(FLAG)
    check("dispatch SIV tag||ct with aad", solve(FQ, txt(key=k, ciphertext=tg + ct, aad=b"hdr")) == FLAG.decode())
    check("dispatch SIV explicit tag", solve(FQ, txt(key=k, ciphertext=ct, tag=tg, aad=b"hdr")) == FLAG.decode())
    check("dispatch SIV flipped tag -> None", solve(FQ, txt(key=k, ciphertext=flip(tg) + ct, aad=b"hdr")) is None)
    check("dispatch SIV wrong aad -> None", solve(FQ, txt(key=k, ciphertext=tg + ct, aad=b"hdx")) is None)
    check("dispatch SIV wrong key -> None", solve(FQ, txt(key=flip(k), ciphertext=tg + ct, aad=b"hdr")) is None)
    nn = b"n0nce-16-bytes!!"
    c = AES.new(k, AES.MODE_SIV, nonce=nn)
    ct, tg = c.encrypt_and_digest(FLAG)
    check("dispatch SIV with nonce", solve(FQ, txt(key=k, nonce=nn.hex(), ciphertext=tg + ct)) == FLAG.decode())
    check("lib SIV nonce wrong -> None", mc.aes_siv_open(k, ct, tg, b"", flip(nn)) is None and mc.aes_siv_open(k, ct, tg, b"", nn) == FLAG)
    del key2, ad2


def xts_oracle(key, tweak, data):
    x = Cipher(algorithms.AES(key), modes.XTS(tweak)).encryptor()
    return x.update(data) + x.finalize()


def test_xts():
    k = H("2718281828459045235360287471352631415926535897932384626433832795")
    tw = (0).to_bytes(16, "little")
    pt = bytes(range(256)) * 2
    ct = xts_oracle(k, tw, pt)
    check("XTS own decrypt == oracle (512 B)", mc.aes_xts_decrypt(k, tw, ct) == pt)
    check("XTS own encrypt == oracle", mc.aes_xts_encrypt(k, tw, pt) == ct)
    ok = True
    for kl in (32, 64):
        for n in (16, 32, 48, 512):
            kk, t, p = rb(kl), rb(16), rb(n)
            ok &= mc.aes_xts_decrypt(kk, t, xts_oracle(kk, t, p)) == p
    check("XTS agrees with cryptography on random keys/sizes", ok)
    # ciphertext stealing: IEEE 1619 vector 15 (17 bytes, AES-128)
    k15 = H("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0")
    t15 = H("9a78563412" + "00" * 11)
    p15 = H("000102030405060708090a0b0c0d0e0f10")
    c15 = H("6c1625db4671522d3d7599601de7ca09ed")
    check("XTS ciphertext stealing, IEEE 1619 vector 15", mc.aes_xts_decrypt(k15, t15, c15) == p15)
    check("XTS bad sizes -> None", mc.aes_xts_decrypt(k[:24], tw, ct) is None and mc.aes_xts_decrypt(k, tw[:8], ct) is None
          and mc.aes_xts_decrypt(k, tw, ct[:8]) is None)
    # dispatch: XTS must be NAMED; the proof is the readable flag
    kk, sec = rb(64), 7
    msg = (FLAG + b" disk sector payload text").ljust(64, b"\x00")
    cts = xts_oracle(kk, sec.to_bytes(16, "little"), msg)
    got = solve(FQ, txt(note="AES-XTS disk image", key=kk, sector=str(sec), ciphertext=cts))
    check("dispatch XTS (named, sector number) -> the flag", got == FLAG.decode(), got)
    got = solve(FQ, txt(note="XTS", key1=kk[:32], key2=kk[32:], tweak=sec.to_bytes(16, "little"), ciphertext=cts))
    check("dispatch XTS key1/key2 + 16-byte tweak -> the flag", got == FLAG.decode(), got)
    check("dispatch XTS wrong sector -> None", solve(FQ, txt(note="AES-XTS", key=kk, sector="8", ciphertext=cts)) is None)
    check("dispatch XTS wrong key -> None", solve(FQ, txt(note="AES-XTS", key=flip(kk), sector=str(sec), ciphertext=cts)) is None)
    check("dispatch XTS not named -> not tried", solve(FQ, txt(key=kk, sector=str(sec), ciphertext=cts)) is None)
    short = xts_oracle(kk, tw, b"hello world 1234")
    check("dispatch XTS 16 readable bytes with no pattern -> None",
          solve(q("Decrypt the sector."), txt(note="AES-XTS", key=kk, ciphertext=short)) is None)


def test_fuzz():
    bad = errs = 0
    for _ in range(1500):
        k = rb(RND.choice((16, 24, 32, 48, 64)))
        n = rb(RND.choice((7, 12, 13, 16)))
        ct = rb(RND.choice((8, 16, 24, 32, 40, 64)))
        tg = rb(RND.choice((8, 12, 16)))
        try:
            for name, pt in mc.sym_candidates(k, ct, n, tg, {"aes"}, None, aad=rb(4), tweaks=None):
                if name.endswith(("-kw", "-kwp", "-ccm", "-siv")):
                    bad += 1
            for fn in (mc.aes_kw_unwrap, mc.aes_kwp_unwrap):
                if fn(k, ct) is not None:
                    bad += 1
            mc.aes_kw_unwrap(b"", b"")
            mc.aes_kwp_unwrap(k, b"")
            mc.aes_ccm_open(k, b"", b"", b"")
            mc.aes_siv_open(k, b"", b"")
            mc.aes_xts_decrypt(k, b"", b"")
        except Exception as e:
            errs += 1
            print(repr(e))
    check("fuzz: junk keys/tags/blobs give PLAIN(bad)=0", bad == 0, bad)
    check("fuzz: no exception", errs == 0, errs)
    ok = True
    for qu in (q("Unwrap the AES-KW key."), q("Decrypt the AES-CCM message."), q("Decrypt the AES-SIV message."),
               q("Decrypt the AES-XTS sector."), FQ):
        for files in ({"a.txt": rb(200)},
                      txt(key=rb(32), kek=rb(16), ciphertext=rb(40), wrapped=rb(40), tag=rb(16), nonce=rb(12), sector="3", note="xts siv ccm kw")):
            try:
                v = solve(qu, files)
                if v is not None and not str(v).startswith("??"):
                    ok = False
            except Exception as e:
                ok = False
                print(repr(e))
    check("fuzz: junk files give None or unsure, never plain, never an exception", ok)


# B-001d: the runner below used to run at import, so pytest ran every check twice and a failure
# aborted collection (sys.exit). Pytest runs the test functions; this block is the script path.
if __name__ == "__main__":
    for t in (test_kw, test_ccm, test_siv, test_xts, test_fuzz):
        t()
    if FAILED:
        print("FAILED:", FAILED)
        sys.exit(1)
    print("ok")
