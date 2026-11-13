#!/usr/bin/env python3
"""Offline tests of the Day-26 crypto depth hardening: (1) a base64 modulus or ciphertext on a labelled
line (`c = <base64>`, `ciphertext = <base64>`) reads like the same bytes hex- or decimal-wrapped, and feeds
the existing verified RSA path (the plaintext only emerges after the path's own factor/decrypt checks);
(2) the keyless repeating-key XOR break stays an UNSURE candidate (never plain) and gives nothing for
random or non-English bytes.

  .venv/bin/python tests/test_day26_crypto_depth.py

No network, no token. Prints `ok`, exits 1 on a failure.
"""
import importlib.util
import os
import random
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_day26_depth_")
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


import base64  # noqa: E402

sys.path.insert(0, str(REPO / "tests"))
import loadclock  # noqa: E402  (tests/loadclock.py)

from Crypto.Util.number import getPrime, isPrime  # noqa: E402

RND = random.Random(20261026)
FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)


def q(question, aid="m", kind="exact_text"):
    return {"id": aid, "qid": aid, "answer_id": aid, "question": question, "answer_format": {"kind": kind}}


def solve(question, files):
    """The toolkit's answer, its budgets (BUDGET, the keyless XOR break's deadline) counted in CPU seconds
    (tests/loadclock.cpu_clock): on a loaded machine the wall-clock 0.8 s ran out before the break's
    first key length (about 0.05 s of CPU) and the key was not offered (SH-10). Work over the budget
    still runs it out."""
    with loadclock.cpu_clock():
        return tk.solve_set([question], files, {})[question["qid"]]


def bl(x):
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def rsa_close():
    p = getPrime(512)
    r = p + 2
    while not isPrime(r):
        r += 2
    return p * r


def test_b64_rsa():
    n = rsa_close()
    text = b"flag{b64_rsa_ok}"
    c = pow(int.from_bytes(text, "big"), 65537, n)
    Q = q("Decrypt the RSA message. What is the plaintext flag?")
    answers = {}
    for form, f in (("hex", hex), ("dec", str), ("b64", lambda x: base64.b64encode(bl(x)).decode()),
                    ("b64url", lambda x: base64.urlsafe_b64encode(bl(x)).decode().rstrip("="))):
        for lab in ("c", "ciphertext"):
            got = solve(Q, {"p.txt": f"n = {f(n)}\ne = 65537\n{lab} = {f(c)}\n".encode()})
            answers[(form, lab)] = got
            check(f"{form} {lab}: solved, text offered", isinstance(got, str) and text.decode() in got, got)
    check("b64 gives the very same answer as hex", answers[("b64", "c")] == answers[("hex", "c")]
          and answers[("b64", "ciphertext")] == answers[("hex", "ciphertext")])
    # near misses: a flipped bit in the base64 ciphertext, or a ciphertext of another modulus, is never plain
    bad = bytearray(bl(c)); bad[5] ^= 1
    for cc in (base64.b64encode(bytes(bad)).decode(), base64.b64encode(bl(pow(7, 65537, rsa_close()))).decode()):
        got = solve(Q, {"p.txt": f"n = {base64.b64encode(bl(n)).decode()}\ne = 65537\nc = {cc}\n".encode()})
        check("near miss: wrong base64 ciphertext is not the plaintext", got is None or text.decode() not in str(got), got)
    # hard modulus (random primes): nothing is proven
    n2 = getPrime(512) * getPrime(512)
    c2 = pow(int.from_bytes(text, "big"), 65537, n2)
    got = solve(Q, {"p.txt": f"n = {base64.b64encode(bl(n2)).decode()}\ne = 65537\nc = {base64.b64encode(bl(c2)).decode()}\n".encode()})
    check("hard modulus in base64: None", got is None, got)
    # the reader itself: hex-only and short runs keep their old reading
    P = mc.read_params("n = deadbeefdeadbeefdeadbeefdeadbeef\nc = 12345678901234567890123456789012\n")
    check("a hex-only or decimal run keeps its old reading", P.one("n") == int("deadbeefdeadbeefdeadbeefdeadbeef", 16)
          and P.one("c") == 12345678901234567890123456789012, dict(P))
    P = mc.read_params("e = Zm9vYmFyYmF6cXV4cXV1eHF1dXg=\nk = Zm9vYmFyYmF6cXV4cXV1eHF1dXg=\n")
    check("only the labels n and c take base64", "e" not in P and "k" not in P, dict(P))


ENG = (b"It was a bright cold day in April, and the clocks were striking thirteen. Winston Smith, his chin "
       b"nuzzled into his breast in an effort to escape the vile wind, slipped quickly through the glass doors "
       b"of Victory Mansions, though not quickly enough to prevent a swirl of gritty dust from entering along "
       b"with him. The hallway smelt of boiled cabbage and old rag mats. At one end of it a coloured poster, "
       b"too large for indoor display, had been tacked to the wall. ")


def rx(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def test_keyless_xor():
    Q = q("The file is repeating-key XOR encrypted. What is the XOR key?")
    key = b"Terminator"
    got = solve(Q, {"c.bin": rx(ENG * 2, key)})
    check("keyless repeating-XOR on English: the key is offered, never plain",
          isinstance(got, str) and got.startswith("??") and "Terminator" in got, got)
    QP = q("The message was XOR encrypted with a repeating key. What is the plaintext?")
    got = solve(QP, {"c.bin": rx(ENG * 2, key)})
    check("keyless plaintext: unsure, never plain", got is None or str(got).startswith("??"), got)
    bad = 0
    for i in range(300):
        blob = bytes(RND.getrandbits(8) for _ in range(RND.choice((64, 300, 1000, 4000))))
        for qq in (Q, QP):
            v = solve(qq, {"x.bin": blob})
            if v is not None and not str(v).startswith("??"):
                bad += 1
    check("fuzz: random blobs give PLAIN(bad)=0", bad == 0, bad)
    bad = 0
    for i in range(60):
        junk = bytes(RND.choice(b"abcdefghij 0123456789") for _ in range(600))
        v = solve(Q, {"x.bin": rx(junk, bytes(RND.getrandbits(8) for _ in range(RND.randint(3, 12))))})
        if v is not None and not str(v).startswith("??"):
            bad += 1
    check("fuzz: non-English XORed text gives PLAIN(bad)=0", bad == 0, bad)


# B-001d: the runner below used to run at import, so pytest ran every check twice and a failure
# aborted collection (sys.exit). Pytest runs the test functions; this block is the script path.
if __name__ == "__main__":
    for t in (test_b64_rsa, test_keyless_xor):
        t()
    if FAILED:
        print("FAILED:", FAILED)
        sys.exit(1)
    print("ok")
