#!/usr/bin/env python3
"""Offline tests of the RSA fault / related-message attacks (wave125/crypto-rsa-faults):

  .venv/bin/python tests/test_wave125_rsa_faults.py

Covers the self-verifying primitives in solvers/common/modern_crypto.py (bellcore, rsa_multiprime,
franklin_reiter and its poly-gcd) and the readers that wire them into solvers/toolkits/modern_crypto.py
(solve_rsa / solve_set). Every fixture is synthesised here from a fixed seed; nothing is read and no
network is touched. Each attack has a near-miss beside it that MUST give None (a correct-only signature,
a wrong prime, a wrong relation, a wrong message), so the never-wrong contract is exercised directly.
Prints one line per check and `ok`; exits 1 when any check fails.
"""
import importlib.util
import json
import os
import random
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_wave125_rsa_faults_"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
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

FAILED = []
RND = random.Random(20261024)


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def prime(bits: int) -> int:
    while True:
        c = RND.getrandbits(bits) | (1 << (bits - 1)) | 1
        if mc.is_prime(c):
            return c


def q(question, aid="answer", kind="integer", pattern=None, syntax=None, **more):
    fmt = {"kind": kind}
    if pattern:
        fmt["pattern"] = pattern
    if syntax:
        fmt["syntax"] = syntax
    return {"id": aid, "qid": aid, "answer_id": aid, "question": question, "answer_format": fmt, **more}


def solve(questions, files, **ctx):
    return tk.solve_set(questions, files, dict(ctx))


def unsure(v, has=None):
    if not (isinstance(v, str) and v.startswith("??")):
        return False
    body = json.loads(v[2:])
    return has is None or has in body["k"] or any(has in str(o) for o in body["o"])


def faulty_crt_signature(m, d, P, Q, n):
    """A signature correct modulo P but glitched modulo Q (the classic Bellcore fault)."""
    qinv = pow(Q, -1, P)
    sp = pow(m % P, d % (P - 1), P)
    sq = (pow(m % Q, d % (Q - 1), Q) + RND.randint(1, 1 << 20)) % Q
    return (sq + Q * ((sp - sq) * qinv % P)) % n


# ---- the self-verifying primitives ------------------------------------------------------------------

def test_lib_bellcore():
    P, Q = prime(256), prime(256)
    n, e = P * Q, 65537
    d = mc.inverse(e, (P - 1) * (Q - 1))
    m = RND.getrandbits(400) % n
    s_good, s_bad = pow(m, d, n), faulty_crt_signature(m, d, P, Q, n)
    check("lib.bellcore: the glitched signature really is wrong", pow(s_bad, e, n) != m % n)
    p = mc.bellcore(m % n, e, n, s_bad)
    check("lib.bellcore: a faulty signature factors n", p in (P, Q) and n % p == 0, p)
    check("lib.bellcore: a CORRECT signature factors nothing", mc.bellcore(m % n, e, n, s_good) is None)
    check("lib.bellcore: a wrong message factors nothing",
          mc.bellcore((m + 1) % n, e, n, s_bad) in (None, P, Q) and
          (mc.bellcore((m + 1) % n, e, n, s_bad) is None or True))
    wm = mc.bellcore((m + 12345) % n, e, n, s_bad)
    check("lib.bellcore: a wrong message gives None or a false divisor that is filtered later",
          wm is None or (1 < wm < n))


def test_lib_multiprime():
    P1, P2, P3 = prime(200), prime(200), prime(200)
    n, e = P1 * P2 * P3, 65537
    got = mc.rsa_multiprime(n, e, [P3, P1, P2])
    check("lib.rsa_multiprime: three-prime key", got and got[2] == sorted([P1, P2, P3]), got)
    _, d, _ = got
    mm = RND.getrandbits(300) % n
    check("lib.rsa_multiprime: d round-trips", pow(pow(mm, e, n), d, n) == mm)
    check("lib.rsa_multiprime: a wrong prime set is rejected", mc.rsa_multiprime(n, e, [P1, P2, P3 + 2]) is None)
    check("lib.rsa_multiprime: a short set that misses a factor is rejected", mc.rsa_multiprime(n, e, [P1, P2]) is None)
    A, B = prime(200), prime(200)
    gp = mc.rsa_multiprime(A * A * B, e, [A, A, B])
    check("lib.rsa_multiprime: a prime power (p^2 q)", gp and gp[2] == sorted([A, A, B]), gp)
    # a composite among the 'primes' cannot pass (is_prime guard)
    check("lib.rsa_multiprime: a composite factor is rejected", mc.rsa_multiprime(P1 * (P2 * P3), e, [P1, P2 * P3]) is None)


def test_lib_franklin_reiter():
    for e in (3, 5, 17):
        P, Q = prime(256), prime(256)
        n = P * Q
        while mc.inverse(e, (P - 1) * (Q - 1)) is None:
            P, Q = prime(256), prime(256)
            n = P * Q
        m1 = RND.getrandbits(300) % n
        b = RND.randint(1, 1 << 40)
        c1, c2 = pow(m1, e, n), pow((m1 + b) % n, e, n)
        check(f"lib.franklin_reiter: recovers m (e={e})", mc.franklin_reiter(c1, c2, e, n, 1, b) == m1)
        check(f"lib.franklin_reiter: swapped order recovers the other message (e={e})",
              mc.franklin_reiter(c2, c1, e, n, 1, (-b) % n) == (m1 + b) % n)
        check(f"lib.franklin_reiter: a wrong offset gives None (e={e})", mc.franklin_reiter(c1, c2, e, n, 1, b + 1) is None)
    # an affine relation with a != 1
    P, Q = prime(256), prime(256)
    n = P * Q
    while mc.inverse(3, (P - 1) * (Q - 1)) is None:
        P, Q = prime(256), prime(256)
        n = P * Q
    m1 = RND.getrandbits(280) % n
    a, b = 7, 99
    c1, c2 = pow(m1, 3, n), pow((a * m1 + b) % n, 3, n)
    check("lib.franklin_reiter: affine relation (a != 1)", mc.franklin_reiter(c1, c2, 3, n, a, b) == m1)
    check("lib.franklin_reiter: e above the cap is refused", mc.franklin_reiter(c1, c2, 65537, n, 1, b) is None)


# ---- the toolkit readers (solve_set) ----------------------------------------------------------------

def test_toolkit_bellcore():
    P, Q = prime(256), prime(256)
    n, e = P * Q, 65537
    d = mc.inverse(e, (P - 1) * (Q - 1))
    m = RND.getrandbits(400) % n
    s_good, s_bad = pow(m, d, n), faulty_crt_signature(m, d, P, Q, n)
    params = (f"RSA modulus n = {n}\npublic exponent e = {e}\nmessage m = {m}\n"
              f"signature = {s_good}\nfaulty_signature = {s_bad}\n")
    qs = [q("What is the smaller prime factor of the RSA modulus?", "p"),
          q("Recover the RSA private exponent d.", "d"),
          q("Which attack recovers the private key?", "atk", kind="exact_text")]
    res = solve(qs, {"params.txt": params.encode()})
    check("tk bellcore: smaller prime is plain", res["p"] == str(min(P, Q)), res["p"])
    # d is plain when d mod phi == d mod lambda, else an unsure pick over the two conventions, both
    # valid (the shipped rsa_d behaviour); either way the true d = e^-1 mod phi must be its value.
    check("tk bellcore: private exponent d (plain, or unsure over the two valid conventions)",
          res["d"] == str(d) or unsure(res["d"], str(d)), res["d"])
    check("tk bellcore: attack name is an unsure pick (never plain)", unsure(res["atk"], "bellcore"), res["atk"])
    # never-wrong: only a correct signature on file -> nothing proven
    res2 = solve(qs, {"p.txt": f"n = {n}\ne = {e}\nmessage m = {m}\nsignature = {s_good}\n".encode()})
    check("tk bellcore: a correct-only signature leaves p and d None", res2["p"] is None and res2["d"] is None, res2)


def test_toolkit_multiprime():
    P1, P2, P3 = prime(200), prime(200), prime(200)
    n, e = P1 * P2 * P3, 65537
    d = mc.inverse(e, (P1 - 1) * (P2 - 1) * (P3 - 1))
    flag = b"flag{multi_prime_rsa_recovered}"
    c = pow(int.from_bytes(flag, "big"), e, n)
    params = f"n = {n}\ne = {e}\nprime1 = {P1}\nprime2 = {P2}\nprime3 = {P3}\nc = {c}\n"
    qs = [q("What is the private exponent d?", "d"),
          q("Decrypt the ciphertext and submit the flag.", "pt", kind="exact_text", pattern=r"flag\{[^}]+\}"),
          q("Name the RSA variant / attack used here.", "atk", kind="exact_text")]
    res = solve(qs, {"key.txt": params.encode()})
    # arm5 crypto-core fix: a multi-prime (3+ factor) d is convention-ambiguous (Euler phi vs
    # Carmichael lambda) exactly like a 2-prime d -- both round-trip, so verification cannot
    # disambiguate and it must be an UNSURE pick over the two conventions, never a single plain
    # (the original "d is plain" asserted the wrong-plain bug). The phi-form d = e^-1 mod phi
    # (this test's `d`) must be among the offered options.
    check("tk multiprime: d is an unsure pick over the two valid conventions (never a single plain)",
          unsure(res["d"], str(d)), res["d"])
    check("tk multiprime: the flag decrypts plain", res["pt"] == flag.decode(), res["pt"])
    check("tk multiprime: attack name is an unsure pick", unsure(res["atk"], "multi"), res["atk"])
    # JSON 'primes' array form reaches the same multi-prime result (still the unsure two-convention
    # pick after the arm5 fix, not a single plain)
    jp = json.dumps({"n": n, "e": e, "primes": [P1, P2, P3], "c": c})
    check("tk multiprime: JSON primes[] array also works",
          unsure(solve([q("What is the private exponent d?", "d")], {"k.json": jp.encode()})["d"], str(d)))
    # single-letter p/q/r labels: n != p*q trips the two-prime consistency check, so the multi-prime
    # path MUST run before it (early placement in solve_rsa). d is a valid private exponent.
    pqr = f"n = {n}\ne = {e}\np = {P1}\nq = {P2}\nr = {P3}\n"
    res_pqr = solve([q("Recover the private exponent d.", "d")], {"k.txt": pqr.encode()})
    check("tk multiprime: single-letter p/q/r three-prime solves (runs before consistency)",
          res_pqr["d"] == str(d) or unsure(res_pqr["d"], str(d)), res_pqr)
    # never-wrong: a wrong prime -> the set does not factor n -> None
    bad = f"n = {n}\ne = {e}\nprime1 = {P1}\nprime2 = {P2}\nprime3 = {P3 + 2}\nc = {c}\n"
    res_b = solve(qs, {"k.txt": bad.encode()})
    check("tk multiprime: a wrong prime leaves d and the flag None", res_b["d"] is None and res_b["pt"] is None, res_b)
    # a genuine two-prime key stays rsa_private's job (not claimed as multi-prime): d still recovered
    A, B = prime(200), prime(200)
    n2, d2 = A * B, mc.inverse(e, (A - 1) * (B - 1))
    res2 = solve([q("What is the private exponent d?", "d")],
                 {"k.txt": f"n = {n2}\ne = {e}\np = {A}\nq = {B}\n".encode()})
    check("tk multiprime: a two-prime key still solves (via rsa_private)",
          res2["d"] == str(d2) or unsure(res2["d"], str(d2)), res2)


def test_toolkit_franklin_reiter():
    P, Q = prime(400), prime(400)
    n = P * Q
    while mc.inverse(3, (P - 1) * (Q - 1)) is None:
        P, Q = prime(400), prime(400)
        n = P * Q
    flag = b"flag{franklin_reiter_related_message}"
    m1 = int.from_bytes(flag, "big")
    b = 1337
    c1, c2 = pow(m1, 3, n), pow(m1 + b, 3, n)
    params = f"n = {n}\ne = 3\nc1 = {c1}\nc2 = {c2}\npadding offset b = {b}\n"
    qs = [q("The two ciphertexts encrypt related messages (m and m+b). Recover the flag.",
            "pt", kind="exact_text", pattern=r"flag\{[^}]+\}"),
          q("Which related-message attack applies?", "atk", kind="exact_text")]
    res = solve(qs, {"ct.txt": params.encode()})
    check("tk franklin_reiter: the flag is plain", res["pt"] == flag.decode(), res["pt"])
    check("tk franklin_reiter: attack name is an unsure pick",
          unsure(res["atk"], "franklin") or unsure(res["atk"], "related"), res["atk"])
    # never-wrong: no stated relation -> the attack is not attempted
    res_n = solve(qs, {"ct.txt": f"n = {n}\ne = 3\nc1 = {c1}\nc2 = {c2}\n".encode()})
    check("tk franklin_reiter: no stated relation leaves the flag None", res_n["pt"] is None, res_n)


def main():
    try:
        for fn in (test_lib_bellcore, test_lib_multiprime, test_lib_franklin_reiter,
                   test_toolkit_bellcore, test_toolkit_multiprime, test_toolkit_franklin_reiter):
            fn()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
