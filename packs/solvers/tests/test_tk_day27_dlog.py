#!/usr/bin/env python3
"""Offline tests of solvers/common/dlog.py and its wiring in the modern_crypto toolkit (Day 27, KB-10):
discrete logarithms in Z_p^* for ElGamal / Diffie-Hellman in a weak group. Pohlig-Hellman (smooth p-1, prime
powers, CRT), the small-subgroup case, BSGS, Pollard's kangaroo for a stated exponent bound, and the three
answers the question router asks (shared secret, private exponent, ElGamal plaintext).

Every instance is generated with a known secret. Since fix round 4 (convergence by restriction) the hook answers NOTHING plain:
every value it derives is a candidate pick (labels.candidates, row 346) under a key fingerprinted per instance
(`modern_crypto.dlog_<kind>/zp@inst-<64 hex>#candidates`). A former plain control now asserts that the truth is among the
candidates, first where it is the computed value, and that the answer is never plain (`holds`); every decoy gives None or an
unsure pick, never a plain value (a strict block asserts None): a non-smooth p declines in time, a wrong generator, an h outside
the subgroup, a composite modulus, conflicting labels, an elliptic-curve / DSA wording, a question for a value derived from the
secret, an unnamed party.

  .venv/bin/python tests/test_tk_day27_dlog.py

Sections: lib_tests (the library), tk_tests (the toolkit's three answers), fuzz_tests (random instances), review_tests (R1 to R9,
one regression per issue of the first adversarial review of 6a11f24), round2_tests (R10 to R14, the verifier's own pass over the
fixed head 2cc5f27: numbers the reader must not take, asks that are not plain asks, programs and prose in the delivery, key
isolation after the judge accepts a name, the ElGamal plaintext), fix1_tests (R15 to R26, the second verifier's pass over 95699e2: a preamble
that names the target, operands the router does not read, roles, operators, expressions of the target, ranges of another variable, keys scoped to
the delivery, time and the set's other questions, the library against a naive reference, a question fuzz with ground truth, and a salad of random
sentences from the plain-ask vocabulary: verb-less asks, a formula target, a party against an exponent letter), fix2_tests (R27 to R31,
fix round 4: no dlog value is ever plain, the per-instance key after the judge accepts a name, the review's latent keys accepted
change nothing, the discrete-log pass runs after every older reader and no older answer is lost to a slow group, ten new question
shapes), fix3_tests (R32 to R35, the independent review of eddb777: the pass's own material, the same files arranged otherwise,
what Material does not keep, no Material outside the deadline). Every decoy gives None or an unsure pick, never a plain value (a strict block asserts None); every control holds the truth.

Fixed seed, no network, no token. A few seconds.
"""
import sys as _b240_sys  # noqa: E402
if "pytest" in _b240_sys.modules and __name__ != "__main__":
    # B-240 carry: a check()-style script. Its checks never fail a pytest run and its module-level setup changes
    # os.environ for the whole worker, so pytest does not collect it; tests/test_carry_checklist.py runs it as a
    # script (exit code and FAIL lines) and reports its saved-data sections as not run.
    import pytest
    pytest.skip("script-style test: run as a script by tests/test_carry_checklist.py", allow_module_level=True)
import importlib.util
import os
import random
import re
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_tk_day27_dlog_")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
import dlog as D  # noqa: E402

spec = importlib.util.spec_from_file_location("tk_modern_crypto_d27", REPO / "solvers" / "toolkits" / "modern_crypto.py")
tk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tk)

RND = random.Random(20261027)
FAILED = []
TIMES = {}


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)


def overrun(seconds):
    """Work for `seconds` of process time: a solve that overruns its window (R29). It works rather than sleeps,
    so the overrun moves every clock a deadline may read: the wall clock, and the CPU clock run() puts the
    toolkit on (inside sh09_clocks.cpu_clock time.monotonic reads process time, and time.sleep raises, which
    would turn the overrun into an exception the toolkit catches: SH-09 round 2)."""
    t0 = time.process_time()
    while time.process_time() - t0 < seconds:
        pass


def is_prime(n):
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % sp == 0:
            return n == sp
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rprime(bits):
    while True:
        c = RND.getrandbits(bits) | 1 | (1 << (bits - 1))
        if is_prime(c):
            return c


SMALLP = [q for q in range(3, 1 << 17) if is_prime(q)]


def smooth_p(nfac, maxbits=17, extra_two=1):
    """(p, distinct prime factors of p-1) with p-1 a product of small primes (known by construction)."""
    cands = [q for q in SMALLP if q.bit_length() <= maxbits]
    while True:
        fs = [RND.choice(cands) for _ in range(nfac)]
        m = 2 ** extra_two
        for f in fs:
            m *= f
        if is_prime(m + 1):
            return m + 1, sorted(set(fs) | {2})


def primitive_root(p, fs):
    for g in range(2, 1000):
        if all(pow(g, (p - 1) // f, p) != 1 for f in fs):
            return g
    raise AssertionError("no primitive root")


def safe_prime(bits):
    while True:
        q_ = rprime(bits - 1)
        if is_prime(2 * q_ + 1):
            return 2 * q_ + 1


def ask(question, kind="integer", aid="m"):
    return {"id": aid, "qid": aid, "answer_id": aid, "question": question, "answer_format": {"kind": kind}}


def solve(question, files):
    return tk.solve_set([question], files, {})[question["qid"]]


def unsure(v):
    return isinstance(v, str) and v.startswith("??")


def opts(v):
    """The (name, value) options of a candidate pick of the discrete-log hook (a key `...@inst-<fp>#candidates`), else []."""
    if not unsure(v) or tk.labels is None:
        return []
    u = tk.labels.parse(v)
    if u is None or not str(u.key).endswith("#candidates") or "@inst-" not in str(u.key):
        return []
    return [(str(n), str(val)) for n, val in u.options]


def holds(v, truth, first=True):
    """Fix round 4's form of a former plain control: v is the hook's candidate pick (never plain), the truth is among its values,
    and (first) it is the first value: the one the router computed and verified."""
    vals = [val for _, val in opts(v)]
    return bool(vals) and str(truth) in vals and (not first or vals[0] == str(truth))


def timed(label, fn):
    t0 = time.monotonic()
    r = fn()
    TIMES[label] = time.monotonic() - t0
    return r


# ---- the library -------------------------------------------------------------------------------------------

def lib_tests():
    for bits_f in (6, 10, 14):
        p, fs = smooth_p(bits_f)
        g = primitive_root(p, fs)
        x = RND.randrange(2, p - 1)
        h = pow(g, x, p)
        r = timed(f"ph{bits_f}", lambda: D.solve_dlog(p, g, h))
        check(f"Pohlig-Hellman, {p.bit_length()}-bit smooth p, primitive root: x recovered and verified",
              r is not None and pow(g, r.x, p) == h and r.x == x and r.primitive and r.order == p - 1, r)
    # a prime-power group order (2^40 * 3^20 + 1 style): digit-by-digit lifting
    while True:
        k = RND.randrange(1, 400)
        p = 2 ** 33 * 3 ** 15 * k + 1
        if is_prime(p):
            break
    g = 5
    x = RND.randrange(2, p - 1)
    r = D.solve_dlog(p, g, pow(g, x, p))
    check("prime-power group order: x with g^x == h", r is not None and pow(g, r.x, p) == pow(g, x, p), r)
    # a non-primitive generator (order (p-1)/2): the answer is the least residue, flagged non-primitive
    p, fs = smooth_p(8)
    g0 = primitive_root(p, fs)
    g = pow(g0, 2, p)
    x = RND.randrange(1, (p - 1) // 2)
    r = D.solve_dlog(p, g, pow(g, x, p))
    check("non-primitive generator: verified, primitive False, order (p-1)/2", r is not None and r.x == x and not r.primitive and r.order == (p - 1) // 2, r)
    # the small-subgroup case with a p-1 that cannot be factored: g has a small order r, the cofactor is a
    # 2 x 80-bit semiprime nobody splits in time
    r_ord = rprime(30)
    while True:
        k = 2 * rprime(80) * rprime(80)
        p = k * r_ord + 1
        if is_prime(p):
            break
    g = pow(3, k, p)
    if g == 1:
        g = pow(5, k, p)
    x = RND.randrange(2, r_ord)
    h = pow(g, x, p)
    r = timed("small_subgroup", lambda: D.solve_dlog(p, g, h))
    check("small subgroup (order a 30-bit prime) inside an unfactorable p-1: solved", r is not None and pow(g, r.x, p) == h and r.x == x, r)
    check("small subgroup: the stated order gives the same answer", D.solve_dlog(p, g, h, order=r_ord).x == x)
    # BSGS inside a group of prime order ~2^32 (p = 2q + 1 safe prime, g of order q)
    p = safe_prime(34)
    g = pow(RND.randrange(2, p - 2), 2, p)
    x = RND.randrange(2, (p - 1) // 2)
    h = pow(g, x, p)
    r = timed("bsgs", lambda: D.solve_dlog(p, g, h))
    check("BSGS in a prime-order group of ~2^33: verified", r is not None and pow(g, r.x, p) == h, r)
    # kangaroo: 64-bit safe prime (no PH), a stated 28-bit exponent
    p = safe_prime(64)
    g = next(a for a in range(2, 60) if pow(a, (p - 1) // 2, p) != 1)
    x = RND.randrange(1 << 26, 1 << 28)
    h = pow(g, x, p)
    r = timed("kangaroo", lambda: D.solve_dlog(p, g, h, bound=1 << 28))
    check("kangaroo: stated 28-bit exponent in a safe prime: verified", r is not None and r.x == x and r.method == "kangaroo", r)
    check("kangaroo: without the stated bound the same instance declines", D.solve_dlog(p, g, h) is None)
    check("kangaroo: a WRONG bound (x above it) finds nothing", D.solve_dlog(p, g, h, bound=1 << 20) is None)
    # parse_bound
    check("parse_bound: x < 2^40", D.parse_bound("the private exponent x < 2^40") == 1 << 40)
    check("parse_bound: a 32-bit secret", D.parse_bound("Alice picked a 32-bit secret") == 1 << 32)
    check("parse_bound: two different bounds are ambiguous", D.parse_bound("x < 2^20 and x < 2^30") is None)
    check("parse_bound: nothing stated", D.parse_bound("find the discrete logarithm") is None)

    # ---- decoys ------------------------------------------------------------------------------------------
    p = safe_prime(128)
    g = 3
    h = pow(g, RND.randrange(2, p - 2), p)
    r = timed("decoy_safe128", lambda: D.solve_dlog(p, g, h))
    check("a 128-bit safe prime (no weakness) declines", r is None)
    check("... and in time (under 0.7 s)", TIMES["decoy_safe128"] < 0.7, TIMES["decoy_safe128"])
    while True:
        a_, b_ = rprime(60), rprime(60)
        p = 2 * a_ * b_ + 1
        if is_prime(p):
            break
    h = pow(3, RND.randrange(2, p - 2), p)
    r = timed("decoy_semiprime", lambda: D.solve_dlog(p, 3, h))
    check("p-1 = 2 x two 60-bit primes declines in time (under 0.8 s)", r is None and TIMES["decoy_semiprime"] < 0.8, TIMES["decoy_semiprime"])
    # h outside <g>: g a square (order (p-1)/2), h a non-residue
    p, fs = smooth_p(8)
    g0 = primitive_root(p, fs)
    g = pow(g0, 2, p)
    h = pow(g0, 2 * RND.randrange(1, (p - 1) // 2) + 1, p)
    check("h outside the subgroup of g: None, not a wrong x", D.solve_dlog(p, g, h) is None)
    check("wrong generator: g=1 declines", D.solve_dlog(p, 1, 5) is None)
    check("h = 0 declines", D.solve_dlog(p, g0, 0) is None)
    check("a composite modulus declines", D.solve_dlog(91, 3, 9) is None)
    check("p huge (over 4096 bits) declines", D.solve_dlog((1 << 4100) + 1, 3, 9) is None)
    # a tiny exhaustive cross-check: every answer verified against brute force
    bad = 0
    for p in (101, 211, 1009, 2003, 4001):
        for g in range(2, 12):
            for h in range(1, min(p, 60)):
                r = D.solve_dlog(p, g, h)
                brute = next((e for e in range(p - 1) if pow(g, e, p) == h), None)
                if (r is None) != (brute is None) and not (r is None and brute is not None):
                    bad += 1                       # an answer where no logarithm exists
                if r is not None and (brute is None or r.x != brute):
                    bad += 1                       # a wrong or non-least answer
    check("exhaustive small p: every answer is the least exponent, none where no logarithm exists", bad == 0, bad)
    # dh_shared / elgamal_decrypt direct
    p, fs = smooth_p(8)
    g = primitive_root(p, fs)
    a, b = RND.randrange(2, p - 1), RND.randrange(2, p - 1)
    A, B = pow(g, a, p), pow(g, b, p)
    s = D.dh_shared(p, g, A, B)
    check("dh_shared: g^(ab) recovered", s is not None and s[0] == pow(g, a * b, p), s)
    s2 = D.dh_shared(p, g, A, B, priv_a=a)
    check("dh_shared with a stated private value that reproduces A", s2 is not None and s2[0] == pow(g, a * b, p) and s2[1] == "stated", s2)
    check("dh_shared: a stated private value that does NOT reproduce A is ignored (still solved)",
          D.dh_shared(p, g, A, B, priv_a=a + 1)[1] == "dlog")
    sub_g = pow(g, 2, p)
    Bout = pow(g, 2 * b + 1, p)                      # outside <sub_g>
    check("dh_shared: the other public value outside <g> declines", D.dh_shared(p, sub_g, pow(sub_g, a, p), Bout) is None)
    m = RND.randrange(2, p - 1)
    x = RND.randrange(2, p - 1)
    h = pow(g, x, p)
    k = RND.randrange(2, p - 1)
    c1, c2 = pow(g, k, p), m * pow(h, k, p) % p
    e = D.elgamal_decrypt(p, g, h, c1, c2)
    check("elgamal_decrypt: plaintext recovered", e is not None and e[0] == m, e)
    check("elgamal_decrypt: c1 outside <g> declines", D.elgamal_decrypt(p, sub_g, pow(sub_g, x, p), pow(g, 2 * k + 1, p), c2) is None)


# ---- the toolkit ---------------------------------------------------------------------------------------------

def tk_tests():
    p, fs = smooth_p(9)
    g = primitive_root(p, fs)
    a, b = RND.randrange(2, p - 1), RND.randrange(2, p - 1)
    A, B = pow(g, a, p), pow(g, b, p)
    s = pow(g, a * b, p)
    params = f"p = {p}\ng = {g}\nA = {A}\nB = {B}\n".encode()
    files = {"params.txt": params}
    v = timed("tk_shared", lambda: solve(ask("What is the Diffie-Hellman shared secret? Give it in decimal."), files))
    check("DH shared secret (integer kind): the computed secret first among the candidates, never plain", holds(v, s), v)
    v = solve(ask("Compute the shared secret of Alice and Bob.", kind="exact_text"), files)
    check("DH shared secret (text kind): a candidate pick (decimal first, then the hex forms), never a bare plain",
          holds(v, s) and f"{s:x}" in [val for _, val in opts(v)], v)
    v = solve(ask("Find the private exponent of Alice (the discrete log of her public value A)."), files)
    check("Alice's private exponent, g a primitive root, range NOT stated: a candidate pick holding it first (review: a secret above "
          "p-1 would make the least residue a wrong plain)", holds(v, a), v)
    v = solve(ask("Find Bob's private exponent."), files)
    check("Bob's private exponent, range not stated: a candidate pick holding it first, then Alice's and the shared secret",
          holds(v, b) and [val for _, val in opts(v)][1:3] == [str(a), str(s)], v)
    files_rng = {"params.txt": params + b"Private exponents are chosen uniformly with x < p-1.\n"}
    v = solve(ask("Find the private exponent of Alice (the discrete log of her public value A)."), files_rng)
    check("Alice's private exponent, g a primitive root, range stated in the material (x < p-1): first among the candidates, never plain",
          holds(v, a), v)
    v = solve(ask("Find Bob's private exponent; it satisfies x < p-1."), files)
    check("Bob's private exponent, range stated in the question: first among the candidates, never plain", holds(v, b), v)
    v = solve(ask("Find Bob's private exponent."), {"params.txt": params + b"The secret is generated as random.randrange(2, p-1).\n"})
    check("range stated as randrange(2, p-1) in a script line: first among the candidates, never plain", holds(v, b), v)
    v = solve(ask("Find the private exponent."), files)
    check("DECOY unnamed party with both A and B: None", v is None, v)
    v = solve(ask("What is the SHA-256 of the shared secret?", kind="exact_text"), files)
    check("DECOY a value derived from the shared secret: not the bare secret", v is None or v != str(s), v)
    v = solve(ask("What is the elliptic-curve Diffie-Hellman shared secret?"), files)
    check("DECOY elliptic-curve wording is left to the ECC path: None", v is None, v)
    v = solve(ask("Recover the DSA private key x from the signature."), files)
    check("DECOY DSA wording: None", v is None, v)
    # private exponent in the question: a stated value that reproduces A is used and verified
    files_priv = {"params.txt": params + f"a = {a}\n".encode()}
    v = solve(ask("What is the shared secret?"), files_priv)
    check("shared secret with Alice's private value stated: the secret first among the candidates", holds(v, s), v)
    files_bad = {"params.txt": params + f"a = {a + 1}\n".encode()}
    v = solve(ask("What is the shared secret?"), files_bad)
    check("DECOY a stated 'a' that does not reproduce A: ignored, still the right secret first", holds(v, s), v)
    files_cs = {"hs.json": ('{"p": "%d", "g": %d, "client_public": "%d", "server_public": "%d"}' % (p, g, A, B)).encode()}
    v = solve(ask("What is the shared secret of the key exchange?"), files_cs)
    check("JSON client_public / server_public: the shared secret first among the candidates", holds(v, s), v)
    v = solve(ask("Recover the server's private exponent."), files_cs)
    check("JSON: the server's private exponent (role from the question): a candidate pick holding it first", holds(v, b), v)
    # conflicting labels
    v = solve(ask("What is the shared secret?"), {"params.txt": params + f"p = {p + 2}\n".encode()})
    check("DECOY two different p: None", v is None, v)
    # a composite modulus
    v = solve(ask("What is the shared secret?"), {"params.txt": f"p = {p * 3}\ng = {g}\nA = {A}\nB = {B}\n".encode()})
    check("DECOY composite p: None", v is None, v)

    # a subgroup generator: the private exponent is a residue class, so unsure; the shared secret is exact
    sg = pow(g, 2, p)
    a2, b2 = RND.randrange(2, (p - 1) // 2), RND.randrange(2, (p - 1) // 2)
    A2, B2 = pow(sg, a2, p), pow(sg, b2, p)
    files2 = {"params.txt": f"p = {p}\ng = {sg}\nA = {A2}\nB = {B2}\n".encode()}
    v = solve(ask("Find Alice's private exponent."), files2)
    check("subgroup generator: the private exponent is NOT plain (a residue class): a candidate pick holding it first", holds(v, a2), v)
    v = solve(ask("What is the shared secret?"), files2)
    check("subgroup generator: the shared secret first among the candidates", holds(v, pow(sg, a2 * b2, p)), v)
    files2b = {"params.txt": f"p = {p}\ng = {sg}\nA = {A2}\nB = {pow(g, 2 * b2 + 1, p)}\n".encode()}
    v = solve(ask("What is the shared secret?"), files2b)
    check("DECOY B outside <g>: None", v is None, v)
    v = solve(ask("Find Alice's private exponent."), {"params.txt": f"p = {p}\ng = {sg}\nA = {pow(g, 2 * a2 + 1, p)}\nB = {B2}\n".encode()})
    check("DECOY A outside <g> (no logarithm): None", v is None, v)

    # a single public value, stated bound, kangaroo path
    P = safe_prime(64)
    G = next(c for c in range(2, 60) if pow(c, (P - 1) // 2, P) != 1)
    X = RND.randrange(1 << 26, 1 << 28)
    H = pow(G, X, P)
    files3 = {"y.txt": f"p = {P}\ng = {G}\nh = {H}\n".encode()}
    v = timed("tk_kangaroo", lambda: solve(ask("Find the discrete log x of h to base g; x is a 28-bit number."), files3))
    check("kangaroo through the toolkit: the bounded log first among the candidates (safe prime, g of order p-1), never plain", holds(v, X), v)
    v = solve(ask("Find the discrete log x of h to base g."), files3)
    check("DECOY the same safe prime with no stated bound: None", v is None, v)

    # ElGamal plaintext
    msg = b"flag{elgamal_smooth_p}"
    m = int.from_bytes(msg, "big")
    p4 = None
    while True:
        p4, fs4 = smooth_p(12, maxbits=17)
        if p4 > m * 4 and p4.bit_length() > 8 * len(msg) + 4:
            break
    g4 = primitive_root(p4, fs4)
    x4 = RND.randrange(2, p4 - 1)
    h4 = pow(g4, x4, p4)
    k4 = RND.randrange(2, p4 - 1)
    c1, c2 = pow(g4, k4, p4), m * pow(h4, k4, p4) % p4
    files4 = {"challenge.txt": f"p = {p4}\ng = {g4}\nh = {h4}\nciphertext = ({c1}, {c2})\n".encode()}
    qf = {"id": "m", "qid": "m", "answer_id": "m", "question": "Decrypt the ElGamal ciphertext. What is the flag?",
          "answer_format": {"kind": "exact_text", "pattern": r"flag\{[a-z_]+\}"}}
    v = timed("tk_elgamal", lambda: solve(qf, files4))
    check("ElGamal plaintext, flag pattern: the flag first among the candidates, never plain", holds(v, msg.decode()), v)
    qt = ask("Decrypt the ElGamal ciphertext. What is the plaintext message?", kind="exact_text")
    v = solve(qt, files4)
    check("ElGamal plaintext, no pattern: the flag text first among the candidates (its forms after it), never plain",
          holds(v, msg.decode()), v)
    qi = ask("Decrypt the ElGamal ciphertext and give the message as an integer.")
    v = solve(qi, files4)
    check("ElGamal plaintext as an integer: a candidate pick holding it first (then the swapped-label reading)",
          holds(v, m) and [n for n, _ in opts(v)][:2] == ["message:decimal", "swapped:decimal"], v)
    v = solve(ask("Find the private exponent x of the ElGamal public key h."), files4)
    check("ElGamal material, a PRIVATE-exponent question: the exponent first (candidate pick), not the plaintext",
          holds(v, x4) and str(m) not in v, v)
    v = solve(ask("Decrypt the ElGamal message. What is the private key x?"), files4)
    check("DECOY two different asks in one question (decrypt, private key): None", v is None, v)
    v = solve(ask("Using the private key, decrypt the ElGamal ciphertext and give the message as an integer."), files4)
    check("the private key mentioned but the message asked: the message first (candidate pick)", holds(v, m), v)
    files4b = {"challenge.txt": f"p = {p4}\ng = {g4}\nh = {h4}\nc1 = {c1}\nc2 = {c2}\n".encode()}
    check("ElGamal with c1 / c2 labels: same", holds(solve(qf, files4b), msg.decode()), solve(qf, files4b))
    files4c = {"challenge.txt": f"p = {p4}\ng = {g4}\nh = {h4}\nciphertext = ({c1}, {c2 + 1})\n".encode()}
    v = solve(qf, files4c)
    check("DECOY a tampered c2: the plaintext is junk, so the flag pattern refuses it (None)", v is None, v)
    sg4 = pow(g4, 2, p4)
    h5 = pow(sg4, x4, p4)
    files4d = {"challenge.txt": f"p = {p4}\ng = {sg4}\nh = {h5}\nciphertext = ({pow(g4, 2 * k4 + 1, p4)}, {c2})\n".encode()}
    v = solve(qf, files4d)
    check("DECOY c1 outside <g>: None", v is None, v)
    P2 = safe_prime(128)
    files5 = {"challenge.txt": f"p = {P2}\ng = 3\nh = {pow(3, RND.randrange(2, P2 - 2), P2)}\nciphertext = (5, 7)\n".encode()}
    v = timed("tk_decoy_elgamal", lambda: solve(qf, files5))
    check("DECOY ElGamal over a 128-bit safe prime: None, in time", v is None and TIMES["tk_decoy_elgamal"] < 0.8, (v, TIMES["tk_decoy_elgamal"]))

    # the intent routes a discrete-log question the older intents do not read
    check("intent: 'discrete logarithm' alone is asked", bool(tk.intent(ask("Find x such that g^x = h (mod p)."))))
    check("signals: an ElGamal question set scores", tk.signals([qf], files4) > 0.2, tk.signals([qf], files4))
    # an RSA question is not touched
    v = solve(ask("What is the private exponent d?"), {"k.txt": b"n = 3233\ne = 17\n"})
    check("RSA private-exponent question is untouched (no p, g material)", v in (None,) or v == "2753" or unsure(v), v)


def fuzz_tests(n=120):
    """Random instances over random primes (18 to 40 bits, so most are solvable and some are not): NO answer is plain (fix round
    4); every option of a candidate pick is what its hypothesis says (`log` a logarithm of A, `other_party` one of B,
    `shared_secret` g^(ab)); an h outside the subgroup must be None."""
    wrong = outside_bad = solved = declined = 0
    for _ in range(n):
        p = rprime(RND.randrange(18, 41))
        g = RND.randrange(2, p - 1)
        a, b = RND.randrange(2, p - 1), RND.randrange(2, p - 1)
        A, B = pow(g, a, p), pow(g, b, p)
        files = {"d.txt": f"p = {p}\ng = {g}\nA = {A}\nB = {B}\n".encode()}
        v = solve(ask("What is the shared secret?"), files)
        truth = str(pow(g, a * b, p))
        if v is not None and (not unsure(v) or not holds(v, truth)):
            wrong += 1
        v = solve(ask("Find Alice's private exponent."), files)
        if v is not None and not unsure(v):
            wrong += 1                                  # nothing is plain any more
        elif v is None:
            declined += 1
        else:                                           # a candidate pick: every option is what its hypothesis names
            solved += 1
            got = opts(v)
            for name, val in got:
                hyp = name.split(":")[0]
                ok = (hyp == "log" and pow(g, int(val), p) == A or hyp == "other_party" and pow(g, int(val), p) == B
                      or hyp == "shared_secret" and val == truth)
                if not ok or not name.endswith(":decimal"):
                    wrong += 1
            if not got or got[0][0] != "log:decimal":
                wrong += 1
        # an A outside <g>: with g of order (p-1)/2 and A a non-residue
        o = D.group_order_of(p, g)
        if o is not None and o[0] < p - 1:
            bad = next((c for c in range(2, p) if pow(c, o[0], p) != 1), None)
            if bad is not None:
                files_o = {"d.txt": f"p = {p}\ng = {g}\nA = {bad}\nB = {B}\n".encode()}
                v = solve(ask("Find Alice's private exponent."), files_o)
                v2 = solve(ask("What is the shared secret?"), files_o)
                if v is not None or v2 is not None:
                    outside_bad += 1
    check(f"fuzz: {n} random instances, nothing plain, every candidate what its hypothesis names ({solved} offered, {declined} declined)",
          wrong == 0 and solved > n // 2, (wrong, solved))
    check("fuzz: an A outside <g> is always None (private exponent and shared secret)", outside_bad == 0, outside_bad)


def review_tests():
    """One regression per issue of the adversarial review of 6a11f24 (each shape was a wrong plain, a hang, a regression
    or a slowdown): every decoy must give None or an unsure pick, never a plain value."""
    import hashlib

    def plain(v):
        return v is not None and not unsure(v)

    # R1: the kangaroo's tame walk checks the deadline; a stated bound over 2^34 declines in time ---------------------
    P = safe_prime(160)
    G = next(c for c in range(2, 60) if pow(c, (P - 1) // 2, P) != 1)
    X = RND.randrange(1 << 38, 1 << 40)
    H = pow(G, X, P)
    for bits in (40, 44, 64):
        t0 = time.monotonic()
        r = D.solve_dlog(P, G, H, bound=1 << bits)
        dt = time.monotonic() - t0
        check(f"R1 library: a 2^{bits} stated bound over a safe prime declines within the cap ({dt:.2f}s)", r is None and dt < 0.9, (r, dt))
    files1 = {"handshake.txt": f"p = {P}\ng = {G}\nA = {H}\nB = {pow(G, RND.randrange(2, P - 2), P)}\n".encode(),
              "notes.txt": b"The IV is a 64-bit value. A 40-bit key is derived from the secret."}
    t0 = time.monotonic()
    v = solve(ask("What is the shared secret?"), files1)
    dt = time.monotonic() - t0
    check(f"R1 toolkit: an unrelated '64-bit value' sentence no longer hangs or bounds the solve ({dt:.2f}s)", v is None and dt < 0.9, (v, dt))
    t0 = time.monotonic()
    v = solve(ask("Find the discrete log x of A to base g; x is a 64-bit number."), {"y.txt": files1["handshake.txt"]})
    dt = time.monotonic() - t0
    check(f"R1 toolkit: a question that does state a 2^64 bound over a safe prime declines in time ({dt:.2f}s)", v is None and dt < 0.9, (v, dt))

    # R2: a key DERIVED from the secret is never the bare secret --------------------------------------------------------
    while True:
        p, fs = smooth_p(14, maxbits=17)
        if p.bit_length() >= 200:
            break
    g = primitive_root(p, fs)
    a, b = RND.randrange(2, p - 1), RND.randrange(2, p - 1)
    A, B = pow(g, a, p), pow(g, b, p)
    s = pow(g, a * b, p)
    src = (b"from hashlib import sha256\nshared = pow(B, a, p)\nsession_key = sha256(str(shared).encode()).hexdigest()\n")
    out = f"p = {p}\ng = {g}\nA = {A}\nB = {B}\n".encode()
    files2 = {"chall.py": src, "output.txt": out}
    hex64 = r"^[0-9a-f]{64}$"
    for qtext, kind, pat in (("What is the session key?", "exact_text", hex64),
                             ("What is the shared key Alice and Bob use?", "exact_text", hex64),
                             ("Alice and Bob derive the session key as K = SHA256(s). What is the session key K?", "exact_text", hex64),
                             ("What is the AES key derived from the shared secret?", "exact_text", hex64),
                             ("What is the session key?", "integer", None),
                             ("What is the shared secret?", "integer", None)):      # a script hashes it: still never plain
        qq = ask(qtext, kind)
        if pat:
            qq["answer_format"]["pattern"] = pat
        v = solve(qq, files2)
        check(f"R2 derived key, never plain: {qtext[:60]!r} ({kind})", not plain(v), v)
    plain_files = {"output.txt": out}
    v = solve(ask("What is the shared secret?"), plain_files)
    check("R2 control: the shared secret with no hash anywhere: first among the candidates", holds(v, s), v)

    # R3: a named party takes that party's slot; a third party or group is not the A/B secret ---------------------------
    e_ = RND.randrange(2, p - 1)
    E = pow(g, e_, p)
    v = solve(ask("What is Bob's private key?"), {"params.txt": f"p = {p}\ng = {g}\nA = {A}\nBob's public value: {B}\n".encode()})
    check("R3 Bob's key with only A readable: None, never Alice's exponent", v is None, v)
    v = solve(ask("What is Bob's private key?"), {"params.txt": f"p = {p}\ng = {g}\nh = {A}\nB = {B}\n".encode()})
    check("R3 Bob's key, h and B stated: Bob's slot only (never h's exponent as plain)", not plain(v) or v == str(b), v)
    v = solve(ask("What is the shared secret that Alice computed with Eve?"),
              {"t.txt": f"p = {p}\ng = {g}\nA = {A}\nB = {B}\neve_public = {E}\n".encode()})
    check("R3 MITM with Eve: None", v is None, v)
    v = solve(ask("What is the shared key between Mallory and Bob?"), {"t.txt": f"p = {p}\ng = {g}\nA = {A}\nB = {B}\nM = {E}\n".encode()})
    check("R3 Mallory's key (a labelled third value): None", v is None, v)
    v = solve(ask("What is the group shared secret of Alice, Bob and Carol?"), {"t.txt": f"p = {p}\ng = {g}\nA = {A}\nB = {B}\nC = {E}\n".encode()})
    check("R3 three-party group secret: None", v is None, v)
    v = solve(ask("What is the shared secret?"), {"t.txt": f"p = {p}\ng = {g}\nA = {A}\nB = {B}\nC = {E}\n".encode()})
    check("R3 a third public value C labelled in the material: the shared secret asked plainly is still None", v is None, v)

    # R4: an ElGamal integer plaintext is never plain; variants decline --------------------------------------------------
    x = RND.randrange(2, p - 1)
    h = pow(g, x, p)
    k = RND.randrange(2, p - 1)
    c1, c2e = pow(g, k, p), pow(g, 42, p) * pow(h, k, p) % p
    v = solve(ask("Decrypt the ElGamal ciphertext. What is the message m as an integer?"),
              {"vote.txt": (f"Exponential ElGamal (votes are encoded as g^m).\np = {p}\ng = {g}\nh = {h}\nx = {x}\nc1 = {c1}\nc2 = {c2e}\n").encode()})
    check("R4 exponential ElGamal: None (never g^m as a plain integer)", v is None, v)
    m2 = RND.randrange(2, p - 1)
    v = solve(ask("Decrypt the ElGamal ciphertext and give the message as an integer."),
              {"ct.txt": f"p = {p}\ng = {g}\nh = {h}\nx = {x}\nc1 = {m2 * pow(h, k, p) % p}\nc2 = {pow(g, k, p)}\n".encode()})
    check("R4 swapped c1/c2: never a plain integer", not plain(v), v)
    m3 = RND.randrange(2, 1 << 64)
    mask = int.from_bytes(hashlib.sha256(str(pow(h, k, p)).encode()).digest()[:8], "big")
    v = solve(ask("Decrypt the ElGamal ciphertext and give the message as an integer."),
              {"ct.txt": f"hashed ElGamal: c2 = m xor H(h^k)\np = {p}\ng = {g}\nh = {h}\nc1 = {pow(g, k, p)}\nc2 = {m3 ^ mask}\n".encode()})
    check("R4 hashed ElGamal: None", v is None, v)
    m4 = RND.randrange(2, p - 1)
    v = solve(ask("Decrypt the ElGamal ciphertext and give the message as an integer."),
              {"ct.txt": f"p = {p}\ng = {g}\nh = {h}\nc1 = {pow(g, k, p)}\nc2 = {m4 * pow(h, k, p) % p}\n".encode()})
    check("R4 an ordinary ElGamal integer plaintext: a candidate pick holding it first, never plain", holds(v, m4), v)

    # R5: a bound read from unrelated text; a subgroup residue stays unsure ---------------------------------------------
    bd = {"The server allows attempts under 100 per minute.": None, "blocks smaller than 16 are padded": None,
          "max: 10 tries": None, "The IV is a 64-bit value.": None, "AES uses a 128-bit key; the nonce is a 64-bit number.": None,
          "keys below 4096 are rejected": None, "x < 2^40": 1 << 40, "a 32-bit secret": 1 << 32, "x is a 28-bit number": 1 << 28,
          "The private key is at most 2^20": 1 << 20}
    bad = [t for t, want in bd.items() if D.parse_bound(t) != want]
    check("R5 parse_bound: whole-word private-value phrases only (no 'attempts', 'blocks', 'IV', 'nonce', 'tries')", not bad, bad)
    ps, fss = smooth_p(9)
    g0 = primitive_root(ps, fss)
    qq_ = max(fss)
    gs = pow(g0, (ps - 1) // qq_, ps)
    a_full = qq_ * RND.randrange(10, (ps - 1) // qq_ - 1) + 37
    for note in ("The server allows attempts under 100 per minute.\n", "blocks smaller than 64 are padded\n", ""):
        v = solve(ask("What is Alice's private key a?"), {"p.txt": f"p = {ps}\ng = {gs}\nA = {pow(gs, a_full, ps)}\n{note}".encode()})
        check(f"R5 subgroup residue, spurious sentence {note.strip()[:30]!r}: never plain", not plain(v), v)
    v = solve(ask("What is Alice's private key a, where a < 2^10?"), {"p.txt": f"p = {ps}\ng = {gs}\nA = {pow(gs, 37, ps)}\n".encode()})
    check("R5 control: a numeric bound the question states (<= ord(g)): the exponent first among the candidates, never plain",
          holds(v, 37), v)

    # R6: the exponent REDUCED modulo something is not the exponent --------------------------------------------------
    for qtext in ("What is the private exponent x modulo q?", "What is the private key x reduced modulo the prime q?", "What is x modulo q?",
                  "What is the inverse of x mod p-1?"):
        v = solve(ask(qtext), {"p.txt": f"p = {p}\ng = {g}\nq = {max(fs)}\nh = {h}\n".encode()})
        check(f"R6 {qtext!r}: None", v is None, v)
    v = solve(ask("Find x such that g^x = h mod p."), {"p.txt": f"p = {p}\ng = {g}\nh = {h}\nThe exponent satisfies x < p-1.\n".encode()})
    check("R6 control: the statement's own 'g^x = h mod p' is still read: x first among the candidates", holds(v, x), v)

    # R7: the DSA path keeps a toy nonce-reuse question worded without DSA ---------------------------------------------
    qd = rprime(32)
    while True:
        pd = qd * RND.getrandbits(224) * 2 + 1
        if pd.bit_length() >= 250 and is_prime(pd):
            break
    gd = 1
    while gd == 1:
        gd = pow(RND.randrange(2, pd - 1), (pd - 1) // qd, pd)
    xd = RND.randrange(2, qd)
    yd = pow(gd, xd, pd)
    kd = RND.randrange(2, qd)

    def zof(msg):
        return int.from_bytes(hashlib.sha256(msg).digest(), "big") >> max(0, 256 - qd.bit_length())

    def sign(z):
        r = pow(gd, kd, pd) % qd
        return r, pow(kd, -1, qd) * (z + xd * r) % qd

    r_, s1 = sign(zof(b"alpha"))
    _, s2 = sign(zof(b"bravo"))
    dsa_files = {"data.txt": (f"p = {pd}\nq = {qd}\ng = {gd}\ny = {yd}\nr1 = {r_}\ns1 = {s1}\nmsg1 = alpha\n"
                              f"r2 = {r_}\ns2 = {s2}\nmsg2 = bravo\n").encode()}
    v = solve(ask("The same nonce k was used twice. Recover the private key x."), dsa_files)
    check("R7 toy DSA nonce reuse worded without DSA: the DSA path's plain answer stands", v == str(xd), v)
    v = solve(ask("Find the discrete logarithm x of y to base g."), dsa_files)
    check("R7 a signature delivery (r/s pairs) is not read as a DH/ElGamal instance for a vague question", not plain(v) or v == str(xd), v)

    # R8: the material is parsed once; a large text with no group costs nothing -------------------------------------------
    rr = random.Random(1)
    big = ("\n".join(f"field_{i} = {rr.getrandbits(64)}" for i in range(20000)) + "\n").encode()[:500000]
    qs = [ask(f"Decrypt record {i}. What is the plaintext?", kind="exact_text", aid=f"q{i}") for i in range(40)]
    t0 = time.monotonic()
    tk.solve_set(qs, {"log.txt": big}, {"budget": 60})
    dt = time.monotonic() - t0
    TIMES["overhead_40q_500kb"] = dt
    check(f"R8 40 decrypt questions over a 500 KB labelled text: {dt:.2f}s (base 0.17 s, the unfixed head 1.45 s; under 0.7 s)", dt < 0.7, dt)
    check("R8 may_state_group: a text with a p and a g label passes, a log does not",
          D.may_state_group("p = 23\ng = 5") and not D.may_state_group(big.decode()))

    # R9 (minor): the least residue is plain only for a stated range; a big modulus declines in the cap -------------------
    p2, fs2 = smooth_p(10)
    g2 = primitive_root(p2, fs2)
    while True:
        a2 = RND.getrandbits(p2.bit_length())
        if a2 >= p2 - 1:
            break
    v = solve(ask("What is Alice's private key a?"), {"p.txt": f"p = {p2}\ng = {g2}\nA = {pow(g2, a2, p2)}\n# a = getrandbits(p.bit_length())\n".encode()})
    check("R9 a secret above p-1 (getrandbits): never plain", not plain(v), v)
    try:
        import gmpy2
        big_p = int(gmpy2.next_prime((1 << 1535) + RND.getrandbits(1500)))
        t0 = time.monotonic()
        r = D.solve_dlog(big_p, 5, RND.randrange(2, big_p - 1))
        dt = time.monotonic() - t0
        check(f"R9 a 1536-bit prime modulus declines inside the cap ({dt:.2f}s)", r is None and dt < 0.9, (r, dt))
    except ImportError:
        pass


def round2_tests():
    """Review round 2, the verifier's own pass over the fixed head (2cc5f27): every shape below was a confident WRONG plain
    answer on it. A decoy must give None or an unsure pick, never a plain value; each control held the truth plain (since fix round 4:
    the truth among the candidates, first where it is the computed value, never plain)."""
    import hashlib

    def plain(v):
        return v is not None and not unsure(v)

    # R10: a labelled number that goes on as an expression, a digit group or a wrapped line is not read as its first piece ----
    cases = [("p = 7 * 2**26 + 1", None), ("p = 2^255 - 19", None), ("p = 5 * 2^25 + 1", None), ("p = 479 * 2 ** 21 + 1", None),
             ("p = 10**9+7", None), ("p = 3 << 4", None), ("p = 5 / 2", None), ("p = 12 + 5", None), ("p = 1,000,003", None),
             ("p = 1 000 003", None), ("p = 23 45", None), ("p = 2.5", None), ("p = 123...", None), ("g = 2 ** 3", None),
             ("g = 2×3", None), ("p = 1234567890\n    12345678901234", None), ("p = 1234567890\r\n    deadbeef0123", None),
             ("p = 23", 23), ("p = 23\ng = 5\n", 23), ("p = 23, g = 5", 23), ("- p = 23\n- g = 5\n", 23), ("p: 23.", 23),
             ("p=23;g=5;A=8;B=19", 23), ("  p = 23   # modulus", 23), ("p = 23\r\ng = 5\r\n", 23), ("p = 23\n    g = 5", 23),
             ("p = 23\n\n- note", 23), ("A = 8 B = 19\np = 23", 23)]
    bad = [(t, D.read_instance(t)["p"], want) for t, want in cases if D.read_instance(t)["p"] != want]
    check("R10 library: expressions, digit groups, wrapped lines are not read as p; plain statements still are", not bad, bad)
    check("R10 library: `g = 2 ** 3` is not read as g = 2 (a plain `g = 5` is)",
          D.read_instance("g = 2 ** 3")["g"] is None and D.read_instance("g = 5")["g"] == 5)
    ntt = [("479 * 2**21 + 1", 479 * 2 ** 21 + 1, [2, 479]), ("7 * 2**26 + 1", 7 * 2 ** 26 + 1, [2, 7]),
           ("5 * 2^25 + 1", 5 * 2 ** 25 + 1, [2, 5]), ("479 * 2 ** 21 + 1", 479 * 2 ** 21 + 1, [2, 479])]
    wrong = []
    for expr, pn, fsn in ntt:
        gn = primitive_root(pn, fsn)
        for _ in range(12):
            an, bn = RND.randrange(2, pn - 1), RND.randrange(2, pn - 1)
            An, Bn = pow(gn, an, pn), pow(gn, bn, pn)
            for qtext in ("What is the shared secret?", "What is Alice's private key a? It satisfies a < p-1."):
                v = solve(ask(qtext), {"params.txt": f"p = {expr}\ng = {gn}\nA = {An}\nB = {Bn}\n".encode()})
                if plain(v):
                    wrong.append((expr, qtext, v))
        v = solve(ask("What is the shared secret?"), {"params.txt": f"p = {pn}\ng = {gn}\nA = {An}\nB = {Bn}\n".encode()})
        if not holds(v, pow(gn, an * bn, pn)):
            wrong.append((expr, "control: literal p", v))
    check("R10 toolkit: p written as `<prime> * 2**k + 1` is never read as its first term (48 instances); the literal p holds the truth",
          not wrong, wrong[:3])
    pg, fsg = smooth_p(10)
    while not all(pow(2, (pg - 1) // f, pg) != 1 for f in fsg):         # 2 a primitive root, so 8 = 2^3 is a generator of an index-3 subgroup
        pg, fsg = smooth_p(10)
    ag, bg = RND.randrange(2, pg - 1), RND.randrange(2, pg - 1)
    wrong = []
    for expr in ("2 ** 3", "2^3", "2*4", "2×4"):
        v = solve(ask("What is the shared secret?"), {"params.txt": f"p = {pg}\ng = {expr}\nA = {pow(8, ag, pg)}\nB = {pow(8, bg, pg)}\n".encode()})
        if plain(v):
            wrong.append((expr, v))
    check("R10 toolkit: g written as `2 ** 3` (true g 8) is never read as g = 2", not wrong, wrong)

    # R10c: a second exchange under numbered labels: which one a question means is not read ----------------------------
    p1, f1 = smooth_p(10)
    p2, f2 = smooth_p(10)
    g1, g2 = primitive_root(p1, f1), primitive_root(p2, f2)
    a1, b1, a2, b2 = (RND.randrange(2, p1 - 1), RND.randrange(2, p1 - 1), RND.randrange(2, p2 - 1), RND.randrange(2, p2 - 1))
    first = f"# first exchange\np = {p1}\ng = {g1}\nA = {pow(g1, a1, p1)}\nB = {pow(g1, b1, p1)}\n"
    wrong = []
    for nm, second in (("A2", f"p2 = {p2}\ng2 = {g2}\nA2 = {pow(g2, a2, p2)}\nB2 = {pow(g2, b2, p2)}\n"),
                       ("A_2", f"p_2 = {p2}\ng_2 = {g2}\nA_2 = {pow(g2, a2, p2)}\nB_2 = {pow(g2, b2, p2)}\n"),
                       ("alice_public_2", f"modulus_2 = {p2}\ngenerator_2 = {g2}\nalice_public_2 = {pow(g2, a2, p2)}\n"
                                          f"bob_public_2 = {pow(g2, b2, p2)}\n")):
        for qtext in ("What is the shared secret?", "What is the shared secret of the exchange that used the larger prime?",
                      "What is the shared secret of the first exchange?", "What is the shared secret of the second exchange?"):
            v = solve(ask(qtext), {"params.txt": (first + "# second exchange\n" + second).encode()})
            if plain(v):
                wrong.append((nm, qtext, v))
    check("R10 toolkit: a delivery with a numbered second exchange (A2, A_2, alice_public_2) answers none of its asks plain", not wrong, wrong)
    v = solve(ask("What is the shared secret?"), {"params.txt": first.encode()})
    check("R10 control: the same delivery with one exchange: the secret first among the candidates", holds(v, pow(g1, a1 * b1, p1)), v)
    # a text past the read limit: a second statement beyond it would go unseen, so nothing is answered from the first
    filler = "note: nothing to see here\n" * 17500                          # 455 KB, under the 512 KB a text file may have
    second_stmt = f"p = {p2}\ng = {g2}\nA = {pow(g2, a2, p2)}\nB = {pow(g2, b2, p2)}\n"
    v = solve(ask("What is the shared secret?"), {"big.txt": (first + filler + second_stmt).encode()})
    check("R10 a text longer than the read limit holding a second exchange past it: never plain", not plain(v), v)
    v = solve(ask("What is the shared secret?"), {"big.txt": (first + filler[:200000]).encode()})
    check("R10 control: the same instance under 200 KB of unrelated lines: the secret first", holds(v, pow(g1, a1 * b1, p1)), v)

    # R11: asks for something computed FROM the number, in words `_DERIVED` does not list -------------------------------
    while True:
        pe, fse = smooth_p(12)
        if pe.bit_length() >= 90:
            break
    ge = primitive_root(pe, fse)
    ae, be = RND.randrange(2, pe - 1), RND.randrange(2, pe - 1)
    Ae, Be = pow(ge, ae, pe), pow(ge, be, pe)
    se = pow(ge, ae * be, pe)
    base_txt = f"p = {pe}\ng = {ge}\nA = {Ae}\nB = {Be}\n"
    shared_bad = ["What is the parity of the shared secret (0 for even, 1 for odd)?", "Is the shared secret a quadratic residue? Answer 1 for yes, 0 for no.",
                  "What is the smallest prime factor of the shared secret?", "What is the negation of the shared secret in the group?",
                  "What is half of the shared secret rounded down?", "What is twice the shared secret?", "What is the shared secret in octal?",
                  "What is the shared secret in base 7?", "What is the shared secret reduced to 32 bits?", "What is the shared secret truncated?",
                  "What is the Hamming weight of the shared secret?", "What is the shared secret's popcount?",
                  "Return the integer logarithm base 2 of the shared secret.", "What is floor(log2(shared secret))?",
                  "What is the shared secret written backwards?", "What is the next prime after the shared secret?",
                  "What is the shared secret as a string of text?", "What is the shared secret in two's complement?",
                  "What is the shared secret exponentiated to the power 2?", "What is the index of the shared secret in the list of residues?",
                  "Alice and Bob derive a key from the shared secret. What is that key?", "What is the number below the shared secret?",
                  "What is the order of the shared secret?", "What is the shared secret's discrete log base 2?"]
    wrong = [t for t in shared_bad if plain(solve(ask(t), {"params.txt": base_txt.encode()}))]
    check(f"R11 {len(shared_bad)} asks for something computed FROM the shared secret: never plain", not wrong, wrong)
    rng_txt = base_txt + "Private exponents are chosen with x < p-1.\n"
    x_bad = ["What is the parity of Alice's private exponent?", "What is the smallest prime factor of Alice's private exponent?",
             "What is Alice's private key in octal?", "What is twice Alice's private exponent?",
             "What is Alice's private key as a Python hex literal?", "What is Alice's private key in base 7?",
             "What is the next prime after Alice's private key?", "What is Alice's private key negated?",
             "What is the order of Alice's private key?"]
    wrong = [t for t in x_bad if plain(solve(ask(t), {"params.txt": rng_txt.encode()}))]
    check(f"R11 {len(x_bad)} asks for something computed FROM the private exponent (range stated): never plain", not wrong, wrong)
    shared_ok = ["What is the shared secret?", "What is the Diffie-Hellman shared secret? Give it in decimal.",
                 "Compute the shared secret s = g^(ab) mod p.", "What is the shared secret value that both parties compute?",
                 "Calculate the shared secret between Alice and Bob.", "Submit the shared secret as a decimal integer.",
                 "Alice and Bob run a Diffie-Hellman exchange. What shared secret do they end up with?",
                 "Alice and Bob perform a Diffie-Hellman exchange over the prime p with generator g. What is the shared secret?",
                 "What is the shared secret of the key exchange?"]
    wrong = [t for t in shared_ok if not holds(solve(ask(t), {"params.txt": base_txt.encode()}), se)]
    check(f"R11 control: {len(shared_ok)} plain asks of the shared secret: the secret first among the candidates", not wrong, wrong)
    x_ok = [("What is Alice's private key?", ae), ("Find Alice's secret exponent a.", ae), ("What is Bob's private exponent?", be),
            ("Find Alice's discrete logarithm to base g.", ae), ("What is the private key of Alice?", ae),
            ("Recover Bob's private key b.", be), ("Find the private exponent of Alice (the discrete log of her public value A).", ae)]
    wrong = [t for t, truth in x_ok if not holds(solve(ask(t), {"params.txt": rng_txt.encode()}), truth)]
    check(f"R11 control: {len(x_ok)} plain asks of a private exponent with its range stated: the exponent first", not wrong, wrong)

    # R11b: the HEAD of the ask is another quantity and the target is only mentioned ----------------------------------
    head_shared = ["What is Bob's public key used to compute the shared secret?", "What is the modulus used in computing the shared secret?",
                   "What is the generator g used to compute the shared secret?", "What does Alice need to compute the shared secret?",
                   "Which exponent is needed to compute the shared secret?",
                   "What is Alice's public value, which Bob uses to compute the shared secret?",
                   "What is the prime p that Alice and Bob use for the shared secret?",
                   "What is the name of the protocol that yields a shared secret?"]
    wrong = [t for t in head_shared if plain(solve(ask(t), {"params.txt": base_txt.encode()}))]
    check(f"R11b {len(head_shared)} asks whose head is another quantity (public key, modulus, generator, ...) that only mention the shared secret: "
          "never plain", not wrong, wrong)
    head_x = ["What is the public key that matches Alice's private key?", "What is the modulus used with Bob's private exponent?",
              "What is the prime p for which Alice's private key was chosen?", "What is the order of the group in which we take the discrete log?"]
    wrong = [t for t in head_x if plain(solve(ask(t), {"params.txt": (base_txt + "Private exponents are chosen with x < p-1.\n").encode()}))]
    check(f"R11b {len(head_x)} asks whose head is another quantity that only mention the private exponent: never plain", not wrong, wrong)
    lead_ok = ["What is the value of the shared secret?", "What is the Diffie-Hellman shared secret value?", "What is Alice and Bob's shared secret?",
               "Give the shared secret.", "Submit the final shared secret as an integer."]
    wrong = [t for t in lead_ok if not holds(solve(ask(t), {"params.txt": base_txt.encode()}), se)]
    check(f"R11b control: {len(lead_ok)} lead-in forms (value of, Diffie-Hellman, Alice and Bob's, final): the secret first", not wrong, wrong)

    # R11c: two things asked in one sentence, a bit count that is a truncation, a head that sits before the verb ---------
    double = ["What is the shared secret and Alice's private key?", "Compute the shared secret value and Bob's private exponent.",
              "Find the shared secret, Alice's private key.", "What is the shared secret value and the private exponent of Alice?"]
    wrong = [t for t in double if plain(solve(ask(t), {"params.txt": rng_txt.encode()}))]
    check(f"R11c {len(double)} questions that ask for the shared secret AND a private exponent in one sentence: never plain", not wrong, wrong)
    bits = ["Give the DH shared secret to 16 bits?", "What is the shared secret to 32 bits?", "Tell me Alice and Bob's shared secret to 16 bits."]
    wrong = [t for t in bits if plain(solve(ask(t), {"params.txt": base_txt.encode()}))]
    wrong += [t for t in ("What is Alice's private key to 16 bits?",) if plain(solve(ask(t), {"params.txt": rng_txt.encode()}))]
    check("R11c a bit count that truncates (`to 16 bits`) is not notation: never plain", not wrong, wrong)
    before_verb = ["Tell me the exchange used to compute the shared secret value.", "What is the exchange that is used to compute the shared secret?",
                   "Find Bob of the shared secret.", "What is A of the shared secret?"]
    wrong = [t for t in before_verb if plain(solve(ask(t), {"params.txt": base_txt.encode()}))]
    check(f"R11c {len(before_verb)} questions whose head stands before the verb that names the target (`... used to compute the shared secret`): "
          "never plain", not wrong, wrong)
    wrong = [t for t in ("What is the shared secret as hex?", "Give the shared secret in hexadecimal.") if solve(ask(t, "integer"), {"params.txt": base_txt.encode()}) is not None
             and plain(solve(ask(t, "integer"), {"params.txt": base_txt.encode()}))]
    check("R11c an integer-kind answer asked in hex: the kind and the words disagree, never plain", not wrong, wrong)
    clause_ok = ["Given p, g, A and B, find the shared secret.", "Using Alice's private key and Bob's public value, compute the shared secret.",
                 "Alice and Bob exchange A and B. What is the shared secret in the file?", "Show the shared secret value (an integer).",
                 "Tell me the shared secret from the transcript.", "Now compute the final shared secret."]
    wrong = [t for t in clause_ok if not holds(solve(ask(t), {"params.txt": base_txt.encode()}), se)]
    check(f"R11c control: {len(clause_ok)} clause forms (given ..., using ..., a preamble sentence, file / transcript): the secret first", not wrong, wrong)
    x_clause_ok = [("Provide Bob's private key b.", be), ("Determine the private key of Bob.", be), ("Given p, g, A and B, find Alice's private exponent.", ae),
                   ("Report Alice's private key a in the file.", ae)]
    wrong = [t for t, truth in x_clause_ok if not holds(solve(ask(t), {"params.txt": rng_txt.encode()}), truth)]
    check(f"R11c control: {len(x_clause_ok)} private-exponent asks (provide / determine / given / in the file) with the range stated: the exponent first", not wrong, wrong)

    # R12: a program in the delivery may reduce, truncate or format the number before it is used ---------------------
    out = base_txt.encode()
    srcs = {"mod2^128": b"shared = pow(B, a, p) % (2 ** 128)\n", "mask": b"shared = pow(B, a, p) & ((1 << 128) - 1)\n",
            "shift": b"shared = pow(B, a, p) >> 64\n", "tobytes": b"key = pow(B, a, p).to_bytes(64, 'big')[:16]\n",
            "slice": b"shared = str(pow(B, a, p))[:16]\n", "plain": b"shared = pow(B, a, p)\nprint(shared)\n"}
    wrong, noholds = [], []
    for nm, src in srcs.items():
        fl = {"chall.py": src, "output.txt": out}
        v = solve(ask("What is the shared secret?"), fl)
        if plain(v):
            wrong.append(nm)
        elif not holds(v, se):
            noholds.append((nm, v))
        v = solve(ask("What is Alice's private key?"), {"chall.py": src, "output.txt": rng_txt.encode()})
        if plain(v):
            wrong.append(nm + " (private key)")
    check("R12 a program in the delivery (truncation, mask, shift, slice, plain print): the shared secret and the private exponent are never plain",
          not wrong, wrong)
    check("R12 ... and the number is still offered as an unsure pick, so a probe on the untimed base can settle it", not noholds, noholds)
    v = solve(ask("What is the shared secret?"), {"README.txt": b"Alice and Bob exchange public values.\n", "output.txt": out})
    check("R12 control: data files only (no program): the secret first among the candidates", holds(v, se), v)
    wrong = [prose for prose in ("The shared secret is reduced modulo 2^64 before it is used.",
                                 "The session key is the lower 128 bits of the shared secret.",
                                 "Only the first 16 bytes of the shared secret are kept.",
                                 "Both sides hash the shared value with SHA-256 and keep the digest.")
             if plain(solve(ask("What is the shared secret?"), {"README.txt": prose.encode(), "output.txt": out}))]
    check("R12 prose that says the secret is reduced, cut or hashed (no program in the delivery): never plain", not wrong, wrong)

    # R13 (fix round 4): the round-2 keys are gone, and nothing the judge accepts for one key answers another instance ----------
    if tk.labels is not None:
        for old in ("modern_crypto.dh_shared/zp", "modern_crypto.dlog_x/least_residue", "modern_crypto.dlog_x/unique",
                    "modern_crypto.elgamal_m/zp", "modern_crypto.plaintext/elgamal", "modern_crypto.dh_shared/zp+src",
                    "modern_crypto.dh_shared/zp+key"):
            tk.labels.learn(old, "decimal", "accepted", scope="key", attempt_id="r13", answer_ids=["m"], left=None)
        notplain = []
        for nm, qtext, fl in (("session key", "What is the session key?", {"params.txt": base_txt.encode()}),
                              ("program", "What is the shared secret?", {"chall.py": srcs["mod2^128"], "output.txt": out}),
                              ("parity", "What is the parity of the shared secret?", {"params.txt": base_txt.encode()}),
                              ("octal", "What is the shared secret in octal?", {"params.txt": base_txt.encode()}),
                              ("plain ask", "What is the shared secret?", {"params.txt": base_txt.encode()}),
                              ("exponent", "What is Alice's private key?", {"params.txt": rng_txt.encode()})):
            v = solve(ask(qtext), fl)
            if plain(v) or v is None or not opts(v):
                notplain.append((nm, str(v)[:90]))
        check("R13 with `decimal` accepted for every key of rounds 1 to 3 (dh_shared/zp, +src, +key, dlog_x/least_residue, dlog_x/unique, "
              "elgamal_m/zp, plaintext/elgamal): nothing is plain, every answer is a candidate pick under an instance key", not notplain, notplain)
        # the key is the instance's own: the same question on the same delivery has the same key; another wording, another delivery
        # (one comment more), another answer format each have another
        v1 = solve(ask("What is the shared secret?"), {"params.txt": base_txt.encode()})
        v1b = solve(ask("What is the shared secret?"), {"params.txt": base_txt.encode()})
        v2 = solve(ask("What is the shared secret?"), {"params.txt": (base_txt + "# again\n").encode()})
        v3 = solve(ask("What is the shared secret value?"), {"params.txt": base_txt.encode()})
        v4 = solve(ask("What is the shared secret?", kind="exact_text"), {"params.txt": base_txt.encode()})
        k1, k1b, k2, k3, k4 = (tk.labels.parse(v).key for v in (v1, v1b, v2, v3, v4))
        check("R13 the candidate key is the instance's: the same question and delivery the same key; another delivery, wording or format another",
              k1 == k1b and len({k1, k2, k3, k4}) == 4 and all("@inst-" in k_ and k_.endswith("#candidates") for k_ in (k1, k2, k3, k4)),
              (k1, k2, k3, k4))
    v = solve(ask("What is the shared secret?"), {"README.txt": b"The shared secret is 256 bits long. Alice and Bob each pick a random exponent.\n", "output.txt": out})
    check("R12 control: prose that only describes the size of the secret (`256 bits long`) is not a derivation: the secret first", holds(v, se), v)

    # R14: an ElGamal plaintext whose pattern fits is plain only for a plain ask of it ------------------------------------
    msg = b"flag{elgamal_round_two}"
    mm = int.from_bytes(msg, "big")
    while True:
        p4, fs4 = smooth_p(12)
        if p4 > mm * 4 and p4.bit_length() > 8 * len(msg) + 4:
            break
    g4 = primitive_root(p4, fs4)
    x4 = RND.randrange(2, p4 - 1)
    h4 = pow(g4, x4, p4)
    k4 = RND.randrange(2, p4 - 1)
    c1, c2 = pow(g4, k4, p4), mm * pow(h4, k4, p4) % p4
    fl4 = {"challenge.txt": f"p = {p4}\ng = {g4}\nh = {h4}\nciphertext = ({c1}, {c2})\n".encode()}
    pat = {"kind": "exact_text", "pattern": r"flag\{[a-z_]+\}"}

    def qpat(text):
        return {"id": "m", "qid": "m", "answer_id": "m", "question": text, "answer_format": dict(pat)}

    v = solve(qpat("Decrypt the ElGamal ciphertext. What is the flag?"), fl4)
    check("R14 control: the plain ask of the plaintext, a specific pattern: the flag first among the candidates", holds(v, msg.decode()), v)
    wrong = [t for t in ("Decrypt the ElGamal ciphertext. What is the ROT13 of the flag?", "Decrypt the ElGamal ciphertext. What is the flag reversed?",
                         "Decrypt the ElGamal ciphertext. What is the flag with its words swapped?",
                         "Decrypt the ElGamal ciphertext. What is the flag in uppercase?") if plain(solve(qpat(t), fl4))]
    check("R14 a transform of the plaintext asked in words the denylist lacks (ROT13, swapped): never plain", not wrong, wrong)
    msg2 = b"flag{another_message_x}"
    k5 = RND.randrange(2, p4 - 1)
    c1b, c2b = pow(g4, k5, p4), int.from_bytes(msg2, "big") * pow(h4, k5, p4) % p4
    fl5 = {"challenge.txt": f"p = {p4}\ng = {g4}\nh = {h4}\nc1 = {c1}\nc2 = {c2}\nc1_2 = {c1b}\nc2_2 = {c2b}\n".encode()}
    wrong = [t for t in ("Decrypt the second ElGamal message. What is the flag?", "Decrypt the ElGamal ciphertext. What is the flag?",
                         "Decrypt the other ElGamal ciphertext. What is the flag?") if plain(solve(qpat(t), fl5))]
    check("R14 two ciphertexts, the second under numbered labels (c1_2, c2_2): which one is meant is not read, never plain", not wrong, wrong)


def ask2(question, kind="integer", aid="m", **fmt):
    f = {"kind": kind}
    f.update(fmt)
    return {"id": aid, "qid": aid, "answer_id": aid, "question": question, "answer_format": f}


def mk_instance(nfac=12, minbits=90, sub=False):
    """A Diffie-Hellman instance with known secrets over a smooth p; `sub`: g generates the subgroup of the largest prime order q."""
    while True:
        p, fs = smooth_p(nfac, maxbits=17)
        if p.bit_length() >= minbits:
            break
    g0 = primitive_root(p, fs)
    q = max(fs) if sub else None
    g = pow(g0, (p - 1) // q, p) if sub else g0
    o = q if sub else p - 1
    a, b = RND.randrange(2, o), RND.randrange(2, o)
    return {"p": p, "g": g, "q": q, "o": o, "a": a, "b": b, "A": pow(g, a, p), "B": pow(g, b, p), "s": pow(g, a * b, p), "fs": fs}


def fix1_tests():
    """Review of 95699e2 (the KB-10 head after round 2d, fix round 3): one block per issue the second verifier's pass forced. Every
    decoy gives None or an unsure pick, never a plain value (a wrong plain costs the whole batch); every control holds the truth (since fix
    round 4 as the first candidate, never plain).

      R15 a preamble that names the target, then an ask for another quantity (122 of 128 such questions went out plain)
      R16 the question names an operand the router does not read: c1, a ciphertext, a number, a pair, a Pedersen commitment, base A
      R17 roles stay apart: client / server are not the bare A / B; a JSON key that names a role
      R18 operators and shifts on the number asked (>>, <<, &, |, % 2**N, // 2^N, xor, ...)
      R19 an expression OF the target is asked (g^x where x is the private key)
      R20 a range counts for the variable it is stated about and for no other
      R21 a name the judge accepted never makes another delivery's value plain
      R22 time: a Proth prime, 250 prime factors, a labelled megabyte, the set's other questions
      R23 the library: orders and cofactor powers against a naive reference; classic Pohlig-Hellman sizes
      R24 a question fuzz with ground truth (preambles, operands, operators, roles, ranges, imperatives, yes/no, hypotheticals)
      R25 the vocabulary salad: verb-less asks, a formula target and a party against an exponent letter bind or decline
      R26 the layers one at a time (`_dlog_target`, `_dlog_bind` called directly): two asks, a verb-less multi-clause ask, another base
    """
    import hashlib

    def plain(v):
        return v is not None and not unsure(v)

    def wrong_plain(cases, files, label, kind="integer", strict=False, **fmt):
        """cases: [(question, truth or None)]; a plain answer must equal the truth (None: no plain answer is right), and since fix round 4
        none is plain at all. strict: the router must answer None (not even an unsure pick that holds another quantity's value): the
        layer that says so is tested alone."""
        bad = []
        for text, truth in cases:
            v = solve(ask2(text, kind, **fmt), files)
            if strict and v is not None and not (plain(v) and truth is not None and v == str(truth)):
                bad.append((text[:70], str(v)[:30]))
            elif not strict and plain(v) and (truth is None or v != str(truth)):
                bad.append((text[:70], str(v)[:30]))
        check(f"{label}: {len(cases)} questions, {'None' if strict else 'no wrong plain answer'}", not bad, bad[:3])

    I = mk_instance()
    p, g, a, b, A, B, s = I["p"], I["g"], I["a"], I["b"], I["A"], I["B"], I["s"]
    base_txt = f"p = {p}\ng = {g}\nA = {A}\nB = {B}\n"
    rng_txt = base_txt + "Private exponents are chosen with x < p-1.\n"
    F, FR = {"params.txt": base_txt.encode()}, {"params.txt": rng_txt.encode()}

    # R15: a preamble that names the target, then an ask for another quantity --------------------------------------------------
    pre = ["The shared secret is known to both parties.", "The shared secret is computed by Alice and Bob.",
           "The Diffie-Hellman shared secret is the value both parties agree on.", "The shared secret is unknown.", "The shared secret is not given in the file.",
           "g^(ab) mod p is the shared secret.", "Alice's private key is unknown.", "Bob's private exponent is random.", "Alice's secret exponent is hidden."]
    asks = [("What is the generator?", g), ("What is the generator g?", g), ("What is the prime modulus?", p), ("What is the modulus p?", p),
            ("What is Bob's public value?", B), ("What is Alice's public key?", A), ("Give the prime p.", p), ("Submit the generator.", g),
            ("Report the group's prime.", p), ("Tell me Alice's public value A.", A), ("Determine the modulus.", p), ("State the base g.", g),
            ("Identify the generator.", g), ("Which prime is used?", p), ("Reveal Bob's public value.", B)]
    cases = [(t, tv) for pr_ in pre for q_, tv in asks for t in (f"{pr_} {q_}", f"{q_} {pr_}", f"{pr_}\n{q_}")]
    wrong_plain(cases, FR, f"R15 preamble that names the target, then an ask for another quantity ({len(cases)} questions)", strict=True)
    twoasks = [(f"{lead} the shared secret{glue}{other}.", None) for lead in ("Find", "Give", "Compute", "Provide", "What is", "Report", "Determine", "Submit")
               for other in ("the generator", "the modulus", "Bob's public key", "the prime p")
               for glue in (" and ", ", then ", " along with ", ", and also ", " or ")]
    twoasks += [(f"{lead} {other}{glue}the shared secret.", None) for lead in ("Find", "Give", "Compute", "What is")
                for other in ("the generator", "the prime p") for glue in (" and ", ", then ", ", and also ")]
    wrong_plain(twoasks, F, "R15 two things asked in one sentence (the shared secret and another quantity)")
    imper = [(f"{imp} {other}. {tail}", None) for imp in ("Get", "Make", "Run", "Perform", "Carry", "Reach", "Use", "Answer", "Share", "Agree", "Yield", "Come")
             for other in ("the generator", "the prime p", "Bob's public key") for tail in ("What is the shared secret?", "Find the shared secret.")]
    imper += [(f"What is the shared secret? {imp} the generator.", None) for imp in ("Get", "Use", "Share", "Answer", "Run")]
    wrong_plain(imper, F, "R15 an imperative the plain-ask vocabulary allows but the ask search did not know (Get, Share, Use ...)", strict=True)
    yesno = [(t, None) for t in ("Is the shared secret the generator?", "Is the shared secret odd?", "Does the shared secret equal the generator?",
                                 "Was the shared secret computed by Alice?", "Can the shared secret be the generator?", "Has the shared secret been computed?")]
    wrong_plain(yesno, F, "R15 yes / no questions (no number answers them)", strict=True)
    sem = [(t, None) for t in ("What would the shared secret be if Bob's key were Alice's?", "If Bob's public key were Alice's, what is the shared secret?",
                               "What is the shared secret if Bob's key were Alice's?", "What is not the shared secret?", "What could the shared secret have been?",
                               "What is the shared secret, not the generator?", "What is the shared secret unless Alice cheats?",
                               "Which value is not the shared secret?", "What is neither the generator nor the shared secret?",
                               "What is the shared secret without Bob?")]
    wrong_plain(sem, F, "R15 hypotheticals, negations and `without` over allowed words")
    greek = [(t, None) for t in ("What is the shared secret β?", "What is the shared secret α?", "Give the shared secret ω.", "What is the shared secret Δ?")]
    wrong_plain(greek, F, "R15 a Greek symbol after the target is no word of the vocabulary and no symbol of the instance", strict=True)
    ctl = ["The shared secret is known to both parties. What is the shared secret?", "Alice and Bob run a Diffie-Hellman exchange. What shared secret do they end up with?",
           "What is the shared secret? Give it in decimal.", "What is the shared secret K?", "Find the shared secret S.", "Given p, g, A and B, find the shared secret."]
    wrong = [t for t in ctl if not holds(solve(ask2(t), F), s)]
    check(f"R15 control: {len(ctl)} plain asks (a preamble that names the target included): the secret first among the candidates", not wrong, wrong)

    # R16: the question names an operand the router does not read --------------------------------------------------------------
    x = RND.randrange(2, p - 1)
    h_ = pow(g, x, p)
    k = RND.randrange(2, p - 1)
    msg = RND.randrange(2, p - 1)
    c1, c2 = pow(g, k, p), msg * pow(h_, k, p) % p
    FE = {"params.txt": (f"p = {p}\ng = {g}\nh = {h_}\nc1 = {c1}\nc2 = {c2}\nThe private key satisfies x < p-1 and the ephemeral key k < p-1.\n").encode()}
    wrong_plain([("What is the discrete log of c1 to base g?", k), ("What is the discrete logarithm of c1?", k), ("Find the discrete log of c1.", k),
                 ("Find the discrete log of c2 to base g.", None), ("What is the discrete log of the ciphertext?", None),
                 ("Find the discrete log x of the ephemeral key.", k), ("What is the discrete log of the nonce?", None), ("Find the discrete log of C.", None),
                 ("What is the discrete log of the commitment?", None), ("Find the discrete log of k.", None)], FE, "R16 an ElGamal file, the discrete log of another operand", strict=True)
    v = solve(ask2("What is the private key x?"), FE)
    check("R16 control: the ElGamal file's private key x, its range stated: x first among the candidates", holds(v, x), v)
    wrong_plain([("Find x such that g^x = c1 mod p, where x < p-1.", k), ("Find x such that g^x = c2 mod p, where x < p-1.", None), ("Find k such that g^k = c1 (mod p).", k),
                 ("Solve g^x = C mod p for x.", None), ("Find x such that h^x = g mod p, where x < p-1.", None), ("Solve for x in g^x = H (mod p).", None),
                 ("Find x such that g^x = k mod p.", k), ("Find k such that c1 = g^k mod p.", k), ("Find x such that c2 = g^x mod p.", None),
                 ("Find x such that C = g^x mod p.", None), ("Find x such that h = B^x mod p.", None)],
                FE, "R16 the discrete-log equation (either way round) names another operand on a side, or another base", strict=True)
    wrong = [t for t in ("Find x such that g^x = h mod p, where x < p-1.", "Find x such that g^x = y mod p.", "Solve for x in g^x = h (mod p).",
                         "Find x such that h = g^x mod p, where x < p-1.", "Find x such that y = g^x (mod p).")
             if not holds(solve(ask2(t), FE), x)]
    check("R16 control: the equation whose right-hand side is the public key (h, y) stays the problem: x first", not wrong, wrong)
    n42 = pow(g, 4242, p)
    wrong_plain([(f"Find x such that g^x = {n42} mod p, where x < p-1.", 4242), (f"What is the discrete log of {n42} to base g? It satisfies x < p-1.", 4242),
                 (f"Find the discrete log of {n42}.", 4242), (f"Find x such that g^x = {n42} (mod p).", 4242), (f"What is the discrete log of 123456789012?", None)],
                FE, "R16 a target number the question states that the material does not hold", strict=True)
    d1, d2 = pow(g, k + 1, p), (msg + 1) * pow(h_, k + 1, p) % p
    msgb = b"flag{first_message_here}"
    mm = int.from_bytes(msgb, "big")
    while True:
        pe, fse = smooth_p(16, maxbits=17)
        if pe.bit_length() > 8 * len(msgb) + 8:
            break
    ge = primitive_root(pe, fse)
    xe, ke, ke2 = RND.randrange(2, pe - 1), RND.randrange(2, pe - 1), RND.randrange(2, pe - 1)
    he = pow(ge, xe, pe)
    e1, e2 = pow(ge, ke, pe), mm * pow(he, ke, pe) % pe
    m2b = int.from_bytes(b"flag{second_message_xyz}", "big")
    f1, f2 = pow(ge, ke2, pe), m2b * pow(he, ke2, pe) % pe
    FD = {"challenge.txt": f"p = {pe}\ng = {ge}\nh = {he}\nc1 = {e1}\nc2 = {e2}\n".encode()}
    pat = {"pattern": r"flag\{[a-z_]+\}"}
    wrong_plain([(f"Decrypt the ElGamal ciphertext ({f1}, {f2}). What is the flag?", None), (f"The second ElGamal ciphertext is ({f1}, {f2}). Decrypt it: what is the flag?", None),
                 (f"Decrypt c1 = {f1}, c2 = {f2}. What is the flag?", None), ("Decrypt the second ElGamal ciphertext. What is the flag?", None)],
                FD, "R16 a ciphertext the question states that the material does not hold", kind="exact_text", strict=True, **pat)
    v = solve(ask2("Decrypt the ElGamal ciphertext. What is the flag?", "exact_text", **pat), FD)
    check("R16 control: the material's own ciphertext, a specific pattern: the flag first among the candidates", holds(v, msgb.decode()), v)
    v = solve(ask2(f"Decrypt the ElGamal ciphertext ({e1}, {e2}). What is the flag?", "exact_text", **pat), FD)
    check("R16 the question restates the material's own ciphertext: never a wrong plain", not plain(v) or v == msgb.decode(), v)
    # a Pedersen commitment C = g^m h^r over a subgroup: `the secret value` is m, never log_g(h)
    Ic = mk_instance(sub=True)
    pc, gc, qc = Ic["p"], Ic["g"], Ic["q"]
    t_ = RND.randrange(2, qc)
    hc = pow(gc, t_, pc)
    mc, rc = RND.randrange(2, qc), RND.randrange(2, qc)
    Cc = pow(gc, mc, pc) * pow(hc, rc, pc) % pc
    FC = {"commit.txt": f"p = {pc}\nq = {qc}\ng = {gc}\nh = {hc}\nC = {Cc}\nPrivate exponents satisfy x < q.\n".encode()}
    wrong_plain([("What is the secret value? It is less than q.", mc), ("What is the secret value m? The secret value is less than q.", mc),
                 ("Find the discrete log.", t_), ("What is the private key?", t_)], FC, "R16 a Pedersen commitment beside the instance (x < q stated, so log_g(h) would be plain)", strict=True)
    v = solve(ask2("What is the discrete log of h to base g? It is less than q."), FC)
    check("R16 control: the same file, the operand named (h): never plain (a candidate pick or None)", not plain(v), v)
    FCs = {"commit.txt": f"p = {pc}\nq = {qc}\ng = {gc}\nh = {hc}\nPrivate exponents satisfy x < q.\n".encode()}
    v = solve(ask2("What is the secret value?"), FCs)
    check("R16 control: without the commitment C the single public value is the one asked about: its log first", holds(v, t_), v)
    wrong_plain([("What is the discrete log of g to base A?", None), ("Find the discrete log of A to base B.", None), ("What is the discrete log of A in base 16?", None),
                 ("What is the discrete log of g with respect to A?", None), ("What is the discrete log of A to base h?", None)], FR, "R16 a logarithm in a base that is not g", strict=True)
    wrong_plain([("What is the shared secret for a = 5 and b = 7?", pow(g, 35, p)), ("What is the shared secret when a = 12345 and b = 67890?", pow(g, 12345 * 67890, p)),
                 (f"What is the shared secret given a = {a + 1}?", None), (f"What is Alice's private key given a = {a + 1}?", None),
                 ("What is the shared secret when a = 5?", None), ("Compute the shared secret given b = 7.", None), ("What is Alice's private key given a = 5?", None),
                 ("What is the shared secret if a = 3?", None), ("What is Bob's private key given b = 9?", None)], FR,
                "R16 the question restates a private value (even one digit: `when a = 5`) that the public values do not reproduce", strict=True)
    v = solve(ask2(f"What is the shared secret given a = {a}?"), F)
    check("R16 control: a restated private value that DOES reproduce A: the shared secret first", holds(v, s), v)
    # the material states a group element the instance does not read: which pair or value is asked is not known (None), the pair named is
    unread_f = {"p.txt": (rng_txt + f"T = {pow(g, RND.randrange(2, p - 1), p)}\n").encode()}
    wrong_plain([("What is the shared secret?", None)], unread_f, "R16 a labelled group element beside A and B that nothing reads (T): which pair is asked is not known", strict=True)
    v1, v2 = solve(ask2("What is Alice's private key?"), unread_f), solve(ask2("What is the discrete log of A?"), unread_f)
    check("R16 control: ... but a private exponent whose party or public value the question NAMES: its log first", holds(v1, a) and holds(v2, a), (v1, v2))
    one_pub = {"p.txt": (f"p = {p}\ng = {g}\nA = {A}\nPrivate exponents are chosen with x < p-1.\n").encode()}
    wrong_plain([("What is the sender's private key?", a), ("What is the receiver's private key?", a), ("What is the peer's private key?", a)],
                one_pub, "R16 a party word that names no slot over a single public value A: no slot is that party's", strict=True)
    check("R16 control: the same single public value, no party named: its log first", holds(solve(ask2("What is the private key?"), one_pub), a), solve(ask2("What is the private key?"), one_pub))
    wrong_plain([(f"What is the shared secret of {p} and {B}?", None), (f"What is the shared secret of {A + 1} and {B}?", None)],
                F, "R16 long numbers asked inside the ask that are not the public values", strict=True)
    wrong_plain([(f"What is the shared secret of {g} and {B}?", None), (f"What is the shared secret of 5 and {B}?", None), (f"What is the shared secret of 7 and 11?", None)], F, "R16 short numbers asked inside the ask (g's value, a toy value)")

    # R17: roles stay apart ---------------------------------------------------------------------------------------------------
    srv, cli = a, b
    ftext = (f"p = {p}\ng = {g}\n# the server sends its public value first\nA = {A}\n# then the client answers with its own\nB = {B}\n"
             "Private exponents are chosen with x < p-1.\n")
    FT = {"transcript.txt": ftext.encode()}
    wrong_plain([("What is the server's private key?", srv), ("What is the client's private key?", cli), ("Find the private exponent of the server.", srv),
                 ("What is the sender's private key?", None), ("What is the receiver's private key?", None), ("What is the peer's private key?", None),
                 ("What is Alice's private key?", None), ("What is Bob's private key?", None)],
                FT, "R17 bare A / B labels in a transcript whose prose names a server and a client (the first value is the server's): no party's key is plain", strict=True)
    js = '{"p": %d, "g": %d, "server": {"A": %d}, "client": {"B": %d}, "note": "x < p-1"}' % (p, g, A, B)
    wrong_plain([("What is the server's private key? It satisfies x < p-1.", srv), ("What is the client's private key? It satisfies x < p-1.", cli)],
                {"t.json": js.encode()}, "R17 JSON keys that name a role (`{\"server\": {\"A\": ...}}` is no bare A)", strict=True)
    js2 = '{"p": %d, "g": %d, "client_public": %d, "server_public": %d, "note": "x < p-1"}' % (p, g, A, B)
    v1 = solve(ask2("What is the client's private key? It satisfies x < p-1."), {"t.json": js2.encode()})
    v2 = solve(ask2("What is the server's private key? It satisfies x < p-1."), {"t.json": js2.encode()})
    check("R17 control: labelled client_public / server_public: each role's own slot first", holds(v1, a) and holds(v2, b), (v1, v2))
    v = solve(ask2("What is the shared secret of the key exchange?"), {"t.json": js2.encode()})
    check("R17 control: the client / server pair gives the shared secret first", holds(v, s), v)
    FAB = {"params.txt": (f"prime = {p}\ngenerator = {g}\nalice_public = {A}\nbob_public = {B}\n" + "Private exponents are chosen with x < p-1.\n").encode()}
    wrong_plain([("What is the client's private key?", None), ("What is the server's private key?", None)], FAB, "R17 Alice / Bob labels and a question about client / server", strict=True)
    v = solve(ask2("What is Alice's private key?"), FAB)
    check("R17 control: alice_public and the question names Alice: her log first", holds(v, a), v)
    wrong_plain([("Alice and Bob exchange A and B. What is Alice's private key?", None), ("What is Alice's private key? Bob also has one.", None)], FR,
                "R17 both parties named in a question about one of them", strict=True)
    both = {"t.json": ('{"p": %d, "g": %d, "client_public": %d, "server_public": %d, "A": %d, "B": %d}' % (p, g, B, A, A, B)).encode()}
    v = solve(ask2("What is the shared secret?"), both)
    check("R17 two different pairs (A / B and client / server swapped): which one is asked is not known, never plain", not plain(v), v)

    # R18: operators and shifts on the number asked ---------------------------------------------------------------------------
    ops = [(">> 64", lambda v: v >> 64), ("<< 3", lambda v: v << 3), ("& 65535", lambda v: v & 65535), ("| 1", lambda v: v | 1), ("% 2**64", lambda v: v % (1 << 64)),
           ("% 2^32", lambda v: v % (1 << 32)), ("// 2^32", lambda v: v >> 32), ("+ 1", lambda v: v + 1), ("- 1", lambda v: v - 1), ("* 2", lambda v: v * 2),
           ("/ 2", lambda v: v // 2), ("^ 5", lambda v: v ^ 5), ("xor 255", lambda v: v ^ 255), ("mod 1000", lambda v: v % 1000), ("% 1000", lambda v: v % 1000),
           ("× 2", lambda v: v * 2), ("÷ 2", lambda v: v // 2), ("⊕ 7", lambda v: v ^ 7), ("**2", lambda v: v * v), ("squared", lambda v: v * v)]
    for sub, val, fl in (("the shared secret", s, F), ("Alice's private key", a, FR), ("Bob's private key", b, FR)):
        cases = []
        for sym, fn in ops:
            tv = fn(val)
            if tv == val:
                continue
            cases += [(t, tv) for t in (f"What is {sub} {sym}?", f"Give {sub} {sym}.", f"What is ({sub}) {sym}?", f"What is {sub}? Submit it as s {sym}.")]
        wrong_plain(cases, fl, f"R18 an operator on {sub}", strict=True)
    wrong_plain([("What is the discrete log of A >> 64?", None), ("Find x % 2**128 such that g^x = A mod p.", None)], FR, "R18 an operator on the logarithm asked", strict=True)
    wrong = [t for t in ("Compute the shared secret s = g^(ab) mod p.", "What is the shared secret? (s = g^(ab) mod p)", "Find the shared secret K = g^(ab) mod p.")
             if not holds(solve(ask2(t), F), s)]
    check("R18 control: the shared-secret formula written out: the secret first", not wrong, wrong)
    wrong_plain([("What is g^(ab+1) mod p?", None), ("Compute g^(ab*2) mod p.", None), ("What is g^(ab+a) mod p?", None)], F, "R18 an exponent that only starts like g^(ab)", strict=True)

    # R19: an expression OF the target is asked ---------------------------------------------------------------------------------
    wrong_plain([("What is g^x where x is Alice's private key?", A), ("What is g^x where x is Bob's private key?", B),
                 ("What is A^x mod p, where x is Bob's private key?", pow(A, b, p)), ("What is g^(2x) mod p, where x is Alice's private key?", pow(g, 2 * a, p)),
                 ("What is 2^x mod p where x is Bob's private key?", pow(2, b, p)), ("What is x^2 where x is Alice's private key?", a * a),
                 ("What is x+1 where x is Alice's private key?", a + 1)], FR, "R19 an expression of the private key", strict=True)
    wrong_plain([("What is g raised to Alice's private key?", A)], FR, "R19 an expression of the private key in words")
    check("R19 the `x` alternative of the target regex reaches only lead-in words: an expression of x is never the target",
          tk._dlog_target("What is g^x where x is Alice's private key?") in (None, "priv")
          and solve(ask2("What is g^x where x is Alice's private key?"), FR) is None and tk._dlog_target("What is x?") == "priv")
    Fh = {"y.txt": (f"p = {p}\ng = {g}\nh = {A}\nThe exponent satisfies x < p-1.\n").encode()}
    wrong = [t for t in ("Find x such that g^x = h mod p.", "Solve for x in g^x = h (mod p).", "Find the discrete log x of h to base g.") if not holds(solve(ask2(t), Fh), a)]
    check("R19 control: the statement's own g^x = h mod p is still the problem: x first among the candidates", not wrong, wrong)

    # R20: a range counts for the variable it is stated about and for no other ----------------------------------------------------
    while True:
        ab_ = RND.getrandbits(p.bit_length() + 8)
        bb_ = RND.getrandbits(p.bit_length() + 8)
        if ab_ >= p - 1 and bb_ >= p - 1:
            break
    Ab_, Bb_ = pow(g, ab_, p), pow(g, bb_, p)
    notes = ["", "# a = getrandbits(p.bit_length() + 8)\n", "# k = randrange(2, p-1)   (the ephemeral key)\n", "# a = getrandbits(p.bit_length() + 8)\n# k = randrange(2, p-1)   (the ephemeral key)\n",
             "The ephemeral exponent b is drawn with b < p-1; Alice's a is a 72-bit random number.\n", "The nonce k < p-1.\n", "Bob's key is below p-1.\n",
             "The server's private key is below p-1.\n", "Eve's private key is less than p-1.\n", "y = randrange(2, p-1)\n", "A < p-1.\n", "The public value A is less than p-1.\n",
             "The ephemeral exponent is below p-1.\n", "The shared secret is below p-1.\n", "The session key is less than p-1.\n", "x is Alice's secret, x < p-1.\n",
             "# b_priv = randrange(2, p-1)\n", "priv_b = randint(1, p-1)\n"]
    bad = []
    for note in notes:
        Fb = {"p.txt": (f"p = {p}\ng = {g}\nA = {Ab_}\nB = {Bb_}\n{note}").encode()}
        for text, tv in (("What is Alice's private key?", ab_), ("What is Alice's private key a?", ab_), ("Find Alice's private exponent.", ab_)):
            v = solve(ask2(text), Fb)
            if plain(v) and v != str(tv):
                bad.append((note[:50], text))
        if not note.startswith(("# b_priv", "priv_b")):
            v = solve(ask2("What is Bob's private key?"), Fb)
            if plain(v) and v != str(bb_):
                bad.append((note[:50], "Bob"))
    check(f"R20 secrets above p-1 (a primitive root) beside a range stated for ANOTHER variable ({len(notes)} notes): never plain", not bad, bad[:3])
    Is = mk_instance(sub=True)
    ps, gs, qs_ = Is["p"], Is["g"], Is["q"]
    while True:
        af, bf = RND.randrange(2, ps - 2), RND.randrange(2, ps - 2)
        if af >= qs_ and bf >= qs_:
            break
    bs_ = RND.randrange(2, 1 << 8)
    As_, Bs_ = pow(gs, af, ps), pow(gs, bs_, ps)
    bad = []
    for note in ("", "b is drawn with b < p-1.\n", "The sender's private key is less than 2^15.\n", "The exponent b < 256.\n", "k_priv = randrange(2, p-1)\n"):
        Fs = {"p.txt": (f"p = {ps}\ng = {gs}\nA = {As_}\nB = {Bs_}\n{note}").encode()}
        v = solve(ask2("What is Alice's private key a?"), Fs)
        if plain(v) and v != str(af):
            bad.append((note[:40], "Alice"))
    for qtext in ("Find Bob's private key. The sender's private key is less than 2^15.", "Find Bob's private key. Alice's private key is less than 2^15."):
        v = solve(ask2(qtext), {"p.txt": (f"p = {ps}\ng = {gs}\nA = {As_}\nB = {Bs_}\n").encode()})
        if plain(v) and v != str(bs_):
            bad.append((qtext[:50], "Bob"))
    check("R20 a subgroup generator, a bound stated for another party in the QUESTION: never a wrong plain", not bad, bad[:3])
    wrong = []
    for note, who, tv in (("a_priv = random.randrange(2, p-1)\n", "Alice", a), ("b = random.randrange(2, p-1)\n", "Bob", b), ("alice_secret = randrange(2, p-1)\n", "Alice", a),
                          ("bob_priv = randint(1, p-2)\n", "Bob", b), ("Private exponents are chosen with x < p-1.\n", "Alice", a),
                          ("The secret is generated as random.randrange(2, p-1).\n", "Bob", b), ("The private key is less than p-1.\n", "Alice", a)):
        v = solve(ask2(f"What is {who}'s private key?"), {"p.txt": (base_txt + note).encode()})
        if not holds(v, tv):
            wrong.append((note[:40], who, str(v)[:20]))
    check("R20 control: a range stated for the asked party's own variable (or in general): the exponent first among the candidates", not wrong, wrong)

    # R21 (fix round 4): a name the judge accepted answers plain only the very instance it was accepted on (a replay) ----------------
    if tk.labels is not None:
        while True:
            pk, fk = smooth_p(14, maxbits=17)
            if pk.bit_length() >= 200:
                break
        gk = primitive_root(pk, fk)
        ak, bk = RND.randrange(2, pk - 1), RND.randrange(2, pk - 1)
        Ak, Bk = pow(gk, ak, pk), pow(gk, bk, pk)
        sk = pow(gk, ak * bk, pk)
        outk = f"p = {pk}\ng = {gk}\nA = {Ak}\nB = {Bk}\n".encode()
        src_hash = b"from hashlib import sha256\nshared = pow(B, a, p)\nsession_key = sha256(str(shared).encode()).hexdigest()\n"
        src_trunc = b"shared = pow(B, a, p) % (2 ** 128)\n"

        def key_of(v):
            return tk.labels.parse(v).key if unsure(v) else None

        def learn_first(v):
            """The judge accepts the first option of v's key (as tools/verify.py records it after an accepted probe)."""
            if not opts(v):
                check("R21 the delivery's first answer is a candidate pick with a key to accept a name for", False, v)
                return
            tk.labels.learn(key_of(v), opts(v)[0][0], "accepted", scope="key", attempt_id="r21", answer_ids=["m"], left=None)

        qs_ = ask2("What is the shared secret?")
        va = solve(qs_, {"output.txt": outk})
        learn_first(va)
        check("R21 control: the delivery the name was accepted on gives the accepted value plain again (a replay)",
              solve(qs_, {"output.txt": outk}) == str(sk), solve(qs_, {"output.txt": outk}))
        others = (("another wording", ask2("What is the shared secret value?"), {"output.txt": outk}),
                  ("a session key", ask2("What is the session key?"), {"output.txt": outk}),
                  ("a program that hashes", qs_, {"chall.py": src_hash, "output.txt": outk}),
                  ("a program that truncates", qs_, {"chall.py": src_trunc, "output.txt": outk}),
                  ("one comment more", qs_, {"output.txt": outk + b"# note\n"}),
                  ("another file name", qs_, {"params.txt": outk}),
                  ("another answer format", ask2("What is the shared secret?", "exact_text"), {"output.txt": outk}),
                  ("another instance", qs_, {"output.txt": f"p = {pk}\ng = {gk}\nA = {Bk}\nB = {pow(gk, ak + 1, pk)}\n".encode()}))
        leaked = [(nm, str(solve(q_, fl))[:40]) for nm, q_, fl in others if plain(solve(q_, fl))]
        check(f"R21 the name accepted on one instance makes none of {len(others)} others plain (wording, session key, programs, a comment, "
              "a file name, a format, another instance)", not leaked, leaked)
        # a least residue: g of order q, a drawn from [2, p-2]; accepted on one delivery, another delivery stays unsure
        qq = max(fk)
        gsub = pow(gk, (pk - 1) // qq, pk)
        while True:
            af2 = RND.randrange(2, pk - 2)
            if af2 >= qq:
                break
        ql = ask2("What is Alice's private key?")
        f1 = {"params.txt": f"p = {pk}\ng = {gsub}\nA = {pow(gsub, af2 % qq, pk)}\n".encode()}
        learn_first(solve(ql, f1))
        v2 = solve(ql, {"params.txt": f"p = {pk}\ng = {gsub}\nA = {pow(gsub, af2, pk)}\nB = {pow(gsub, 5, pk)}\n".encode()})
        check("R21 a least residue accepted on one delivery: another's (a drawn from [2, p-2]) stays unsure", not plain(v2) and opts(v2), v2)
        check("R21 ... and the delivery it was accepted on is plain again on replay", solve(ql, f1) == str(af2 % qq), solve(ql, f1))
        # an ElGamal integer plaintext
        xk = RND.randrange(2, pk - 1)
        hk_ = pow(gk, xk, pk)
        kk = RND.randrange(2, pk - 1)
        mk_ = RND.randrange(2, pk - 1)
        qi = ask2("Decrypt the ElGamal ciphertext and give the message as an integer.")
        fa = {"ct.txt": f"p = {pk}\ng = {gk}\nh = {hk_}\nc1 = {pow(gk, kk, pk)}\nc2 = {mk_ * pow(hk_, kk, pk) % pk}\n".encode()}
        learn_first(solve(qi, fa))
        m2k = RND.randrange(2, pk - 1)
        fb = {"ct.txt": f"p = {pk}\ng = {gk}\nh = {hk_}\nc1 = {m2k * pow(hk_, kk, pk) % pk}\nc2 = {pow(gk, kk, pk)}\n".encode()}
        vb_ = solve(qi, fb)
        check("R21 an integer plaintext accepted on one delivery: swapped c1 / c2 on another stays unsure, its swapped reading offered second",
              not plain(vb_) and holds(vb_, m2k, first=False) and opts(vb_)[1][0] == "swapped:decimal", vb_)
        check("R21 ... and the delivery it was accepted on is plain again on replay", solve(qi, fa) == str(mk_), solve(qi, fa))
        # a name the judge REJECTED for one instance's key is no strike against another instance's
        ka_ = key_of(solve(ask2("Find Bob's private key."), {"output.txt": outk}))
        tk.labels.learn(ka_, "log:decimal", "rejected", scope="key", attempt_id="r21", answer_ids=["m"], left=None)
        vr = solve(ask2("Find Bob's private key."), {"output.txt": outk})
        vo = solve(ask2("Find Bob's private key."), {"output.txt": outk + b"# other\n"})
        check("R21 a rejected name leaves the other options of its own key and touches no other instance's",
              not plain(vr) and "log:decimal" not in [n for n, _ in opts(vr)] and holds(vo, bk), (vr, vo))

    # R22: time ------------------------------------------------------------------------------------------------------------------
    try:
        import gmpy2
    except ImportError:
        gmpy2 = None
    n_ = 3000 if gmpy2 is not None else 800     # big enough that one exponentiation per factor of 2 is seconds (it was 8 s at 3000 and 15 s at 4000)
    kp = 301                                    # k above 300 so that the odd-order subgroup is big enough for g^5, g^7 to differ from 1
    while not (gmpy2.is_prime(kp * (1 << n_) + 1, 25) if gmpy2 is not None else is_prime(kp * (1 << n_) + 1)):
        kp += 2
    pp_ = kp * (1 << n_) + 1
    rp_ = 3
    while pow(rp_, 1 << n_, pp_) == 1 or pow(pow(rp_, 1 << n_, pp_), 7, pp_) == 1:
        rp_ += 1
    gp = pow(rp_, 1 << n_, pp_)                 # an element of odd order dividing k
    t0 = time.monotonic()
    r = D.solve_dlog(pp_, gp, pow(gp, 5, pp_))
    dt = time.monotonic() - t0
    check(f"R22 library: p = {kp} * 2^{n_} + 1 (a Proth prime) and g of odd order: solved and verified in {dt:.2f} s (it was 8 to 15 s and None)",
          r is not None and r.x == 5 and dt < 2.0, (r, dt))
    t0 = time.monotonic()
    v = solve(ask2("What is the shared secret?"), {"p.txt": f"p = {pp_}\ng = {gp}\nA = {pow(gp, 5, pp_)}\nB = {pow(gp, 7, pp_)}\n".encode()})
    dt = time.monotonic() - t0
    check(f"R22 toolkit: the same group, the shared secret first among the candidates in {dt:.2f} s", holds(v, pow(gp, 35, pp_)) and dt < 2.0, (v, dt))
    if gmpy2 is not None:
        # p - 1 = 2 * c * (every odd prime below 2400), c a prime above it: squarefree, ~3400 bits and ~360 prime factors, a prime found
        # in under a second (a random modulus of that shape took minutes to find; the old group_order_of did one full-size
        # exponentiation per factor: 2 s here)
        odd_primes = [q_ for q_ in range(3, 2400) if gmpy2.is_prime(q_)]      # (this file's own is_prime misses 41, a Miller-Rabin base)
        m4 = 2
        for f_ in odd_primes:
            m4 *= f_
        c4 = 3457                               # found once by searching the primes above 2399 (about a second); the prime and the root are checked here
        p4 = m4 * c4 + 1
        fs4 = sorted(set(odd_primes) | {2, c4})
        g4 = 12                                 # the smallest primitive root of p4 (checked below with the product tree)
        check("R22 fixture: p4 is prime and 12 is a primitive root of it", gmpy2.is_prime(p4, 25) and all(t_ != 1 for t_ in D._cof_pows(g4, fs4, p4, None)))
        t0 = time.monotonic()
        D._ORDER_CACHE.clear()
        o4 = D.group_order_of(p4, g4, None, time.monotonic() + 5.0)
        dt = time.monotonic() - t0
        check(f"R22 library: the order of a primitive root of a {p4.bit_length()}-bit prime whose p - 1 has {len(fs4)} prime factors in {dt:.2f} s (one exponentiation per factor took 2 s)",
              o4 is not None and o4[0] == p4 - 1 and dt < 1.0, (o4 and o4[0] == p4 - 1, dt))
        check("R22 library: the cofactor powers of the order are kept for the logarithm (one product tree, not two)", (p4, g4, p4 - 1) in D._TREE_CACHE)
        t0 = time.monotonic()
        # Benchmark the PH implementation itself with an explicit long
        # deadline. solve_dlog() intentionally clamps even a caller deadline
        # to DEFAULT_BUDGET (0.5 s); the next check separately proves that
        # production cap returns promptly and may safely decline under load.
        r = D._solve_dlog(p4, g4, pow(g4, 12345678901234567890, p4),
                          None, None, time.monotonic() + 10.0)
        dt = time.monotonic() - t0
        check(f"R22 library: ... and its discrete logarithm ({len(fs4)} Pohlig-Hellman primes) in {dt:.2f} s",
              r is not None and pow(g4, r.x, p4) == pow(g4, 12345678901234567890, p4) and dt < 5.0, (r is not None, dt))
        # no unbounded time even when the budget is tight
        t0 = time.monotonic()
        D.solve_dlog(p4, g4, pow(g4, 99999999, p4))
        dt = time.monotonic() - t0
        check(f"R22 library: the default 0.5 s budget on that group returns within {dt:.2f} s (solved or None, never a hang)", dt < 1.5, dt)
        # a labelled megabyte of hex beside a DH instance, and a set whose other question the older paths answer
        pb2 = int(gmpy2.next_prime((1 << 2047) + RND.getrandbits(2000)))
        Ab2, Bb2 = pow(2, RND.getrandbits(256), pb2), pow(2, RND.getrandbits(256), pb2)
        blob = "%x" % RND.getrandbits(4 * 100000)
        t0 = time.monotonic()
        v = solve(ask2("What is the shared secret?"), {"t.txt": f"p = {pb2}\ng = 2\nA = {Ab2}\nB = {Bb2}\nsecret_blob = 0x{blob}\n".encode()})
        dt = time.monotonic() - t0
        check(f"R22 a labelled 100000-hex-digit value beside a 2048-bit instance: no hang ({dt:.2f} s, was 22 s at 390000 digits)", not plain(v) and dt < 2.0, (str(v)[:30], dt))
        t0 = time.monotonic()
        v = solve(ask2("What is the shared secret?"), {"t.txt": f"p = {pb2}\ng = 2\nA = {Ab2}\nB = {Bb2}\nsecret_blob = 0x{'%x' % RND.getrandbits(4 * 390000)}\n".encode()})
        dt = time.monotonic() - t0
        check(f"R22 a labelled 390000-hex-digit value beside the instance: None, no hang ({dt:.2f} s)", v is None and dt < 2.0, (str(v)[:30], dt))
        rr_ = random.Random(5)
        while True:
            pr1, qr1 = int(gmpy2.next_prime(rr_.getrandbits(1024))), int(gmpy2.next_prime(rr_.getrandbits(1024)))
            if (pr1 - 1) % 3 and (qr1 - 1) % 3:
                break
        flag = b"flag{cube_root_small_m}"
        rsa_txt = f"n = {pr1 * qr1}\ne = 3\nc = {pow(int.from_bytes(flag, 'big'), 3, pr1 * qr1)}\n"
        dh_txt = f"prime = {p4}\ngenerator = {g4}\nalice_public = {pow(g4, 12345, p4)}\nbob_public = {pow(g4, 54321, p4)}\n"
        qs = [ask2("What is the Diffie-Hellman shared secret?", aid="q1"),
              {"id": "q2", "qid": "q2", "answer_id": "q2", "question": "Decrypt the ciphertext c. What is the flag?",
               "answer_format": {"kind": "exact_text", "pattern": r"flag\{[a-z_]+\}"}}]
        t0 = time.monotonic()
        out = tk.solve_set(qs, {"one.txt": rsa_txt.encode(), "two.txt": dh_txt.encode()}, {})
        dt = time.monotonic() - t0
        check(f"R22 a set with a 4-kbit group and an RSA question: the RSA question is still answered ({dt:.2f} s; it got None when the group overran the set)",
              out["q2"] == flag.decode() and dt < 2.0, (out, dt))
        # discrete-log questions that each burn their whole budget (p - 1 = 2 * two 60-bit primes: rho cannot split it, so every attempt
        # runs to its deadline), then an RSA question: since fix round 4 the discrete-log pass runs after every older reader, inside
        # DLOG_SET_CAP of what is left of the set (unbounded and first, six attempts of 0.2 to 0.25 s took the set and the RSA question got None)
        while True:
            ha_, hb_ = int(gmpy2.next_prime(RND.getrandbits(60) | (1 << 59))), int(gmpy2.next_prime(RND.getrandbits(60) | (1 << 59)))
            if ha_ != hb_ and gmpy2.is_prime(2 * ha_ * hb_ + 1, 25):
                break
        pz = 2 * ha_ * hb_ + 1
        fz_ = {"one.txt": rsa_txt.encode(), "two.txt": f"prime = {pz}\ngenerator = 3\nA = {pow(3, 99999, pz)}\nB = {pow(3, 77777, pz)}\n".encode()}
        # every one of them is a `dlog` intent (nothing but the hook reads it), so no earlier question computes the RSA result the last one
        # needs (once it is cached the toolkit answers later RSA questions even past the deadline): the hook alone decides whether the set
        # keeps its last seconds. B's exponent 77777 is out of reach of every bound below, so each attempt runs to its deadline.
        hard = [ask2("Find the discrete log of A to base g.", aid="h1"), ask2("Find the discrete log of B to base g.", aid="h2")]
        hard += [ask2(f"Find the discrete log x of B to base g; x < 2^{n_}.", aid=f"hb{n_}") for n_ in (10, 11, 12, 13, 14, 15, 16)]
        t0 = time.monotonic()
        out = tk.solve_set(hard + [qs[1]], fz_, {})
        dt = time.monotonic() - t0
        check(f"R22 nine discrete-log questions that each run to their deadline, then an RSA question in one set: still answered ({dt:.2f} s; unbounded the set was gone after the third)",
              out["q2"] == flag.decode() and dt < 2.0, (out.get("q2"), dt))
        t0 = time.monotonic()
        r0 = tk._dlog_answer(hard[0], tk.Material(fz_), tk._words(hard[0]), time.monotonic() - 0.01)
        r1 = tk._dlog_fallback(hard[0], tk.Material(fz_), time.monotonic() + tk.DLOG_MIN / 2)
        dt0 = time.monotonic() - t0
        check(f"R22 the discrete-log hook with no window left (a deadline passed, or under DLOG_MIN) answers None at once ({dt0:.3f} s)",
              r0 is None and r1 is None and dt0 < 0.1, (r0, r1, dt0))

    # R23: the library -----------------------------------------------------------------------------------------------------------
    bad = 0
    for _ in range(150):
        pp3, _f = smooth_p(RND.randrange(1, 4), maxbits=9)
        while pp3 > (1 << 20):
            pp3, _f = smooth_p(RND.randrange(1, 4), maxbits=9)
        gg = RND.randrange(2, pp3 - 1)
        D._ORDER_CACHE.clear()
        got = D.group_order_of(pp3, gg)
        o_, e_ = 1, gg % pp3
        while e_ != 1:
            e_ = e_ * gg % pp3
            o_ += 1
        if got is None or got[0] != o_ or got[1] != (o_ == pp3 - 1):
            bad += 1
    check("R23 group_order_of (prime by prime, a product tree) equals the naive order on 150 random groups", bad == 0, bad)
    bad = 0
    for _ in range(100):
        mod, _f = smooth_p(3, maxbits=8)
        base_ = RND.randrange(2, mod - 1)
        qs3 = sorted({RND.choice([2, 3, 5, 7, 11, 13, 17, 19, 23]) ** RND.randrange(1, 4) for _ in range(RND.randrange(1, 6))})
        prod_ = 1
        for q_ in qs3:
            prod_ *= q_
        if D._cof_pows(base_, qs3, mod, None) != [pow(base_, prod_ // q_, mod) for q_ in qs3]:
            bad += 1
    check("R23 _cof_pows (the cofactor powers by a product tree) equal the direct powers on 100 random lists", bad == 0, bad)
    check("R23 a deadline in the past returns None from group_order_of, never a late answer", D.group_order_of(2 ** 61 - 1, 3, None, time.monotonic() - 1) is None)
    check("R23 `g^x = N mod p` states no private value x = N (a label after ^ or ** is no label)",
          D.read_instance("Find x such that g^x = 12345678901234 mod p")["privs"] == [] and D.read_instance("Find x such that g**x = 12345678901234 mod p")["privs"] == []
          and D.read_instance("x = 12345678901234")["privs"] == [12345678901234])
    try:
        deep = D.read_instance("[" * 3000 + "]" * 3000 + " p = 23 g = 5")
        check("R23 a deeply nested JSON text is read as text, not a crash", isinstance(deep, dict))
    except RecursionError:
        check("R23 a deeply nested JSON text is read as text, not a crash", False)
    bad = []
    for (nf, mb) in ((32, 16), (64, 16)):
        cands = [q_ for q_ in SMALLP if q_.bit_length() == mb]
        while True:
            fs5 = RND.sample(cands, min(nf, len(cands)))
            m5 = 2
            for f_ in fs5:
                m5 *= f_
            if gmpy2 is not None and gmpy2.is_prime(m5 + 1, 25) or gmpy2 is None and m5.bit_length() < 600 and is_prime(m5 + 1):
                break
        p5 = m5 + 1
        g5 = primitive_root(p5, sorted(set(fs5) | {2}))
        x5 = RND.randrange(2, p5 - 1)
        t0 = time.monotonic()
        r = D.solve_dlog(p5, g5, pow(g5, x5, p5))
        dt = time.monotonic() - t0
        if r is None or r.x != x5 or dt > 1.5:
            bad.append((p5.bit_length(), nf, dt))
        if gmpy2 is None:
            break
    check("R23 classic Pohlig-Hellman sizes (p of 500 to 1000 bits, p - 1 a product of 16-bit primes) are solved inside the budget", not bad, bad)
    check("R23 plausible_priv: a stated private value 64 bits wider than p is skipped, a smaller one is tried",
          not D.plausible_priv(23, 1 << 80) and D.plausible_priv(23, 12) and not D.plausible_priv(23, 0) and not D.plausible_priv(23, True))
    check("R23 read_instance: a labelled number of more than 1400 characters is never converted, and a modelled label with one is ambiguous",
          "oversize_value" in D.read_instance("p = " + "9" * 1500 + "\ng = 5\n")["ambiguous"] and D._ival("9" * 1500) is None and D._ival("12") == 12)
    cl = D.range_claims("Private exponents are chosen with x < p-1. Eve's private key is less than p-1. The ephemeral exponent b < 2^20. Alice picked a 32-bit secret.")
    check("R23 range_claims: a generic statement, a letter, a party, an unattributed `Eve's` (other) are told apart",
          ("generic", None, "p1", None) in cl and ("letter", "x", "p1", None) in cl and ("other", None, "p1", None) in cl and ("party", "alice", "num", 1 << 32) in cl, cl)
    check("R23 range_claims: a call's assigned name sets its subject (k other, a_priv Alice's letter, secret generic, bob_priv Bob's)",
          D.range_claims("k = randrange(2, p-1)")[0][:2] == ("letter", "k") and D.range_claims("a_priv = randrange(2, p-1)")[0][:2] == ("letter", "a")
          and D.range_claims("secret = random.randrange(2, p-1)")[0][:2] == ("generic", None) and D.range_claims("bob_priv = randint(1, p-2)")[0][:2] == ("party", "bob"),
          [D.range_claims(t_) for t_ in ("k = randrange(2, p-1)", "a_priv = randrange(2, p-1)", "secret = random.randrange(2, p-1)", "bob_priv = randint(1, p-2)")])
    check("R23 range_claims: getrandbits(p.bit_length() + 8) is a `big` claim, getrandbits(64) a number",
          D.range_claims("a = getrandbits(p.bit_length() + 8)")[0][2] == "big" and D.range_claims("a = getrandbits(64)")[0][2:] == ("num", 1 << 64))
    js3 = D.read_instance('{"p": 23, "g": 5, "server": {"A": 8}, "client": {"public": 19}}')
    check("R23 read_instance: a JSON key that names a role prefixes what is below it (server.A is no bare A; client.public is client_public)",
          "a" not in js3["pubs"] and js3["pubs"].get("client") == 19, js3["pubs"])
    pe_ = D.read_instance("p = 1000003\ng = 2\nA = 77\nB = 88\nT = 999983\ncommit = 123457\nbits = 512")
    check("R23 unread_elements: only a group-sized number under a label nobody reads counts (T and commit at p's width, not `bits`)",
          D.unread_elements(dict(pe_, p=(1 << 100) + 277)) == [] and D.unread_elements({"p": 1000003, "pubs": {}, "privs": [], "raw": [("T", 999983)], "pairs": []}) == [], D.unread_elements(pe_))
    big_p = (1 << 90) + 297
    check("R23 unread_elements: a Pedersen C or a value under an unread label, as wide as p, is an unread element",
          D.unread_elements({"p": big_p, "pubs": {"one": big_p // 3}, "privs": [], "raw": [("C", big_p // 5), ("bits", 512), ("nonce", 1 << 40)], "pairs": []}) == ["C"])

    # R24: a question fuzz with ground truth ------------------------------------------------------------------------------------
    cases = []
    for imp in ("Get", "Share", "Use", "Run"):
        for other, tv in (("the generator", g), ("the prime p", p)):
            cases.append((f"{imp} {other}. What is the shared secret?", None))
    for pre_ in pre[:5]:
        for q_, tv in asks[:6]:
            cases.append((f"{pre_} {q_}", tv))
    for sym in ("c1", "C", "r", "m", "the nonce", "T"):
        cases.append((f"What is the discrete log of {sym} to base g?", None))
    wrong_plain(cases, FR, "R24 imperatives, preambles, operands")
    # the same questions over a second, different instance (a primitive root of another smooth prime): nothing instance-specific
    I2 = mk_instance(nfac=10, minbits=80)
    F2 = {"d.txt": (f"p = {I2['p']}\ng = {I2['g']}\nA = {I2['A']}\nB = {I2['B']}\nPrivate exponents are chosen with x < p-1.\n").encode()}
    wrong = [t for t in ("What is the shared secret?", "Give the shared secret.", "What is the shared secret? Give it in decimal.") if not holds(solve(ask2(t), F2), I2["s"])]
    wrong += [t for t, tv in (("What is Alice's private key?", I2["a"]), ("Find Bob's private exponent.", I2["b"])) if not holds(solve(ask2(t), F2), tv)]
    check("R24 control: a second instance, the plain asks hold the truth first", not wrong, wrong)

    # R25: the vocabulary-salad review (random sentences of the plain-ask vocabulary around a target found three more holes) ----------
    # a verb-less ask has no ask phrase: its operands were never bound (`The shared secret of A and C`, `The discrete log of B for
    # Alice`); a formula target is blanked by the statement strip (`Recover g^(ab) mod p D`); a party and an exponent letter that name
    # different exponents (`Bob's private exponent a`) contradict each other; a sentence-initial `A` is an article
    none_ = [("The shared secret of A and C", None), ("Shared secret between A and D", None), ("The discrete log of c1", None), ("The discrete log of B for Alice", None),
             ("The discrete log of A of Bob", None), ("Recover g^(ab) mod p D", None), ("Recover g^(ab) mod p H?", None), ("Show g^(ab) mod p y", None),
             ("Recover g^(ab) mod p k", None), ("What is Bob's private exponent a?", None), ("What is Alice's private exponent b?", None),
             ("The private exponent a of Bob", None), ("Find the private key b of Alice.", None), ("Find Bob's private key a.", None)]
    wrong_plain(none_, FR, "R25 a verb-less ask, a formula target, a party against a letter: operands bound, contradictions decline", strict=True)
    wrong_plain([("A discrete log of the exchange?", None), ("A the discrete logarithm after provided been?", None), ("The shared secret of A and 7", None)], FR,
                "R25 a sentence-initial A is the article; a stray digit leaves the ask not plain")
    ctl = [("The shared secret of A and B", s), ("The shared secret", s), ("Discrete log of B", b), ("A discrete log of B", b), ("Alice's private key", a), ("Bob's private key", b),
           ("Recover g^(ab) mod p", s), ("Compute the shared secret g^(ab) mod p.", s), ("What is Alice's private exponent a?", a), ("Find the private exponent b of Bob.", b),
           ("What is Bob's private key b?", b), ("What is the private exponent a of Alice?", a), ("What is the discrete log of A?", a)]
    wrong = [(t, str(solve(ask2(t), FR))[:20]) for t, tv in ctl if not holds(solve(ask2(t), FR), tv)]
    check(f"R25 control: {len(ctl)} verb-less asks, a formula target and a party that agrees with its letter: the truth first", not wrong, wrong)

    # the vocabulary rounds 2 and 3 called plain-ask words (fix round 4 removed it from the toolkit: nothing is plain any more)
    salad_vocab = sorted(set("""
        what whats which who whose find compute computes computed calculate calculates determine recover give submit enter
        provide report solve obtain extract return state tell show name break me is are was were be been am the a an of to for in on
        at by with without and or as from into over using use used uses given this that these those it its they their them both each
        either all any do does did you your we our my please now then here there so such thus hence can could will would shall must
        should may might not no yes if when where whether while after before once also only just exactly between among via per end up
        have has get make reach arrive agree come yield result answer share run perform carry out number integer decimal hex value
        values diffie hellman dh elgamal discrete exponent key keys private public secret shared common exchange handshake protocol
        alice bob party parties client server sender receiver user her his modulus prime generator group satisfies hint note known
        unknown problem file transcript output log data attachment provided above below document final resulting agreed numeric
    """.split()))
    salad_x = sorted(set("smaller less than below under most bound bounded upper range uniformly random randomly drawn picked selected "
                         "small chosen choose chose".split()))

    def salad(mode, n, seed):
        """Random sentences made of the plain-ask vocabulary around a target, with stray symbols and numbers. Since fix round 4 no
        answer is plain at all, whatever the tokens (the risky ones included); a candidate pick may hold any value. Counted: the
        candidate picks whose first value is the target's own (the router's reading of a clean sentence still lands)."""
        import random as _random
        r_ = _random.Random(seed)
        vocab = salad_vocab + (salad_x if mode == "x" else [])
        extra = ["A", "B", "C", "D", "a", "b", "c", "k", "r", "x", "y", "g", "p", "q", "s", "S", "K", "H", "m", "1", "2", "7", "65537", "0x10", "123456789", "h", "X"]
        targets = (["the shared secret", "the common secret", "the Diffie-Hellman shared secret", "g^(ab) mod p"] if mode == "shared"
                   else ["Alice's private key", "Bob's private key", "the discrete log of A", "the discrete log of B", "the private exponent a"])
        want = {"Alice's private key": a, "Bob's private key": b, "the discrete log of A": a, "the discrete log of B": b, "the private exponent a": a}
        verbs = ["What is", "Find", "Compute", "Determine", "Give", "Recover", "Calculate", "What's", "Tell me", "Which is", "Show", "Report", "Solve for", ""]

        def chunk(k):
            ws = [r_.choice(vocab) for _ in range(k)]
            if r_.random() < 0.5:
                ws.insert(r_.randrange(len(ws) + 1), r_.choice(extra))
            return " ".join(ws)

        seen, bad, nfirst = set(), [], 0
        for _ in range(n):
            t_ = r_.choice(targets)
            sent = " ".join(w for w in (chunk(r_.choice([0, 0, 1, 2, 3])), r_.choice(verbs), chunk(r_.choice([0, 0, 1, 2])), t_, chunk(r_.choice([0, 0, 1, 2, 3, 4]))) if w)
            sent = sent[0].upper() + sent[1:] + r_.choice(["?", ".", "", "!", "?"])
            if sent in seen:
                continue
            seen.add(sent)
            v = solve(ask2(sent), FR)
            if plain(v):
                bad.append((sent[:70], str(v)[:20]))
            elif holds(v, want[t_] if mode == "x" else s):
                nfirst += 1
        return len(seen), nfirst, bad

    for mode, n_, seed_ in (("shared", 1200, 4), ("x", 1200, 5)):
        t0 = time.monotonic()
        nseen, nfirst, bad = salad(mode, n_, seed_)
        check(f"R25 vocabulary salad ({mode}): {nseen} random sentences, none plain, {nfirst} candidate picks with the target's value first "
              f"({time.monotonic() - t0:.1f} s)", not bad and nfirst > 50, bad[:3])

    # R26: the layers one at a time. The router answers None through several layers at once, so a gate that another layer also closes
    # survives a mutation check run through `solve`; each is pinned here on its own (`_dlog_target`, `_dlog_bind` called directly) --------
    def bind(qt, kind, files):
        return tk._dlog_bind(qt, tk._words(ask2(qt)).lower(), kind, tk._dlog_instance(tk.Material(files), qt))

    two = ["Find the shared secret and Alice's private key.", "What is the shared secret and the private key?", "Compute Bob's private key and the shared secret.",
           "Decrypt the message and give the shared secret."]
    check("R26 _dlog_target: two different things named in one sentence: None", all(tk._dlog_target(t) is None for t in two), [t for t in two if tk._dlog_target(t) is not None])
    bare2 = ["The generator, and the shared secret?", "Bob's public key, the shared secret?", "Alice's public value; the shared secret?"]
    check("R26 _dlog_target: a verb-less interrogative of several clauses is no single ask of the target: None",
          all(tk._dlog_target(t) is None for t in bare2) and tk._dlog_target("The shared secret?") == "shared", [t for t in bare2 if tk._dlog_target(t) is not None])
    check("R26 _dlog_bind: a logarithm in another base than g, written as an equation (h^x = g), is no operand of the instance",
          bind("Find x such that h^x = g mod p, where x < p-1.", "x", FE) is None and bind("Find x such that g^x = h mod p, where x < p-1.", "x", FE) is not None)
    check("R26 _dlog_bind: a power assigned to a symbol in another base (A = B^a) names another logarithm; only a shared secret may be B^a",
          bind("Find a such that A = B^a mod p.", "x", F) is None and bind("Find a such that A = g^a mod p.", "x", F) is not None
          and bind("What is the shared secret s = B^a mod p?", "shared", F) is not None and bind("What is the shared secret s = h^a mod p?", "shared", F) is None)
    check("R26 _dlog_bind: the shared-secret formula in a base other than g (A^(ab)) is no statement of the instance",
          bind("What is the shared secret A^(ab) mod p?", "shared", F) is None and bind("What is the shared secret g^(ab) mod p?", "shared", F) is not None)


def fix2_tests():
    """Fix round 4 (convergence by restriction, after the review of 95699e2 and the cut-off round 3): the discrete-log hook never
    answers plain, its key is the instance's own, and it runs after every older reader of the set.

      R27 nothing the hook derives is plain, over every former plain control and three instances; every unsure answer is under an
          instance key (`modern_crypto.dlog_<kind>/zp@inst-<64 hex>#candidates`), never one of the keys of rounds 1 to 3
      R28 the options: the computed value first, then the alternatives (other party, shared secret, swapped labels, a stated value)
      R29 the pass runs after the older readers: a dlog that overruns by seconds takes no answer of theirs, from the return value
          or from ctx["partial"], and every answer they give equals the toolkit's with the discrete-log pass off
      R30 the budget: a tiny set budget, a deadline in the past, a structured answer kind
      R31 the last adversarial pass: ten new question shapes that try to make a dlog value plain or a base answer disappear
    """
    import hashlib

    def plain(v):
        return v is not None and not unsure(v)

    def keyof(v):
        return tk.labels.parse(v).key if unsure(v) and tk.labels is not None else None

    I = mk_instance()
    p, g, a, b, A, B, s = I["p"], I["g"], I["a"], I["b"], I["A"], I["B"], I["s"]
    base_txt = f"p = {p}\ng = {g}\nA = {A}\nB = {B}\n"
    rng_txt = base_txt + "Private exponents are chosen with x < p-1.\n"
    F, FR = {"params.txt": base_txt.encode()}, {"params.txt": rng_txt.encode()}

    # R27: nothing plain, over the former plain controls on three instances ----------------------------------------------------
    controls = ["What is the shared secret?", "What is the Diffie-Hellman shared secret? Give it in decimal.", "Compute the shared secret s = g^(ab) mod p.",
                "Submit the shared secret as a decimal integer.", "Given p, g, A and B, find the shared secret.", "The shared secret", "Recover g^(ab) mod p",
                "What is Alice's private key?", "Find Bob's private exponent.", "What is the discrete log of A?", "Find x such that g^x = A mod p.",
                "What is Bob's private key b?", "Report Alice's private key a in the file.", "Discrete log of B"]
    bad, oldkey, n = [], [], 0
    for inst_ in (I, mk_instance(nfac=10, minbits=80), mk_instance(sub=True)):
        fl = {"params.txt": (f"p = {inst_['p']}\ng = {inst_['g']}\nA = {inst_['A']}\nB = {inst_['B']}\nPrivate exponents are chosen with x < p-1.\n").encode()}
        for t in controls:
            for kind in ("integer", "exact_text"):
                v = solve(ask2(t, kind), fl)
                n += 1
                if plain(v):
                    bad.append((t, kind, str(v)[:20]))
                elif v is not None and not re.fullmatch(r"modern_crypto\.dlog_(?:x|shared|plaintext)/zp@inst-[0-9a-f]{64}#candidates", keyof(v) or ""):
                    oldkey.append((t, kind, keyof(v)))
    check(f"R27 {n} former plain controls (14 wordings x 2 kinds x 3 instances): none plain", not bad, bad[:3])
    check("R27 ... and every unsure answer is under an instance key (dlog_x / dlog_shared / dlog_plaintext @inst-<64 hex>#candidates)", not oldkey, oldkey[:3])
    msg = b"flag{fix_round_four}"
    mm = int.from_bytes(msg, "big")
    while True:
        p4, fs4 = smooth_p(12)
        if p4 > mm * 4 and p4.bit_length() > 8 * len(msg) + 4:
            break
    g4 = primitive_root(p4, fs4)
    x4 = RND.randrange(2, p4 - 1)
    h4 = pow(g4, x4, p4)
    k4 = RND.randrange(2, p4 - 1)
    c1, c2 = pow(g4, k4, p4), mm * pow(h4, k4, p4) % p4
    fe = {"challenge.txt": f"p = {p4}\ng = {g4}\nh = {h4}\nc1 = {c1}\nc2 = {c2}\n".encode()}
    pat = r"flag\{[a-z_]+\}"
    pts = [solve(ask2(t, "exact_text", pattern=pat), fe) for t in ("Decrypt the ElGamal ciphertext. What is the flag?", "What is the flag?",
                                                                  "Decrypt the ciphertext.", "Recover the message.")]
    pts += [solve(ask2("Decrypt the ElGamal ciphertext and give the message as an integer."), fe),
            solve(ask2("Decrypt the ElGamal ciphertext. What is the plaintext?", "exact_text"), fe)]
    check("R27 an ElGamal plaintext, with a specific flag pattern or none, as text or as an integer: never plain",
          not any(plain(v) for v in pts) and holds(pts[0], msg.decode()), [str(v)[:60] for v in pts])

    # R28: the options and their order --------------------------------------------------------------------------------------------
    v = solve(ask2("Find Alice's private exponent."), FR)
    check("R28 a private exponent: its computed log first, then the other party's exponent and the shared secret",
          [n_ for n_, _ in opts(v)] == ["log:decimal", "other_party:decimal", "shared_secret:decimal"]
          and [val for _, val in opts(v)] == [str(a), str(b), str(s)], v)
    v = solve(ask2("Find Alice's private exponent.", "exact_text"), FR)
    names = [n_ for n_, _ in opts(v)]
    check("R28 ... a text kind: the log in all four forms first, then the alternatives in decimal, then their other forms; at most 12",
          names[:5] == ["log:decimal", "log:hex", "log:0x_hex", "log:hex_upper", "other_party:decimal"] and len(names) <= 12, names)
    one = {"p.txt": (f"p = {p}\ng = {g}\nA = {A}\nPrivate exponents are chosen with x < p-1.\n").encode()}
    v = solve(ask2("What is Alice's private key?"), one)
    check("R28 a single public value: the log alone (no other party, no shared secret)", [n_ for n_, _ in opts(v)] == ["log:decimal"] and holds(v, a), v)
    st = {"p.txt": (rng_txt + f"a = {a + (p - 1)}\n").encode()}
    v = solve(ask2("What is Alice's private key?"), st)
    check("R28 a stated private value that reproduces A but is not the least residue: offered after the log, under `stated`",
          holds(v, a) and ("stated:decimal", str(a + p - 1)) in opts(v), v)
    Jq = mk_instance(sub=True)
    ps_, gs_, qs_ = Jq["p"], Jq["g"], Jq["q"]
    as_ = RND.randrange(2, qs_)
    v = solve(ask2("What is Alice's private key?"), {"p.txt": f"p = {ps_}\nq = {qs_}\ng = {gs_}\nA = {pow(gs_, as_, ps_)}\n".encode()})
    check("R28 a subgroup generator with its order stated: the log (a residue mod q) first", holds(v, as_), v)
    sw = {"ct.txt": f"p = {p4}\ng = {g4}\nh = {h4}\nc1 = {c2}\nc2 = {c1}\n".encode()}
    v = solve(ask2("Decrypt the ElGamal ciphertext. What is the flag?", "exact_text", pattern=pat), sw)
    check("R28 c1 and c2 swapped by the author, a flag pattern: the swapped reading is offered (the straight one does not fit the pattern)",
          opts(v) == [("swapped:text", msg.decode())], v)
    v = solve(ask2("What is the shared secret?", "exact_text"), F)
    check("R28 the shared secret, a text kind: decimal, then the three hex forms", [n_ for n_, _ in opts(v)] ==
          ["shared_secret:decimal", "shared_secret:hex", "shared_secret:0x_hex", "shared_secret:hex_upper"], v)

    # R29: after every older reader; a slow dlog takes nothing ----------------------------------------------------------------------
    try:
        import gmpy2
    except ImportError:
        gmpy2 = None
    if gmpy2 is not None:
        rr_ = random.Random(5)
        while True:
            pr1, qr1 = int(gmpy2.next_prime(rr_.getrandbits(1024))), int(gmpy2.next_prime(rr_.getrandbits(1024)))
            if (pr1 - 1) % 3 and (qr1 - 1) % 3:
                break
        flag = b"flag{cube_root_small_m}"
        rsa_txt = f"n = {pr1 * qr1}\ne = 3\nc = {pow(int.from_bytes(flag, 'big'), 3, pr1 * qr1)}\n"
        # (the DH labels are prime / generator / alice_public / bob_public: a bare `p` beside n, e and c is an RSA prime to the RSA reader,
        # which then declines on parameters that contradict each other)
        dh_txt = f"prime = {p}\ngenerator = {g}\nalice_public = {A}\nbob_public = {B}\n"
        files = {"one.txt": rsa_txt.encode(), "two.txt": dh_txt.encode()}
        q_rsa = {"id": "r1", "qid": "r1", "answer_id": "r1", "question": "Decrypt the ciphertext c. What is the flag?",
                 "answer_format": {"kind": "exact_text", "pattern": r"flag\{[a-z_]+\}"}}
        q_rsa2 = {"id": "r2", "qid": "r2", "answer_id": "r2", "question": "What is the RSA modulus n?", "answer_format": {"kind": "integer"}}
        q_rsa3 = {"id": "r3", "qid": "r3", "answer_id": "r3", "question": "What is the public exponent e?", "answer_format": {"kind": "integer"}}
        dl_qs = [ask2("Find the discrete log of A to base g.", aid="d1"), ask2("Find the discrete log of B to base g.", aid="d2"),
                 ask2("What is the shared secret?", aid="d3")]
        orders = (dl_qs + [q_rsa, q_rsa2, q_rsa3], [q_rsa] + dl_qs + [q_rsa2, q_rsa3], [dl_qs[0], q_rsa, dl_qs[1], q_rsa2, dl_qs[2], q_rsa3])
        real_dlog = tk.dlog
        tk.dlog = None
        try:
            base_out = [tk.solve_set(qs_o, files, {}) for qs_o in orders]
        finally:
            tk.dlog = real_dlog
        check("R29 fixture: with the discrete-log pass off the older readers answer the RSA flag (the armed tree's answer)",
              all(o_["r1"] == flag.decode() for o_ in base_out), [o_["r1"] for o_ in base_out])
        real_solve = tk._dlog_solve
        seen_partial, overran = [], []

        def slow_solve(*args):
            seen_partial.append(dict(slow_ctx["partial"]))
            t0_ = time.monotonic()
            overrun(0.6)                          # far past every window the pass gives it: an overrun the deadline did not catch
            overran.append(time.monotonic() - t0_)
            return real_solve(*args)

        lost = []
        tk._dlog_solve = slow_solve
        try:
            for qs_o, bo in zip(orders, base_out):
                slow_ctx = {"partial": {}}
                got = tk.solve_set(qs_o, files, slow_ctx)
                for qid_, val in bo.items():
                    if val is not None and (got.get(qid_) != val or slow_ctx["partial"].get(qid_) != val):
                        lost.append((qid_, str(got.get(qid_))[:30]))
        finally:
            tk._dlog_solve = real_solve
        check("R29 a discrete-log solve that overruns by 0.6 s on every call, in three question orders: every answer the older readers give "
              "is in the return value and in ctx['partial'] unchanged", not lost, lost[:3])
        check("R29 ... and every one of those solves did overrun: the clock the pass reads moved 0.6 s or more inside it, and the solve "
              "went on (an overrun that raises instead tests an exception path, not an overrun)",
              bool(overran) and len(overran) == len(seen_partial) and all(x >= 0.6 for x in overran),
              (len(seen_partial), [round(x, 3) for x in overran]))
        check("R29 ... and the older readers' answers were all in ctx['partial'] before the first discrete-log solve began",
              bool(seen_partial) and all(sp.get("r1") == flag.decode() for sp in seen_partial), seen_partial[:1])
        out = tk.solve_set(orders[2], files, {})
        check("R29 the normal pass: the RSA answers stand and the discrete-log questions the older readers left None get candidate picks",
              out["r1"] == flag.decode() and holds(out["d1"], a) and holds(out["d2"], b), (out["r1"], str(out["d1"])[:40]))
        # a question an older reader answers is never handed to the discrete-log pass, even when it names the problem: the older answer stands
        q_dh_rsa = ask2("What is the Diffie-Hellman shared secret?", "exact_text", aid="x1")
        out_on = tk.solve_set([q_dh_rsa, q_rsa], files, {})
        tk.dlog = None
        try:
            out_off = tk.solve_set([q_dh_rsa, q_rsa], files, {})
        finally:
            tk.dlog = real_dlog
        check("R29 a DH question an older reader already answers (an RSA plaintext pick: `secret` is a plaintext word) keeps that answer, "
              "as on the armed tree; the pass only fills a None", out_on == out_off, (str(out_on["x1"])[:50], str(out_off["x1"])[:50]))

    # R30: the budget ---------------------------------------------------------------------------------------------------------------
    t0 = time.monotonic()
    v = tk.solve_set([ask2("Find Alice's private exponent.")], FR, {"budget": 0.05})["m"]
    dt = time.monotonic() - t0
    check(f"R30 a set budget under DLOG_MIN: the pass does not start (None, {dt:.3f} s)", v is None and dt < 0.2, (v, dt))
    for kind_ in ("json", "ordered_tokens", "mitre_attack_id"):
        v = solve(ask2("What is the shared secret?", kind_), F)
        check(f"R30 a structured answer kind ({kind_}): the discrete-log pass does not read it", v is None, v)
    v = tk.answer(ask2("What is the shared secret?"), tk.Material(F), time.monotonic() - 1.0)
    check("R30 answer() with its deadline already passed: None (no late discrete-log work)", v is None, v)
    v = tk.answer(ask2("What is the shared secret?"), tk.Material(F), time.monotonic() + 1.0)
    check("R30 answer() for one question: the older paths, then the discrete-log pass (a candidate pick)", holds(v, s), v)

    # R31: ten new question shapes (the last adversarial pass of fix round 4) -------------------------------------------------------
    leaks = []
    # 1. a pattern that fixes the form exactly (`^[0-9]+$`) and an integer kind: still a candidate pick
    v = solve(ask2("What is the shared secret?", "integer", pattern=r"^[0-9]+$", syntax="decimal integer"), F)
    leaks += [("1 pattern ^[0-9]+$", v)] if plain(v) else []
    check("R31.1 a pattern that leaves one form (^[0-9]+$, integer, `decimal integer`): a candidate pick, the secret first", holds(v, s), v)
    # 2. the material states the shared secret itself (a decoy or the truth): our value is still only a candidate
    fl2 = {"params.txt": (base_txt + f"shared_secret = {s}\n").encode()}
    v = solve(ask2("What is the shared secret?"), fl2)
    leaks += [("2 stated secret", v)] if plain(v) else []
    check("R31.2 the material states a `shared_secret` value: the computed secret is still a candidate pick, never plain", not plain(v), v)
    # 3. the same question in a Mastery: two sets, two deliveries; a name accepted on one set's instance answers only that set
    I3 = mk_instance(nfac=10, minbits=80)
    f3a = {"set1.txt": (f"p = {I3['p']}\ng = {I3['g']}\nA = {I3['A']}\nB = {I3['B']}\n").encode()}
    f3b = {"set2.txt": (f"p = {I3['p']}\ng = {I3['g']}\nA = {I3['B']}\nB = {pow(I3['g'], I3['a'] + 3, I3['p'])}\n").encode()}
    q3 = ask2("What is the shared secret?", aid="set1.m")
    v3a = solve(q3, f3a)
    if tk.labels is not None and opts(v3a):
        tk.labels.learn(keyof(v3a), opts(v3a)[0][0], "accepted", scope="key", attempt_id="r31", answer_ids=["set1.m"], left=None)
    v3a2, v3b = solve(q3, f3a), solve(ask2("What is the shared secret?", aid="set2.m"), f3b)
    leaks += [("3 other set", v3b)] if plain(v3b) else []
    check("R31.3 a Mastery: the name accepted on set 1's instance answers set 1 plain (a replay) and leaves set 2 a candidate pick",
          v3a2 == str(I3["s"]) and not plain(v3b) and holds(v3b, pow(I3["g"], I3["b"] * (I3["a"] + 3), I3["p"])), (v3a2, str(v3b)[:40]))
    # 4. the same delivery and question under another answer id: the same instance, so the same key (one truth for both ids)
    v4 = solve(ask2("What is the shared secret?", aid="other-id"), f3a)
    check("R31.4 the same question on the same delivery under another answer id: the same key, so the accepted value (the same truth)",
          v4 == str(I3["s"]), v4)
    # 5. case and blanks: blanks are folded, case is kept (A and a are different values)
    k5 = [keyof(solve(ask2(t), F)) for t in ("What is the shared secret?", "What  is the shared\tsecret?", "what is the shared secret?")]
    check("R31.5 blanks folded, case kept: the same key for a re-spaced question, another for a re-cased one", k5[0] == k5[1] != k5[2], k5)
    # 6. a question restating 64 private values that reproduce nothing: bounded, None
    many = " ".join(f"a = {RND.randrange(2, p - 1)}," for _ in range(64))
    t0 = time.monotonic()
    v = solve(ask2(f"What is the shared secret for {many} and b = 5?"), F)
    dt = time.monotonic() - t0
    leaks += [("6 many privs", v)] if plain(v) else []
    check(f"R31.6 a question restating 64 private values (none reproduces A): None in {dt:.2f} s", v is None and dt < 1.0, (str(v)[:30], dt))
    # 7. an RSA question and an ElGamal question over one delivery that holds both: the RSA answer is the older reader's, untouched
    if gmpy2 is not None:
        fl7 = {"rsa.txt": rsa_txt.encode(), "eg.txt": f"prime = {p4}\ngenerator = {g4}\npublic_key = {h4}\nephemeral = {c1}\nmasked = {c2}\n".encode()}
        q7 = [q_rsa, ask2("Decrypt the ElGamal ciphertext (c1, c2). What is the message as an integer?", aid="e7")]
        out7 = tk.solve_set(q7, fl7, {})
        tk.dlog = None
        try:
            off7 = tk.solve_set(q7, fl7, {})
        finally:
            tk.dlog = real_dlog
        same = all(off7[k_] is None or out7[k_] == off7[k_] for k_ in off7)
        leaks += [("7 elgamal beside rsa", out7["e7"])] if plain(out7["e7"]) and off7["e7"] is None else []
        check("R31.7 RSA and ElGamal material together: every answer an older reader gives is unchanged (the RSA flag plain); the pass "
              "adds only candidate picks", out7["r1"] == flag.decode() and same and (off7["e7"] is not None or not plain(out7["e7"])),
              (out7["r1"], str(out7["e7"])[:40], str(off7["e7"])[:40]))
    # 8. the hex words with an integer kind, and a 0x pattern with a text kind: the forms follow the question, never plain
    v8a = solve(ask2("What is the shared secret in hex?", "integer"), F)
    v8b = solve(ask2("What is the shared secret?", "exact_text", pattern=r"^0x[0-9a-f]+$"), F)
    leaks += [(n_, v_) for n_, v_ in (("8a", v8a), ("8b", v8b)) if plain(v_)]
    check("R31.8 hex words under an integer kind (decimal only) and a 0x pattern (the 0x form only): candidate picks, never plain",
          holds(v8a, s) and opts(v8b) == [("shared_secret:0x_hex", f"0x{s:x}")], (str(v8a)[:50], str(v8b)[:80]))
    # 9. a label the judge accepted for the instance key, then the material gains a numbered second exchange: no longer read (None)
    fl9 = {"params.txt": (base_txt + f"A2 = {pow(g, 7, p)}\nB2 = {pow(g, 9, p)}\n").encode()}
    v9 = solve(ask2("What is the shared secret?"), fl9)
    check("R31.9 a second exchange under numbered labels appears: None, never the first exchange's value", v9 is None, v9)
    # 10. a candidate key the judge split (an accepted name later rejected on another id): unsure again, never plain
    v10 = solve(ask2("Find Bob's private exponent."), FR)
    if tk.labels is not None and opts(v10):
        k10 = keyof(v10)
        tk.labels.learn(k10, opts(v10)[0][0], "accepted", scope="key", attempt_id="r31", answer_ids=["m"], left=None)
        tk.labels.learn(k10, opts(v10)[0][0], "split", scope="key", attempt_id="r31", answer_ids=["m2"], left=None)
        v10b = solve(ask2("Find Bob's private exponent."), FR)
        leaks += [("10 split", v10b)] if plain(v10b) else []
        check("R31.10 a split key (accepted, then rejected on another id): unsure again, the accepted name first", unsure(v10b) and holds(v10b, b), v10b)
    check("R31 none of the ten new shapes makes a discrete-log value plain where it was not accepted for that very instance", not leaks,
          [(n_, str(v_)[:40]) for n_, v_ in leaks])


def fix3_tests():
    """The independent review of eddb777 (fix round 4c): one regression per finding.

      R32 the discrete-log pass's own material (_DlogMaterial) reads exactly the texts, names and members Material reads
      R33 the same files arranged otherwise (a member moved into the archive changes the reading order, so `stated`): another key
      R34 a delivery that differs only in what Material does not keep (a magic-header file, a PEM body, a member moved into or out
          of the archive, a binary over 1 MiB, a 65th file): another key
      R35 a set only the discrete-log intent reads, beside megabytes of text: no Material is built outside the deadline
      R36 (the second pass, over 7f4ad82) a member of unmatched PEM headers: a linear PEM strip equal to the regex, read_keys only
          where its answer matters
    """
    def plain(v):
        return v is not None and not unsure(v)

    def keyof(v):
        return tk.labels.parse(v).key if unsure(v) and tk.labels is not None else None

    I = mk_instance()
    p, g, a, A, B, o = I["p"], I["g"], I["a"], I["A"], I["B"], I["o"]
    base_txt = f"p = {p}\ng = {g}\nA = {A}\nB = {B}\n"

    # R32: the same texts as Material ------------------------------------------------------------------------------------------
    pem = ("-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf\n"
           "9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END PUBLIC KEY-----\n")
    deliveries = [
        {"params.txt": base_txt.encode()},
        {"evidence.zip": b"PK\x03\x04" + b"\x00" * 26, "evidence.zip -> params.txt": base_txt.encode(), "notes.md": b"# notes\nAlice and Bob.\n"},
        {"k.txt": (base_txt + pem + "after the key\n").encode(), "id.pub": b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC0 user@host\n"},
        {"jwk.json": b'{"kty": "RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP", "e": "AQAB"}',
         "params.txt": base_txt.encode()},
        {"blob.bin": bytes(range(256)) * 8, "params.txt": base_txt.encode(), "u16.txt": base_txt.encode("utf-16")},
        {"chall.py": b"shared = pow(B, a, p)\nprint(shared)\n", "out.txt": base_txt.encode(), "img.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 64},
    ]
    bad = []
    for n_, fl in enumerate(deliveries):
        for extra in ("", f"What is the shared secret of {A} and {B}?"):
            full, light = tk.Material(fl, extra), tk._DlogMaterial(fl, extra)
            if (full.texts, full.names, full.members, full.all_text) != (light.texts, light.names, light.members, light.all_text):
                bad.append((n_, bool(extra)))
            if extra:
                based = tk._DlogMaterial(fl, extra, base=tk._DlogMaterial(fl))
                if (based.texts, based.names, based.all_text) != (full.texts, full.names, full.all_text):
                    bad.append((n_, "base"))
    check(f"R32 _DlogMaterial reads the same texts, names, members and all_text as Material ({len(deliveries)} deliveries x with and without "
          "a question member, and built on a base material)", not bad, bad)
    big = {"params.txt": base_txt.encode(), "log.txt": ("a " * 250000).encode()}
    lm = tk._DlogMaterial(big)
    check("R32 a text past dlog.READ_LIMIT stops the reading (`oversize`) and the discrete-log answer is None, as the instance reader's "
          "`oversize` ambiguity gives", lm.oversize and solve(ask2("What is the shared secret?"), big) is None, (lm.oversize,))
    lt = tk._DlogMaterial({"params.txt": base_txt.encode()}, deadline=time.monotonic() - 1)
    check("R32 a deadline already passed stops the reading (`incomplete`): None",
          lt.incomplete and tk._dlog_answer(ask2("What is the shared secret?"), lt, "What is the shared secret?", time.monotonic() + 1) is None)

    # R33: the same files arranged otherwise ------------------------------------------------------------------------------------
    T1 = (base_txt + f"a = {a + o}\n").encode()
    T2 = f"a = {a + 2 * o}\n".encode()
    Z = b"PK\x03\x04" + b"\x00" * 26
    D1 = {"evidence.zip": Z, "evidence.zip -> n1.txt": T1, "n2.txt": T2}
    D2 = {"evidence.zip": Z, "evidence.zip -> n2.txt": T2, "n1.txt": T1}
    q_ = ask2("What is Alice's private key?")
    v1, v2 = solve(q_, D1), solve(q_, D2)
    st1, st2 = dict(opts(v1)).get("stated:decimal"), dict(opts(v2)).get("stated:decimal")
    check("R33 the review's arrangement pair: the stated values differ (the reader meets them in another order) and so do the keys",
          st1 == str(a + o) and st2 == str(a + 2 * o) and keyof(v1) != keyof(v2), (st1, st2, keyof(v1), keyof(v2)))
    if tk.labels is not None and keyof(v1):
        tk.labels.learn(keyof(v1), "stated:decimal", "accepted", scope="key", attempt_id="r33", answer_ids=["m"], left=None)
        r1, r2 = solve(q_, D1), solve(q_, D2)
        check("R33 `stated:decimal` accepted on one arrangement: it replays plain there, the other arrangement stays unsure",
              r1 == str(a + o) and not plain(r2), (r1, str(r2)[:50]))

    # R34: what Material does not keep is still part of the key ----------------------------------------------------------------
    q2 = ask2("What is the shared secret?")
    pairs = [("a magic-header member's bytes", {"p.txt": base_txt.encode(), "cap.zip": b"PK\x03\x04" + b"\x00" * 20 + b"\x00"},
              {"p.txt": base_txt.encode(), "cap.zip": b"PK\x03\x04" + b"\x00" * 20 + b"\x01"}),
             ("a PEM block's body", {"p.txt": (base_txt + pem).encode()}, {"p.txt": (base_txt + pem.replace("MFww", "MFwx")).encode()}),
             ("a member moved into the archive", {"evidence.zip": Z, "evidence.zip -> p.txt": base_txt.encode()},
              {"evidence.zip": Z, "p.txt": base_txt.encode()}),
             ("a binary over 1 MiB", {"p.txt": base_txt.encode(), "big.bin": b"\x01" * (1 << 21)},
              {"p.txt": base_txt.encode(), "big.bin": b"\x01" * ((1 << 21) - 1) + b"\x02"}),
             ("a 65th file", dict({"p.txt": base_txt.encode()}, **{f"z{i:02d}.bin": b"\x00\x01" * 8 for i in range(64)}),
              dict({"p.txt": base_txt.encode()}, **{f"z{i:02d}.bin": b"\x00\x01" * 8 for i in range(63)}, z63=b"\x00\x02" * 8))]
    same = []
    for nm, fa, fb in pairs:
        ka, kb = keyof(solve(q2, fa)), keyof(solve(q2, fb))
        if ka is None or kb is None or ka == kb:
            same.append((nm, ka, kb))
    check(f"R34 {len(pairs)} deliveries that differ only in what Material does not keep (magic-header bytes, a PEM body, the archive, "
          "a binary over 1 MiB, a 65th file): each has another key", not same, same)

    # R35: no Material outside the deadline ---------------------------------------------------------------------------------------
    line = "a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a\n"
    slow = []
    for nf in (1, 2, 3):
        fl = {"params.txt": base_txt.encode()}
        fl.update({f"log{i}.txt": (line * (500_000 // len(line))).encode() for i in range(nf)})
        for q3 in (ask2("Find the discrete log of A to base g."), ask2("Find the discrete log of A to base g.", "json")):
            t0 = time.monotonic()
            v = solve(q3, fl)
            dt = time.monotonic() - t0
            if v is not None or dt > 0.3:
                slow.append((nf, q3["answer_format"]["kind"], round(dt, 2), str(v)[:20]))
    check("R35 a question only the discrete-log intent reads (or a json kind it never reads) beside 1 to 3 x 500 KB of word-like text: "
          "None in under 0.3 s each (a Material build took 0.9 s a file, outside every deadline)", not slow, slow)
    v = solve(ask2("Find the discrete log of A to base g."), {"params.txt": base_txt.encode(), "notes.txt": (line * 1000).encode()})
    check("R35 control: the same question beside 79 KB of text: the log first among the candidates", holds(v, a), v)

    # R36: the review of 7f4ad82, a member of unmatched PEM headers (read_keys and the PEM strip grew with the square of its size) -------
    rx_pem = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.S)
    toks = ["-----BEGIN A-----", "-----END A-----", "-----BEGIN B C-----", "-----END B C-----", "-----BEGIN ", "-----END ", "-----", "A", "B", " ",
            "x", "\n", "-", "-----BEGIN A-----END A-----", "-----BEGIN AB-----", "-----END AB-----", "-----BEGIN a-----", "-----END A ------",
            "-----BEGIN A -----", "-----BEGIN -----", "-----BEGIN  -----", "-----END  -----", "1", "-----BEGIN 1-----", "-----END 1-----"]
    r_ = random.Random(36)
    diff = [s_ for s_ in ("".join(r_.choice(toks) for _ in range(r_.randrange(0, 50))) for _ in range(4000)) if tk._strip_pem(s_) != rx_pem.sub("", s_)]
    check("R36 _strip_pem equals Material's PEM regex on 4000 random strings of BEGIN / END tags, labels and junk", not diff, diff[:2])
    hostile = {"params.txt": base_txt.encode(), "notes.txt": ("-----BEGIN A-----\n" * 5600).encode()}
    t0 = time.monotonic()
    v = solve(ask2("Find the discrete log of A to base g."), hostile)
    dt = time.monotonic() - t0
    check(f"R36 100 KB of unmatched PEM headers beside the instance, a question only the dlog intent reads: {dt:.3f} s (was 2.8 s), "
          "the log first among the candidates", dt < 0.3 and holds(v, a), (dt, str(v)[:40]))
    mixed = {"params.txt": base_txt.encode(), "notes.txt": ("-----BEGIN A-----\nzz\n" * 40 + pem + "tail -----END A-----\n").encode()}
    full, light = tk.Material(mixed), tk._DlogMaterial(mixed)
    check("R36 a member of matched and unmatched PEM headers: _DlogMaterial's texts equal Material's (the regex's)", full.texts == light.texts)


def main():
    lib_tests()
    tk_tests()
    fuzz_tests()
    review_tests()
    round2_tests()
    fix1_tests()
    fix2_tests()
    fix3_tests()
    print("timings: " + ", ".join(f"{k}={v:.3f}s" for k, v in TIMES.items()))
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: {FAILED}")
        return 1
    print("\nok: all discrete-log checks passed")
    return 0


def run(checks=main):
    """checks() on the CPU clock (SH-09): for the run, time.monotonic and time.perf_counter read process CPU
    time, so every budget and deadline of the toolkit and dlog.py, and every time bound of this script, keeps
    its number in seconds of work. A full-suite run on a loaded machine (the script then took 8x its time)
    left `R10 control: ... under 200 KB of unrelated lines` None: the toolkit's wall-clock budget ran out
    while the process waited for a core."""
    sys.path.append(str(REPO / "tests"))       # last: tests/ shadows no solver module
    from sh09_clocks import cpu_clock
    with cpu_clock():
        return checks()


if __name__ == "__main__":
    sys.exit(run())
