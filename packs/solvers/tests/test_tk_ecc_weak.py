#!/usr/bin/env python3
"""Offline tests of weak-curve private-scalar recovery: solvers/common/ecc_weak.py (the maths) and
its wiring into solvers/toolkits/modern_crypto.py (the `ecc_d` intent, the curve reader, solve_set).

  .venv/bin/python tests/test_tk_ecc_weak.py

No network and no token. Every fixture is built here. Three weaknesses are exercised, each with a
near-miss beside it that must give None:

* an anomalous curve #E == p (Smart's attack), proven exact against brute point counts;
* a singular curve: a cusp (y^2 = x^3, map to F_p^+) and a split node (map to F_p^*, p-1 smooth),
  and a non-split node that must DECLINE;
* a smooth group order (Pohlig-Hellman over the points).

The never-wrong contract is checked directly: a strong curve, a point off the curve, a wrong public
point and a non-smooth order all give None, and the only scalar ever returned satisfies d*G == Q.
Prints one line per check and `ok` at the end; exits 1 when a check fails.
"""
import importlib.util
import os
import random
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_TESTING"] = "1"
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))

spec = importlib.util.spec_from_file_location("ecc_weak", REPO / "solvers" / "common" / "ecc_weak.py")
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)

tkspec = importlib.util.spec_from_file_location("tk_modern_crypto", REPO / "solvers" / "toolkits" / "modern_crypto.py")
tk = importlib.util.module_from_spec(tkspec)
tkspec.loader.exec_module(tk)

FAILED = []
RND = random.Random(20261024)


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)


def legendre(a, p):
    return pow(a % p, (p - 1) // 2, p)


def curve_order(p, a, b):
    """#E(F_p) by brute Legendre sum; only for the small primes used here."""
    c = 1
    for x in range(p):
        ls = legendre((x * x * x + a * x + b) % p, p)
        c += 1 + (1 if ls == 1 else (-1 if ls == p - 1 else 0))
    return c


def a_point(p, a, b):
    for gx in range(1, p):
        f = (gx ** 3 + a * gx + b) % p
        gy = e.tonelli(f, p)
        if gy and gy != 0:
            return (gx, gy)
    raise AssertionError("no point")


def q(question, kind="integer", pattern=None):
    fmt = {"kind": kind}
    if pattern:
        fmt["pattern"] = pattern
    return {"id": "d", "qid": "d", "answer_id": "d", "question": question, "answer_format": fmt}


def solve(question, files):
    return tk.solve_set([question], files, {})["d"]


SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


# ---- the library maths ------------------------------------------------------------------------------

def test_anomalous():
    # two curves confirmed anomalous (#E == p) by brute point count
    for p, a, b in ((1013, 259, 320), (5003, 158, 4162)):
        check(f"anomalous fixture p={p} has #E == p", curve_order(p, a, b) == p)
        G = a_point(p, a, b)
        bad = 0
        for _ in range(25):
            d = RND.randrange(1, p)
            Q = e.ec_mul(d, G, p, a)
            if e._smart_scalar(p, a, b, G, Q) != d:
                bad += 1
        check(f"Smart's attack recovers d exactly on p={p} (25/25)", bad == 0, f"{25 - bad}/25")
        d = RND.randrange(1, p)
        Q = e.ec_mul(d, G, p, a)
        check(f"recover_scalar routes to the anomalous answer on p={p}", e.recover_scalar(p, a, b, G, Q) == d)


def test_singular_cusp():
    p = SECP_P
    g = RND.randrange(2, p)
    G = (g * g % p, pow(g, 3, p))                 # (u^2, u^3) is on y^2 = x^3
    check("cusp fixture: G is on y^2 = x^3", e.on_curve(G, p, 0, 0))
    d = RND.randrange(2, p)
    Q = e.ec_mul(d, G, p, 0)
    got = e.recover_scalar(p, 0, 0, G, Q)
    check("cusp: recovered d is exact and verifies d*G == Q", got == d and e.ec_mul(got, G, p, 0) == Q)
    check("cusp: weakness label is 'singular'", e.weakness(p, 0, 0) == "singular")


def smooth_prime(bits):
    sp = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    while True:
        m = 1
        while m.bit_length() < bits:
            m *= RND.choice(sp)
        for mult in (m, m * 2, m * 3):
            if e.is_prime(mult + 1):
                return mult + 1


def test_singular_node():
    p = smooth_prime(46)
    # pick alpha so that c = 3*alpha is a quadratic residue (split node)
    alpha = None
    for cand in range(2, 4000):
        if e.tonelli(3 * cand % p, p) is not None and 3 * cand % p != 0:
            alpha = cand
            break
    a = (-3 * alpha * alpha) % p
    b = (2 * pow(alpha, 3, p)) % p
    check("split-node fixture is singular", (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p == 0)
    G = None
    for _ in range(5000):
        x = RND.randrange(0, p)
        if (x - alpha) % p == 0:
            continue
        y = e.tonelli((x ** 3 + a * x + b) % p, p)
        if y and y != 0:
            G = (x, y)
            break
    d = RND.randrange(2, p - 1)
    Q = e.ec_mul(d, G, p, a)
    got = e.recover_scalar(p, a, b, G, Q)
    check("split node: recovered d verifies d*G == Q (p-1 smooth)", got is not None and e.ec_mul(got, G, p, a) == Q, got)

    # a non-split node (3*alpha a non-residue) must DECLINE, never return a wrong value
    alpha2 = None
    for cand in range(2, 4000):
        if e.tonelli(3 * cand % p, p) is None:
            alpha2 = cand
            break
    a2 = (-3 * alpha2 * alpha2) % p
    b2 = (2 * pow(alpha2, 3, p)) % p
    G2 = None
    for _ in range(5000):
        x = RND.randrange(0, p)
        if (x - alpha2) % p == 0:
            continue
        y = e.tonelli((x ** 3 + a2 * x + b2) % p, p)
        if y and y != 0:
            G2 = (x, y)
            break
    if G2 is not None:
        Q2 = e.ec_mul(RND.randrange(2, p), G2, p, a2)
        check("non-split node declines (None, not a wrong value)", e.recover_scalar(p, a2, b2, G2, Q2) is None)


def test_smooth_order():
    p = 7001
    a = b = o = None
    for _ in range(400):
        a = RND.randrange(0, p)
        b = RND.randrange(0, p)
        if (4 * a * a * a + 27 * b * b) % p == 0:
            continue
        o = curve_order(p, a, b)
        if o != p and o > 100:
            break
    G = a_point(p, a, b)
    d = RND.randrange(2, o)
    Q = e.ec_mul(d, G, p, a)
    got = e.recover_scalar(p, a, b, G, Q, order=o)
    check("smooth order: recovered d verifies d*G == Q (Pohlig-Hellman)", got is not None and e.ec_mul(got, G, p, a) == Q, got)
    check("smooth order: weakness label is 'smooth'", e.weakness(p, a, b, o) == "smooth")


def test_never_wrong():
    # a point off the curve
    check("point not on curve -> None", e.recover_scalar(1013, 259, 320, (1, 1), (2, 2)) is None)
    # wrong public point on an anomalous curve
    G = a_point(1013, 259, 320)
    Q = e.ec_mul(5, G, 1013, 259)
    Qwrong = e.ec_add(Q, G, 1013, 259)        # (d+1)*G, not matched to the claimed d
    got = e.recover_scalar(1013, 259, 320, G, Qwrong)
    check("recover never returns a value that fails d*G == Q", got is None or e.ec_mul(got, G, 1013, 259) == Qwrong)
    # a strong curve (secp256r1) with a prime order given -> declines fast, never a wrong value
    P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = (-3) % P
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    G = (Gx, Gy)
    Q = e.ec_mul(12345678901234567890, G, P, a)
    import time
    t0 = time.monotonic()
    got = e.recover_scalar(P, a, b, G, Q, order=n, deadline=time.monotonic() + 3)
    check("strong curve (prime order) declines", got is None, got)
    check("strong-curve decline is fast (< 2s, no huge table)", time.monotonic() - t0 < 2.0, round(time.monotonic() - t0, 3))


# ---- the toolkit: intent, curve reader, solve_set ---------------------------------------------------

def test_toolkit_solve_set():
    # anomalous, kind=integer -> plain decimal
    p, a, b = 1013, 259, 320
    G = a_point(p, a, b)
    d = 577
    Q = e.ec_mul(d, G, p, a)
    txt = f"The server used an anomalous elliptic curve.\np = {p}\na = {a}\nb = {b}\nG = ({G[0]}, {G[1]})\nQ = ({Q[0]}, {Q[1]})\n"
    ans = solve(q("Recover the private scalar d such that Q = d*G on the elliptic curve."), {"c.txt": txt.encode()})
    check("solve_set anomalous: plain decimal d", ans == str(d), ans)

    # cusp, 'public key = (x,y)' two-word label, hex pattern answer
    pc = SECP_P
    g = RND.randrange(2, pc)
    Gc = (g * g % pc, pow(g, 3, pc))
    dc = RND.randrange(2, pc)
    Qc = e.ec_mul(dc, Gc, pc, 0)
    txt = f"The curve y^2 = x^3 is singular.\np = {pc}\na = 0\nb = 0\nG = ({Gc[0]}, {Gc[1]})\npublic key = ({Qc[0]}, {Qc[1]})\n"
    ans = solve(q("Find the private key (the discrete logarithm of the public point) on this singular curve, in hexadecimal.",
                  kind="exact_text", pattern=r"[0-9a-f]+"), {"c.txt": txt.encode()})
    check("solve_set cusp: plain hex (hexadecimal requested), value verifies", isinstance(ans, str) and int(ans, 16) == dc, ans)
    # with an ambiguous format (no 'hex' word, a pattern decimal also matches) the answer is unsure, never a wrong plain
    amb = solve(q("Find the private key (discrete logarithm of the public point) on this singular curve.",
                  kind="exact_text", pattern=r"[0-9a-f]+"), {"c.txt": txt.encode()})
    check("solve_set cusp: an ambiguous format is an unsure pick, not a wrong plain",
          isinstance(amb, str) and amb.startswith("??"), amb)

    # smooth order via solve_set
    ps = 7001
    aa = bb = oo = None
    r2 = random.Random(7)
    for _ in range(400):
        aa = r2.randrange(0, ps)
        bb = r2.randrange(0, ps)
        if (4 * aa * aa * aa + 27 * bb * bb) % ps == 0:
            continue
        oo = curve_order(ps, aa, bb)
        if oo != ps and oo > 100:
            break
    Gs = a_point(ps, aa, bb)
    ds = r2.randrange(2, oo)
    Qs = e.ec_mul(ds, Gs, ps, aa)
    txt = f"p = {ps}\na = {aa}\nb = {bb}\nn = {oo}\ngenerator = ({Gs[0]}, {Gs[1]})\npublic = ({Qs[0]}, {Qs[1]})\n"
    ans = solve(q("The group order is smooth; recover the private scalar by Pohlig-Hellman on this elliptic curve."), {"s.txt": txt.encode()})
    check("solve_set smooth: plain d verifies d*G == Q", ans is not None and e.ec_mul(int(ans), Gs, ps, aa) == Qs, ans)

    # a DERIVED question (d mod N) must be None even though the curve is weak
    txt = f"p = {p}\na = {a}\nb = {b}\nG = ({G[0]}, {G[1]})\nQ = ({Q[0]}, {Q[1]})\n"
    ans = solve(q("On this anomalous elliptic curve, what is the private scalar d modulo 1000?"), {"c.txt": txt.encode()})
    check("solve_set: a derived question (d mod 1000) is None", ans is None, ans)

    # a strong curve read by the toolkit -> None (never a wrong plain)
    P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    aN = (-3) % P
    bN = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    GN = (Gx, Gy)
    QN = e.ec_mul(424242, GN, P, aN)
    txt = f"p = {P}\na = {aN}\nb = {bN}\nG = ({Gx}, {Gy})\nQ = ({QN[0]}, {QN[1]})\n"
    ans = solve(q("Recover the private key d on this elliptic curve (ECDLP)."), {"n.txt": txt.encode()})
    check("solve_set strong curve: None (never wrong)", ans is None, ans)

    # a non-ECC crypto question is untouched (no ecc_d intent)
    check("intent: a plain RSA question is not ecc_d", tk.intent(q("What is the RSA private key d?")) != "ecc_d")
    check("intent: an anomalous-curve private-scalar question is ecc_d",
          tk.intent(q("Recover the private scalar on the anomalous elliptic curve.")) == "ecc_d")


def main():
    for fn in (test_anomalous, test_singular_cusp, test_singular_node, test_smooth_order,
               test_never_wrong, test_toolkit_solve_set):
        fn()
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
