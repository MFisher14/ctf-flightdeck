#!/usr/bin/env python3
"""Offline tests of solvers/common/rsa_lattice.py and its wiring in the modern_crypto toolkit (Day 26):
Coppersmith (stereotyped message, partial prime), Boneh-Durfee, ROCA. Every attack has a known-vulnerable
key (recovered AND verified) and a safe key (None, no false factorization).

  .venv/bin/python tests/test_day26_rsa_lattice.py

Fixed seed, no network, no token. Takes a few minutes (pure-Python LLL).
"""
import importlib.util
import math
import random
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))
import rsa_lattice as R  # noqa: E402

sys.path.insert(0, str(REPO / "tests"))
import loadclock  # noqa: E402  (tests/loadclock.py)

spec = importlib.util.spec_from_file_location("tk_mc26", REPO / "solvers" / "toolkits" / "modern_crypto.py")
tk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tk)

RND = random.Random(26)
FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)


def prime(bits):
    while True:
        c = RND.getrandbits(bits) | (1 << (bits - 1)) | 1
        if tk.lib.is_prime(c):
            return c


def dl(s=120):
    return time.monotonic() + s


def test_lll():
    b = R.lll([[1, 1, 1], [-1, 0, 2], [3, 5, 6]])
    check("LLL reduces a known basis", b == [[0, 1, 0], [1, 0, 1], [-1, 0, 2]], b)
    check("LLL gives None on dependent rows", R.lll([[1, 2], [2, 4]]) is None)
    big = [[RND.getrandbits(300) for _ in range(12)] for _ in range(12)]
    check("LLL gives None past a deadline", R.lll(big, deadline=time.monotonic() - 1) is None)


def test_stereotyped():
    p, q = prime(256), prime(256)
    n, e = p * q, 3
    msg = b"The flag is: ABCDEFGHIJKL"
    c = pow(int.from_bytes(msg, "big"), e, n)
    got = R.stereotyped_message(n, e, c, prefix=b"The flag is: ", unknown_len=12, deadline=dl())
    check("stereotyped message (known prefix) recovered and re-encrypts", got == msg, got)
    msg2 = b"ABCDEFGHIJKL: flag end"
    c2 = pow(int.from_bytes(msg2, "big"), e, n)
    got = R.stereotyped_message(n, e, c2, suffix=b": flag end", unknown_len=12, deadline=dl())
    check("stereotyped message (known suffix)", got == msg2, got)
    check("too many unknown bytes (beyond n^(1/e)) -> None",
          R.stereotyped_message(n, e, c, prefix=b"The flag is: ", unknown_len=100, deadline=dl()) is None)
    check("wrong prefix -> None, never a wrong message",
          R.stereotyped_message(n, e, c, prefix=b"The flag was: ", unknown_len=12, deadline=dl()) is None)
    cr = pow(RND.randrange(2, n - 1), e, n)
    check("random ciphertext with a stated prefix -> None",
          R.stereotyped_message(n, e, cr, prefix=b"flag{", unknown_len=12, deadline=dl()) is None)


def test_partial_prime():
    p, q = prime(256), prime(256)
    n = p * q
    want = tuple(sorted((p, q)))
    check("partial prime, 150 high bits known", R.partial_prime(n, p >> 106, 150, "high", 256, deadline=dl()) == want)
    check("partial prime, 150 low bits known",
          R.partial_prime(n, p & ((1 << 150) - 1), 150, "low", 256, deadline=dl()) == want)
    check("partial prime with only 60 bits known -> None (beyond the bound)",
          R.partial_prime(n, p >> 196, 60, "high", 256, deadline=dl()) is None)
    got = R.partial_prime(n, prime(150), 150, "high", 256, deadline=dl(30))
    check("unrelated high bits -> None", got is None, got)
    got = R.partial_prime(prime(512), prime(150), 150, "high", 256, deadline=dl(30))
    check("a prime modulus -> None", got is None, got)


def keypair(bits, dfrac):
    while True:
        p, q = prime(bits // 2), prime(bits // 2)
        if p != q and p < q < 2 * p:
            break
    n, phi = p * q, (p - 1) * (q - 1)
    nb = int(bits * dfrac)
    while True:
        d = RND.getrandbits(nb) | 1 | (1 << (nb - 1))
        if math.gcd(d, phi) == 1:
            return n, pow(d, -1, phi), d, p, q


def test_boneh_durfee():
    while True:                  # a key beyond Wiener (the 0.25 band is near its edge)
        n, e, d, p, q = keypair(256, 0.25)
        if tk.lib.wiener(n, e) is None:
            break
    got = R.boneh_durfee(n, e, delta=0.26, m=4, t=2, deadline=dl(200))
    check("Boneh-Durfee recovers d ~ n^0.25 and verifies it",
          got is not None and got[0] == d and got[1] * got[2] == n, got)
    check("that d is beyond Wiener's bound for this key", tk.lib.wiener(n, e) is None)
    p, q = prime(128), prime(128)
    got = R.boneh_durfee(p * q, 65537, delta=0.26, m=3, t=1, deadline=dl(60))
    check("safe key (e=65537) -> None", got is None, got)
    n2, e2, *_ = keypair(256, 0.6)
    check("large d (0.6) -> None", R.boneh_durfee(n2, e2, delta=0.26, m=3, t=1, deadline=dl(60)) is None)


def roca_prime(M, pbits):
    while True:
        a = RND.randrange(1, 10 ** 6)
        k = RND.getrandbits(pbits - M.bit_length()) | (1 << (pbits - M.bit_length() - 1))
        p = k * M + pow(65537, a, M)
        if tk.lib.is_prime(p):
            return p


def roca_prime_at(M, pbits, a, rnd):
    """A prime k * M + 65537^a mod M of pbits bits: the ROCA search over a finds it at step a."""
    while True:
        k = rnd.getrandbits(pbits - M.bit_length()) | (1 << (pbits - M.bit_length() - 1))
        p = k * M + pow(65537, a, M)
        if tk.lib.is_prime(p):
            return p


# SH-10: the toy key's primes sit at fixed steps of the ROCA search (the search costs about 13 ms of CPU a
# step). They came from the module's shared RND, so the step, and with it the cost, depended on which tests
# had drawn from RND before this one in the same process: 8,978 steps (106 s of CPU) after the four tests
# above, a different key when run alone. On a loaded machine the 120 s wall deadline then ran out first.
TOY_STEP_P, TOY_STEP_Q = 1000, 21000


def test_roca():
    M39 = 1
    for pr in R._PRIMES[:39]:
        M39 *= pr
    p, q = roca_prime(M39, 256), roca_prime(M39, 256)
    check("ROCA fingerprint: an Infineon-form modulus is detected", R.roca_fingerprint(p * q))
    safe = [prime(256) * prime(256) for _ in range(40)]
    check("ROCA fingerprint: 40 random moduli are not flagged", not any(R.roca_fingerprint(s) for s in safe))
    # The search's deadlines are counted in CPU seconds (tests/loadclock.cpu_clock), the same numbers.
    with loadclock.cpu_clock():
        got, took = loadclock.cpu_seconds(R.roca_factor, p * q, deadline=dl(20))
        check("a real-size ROCA key -> None within the cap (25 s of CPU)", got is None and took < 25, (got, took))
        M12 = 1
        for pr in R._PRIMES[:12]:
            M12 *= pr
        rnd = random.Random(2026)
        p, q = roca_prime_at(M12, 64, TOY_STEP_P, rnd), roca_prime_at(M12, 64, TOY_STEP_Q, rnd)
        got = R.roca_factor(p * q, check=False, n_primes=12, deadline=dl(120))
        check("toy ROCA-form modulus factored and verified", got == tuple(sorted((p, q))), got)
        r, s = prime(64), prime(64)
        check("toy search on a safe modulus -> None", R.roca_factor(r * s, check=False, n_primes=12, deadline=dl(8)) is None)


def test_wiring():
    p, q = prime(256), prime(256)
    n, e = p * q, 65537
    text = f"n = {n}\ne = {e}\np_high = {p >> 106}\n"
    M = tk.material({"challenge.txt": text.encode()})
    rs = tk.solve_rsa(M, deadline=dl(120))
    ok = [r for r in rs if r.attack == "partial_prime_high"]
    check("solve_rsa: labelled high bits of p factor n (verified)",
          bool(ok) and ok[0].factors == sorted((p, q)) and ok[0].d is not None, [r.attack for r in rs])
    msg = b"flag{lattice_ok}"
    c = pow(int.from_bytes(msg, "big"), e, n)
    M = tk.material({"challenge.txt": f"{text}c = {c}\n".encode()})
    rs = [r for r in tk.solve_rsa(M, deadline=dl(120)) if r.attack == "partial_prime_high"]
    check("solve_rsa: the message is read after the lattice factoring",
          bool(rs) and any(pt == msg for _, pt in rs[0].messages))
    M = tk.material({"challenge.txt": f"n = {n}\ne = {e}\np_high = {prime(150)}\n".encode()})
    rs = tk.solve_rsa(M, deadline=dl(60))
    check("solve_rsa: an unrelated hint gives no result", not any(r.attack.startswith("partial") for r in rs),
          [r.attack for r in rs])
    p, q = prime(256), prime(256)
    n = p * q
    msg = b"The flag is:ABCDEFGHIJKL"
    c = pow(int.from_bytes(msg, "big"), 3, n)
    M = tk.material({"challenge.txt": f"n = {n}\ne = 3\nc = {c}\nknown_prefix = 0x{b"The flag is:".hex()}\nunknown_len = 12\n".encode()})
    rs = [r for r in tk.solve_rsa(M, deadline=dl(120)) if r.attack == "stereotyped_message"]
    check("solve_rsa: stereotyped message recovered", bool(rs) and any(pt == msg for _, pt in rs[0].messages))


def main():
    t0 = time.time()
    for fn in (test_lll, test_stereotyped, test_partial_prime, test_boneh_durfee, test_roca, test_wiring):
        fn()
    print(f"({time.time() - t0:.0f} s)")
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
