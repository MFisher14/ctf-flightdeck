#!/usr/bin/env python3
"""Gate-safe (about 10-20 s) never-wrong checks of solvers/common/rsa_lattice.py. The full recoveries
(Boneh-Durfee, toy ROCA, large partial primes) stay in tests/test_day26_rsa_lattice.py (slow).

  .venv/bin/python tests/test_day26_rsa_lattice_fast.py
"""
import importlib.util
import random
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))
import rsa_lattice as R  # noqa: E402

spec = importlib.util.spec_from_file_location("tk_mc26f", REPO / "solvers" / "toolkits" / "modern_crypto.py")
tk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tk)

RND = random.Random(2626)
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


def dl(s):
    return time.monotonic() + s


def main():
    t0 = time.time()
    p, q = prime(256), prime(256)
    n, e = p * q, 3
    msg = b"The flag is: ABCDEFGHIJKL"
    c = pow(int.from_bytes(msg, "big"), e, n)
    check("stereotyped: correct prefix recovers and re-encrypts",
          R.stereotyped_message(n, e, c, prefix=b"The flag is: ", unknown_len=12, deadline=dl(10)) == msg)
    check("stereotyped: wrong prefix -> None",
          R.stereotyped_message(n, e, c, prefix=b"The flag was: ", unknown_len=12, deadline=dl(2.5)) is None)
    check("stereotyped: unknown length beyond n^(1/e) -> None",
          R.stereotyped_message(n, e, c, prefix=b"The flag is: ", unknown_len=100, deadline=dl(2.5)) is None)
    cr = pow(RND.randrange(2, n - 1), e, n)
    check("stereotyped: random ciphertext -> None",
          R.stereotyped_message(n, e, cr, prefix=b"flag{", unknown_len=12, deadline=dl(2.5)) is None)
    check("stereotyped: out-of-range ciphertext -> None",
          R.stereotyped_message(n, e, n + 5, prefix=b"x", unknown_len=2, deadline=dl(5)) is None)

    # one small real recovery, verified in code
    P, Q = prime(128), prime(128)
    N = P * Q
    got = R.partial_prime(N, P >> 44, 84, "high", 128, deadline=dl(20))
    check("partial prime: 84 of 128 high bits -> factors with p*q == n",
          got is not None and got[0] * got[1] == N and 1 < got[0] < N, got)
    # degenerate / unrelated hints
    for label, known, kb in (("known=0", 0, 84), ("known=1", 1, 84), ("known=n", N, 84)):
        got = R.partial_prime(N, known, kb, "high", 128, deadline=dl(2.5))
        check(f"partial prime: {label} -> None or a verified split",
              got is None or (got[0] * got[1] == N and 1 < got[0] < N), got)
    got = R.partial_prime(N, prime(84), 84, "high", 128, deadline=dl(2.5))
    check("partial prime: unrelated bits -> None or a verified split",
          got is None or (got[0] * got[1] == N and 1 < got[0] < N), got)
    # a hint that is 3*p shares a factor with n but is not a divisor: the low-bit path must not accept it
    got = R.partial_prime(N, (3 * P) >> 44, 84, "high", 128, deadline=dl(2.5))
    check("partial prime: hint from 3p -> None or a verified split",
          got is None or (got[0] * got[1] == N and 1 < got[0] < N), got)
    check("partial prime: a prime modulus -> None", R.partial_prime(prime(256), prime(84), 84, "high", 128, deadline=dl(2.5)) is None)
    check("partial prime: too few bits (30 of 128) -> None", R.partial_prime(N, P >> 98, 30, "high", 128, deadline=dl(2.5)) is None)

    # Boneh-Durfee on a safe key
    a, b = prime(96), prime(96)
    check("Boneh-Durfee: safe key e=65537 -> None", R.boneh_durfee(a * b, 65537, delta=0.26, m=3, t=1, deadline=dl(2.5)) is None)
    check("Boneh-Durfee: tiny modulus -> None", R.boneh_durfee(77, 7, deadline=dl(2)) is None)

    # ROCA: detection is exact on random moduli; a real-size Infineon-form key is not factored in a tight cap
    check("ROCA fingerprint: 40 random moduli not flagged", not any(R.roca_fingerprint(prime(128) * prime(128)) for _ in range(40)))
    M39 = 1
    for pr in R._PRIMES[:39]:
        M39 *= pr

    def roca_prime(bits):
        while True:
            k = RND.getrandbits(bits - M39.bit_length()) | (1 << (bits - M39.bit_length() - 1))
            x = k * M39 + pow(65537, RND.randrange(1, 10 ** 6), M39)
            if tk.lib.is_prime(x):
                return x

    rn = roca_prime(256) * roca_prime(256)
    check("ROCA fingerprint: Infineon-form modulus detected", R.roca_fingerprint(rn))
    t1 = time.time()
    got = R.roca_factor(rn, deadline=dl(6))
    check("ROCA: real-size key -> None within a tight cap", got is None and time.time() - t1 < 10, (got, time.time() - t1))

    print(f"({time.time() - t0:.1f} s)")
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
