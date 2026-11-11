"""Textbook RSA, made quick: e = 3. Writes output.txt."""

import secrets
from pathlib import Path

E = 3


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def prime(bits: int) -> int:
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if n % E != 1 and is_probable_prime(n):
            return n


p, q = prime(1024), prime(1024)
n = p * q
m = int.from_bytes(Path("flag.txt").read_bytes().strip(), "big")
c = pow(m, E, n)
Path("output.txt").write_text(f"n = {n}\ne = {E}\nc = {c}\n")
