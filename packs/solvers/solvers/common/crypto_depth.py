"""Depth crypto primitives for offline AEAD and biased-nonce analysis.

All recovery candidates are verified before anything is believed:

  * AES-GCM / GMAC nonce reuse (the "forbidden attack"). Given two or more
    ciphertext+tag pairs produced under the SAME key and the SAME nonce, the
    authentication subkey H = E_K(0^128) is recovered as a root of a polynomial
    over GF(2^128) (the tag mask E_K(J0) cancels between two tags). A recovered
    H is kept only when it REPRODUCES an observed tag that was not used to build
    the polynomial (needs >= 3 pairs to be unique); with exactly two pairs every
    root is self-consistent, so all roots are returned as candidates. With H and
    the tag mask known, a tag for a chosen (aad, ciphertext) can be forged.
    Nothing here is ever emitted plain: the caller offers H / a forged tag as an
    unsure label (the judge's spelling for it has not been seen).

  * ChaCha20-Poly1305 nonce-reuse analysis for the algebraically supported
    (linear/quadratic Poly1305) cases.  Candidate one-time keys are retained
    only when they reproduce every supplied tag exactly.  The engine never
    asks an oracle and never encrypts or sends a payload.

  * GHASH candidate commitment and partition reports.  These group local
    candidate ``(H, E_K(J0))`` pairs by the tag they predict, or group captured
    observations by their derived counter mask.  The report is an algebraic
    commitment only; it does not claim recovery of the underlying AES key.

  * ECDSA biased- or partial-nonce key recovery via the Hidden Number Problem
    (an LLL lattice). Given N signatures (r, s, z) whose per-signature nonces are
    short (k < 2^L, L stated) the private scalar d is recovered from a reduced
    lattice basis. A recovered d is ACCEPTED ONLY WHEN d*G == the given public
    key, on secp256k1 or P-256; anything else is None. So the lattice heuristic
    can only ever affect recall, never correctness.

Self-contained: no third-party import, and the small amount of GF(2^128), curve
and lattice arithmetic it needs is defined here so the module loads on its own
(solvers/common/modern_crypto.py carries the same curve table; this copy is kept
tiny on purpose).  Library calls are pure computation.  The guarded CLI reads
only a bounded local JSON fixture; there is no network, oracle, execution, or
submission path.

  .venv/bin/python -c "import sys; sys.path.insert(0,'solvers/common'); import crypto_depth"
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from fractions import Fraction
from pathlib import Path


MAX_AEAD_BYTES = 64 * 1024 * 1024
MAX_AEAD_OBSERVATIONS = 64
MAX_GHASH_CANDIDATES = 4096
MAX_GHASH_PARTITION_BLOCKS = 262144
MAX_CLI_JSON = 8 * 1024 * 1024

# ---------------------------------------------------------------------------
# GF(2^128), the GCM field
# ---------------------------------------------------------------------------
# A 16-byte block is read big-endian into a 128-bit integer; bit 127 (the most
# significant) is the x^0 coefficient, matching NIST SP 800-38D / the GHASH
# reduction x^128 + x^7 + x^2 + x + 1.  _R is that polynomial, reflected.
_R = 0xE1 << 120
_MASK = (1 << 128) - 1
# In this (GCM / bit-reflected) representation the MOST significant bit is the
# x^0 coefficient, so the multiplicative identity is 1<<127, not integer 1.
GF_ONE = 1 << 127


def gf_mul(x: int, y: int) -> int:
    """x * y in GF(2^128) under GCM's bit convention. x and y are 128-bit ints."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z & _MASK


def _blocks(data: bytes):
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        if len(chunk) < 16:
            chunk = chunk + b"\x00" * (16 - len(chunk))
        yield int.from_bytes(chunk, "big")


def ghash(h: int, aad: bytes, ct: bytes) -> int:
    """GHASH_H(aad, ct): the authenticated data and ciphertext folded over the
    subkey H, with the trailing 128-bit length block. A 128-bit int."""
    y = 0
    for b in _blocks(aad):
        y = gf_mul(y ^ b, h)
    for b in _blocks(ct):
        y = gf_mul(y ^ b, h)
    length = ((len(aad) * 8) << 64) | (len(ct) * 8)
    y = gf_mul(y ^ (length & _MASK), h)
    return y & _MASK


def gcm_tag(h: int, mask: int, aad: bytes, ct: bytes) -> bytes:
    """The 16-byte GCM tag for (aad, ct) given the subkey H and the tag mask
    S = E_K(J0). This is the forge primitive: with H and S known, any message's
    tag is deterministic."""
    return ((ghash(h, aad, ct) ^ mask) & _MASK).to_bytes(16, "big")


forge_tag = gcm_tag


def _checked_bytes(value, name: str) -> bytes:
    """Return an immutable byte string without accepting text implicitly."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    return bytes(value)


def _checked_aead_data(aad, ciphertext) -> tuple[bytes, bytes]:
    aad_b = _checked_bytes(aad, "aad")
    ct_b = _checked_bytes(ciphertext, "ciphertext")
    if len(aad_b) + len(ct_b) > MAX_AEAD_BYTES:
        raise ValueError(f"authenticated input exceeds {MAX_AEAD_BYTES} bytes")
    return aad_b, ct_b


def _u128(value, name: str) -> int:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) != 16:
            raise ValueError(f"{name} must be exactly 16 bytes")
        return int.from_bytes(raw, "big")
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be a 128-bit integer or 16 bytes")
    if not 0 <= value <= _MASK:
        raise ValueError(f"{name} is outside the 128-bit range")
    return value


def gcm_forge_tag(h, counter_mask, aad=b"", ciphertext=b"", tag_length: int = 16) -> bytes:
    """Build an AES-GCM tag from a recovered authentication key and mask.

    ``counter_mask`` is ``E_K(J0)`` (sometimes called ``S``), supplied either
    as a 128-bit integer or as 16 big-endian bytes.  AAD and ciphertext may
    have any byte length within :data:`MAX_AEAD_BYTES`, including zero and
    non-block-aligned lengths.  GCM tags are the leftmost ``tag_length`` bytes
    of the full tag.  This function performs no encryption and no I/O.
    """
    h_i = _u128(h, "H")
    mask_i = _u128(counter_mask, "counter mask")
    aad_b, ct_b = _checked_aead_data(aad, ciphertext)
    if isinstance(tag_length, bool) or not isinstance(tag_length, int) or not 4 <= tag_length <= 16:
        raise ValueError("GCM tag length must be between 4 and 16 bytes")
    return gcm_tag(h_i, mask_i, aad_b, ct_b)[:tag_length]


# Explicit long name for callers that want to distinguish this from a
# ciphertext-malleability helper.  Keep ``forge_tag`` above for compatibility.
gcm_tag_from_recovered_h = gcm_forge_tag


# ---- polynomials over GF(2^128) (coefficients low-degree first) -------------

def _p_trim(p):
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def _p_add(a, b):
    out = [0] * max(len(a), len(b))
    for i, c in enumerate(a):
        out[i] ^= c
    for i, c in enumerate(b):
        out[i] ^= c
    return _p_trim(out)


def _p_scale(a, s):
    return [gf_mul(c, s) for c in a]


def _p_mul(a, b):
    if a == [0] or b == [0]:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, ca in enumerate(a):
        if not ca:
            continue
        for j, cb in enumerate(b):
            if cb:
                out[i + j] ^= gf_mul(ca, cb)
    return _p_trim(out)


def gf_inv(x: int) -> int:
    """Multiplicative inverse in GF(2^128) (x^(2^128-2))."""
    if x == 0:
        raise ZeroDivisionError("no inverse of 0 in GF(2^128)")
    result = GF_ONE
    base = x
    exp = (1 << 128) - 2
    while exp:
        if exp & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        exp >>= 1
    return result


def _p_monic(p):
    p = _p_trim(list(p))
    lead = p[-1]
    if lead == GF_ONE or lead == 0:
        return p
    inv = gf_inv(lead)
    return _p_scale(p, inv)


def _p_divmod(a, b):
    a = _p_trim(list(a))
    b = _p_trim(list(b))
    if b == [0]:
        raise ZeroDivisionError
    if len(a) < len(b):
        return [0], a
    inv_lead = gf_inv(b[-1])
    quot = [0] * (len(a) - len(b) + 1)
    rem = list(a)
    for i in range(len(a) - len(b), -1, -1):
        coeff = gf_mul(rem[i + len(b) - 1], inv_lead)
        quot[i] = coeff
        if coeff:
            for j in range(len(b)):
                rem[i + j] ^= gf_mul(coeff, b[j])
    return _p_trim(quot), _p_trim(rem)


def _p_mod(a, b):
    return _p_divmod(a, b)[1]


def _p_gcd(a, b):
    a = _p_trim(list(a))
    b = _p_trim(list(b))
    while b != [0]:
        a, b = b, _p_mod(a, b)
    return _p_monic(a) if a != [0] else [0]


def _p_powmod_x_q(mod):
    """X^(2^128) mod `mod`: square the polynomial X 128 times."""
    h = _p_mod([0, GF_ONE], mod)   # X mod mod
    for _ in range(128):
        h = _p_mod(_p_mul(h, h), mod)
    return h


def _rng(seed: int):
    state = seed & _MASK or 0x12345
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & ((1 << 128) - 1)
        yield state


def _edf_linear(g, limit: int = 4000):
    """Roots of a squarefree polynomial all of whose irreducible factors are
    linear (char 2, trace-based equal-degree splitting)."""
    g = _p_monic(g)
    roots = []
    stack = [g]
    rng = _rng(0xC0FFEE)
    guard = 0
    while stack:
        guard += 1
        if guard > limit:
            break
        f = stack.pop()
        f = _p_monic(f)
        d = len(f) - 1
        if d <= 0:
            continue
        if d == 1:
            # X + c  ->  root c
            roots.append(f[0])
            continue
        # trace poly T = sum_{i=0}^{127} (r*X)^(2^i) mod f, for random r
        r = next(rng)
        term = _p_mod([0, r], f)       # r*X mod f
        acc = [0]
        for _ in range(128):
            acc = _p_add(acc, term)
            term = _p_mod(_p_mul(term, term), f)
        c = _p_gcd(f, acc)
        dc = len(c) - 1
        if 0 < dc < d:
            stack.append(c)
            other, _ = _p_divmod(f, c)
            stack.append(other)
        else:
            stack.append(f)          # retry with another r
            guard += 0
    return sorted(set(roots))


def poly_roots(coeffs):
    """Roots in GF(2^128) of the polynomial with the given coefficients
    (low-degree first). Returns a sorted list of 128-bit ints."""
    p = _p_trim(list(coeffs))
    if p == [0]:
        return []
    if len(p) == 1:
        return []                    # non-zero constant: no root
    p = _p_monic(p)
    if len(p) == 2:                  # already linear: one root
        return _edf_linear(p)
    # distinct roots in the field: gcd(p, X^q - X)
    xq = _p_powmod_x_q(p)
    xq_minus_x = _p_add(xq, [0, GF_ONE])
    g = _p_gcd(p, xq_minus_x)
    if g == [0] or len(g) <= 1:
        return []
    return _edf_linear(g)


# ---------------------------------------------------------------------------
# AES-GCM nonce-reuse (the forbidden attack)
# ---------------------------------------------------------------------------

def _ghash_poly(aad: bytes, ct: bytes):
    """GHASH_H(aad, ct) as a polynomial in H (low-degree first); constant term 0.
    Block B_i (1-indexed from the start, length block last) sits at H^(m-i+1)."""
    blocks = list(_blocks(aad)) + list(_blocks(ct))
    length = ((len(aad) * 8) << 64) | (len(ct) * 8)
    blocks.append(length & _MASK)
    m = len(blocks)
    coeffs = [0] * (m + 1)           # index = power of H
    for i, b in enumerate(blocks):   # i = 0..m-1  ->  B_{i+1}, power m-i
        coeffs[m - i] = b
    return _p_trim(coeffs)


def gcm_recover_subkey(pairs):
    """Recover the GCM authentication subkey H from ciphertext+tag pairs made
    under one key and one nonce.

    pairs: a list of (aad, ct, tag) with aad/ct `bytes` and tag 16 `bytes`.
    Returns a list of (H, S) tuples (S = the tag mask E_K(J0)), best first:
      * a single element when a third pair pins H uniquely (H reproduces a tag
        that did not build the polynomial),
      * several candidates when only two pairs are given (every root is then
        self-consistent and none can be ruled out),
      * [] when fewer than two pairs are given or nothing is consistent.
    No value is ever returned unless it reproduces every supplied tag."""
    triples = []
    for ap in pairs or []:
        if len(ap) == 3:
            aad, ct, tag = ap
        elif len(ap) == 2:
            aad, (ct, tag) = b"", ap
        else:
            continue
        tag = bytes(tag)
        if len(tag) != 16:
            continue
        triples.append((bytes(aad or b""), bytes(ct), tag))
    if len(triples) < 2:
        return []
    # Build the polynomial from the two SHORTEST pairs (lowest degree = fastest
    # root find); verify every recovered H against ALL pairs below. Bounded so a
    # pathologically long message cannot stall the root finder.
    order = sorted(range(len(triples)), key=lambda i: len(triples[i][0]) + len(triples[i][1]))
    a0, a1 = triples[order[0]], triples[order[1]]
    if (max(len(a0[0]) + len(a0[1]), len(a1[0]) + len(a1[1])) // 16) + 2 > 512:
        return []
    t0 = int.from_bytes(a0[2], "big")
    t1 = int.from_bytes(a1[2], "big")
    poly = _p_add(_ghash_poly(a0[0], a0[1]), _ghash_poly(a1[0], a1[1]))
    poly = list(poly)
    if not poly:
        poly = [0]
    poly[0] ^= (t0 ^ t1)
    poly = _p_trim(poly)
    cands = poly_roots(poly)
    out = []
    for h in cands:
        if h == 0:
            continue
        mask = ghash(h, a0[0], a0[1]) ^ t0
        ok = True
        for (aad, ct, tag) in triples:
            if gcm_tag(h, mask, aad, ct) != tag:
                ok = False
                break
        if ok:
            out.append((h, mask))
    # With >= 3 pairs the extra tags (not used to build the polynomial) rule out
    # every spurious root, so `out` is already the single true H; with exactly 2
    # pairs every root is self-consistent and all are returned as candidates.
    return out


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 nonce reuse and GHASH commitment/partitioning
# ---------------------------------------------------------------------------

POLY1305_P = (1 << 130) - 5
POLY1305_TAG_MODULUS = 1 << 128
POLY1305_R_MASK = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
MAX_POLY1305_RECOVERY_BLOCKS = 4096
MAX_POLY1305_ROOT_DEGREE = 256


def _normalise_aead_observations(observations) -> list[tuple[bytes, bytes, bytes]]:
    """Validate a bounded sequence of ``(aad, ciphertext, tag)`` records."""
    if observations is None:
        return []
    try:
        iterator = iter(observations)
    except TypeError as exc:
        raise TypeError("observations must be an iterable") from exc
    out = []
    total = 0
    for index, item in enumerate(iterator):
        if index >= MAX_AEAD_OBSERVATIONS:
            raise ValueError(f"at most {MAX_AEAD_OBSERVATIONS} observations are supported")
        if isinstance(item, dict):
            if "ciphertext" in item:
                ct = item["ciphertext"]
            elif "ct" in item:
                ct = item["ct"]
            else:
                raise ValueError(f"observation {index} has no ciphertext")
            aad = item.get("aad", b"")
            if "tag" not in item:
                raise ValueError(f"observation {index} has no tag")
            tag = item["tag"]
        else:
            try:
                aad, ct, tag = item
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"observation {index} must be (aad, ciphertext, tag)"
                ) from exc
        aad_b, ct_b = _checked_aead_data(aad, ct)
        tag_b = _checked_bytes(tag, f"observation {index} tag")
        if len(tag_b) != 16:
            raise ValueError("nonce-reuse recovery requires full 16-byte tags")
        total += len(aad_b) + len(ct_b) + len(tag_b)
        if total > MAX_AEAD_BYTES:
            raise ValueError(f"observations exceed {MAX_AEAD_BYTES} bytes in total")
        out.append((aad_b, ct_b, tag_b))
    return out


def _poly1305_aead_blocks(aad: bytes, ciphertext: bytes):
    """Yield RFC 8439 AEAD MAC blocks as Poly1305 integers.

    Padding belongs to the AEAD construction, so every yielded block is a full
    16 bytes and therefore receives Poly1305's ``2**128`` high bit.
    """
    for data in (aad, ciphertext):
        for offset in range(0, len(data), 16):
            block = data[offset:offset + 16]
            if len(block) != 16:
                block += b"\x00" * (16 - len(block))
            yield int.from_bytes(block, "little") + (1 << 128)
    lengths = len(aad).to_bytes(8, "little") + len(ciphertext).to_bytes(8, "little")
    yield int.from_bytes(lengths, "little") + (1 << 128)


def _check_poly1305_key(r, s) -> tuple[int, int]:
    if isinstance(r, bool) or not isinstance(r, int) or not 0 <= r < (1 << 128):
        raise ValueError("Poly1305 r must be a 128-bit integer")
    if r & ~POLY1305_R_MASK:
        raise ValueError("Poly1305 r is not clamped")
    if isinstance(s, bool) or not isinstance(s, int) or not 0 <= s < POLY1305_TAG_MODULUS:
        raise ValueError("Poly1305 s must be a 128-bit integer")
    return r, s


def poly1305_aead_accumulator(r: int, aad=b"", ciphertext=b"") -> int:
    """Return the RFC 8439 Poly1305 accumulator before adding ``s``."""
    if isinstance(r, bool) or not isinstance(r, int) or not 0 <= r < (1 << 128):
        raise ValueError("Poly1305 r must be a 128-bit integer")
    if r & ~POLY1305_R_MASK:
        raise ValueError("Poly1305 r is not clamped")
    aad_b, ct_b = _checked_aead_data(aad, ciphertext)
    acc = 0
    for block in _poly1305_aead_blocks(aad_b, ct_b):
        acc = ((acc + block) * r) % POLY1305_P
    return acc


def chacha20_poly1305_forge_tag(r: int, s: int, aad=b"", ciphertext=b"") -> bytes:
    """Build an RFC 8439 tag from a recovered one-time ``(r, s)`` key.

    This authenticates already-supplied ciphertext; it neither creates a
    ChaCha20 keystream nor modifies plaintext.  The same one-time key is valid
    only for the reused ChaCha20 key/nonce pair from which it was recovered.
    """
    r_i, s_i = _check_poly1305_key(r, s)
    acc = poly1305_aead_accumulator(r_i, aad, ciphertext)
    return ((acc + s_i) % POLY1305_TAG_MODULUS).to_bytes(16, "little")


# Shorter, protocol-neutral spelling useful in notebooks.
poly1305_aead_tag = chacha20_poly1305_forge_tag


def _poly1305_polynomial(aad: bytes, ciphertext: bytes) -> list[int]:
    block_count = ((len(aad) + 15) // 16) + ((len(ciphertext) + 15) // 16) + 1
    if block_count > MAX_POLY1305_RECOVERY_BLOCKS:
        raise ValueError(
            f"Poly1305 recovery is limited to {MAX_POLY1305_RECOVERY_BLOCKS} MAC blocks"
        )
    blocks = list(_poly1305_aead_blocks(aad, ciphertext))
    # h = n_0*r**m + n_1*r**(m-1) + ... + n_(m-1)*r
    coeffs = [0] * (len(blocks) + 1)
    for index, block in enumerate(blocks):
        coeffs[len(blocks) - index] = block % POLY1305_P
    return coeffs


def _prime_poly_trim(poly: list[int]) -> list[int]:
    while len(poly) > 1 and poly[-1] % POLY1305_P == 0:
        poly.pop()
    return [coefficient % POLY1305_P for coefficient in poly]


def _poly1305_difference(left: list[int], right: list[int]) -> list[int]:
    size = max(len(left), len(right))
    out = [0] * size
    for index in range(size):
        a = left[index] if index < len(left) else 0
        b = right[index] if index < len(right) else 0
        out[index] = (a - b) % POLY1305_P
    return _prime_poly_trim(out)


def _prime_roots_degree_two(poly: list[int]) -> list[int]:
    """Roots modulo ``2**130-5`` for a nonzero polynomial of degree <= 2."""
    poly = _prime_poly_trim(list(poly))
    degree = len(poly) - 1
    if degree <= 0:
        return []
    if degree == 1:
        return [(-poly[0] * pow(poly[1], -1, POLY1305_P)) % POLY1305_P]
    if degree != 2:
        return []
    c, b, a = poly
    discriminant = (b * b - 4 * a * c) % POLY1305_P
    root = pow(discriminant, (POLY1305_P + 1) // 4, POLY1305_P)
    if root * root % POLY1305_P != discriminant:
        return []
    inverse = pow(2 * a, -1, POLY1305_P)
    return sorted({((-b + root) * inverse) % POLY1305_P,
                   ((-b - root) * inverse) % POLY1305_P})


def _prime_poly_add(left: list[int], right: list[int]) -> list[int]:
    size = max(len(left), len(right))
    out = [0] * size
    for index in range(size):
        out[index] = ((left[index] if index < len(left) else 0)
                      + (right[index] if index < len(right) else 0)) % POLY1305_P
    return _prime_poly_trim(out)


def _prime_poly_mul(left: list[int], right: list[int]) -> list[int]:
    if not left or not right:
        return [0]
    out = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        if not a:
            continue
        for j, b in enumerate(right):
            out[i + j] = (out[i + j] + a * b) % POLY1305_P
    return _prime_poly_trim(out)


def _prime_poly_divmod(dividend: list[int], divisor: list[int]):
    dividend = _prime_poly_trim(list(dividend))
    divisor = _prime_poly_trim(list(divisor))
    if divisor == [0]:
        raise ZeroDivisionError("polynomial division by zero")
    if len(dividend) < len(divisor):
        return [0], dividend
    quotient = [0] * (len(dividend) - len(divisor) + 1)
    inverse = pow(divisor[-1], -1, POLY1305_P)
    for offset in range(len(dividend) - len(divisor), -1, -1):
        factor = dividend[offset + len(divisor) - 1] * inverse % POLY1305_P
        quotient[offset] = factor
        if factor:
            for index, coefficient in enumerate(divisor):
                dividend[offset + index] = (
                    dividend[offset + index] - factor * coefficient
                ) % POLY1305_P
    return _prime_poly_trim(quotient), _prime_poly_trim(dividend)


def _prime_poly_mod(poly: list[int], modulus: list[int]) -> list[int]:
    return _prime_poly_divmod(poly, modulus)[1]


def _prime_poly_monic(poly: list[int]) -> list[int]:
    poly = _prime_poly_trim(list(poly))
    if poly == [0] or poly[-1] == 1:
        return poly
    inverse = pow(poly[-1], -1, POLY1305_P)
    return [(coefficient * inverse) % POLY1305_P for coefficient in poly]


def _prime_poly_gcd(left: list[int], right: list[int]) -> list[int]:
    left, right = _prime_poly_trim(list(left)), _prime_poly_trim(list(right))
    while right != [0]:
        left, right = right, _prime_poly_mod(left, right)
    return _prime_poly_monic(left)


def _prime_poly_powmod(base: list[int], exponent: int, modulus: list[int]) -> list[int]:
    result = [1]
    base = _prime_poly_mod(base, modulus)
    while exponent:
        if exponent & 1:
            result = _prime_poly_mod(_prime_poly_mul(result, base), modulus)
        base = _prime_poly_mod(_prime_poly_mul(base, base), modulus)
        exponent >>= 1
    return result


def _prime_poly_roots(poly: list[int], max_degree: int = MAX_POLY1305_ROOT_DEGREE) -> list[int]:
    """All roots of a bounded polynomial over GF(2**130-5).

    ``gcd(f, X**p-X)`` first removes non-linear irreducible factors and repeated
    multiplicities.  Deterministic Cantor--Zassenhaus splits the remaining
    product of linear factors.  This is dependency-free and works for the
    higher-degree Poly1305 equations produced by unequal message layouts.
    """
    poly = _prime_poly_trim(list(poly))
    degree = len(poly) - 1
    if degree <= 0 or degree > max_degree:
        return []
    if degree <= 2:
        return _prime_roots_degree_two(poly)
    f = _prime_poly_monic(poly)
    xp = _prime_poly_powmod([0, 1], POLY1305_P, f)
    linear_product = _prime_poly_gcd(f, _prime_poly_add(xp, [0, -1]))
    if len(linear_product) <= 1:
        return []
    roots: list[int] = []
    stack = [linear_product]
    state = 0x4353435446503133
    guard = 0
    while stack:
        factor = _prime_poly_monic(stack.pop())
        factor_degree = len(factor) - 1
        if factor_degree == 1:
            roots.append((-factor[0] * pow(factor[1], -1, POLY1305_P)) % POLY1305_P)
            continue
        split = None
        for _ in range(max(32, factor_degree * 16)):
            guard += 1
            if guard > max_degree * 128:
                return []
            state = (state * 6364136223846793005 + 1442695040888963407) % POLY1305_P
            # A changing affine polynomial is enough for equal-degree-one splitting.
            probe = _prime_poly_powmod([state, 1], (POLY1305_P - 1) // 2, factor)
            probe = _prime_poly_add(probe, [-1])
            candidate = _prime_poly_gcd(factor, probe)
            if 1 < len(candidate) < len(factor):
                split = candidate
                break
        if split is None:
            return []
        quotient, remainder = _prime_poly_divmod(factor, split)
        if remainder != [0]:
            return []
        stack.extend((split, quotient))
    return sorted(set(root for root in roots
                      if sum(coefficient * pow(root, index, POLY1305_P)
                             for index, coefficient in enumerate(poly)) % POLY1305_P == 0))


def recover_chacha20_poly1305_nonce_reuse(
    observations, max_carry: int = 4, max_degree: int = 2
):
    """Recover candidate Poly1305 one-time keys from nonce-reused records.

    Each observation is ``(aad, ciphertext, 16-byte tag)`` or a mapping with
    those keys.  The same ChaCha20 key *and nonce* must have produced every
    record.  The tag hides a multiple of ``2**128``; all carry differences in
    ``[-max_carry, max_carry]`` are tried (four is exhaustive for Poly1305).

    ``max_degree`` bounds dependency-free finite-field factorisation.  It
    defaults to two for API compatibility; callers may request up to 256 to
    solve unequal-layout/high-degree equations.  Every returned ``(r, s)`` is
    clamped and exactly reproduces *all* observations.
    """
    triples = _normalise_aead_observations(observations)
    if isinstance(max_carry, bool) or not isinstance(max_carry, int) or not 0 <= max_carry <= 4:
        raise ValueError("max_carry must be an integer from 0 through 4")
    if (isinstance(max_degree, bool) or not isinstance(max_degree, int)
            or not 1 <= max_degree <= MAX_POLY1305_ROOT_DEGREE):
        raise ValueError(f"max_degree must be in 1..{MAX_POLY1305_ROOT_DEGREE}")
    if len(triples) < 2:
        return []
    polynomials = [_poly1305_polynomial(aad, ct) for aad, ct, _ in triples]
    tags = [int.from_bytes(tag, "little") for _, _, tag in triples]
    informative_pairs = []
    for left in range(len(triples)):
        for right in range(left + 1, len(triples)):
            difference = _poly1305_difference(polynomials[left], polynomials[right])
            degree = len(difference) - 1
            if 1 <= degree <= max_degree:
                informative_pairs.append((degree, left, right, difference))
    if not informative_pairs:
        return []
    informative_pairs.sort(key=lambda item: item[:3])
    candidates = set()
    for _degree, left, right, informative in informative_pairs[:16]:
        tag_difference = tags[left] - tags[right]
        for carry in range(-max_carry, max_carry + 1):
            equation = list(informative)
            equation[0] = (
                equation[0] - tag_difference - carry * POLY1305_TAG_MODULUS
            ) % POLY1305_P
            for r in _prime_poly_roots(equation, max_degree=max_degree):
                if r >= (1 << 128) or r & ~POLY1305_R_MASK:
                    continue
                s = (tags[0] - poly1305_aead_accumulator(
                    r, triples[0][0], triples[0][1]
                )) % POLY1305_TAG_MODULUS
                if all(
                    chacha20_poly1305_forge_tag(r, s, aad, ct) == tag
                    for aad, ct, tag in triples
                ):
                    candidates.add((r, s))
    return sorted(candidates)


# Alternative word ordering kept discoverable for callers and playbook snippets.
chacha20_poly1305_recover_nonce_reuse = recover_chacha20_poly1305_nonce_reuse


def chacha20_poly1305_nonce_reuse_forge(
    observations, target_aad=b"", target_ciphertext=b"", max_carry: int = 4,
    max_degree: int = 2,
):
    """Return exactly-verified candidate tags for a target ciphertext.

    The result is a ranked list of dictionaries with integer ``r``/``s`` and a
    byte-string ``tag``.  Multiple entries are preserved when the captures do
    not uniquely determine the one-time key; callers must not silently choose.
    """
    aad_b, ct_b = _checked_aead_data(target_aad, target_ciphertext)
    keys = recover_chacha20_poly1305_nonce_reuse(
        observations, max_carry=max_carry, max_degree=max_degree
    )
    return [
        {"r": r, "s": s, "tag": chacha20_poly1305_forge_tag(r, s, aad_b, ct_b)}
        for r, s in keys
    ]


def _normalise_ghash_candidates(candidates) -> list[tuple[int, int]]:
    if candidates is None:
        return []
    out = []
    for index, candidate in enumerate(candidates):
        if index >= MAX_GHASH_CANDIDATES:
            raise ValueError(f"at most {MAX_GHASH_CANDIDATES} GHASH candidates are supported")
        if isinstance(candidate, dict):
            h = candidate.get("h", candidate.get("H"))
            mask = candidate.get("counter_mask", candidate.get("mask", candidate.get("s")))
        else:
            try:
                h, mask = candidate
            except (TypeError, ValueError) as exc:
                raise ValueError(f"candidate {index} must contain H and counter mask") from exc
        out.append((_u128(h, f"candidate {index} H"), _u128(mask, f"candidate {index} mask")))
    return out


def _ghash_record_blocks(aad: bytes, ciphertext: bytes) -> int:
    return ((len(aad) + 15) // 16) + ((len(ciphertext) + 15) // 16) + 1


def _check_ghash_partition_work(candidate_count: int, records) -> None:
    blocks = sum(_ghash_record_blocks(aad, ciphertext) for aad, ciphertext in records)
    if candidate_count * blocks > MAX_GHASH_PARTITION_BLOCKS:
        raise ValueError(
            f"GHASH partition work exceeds {MAX_GHASH_PARTITION_BLOCKS} candidate-blocks"
        )


def verify_ghash_key_commitment(h, counter_mask, observations) -> bool:
    """Whether ``(H, counter_mask)`` reproduces every full observed GCM tag."""
    h_i = _u128(h, "H")
    mask_i = _u128(counter_mask, "counter mask")
    triples = _normalise_aead_observations(observations)
    return bool(triples) and all(gcm_tag(h_i, mask_i, aad, ct) == tag for aad, ct, tag in triples)


ghash_key_commitment = verify_ghash_key_commitment


def ghash_partition_candidates(candidates, aad=b"", ciphertext=b"", observed_tag=None):
    """Partition candidate ``(H, mask)`` pairs by their predicted GCM tag.

    This is the local computation used by key-partitioning analyses: candidates
    in one group are indistinguishable for this selected transcript.  If an
    ``observed_tag`` is supplied it must be 16 bytes and each group records an
    exact ``matches_observed`` boolean.  No candidate is selected automatically.
    """
    pairs = _normalise_ghash_candidates(candidates)
    aad_b, ct_b = _checked_aead_data(aad, ciphertext)
    _check_ghash_partition_work(len(pairs), [(aad_b, ct_b)])
    known = None
    if observed_tag is not None:
        known = _checked_bytes(observed_tag, "observed tag")
        if len(known) != 16:
            raise ValueError("observed GCM tag must be 16 bytes")
    groups = {}
    for index, (h, mask) in enumerate(pairs):
        tag = gcm_tag(h, mask, aad_b, ct_b)
        group = groups.setdefault(tag, {"tag": tag, "candidate_indices": [], "candidates": []})
        group["candidate_indices"].append(index)
        group["candidates"].append((h, mask))
    out = []
    for tag in sorted(groups):
        group = groups[tag]
        group["matches_observed"] = known is not None and tag == known
        out.append(group)
    return out


def ghash_partition_observations(h_candidates, observations):
    """Partition GCM observations by the counter mask derived for each ``H``.

    Records made under the same key and nonce have the same ``H`` and counter
    mask, so a correct ``H`` groups them together.  Each returned report keeps
    observation indices rather than values, and re-verifies every group tag.
    """
    triples = _normalise_aead_observations(observations)
    if not triples:
        return []
    hs = []
    for index, value in enumerate(h_candidates or []):
        if index >= MAX_GHASH_CANDIDATES:
            raise ValueError(f"at most {MAX_GHASH_CANDIDATES} H candidates are supported")
        hs.append(_u128(value, f"H candidate {index}"))
    _check_ghash_partition_work(len(hs), [(aad, ct) for aad, ct, _ in triples])
    reports = []
    for h in hs:
        masks = {}
        for index, (aad, ct, tag) in enumerate(triples):
            mask = ghash(h, aad, ct) ^ int.from_bytes(tag, "big")
            masks.setdefault(mask, []).append(index)
        # The discriminating evidence for a candidate H is a REUSED-nonce group: >= 2 observations
        # that share one counter mask AND whose tags all reproduce under it. For a single-observation
        # group gcm_tag(h, mask, ...) == tag is TAUTOLOGICAL (mask was derived as ghash(h,...) ^ tag),
        # so a split into all-singletons (the typical wrong-H case) proves nothing and must NOT verify.
        groups = []
        multi_seen = False
        all_multi_exact = True
        for mask in sorted(masks):
            indices = masks[mask]
            if len(indices) >= 2:
                multi_seen = True
                exact = all(
                    gcm_tag(h, mask, triples[index][0], triples[index][1]) == triples[index][2]
                    for index in indices
                )
                all_multi_exact = all_multi_exact and exact
            else:
                exact = False  # singleton: no discriminating information
            groups.append({"counter_mask": mask, "observation_indices": indices, "verified": exact})
        verified = multi_seen and all_multi_exact
        reports.append({
            "h": h,
            "groups": groups,
            "group_count": len(groups),
            "all_share_counter_mask": len(groups) == 1,
            "observation_count": len(triples),
            "verified": verified,
        })
    return reports


# ---------------------------------------------------------------------------
# curves (a tiny self-contained copy) and point arithmetic
# ---------------------------------------------------------------------------
CURVES = {
    "secp256k1": {"p": 2 ** 256 - 2 ** 32 - 977, "a": 0, "b": 7,
                  "gx": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                  "gy": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
                  "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141},
    "secp256r1": {"p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF, "a": -3,
                  "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
                  "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                  "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
                  "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551},
}
CURVE_NAMES = {"secp256k1": "secp256k1", "p-256": "secp256r1", "p256": "secp256r1", "prime256v1": "secp256r1",
               "secp256r1": "secp256r1", "nistp256": "secp256r1", "nist p-256": "secp256r1"}


def ec_add(P, Q, cv):
    if P is None:
        return Q
    if Q is None:
        return P
    p = cv["p"]
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + cv["a"]) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p


def ec_mul(k: int, cv, point=None):
    k %= cv["n"]
    addend = point or (cv["gx"], cv["gy"])
    acc = None
    while k:
        if k & 1:
            acc = ec_add(acc, addend, cv)
        addend = ec_add(addend, addend, cv)
        k >>= 1
    return acc


# ---------------------------------------------------------------------------
# exact LLL (over the rationals)
# ---------------------------------------------------------------------------

def _dot(a, b):
    return sum((x * y for x, y in zip(a, b)), Fraction(0))


def lll(basis, delta=Fraction(99, 100), max_steps: int = 200000, deadline=None):
    """LLL-reduce an integer or rational lattice basis exactly, with incremental
    Gram-Schmidt updates (the textbook algorithm; no full re-orthogonalisation
    per step). Returns the reduced basis as lists of Fraction. Bounded by
    `max_steps` and an optional wall-clock `deadline`."""
    B = [[Fraction(x) for x in row] for row in basis]
    n = len(B)
    if n < 2:
        return B
    dim = len(B[0])
    Bstar = [[Fraction(0)] * dim for _ in range(n)]
    mu = [[Fraction(0)] * n for _ in range(n)]
    norm = [Fraction(0)] * n          # ||Bstar_i||^2

    def full_gs():
        for i in range(n):
            vi = list(B[i])
            for j in range(i):
                mu[i][j] = _dot(B[i], Bstar[j]) / norm[j] if norm[j] != 0 else Fraction(0)
                vi = [vi[t] - mu[i][j] * Bstar[j][t] for t in range(dim)]
            Bstar[i] = vi
            norm[i] = _dot(vi, vi)

    full_gs()
    half = Fraction(1, 2)
    k = 1
    steps = 0
    while k < n:
        steps += 1
        if steps > max_steps or (deadline is not None and time.monotonic() > deadline):
            break
        # size-reduce B[k] against B[k-1..0], updating mu incrementally
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > half:
                q = round(mu[k][j])
                B[k] = [B[k][t] - q * B[j][t] for t in range(dim)]
                for l in range(j):
                    mu[k][l] -= q * mu[j][l]
                mu[k][j] -= q
        if norm[k] >= (delta - mu[k][k - 1] * mu[k][k - 1]) * norm[k - 1]:
            k += 1
        else:
            # swap B[k] and B[k-1]; update Gram-Schmidt in place
            mu_kk1 = mu[k][k - 1]
            new_norm_km1 = norm[k] + mu_kk1 * mu_kk1 * norm[k - 1]
            if new_norm_km1 == 0:
                B[k], B[k - 1] = B[k - 1], B[k]
                full_gs()
                k = max(k - 1, 1)
                continue
            t_ratio = norm[k - 1] / new_norm_km1
            new_mu_kk1 = mu_kk1 * t_ratio
            norm[k] = norm[k] * t_ratio
            norm[k - 1] = new_norm_km1
            B[k], B[k - 1] = B[k - 1], B[k]
            for j in range(k - 1):
                mu[k][j], mu[k - 1][j] = mu[k - 1][j], mu[k][j]
            mu[k][k - 1] = new_mu_kk1
            for i in range(k + 1, n):
                t = mu[i][k]
                mu[i][k] = mu[i][k - 1] - mu_kk1 * t
                mu[i][k - 1] = t + new_mu_kk1 * mu[i][k]
            k = max(k - 1, 1)
    return B


# ---------------------------------------------------------------------------
# ECDSA biased-nonce recovery (Hidden Number Problem)
# ---------------------------------------------------------------------------

def _resolve_curve(name):
    if isinstance(name, dict):
        return name
    key = CURVE_NAMES.get(str(name or "").strip().lower())
    return CURVES.get(key) if key else None


def ecdsa_hnp_recover(curve, pubkey, sigs, nonce_bits: int, deadline=None):
    """Recover the ECDSA private scalar d from signatures with short nonces.

    curve:      'secp256k1' / 'p-256' / 'secp256r1' (or a curve dict).
    pubkey:     (x, y) of the public key Q. REQUIRED: d is accepted only when
                d*G == Q. With no public key, returns None.
    sigs:       a list of (r, s, z) over the curve order n.
    nonce_bits: L, so every nonce satisfies 0 <= k < 2^L (the stated leak).

    Returns d (int) with d*G == pubkey, or None. The lattice is a heuristic; the
    curve check is what makes the answer trustworthy, so a failed reduction or a
    wrong L can only yield None, never a wrong d."""
    cv = _resolve_curve(curve)
    if cv is None or pubkey is None:
        return None
    try:
        Q = (int(pubkey[0]), int(pubkey[1]))
    except (TypeError, ValueError, IndexError):
        return None
    n = cv["n"]
    nbits = n.bit_length()
    if not isinstance(nonce_bits, int) or not (1 <= nonce_bits < nbits):
        return None
    rows = []
    for sig in sigs or []:
        try:
            r, s, z = int(sig[0]) % n, int(sig[1]) % n, int(sig[2]) % n
        except (TypeError, ValueError, IndexError):
            continue
        if r == 0 or s == 0:
            continue
        rows.append((r, s, z))
    m = len(rows)
    if m < 2 or m > 64:
        return None
    KT = 1 << nonce_bits
    sinv = [pow(s, -1, n) for (_, s, _) in rows]
    t = [(r * sinv[i]) % n for i, (r, _, _) in enumerate(rows)]
    a = [(z * sinv[i]) % n for i, (_, _, z) in enumerate(rows)]
    # k_i = a_i + t_i*d (mod n), with 0 <= k_i < KT = 2^L.  The target short
    # vector is (k_0, .., k_{m-1}, d*KT/n, KT).  To keep the KT/n entry integer
    # the whole basis is scaled by n (uniform scaling leaves LLL's result scaled
    # by the same n, undone on extraction) -- so every entry below is an integer.
    dim = m + 2
    basis = [[0] * dim for _ in range(dim)]
    for i in range(m):
        basis[i][i] = n * n
    for i in range(m):
        basis[m][i] = n * t[i]
    basis[m][m] = KT
    for i in range(m):
        basis[m + 1][i] = n * a[i]
    basis[m + 1][m + 1] = n * KT
    try:
        reduced = lll(basis, deadline=deadline)
    except Exception:
        return None

    def _try(dval):
        if dval is None:
            return None
        dval %= n
        if dval == 0:
            return None
        if ec_mul(dval, cv) == Q:
            return dval
        return None

    inv_t0 = pow(t[0], -1, n) if t[0] % n else None
    for row in reduced:
        # column m holds (scaled) d*KT/n -> d*KT after the x n scaling; recover d
        # several ways and verify. Every candidate is checked against the key.
        col_m = row[m]
        for sign in (1, -1):
            val = sign * col_m
            cand = val / KT        # = d (Fraction); should be an integer
            for d_int in {int(cand), int(round(cand))} if cand.denominator == 1 else {int(round(cand))}:
                got = _try(d_int)
                if got is not None:
                    return got
        # column m+1 holds +-(n*KT); then columns 0..m-1 are n*k_i, and
        # d = (k0 - a0)/t0 mod n.
        last = row[m + 1]
        if last != 0 and inv_t0 is not None and abs(last) == n * KT:
            s = 1 if last > 0 else -1
            col0 = s * row[0]
            if col0.denominator == 1 and int(col0) % n == 0:
                k0 = int(col0) // n
                got = _try(((k0 - a[0]) * inv_t0) % n)
                if got is not None:
                    return got
    return None


# ---------------------------------------------------------------------------
# Guarded offline CLI
# ---------------------------------------------------------------------------

class _CLIParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def _reject_duplicate_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _load_cli_json(path_value: str):
    path = Path(path_value)
    with path.open("rb") as handle:
        raw = handle.read(MAX_CLI_JSON + 1)
    if len(raw) > MAX_CLI_JSON:
        raise ValueError(f"input JSON exceeds {MAX_CLI_JSON} bytes")

    def reject_constant(value):
        raise ValueError(f"non-finite JSON number is not supported: {value}")

    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=reject_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("input JSON must be an object")
    return value


def _json_hex_bytes(value, name: str, *, max_bytes: int = MAX_AEAD_BYTES) -> bytes:
    if value is None:
        return b""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a hex string")
    text = value[2:] if value.startswith(("0x", "0X")) else value
    if len(text) % 2:
        raise ValueError(f"{name} has an odd number of hex digits")
    if len(text) > max_bytes * 2:
        raise ValueError(f"{name} exceeds {max_bytes} bytes")
    if any(ch not in "0123456789abcdefABCDEF" for ch in text):
        raise ValueError(f"{name} is not strict hexadecimal")
    return bytes.fromhex(text)


def _json_u128(value, name: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return _u128(value, name)
    raw = _json_hex_bytes(value, name, max_bytes=16)
    if len(raw) != 16:
        raise ValueError(f"{name} must encode exactly 16 bytes")
    return int.from_bytes(raw, "big")


def _json_small_int(value, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _json_observations(value) -> list[tuple[bytes, bytes, bytes]]:
    if not isinstance(value, list):
        raise ValueError("observations must be a JSON array")
    if len(value) > MAX_AEAD_OBSERVATIONS:
        raise ValueError(f"at most {MAX_AEAD_OBSERVATIONS} observations are supported")
    out = []
    total = 0
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"observation {index} must be an object")
        aad = _json_hex_bytes(item.get("aad", ""), f"observation {index} aad")
        ciphertext = _json_hex_bytes(
            item.get("ciphertext", item.get("ct")), f"observation {index} ciphertext"
        )
        tag = _json_hex_bytes(item.get("tag"), f"observation {index} tag", max_bytes=16)
        if len(tag) != 16:
            raise ValueError(f"observation {index} tag must be 16 bytes")
        total += len(aad) + len(ciphertext) + len(tag)
        if total > MAX_AEAD_BYTES:
            raise ValueError(f"observations exceed {MAX_AEAD_BYTES} bytes in total")
        out.append((aad, ciphertext, tag))
    return out


def _json_safe(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    return value


def _build_cli_parser():
    parser = _CLIParser(
        prog="crypto_depth",
        description="Offline AES-GCM and ChaCha20-Poly1305 analysis/payload generation",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    commands = parser.add_subparsers(dest="command")
    for name, help_text in (
        ("gcm-forge", "build a GCM tag from recovered H and counter mask"),
        ("gcm-recover", "recover GCM H and counter-mask candidates from nonce reuse"),
        ("chacha-recover", "recover exactly verified Poly1305 one-time-key candidates"),
        ("chacha-forge", "recover candidates and build tags for a target ciphertext"),
        ("ghash-partition", "partition GHASH candidates or observations"),
    ):
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument("input", help="bounded local JSON fixture")
        sub.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                         help="emit machine-readable JSON")
    return parser


def _cli_run(args):
    data = _load_cli_json(args.input)
    if args.command == "gcm-forge":
        h = _json_u128(data.get("h", data.get("H")), "H")
        mask = _json_u128(data.get("counter_mask", data.get("mask")), "counter mask")
        aad = _json_hex_bytes(data.get("aad", ""), "aad")
        ciphertext = _json_hex_bytes(data.get("ciphertext", data.get("ct")), "ciphertext")
        tag_length = _json_small_int(data.get("tag_length", 16), "tag_length", 4, 16)
        tag = gcm_forge_tag(h, mask, aad, ciphertext, tag_length)
        return {"tag": tag, "tag_length": len(tag)}

    observations = []
    if not (args.command == "ghash-partition" and "candidates" in data):
        observations = _json_observations(data.get("observations"))
    if args.command == "gcm-recover":
        candidates = gcm_recover_subkey(observations)
        return {
            "candidate_count": len(candidates),
            "candidates": [
                {
                    "rank": index + 1,
                    "h": h.to_bytes(16, "big"),
                    "counter_mask": mask.to_bytes(16, "big"),
                    "verified_observations": len(observations),
                }
                for index, (h, mask) in enumerate(candidates)
            ],
            "ambiguous": len(candidates) != 1,
        }
    if args.command == "chacha-recover":
        max_carry = _json_small_int(data.get("max_carry", 4), "max_carry", 0, 4)
        max_degree = _json_small_int(
            data.get("max_degree", 64), "max_degree", 1, MAX_POLY1305_ROOT_DEGREE
        )
        keys = recover_chacha20_poly1305_nonce_reuse(
            observations, max_carry=max_carry, max_degree=max_degree
        )
        return {
            "candidate_count": len(keys),
            "candidates": [
                {"rank": index + 1, "r": r.to_bytes(16, "little"), "s": s.to_bytes(16, "little")}
                for index, (r, s) in enumerate(keys)
            ],
            "max_degree": max_degree,
        }
    if args.command == "chacha-forge":
        target = data.get("target", {})
        if not isinstance(target, dict):
            raise ValueError("target must be an object")
        target_aad = _json_hex_bytes(
            target.get("aad", data.get("target_aad", "")), "target aad"
        )
        target_ct = _json_hex_bytes(
            target.get("ciphertext", target.get("ct", data.get("target_ciphertext"))),
            "target ciphertext",
        )
        max_carry = _json_small_int(data.get("max_carry", 4), "max_carry", 0, 4)
        max_degree = _json_small_int(
            data.get("max_degree", 64), "max_degree", 1, MAX_POLY1305_ROOT_DEGREE
        )
        forged = chacha20_poly1305_nonce_reuse_forge(
            observations, target_aad, target_ct, max_carry=max_carry,
            max_degree=max_degree,
        )
        return {
            "candidate_count": len(forged),
            "candidates": [dict({"rank": index + 1}, **candidate)
                           for index, candidate in enumerate(forged)],
            "limitation": "tags authenticate supplied ciphertext only; no keystream is generated",
        }
    if args.command == "ghash-partition":
        if "candidates" in data:
            raw_candidates = data["candidates"]
            if not isinstance(raw_candidates, list):
                raise ValueError("candidates must be an array")
            if len(raw_candidates) > MAX_GHASH_CANDIDATES:
                raise ValueError(f"at most {MAX_GHASH_CANDIDATES} candidates are supported")
            candidates = []
            for index, item in enumerate(raw_candidates):
                if not isinstance(item, dict):
                    raise ValueError(f"candidate {index} must be an object")
                candidates.append((
                    _json_u128(item.get("h", item.get("H")), f"candidate {index} H"),
                    _json_u128(
                        item.get("counter_mask", item.get("mask")), f"candidate {index} mask"
                    ),
                ))
            aad = _json_hex_bytes(data.get("aad", ""), "aad")
            ciphertext = _json_hex_bytes(data.get("ciphertext", data.get("ct")), "ciphertext")
            known = None
            if data.get("observed_tag") is not None:
                known = _json_hex_bytes(data["observed_tag"], "observed tag", max_bytes=16)
            return {"partitions": ghash_partition_candidates(candidates, aad, ciphertext, known)}
        raw_hs = data.get("h_candidates")
        if not isinstance(raw_hs, list):
            raise ValueError("h_candidates must be an array when candidates are absent")
        if len(raw_hs) > MAX_GHASH_CANDIDATES:
            raise ValueError(f"at most {MAX_GHASH_CANDIDATES} H candidates are supported")
        hs = [_json_u128(value, f"H candidate {index}") for index, value in enumerate(raw_hs)]
        return {"partitions": ghash_partition_observations(hs, observations)}
    raise ValueError("a command is required")


def main(argv=None) -> int:
    """Guarded CLI: malformed local input yields ``crypto_depth: ...`` and 2."""
    parser = _build_cli_parser()
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:  # argparse --help; preserve a clean status.
            return int(exc.code or 0)
        if args.command is None:
            raise ValueError("a command is required")
        result = _json_safe(_cli_run(args))
        if getattr(args, "json", False):
            print(json.dumps(result, sort_keys=True))
        elif args.command == "gcm-forge":
            print(f"tag: {result['tag']}")
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError, MemoryError, json.JSONDecodeError) as exc:
        print(f"crypto_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
