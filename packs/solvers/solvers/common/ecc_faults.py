"""Verified, offline ECC signature-fault and invalid-curve recovery helpers.

The functions in this module deliberately have a fail-closed API: attack entry
points return a scalar only after it reproduces the supplied public key *and*
the original signature or subgroup transcript.  Malformed, underdetermined, or
contradictory evidence returns ``None``.  There is no networking and no search
for flags.

Covered attack families:

* ECDSA known/reused nonce and known nonce-delta (fault) equations;
* Ed25519/EdDSA repeated nonce and known nonce-delta faults;
* invalid-curve/small-subgroup residue recovery and generalized-CRT key
  reconstruction with a final ``[d]G == Q`` check.

Only standard-library integer arithmetic is used.  The two named Weierstrass
curves are included so callers do not have to trust a callback for ECDSA.  The
small-subgroup layer is callback based because invalid-curve transcripts often
come from several attacker-selected curves, but it validates the exact order,
replays every response, and requires a separate real-group public-key callback
before emitting a private scalar.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import itertools
import math
from typing import Any, Callable, Iterable, Optional


# ---------------------------------------------------------------------------
# Short-Weierstrass curves and ECDSA

Point = Optional[tuple[int, int]]


@dataclass(frozen=True)
class WeierstrassCurve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int

    @property
    def generator(self) -> tuple[int, int]:
        return self.gx, self.gy


SECP256K1 = WeierstrassCurve(
    "secp256k1",
    2**256 - 2**32 - 977,
    0,
    7,
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)

SECP256R1 = WeierstrassCurve(
    "secp256r1",
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    -3,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)

CURVES = {
    "secp256k1": SECP256K1,
    "secp256r1": SECP256R1,
    "prime256v1": SECP256R1,
    "p-256": SECP256R1,
    "p256": SECP256R1,
}


def _curve(curve: str | WeierstrassCurve) -> Optional[WeierstrassCurve]:
    if isinstance(curve, WeierstrassCurve):
        return curve
    if isinstance(curve, str):
        return CURVES.get(curve.lower())
    return None


def _on_curve(point: Point, curve: WeierstrassCurve) -> bool:
    if point is None:
        return True
    if not (isinstance(point, tuple) and len(point) == 2):
        return False
    x, y = point
    return (
        isinstance(x, int)
        and isinstance(y, int)
        and 0 <= x < curve.p
        and 0 <= y < curve.p
        and (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0
    )


def _raw_add(left: Point, right: Point, p: int, a: int) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    try:
        if left == right:
            slope = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
        else:
            slope = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p
    except ValueError:
        return None
    x3 = (slope * slope - x1 - x2) % p
    return x3, (slope * (x1 - x3) - y1) % p


def _raw_mul(scalar: int, point: Point, p: int, a: int) -> Point:
    if not isinstance(scalar, int) or point is None or scalar == 0:
        return None
    if scalar < 0:
        point = (point[0], (-point[1]) % p)
        scalar = -scalar
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _raw_add(result, addend, p, a)
        addend = _raw_add(addend, addend, p, a)
        scalar >>= 1
    return result


def ec_mul(
    scalar: int,
    point: Point = None,
    curve: str | WeierstrassCurve = "secp256k1",
) -> Point:
    """Multiply a point without silently accepting an unknown curve."""

    cv = _curve(curve)
    if cv is None or not isinstance(scalar, int):
        return None
    chosen = cv.generator if point is None else point
    if not _on_curve(chosen, cv):
        return None
    return _raw_mul(scalar, chosen, cv.p, cv.a)


def _valid_public(public_key: Any, curve: WeierstrassCurve) -> bool:
    if not (isinstance(public_key, (tuple, list)) and len(public_key) == 2):
        return False
    public = (public_key[0], public_key[1])
    return (
        public is not None
        and _on_curve(public, curve)
        and _raw_mul(curve.n, public, curve.p, curve.a) is None
    )


def _ecdsa_tuple(signature: Any, n: int) -> Optional[tuple[int, int, int]]:
    if not (isinstance(signature, (tuple, list)) and len(signature) == 3):
        return None
    r, s, z = signature
    if not all(isinstance(value, int) for value in (r, s, z)):
        return None
    if not (0 < r < n and 0 < s < n):
        return None
    return r, s, z % n


def ecdsa_verify(
    signature: Any,
    public_key: Any,
    curve: str | WeierstrassCurve = "secp256k1",
) -> bool:
    """Verify an ECDSA ``(r, s, z)`` tuple using exact curve arithmetic."""

    cv = _curve(curve)
    if cv is None or not _valid_public(public_key, cv):
        return False
    sig = _ecdsa_tuple(signature, cv.n)
    if sig is None:
        return False
    r, s, z = sig
    try:
        inv_s = pow(s, -1, cv.n)
    except ValueError:
        return False
    left = _raw_mul(z * inv_s % cv.n, cv.generator, cv.p, cv.a)
    right = _raw_mul(r * inv_s % cv.n, tuple(public_key), cv.p, cv.a)
    check = _raw_add(left, right, cv.p, cv.a)
    return check is not None and check[0] % cv.n == r


def _ecdsa_proves_private(
    private: int,
    public_key: Any,
    signatures: Iterable[Any],
    curve: WeierstrassCurve,
) -> bool:
    return (
        isinstance(private, int)
        and 0 < private < curve.n
        and _raw_mul(private, curve.generator, curve.p, curve.a) == tuple(public_key)
        and all(ecdsa_verify(signature, public_key, curve) for signature in signatures)
    )


def recover_ecdsa_known_nonce(
    signature: Any,
    nonce: int,
    public_key: Any,
    curve: str | WeierstrassCurve = "secp256k1",
) -> Optional[int]:
    """Recover ``d`` from a known ECDSA nonce, with public/signature proof.

    Both ``k`` and ``-k`` are considered because low-S canonicalization changes
    the effective nonce sign.  More than one proven scalar is treated as
    ambiguous and declined.
    """

    cv = _curve(curve)
    if cv is None or not _valid_public(public_key, cv) or not isinstance(nonce, int):
        return None
    sig = _ecdsa_tuple(signature, cv.n)
    if sig is None or not ecdsa_verify(sig, public_key, cv):
        return None
    r, s, z = sig
    found: set[int] = set()
    for candidate_nonce in {nonce % cv.n, (-nonce) % cv.n}:
        point = _raw_mul(candidate_nonce, cv.generator, cv.p, cv.a)
        if candidate_nonce == 0 or point is None or point[0] % cv.n != r:
            continue
        try:
            private = (s * candidate_nonce - z) * pow(r, -1, cv.n) % cv.n
        except ValueError:
            continue
        if (
            s * candidate_nonce % cv.n == (z + r * private) % cv.n
            and _ecdsa_proves_private(private, public_key, (sig,), cv)
        ):
            found.add(private)
    return next(iter(found)) if len(found) == 1 else None


def recover_ecdsa_reused_nonce(
    signature1: Any,
    signature2: Any,
    public_key: Any,
    curve: str | WeierstrassCurve = "secp256k1",
) -> Optional[int]:
    """Recover the unique private scalar from two repeated-nonce signatures."""

    cv = _curve(curve)
    if cv is None or not _valid_public(public_key, cv):
        return None
    first = _ecdsa_tuple(signature1, cv.n)
    second = _ecdsa_tuple(signature2, cv.n)
    if first is None or second is None or first[0] != second[0] or first == second:
        return None
    if not ecdsa_verify(first, public_key, cv) or not ecdsa_verify(second, public_key, cv):
        return None
    r, s1, z1 = first
    _, s2, z2 = second
    found: set[int] = set()
    for effective_s1 in {s1, (-s1) % cv.n}:
        for effective_s2 in {s2, (-s2) % cv.n}:
            denominator = (effective_s1 - effective_s2) % cv.n
            try:
                nonce = (z1 - z2) * pow(denominator, -1, cv.n) % cv.n
                private = (effective_s1 * nonce - z1) * pow(r, -1, cv.n) % cv.n
            except ValueError:
                continue
            nonce_point = _raw_mul(nonce, cv.generator, cv.p, cv.a)
            if (
                nonce
                and nonce_point is not None
                and nonce_point[0] % cv.n == r
                and effective_s1 * nonce % cv.n == (z1 + r * private) % cv.n
                and effective_s2 * nonce % cv.n == (z2 + r * private) % cv.n
                and _ecdsa_proves_private(private, public_key, (first, second), cv)
            ):
                found.add(private)
    return next(iter(found)) if len(found) == 1 else None


def recover_ecdsa_nonce_delta(
    signature1: Any,
    signature2: Any,
    nonce_delta: int,
    public_key: Any,
    curve: str | WeierstrassCurve = "secp256k1",
) -> Optional[int]:
    """Recover ``d`` when a fault makes ``k2 = k1 + nonce_delta``.

    The two signatures may cover different messages and have different ``r``.
    Low-S sign alternatives are tried, but a scalar is emitted only if the
    recovered nonces reproduce both R coordinates and every original signature.
    """

    cv = _curve(curve)
    if (
        cv is None
        or not isinstance(nonce_delta, int)
        or not _valid_public(public_key, cv)
    ):
        return None
    first = _ecdsa_tuple(signature1, cv.n)
    second = _ecdsa_tuple(signature2, cv.n)
    if first is None or second is None or first == second:
        return None
    if not ecdsa_verify(first, public_key, cv) or not ecdsa_verify(second, public_key, cv):
        return None
    r1, s1, z1 = first
    r2, s2, z2 = second
    delta = nonce_delta % cv.n
    found: set[int] = set()
    for effective_s1 in {s1, (-s1) % cv.n}:
        for effective_s2 in {s2, (-s2) % cv.n}:
            denominator = (effective_s1 * r2 - effective_s2 * r1) % cv.n
            numerator = (
                effective_s2 * z1
                - effective_s1 * z2
                + effective_s1 * effective_s2 * delta
            ) % cv.n
            try:
                private = numerator * pow(denominator, -1, cv.n) % cv.n
                nonce1 = (z1 + r1 * private) * pow(effective_s1, -1, cv.n) % cv.n
            except ValueError:
                continue
            nonce2 = (nonce1 + delta) % cv.n
            point1 = _raw_mul(nonce1, cv.generator, cv.p, cv.a)
            point2 = _raw_mul(nonce2, cv.generator, cv.p, cv.a)
            if (
                nonce1
                and nonce2
                and point1 is not None
                and point2 is not None
                and point1[0] % cv.n == r1
                and point2[0] % cv.n == r2
                and effective_s1 * nonce1 % cv.n == (z1 + r1 * private) % cv.n
                and effective_s2 * nonce2 % cv.n == (z2 + r2 * private) % cv.n
                and _ecdsa_proves_private(private, public_key, (first, second), cv)
            ):
                found.add(private)
    return next(iter(found)) if len(found) == 1 else None


# ---------------------------------------------------------------------------
# Ed25519 arithmetic and EdDSA nonce faults

ED25519_P = 2**255 - 19
ED25519_L = 2**252 + 27742317777372353535851937790883648493
ED25519_D = -121665 * pow(121666, -1, ED25519_P) % ED25519_P
ED25519_SQRT_M1 = pow(2, (ED25519_P - 1) // 4, ED25519_P)

# Extended Edwards coordinates (X, Y, Z, T), with x=X/Z and y=Y/Z.
EdPoint = tuple[int, int, int, int]
_ED_IDENTITY: EdPoint = (0, 1, 1, 0)


def _ed_add(left: EdPoint, right: EdPoint) -> EdPoint:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % ED25519_P
    b = (y1 + x1) * (y2 + x2) % ED25519_P
    c = 2 * ED25519_D * t1 * t2 % ED25519_P
    d = 2 * z1 * z2 % ED25519_P
    e = (b - a) % ED25519_P
    f = (d - c) % ED25519_P
    g = (d + c) % ED25519_P
    h = (b + a) % ED25519_P
    return e * f % ED25519_P, g * h % ED25519_P, f * g % ED25519_P, e * h % ED25519_P


def _ed_double(point: EdPoint) -> EdPoint:
    x, y, z, _ = point
    a = x * x % ED25519_P
    b = y * y % ED25519_P
    c = 2 * z * z % ED25519_P
    d = -a % ED25519_P
    e = ((x + y) * (x + y) - a - b) % ED25519_P
    g = (d + b) % ED25519_P
    f = (g - c) % ED25519_P
    h = (d - b) % ED25519_P
    return e * f % ED25519_P, g * h % ED25519_P, f * g % ED25519_P, e * h % ED25519_P


def _ed_mul(scalar: int, point: EdPoint) -> EdPoint:
    if scalar < 0:
        # Negation on a twisted Edwards curve is (-x, y).
        point = ((-point[0]) % ED25519_P, point[1], point[2], (-point[3]) % ED25519_P)
        scalar = -scalar
    result = _ED_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_double(addend)
        scalar >>= 1
    return result


def _ed_equal(left: EdPoint, right: EdPoint) -> bool:
    return (
        left[0] * right[2] - right[0] * left[2]
    ) % ED25519_P == 0 and (
        left[1] * right[2] - right[1] * left[2]
    ) % ED25519_P == 0


def _ed_encode(point: EdPoint) -> bytes:
    x, y, z, _ = point
    try:
        inverse_z = pow(z, -1, ED25519_P)
    except ValueError:
        return b""
    affine_x = x * inverse_z % ED25519_P
    affine_y = y * inverse_z % ED25519_P
    encoded = affine_y | ((affine_x & 1) << 255)
    return encoded.to_bytes(32, "little")


def _ed_decode(encoded: Any) -> Optional[EdPoint]:
    if not isinstance(encoded, (bytes, bytearray)) or len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= ED25519_P:
        return None
    y2 = y * y % ED25519_P
    try:
        x2 = (y2 - 1) * pow((ED25519_D * y2 + 1) % ED25519_P, -1, ED25519_P) % ED25519_P
    except ValueError:
        return None
    x = pow(x2, (ED25519_P + 3) // 8, ED25519_P)
    if x * x % ED25519_P != x2:
        x = x * ED25519_SQRT_M1 % ED25519_P
    if x * x % ED25519_P != x2:
        return None
    if (x & 1) != sign:
        x = (-x) % ED25519_P
    if x == 0 and sign:
        return None
    return x, y, 1, x * y % ED25519_P


_ED_BASE_ENCODING = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")
_ED_BASE = _ed_decode(_ED_BASE_ENCODING)
if _ED_BASE is None:  # pragma: no cover - constant-integrity assertion
    raise RuntimeError("invalid built-in Ed25519 base point")


def ed25519_public_from_scalar(private_scalar: int) -> Optional[bytes]:
    """Return the canonical public encoding for a nonzero scalar modulo L."""

    if not isinstance(private_scalar, int):
        return None
    scalar = private_scalar % ED25519_L
    if scalar == 0:
        return None
    return _ed_encode(_ed_mul(scalar, _ED_BASE))


def _strict_ed_public(encoded: Any) -> Optional[EdPoint]:
    point = _ed_decode(encoded)
    if point is None or _ed_equal(point, _ED_IDENTITY):
        return None
    if not _ed_equal(_ed_mul(ED25519_L, point), _ED_IDENTITY):
        return None
    # Reject torsion encodings even if a future multiplication implementation
    # changes how L is reduced.
    if _ed_equal(_ed_mul(8, point), _ED_IDENTITY):
        return None
    return point


def _ed_signature_parts(signature: Any) -> Optional[tuple[bytes, int, EdPoint]]:
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return None
    raw = bytes(signature)
    encoded_r = raw[:32]
    scalar_s = int.from_bytes(raw[32:], "little")
    point_r = _strict_ed_public(encoded_r)
    if point_r is None or scalar_s >= ED25519_L:
        return None
    return encoded_r, scalar_s, point_r


def _ed_challenge(encoded_r: bytes, public_key: bytes, message: bytes) -> int:
    return int.from_bytes(hashlib.sha512(encoded_r + public_key + message).digest(), "little") % ED25519_L


def ed25519_verify(signature: Any, message: Any, public_key: Any) -> bool:
    """Strict Ed25519 verification used as the recovery proof oracle."""

    if not isinstance(message, (bytes, bytearray)) or not isinstance(public_key, (bytes, bytearray)):
        return False
    public = bytes(public_key)
    point_a = _strict_ed_public(public)
    parts = _ed_signature_parts(signature)
    if point_a is None or parts is None:
        return False
    encoded_r, scalar_s, point_r = parts
    challenge = _ed_challenge(encoded_r, public, bytes(message))
    return _ed_equal(
        _ed_mul(scalar_s, _ED_BASE),
        _ed_add(point_r, _ed_mul(challenge, point_a)),
    )


def recover_ed25519_reused_nonce(
    signature1: Any,
    message1: Any,
    signature2: Any,
    message2: Any,
    public_key: Any,
) -> Optional[int]:
    """Recover Ed25519 ``a`` from two signatures carrying the same R."""

    if not all(isinstance(value, (bytes, bytearray)) for value in (message1, message2, public_key)):
        return None
    public = bytes(public_key)
    first = _ed_signature_parts(signature1)
    second = _ed_signature_parts(signature2)
    if first is None or second is None or first[0] != second[0] or bytes(message1) == bytes(message2):
        return None
    if not ed25519_verify(signature1, message1, public) or not ed25519_verify(signature2, message2, public):
        return None
    encoded_r, scalar_s1, _ = first
    _, scalar_s2, _ = second
    h1 = _ed_challenge(encoded_r, public, bytes(message1))
    h2 = _ed_challenge(encoded_r, public, bytes(message2))
    try:
        private = (scalar_s1 - scalar_s2) * pow((h1 - h2) % ED25519_L, -1, ED25519_L) % ED25519_L
    except ValueError:
        return None
    nonce = (scalar_s1 - h1 * private) % ED25519_L
    if (
        private == 0
        or nonce == 0
        or ed25519_public_from_scalar(private) != public
        or _ed_encode(_ed_mul(nonce, _ED_BASE)) != encoded_r
        or not ed25519_verify(signature1, message1, public)
        or not ed25519_verify(signature2, message2, public)
    ):
        return None
    return private


def recover_ed25519_nonce_delta(
    signature1: Any,
    message1: Any,
    signature2: Any,
    message2: Any,
    nonce_delta: int,
    public_key: Any,
) -> Optional[int]:
    """Recover Ed25519 ``a`` when ``r2 = r1 + nonce_delta (mod L)``."""

    if (
        not isinstance(nonce_delta, int)
        or not all(isinstance(value, (bytes, bytearray)) for value in (message1, message2, public_key))
    ):
        return None
    public = bytes(public_key)
    first = _ed_signature_parts(signature1)
    second = _ed_signature_parts(signature2)
    if first is None or second is None or first == second:
        return None
    if not ed25519_verify(signature1, message1, public) or not ed25519_verify(signature2, message2, public):
        return None
    encoded_r1, scalar_s1, point_r1 = first
    encoded_r2, scalar_s2, point_r2 = second
    delta = nonce_delta % ED25519_L
    if not _ed_equal(point_r2, _ed_add(point_r1, _ed_mul(delta, _ED_BASE))):
        return None
    h1 = _ed_challenge(encoded_r1, public, bytes(message1))
    h2 = _ed_challenge(encoded_r2, public, bytes(message2))
    try:
        private = (scalar_s2 - scalar_s1 - delta) * pow((h2 - h1) % ED25519_L, -1, ED25519_L) % ED25519_L
    except ValueError:
        return None
    nonce1 = (scalar_s1 - h1 * private) % ED25519_L
    nonce2 = (scalar_s2 - h2 * private) % ED25519_L
    if (
        private == 0
        or nonce1 == 0
        or nonce2 != (nonce1 + delta) % ED25519_L
        or ed25519_public_from_scalar(private) != public
        or _ed_encode(_ed_mul(nonce1, _ED_BASE)) != encoded_r1
        or _ed_encode(_ed_mul(nonce2, _ED_BASE)) != encoded_r2
        or not ed25519_verify(signature1, message1, public)
        or not ed25519_verify(signature2, message2, public)
    ):
        return None
    return private


# Explicit routing names: challenge triage commonly says "fault" rather than
# "nonce delta".  These aliases retain the same fail-closed proof contract.
recover_ecdsa_faulted_nonce_delta = recover_ecdsa_nonce_delta
recover_ecdsa_fault_reused_nonce = recover_ecdsa_reused_nonce
recover_ed25519_faulted_nonce_delta = recover_ed25519_nonce_delta
recover_eddsa_faulted_nonce_delta = recover_ed25519_nonce_delta
recover_eddsa_reused_nonce = recover_ed25519_reused_nonce


# ---------------------------------------------------------------------------
# Ed25519 S+kL signature malleability (B-059)


def _ed_signature_parts_permissive(signature: Any) -> Optional[tuple[bytes, int, EdPoint]]:
    """Parse ``R || S`` allowing a non-canonical ``S`` (``S >= L``).

    ``R`` is still decoded strictly: a non-canonical or torsion ``R`` is a
    distinct, far rarer bug and is not what S+kL malleability exercises.  The
    scalar read from 32 little-endian bytes is always ``< 2**256``, so no upper
    bound is imposed here beyond the fixed width.
    """

    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return None
    raw = bytes(signature)
    encoded_r = raw[:32]
    scalar_s = int.from_bytes(raw[32:], "little")
    point_r = _strict_ed_public(encoded_r)
    if point_r is None:
        return None
    return encoded_r, scalar_s, point_r


# ``R || S`` with the top three bits of ``S`` set (``S >= 2**253``): the
# SUPERCOP ref10 verifier and libsodium built with ``ED25519_COMPAT`` reject a
# signature on ``sig[63] & 224`` before the group equation, and do no other
# range check on ``S``.
ED25519_REF10_S_BOUND = 1 << 253
# ``S`` is 32 little-endian bytes, so ``S + kL`` must stay below this.
ED25519_S_ENCODING_BOUND = 1 << 256


def _ed25519_ref10_scalar_ok(scalar_s: int) -> bool:
    """True when ``S`` passes the ref10 / libsodium-compat ``sig[63] & 224`` test."""

    return scalar_s < ED25519_REF10_S_BOUND


def ed25519_verify_lax(
    signature: Any,
    message: Any,
    public_key: Any,
    *,
    ref10_top_bits: bool = False,
) -> bool:
    """Permissive Ed25519 verification that accepts a non-canonical ``S``.

    Models a verifier that omits the RFC 8032 ``0 <= S < L`` bound.  Because
    ``L*B`` is the identity, ``S`` and ``S + kL`` give the same ``S*B`` and both
    satisfy the group equation.  Two lax families exist and differ on which
    ``S + kL`` they accept:

    - ``ref10_top_bits=False`` (default): no range check on ``S`` at all beyond
      its 32-byte width, so every ``S + kL < 2**256`` is accepted.  Examples:
      the original Python reference ``ed25519.py`` and TweetNaCl's
      ``crypto_sign_open``, and hand-rolled verifiers that just decode ``S``.
    - ``ref10_top_bits=True``: the SUPERCOP ref10 code and libsodium built with
      ``ED25519_COMPAT`` reject ``S`` whose top three bits are set
      (``sig[63] & 224``, i.e. ``S >= 2**253``).  Since ``2L > 2**253`` such a
      verifier accepts at most the ``S + L`` variant (and only when
      ``S + L < 2**253``), never ``S + 2L``.

    Current libsodium (default build), ``cryptography``/OpenSSL and other
    RFC 8032 verifiers are strict; :func:`ed25519_verify` is that oracle.
    ``R`` is decoded strictly in both lax modes.
    """

    if not isinstance(message, (bytes, bytearray)) or not isinstance(public_key, (bytes, bytearray)):
        return False
    public = bytes(public_key)
    point_a = _strict_ed_public(public)
    parts = _ed_signature_parts_permissive(signature)
    if point_a is None or parts is None:
        return False
    encoded_r, scalar_s, point_r = parts
    if ref10_top_bits and not _ed25519_ref10_scalar_ok(scalar_s):
        return False
    challenge = _ed_challenge(encoded_r, public, bytes(message))
    return _ed_equal(
        _ed_mul(scalar_s, _ED_BASE),
        _ed_add(point_r, _ed_mul(challenge, point_a)),
    )


def ed25519_canonicalize_signature(signature: Any) -> Optional[tuple[bytes, int]]:
    """Reduce an observed signature's ``S`` modulo ``L``.

    Returns ``(R || (S mod L), k)`` where the observed scalar is
    ``(S mod L) + k*L``: ``k == 0`` means the input was already canonical,
    ``k >= 1`` means it was an S+kL malleable form (as on the CSCTF 9099
    landfall audit ledger).  The reduced signature is what a strict verifier
    accepts.  Returns ``None`` for input that is not 64 bytes or whose ``R`` is
    not a canonical, non-torsion point encoding.
    """

    parts = _ed_signature_parts_permissive(signature)
    if parts is None:
        return None
    encoded_r, scalar_s, _point_r = parts
    k, reduced = divmod(scalar_s, ED25519_L)
    return encoded_r + reduced.to_bytes(32, "little"), k


@dataclass(frozen=True)
class Ed25519MalleableSignature:
    """A non-canonical ``R || (S + kL)`` variant of a valid Ed25519 signature.

    ``k`` counts from the canonical ``S`` (``S mod L``), so ``scalar_s ==
    (scalar_s mod L) + k*L`` always.
    """

    k: int
    scalar_s: int
    signature: bytes

    @property
    def ref10_compatible(self) -> bool:
        """True when a ref10 / libsodium-compat verifier would accept it.

        Those verifiers reject ``S >= 2**253`` (see :func:`ed25519_verify_lax`),
        so in practice only ``k == 1`` can be compatible.
        """

        return _ed25519_ref10_scalar_ok(self.scalar_s)


def ed25519_malleable_signatures(
    signature: Any,
    *,
    count: int = 2,
    public_key: Any = None,
    message: Any = None,
    canonicalize: bool = False,
) -> list[Ed25519MalleableSignature]:
    """Emit non-canonical ``R || (S + kL)`` malleable variants of a signature.

    A canonical Ed25519 signature carries ``0 <= S < L``.  Adding any multiple
    of the group order ``L`` to ``S`` leaves ``S*B`` unchanged (``L*B`` is the
    identity), so ``R || (S + kL)`` still satisfies the verification equation
    for the same message and key, yet is a *different* 64-byte string.  A
    verifier that omits the RFC 8032 ``S < L`` canonicity check accepts it,
    which breaks any signature-uniqueness / replay / exact-match assumption
    (CSCTF 9099 landfall).  That the variants verify is the identity above, not
    a runtime check; the tests prove it against the ``cryptography`` library.

    Up to ``count`` variants are returned for ``k = 1, 2, ...`` (the default
    emits the classic ``S+L`` and ``S+2L``).  Ceiling: ``S + kL`` must fit in
    32 little-endian bytes (``< 2**256``), so the largest ``k`` is
    ``(2**256 - 1 - S) // L``: 15 for small ``S``, 14 once ``S >
    2**256 - 1 - 15L`` (about ``2**252 - 15*(L - 2**252)``, i.e. ``S`` near
    ``L``); never 16.  The series stops there, so a larger ``count`` returns
    fewer variants (check ``len``); with ``canonicalize=True`` the skipped
    observed ``k`` costs one more.  See ``Ed25519MalleableSignature.
    ref10_compatible`` for which variants a ref10-style verifier accepts.

    ``canonicalize``: by default the input must be canonical (``S < L``), and an
    input that is already an S+kL form yields ``[]`` -- call
    :func:`ed25519_canonicalize_signature` to see its ``k``.  With
    ``canonicalize=True`` the input's ``S`` is first reduced mod ``L`` and the
    observed ``k`` is *skipped*, so every emitted variant is byte-distinct from
    the observed signature (the "unseen but valid" signature a replay check
    misses).  The canonical form itself is ``ed25519_canonicalize_signature``'s
    first value.

    Proof check: when ``public_key`` and ``message`` are both given, the
    (reduced) input must verify strictly, or ``[]`` is returned.

    Errors: caller mistakes raise ``ValueError`` -- ``count`` not a positive
    ``int`` (``bool`` refused), or only one of ``public_key`` / ``message``
    given (which would otherwise skip the proof check without a word).  Bad
    signature *data* (wrong length, non-canonical ``R``, non-canonical ``S``
    without ``canonicalize``) fails closed with ``[]`` like the rest of this
    module.
    """

    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise ValueError(f"count must be a positive int, got {count!r}")
    if (public_key is None) != (message is None):
        raise ValueError(
            "public_key and message must be given together (for the proof check) "
            "or both omitted"
        )
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return []
    raw = bytes(signature)
    observed_k = 0
    if canonicalize:
        reduced = ed25519_canonicalize_signature(raw)
        if reduced is None:
            return []
        raw, observed_k = reduced
    # A strict parse enforces both a canonical R and the canonical S < L bound;
    # a non-canonical input is refused rather than compounded.
    elif _ed_signature_parts(raw) is None:
        return []
    encoded_r = raw[:32]
    scalar_s = int.from_bytes(raw[32:], "little")
    if public_key is not None and not ed25519_verify(raw, message, public_key):
        return []
    variants: list[Ed25519MalleableSignature] = []
    k = 0
    while len(variants) < count:
        k += 1
        candidate = scalar_s + k * ED25519_L
        if candidate >= ED25519_S_ENCODING_BOUND:
            break
        if k == observed_k:
            continue
        variants.append(
            Ed25519MalleableSignature(
                k=k,
                scalar_s=candidate,
                signature=encoded_r + candidate.to_bytes(32, "little"),
            )
        )
    return variants


# ---------------------------------------------------------------------------
# Invalid-curve / small-subgroup transcripts and CRT reconstruction

MAX_SUBGROUP_ORDER = 1 << 18
MAX_OBSERVATIONS = 64
MAX_CRT_CANDIDATES = 1 << 18


@dataclass(frozen=True)
class SmallSubgroupObservation:
    """One offline response ``response == [d]probe`` in a claimed subgroup."""

    order: int
    probe: Any
    response: Any
    scalar_mul: Callable[[int, Any], Any]
    identity: Any
    equal: Callable[[Any, Any], bool] = lambda left, right: left == right


def _checked_equal(equal: Callable[[Any, Any], bool], left: Any, right: Any) -> bool:
    """Call a transcript equality predicate and reject non-boolean protocols."""

    result = equal(left, right)
    if not isinstance(result, bool):
        raise TypeError("group equality callback must return bool")
    return result


def _prime_divisors(value: int) -> list[int]:
    divisors: list[int] = []
    candidate = 2
    remaining = value
    while candidate * candidate <= remaining:
        if remaining % candidate == 0:
            divisors.append(candidate)
            while remaining % candidate == 0:
                remaining //= candidate
        candidate = 3 if candidate == 2 else candidate + 2
    if remaining > 1:
        divisors.append(remaining)
    return divisors


def recover_small_subgroup_residue(
    observation: SmallSubgroupObservation,
) -> Optional[tuple[int, int]]:
    """Return the unique, replay-verified ``(d mod order, order)``."""

    if not isinstance(observation, SmallSubgroupObservation):
        return None
    order = observation.order
    if not isinstance(order, int) or not (1 < order <= MAX_SUBGROUP_ORDER):
        return None
    if not callable(observation.scalar_mul) or not callable(observation.equal):
        return None
    try:
        if not _checked_equal(observation.equal,
            observation.scalar_mul(order, observation.probe), observation.identity
        ):
            return None
        # The claimed order must be exact; otherwise several residues could
        # encode the same response under the oversized modulus.
        for divisor in _prime_divisors(order):
            if _checked_equal(observation.equal,
                observation.scalar_mul(order // divisor, observation.probe),
                observation.identity,
            ):
                return None
        matches = [
            residue
            for residue in range(order)
            if _checked_equal(observation.equal,
                observation.scalar_mul(residue, observation.probe),
                observation.response,
            )
        ]
    except Exception:
        return None
    if len(matches) != 1:
        return None
    residue = matches[0]
    try:
        if not _checked_equal(observation.equal,
            observation.scalar_mul(residue, observation.probe), observation.response
        ):
            return None
    except Exception:
        return None
    return residue, order


def _is_probable_prime(value: int) -> bool:
    if value < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small:
        if value % prime == 0:
            return value == prime
    d = value - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    # Deterministic for 64-bit inputs; larger challenge fields receive strong,
    # deterministic fixed-base screening without claiming a primality proof.
    bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    for base in bases:
        if base % value == 0:
            continue
        x = pow(base, d, value)
        if x in (1, value - 1):
            continue
        for _ in range(s - 1):
            x = x * x % value
            if x == value - 1:
                break
        else:
            return False
    return True


def make_invalid_curve_observation(
    p: int,
    a: int,
    b: int,
    point: Any,
    response: Any,
    subgroup_order: int,
) -> Optional[SmallSubgroupObservation]:
    """Validate and package one short-Weierstrass invalid-curve transcript."""

    if (
        not all(isinstance(value, int) for value in (p, a, b, subgroup_order))
        or p <= 3
        or not _is_probable_prime(p)
        or (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p == 0
        or not (isinstance(point, (tuple, list)) and len(point) == 2)
    ):
        return None
    def _as_point(seq):
        # Shape was checked above; coordinates must also coerce to int, else fail closed (the
        # module's contract is to return None on malformed evidence, not raise).
        if not (isinstance(seq, (tuple, list)) and len(seq) == 2):
            return None
        try:
            return (int(seq[0]) % p, int(seq[1]) % p)
        except (TypeError, ValueError):
            return None
    probe = _as_point(point)
    if probe is None:
        return None
    observed: Point
    if response is None:
        observed = None
    else:
        observed = _as_point(response)
        if observed is None:
            return None
    on_alternate_curve = lambda candidate: candidate is None or (
        candidate[1] * candidate[1]
        - (candidate[0] * candidate[0] * candidate[0] + a * candidate[0] + b)
    ) % p == 0
    if not on_alternate_curve(probe) or not on_alternate_curve(observed):
        return None
    return SmallSubgroupObservation(
        order=subgroup_order,
        probe=probe,
        response=observed,
        scalar_mul=lambda scalar, selected: _raw_mul(scalar, selected, p, a),
        identity=None,
    )


def recover_invalid_curve_residue(
    p: int,
    a: int,
    b: int,
    point: Any,
    response: Any,
    subgroup_order: int,
) -> Optional[tuple[int, int]]:
    """Recover a residue from a concrete alternate-curve transcript."""

    observation = make_invalid_curve_observation(
        p, a, b, point, response, subgroup_order
    )
    return recover_small_subgroup_residue(observation) if observation else None


def _crt_merge(left: tuple[int, int], right: tuple[int, int]) -> Optional[tuple[int, int]]:
    x, modulus_x = left
    y, modulus_y = right
    common = math.gcd(modulus_x, modulus_y)
    if (y - x) % common:
        return None
    reduced_x = modulus_x // common
    reduced_y = modulus_y // common
    try:
        step = (
            (y - x) // common * pow(reduced_x, -1, reduced_y) % reduced_y
            if reduced_y > 1
            else 0
        )
    except ValueError:
        return None
    modulus = modulus_x * reduced_y
    return (x + modulus_x * step) % modulus, modulus


def recover_invalid_curve_private_scalar(
    observations: Iterable[SmallSubgroupObservation],
    group_order: int,
    public_key: Any,
    public_mul: Callable[[int], Any],
    public_identity: Any,
    *,
    public_equal: Callable[[Any, Any], bool] = lambda left, right: left == right,
    max_candidates: int = MAX_CRT_CANDIDATES,
) -> Optional[int]:
    """Combine subgroup residues and emit only a uniquely point-proven scalar.

    ``public_mul(k)`` must compute ``[k]G`` in the *real* target group.  Candidate
    enumeration is refused when the CRT evidence leaves more than
    ``max_candidates`` representatives, avoiding accidental brute force.
    """

    if (
        not isinstance(group_order, int)
        or group_order <= 2
        or not callable(public_mul)
        or not callable(public_equal)
        or not isinstance(max_candidates, int)
        or not (0 < max_candidates <= MAX_CRT_CANDIDATES)
    ):
        return None
    try:
        iterator = iter(observations)
        rows = list(itertools.islice(iterator, MAX_OBSERVATIONS + 1))
    except (TypeError, MemoryError):
        return None
    if not rows or len(rows) > MAX_OBSERVATIONS:
        return None
    try:
        if not _checked_equal(public_equal, public_mul(group_order), public_identity):
            return None
        if _checked_equal(public_equal, public_key, public_identity):
            return None
    except Exception:
        return None
    combined = (0, 1)
    for observation in rows:
        residue = recover_small_subgroup_residue(observation)
        if residue is None:
            return None
        merged = _crt_merge(combined, residue)
        if merged is None:
            return None
        combined = merged
    residue, modulus = combined
    first = residue if residue > 0 else modulus
    if first >= group_order:
        return None
    candidate_count = 1 + (group_order - 1 - first) // modulus
    if candidate_count > max_candidates:
        return None
    matches: list[int] = []
    try:
        for candidate in range(first, group_order, modulus):
            if _checked_equal(public_equal, public_mul(candidate), public_key):
                # Replay every observation with the full scalar as a second,
                # independent check of the CRT assembly.
                if all(
                    _checked_equal(observation.equal,
                        observation.scalar_mul(candidate, observation.probe),
                        observation.response,
                    )
                    for observation in rows
                ):
                    matches.append(candidate)
    except Exception:
        return None
    return matches[0] if len(matches) == 1 else None


__all__ = [
    "CURVES",
    "ED25519_L",
    "ED25519_REF10_S_BOUND",
    "ED25519_S_ENCODING_BOUND",
    "Ed25519MalleableSignature",
    "SECP256K1",
    "SECP256R1",
    "SmallSubgroupObservation",
    "WeierstrassCurve",
    "ec_mul",
    "ecdsa_verify",
    "ed25519_canonicalize_signature",
    "ed25519_malleable_signatures",
    "ed25519_public_from_scalar",
    "ed25519_verify",
    "ed25519_verify_lax",
    "make_invalid_curve_observation",
    "recover_ecdsa_known_nonce",
    "recover_ecdsa_nonce_delta",
    "recover_ecdsa_fault_reused_nonce",
    "recover_ecdsa_faulted_nonce_delta",
    "recover_ecdsa_reused_nonce",
    "recover_eddsa_faulted_nonce_delta",
    "recover_eddsa_reused_nonce",
    "recover_ed25519_faulted_nonce_delta",
    "recover_ed25519_nonce_delta",
    "recover_ed25519_reused_nonce",
    "recover_invalid_curve_private_scalar",
    "recover_invalid_curve_residue",
    "recover_small_subgroup_residue",
]
