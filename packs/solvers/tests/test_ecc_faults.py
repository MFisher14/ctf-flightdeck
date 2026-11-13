"""Deterministic proof/ambiguity tests for the r5c ECC fault suite."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).resolve().parents[1] / "solvers" / "common"
sys.path.insert(0, str(COMMON))

import ecc_faults as ecc  # noqa: E402


def _ecdsa_sign(private: int, nonce: int, digest: bytes):
    curve = ecc.SECP256R1
    z = int.from_bytes(digest, "big")
    nonce_point = ecc.ec_mul(nonce, curve=curve)
    assert nonce_point is not None
    r = nonce_point[0] % curve.n
    s = pow(nonce, -1, curve.n) * (z + r * private) % curve.n
    return r, s, z


def _cryptography_check(signature, digest, public_key):
    crypto = pytest.importorskip("cryptography")
    del crypto
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    public_key.verify(
        utils.encode_dss_signature(signature[0], signature[1]),
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )


def test_ecdsa_known_reused_and_delta_faults_are_publicly_proven():
    from cryptography.hazmat.primitives.asymmetric import ec

    curve = ecc.SECP256R1
    private = 0x123456789ABCDEF123456789ABCDEF123456789ABCDEF
    public = ecc.ec_mul(private, curve=curve)
    assert public is not None

    # Independent-library point cross-check.
    library_private = ec.derive_private_key(private, ec.SECP256R1())
    numbers = library_private.public_key().public_numbers()
    assert public == (numbers.x, numbers.y)

    digest1 = hashlib.sha256(b"r5c known/reused nonce one").digest()
    digest2 = hashlib.sha256(b"r5c known/reused nonce two").digest()
    reused_nonce = 0x112233445566778899
    sig1 = _ecdsa_sign(private, reused_nonce, digest1)
    sig2 = _ecdsa_sign(private, reused_nonce, digest2)
    _cryptography_check(sig1, digest1, library_private.public_key())
    _cryptography_check(sig2, digest2, library_private.public_key())

    assert ecc.recover_ecdsa_known_nonce(sig1, reused_nonce, public, curve) == private
    assert ecc.recover_ecdsa_reused_nonce(sig1, sig2, public, curve) == private
    assert ecc.recover_ecdsa_fault_reused_nonce(sig1, sig2, public, curve) == private

    delta = 0x12345
    delta_sig1 = _ecdsa_sign(private, reused_nonce, digest1)
    delta_sig2 = _ecdsa_sign(private, reused_nonce + delta, digest2)
    _cryptography_check(delta_sig2, digest2, library_private.public_key())
    assert ecc.recover_ecdsa_nonce_delta(
        delta_sig1, delta_sig2, delta, public, curve
    ) == private
    assert ecc.recover_ecdsa_faulted_nonce_delta(
        delta_sig1, delta_sig2, delta, public, curve
    ) == private

    # Each attack declines contradictory/ambiguous original evidence.
    wrong_public = ecc.ec_mul(private + 1, curve=curve)
    assert ecc.recover_ecdsa_known_nonce(sig1, reused_nonce, wrong_public, curve) is None
    assert ecc.recover_ecdsa_reused_nonce(sig1, sig1, public, curve) is None
    assert ecc.recover_ecdsa_fault_reused_nonce(sig1, sig1, public, curve) is None
    assert ecc.recover_ecdsa_nonce_delta(
        delta_sig1, delta_sig2, delta + 1, public, curve
    ) is None
    assert ecc.recover_ecdsa_faulted_nonce_delta(
        delta_sig1, delta_sig2, delta + 1, public, curve
    ) is None


def test_ecdsa_low_s_malleability_and_invalid_public_evidence():
    curve = ecc.SECP256R1
    private = 0xC0DEC0FFEE123456789
    public = ecc.ec_mul(private, curve=curve)
    assert public is not None
    digest1 = hashlib.sha256(b"low-S one").digest()
    digest2 = hashlib.sha256(b"low-S two").digest()
    nonce = 0x33445566778899
    delta = 0x6789

    def low_s(signature):
        r, s, z = signature
        return r, min(s, curve.n - s), z

    reused1 = low_s(_ecdsa_sign(private, nonce, digest1))
    reused2 = low_s(_ecdsa_sign(private, nonce, digest2))
    faulted2 = low_s(_ecdsa_sign(private, nonce + delta, digest2))
    assert ecc.recover_ecdsa_known_nonce(reused1, nonce, public, curve) == private
    assert ecc.recover_ecdsa_reused_nonce(reused1, reused2, public, curve) == private
    assert ecc.recover_ecdsa_nonce_delta(
        reused1, faulted2, delta, public, curve
    ) == private

    # A neighboring delta has no valid nonce transcript.  Invalid/off-curve
    # public keys cannot serve as proof, even when the algebra alone has a root.
    assert ecc.recover_ecdsa_nonce_delta(
        reused1, faulted2, delta + 1, public, curve
    ) is None
    assert not ecc.ecdsa_verify(reused1, (0, 0), curve)
    assert ecc.recover_ecdsa_known_nonce(reused1, nonce, (0, 0), curve) is None
    assert ecc.recover_ecdsa_reused_nonce(reused1, reused2, None, curve) is None


def _ed_scalar_from_seed(seed: bytes) -> int:
    expanded = bytearray(hashlib.sha512(seed).digest()[:32])
    expanded[0] &= 248
    expanded[31] &= 63
    expanded[31] |= 64
    return int.from_bytes(expanded, "little") % ecc.ED25519_L


def _ed_sign_with_nonce(private: int, public: bytes, nonce: int, message: bytes) -> bytes:
    encoded_r = ecc.ed25519_public_from_scalar(nonce)
    assert encoded_r is not None
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public + message).digest(), "little"
    ) % ecc.ED25519_L
    scalar_s = (nonce + challenge * private) % ecc.ED25519_L
    return encoded_r + scalar_s.to_bytes(32, "little")


def test_ed25519_reused_nonce_and_nonce_delta_faults_crosscheck_library():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    seed = bytes(range(32))
    private = _ed_scalar_from_seed(seed)
    public = ecc.ed25519_public_from_scalar(private)
    assert public is not None
    library_public = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    assert public == library_public

    message1 = b"r5c EdDSA fault transcript one"
    message2 = b"r5c EdDSA fault transcript two"
    nonce = 0x123456789ABCDEF
    signature1 = _ed_sign_with_nonce(private, public, nonce, message1)
    signature2 = _ed_sign_with_nonce(private, public, nonce, message2)
    Ed25519PrivateKey.from_private_bytes(seed).public_key().verify(signature1, message1)
    Ed25519PrivateKey.from_private_bytes(seed).public_key().verify(signature2, message2)

    assert ecc.ed25519_verify(signature1, message1, public)
    assert ecc.recover_ed25519_reused_nonce(
        signature1, message1, signature2, message2, public
    ) == private
    assert ecc.recover_eddsa_reused_nonce(
        signature1, message1, signature2, message2, public
    ) == private

    delta = 31337
    delta_signature = _ed_sign_with_nonce(private, public, nonce + delta, message2)
    Ed25519PrivateKey.from_private_bytes(seed).public_key().verify(delta_signature, message2)
    assert ecc.recover_ed25519_nonce_delta(
        signature1, message1, delta_signature, message2, delta, public
    ) == private
    assert ecc.recover_eddsa_faulted_nonce_delta(
        signature1, message1, delta_signature, message2, delta, public
    ) == private

    wrong_public = ecc.ed25519_public_from_scalar(private + 1)
    assert wrong_public is not None
    assert ecc.recover_ed25519_reused_nonce(
        signature1, message1, signature2, message2, wrong_public
    ) is None
    assert ecc.recover_eddsa_reused_nonce(
        signature1, message1, signature2, message2, wrong_public
    ) is None
    assert ecc.recover_ed25519_nonce_delta(
        signature1, message1, delta_signature, message2, delta + 1, public
    ) is None
    assert ecc.recover_eddsa_faulted_nonce_delta(
        signature1, message1, delta_signature, message2, delta + 1, public
    ) is None


def test_ed25519_malleable_s_plus_kl_signatures_crosscheck_library():
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = bytes(range(1, 33))
    private = _ed_scalar_from_seed(seed)
    public = ecc.ed25519_public_from_scalar(private)
    assert public is not None
    message = b"landfall S+kL malleability"
    nonce = 0x1337C0DE
    signature = _ed_sign_with_nonce(private, public, nonce, message)

    library_public = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    # The base signature is canonical: a real strict library accepts it.
    library_public.verify(signature, message)
    assert ecc.ed25519_verify(signature, message, public)
    assert ecc.ed25519_verify_lax(signature, message, public)

    variants = ecc.ed25519_malleable_signatures(
        signature, count=3, public_key=public, message=message
    )
    assert [v.k for v in variants] == [1, 2, 3]
    base_s = int.from_bytes(signature[32:], "little")
    for variant in variants:
        assert variant.signature[:32] == signature[:32]  # R unchanged
        assert variant.signature != signature  # byte-distinct from the original
        assert variant.scalar_s == base_s + variant.k * ecc.ED25519_L  # S + kL
        assert variant.scalar_s % ecc.ED25519_L == base_s  # reduces back to S
        assert variant.scalar_s >= ecc.ED25519_L  # genuinely non-canonical
        # A strict verifier -- ours and the real library -- rejects it ...
        assert not ecc.ed25519_verify(variant.signature, message, public)
        with pytest.raises(InvalidSignature):
            library_public.verify(variant.signature, message)
        # ... while a permissive verifier accepts it for the same msg/key.
        assert ecc.ed25519_verify_lax(variant.signature, message, public)

    # Lax verification is not a free pass: a tampered message or wrong key fails.
    assert not ecc.ed25519_verify_lax(variants[0].signature, b"other message", public)
    wrong_public = ecc.ed25519_public_from_scalar(private + 1)
    assert wrong_public is not None
    assert not ecc.ed25519_verify_lax(variants[0].signature, message, wrong_public)


def test_ed25519_malleable_generator_fails_closed():
    seed = bytes(range(2, 34))
    private = _ed_scalar_from_seed(seed)
    public = ecc.ed25519_public_from_scalar(private)
    assert public is not None
    message = b"fail-closed transcript"
    signature = _ed_sign_with_nonce(private, public, 0x4242, message)

    # Wrong length is refused (bad data fails closed) ...
    assert ecc.ed25519_malleable_signatures(signature[:63]) == []
    assert ecc.ed25519_malleable_signatures(b"", count=2) == []
    # ... while a non-positive count is a caller error and raises.
    with pytest.raises(ValueError, match="count"):
        ecc.ed25519_malleable_signatures(signature, count=0)

    # An already non-canonical input (S >= L) is refused, not compounded.
    noncanonical = signature[:32] + (
        int.from_bytes(signature[32:], "little") + ecc.ED25519_L
    ).to_bytes(32, "little")
    assert ecc.ed25519_malleable_signatures(noncanonical) == []

    # A message the signature does not actually sign fails the proof check.
    assert (
        ecc.ed25519_malleable_signatures(signature, public_key=public, message=b"nope")
        == []
    )
    # A mismatched public key fails the proof check too.
    wrong_public = ecc.ed25519_public_from_scalar(private + 1)
    assert (
        ecc.ed25519_malleable_signatures(
            signature, public_key=wrong_public, message=message
        )
        == []
    )

    # Without the optional proof pair the deterministic transform still emits.
    blind = ecc.ed25519_malleable_signatures(signature, count=2)
    assert len(blind) == 2
    assert all(v.signature[:32] == signature[:32] for v in blind)
    assert all(ecc.ed25519_verify_lax(v.signature, message, public) for v in blind)


def test_ed25519_rejects_torsion_noncanonical_and_noncanonical_s():
    private = 0x123456789ABCDEF
    public = ecc.ed25519_public_from_scalar(private)
    assert public is not None
    message1, message2 = b"strict Ed one", b"strict Ed two"
    nonce = 0x9988776655
    signature1 = _ed_sign_with_nonce(private, public, nonce, message1)
    signature2 = _ed_sign_with_nonce(private, public, nonce, message2)

    identity = b"\x01" + b"\x00" * 31
    order_two = (ecc.ED25519_P - 1).to_bytes(32, "little")
    noncanonical_y = ecc.ED25519_P.to_bytes(32, "little")
    for invalid_public in (identity, order_two, noncanonical_y):
        assert not ecc.ed25519_verify(signature1, message1, invalid_public)
        assert ecc.recover_ed25519_reused_nonce(
            signature1, message1, signature2, message2, invalid_public
        ) is None

    for invalid_r in (identity, order_two, noncanonical_y):
        malformed = invalid_r + signature1[32:]
        assert not ecc.ed25519_verify(malformed, message1, public)
        assert ecc.recover_ed25519_reused_nonce(
            malformed, message1, signature2, message2, public
        ) is None

    oversized_s = signature1[:32] + ecc.ED25519_L.to_bytes(32, "little")
    assert not ecc.ed25519_verify(oversized_s, message1, public)
    assert ecc.recover_ed25519_reused_nonce(
        oversized_s, message1, signature2, message2, public
    ) is None


def test_concrete_invalid_curve_residue_replay_and_ambiguity_decline():
    # All alternate curves share p and a, matching the classic implementation
    # bug where the victim's formulas ignore b.  This point has exact order 5.
    p, a, b = 211, 1, 2
    point = (58, 29)
    secret = 173
    response = ecc._raw_mul(secret, point, p, a)
    assert ecc.recover_invalid_curve_residue(p, a, b, point, response, 5) == (3, 5)

    # Claiming a non-exact order leaves multiple representations; fail closed.
    assert ecc.recover_invalid_curve_residue(p, a, b, point, response, 10) is None


def test_invalid_curve_crt_private_scalar_requires_real_public_key_proof():
    p, a = 211, 1
    secret = 173
    fixtures = (
        # (alternate b, point, exact order)
        (2, (58, 29), 5),
        (9, (116, 26), 7),
        (10, (14, 5), 11),
    )
    observations = []
    for b, point, order in fixtures:
        response = ecc._raw_mul(secret, point, p, a)
        observation = ecc.make_invalid_curve_observation(
            p, a, b, point, response, order
        )
        assert observation is not None
        observations.append(observation)

    # The real curve y^2=x^3+x+1 has prime order 223 at G=(0,1).
    generator = (0, 1)
    group_order = 223
    public = ecc._raw_mul(secret, generator, p, a)
    public_mul = lambda scalar: ecc._raw_mul(scalar, generator, p, a)
    assert ecc.recover_invalid_curve_private_scalar(
        observations, group_order, public, public_mul, None
    ) == secret

    # One subgroup leaves too many candidates: decline rather than enumerate.
    assert ecc.recover_invalid_curve_private_scalar(
        observations[:1], group_order, public, public_mul, None, max_candidates=1
    ) is None
    wrong_public = public_mul(secret + 1)
    assert ecc.recover_invalid_curve_private_scalar(
        observations, group_order, wrong_public, public_mul, None
    ) is None


def test_generic_small_subgroup_residue_requires_exact_order_and_unique_replay():
    observation = ecc.SmallSubgroupObservation(
        order=7,
        probe=1,
        response=5,
        scalar_mul=lambda scalar, probe: scalar * probe % 7,
        identity=0,
    )
    assert ecc.recover_small_subgroup_residue(observation) == (5, 7)

    ambiguous_claim = ecc.SmallSubgroupObservation(
        order=14,
        probe=2,
        response=10,
        scalar_mul=lambda scalar, probe: scalar * probe % 14,
        identity=0,
    )
    assert ecc.recover_small_subgroup_residue(ambiguous_claim) is None


def test_generalized_crt_noncoprime_conflict_and_callback_failures():
    def cyclic_observation(order, residue):
        return ecc.SmallSubgroupObservation(
            order=order,
            probe=1,
            response=residue % order,
            scalar_mul=lambda scalar, probe, modulus=order: scalar * probe % modulus,
            identity=0,
        )

    secret = 17
    consistent = [cyclic_observation(6, secret), cyclic_observation(10, secret)]
    public_mul = lambda scalar: scalar % 31
    assert ecc.recover_invalid_curve_private_scalar(
        consistent, 31, secret, public_mul, 0
    ) == secret

    # gcd(6, 10)=2, but 1 mod 6 conflicts with 2 mod 10.
    conflicting = [cyclic_observation(6, 1), cyclic_observation(10, 2)]
    assert ecc.recover_invalid_curve_private_scalar(
        conflicting, 31, secret, public_mul, 0
    ) is None

    exploding = ecc.SmallSubgroupObservation(
        order=5,
        probe=1,
        response=1,
        scalar_mul=lambda _scalar, _probe: (_ for _ in ()).throw(RuntimeError("boom")),
        identity=0,
    )
    assert ecc.recover_small_subgroup_residue(exploding) is None
    assert ecc.recover_invalid_curve_private_scalar(
        consistent,
        31,
        secret,
        lambda _scalar: (_ for _ in ()).throw(RuntimeError("boom")),
        0,
    ) is None
    assert ecc.recover_invalid_curve_private_scalar(
        consistent,
        31,
        secret,
        public_mul,
        0,
        public_equal=lambda _left, _right: (_ for _ in ()).throw(RuntimeError("boom")),
    ) is None
    assert ecc.recover_invalid_curve_private_scalar(
        consistent,
        31,
        secret,
        public_mul,
        0,
        public_equal=lambda _left, _right: "yes",
    ) is None

    malformed_equality = ecc.SmallSubgroupObservation(
        order=5,
        probe=1,
        response=2,
        scalar_mul=lambda scalar, probe: scalar * probe % 5,
        identity=0,
        equal=lambda _left, _right: "yes",
    )
    assert ecc.recover_small_subgroup_residue(malformed_equality) is None


def test_observation_iterator_is_bounded_before_callback_work():
    valid = ecc.SmallSubgroupObservation(
        order=3,
        probe=1,
        response=1,
        scalar_mul=lambda scalar, probe: scalar * probe % 3,
        identity=0,
    )

    def too_many():
        for _ in range(ecc.MAX_OBSERVATIONS + 1):
            yield valid
        raise AssertionError("the bounded reader must not consume beyond MAX+1")

    assert ecc.recover_invalid_curve_private_scalar(
        too_many(), 7, 1, lambda scalar: scalar % 7, 0
    ) is None
