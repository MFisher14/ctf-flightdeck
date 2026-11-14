"""Deterministic equation-replay tests for r5c protocol crypto."""

from __future__ import annotations

import hashlib
import itertools
import math
import random
import sys
from pathlib import Path


COMMON = Path(__file__).resolve().parents[1] / "solvers" / "common"
sys.path.insert(0, str(COMMON))
import protocol_crypto as pc  # noqa: E402


def test_dh_audit_small_subgroup_and_crt_replay():
    p, g, secret = 1019, 2, 173
    public = pow(g, secret, p)
    audit = pc.audit_dh_group(p, g, order_factors=(2, 509), public_values=(public,))
    assert audit and audit.modulus_prime and audit.generator_order == 1018
    incomplete = pc.audit_dh_group(p, g, order_factors=(2,), public_values=(public,))
    assert incomplete and incomplete.generator_order is None and "order_not_proven" in incomplete.findings
    exact_order = pc.audit_dh_group(23, 4, subgroup_order=22, order_factors=(2, 11))
    assert exact_order and exact_order.generator_order == 11
    residues = [(secret % 7, 7), (secret % 11, 11), (secret % 13, 13)]
    assert pc.recover_dh_exponent_crt(p, g, public, residues, exponent_bound=500) == secret
    assert pc.recover_dh_exponent_crt(p, g, public, residues[:1], exponent_bound=500_000) is None

    base, order = pow(g, (p - 1) // 509, p), 509
    assert pc.recover_small_subgroup_residue(p, base, pow(base, secret, p), order) == secret % order
    assert pc.recover_small_subgroup_residue(p, 1, 1, order) is None
    assert pc.recover_small_subgroup_residue(p, base, 1 << (pc.MAX_BITS + 1), order) is None


def test_elgamal_reuse_and_homomorphic_structure_decline_ambiguity():
    p, g, x, k = 467, 2, 127, 17
    y, c1, shared = pow(g, x, p), pow(g, k, p), pow(pow(g, x, p), k, p)
    known_m, target_m = 42, 123
    known, target = (c1, known_m * shared % p), (c1, target_m * shared % p)
    got = pc.recover_elgamal_reused_nonce(p, g, y, known, known_m, target, nonce_bound=64)
    assert got == pc.ElGamalRecovery(target_m, k, shared)
    assert pc.recover_elgamal_reused_nonce(p, g, y, known, known_m, (c1 + 1, target[1]), nonce_bound=64) is None
    product = pc.elgamal_homomorphic_multiply([known, target], p)
    assert product and product.relation_replayed and product.output == (c1 * c1 % p, known[1] * target[1] % p)
    assert pc.elgamal_homomorphic_multiply(itertools.repeat(known), p) is None


def test_paillier_weak_reuse_and_homomorphic_exact_n_squared_replay():
    n, r, m1, m2 = 77, 13, 12, 31
    c1, c2 = pc.paillier_encrypt(m1, r, n), pc.paillier_encrypt(m2, r, n)
    weak = pc.recover_paillier_weak_randomness(c2, n, [2, r, 20])
    assert weak and weak.plaintext == m2 and weak.randomness == r
    assert pc.recover_paillier_weak_randomness(c2, n, [2, 20]) is None
    reused = pc.recover_paillier_reused_randomness(c1, m1, c2, n, [2, r, 20])
    assert reused and reused.plaintext == m2 and reused.randomness == r \
        and reused.randomness_factor == pow(r, n, n * n)
    combined = pc.paillier_homomorphic_add([c1, c2], n)
    assert combined and combined.relation_replayed and combined.output[0] == c1 * c2 % (n * n)
    factor = 2  # Not an n-th residue modulo n^2 for n=15.
    fake1, fake2 = pow(16, 1, 225) * factor % 225, pow(16, 2, 225) * factor % 225
    units = [1, 2, 4, 7, 8, 11, 13, 14]
    assert pc.recover_paillier_reused_randomness(fake1, 1, fake2, 15, units) is None


def test_schnorr_fiat_shamir_reuse_small_nonce_audit_and_decline():
    p, q, g, secret, nonce = 23, 11, 2, 7, 4
    y, commitment = pow(g, secret, p), pow(g, nonce, p)
    signatures = [(commitment, e, (nonce + e * secret) % q) for e in (3, 8)]
    assert pc.recover_schnorr_secret(p, q, g, y, signatures) == secret
    assert pc.recover_schnorr_secret(p, q, g, y, [signatures[0]], nonce_bound=8) == secret
    assert pc.recover_schnorr_secret(p, q, g, y, [(commitment, 0, nonce)]) is None
    audit = pc.audit_schnorr_challenges(signatures + [(commitment, 0, nonce)], q)
    assert audit and commitment in audit.repeated_commitments and "zero_challenge" in audit.findings


def test_dsa_parameter_structure_only():
    good = pc.audit_dsa_parameters(23, 11, 2, pow(2, 7, 23))
    assert good and not good.findings
    bad = pc.audit_dsa_parameters(21, 10, 1, 1)
    assert bad and {"p_not_prime", "q_not_prime", "invalid_generator", "invalid_public_key"} <= set(bad.findings)


def test_robust_shamir_unique_polynomial_and_ambiguity_decline():
    prime, polynomial = 257, (99, 17, 4)
    shares = [(x, sum(coef * pow(x, i, prime) for i, coef in enumerate(polynomial)) % prime) for x in range(1, 7)]
    corrupted = list(shares)
    corrupted[4] = (corrupted[4][0], corrupted[4][1] + 1)
    got = pc.robust_shamir_reconstruct(corrupted, prime, 3, max_errors=1)
    assert got and got.secret == 99 and got.polynomial == polynomial and got.error_indices == (4,)
    assert pc.robust_shamir_reconstruct(corrupted, prime, 3, max_errors=0) is None
    assert pc.robust_shamir_reconstruct(itertools.repeat((1, 2)), prime, 3) is None


def test_pedersen_and_hash_commitments_exact_replay_and_ties_decline():
    p, g, h, randomness = 1019, 2, 5, 19
    known_m, target_m = 33, 71
    known = pc.pedersen_commit(known_m, randomness, p, g, h)
    target = pc.pedersen_commit(target_m, randomness, p, g, h)
    reused = pc.recover_pedersen_reused_randomness(
        known, known_m, target, p, g, h, [70, 71, 72], [18, 19, 20]
    )
    assert reused and reused.message == target_m and reused.randomness == randomness \
        and reused.randomness_factor == pow(h, randomness, p)
    weak = pc.recover_pedersen_weak_opening(target, p, g, h, [70, 71], [18, 19])
    assert weak == pc.PedersenRecovery(target_m, randomness, pow(h, randomness, p))
    assert pc.recover_pedersen_weak_opening(1, 23, 2, 4, [0], [0, 11]) is None

    message, salt = b"launch", b"salt"
    digest = hashlib.sha256(len(message).to_bytes(4, "big") + message + salt).digest()
    assert pc.recover_hash_commitment(digest, [b"other", message], [b"x", salt]) == (message, salt)
    assert pc.recover_hash_commitment(digest, itertools.repeat(message), [salt]) is None
    assert pc.recover_hash_commitment(digest, [message], [salt], algorithm="shake_128") is None
    assert pc.recover_hash_commitment(digest, [message], [salt], algorithm=[]) is None


def test_package_import_and_malformed_fail_closed():
    from solvers.common import protocol_crypto as package
    assert package.paillier_encrypt(1, 2, 15) == pc.paillier_encrypt(1, 2, 15)
    assert pc.audit_dh_group(True, 2) is None
    assert pc.recover_dh_exponent_crt(23, 2, 4, [(0, 2), (0, 2)], exponent_bound=10) is None
    assert pc.audit_schnorr_challenges([(1, True, 2)], 11) is None
    assert pc.elgamal_homomorphic_multiply([(1, 1)], 1 << (pc.MAX_BITS + 1)) is None
    assert pc.paillier_homomorphic_add([1], 1 << (pc.MAX_BITS + 1)) is None
    assert pc.recover_paillier_weak_randomness(1, -3, [1]) is None
    assert pc.audit_schnorr_challenges([(1, 1, 1)], 1 << (pc.MAX_BITS + 1)) is None
    assert pc.robust_shamir_reconstruct([(1, 1), (2, 2), (3, 3)], 257, 2,
                                        max_subsets=pc.MAX_ITEMS + 1) is None
    assert pc.recover_pedersen_weak_opening(1, 21, 2, 4, [0], [0]) is None
    assert pc.recover_pedersen_reused_randomness(1, 0, 1, 23, 2, 4, [0], [-1]) is None
    assert pc.recover_paillier_weak_randomness(1, 15, [1, "bad"]) is None
    assert pc.recover_pedersen_weak_opening(1, 23, 2, 4, [0, "bad"], [0]) is None
    assert pc.recover_hash_commitment(b"x", [b"a" * pc.MAX_BYTES], [b"b"]) is None
    assert pc.recover_dh_exponent_crt(23, 2, 4, [(1 << (pc.MAX_BITS + 1), 3)], exponent_bound=10) is None
    assert pc.recover_dh_exponent_crt(23, 2, 4, [(0, pc.MAX_SEARCH + 1)], exponent_bound=10) is None
    assert pc.recover_dh_exponent_crt(23, 2, 4, [(2, 2)], exponent_bound=10) is None
    assert pc.paillier_encrypt(1, 2, 15, g=1 << (pc.MAX_BITS + 1)) is None
    assert pc.paillier_encrypt(1, 2, 17) is None
    assert pc.paillier_homomorphic_add([1], 17) is None
    assert pc.robust_shamir_reconstruct([(1, 1), (2, 999), (3, 3)], 257, 2) is None
    assert pc.robust_shamir_reconstruct([(1 << (pc.MAX_BITS + 1), 1), (2, 2)], 257, 2) is None

    class BytesSubclass(bytes):
        pass
    assert pc.recover_hash_commitment(b"x", [BytesSubclass(b"a")], [b"b"]) is None

    def failing():
        yield 1
        raise RuntimeError("candidate source failed")

    assert pc.recover_paillier_weak_randomness(1, 15, failing()) is None


def test_seeded_protocol_equation_properties():
    rng = random.Random(0xC5C7F)
    for _ in range(12):
        polynomial = (rng.randrange(257), rng.randrange(257), rng.randrange(257))
        shares = [(x, sum(coef * pow(x, i, 257) for i, coef in enumerate(polynomial)) % 257)
                  for x in range(1, 7)]
        bad = rng.randrange(len(shares))
        shares[bad] = (shares[bad][0], (shares[bad][1] + 1) % 257)
        recovered = pc.robust_shamir_reconstruct(shares, 257, 3, max_errors=1)
        assert recovered and recovered.polynomial == polynomial and recovered.error_indices == (bad,)

        message = rng.randrange(77)
        randomness = rng.choice([value for value in range(1, 77) if math.gcd(value, 77) == 1])
        ciphertext = pc.paillier_encrypt(message, randomness, 77)
        assert pc.recover_paillier_weak_randomness(ciphertext, 77, [randomness]).plaintext == message

        opening = (rng.randrange(1018), rng.randrange(1018))
        commitment = pc.pedersen_commit(opening[0], opening[1], 1019, 2, 5)
        assert pc.recover_pedersen_weak_opening(commitment, 1019, 2, 5, [opening[0]], [opening[1]]) \
            == pc.PedersenRecovery(opening[0], opening[1], pow(5, opening[1], 1019))
