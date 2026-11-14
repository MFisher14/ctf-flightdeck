"""Deterministic verification and ambiguity tests for r5c RSA attacks."""

from __future__ import annotations

import math
import itertools
import sys
import time
from pathlib import Path

import pytest


COMMON = Path(__file__).resolve().parents[1] / "solvers" / "common"
sys.path.insert(0, str(COMMON))

import rsa_attacks as rsa  # noqa: E402


P, Q = 101, 113
N = P * Q
E = 17
D = pow(E, -1, (P - 1) * (Q - 1))


def test_common_modulus_verifies_every_observation_and_declines_ambiguity():
    message = 4243
    samples = [(7, pow(message, 7, N)), (11, pow(message, 11, N)), (13, pow(message, 13, N))]
    assert rsa.recover_common_modulus(N, samples) == message
    assert rsa.recover_common_modulus(N, samples[:1]) is None
    contradictory = samples + [(19, (pow(message, 19, N) + 1) % N)]
    assert rsa.recover_common_modulus(N, contradictory) is None


def test_common_modulus_generalized_gcd_is_exact_and_nonunit_declines():
    message = 7
    samples = [(6, pow(message, 6, N)), (10, pow(message, 10, N))]
    # Without a stated small-message bound, both modular square roots are viable.
    assert rsa.recover_common_modulus(N, samples) is None
    assert rsa.recover_common_modulus(N, samples, message_bound=100) == message
    assert rsa.recover_common_modulus(N, samples, message_bound=N) is None
    # A negative Bezout exponent would require inverting a non-unit ciphertext.
    nonunit = P
    assert rsa.recover_common_modulus(
        N, [(6, pow(nonunit, 6, N)), (10, pow(nonunit, 10, N))], message_bound=200
    ) is None


def test_fermat_factors_are_prime_and_multiply_back_or_decline():
    p, q = 1_000_003, 1_000_033
    assert rsa.recover_fermat_factors(p * q, max_steps=100, max_gap=40) == (p, q)
    assert rsa.recover_fermat_factors(p * q, max_steps=100, max_gap=20) is None
    assert rsa.recover_fermat_factors(1_000_003, max_steps=20) is None
    assert rsa.recover_close_prime_factors(p * q, max_steps=100, max_gap=40) == (p, q)
    assert rsa.recover_close_prime_factors(p * q, max_steps=100, max_gap=20) is None
    # Difference-of-squares alone is not enough: both factors must be prime.
    assert rsa.recover_fermat_factors(225, max_steps=10) is None


def test_wiener_private_key_round_trips_and_safe_key_declines():
    p, q, d = 10_007, 10_009, 5
    phi = (p - 1) * (q - 1)
    e = pow(d, -1, phi)
    assert rsa.recover_wiener_private_key(p * q, e) == (d, p, q)
    assert rsa.recover_wiener_private_key(N, E) is None


def test_hastad_requires_complete_exact_consistent_evidence():
    e, message = 3, 12_345
    moduli = [1_000_003, 1_000_033, 1_000_037]
    pairs = [(n, pow(message, e, n)) for n in moduli]
    assert rsa.recover_hastad_broadcast(pairs, e) == message
    assert rsa.recover_hastad_broadcast(pairs[:2], e) is None
    assert rsa.recover_hastad_broadcast(pairs + [(moduli[0], pairs[0][1] + 1)], e) is None
    shared = [(15, pow(2, 2, 15)), (21, pow(2, 2, 21))]
    assert rsa.recover_hastad_broadcast(shared, 2) is None


def test_franklin_reiter_checks_both_related_ciphertexts():
    e, message, a, b = 3, 1234, 2, 91
    c1 = pow(message, e, N)
    c2 = pow((a * message + b) % N, e, N)
    assert rsa.recover_franklin_reiter(N, e, c1, c2, a=a, b=b) == message
    assert rsa.recover_franklin_reiter(N, e, c1, (c2 + 1) % N, a=a, b=b) is None
    assert rsa.recover_related_message(N, e, c1, c2, a=a, b=b) == message
    assert rsa.recover_related_message(N, e, c1, (c2 + 1) % N, a=a, b=b) is None


def test_coppersmith_root_is_rechecked_and_multiple_roots_decline():
    # Force the exact-LLL path even though this linear fixture is tiny.
    assert rsa.recover_coppersmith_root([-37, 1], 1_000_003, 100, max_enumeration=0) == 37
    # x(x-1) has two proven small roots; choosing either would be unsafe.
    assert rsa.recover_coppersmith_root([0, -1, 1], 1_000_003, 10) is None
    assert rsa.recover_coppersmith_root([0, -1, 1], 1_000_003, 10, max_enumeration=0) is None


def test_stereotyped_message_reencrypts_and_collision_declines():
    n = 18_023_349_892_527_103
    message = b"A\x2aZ"
    ciphertext = pow(int.from_bytes(message, "big"), 3, n)
    assert rsa.recover_stereotyped_message(
        n, 3, ciphertext, prefix=b"A", suffix=b"Z", unknown_len=1
    ) == message
    assert rsa.recover_stereotyped_message(
        n, 3, ciphertext, prefix=b"B", suffix=b"Z", unknown_len=1
    ) is None
    # Many one-byte messages cube to zero modulo 15: evidence is ambiguous.
    assert rsa.recover_stereotyped_message(15, 3, 0, unknown_len=1) is None


def test_partial_prime_high_and_low_bits_verify_full_factorisation():
    p, q, n = 1009, 1013, 1009 * 1013
    assert rsa.recover_partial_prime(n, p >> 4, 6, kind="high", p_bits=10) == (p, q)
    assert rsa.recover_partial_prime(n, p & 0x3F, 6, kind="low", p_bits=10) == (p, q)
    assert rsa.recover_partial_prime(n, 0, 6, kind="high", p_bits=10) is None


def test_known_d_bits_unique_completion_and_equivalent_d_ambiguity():
    total = D.bit_length()
    assert total == 12
    assert rsa.recover_private_exponent_known_bits(
        N, E, D >> 2, total - 2, total, kind="high"
    ) == (D, P, Q)
    # lambda(N)=2800: d=1153 and d=3953 are both valid and odd in this range.
    assert rsa.recover_private_exponent_known_bits(
        N, E, 1, 1, total, kind="low"
    ) is None


def test_boneh_durfee_result_is_private_key_verified_and_bad_input_declines():
    p, q = 134_230_081, 134_272_063
    n, e, d = p * q, 16_829_390_121_700_559, 6959
    assert rsa.recover_wiener_private_key(n, e) is None
    got = rsa.recover_boneh_durfee_private_key(
        n, e, delta=0.29, m=3, t=1, deadline=time.monotonic() + 5
    )
    assert got == (d, p, q)
    assert rsa.recover_boneh_durfee_private_key(n, 65_537, deadline=time.monotonic() + 1) is None


def _crt(residues, moduli):
    value = 0
    product = math.prod(moduli)
    for residue, modulus in zip(residues, moduli):
        part = product // modulus
        value += residue * part * pow(part, -1, modulus)
    return value % product


def test_crt_rsa_fault_derives_and_cross_checks_private_key():
    message = 42
    correct = pow(message, D, N)
    # Correct modulo P, deliberately wrong modulo Q.
    faulty = _crt([correct % P, (correct + 1) % Q], [P, Q])
    assert pow(faulty, E, N) != message
    assert rsa.recover_crt_fault_private_key(
        N, E, message, faulty, correct_signature=correct
    ) == (D, P, Q)
    assert rsa.recover_crt_fault_private_key(N, E, message, correct) is None
    assert rsa.recover_crt_fault_private_key(
        N, E, message, faulty, correct_signature=(correct + 1) % N
    ) is None
    # A productive gcd against a three-prime modulus leaves a composite cofactor.
    assert rsa.recover_crt_fault_private_key(105, 3, 2, 2) is None


@pytest.mark.parametrize(
    "call",
    [
        lambda: rsa.recover_common_modulus(True, [(3, 1), (5, 1)]),
        lambda: rsa.recover_common_modulus(N, [(True, 1), (5, 1)]),
        lambda: rsa.recover_common_modulus(N, [(3, 1), (5, 1)], message_bound=True),
        lambda: rsa.recover_fermat_factors(N, max_steps=True),
        lambda: rsa.recover_close_prime_factors(N, max_gap=True),
        lambda: rsa.recover_wiener_private_key(True, E),
        lambda: rsa.recover_hastad_broadcast([(5, 1), (7, 1)], True),
        lambda: rsa.recover_franklin_reiter(N, 3, 1, 1, a=True),
        lambda: rsa.recover_related_message(N, 3, 1, 1, b=False),
        lambda: rsa.recover_coppersmith_root([True, 1], N, 10),
        lambda: rsa.recover_stereotyped_message(N, 3, 1, unknown_len=True),
        lambda: rsa.recover_partial_prime(N, True, 1, p_bits=7),
        lambda: rsa.recover_partial_prime(N, 1, 1, p_bits=7, kind=[]),
        lambda: rsa.recover_private_exponent_known_bits(N, E, 1, 1, True),
        lambda: rsa.recover_private_exponent_known_bits(N, E, 1, 1, 12, kind=[]),
        lambda: rsa.recover_boneh_durfee_private_key(N, E, m=True),
        lambda: rsa.recover_crt_fault_private_key(N, E, 42, True),
    ],
)
def test_boolean_inputs_are_not_silently_coerced_to_crypto_integers(call):
    assert call() is None


def test_negative_malformed_deadline_and_candidate_caps_decline():
    past = time.monotonic() - 1
    assert rsa.recover_common_modulus(-N, [(3, 1), (5, 1)]) is None
    assert rsa.recover_fermat_factors(N, max_steps=-1) is None
    assert rsa.recover_fermat_factors(N, deadline=past) is None
    assert rsa.recover_coppersmith_root([-1, 1], N, -1) is None
    assert rsa.recover_coppersmith_root([0] * 32 + [1], N, 10) is None
    assert rsa.recover_coppersmith_root([-1, 1], N, 10, deadline=past) is None
    assert rsa.recover_stereotyped_message(N, 3, -1, unknown_len=1) is None
    assert rsa.recover_stereotyped_message(N, 65_537, 1, unknown_len=1) is None
    assert rsa.recover_partial_prime(N, -1, 1, p_bits=7) is None
    assert rsa.recover_partial_prime(N, 1, 1, p_bits=7, deadline=past) is None
    assert rsa.recover_private_exponent_known_bits(
        N, E, 1, 1, 100, max_candidates=32
    ) is None
    assert rsa.recover_private_exponent_known_bits(
        N, E, 1, 1, 12, deadline=past
    ) is None
    assert rsa.recover_boneh_durfee_private_key(N, E, delta=float("nan")) is None
    assert rsa.recover_boneh_durfee_private_key(N, E, deadline=past) is None
    assert rsa.recover_crt_fault_private_key(N, E, 42, -1) is None


def test_iterables_and_stereotyped_integer_construction_are_bounded():
    assert rsa.recover_common_modulus(N, itertools.repeat((3, 1))) is None
    assert rsa.recover_common_modulus(
        N, [(3, 1)] * (rsa.MAX_RSA_OBSERVATIONS + 1)
    ) is None
    assert rsa.recover_hastad_broadcast(itertools.repeat((5, 1)), 2) is None
    assert rsa.recover_hastad_broadcast(
        [(5, 1)] * (rsa.MAX_RSA_OBSERVATIONS + 1), 2
    ) is None
    assert rsa.recover_coppersmith_root(itertools.repeat(1), N, 10) is None
    assert rsa.recover_coppersmith_root(
        [1] * (rsa.MAX_COPPERSMITH_COEFFICIENTS + 1), N, 10
    ) is None
    assert rsa.recover_stereotyped_message(
        N,
        3,
        1,
        prefix=b"A" * rsa.MAX_STEREOTYPED_BYTES,
        unknown_len=1,
    ) is None


def test_wrappers_reject_bogus_underlying_candidates(monkeypatch):
    monkeypatch.setattr(rsa._mc, "fermat", lambda *args, **kwargs: (3, 5))
    assert rsa.recover_fermat_factors(N) is None

    monkeypatch.setattr(rsa._mc, "wiener", lambda *args, **kwargs: (1, P, Q))
    assert rsa.recover_wiener_private_key(N, E) is None

    monkeypatch.setattr(rsa._mc, "franklin_reiter", lambda *args, **kwargs: 1235)
    c1, c2 = pow(1234, 3, N), pow(2 * 1234 + 91, 3, N)
    assert rsa.recover_franklin_reiter(N, 3, c1, c2, a=2, b=91) is None

    monkeypatch.setattr(rsa._mc, "crt", lambda *args, **kwargs: (8, 35))
    assert rsa.recover_hastad_broadcast([(5, 4), (7, 2)], 2) is None

    monkeypatch.setattr(rsa._rl, "coppersmith_roots", lambda *args, **kwargs: [38])
    assert rsa.recover_coppersmith_root([-37, 1], 1_000_003, 100, max_enumeration=0) is None

    monkeypatch.setattr(rsa._rl, "partial_prime", lambda *args, **kwargs: (P, Q))
    assert rsa.recover_partial_prime(N, 0, 1, p_bits=7, max_enumeration=0) is None

    monkeypatch.setattr(rsa._rl, "boneh_durfee", lambda *args, **kwargs: (1, P, Q))
    assert rsa.recover_boneh_durfee_private_key(N, E) is None
