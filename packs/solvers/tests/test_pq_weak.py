"""Deterministic tests for verified toy post-quantum weak-parameter attacks."""

from __future__ import annotations

import sys
import importlib
from dataclasses import FrozenInstanceError
from itertools import product, repeat
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))

import pq_weak as pq  # noqa: E402


def _poly_mul(left, right, modulus, *, negacyclic):
    n = len(left)
    raw = [0] * (2 * n - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            raw[i + j] += a * b
    for degree in range(2 * n - 2, n - 1, -1):
        raw[degree - n] += -raw[degree] if negacyclic else raw[degree]
    return tuple(value % modulus for value in raw[:n])


def _module_product(matrix, secret, modulus):
    output = []
    for row in matrix:
        total = [0] * len(secret[0])
        for poly, sec in zip(row, secret):
            term = _poly_mul(poly, sec, modulus, negacyclic=True)
            total = [(a + b) % modulus for a, b in zip(total, term)]
        output.append(tuple(total))
    return tuple(output)


def _center(value, modulus):
    value %= modulus
    return value - modulus if value > modulus // 2 else value


def _brute_poly_inverse(poly, modulus):
    unit = (1,) + (0,) * (len(poly) - 1)
    for candidate in product(range(modulus), repeat=len(poly)):
        if _poly_mul(poly, candidate, modulus, negacyclic=False) == unit:
            return candidate
    return None


def test_package_and_direct_imports_expose_equivalent_offline_api():
    sys.path.insert(0, str(REPO))
    packaged = importlib.import_module("solvers.common.pq_weak")
    assert packaged.__all__ == pq.__all__
    args = ([[4, 2, 8], [3, 15, 14], [15, 12, 6]], [1, 5, 2], 17)
    assert packaged.recover_lwe_secret(*args, error_bound=1) == pq.recover_lwe_secret(
        *args, error_bound=1
    ) == (1, -1, 0)


def test_parameter_audit_dataclasses_are_immutable_and_rank_aware():
    audit = pq.audit_lwe_parameters([[1, 2], [2, 4]], 17, 0, 1)
    assert isinstance(audit, pq.PQParameterAudit)
    assert all(isinstance(item, pq.ParameterFinding) for item in audit.findings)
    assert audit.rank == 1 and audit.toy_attackable
    assert {item.code for item in audit.findings} >= {
        "tiny_modulus",
        "toy_dimension",
        "zero_noise",
        "rank_deficient",
    }
    with pytest.raises(FrozenInstanceError):
        audit.modulus = 19


def test_ntru_parameter_audit_flags_toy_and_malformed_without_mislabeling_valid_composite_q():
    toy = pq.audit_ntru_parameters(3, 17, 3, 1)
    assert toy.toy_attackable
    assert {item.code for item in toy.findings} >= {"toy_degree", "tiny_modulus"}
    malformed = pq.audit_ntru_parameters(5, 9, 9, 1)
    assert not malformed.toy_attackable
    assert "malformed_moduli" in {item.code for item in malformed.findings}
    # Composite q can be legitimate NTRU; the audit emits only a solver-scope notice.
    production_shape = pq.audit_ntru_parameters(509, 2048, 3, 2)
    notices = {item.code: item.severity for item in production_shape.findings}
    assert notices.get("nonprime_modulus") == "notice"
    assert "toy_degree" not in notices and not production_shape.toy_attackable


def test_kyber_parameter_audit_handles_canonical_and_malformed_toy_shapes():
    canonical = pq.audit_kyber_like_parameters(
        2, 256, 3329, 2, flattened_matrix_rank=512, compression_bits=(10, 4)
    )
    assert canonical.findings == () and not canonical.toy_attackable
    weak = pq.audit_kyber_like_parameters(
        2, 3, 17, 0, flattened_matrix_rank=2, compression_bits=(0, 9)
    )
    codes = {item.code for item in weak.findings}
    assert codes >= {
        "malformed_degree",
        "zero_noise",
        "toy_dimension",
        "rank_deficient",
        "malformed_compression",
    }
    assert not weak.toy_attackable


def test_dilithium_parameter_audit_never_calls_canonical_parameters_attackable():
    canonical = pq.audit_dilithium_like_parameters(4, 256, 8380417, 2, 1 << 17)
    assert canonical.findings == () and not canonical.toy_attackable
    weak = pq.audit_dilithium_like_parameters(
        1, 2, 17, 1, 3, reused_nonce_observed=True
    )
    assert weak.toy_attackable
    assert {item.code for item in weak.findings} >= {"toy_dimension", "reused_y"}


def test_lwe_unique_secret_recovery_reproduces_every_equation():
    matrix = [[4, 2, 8], [3, 15, 14], [15, 12, 6]]
    target = [1, 5, 2]
    secret = pq.recover_lwe_secret(matrix, target, 17, error_bound=1)
    assert secret == (1, -1, 0)
    errors = [
        ((target[i] - sum(matrix[i][j] * secret[j] for j in range(3)) + 8) % 17) - 8
        for i in range(3)
    ]
    assert errors == [-1, 0, -1]


def test_lwe_declines_ambiguous_and_production_sized_searches():
    assert pq.recover_lwe_secret([[0, 0], [0, 0]], [0, 0], 17, error_bound=0) is None
    identity_13 = [[int(i == j) for j in range(13)] for i in range(13)]
    assert pq.recover_lwe_secret(identity_13, [0] * 13, 17, error_bound=0) is None


def test_ntru_private_key_recovery_round_trips_public_key():
    public_h = (5, 11, 9)
    recovered = pq.recover_ntru_private_key(public_h, 3, 17)
    assert recovered == ((-2, -3, 0), (-1, -1, 0))
    f, g = recovered
    # Verify the defining relation f*h = p*g in Z_q[x]/(x^n-1).
    assert _poly_mul(f, public_h, 17, negacyclic=False) == tuple(3 * x % 17 for x in g)


def test_ntru_private_key_declines_multiple_valid_small_keys():
    # This h has three normalized small (f, g) witnesses under the declared domain.
    assert pq.recover_ntru_private_key((0, 3, 14), 3, 17) is None


def test_ntru_message_recovery_reproduces_ciphertext():
    public_h = (5, 11, 9)
    ciphertext = (2, 0, 13)
    message = pq.recover_ntru_message(ciphertext, public_h, 17)
    assert message == (-1, -1, -1)
    blinding = (-1, -1, 0)
    product_value = _poly_mul(blinding, public_h, 17, negacyclic=False)
    assert tuple((product_value[i] + message[i]) % 17 for i in range(3)) == ciphertext


def test_ntru_message_declines_ambiguous_blinding_witnesses():
    assert pq.recover_ntru_message((0, 0, 0), (0, 0, 0), 17) is None


def test_kyber_like_weak_secret_recovery_reproduces_module_lwe_equations():
    matrix = (((1, 2), (2, 11)), ((5, 9), (8, 6)))
    public = ((10, 2), (9, 13))
    secret = pq.recover_kyber_like_secret(matrix, public, 17, error_bound=1)
    assert secret == ((1, -1), (0, 1))
    product_value = _module_product(matrix, secret, 17)
    errors = tuple(
        tuple(((public[i][j] - product_value[i][j] + 8) % 17) - 8 for j in range(2))
        for i in range(2)
    )
    assert errors == ((1, -1), (1, 1))


def test_kyber_like_recovery_declines_ambiguous_and_malformed_inputs():
    zero_matrix = (((0, 0),),)
    assert pq.recover_kyber_like_secret(zero_matrix, ((0, 0),), 17, error_bound=0) is None
    assert pq.recover_kyber_like_secret((((1, 2, 3),),), ((0, 0),), 17) is None


def test_dilithium_reused_y_recovers_and_replays_every_signature():
    q = 97
    signatures = [
        ((1, 0), ((4, 94), (96, 5))),
        ((2, 1), ((6, 94), (95, 6))),
        ((1, -1), ((3, 93), (0, 5))),
    ]
    recovered = pq.recover_dilithium_reused_y(
        signatures,
        q,
        secret_bound=1,
        nonce_bound=4,
        rejection_bound=10,
    )
    assert recovered == (((1, -1), (0, 1)), ((3, -2), (-1, 4)))
    secret, nonce = recovered
    for challenge, observed in signatures:
        for index in range(2):
            term = _poly_mul(challenge, secret[index], q, negacyclic=True)
            assert tuple((nonce[index][j] + term[j]) % q for j in range(2)) == observed[index]


def test_dilithium_reused_y_declines_singular_ambiguous_challenges():
    signature = ((1, 0), ((4, 94), (96, 5)))
    assert (
        pq.recover_dilithium_reused_y(
            [signature, signature],
            97,
            secret_bound=1,
            nonce_bound=4,
            rejection_bound=10,
        )
        is None
    )


def test_dilithium_singular_difference_uses_bounded_unique_fallback():
    # c1-c2 is zero, but |s|,|y| <= 1 makes y+2s=0 (mod 5) uniquely s=y=0.
    recovered = pq.recover_dilithium_reused_y(
        [((2,), ((0,),)), ((2,), ((0,),))],
        5,
        secret_bound=1,
        nonce_bound=1,
        rejection_bound=1,
    )
    assert recovered == (((0,),), ((0,),))


def test_dilithium_reused_y_sympy_runs_only_at_unique_emission_gate(monkeypatch):
    signatures = [
        ((1, 0), ((4, 94), (96, 5))),
        ((2, 1), ((6, 94), (95, 6))),
        ((1, -1), ((3, 93), (0, 5))),
    ]
    original = pq._sympy_poly_mul
    calls = []

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(pq, "_sympy_poly_mul", counted)
    recovered = pq.recover_dilithium_reused_y(
        signatures,
        97,
        secret_bound=1,
        nonce_bound=4,
        rejection_bound=10,
    )
    assert recovered == (((1, -1), (0, 1)), ((3, -2), (-1, 4)))
    # Three signatures times two secret polynomials: exactly one final proof pass.
    assert len(calls) == 6


def test_dilithium_rejection_leak_uniquely_recovers_and_replays_outcomes():
    nonce = ((-4, -1),)
    challenges = [(1, 2), (-2, 5), (1, -2), (2, -2)]
    accepted = (True, False, False, False)
    secret = pq.recover_dilithium_rejection_secret(
        nonce,
        challenges,
        accepted,
        17,
        rejection_bound=1,
    )
    assert secret == ((1, -1),)
    replay = []
    for challenge in challenges:
        term = _poly_mul(challenge, secret[0], 17, negacyclic=True)
        z = tuple((nonce[0][i] + term[i]) % 17 for i in range(2))
        centered = [value - 17 if value > 8 else value for value in z]
        replay.append(max(map(abs, centered)) <= 1)
    assert tuple(replay) == accepted


def test_dilithium_rejection_leak_declines_ambiguous_observations():
    assert (
        pq.recover_dilithium_rejection_secret(
            ((0, 0),),
            [(0, 0), (0, 0)],
            [True, True],
            17,
            rejection_bound=1,
        )
        is None
    )


def test_adversarial_input_caps_and_exact_integer_gate():
    assert pq.recover_lwe_secret(repeat([1]), [0], 17) is None
    assert pq.audit_lwe_parameters(repeat([1]), 17, 1, 1) is None
    assert pq.recover_ntru_private_key([1.0, 2, 3], 3, 17) is None
    assert pq.recover_ntru_message([0, 0], [0, 0.5], 17) is None
    assert pq.recover_kyber_like_secret(((repeat(1),),), ((0, 0),), 17) is None
    assert (
        pq.recover_dilithium_reused_y(
            repeat(((1, 0), ((0, 0),))),
            17,
            secret_bound=1,
            nonce_bound=1,
            rejection_bound=1,
        )
        is None
    )
    assert (
        pq.recover_dilithium_rejection_secret(
            ((0, 0),), repeat((1, 0)), repeat(True), 17, rejection_bound=1
        )
        is None
    )
    # Huge declared noise is classified without constructing a gigantic range.
    huge = pq.audit_kyber_like_parameters(1, 2, 17, 10**100)
    assert huge is not None and not huge.toy_attackable


def test_dilithium_corruption_and_observed_z_proof_gates():
    signatures = [
        ((1, 0), ((4, 94), (96, 5))),
        ((2, 1), ((6, 94), (95, 6))),
        ((1, -1), ((3, 93), (0, 6))),  # one corrupted coefficient
    ]
    assert (
        pq.recover_dilithium_reused_y(
            signatures,
            97,
            secret_bound=1,
            nonce_bound=4,
            rejection_bound=10,
        )
        is None
    )


def test_exhaustive_tiny_recoveries_match_independent_unique_witness_oracles():
    values = (-1, 0, 1)
    q = 5

    # Scalar LWE and its one-polynomial Kyber-like embedding.
    for a, b, bound in product(range(q), range(q), (0, 1)):
        fits = [s for s in values if abs(_center(b - a * s, q)) <= bound]
        expected_lwe = (fits[0],) if len(fits) == 1 else None
        expected_kyber = ((fits[0],),) if len(fits) == 1 else None
        assert pq.recover_lwe_secret([[a]], [b], q, error_bound=bound) == expected_lwe
        assert (
            pq.recover_kyber_like_secret(((((a,),),)), ((b,),), q, error_bound=bound)
            == expected_kyber
        )

    # Every public h for degree-2 NTRU key recovery.
    p = 2
    for h in product(range(q), repeat=2):
        witnesses = []
        for small_f in product(values, repeat=2):
            f = (1 + p * small_f[0], p * small_f[1])
            inverse = _brute_poly_inverse(tuple(value % q for value in f), q)
            if inverse is None:
                continue
            for g in product(values, repeat=2):
                if any(g) and _poly_mul(
                    tuple(p * value % q for value in g), inverse, q, negacyclic=False
                ) == h:
                    witnesses.append((f, g))
        expected = witnesses[0] if len(witnesses) == 1 else None
        assert pq.recover_ntru_private_key(h, p, q) == expected

    # Every degree-2 NTRU public polynomial/ciphertext pair.
    for h in product(range(q), repeat=2):
        for ciphertext in product(range(q), repeat=2):
            witnesses = []
            for blinding in product(values, repeat=2):
                rh = _poly_mul(blinding, h, q, negacyclic=False)
                message = tuple(_center(ciphertext[i] - rh[i], q) for i in range(2))
                if all(value in values for value in message):
                    witnesses.append((blinding, message))
            expected = witnesses[0][1] if len(witnesses) == 1 else None
            assert pq.recover_ntru_message(ciphertext, h, q) == expected

    # All two-signature scalar reused-y observations.
    for c1, c2, z1, z2 in product(range(q), repeat=4):
        witnesses = []
        for secret, nonce in product(values, repeat=2):
            if (
                abs(_center(z1, q)) <= 1
                and abs(_center(z2, q)) <= 1
                and (nonce + c1 * secret - z1) % q == 0
                and (nonce + c2 * secret - z2) % q == 0
            ):
                witnesses.append((((secret,),), ((nonce,),)))
        expected = witnesses[0] if len(witnesses) == 1 else None
        signatures = [((c1,), ((z1,),)), ((c2,), ((z2,),))]
        assert (
            pq.recover_dilithium_reused_y(
                signatures,
                q,
                secret_bound=1,
                nonce_bound=1,
                rejection_bound=1,
            )
            == expected
        )

    # All known-y, two-challenge scalar rejection transcripts.
    for nonce, c1, c2, first, second in product(
        range(q), range(q), range(q), (False, True), (False, True)
    ):
        fits = [
            secret
            for secret in values
            if tuple(
                abs(_center(nonce + challenge * secret, q)) <= 1
                for challenge in (c1, c2)
            )
            == (first, second)
        ]
        expected = ((fits[0],),) if len(fits) == 1 else None
        assert (
            pq.recover_dilithium_rejection_secret(
                ((nonce,),),
                [(c1,), (c2,)],
                [first, second],
                q,
                rejection_bound=1,
            )
            == expected
        )


def test_canonical_parameter_reports_and_attack_caps_never_claim_success():
    identity = [[int(i == j) for j in range(256)] for i in range(256)]
    lwe = pq.audit_lwe_parameters(identity, 3329, 2, 1)
    ntru = pq.audit_ntru_parameters(509, 2048, 3, 2)
    kyber = pq.audit_kyber_like_parameters(2, 256, 3329, 2, flattened_matrix_rank=512)
    dilithium = pq.audit_dilithium_like_parameters(4, 256, 8380417, 2, 1 << 17)
    assert all(not audit.toy_attackable for audit in (lwe, ntru, kyber, dilithium))
    assert lwe.findings == () and kyber.findings == () and dilithium.findings == ()
    assert {item.code for item in ntru.findings} == {"nonprime_modulus"}

    assert pq.recover_ntru_private_key([0] * 509, 3, 2048) is None
    production_poly = tuple([0] * 256)
    assert pq.recover_kyber_like_secret(((production_poly,),), (production_poly,), 3329) is None
    production_signature = (production_poly, (production_poly,))
    assert (
        pq.recover_dilithium_reused_y(
            [production_signature, production_signature],
            8380417,
            secret_bound=2,
            nonce_bound=1 << 17,
            rejection_bound=1 << 17,
        )
        is None
    )


def test_degenerate_modulus_dimension_and_noise_decline_cleanly():
    assert pq.recover_lwe_secret([], [], 17) is None
    assert pq.recover_lwe_secret([[1]], [1], 4) is None
    assert pq.recover_lwe_secret([[1]], [1], 5, error_bound=3) is None
    assert pq.recover_ntru_private_key((1,), 2, 4) is None
    assert pq.recover_ntru_message((0,), (0,), 4) is None
    assert pq.recover_kyber_like_secret(((((1,),),)), ((1,),), 4) is None
    assert pq.audit_kyber_like_parameters(1, 2, 4, 2).toy_attackable is False
    assert pq.audit_dilithium_like_parameters(1, 2, 5, 3, 1).toy_attackable is False


def test_malformed_nested_and_failing_generator_inputs_decline():
    def broken():
        yield [1]
        raise RuntimeError("truncated artifact")

    assert pq.audit_lwe_parameters([[1, 2], [3]], 17, 1, 1) is None
    assert pq.recover_lwe_secret([[1, 2], [3]], [1, 2], 17) is None
    assert pq.recover_lwe_secret(broken(), [1], 17) is None
    assert pq.recover_ntru_message((1, 2), (1,), 17) is None
    assert pq.recover_kyber_like_secret((((1, 2),), ((3, 4),)), ((1, 2),), 17) is None
    assert (
        pq.recover_dilithium_reused_y(
            [((1, 0), ((1, 2),)), ((2,), ((1, 2),))],
            17,
            secret_bound=1,
            nonce_bound=1,
            rejection_bound=2,
        )
        is None
    )
    assert (
        pq.recover_dilithium_rejection_secret(
            ((0, 0),),
            [(1, 0), (0, 1)],
            [True, False],
            17,
            rejection_bound=1,
            observed_z=[((1,),), None],
        )
        is None
    )

    nonce = ((-4, -1),)
    challenges = [(1, 2), (-2, 5), (1, -2), (2, -2)]
    accepted = (True, False, False, False)
    observed = [((16, 0),), None, None, None]
    assert (
        pq.recover_dilithium_rejection_secret(
            nonce,
            challenges,
            accepted,
            17,
            rejection_bound=1,
            observed_z=observed,
        )
        == ((1, -1),)
    )
    observed[0] = ((15, 0),)
    assert (
        pq.recover_dilithium_rejection_secret(
            nonce,
            challenges,
            accepted,
            17,
            rejection_bound=1,
            observed_z=observed,
        )
        is None
    )
    assert (
        pq.recover_dilithium_rejection_secret(
            nonce, challenges, [1, 0, 0, 0], 17, rejection_bound=1
        )
        is None
    )
