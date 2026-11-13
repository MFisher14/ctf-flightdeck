"""Deterministic coverage for the r5c verified lattice/nonce attack lane."""

from __future__ import annotations

import random
import sys
from itertools import repeat
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))

import crypto_depth as depth  # noqa: E402
import lattice_nonce as attacks  # noqa: E402


def test_verified_lll_and_dependent_ambiguity_decline():
    basis = [[1, 1, 1], [-1, 0, 2], [3, 5, 6]]
    reduced = attacks.reduce_lll_verified(basis)
    assert reduced is not None
    assert len(reduced) == len(basis)
    # A dependent input is not a basis: no potentially ambiguous reduction is emitted.
    assert attacks.reduce_lll_verified([[1, 2], [2, 4]]) is None


def test_verified_bkz_harness_and_dependent_ambiguity_decline():
    basis = [[12, 2, 3, 4], [5, 17, 1, 2], [8, 3, 19, 1], [4, 7, 2, 23]]
    reduced = attacks.reduce_bkz_verified(basis, block_size=3, tours=3)
    assert reduced is not None
    assert len(reduced) == len(basis)
    assert attacks.reduce_bkz_verified([[1, 2], [2, 4]], block_size=2) is None


def test_lattice_adversarial_rectangular_truncation_and_input_caps():
    rectangular = [[1, 0, 1], [0, 1, 1]]
    assert attacks.reduce_lll_verified(rectangular) is not None
    hard = [[105, 821, 404], [281, 33, 17], [9, 77, 901]]
    # The exact reducer may return a partial basis at its step cap; the proof gate rejects it.
    assert attacks.reduce_lll_verified(hard, max_steps=1, cross_check=False) is None
    assert attacks.reduce_lll_verified(hard, max_steps=True) is None
    # Bounded materialisation declines infinite/oversized outer and inner iterables.
    assert attacks.reduce_lll_verified(repeat([1, 0])) is None
    assert attacks.reduce_lll_verified([repeat(1)]) is None
    assert attacks.reduce_bkz_verified(rectangular, block_size=True) is None


def test_generic_hidden_number_recovery_and_ambiguous_decline():
    q, secret, bound = 1009, 123, 16
    nonces = (3, 5, 7, 11)
    multipliers = (11, 17, 19, 23)
    samples = [(t, (k - t * secret) % q) for t, k in zip(multipliers, nonces)]
    assert attacks.hidden_number_recover(q, samples, bound, lambda d: d == secret) == secret
    # With no public/problem verifier to distinguish the many fitting values, decline.
    assert attacks.hidden_number_recover(101, [(1, 0), (2, 0)], 100, lambda _d: True) is None


def test_hidden_number_emission_rechecks_verifier_and_handles_exceptions():
    q, secret, bound = 1009, 123, 16
    samples = [(t, (k - t * secret) % q) for t, k in ((11, 3), (17, 5), (19, 7), (23, 11))]
    calls = {}

    def first_call_only(candidate):
        calls[candidate] = calls.get(candidate, 0) + 1
        return calls[candidate] == 1

    assert attacks.hidden_number_recover(q, samples, bound, first_call_only) is None

    def broken_verifier(_candidate):
        raise RuntimeError("no proof")

    assert attacks.hidden_number_recover(q, samples, bound, broken_verifier) is None
    assert attacks.hidden_number_recover(q, samples, True, lambda _d: True) is None
    assert attacks.hidden_number_recover(q, [(11.5, 3), (17, 5)], bound, lambda _d: True) is None


CURVE = "secp256k1"
CV = depth.CURVES[CURVE]
ECDSA_SECRET = 0x123456789ABCDEF
ECDSA_PUBLIC = depth.ec_mul(ECDSA_SECRET, CV)


def _ecdsa_signature(nonce: int, digest: int):
    r = depth.ec_mul(nonce, CV)[0] % CV["n"]
    s = pow(nonce, -1, CV["n"]) * (digest + r * ECDSA_SECRET) % CV["n"]
    return r, s, digest


def test_generic_hidden_number_large_lattice_path():
    rng = random.Random(0x5151)
    samples = []
    for _ in range(8):
        nonce = rng.getrandbits(128) or 1
        r, s, z = _ecdsa_signature(nonce, rng.randrange(1, CV["n"]))
        inverse = pow(s, -1, CV["n"])
        samples.append((r * inverse % CV["n"], z * inverse % CV["n"]))
    assert (
        attacks.hidden_number_recover(
            CV["n"], samples, 1 << 128, lambda candidate: candidate == ECDSA_SECRET
        )
        == ECDSA_SECRET
    )


def test_ecdsa_repeated_nonce_recovery_and_ambiguous_decline():
    signatures = [_ecdsa_signature(1234567, 0x1111), _ecdsa_signature(1234567, 0x2222)]
    signatures.append(_ecdsa_signature(7654321, 0x3333))
    assert attacks.ecdsa_repeated_nonce_recover(CURVE, ECDSA_PUBLIC, signatures) == ECDSA_SECRET
    # Without Q, algebra may yield a number but there is no original-key proof.
    assert attacks.ecdsa_repeated_nonce_recover(CURVE, None, signatures) is None


def test_ecdsa_low_nonce_recovery_and_ambiguous_decline():
    signature = _ecdsa_signature(37, 0xA55A)
    assert attacks.ecdsa_low_nonce_recover(CURVE, ECDSA_PUBLIC, signature, 64) == ECDSA_SECRET
    assert attacks.ecdsa_low_nonce_recover(CURVE, None, signature, 64) is None


def test_ecdsa_partial_nonce_high_and_low_bits_and_ambiguous_decline():
    nonces = (0x1235A, 0x234A7)
    signatures = [_ecdsa_signature(nonces[0], 0xAAAA), _ecdsa_signature(nonces[1], 0xBBBB)]
    highs = [nonce >> 8 for nonce in nonces]
    assert (
        attacks.ecdsa_partial_nonce_recover(
            CURVE, ECDSA_PUBLIC, signatures, highs, 8, known_position="high"
        )
        == ECDSA_SECRET
    )
    lows = [nonce & 0xFF for nonce in nonces]
    # Here the unknown high part is 10 bits wide for both chosen nonces.
    assert (
        attacks.ecdsa_partial_nonce_recover(
            CURVE,
            ECDSA_PUBLIC,
            signatures,
            lows,
            10,
            known_position="low",
            known_bits=8,
        )
        == ECDSA_SECRET
    )
    assert attacks.ecdsa_partial_nonce_recover(CURVE, None, signatures, highs, 8) is None


def test_ecdsa_hnp_short_nonce_recovery_and_ambiguous_decline():
    rng = random.Random(0xC5C7F)
    signatures = []
    for _ in range(8):
        nonce = rng.getrandbits(128) or 1
        digest = rng.randrange(1, CV["n"])
        signatures.append(_ecdsa_signature(nonce, digest))
    assert attacks.ecdsa_hnp_recover(CURVE, ECDSA_PUBLIC, signatures, 128) == ECDSA_SECRET
    assert attacks.ecdsa_hnp_recover(CURVE, None, signatures, 128) is None


def test_ecdsa_routing_spellings_preserve_success_and_ambiguity_decline():
    repeated = [_ecdsa_signature(424242, 0x1010), _ecdsa_signature(424242, 0x2020)]
    assert attacks.ecdsa_nonce_reuse_recover(CURVE, ECDSA_PUBLIC, repeated) == ECDSA_SECRET
    assert attacks.ecdsa_nonce_reuse_recover(CURVE, None, repeated) is None

    rng = random.Random(0xB1A5)
    biased = [
        _ecdsa_signature(rng.getrandbits(128) or 1, rng.randrange(1, CV["n"]))
        for _ in range(8)
    ]
    assert attacks.ecdsa_nonce_bias_recover(CURVE, ECDSA_PUBLIC, biased, 128) == ECDSA_SECRET
    assert attacks.ecdsa_nonce_bias_recover(CURVE, None, biased, 128) is None


def test_ecdsa_adversarial_proof_gate_and_leak_bounds():
    repeated = [_ecdsa_signature(31337, 0x1234), _ecdsa_signature(31337, 0x5678)]
    off_curve = (ECDSA_PUBLIC[0], (ECDSA_PUBLIC[1] + 1) % CV["p"])
    assert attacks.ecdsa_repeated_nonce_recover(CURVE, off_curve, repeated) is None
    r, s, z = repeated[0]
    corrupted = [(r, (s + 1) % CV["n"] or 1, z), repeated[1]]
    assert attacks.ecdsa_repeated_nonce_recover(CURVE, ECDSA_PUBLIC, corrupted) is None
    rounded = [(float(r), s, z), repeated[1]]
    assert attacks.ecdsa_repeated_nonce_recover(CURVE, ECDSA_PUBLIC, rounded) is None
    malformed_curve = dict(CV)
    malformed_curve["n"] -= 1
    assert attacks.ecdsa_low_nonce_recover(malformed_curve, ECDSA_PUBLIC, _ecdsa_signature(7, 9), 8) is None
    # A fully validated custom dictionary for the supported curve remains usable.
    assert (
        attacks.ecdsa_low_nonce_recover(dict(CV), ECDSA_PUBLIC, _ecdsa_signature(7, 9), 8)
        == ECDSA_SECRET
    )
    assert attacks.ecdsa_low_nonce_recover(CURVE, ECDSA_PUBLIC, _ecdsa_signature(7, 9), (1 << 20) + 1) is None
    assert (
        attacks.ecdsa_partial_nonce_recover(
            CURVE, ECDSA_PUBLIC, [_ecdsa_signature(7, 9)], [0], 21
        )
        is None
    )
    assert (
        attacks.ecdsa_partial_nonce_recover(
            CURVE,
            ECDSA_PUBLIC,
            [_ecdsa_signature(7, 9)],
            [256],
            1,
            known_position="low",
            known_bits=8,
        )
        is None
    )
    assert attacks.ecdsa_hnp_recover(CURVE, ECDSA_PUBLIC, repeated, True) is None


DSA_P = 607
DSA_Q = 101
DSA_G = 64
DSA_SECRET = 37
DSA_PUBLIC = pow(DSA_G, DSA_SECRET, DSA_P)


def _dsa_signature(nonce: int, digest: int):
    r = pow(DSA_G, nonce, DSA_P) % DSA_Q
    s = pow(nonce, -1, DSA_Q) * (digest + DSA_SECRET * r) % DSA_Q
    assert r and s
    return r, s, digest


def test_dsa_repeated_nonce_recovery_and_ambiguous_decline():
    signatures = [_dsa_signature(19, 12), _dsa_signature(19, 45), _dsa_signature(23, 61)]
    assert (
        attacks.dsa_repeated_nonce_recover(
            DSA_P, DSA_Q, DSA_G, DSA_PUBLIC, signatures
        )
        == DSA_SECRET
    )
    assert attacks.dsa_repeated_nonce_recover(DSA_P, DSA_Q, DSA_G, None, signatures) is None


def test_dsa_low_nonce_recovery_and_ambiguous_decline():
    signature = _dsa_signature(7, 28)
    assert attacks.dsa_low_nonce_recover(DSA_P, DSA_Q, DSA_G, DSA_PUBLIC, signature, 12) == DSA_SECRET
    assert attacks.dsa_low_nonce_recover(DSA_P, DSA_Q, DSA_G, None, signature, 12) is None


def test_dsa_partial_nonce_high_and_low_bits_and_ambiguous_decline():
    nonces = (13, 14)
    signatures = [_dsa_signature(13, 17), _dsa_signature(14, 39)]
    highs = [nonce >> 2 for nonce in nonces]
    assert (
        attacks.dsa_partial_nonce_recover(
            DSA_P, DSA_Q, DSA_G, DSA_PUBLIC, signatures, highs, 2
        )
        == DSA_SECRET
    )
    lows = [nonce & 3 for nonce in nonces]
    assert (
        attacks.dsa_partial_nonce_recover(
            DSA_P,
            DSA_Q,
            DSA_G,
            DSA_PUBLIC,
            signatures,
            lows,
            2,
            known_position="low",
            known_bits=2,
        )
        == DSA_SECRET
    )
    assert (
        attacks.dsa_partial_nonce_recover(
            DSA_P, DSA_Q, DSA_G, None, signatures, highs, 2
        )
        is None
    )


def test_dsa_hnp_nonce_bias_recovery_and_ambiguous_decline():
    signatures = [_dsa_signature(k, z) for k, z in ((3, 9), (5, 21), (7, 44), (11, 72))]
    assert (
        attacks.dsa_hnp_recover(DSA_P, DSA_Q, DSA_G, DSA_PUBLIC, signatures, 4)
        == DSA_SECRET
    )
    assert attacks.dsa_hnp_recover(DSA_P, DSA_Q, DSA_G, None, signatures, 4) is None


def test_dsa_routing_spellings_preserve_success_and_ambiguity_decline():
    repeated = [_dsa_signature(19, 13), _dsa_signature(19, 47)]
    assert (
        attacks.dsa_nonce_reuse_recover(
            DSA_P, DSA_Q, DSA_G, DSA_PUBLIC, repeated
        )
        == DSA_SECRET
    )
    assert attacks.dsa_nonce_reuse_recover(DSA_P, DSA_Q, DSA_G, None, repeated) is None

    biased = [_dsa_signature(k, z) for k, z in ((3, 8), (5, 20), (7, 41), (11, 73))]
    assert (
        attacks.dsa_nonce_bias_recover(
            DSA_P, DSA_Q, DSA_G, DSA_PUBLIC, biased, 4
        )
        == DSA_SECRET
    )
    assert attacks.dsa_nonce_bias_recover(DSA_P, DSA_Q, DSA_G, None, biased, 4) is None


def test_dsa_adversarial_proof_gate_and_leak_bounds():
    repeated = [_dsa_signature(19, 11), _dsa_signature(19, 42)]
    wrong_public = pow(DSA_G, DSA_SECRET + 1, DSA_P)
    assert (
        attacks.dsa_repeated_nonce_recover(
            DSA_P, DSA_Q, DSA_G, wrong_public, repeated
        )
        is None
    )
    r, s, z = repeated[0]
    corrupted = [(r, (s + 1) % DSA_Q or 1, z), repeated[1]]
    assert (
        attacks.dsa_repeated_nonce_recover(
            DSA_P, DSA_Q, DSA_G, DSA_PUBLIC, corrupted
        )
        is None
    )
    rounded = [(float(r), s, z), repeated[1]]
    assert (
        attacks.dsa_repeated_nonce_recover(
            DSA_P, DSA_Q, DSA_G, DSA_PUBLIC, rounded
        )
        is None
    )
    assert (
        attacks.dsa_low_nonce_recover(
            DSA_P, DSA_Q, DSA_G, DSA_PUBLIC, _dsa_signature(7, 9), (1 << 20) + 1
        )
        is None
    )
    assert (
        attacks.dsa_partial_nonce_recover(
            DSA_P, DSA_Q, DSA_G, DSA_PUBLIC, [_dsa_signature(7, 9)], [0], 21
        )
        is None
    )
    assert (
        attacks.dsa_partial_nonce_recover(
            DSA_P,
            DSA_Q,
            DSA_G,
            DSA_PUBLIC,
            [_dsa_signature(7, 9)],
            [4],
            1,
            known_position="low",
            known_bits=2,
        )
        is None
    )
    assert attacks.dsa_hnp_recover(DSA_P, DSA_Q, DSA_G, DSA_PUBLIC, repeated, True) is None
