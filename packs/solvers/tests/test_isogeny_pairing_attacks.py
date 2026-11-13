"""Deterministic toy-parameter tests for phase-3 isogeny/pairing attacks."""

from __future__ import annotations

import importlib
import itertools
from pathlib import Path
import random
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "common"))

import isogeny_pairing_attacks as attacks  # noqa: E402


def test_package_style_import_uses_phase2_relative_dependency():
    original_path = list(sys.path)
    sys.modules.pop("solvers.common.isogeny_pairing_attacks", None)
    try:
        common = (REPO / "solvers" / "common").resolve()
        sys.path[:] = [
            entry for entry in sys.path if not entry or Path(entry).resolve() != common
        ]
        packaged = importlib.import_module(
            "solvers.common.isogeny_pairing_attacks"
        )
        assert packaged._special.__name__ == "solvers.common.special_curves"
        additive = packaged.GroupOps(
            0,
            lambda left, right: (left + right) % 11,
            lambda value: (-value) % 11,
        )
        target = packaged.GroupOps(
            1,
            lambda left, right: left * right % 23,
            lambda value: pow(value, -1, 23),
        )
        context = packaged.BilinearContext(
            11,
            1,
            1,
            additive,
            additive,
            target,
            lambda left, right: pow(2, left * right % 11, 23),
        )
        assert packaged.audit_bilinear_context(context) is not None
    finally:
        sys.path[:] = original_path


def _additive_group(modulus: int):
    return attacks.GroupOps(
        0,
        lambda left, right: (left + right) % modulus,
        lambda value: (-value) % modulus,
    )


def _product_group(moduli):
    moduli = tuple(moduli)
    identity = (0,) * len(moduli)
    return attacks.GroupOps(
        identity,
        lambda left, right: tuple(
            (x + y) % modulus
            for x, y, modulus in zip(left, right, moduli)
        ),
        lambda value: tuple(
            (-x) % modulus for x, modulus in zip(value, moduli)
        ),
    )


def _bilinear_context(order: int = 11):
    g1 = _additive_group(order)
    g2 = _additive_group(order)
    # 2 has exact order 11 modulo 23.
    target = attacks.GroupOps(
        1,
        lambda left, right: left * right % 23,
        lambda value: pow(value, -1, 23),
    )
    return attacks.BilinearContext(
        order,
        1,
        1,
        g1,
        g2,
        target,
        lambda left, right: pow(2, left * right % order, 23),
    )


def test_torsion_basis_exact_order_independence_and_dependent_decline():
    group = _product_group((5, 5))
    audit = attacks.audit_torsion_basis((1, 0), (0, 1), 5, group)
    assert audit == attacks.TorsionBasisAudit(5, 25, False, True)
    assert attacks.audit_torsion_basis((1, 0), (2, 0), 5, group) is None
    assert attacks.audit_torsion_basis((1, 0), (0, 1), 25, group) is None

    # The basis is established directly and the supplied pairing is then
    # exhaustively checked on both cyclic axes.
    target = attacks.GroupOps(
        1,
        lambda left, right: left * right % 11,
        lambda value: pow(value, -1, 11),
    )
    pairing = lambda left, right: pow(
        4, (left[0] * right[1] - left[1] * right[0]) % 5, 11
    )
    paired = attacks.audit_torsion_basis(
        (1, 0),
        (0, 1),
        5,
        group,
        pairing=pairing,
        target_group=target,
        max_enumeration=25,
    )
    assert paired == attacks.TorsionBasisAudit(5, 25, True, True)

    # Injective fixed-order words are not a direct product without
    # commutativity: two transpositions generate non-abelian S3.
    def compose(left, right):
        return tuple(left[right[index]] for index in range(3))

    def inverse(value):
        result = [0, 0, 0]
        for index, image in enumerate(value):
            result[image] = index
        return tuple(result)

    symmetric = attacks.GroupOps((0, 1, 2), compose, inverse)
    assert attacks.audit_torsion_basis(
        (1, 0, 2), (0, 2, 1), 2, symmetric
    ) is None

    # A sampled fake pairing used to hide Q=4P because scalar 4 was never
    # queried.  Complete direct-product enumeration must reject it first.
    cyclic = _additive_group(5)
    fake_table = {
        (1, 1): 1,
        (4, 4): 1,
        (1, 4): 4,
        (4, 1): 3,
        (2, 4): 5,
        (3, 4): 9,
    }
    assert attacks.audit_torsion_basis(
        1,
        4,
        5,
        cyclic,
        pairing=lambda left, right: fake_table.get((left, right), 1),
        target_group=target,
        max_enumeration=25,
    ) is None


def test_sidh_public_transcript_kernel_basis_and_map_validation():
    domain = _product_group((3, 5, 5))
    codomain = _product_group((5, 5))
    kernel = (1, 0, 0)
    basis = ((0, 1, 0), (0, 0, 1))
    images = ((1, 0), (0, 1))
    point_map = lambda point: (point[1], point[2])
    samples = (
        ((0, 1, 2), (1, 2, 3)),
        ((2, 4, 1), (0, 3, 2)),
        ((1, 2, 4), (2, 1, 3)),
    )
    audit = attacks.audit_sidh_public_transcript(
        3, kernel, basis, images, 5, domain, codomain, point_map, samples
    )
    assert audit == attacks.SIDHPublicTranscriptAudit(3, 5, 3, True)

    wrong_images = ((1, 0), (1, 0))
    assert attacks.audit_sidh_public_transcript(
        3, kernel, basis, wrong_images, 5, domain, codomain, point_map, samples
    ) is None
    assert attacks.audit_sidh_public_transcript(
        5, kernel, basis, images, 5, domain, codomain, point_map, samples
    ) is None
    assert attacks.audit_sidh_public_transcript(
        3, kernel, basis, images, "5", domain, codomain, point_map, samples
    ) is None

    sike = attacks.audit_sike_public_kem_structure(
        3,
        kernel,
        basis,
        images,
        5,
        domain,
        codomain,
        point_map,
        samples,
        ((1, 2), (3, 4)),
        lambda component: isinstance(component, tuple) and len(component) == 2,
        b"SIKE-toy-KEM-v1",
    )
    assert sike == attacks.SIKEPublicKEMAudit(
        audit, 2, b"SIKE-toy-KEM-v1", True, True
    )
    assert attacks.audit_sike_public_kem_structure(
        3,
        kernel,
        basis,
        images,
        5,
        domain,
        codomain,
        point_map,
        samples,
        ((1, 2), "bad"),
        lambda component: isinstance(component, tuple),
        b"SIKE-toy-KEM-v1",
    ) is None


def _leak_observation(secret: int, modulus: int):
    group = _additive_group(modulus)
    return attacks.AuxiliaryLeakObservation(
        modulus,
        1,
        group,
        secret % modulus,
        lambda candidate, auxiliary, mod=modulus: candidate * auxiliary % mod,
    )


def test_invalid_isogeny_auxiliary_leaks_crt_and_public_replay():
    secret = 13
    rows = (_leak_observation(secret, 3), _leak_observation(secret, 5))
    assert attacks.recover_invalid_isogeny_auxiliary_secret(
        rows, 17, secret, lambda candidate: candidate
    ) == secret

    assert attacks.recover_invalid_isogeny_auxiliary_secret(
        rows[:1], 17, secret, lambda candidate: candidate, max_candidates=1
    ) is None
    assert attacks.recover_invalid_isogeny_auxiliary_secret(
        rows, 17, secret + 1, lambda candidate: candidate
    ) is None

    # Residue 1 mod 3 leaves witnesses 1 and 4 below 7; a colliding public
    # action cannot disambiguate them and therefore must decline.
    assert attacks.recover_invalid_isogeny_auxiliary_secret(
        (_leak_observation(4, 3),), 7, 0, lambda _candidate: 0
    ) is None


def test_unique_small_isogeny_path_requires_graph_and_public_replay():
    graph = {
        "A": (("B", 2, "A-B"),),
        "B": (("D", 3, "B-D"),),
        "D": (),
    }
    edge = lambda left, right, degree, proof: (
        proof == f"{left}-{right}" and degree in (2, 3)
    )
    replay = lambda nodes, degrees: (nodes[-1], tuple(degrees))
    result = attacks.recover_unique_isogeny_secret_path(
        "A",
        "D",
        lambda node: graph[node],
        edge,
        replay,
        ("D", (2, 3)),
    )
    assert result == attacks.IsogenyPath(("A", "B", "D"), (2, 3), 6, True)
    assert attacks.recover_unique_isogeny_secret_path(
        "A", "D", lambda node: graph[node], edge, replay, ("D", (2, 5))
    ) is None

    ambiguous = {
        "A": (("B", 2, "A-B"), ("C", 2, "A-C")),
        "B": (("D", 3, "B-D"),),
        "C": (("D", 3, "C-D"),),
        "D": (),
    }
    assert attacks.recover_unique_isogeny_secret_path(
        "A",
        "D",
        lambda node: ambiguous[node],
        edge,
        replay,
        ("D", (2, 3)),
    ) is None

    # Uniqueness is over every simple path within max_depth, not merely the
    # shortest layer of the graph.
    different_depths = {
        "A": (("B", 2, "A-B"), ("C", 2, "A-C")),
        "B": (("D", 3, "B-D"),),
        "C": (("E", 2, "C-E"),),
        "E": (("D", 2, "E-D"),),
        "D": (),
    }
    assert attacks.recover_unique_isogeny_secret_path(
        "A",
        "D",
        lambda node: different_depths[node],
        edge,
        lambda _nodes, _degrees: "same-public",
        "same-public",
        max_depth=3,
    ) is None

    # A cycle-containing bounded walk is also a candidate explanation unless
    # the original problem supplies an admissibility rule.  The helper has no
    # such rule, so it must not silently restrict recovery to simple paths.
    cyclic = {
        "A": (("C", 2, "A-C"), ("B", 2, "A-B")),
        "B": (("A", 2, "B-A"),),
        "C": (("D", 3, "C-D"),),
        "D": (),
    }
    assert attacks.recover_unique_isogeny_secret_path(
        "A",
        "D",
        lambda node: cyclic[node],
        edge,
        lambda _nodes, _degrees: "same-public",
        "same-public",
        max_depth=4,
    ) is None

    target_cycle = {
        "A": (("D", 2, "A-D"),),
        "D": (("E", 2, "D-E"),),
        "E": (("D", 2, "E-D"),),
    }
    assert attacks.recover_unique_isogeny_secret_path(
        "A",
        "D",
        lambda node: target_cycle[node],
        edge,
        lambda _nodes, _degrees: "same-public",
        "same-public",
        max_depth=3,
    ) is None


def test_csidh_action_audit_and_unique_small_exponent_vector():
    weights = (1, 10)
    apply_action = lambda state, index, direction: (
        state + direction * weights[index]
    ) % 101
    audit = attacks.audit_csidh_toy_action(
        0, (3, 5), (1, 1), apply_action
    )
    assert audit == attacks.CSIDHActionAudit(2, 9, 36, 36, True)
    secret = (1, -1)
    public = (secret[0] * weights[0] + secret[1] * weights[1]) % 101
    assert attacks.recover_csidh_small_exponent_vector(
        0, public, (3, 5), (1, 1), apply_action
    ) == secret

    ambiguous_action = lambda state, _index, direction: (state + direction) % 101
    assert attacks.recover_csidh_small_exponent_vector(
        0, 0, (3, 5), (1, 1), ambiguous_action
    ) is None
    noncommutative = lambda state, index, direction: (
        state + direction if index == 0 else state * (2 if direction > 0 else 51)
    ) % 101
    assert attacks.audit_csidh_toy_action(
        1, (3, 5), (1, 1), noncommutative
    ) is None

    # Base-only inverse checks used to miss a broken second step and recovery
    # emitted (2,) even though the inverse transcript did not return to base.
    def malformed_action(state, _index, direction):
        transitions = {
            (0, 1): 1,
            (1, -1): 0,
            (0, -1): -1,
            (-1, 1): 0,
            (1, 1): 99,
            (99, -1): 77,
            (-1, -1): -2,
        }
        return transitions.get((state, direction), state + direction)

    assert attacks.audit_csidh_toy_action(
        0, (3,), (2,), malformed_action
    ) is None
    assert attacks.recover_csidh_small_exponent_vector(
        0, 99, (3,), (2,), malformed_action
    ) is None


def test_bilinear_context_equations_ddh_and_unique_scalar():
    context = _bilinear_context()
    sympy = pytest.importorskip("sympy")
    assert sympy.n_order(2, 23) == 11
    audit = attacks.audit_bilinear_context(context)
    assert audit == attacks.BilinearContextAudit(11, 121, True)
    a, b = 3, 4
    assert attacks.bilinear_ddh_check(context, a, b, a * b % 11)
    assert attacks.bilinear_co_ddh_check(context, a, b, a * b % 11)
    assert attacks.verify_co_cdh_candidate(context, a, b, a * b % 11)
    assert not attacks.bilinear_ddh_check(context, a, b, a * b + 1)
    assert attacks.verify_bilinear_equation(
        context, ((3, 4), (2, 5)), ((1, 1), (1, 10))
    )
    assert attacks.recover_unique_pairing_scalar(context, 7, 1) == 7
    assert attacks.recover_unique_pairing_scalar(context, 0, 1) is None

    # The old 1..3 sample accepted this non-bilinear callback and consequently
    # accepted signature 4 for H(m)=2, pk=5 even though the valid scalar is 10.
    fake = attacks.BilinearContext(
        11,
        1,
        1,
        context.g1_group,
        context.g2_group,
        context.target_group,
        lambda left, right: (
            pow(2, 10, 23)
            if (left, right) == (4, 1)
            else pow(2, left * right % 11, 23)
        ),
    )
    assert attacks.audit_bilinear_context(fake) is None
    assert not attacks.verify_bls_signature(
        fake, 4, 5, b"message", lambda _message: 2
    )

    # [q]P=0 is not membership evidence when the ambient q-torsion has rank 2.
    rank_two = _product_group((11, 11))
    degenerate = attacks.BilinearContext(
        11,
        (1, 0),
        (1, 0),
        rank_two,
        rank_two,
        context.target_group,
        lambda left, right: pow(2, left[0] * right[0] % 11, 23),
    )
    assert attacks.audit_bilinear_context(degenerate) is not None
    assert not attacks.verify_bls_signature(
        degenerate,
        (10, 0),
        (5, 7),
        b"message",
        lambda _message: (2, 0),
    )


def _hash_to_g1(message: bytes) -> int:
    return sum(message) % 10 + 1


def test_bls_signatures_aggregate_duplicates_pop_and_rogue_key():
    context = _bilinear_context()
    secrets = (3, 4)
    keys = secrets
    messages = (b"alpha", b"beta")
    signatures = tuple(
        secret * _hash_to_g1(message) % 11
        for secret, message in zip(secrets, messages)
    )
    aggregate = sum(signatures) % 11
    assert all(
        attacks.verify_bls_signature(context, signature, key, message, _hash_to_g1)
        for signature, key, message in zip(signatures, keys, messages)
    )
    audit = attacks.audit_bls_aggregate(
        context, aggregate, keys, messages, _hash_to_g1
    )
    assert audit == attacks.BLSAggregateAudit(2, (), False, False, True)

    duplicate_message = b"same"
    duplicate_signatures = tuple(
        secret * _hash_to_g1(duplicate_message) % 11 for secret in secrets
    )
    duplicate_aggregate = sum(duplicate_signatures) % 11
    duplicate_audit = attacks.audit_bls_aggregate(
        context,
        duplicate_aggregate,
        keys,
        (duplicate_message, duplicate_message),
        _hash_to_g1,
    )
    assert duplicate_audit.duplicate_messages == ((0, 1),)
    assert duplicate_audit.rogue_key_risk is True
    pop_audit = attacks.audit_bls_aggregate(
        context,
        duplicate_aggregate,
        keys,
        (duplicate_message, duplicate_message),
        _hash_to_g1,
        pop_proofs=(b"p1", b"p2"),
        pop_verifier=lambda _key, proof: proof.startswith(b"p"),
    )
    assert pop_audit.proof_of_possession_checked is True
    assert pop_audit.rogue_key_risk is False

    rogue = attacks.build_bls_rogue_key_witness(
        context, 3, 8, duplicate_message, _hash_to_g1
    )
    assert rogue == attacks.BLSRogueKeyWitness(
        5, 8 * _hash_to_g1(duplicate_message) % 11, 8, True
    )
    assert attacks.verify_bls_aggregate_equation(
        context,
        rogue.aggregate_signature,
        (3, rogue.rogue_public_key),
        (duplicate_message, duplicate_message),
        _hash_to_g1,
    )
    assert attacks.audit_bls_aggregate(
        context, aggregate + 1, keys, messages, _hash_to_g1
    ) is None


def test_reused_linear_proof_scalar_recovery_and_inconsistency_decline():
    group = _additive_group(11)
    secret, nonce = 7, 4
    proof1 = attacks.LinearProof(nonce, (nonce + 2 * secret) % 11, 2)
    proof2 = attacks.LinearProof(nonce, (nonce + 5 * secret) % 11, 5)
    assert attacks.recover_reused_linear_proof_scalar(
        proof1, proof2, secret, 1, 11, group
    ) == secret

    same_challenge = attacks.LinearProof(nonce, proof1.response, proof1.challenge)
    assert attacks.recover_reused_linear_proof_scalar(
        proof1, same_challenge, secret, 1, 11, group
    ) is None
    assert attacks.recover_reused_linear_proof_scalar(
        proof1, proof2, secret + 1, 1, 11, group
    ) is None


def _ibe_hash(domain: bytes, identity: bytes) -> int:
    return (sum(domain) + 3 * sum(identity)) % 10 + 1


def test_ibe_structure_domain_separation_ephemeral_reuse_and_message():
    group = _additive_group(11)
    identity, domain = b"alice", b"IBE-v1"
    identity_point = _ibe_hash(domain, identity)
    first = attacks.IBETranscript(identity, domain, identity_point, 6)
    second = attacks.IBETranscript(identity, domain, identity_point, 6)
    third_domain = b"IBE-v2"
    third = attacks.IBETranscript(
        identity, third_domain, _ibe_hash(third_domain, identity), 7
    )
    audit = attacks.audit_ibe_structure(
        (first, second, third), group, 11, _ibe_hash
    )
    assert audit.ephemeral_reuse == ((0, 1),)
    assert audit.identity_point_collisions == ()

    known_plaintext = b"known message"
    target_plaintext = b"secret bytes!"
    pad = bytes(range(1, len(known_plaintext) + 1))
    known_ciphertext = bytes(a ^ b for a, b in zip(known_plaintext, pad))
    target_ciphertext = bytes(a ^ b for a, b in zip(target_plaintext, pad))
    # Algebraic XOR replay alone is tautological; original-problem evidence is
    # mandatory before plaintext is emitted.
    assert attacks.recover_ibe_reused_ephemeral_message(
        first,
        second,
        known_plaintext,
        known_ciphertext,
        target_ciphertext,
        group,
        11,
        _ibe_hash,
    ) is None
    assert attacks.recover_ibe_reused_ephemeral_message(
        first,
        second,
        known_plaintext,
        known_ciphertext,
        target_ciphertext,
        group,
        11,
        _ibe_hash,
        message_verifier=lambda message: message.startswith(b"secret"),
        negative_control=b"definitely invalid",
    ) == target_plaintext
    assert attacks.recover_ibe_reused_ephemeral_message(
        first,
        second,
        known_plaintext,
        known_ciphertext,
        target_ciphertext,
        group,
        11,
        _ibe_hash,
        message_verifier=lambda _message: False,
        negative_control=b"definitely invalid",
    ) is None
    assert attacks.recover_ibe_reused_ephemeral_message(
        first,
        second,
        known_plaintext,
        known_ciphertext,
        target_ciphertext,
        group,
        11,
        _ibe_hash,
        message_verifier=lambda _message: True,
        negative_control=b"definitely invalid",
    ) is None
    assert attacks.recover_ibe_reused_ephemeral_message(
        first,
        second,
        known_plaintext,
        known_ciphertext,
        target_ciphertext,
        group,
        11,
        _ibe_hash,
        message_verifier=lambda message: message.startswith(b"secret"),
        negative_control=target_plaintext,
    ) is None
    assert attacks.recover_ibe_reused_ephemeral_message(
        first,
        second,
        known_plaintext,
        known_ciphertext,
        target_ciphertext,
        group,
        11,
        _ibe_hash,
        message_verifier=lambda _message: "yes",
        negative_control=b"definitely invalid",
    ) is None
    assert attacks.recover_ibe_reused_ephemeral_message(
        first,
        second,
        known_plaintext,
        known_ciphertext,
        target_ciphertext,
        group,
        11,
        _ibe_hash,
        message_verifier=lambda _message: (_ for _ in ()).throw(
            RuntimeError("verifier failure")
        ),
        negative_control=b"definitely invalid",
    ) is None
    # The target extends beyond the known pad prefix, leaving unconstrained
    # bytes; no partial or guessed plaintext is emitted.
    assert attacks.recover_ibe_reused_ephemeral_message(
        first,
        second,
        known_plaintext,
        known_ciphertext,
        target_ciphertext + b"x",
        group,
        11,
        _ibe_hash,
    ) is None
    assert attacks.recover_ibe_reused_ephemeral_message(
        None,
        second,
        known_plaintext,
        known_ciphertext,
        target_ciphertext,
        group,
        11,
        _ibe_hash,
    ) is None
    assert attacks.recover_ibe_reused_ephemeral_message(
        first,
        third,
        known_plaintext,
        known_ciphertext,
        target_ciphertext,
        group,
        11,
        _ibe_hash,
    ) is None

    # A deliberately broken domain hash is reported as structure misuse, not a
    # recovered secret claim.
    bad_hash = lambda _domain, _identity: 3
    bad_rows = (
        attacks.IBETranscript(b"alice", b"v1", 3, 2),
        attacks.IBETranscript(b"alice", b"v2", 3, 4),
        attacks.IBETranscript(b"bob", b"v1", 3, 5),
    )
    bad_audit = attacks.audit_ibe_structure(bad_rows, group, 11, bad_hash)
    assert bad_audit.identity_point_collisions == ((0, 1), (0, 2), (1, 2))
    assert bad_audit.domain_separation_failures == ((0, 1),)


def test_all_iterables_callbacks_and_work_caps_fail_closed():
    context = _bilinear_context()

    def exploding():
        yield 1
        raise RuntimeError("mid-stream")

    assert not attacks.verify_bls_aggregate_equation(
        context, 1, exploding(), (b"x",), _hash_to_g1
    )
    assert attacks.audit_ibe_structure(exploding(), _additive_group(11), 11, _ibe_hash) is None
    assert attacks.recover_invalid_isogeny_auxiliary_secret(
        exploding(), 11, 1, lambda value: value
    ) is None
    assert attacks.audit_sidh_public_transcript(
        3,
        (1, 0, 0),
        ((0, 1, 0), (0, 0, 1)),
        ((1, 0), (0, 1)),
        5,
        _product_group((3, 5, 5)),
        _product_group((5, 5)),
        lambda point: (point[1], point[2]),
        exploding(),
    ) is None
    assert attacks.audit_sike_public_kem_structure(
        3,
        (1, 0, 0),
        ((0, 1, 0), (0, 0, 1)),
        ((1, 0), (0, 1)),
        5,
        _product_group((3, 5, 5)),
        _product_group((5, 5)),
        lambda point: (point[1], point[2]),
        (
            ((0, 1, 2), (1, 2, 3)),
            ((2, 4, 1), (0, 3, 2)),
            ((1, 2, 4), (2, 1, 3)),
        ),
        exploding(),
        lambda _component: True,
        b"toy",
    ) is None

    assert attacks.audit_csidh_toy_action(
        0,
        (3,) * (attacks.MAX_CSIDH_DIMENSION + 1),
        (1,) * (attacks.MAX_CSIDH_DIMENSION + 1),
        lambda state, _index, direction: state + direction,
    ) is None
    assert attacks.recover_csidh_small_exponent_vector(
        0,
        0,
        (3, 5, 7, 11, 13, 17),
        (2, 2, 2, 2, 2, 2),
        lambda state, index, direction: state + direction * (index + 1),
    ) is None  # 5^6 exceeds the hard work cap.
    assert attacks.audit_csidh_toy_action(
        0,
        (3, 5, 7, 11, 13, 17, 19, 23),
        (1,) * 8,
        lambda state, index, direction: state + direction * (index + 1),
    ) is None  # Reachable-state law checks exceed the aggregate action cap.

    oversized_pairing = attacks.BilinearContext(
        257,
        1,
        1,
        _additive_group(257),
        _additive_group(257),
        _additive_group(257),
        lambda left, right: left * right % 257,
    )
    assert attacks.audit_bilinear_context(oversized_pairing) is None

    huge_message = b"x" * attacks.MAX_MESSAGE_BYTES
    assert not attacks.verify_bls_aggregate_equation(
        context,
        1,
        (1, 1, 1),
        (huge_message, huge_message, huge_message),
        _hash_to_g1,
    )
    huge_rows = tuple(
        attacks.IBETranscript(huge_message, b"", 1, 1) for _ in range(3)
    )
    assert attacks.audit_ibe_structure(
        huge_rows, _additive_group(11), 11, lambda _domain, _identity: 1
    ) is None

    def exploding_neighbors(_node):
        yield ("B", 2, b"proof")
        raise RuntimeError("mid-neighbor-stream")

    assert attacks.recover_unique_isogeny_secret_path(
        "A",
        "B",
        exploding_neighbors,
        lambda _left, _right, _degree, _proof: True,
        lambda _nodes, _degrees: b"public",
        b"public",
    ) is None

    malformed_context = attacks.BilinearContext(
        11,
        1,
        1,
        _additive_group(11),
        _additive_group(11),
        attacks.GroupOps(1, lambda x, y: x * y % 23, lambda x: pow(x, -1, 23)),
        lambda _left, _right: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert attacks.audit_bilinear_context(malformed_context) is None
    assert not attacks.bilinear_ddh_check(None, 1, 1, 1)
    assert not attacks.bilinear_co_ddh_check(None, 1, 1, 1)
    assert not attacks.verify_co_cdh_candidate(None, 1, 1, 1)
    assert attacks.build_bls_rogue_key_witness(
        None, 3, 8, b"same", _hash_to_g1
    ) is None
    assert not attacks.verify_bilinear_equation(
        context,
        ((1, 1),),
        ((pair for pair in itertools.repeat((1, 1)))),
    )
    assert attacks.audit_bls_aggregate(
        context,
        1,
        (1,),
        (b"x",),
        _hash_to_g1,
        pop_proofs=(b"proof",),
        pop_verifier=lambda _key, _proof: "yes",
    ) is None


def test_property_pairing_and_csidh_against_exhaustive_oracle():
    context = _bilinear_context()
    rng = random.Random(0x51D4)
    for _ in range(32):
        secret = rng.randrange(1, 11)
        public = context.g1_group.power(context.g1, secret)
        brute = next(
            candidate
            for candidate in range(11)
            if context.g1_group.power(context.g1, candidate) == public
        )
        assert attacks.recover_unique_pairing_scalar(context, public, context.g2) == brute

    weights = (1, 9, 27)
    apply_action = lambda state, index, direction: (
        state + direction * weights[index]
    ) % 101
    for vector in itertools.product(range(-1, 2), repeat=3):
        public = sum(value * weight for value, weight in zip(vector, weights)) % 101
        witnesses = [
            candidate
            for candidate in itertools.product(range(-1, 2), repeat=3)
            if sum(value * weight for value, weight in zip(candidate, weights)) % 101
            == public
        ]
        recovered = attacks.recover_csidh_small_exponent_vector(
            0, public, (3, 5, 7), (1, 1, 1), apply_action
        )
        assert recovered == (witnesses[0] if len(witnesses) == 1 else None)


def test_property_leakage_and_reused_proofs_against_exhaustive_oracle():
    for secret in range(17):
        rows = (_leak_observation(secret, 3), _leak_observation(secret, 5))
        witnesses = [
            candidate
            for candidate in range(17)
            if candidate % 3 == secret % 3
            and candidate % 5 == secret % 5
            and candidate == secret
        ]
        recovered = attacks.recover_invalid_isogeny_auxiliary_secret(
            rows, 17, secret, lambda candidate: candidate
        )
        assert recovered == (witnesses[0] if len(witnesses) == 1 else None)

    group = _additive_group(11)
    for secret in range(1, 11):
        for nonce in range(11):
            first = attacks.LinearProof(nonce, (nonce + 2 * secret) % 11, 2)
            second = attacks.LinearProof(nonce, (nonce + 7 * secret) % 11, 7)
            brute = [
                candidate
                for candidate in range(1, 11)
                if candidate == secret
                and (first.response - first.challenge * candidate) % 11 == nonce
                and (second.response - second.challenge * candidate) % 11 == nonce
            ]
            recovered = attacks.recover_reused_linear_proof_scalar(
                first, second, secret, 1, 11, group
            )
            assert recovered == (brute[0] if len(brute) == 1 else None)
