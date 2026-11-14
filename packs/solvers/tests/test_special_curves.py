"""Deterministic success and fail-closed tests for r5c special-curve attacks."""

from __future__ import annotations

import importlib
import itertools
from pathlib import Path
import random
import sys

import pytest


COMMON = Path(__file__).resolve().parents[1] / "solvers" / "common"
sys.path.insert(0, str(COMMON))

import special_curves as special  # noqa: E402


def test_package_style_import_without_common_path_injection():
    """Repo-root imports must resolve the sibling helper relatively."""

    original_path = list(sys.path)
    sys.modules.pop("solvers.common.special_curves", None)
    try:
        common_resolved = COMMON.resolve()
        sys.path[:] = [
            entry
            for entry in sys.path
            if not entry or Path(entry).resolve() != common_resolved
        ]
        packaged = importlib.import_module("solvers.common.special_curves")
        assert packaged.__name__ == "solvers.common.special_curves"
        assert packaged._ecc.__name__ == "solvers.common.ecc_weak"
        assert packaged.bsgs_mod_prime(4, pow(4, 17, 59), 59, 29) == 17
    finally:
        sys.path[:] = original_path


def test_bounded_bsgs_and_pohlig_hellman_crosscheck_sympy_and_decline():
    sympy = pytest.importorskip("sympy")
    prime, order, generator, secret = 337, 336, 10, 211
    assert sympy.n_order(generator, prime) == order
    target = pow(generator, secret, prime)
    assert special.bsgs_mod_prime(generator, target, prime, order) == secret
    assert special.pohlig_hellman_mod_prime(generator, target, prime, order) == secret
    assert int(sympy.discrete_log(prime, target, generator)) == secret

    # An oversized table request, false exact-order claim, and out-of-subgroup
    # target all decline rather than return one of several congruence classes.
    assert special.bsgs_mod_prime(
        generator, target, prime, order, max_table=1
    ) is None
    assert special.bsgs_mod_prime(generator, target, prime, order * 2) is None
    assert special.pohlig_hellman_mod_prime(generator, 0, prime, order) is None


def test_toy_index_calculus_recovers_and_rejects_underdetermined_base():
    sympy = pytest.importorskip("sympy")
    prime, order, generator, secret = 59, 29, 4, 17
    target = pow(generator, secret, prime)
    assert special.toy_index_calculus(generator, target, prime, order) == secret
    assert int(sympy.discrete_log(prime, target, generator)) == secret

    # Only one usable factor-base element cannot form a uniquely solved system.
    assert special.toy_index_calculus(
        generator, target, prime, order, factor_base=(3,)
    ) is None
    assert special.toy_index_calculus(generator, target + prime, prime, order) == secret
    assert special.toy_index_calculus(generator, 0, prime, order) is None


def test_index_factor_base_iterables_are_bounded_and_typed():
    target = pow(4, 17, 59)
    finite_generator = (value for value in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37))
    assert special.toy_index_calculus(
        4, target, 59, 29, factor_base=finite_generator
    ) == 17

    def infinite_bases():
        while True:
            yield 3

    assert special.toy_index_calculus(
        4, target, 59, 29, factor_base=infinite_bases()
    ) is None
    assert special.toy_index_calculus(4, target, 59, 29, factor_base=42) is None

    def failing_bases():
        yield 3
        yield 5
        raise RuntimeError("mid-iteration failure")

    assert special.toy_index_calculus(
        4, target, 59, 29, factor_base=failing_bases()
    ) is None
    assert special.toy_index_calculus(
        4, target, 59, 29, factor_base=(True, 3, 5, 7, 17, 19, 29)
    ) is None
    assert special.toy_index_calculus(True, target, 59, 29) is None
    assert special.toy_index_calculus(4, target, 59, True) is None


def test_randomized_dlp_algorithms_match_bounded_brute_force():
    rng = random.Random(0x5EC1A1)

    def brute(generator, target, prime, order):
        return next(
            exponent
            for exponent in range(order)
            if pow(generator, exponent, prime) == target
        )

    for prime, generator, order in ((59, 4, 29), (337, 10, 336)):
        for _ in range(24):
            secret = rng.randrange(order)
            target = pow(generator, secret, prime)
            expected = brute(generator, target, prime, order)
            assert special.bsgs_mod_prime(generator, target, prime, order) == expected
            assert special.pohlig_hellman_mod_prime(
                generator, target, prime, order
            ) == expected

    for secret in range(29):
        target = pow(4, secret, 59)
        assert special.toy_index_calculus(4, target, 59, 29) == brute(
            4, target, 59, 29
        )


@pytest.mark.parametrize(
    "label,a,b,generator,secret,expected",
    (
        ("cusp", 0, 0, (1, 1), 13, (52, 4)),
        ("split-node", 74, 54, (0, 16), 13, (14, 81)),
        ("non-split-node", 98, 2, (4, 16), 13, (54, 59)),
    ),
)
def test_singular_cusp_split_and_nonsplit_reductions(label, a, b, generator, secret, expected):
    del label
    target = special.ec_mul(secret, generator, 101, a)
    assert target == expected
    assert special.recover_singular_curve_dlp(101, a, b, generator, target) == secret
    assert special.ec_mul(secret, generator, 101, a) == target

    # An off-curve target and a nonsingular coefficient set cannot be evidence.
    assert special.recover_singular_curve_dlp(101, a, b, generator, (0, 0)) is None
    assert special.recover_singular_curve_dlp(101, 1, 1, generator, target) is None


def test_singular_recovery_matches_exhaustive_scalar_replay():
    for a, b, generator, order in (
        (0, 0, (1, 1), 101),
        (74, 54, (0, 16), 100),
        (98, 2, (4, 16), 102),
    ):
        for scalar in range(1, order):
            target = special.ec_mul(scalar, generator, 101, a)
            assert target is not None
            assert special.recover_singular_curve_dlp(
                101, a, b, generator, target
            ) == scalar


def test_smart_anomalous_attack_has_order_and_point_proofs():
    # #E(F_11) for y^2=x^3+3x+9 is exactly 11.
    p, a, b = 11, 3, 9
    generator = (0, 3)
    secret = 3
    public = (6, 1)
    assert special.ec_mul(secret, generator, p, a) == public
    assert special.recover_anomalous_smart(p, a, b, generator, public) == secret

    sympy = pytest.importorskip("sympy")
    count = 1 + sum(
        1
        for x in range(p)
        for y in range(p)
        if (y * y - (x**3 + a * x + b)) % p == 0
    )
    assert count == p and sympy.isprime(p)

    # This nearby curve is not anomalous; an off-curve key also declines.
    assert special.recover_anomalous_smart(p, a, 8, generator, public) is None
    assert special.recover_anomalous_smart(p, a, b, generator, (0, 0)) is None


def _twist_observations(secret: int):
    p, a, b, nonresidue = 43, 1, 1, 2
    twist_a = a * nonresidue**2 % p
    rows = []
    for point, order in (((33, 0), 2), ((1, 20), 27)):
        rows.append(
            special.TwistObservation(
                p,
                a,
                b,
                nonresidue,
                point,
                special.ec_mul(secret, point, p, twist_a),
                order,
            )
        )
    return rows


def test_quadratic_twist_residues_crt_and_public_replay():
    secret = 13
    rows = _twist_observations(secret)
    assert [special.recover_quadratic_twist_residue(row) for row in rows] == [
        (1, 2),
        (13, 27),
    ]
    generator = (11, 15)  # exact order 17 on y^2=x^3+x+1 over F_43
    public = special.ec_mul(secret, generator, 43, 1)
    assert special.recover_quadratic_twist_private_scalar(
        rows, 43, 1, 1, generator, public, 17
    ) == secret

    wrong_order = special.TwistObservation(
        43, 1, 1, 2, (33, 0), (33, 0), 4
    )
    assert special.recover_quadratic_twist_residue(wrong_order) is None
    assert special.recover_quadratic_twist_private_scalar(
        rows[:1], 43, 1, 1, generator, public, 17, max_candidates=1
    ) is None
    wrong_public = special.ec_mul(secret + 1, generator, 43, 1)
    assert special.recover_quadratic_twist_private_scalar(
        rows, 43, 1, 1, generator, wrong_public, 17
    ) is None


def _degree_three_pairing_fixture():
    field = special.ExtensionField(5, 3, (1, 0, 1, 1))  # x^3+x^2+1
    base = None
    for candidate in itertools.product(range(5), repeat=3):
        if candidate == field.zero:
            continue
        projected = field.power(candidate, 4)  # (5^3-1)/31
        if projected != field.one and field.power(projected, 31) == field.one:
            base = projected
            break
    assert base is not None
    source_group = special.GroupOps(
        0,
        lambda left, right: (left + right) % 31,
        lambda value: (-value) % 31,
    )
    pairing = lambda left, right: field.power(base, left * right % 31)
    return field, base, source_group, pairing


def test_higher_embedding_pairing_transcript_and_parameter_analyzer():
    field, base, source_group, pairing = _degree_three_pairing_fixture()
    assert field.power(base, 31) == field.one
    secret = 19
    assert special.embedding_degree(5, 31, max_degree=6) == 3
    analysis = special.analyze_pairing_weak_parameters(
        5, 31, claimed_embedding=3, max_embedding=6
    )
    assert analysis == {
        "embedding_degree": 3,
        "extension_field_bits": 7,
        "subgroup_bits": 5,
        "verified": True,
    }
    assert special.recover_pairing_transcript_dlp(
        5,
        3,
        (1, 0, 1, 1),
        31,
        1,
        secret,
        source_group,
        1,
        pairing,
    ) == secret

    assert special.analyze_pairing_weak_parameters(
        5, 31, claimed_embedding=2, max_embedding=6
    ) is None
    bad_pairing = lambda left, right: field.power(base, left * right * right % 31)
    assert special.recover_pairing_transcript_dlp(
        5, 3, (1, 0, 1, 1), 31, 1, secret, source_group, 2, bad_pairing
    ) is None
    # Reducible x^3+1 is refused by the extension-field proof.
    with pytest.raises(ValueError):
        special.ExtensionField(5, 3, (1, 0, 0, 1))


def test_concrete_mov_frey_ruck_transfer_replays_source_point():
    # Supersingular E/F_43, point order 11, minimal embedding degree two.
    generator = (31, 18)
    secret = 7
    public = special.ec_mul(secret, generator, 43, 1)
    assert special.recover_mov_frey_ruck(
        43, 1, 0, generator, public, 11
    ) == secret
    assert special.recover_mov_frey_ruck(
        43, 1, 0, generator, public, 11, embedding=3
    ) is None
    assert special.recover_mov_frey_ruck(
        43, 1, 1, generator, public, 11
    ) is None


def _additive_group(modulus: int):
    return special.GroupOps(
        0,
        lambda left, right: (left + right) % modulus,
        lambda value: (-value) % modulus,
    )


def test_isogeny_kernel_degree_and_homomorphism_transcript_validation():
    domain = _additive_group(35)
    codomain = _additive_group(7)
    transcript = special.IsogenyTranscript(
        degree=5,
        domain_order=35,
        codomain_order=7,
        kernel_generator=7,
        domain_group=domain,
        codomain_group=codomain,
        point_map=lambda point: point % 7,
        image_witness=1,
        homomorphism_samples=((1, 9), (8, 22), (14, 27), (34, 6)),
    )
    result = special.validate_isogeny_transcript(transcript)
    assert result == {
        "degree": 5,
        "kernel_order": 5,
        "domain_order": 35,
        "codomain_order": 7,
        "verified": True,
    }

    wrong_kernel = special.IsogenyTranscript(
        **{**transcript.__dict__, "kernel_generator": 5}
    )
    assert special.validate_isogeny_transcript(wrong_kernel) is None
    bad_map = special.IsogenyTranscript(
        **{**transcript.__dict__, "point_map": lambda point: (point + 1) % 7}
    )
    assert special.validate_isogeny_transcript(bad_map) is None
    zero_map = special.IsogenyTranscript(
        **{**transcript.__dict__, "point_map": lambda _point: 0}
    )
    assert special.validate_isogeny_transcript(zero_map) is None
    duplicate_samples = special.IsogenyTranscript(
        **{**transcript.__dict__, "homomorphism_samples": ((1, 9),) * 3}
    )
    assert special.validate_isogeny_transcript(duplicate_samples) is None


def test_unique_small_degree_isogeny_path_and_ambiguity_decline():
    graph = {
        "A": (("B", 2, "A-B"),),
        "B": (("D", 3, "B-D"),),
        "D": (),
    }
    validator = lambda left, right, degree, proof: proof == f"{left}-{right}" and degree in (2, 3)
    path = special.recover_unique_small_degree_isogeny_path(
        "A", "D", lambda node: graph[node], validator
    )
    assert path == special.IsogenyPath(("A", "B", "D"), (2, 3), 6, True)

    ambiguous = {
        "A": (("B", 2, "A-B"), ("C", 2, "A-C")),
        "B": (("D", 3, "B-D"),),
        "C": (("D", 3, "C-D"),),
        "D": (),
    }
    assert special.recover_unique_small_degree_isogeny_path(
        "A", "D", lambda node: ambiguous[node], validator
    ) is None
    assert special.recover_unique_small_degree_isogeny_path(
        "A", "D", lambda node: graph[node], lambda *_args: False
    ) is None


def test_callback_protocols_and_all_caller_iterables_fail_closed():
    malformed_group = special.GroupOps(
        1,
        lambda left, right: left * right % 59,
        lambda value: pow(value, -1, 59),
        equal=lambda _left, _right: "yes",
    )
    assert special.bounded_bsgs(4, pow(4, 3, 59), 29, malformed_group) is None
    assert special.bsgs_mod_prime(True, 1, 59, 29) is None
    assert special.pohlig_hellman_mod_prime(4, True, 59, 29) is None
    assert special.embedding_degree(5, 31, max_degree=True) is None
    assert special.analyze_pairing_weak_parameters(
        5, 31, claimed_embedding=True
    ) is None
    field, _base, source_group, _pairing = _degree_three_pairing_fixture()
    with pytest.raises(TypeError):
        field.val(True)
    with pytest.raises(ValueError):
        special.ExtensionField(5, 3, (1, 0, True, 1))
    assert special.recover_pairing_transcript_dlp(
        5,
        3,
        (1, 0, 1, 1),
        31,
        1,
        3,
        source_group,
        1,
        lambda _left, _right: "malformed",
    ) is None
    assert special.recover_pairing_transcript_dlp(
        5,
        3,
        (1, 0, 1, 1),
        31,
        1,
        3,
        source_group,
        1,
        lambda _left, _right: (_ for _ in ()).throw(RuntimeError("boom")),
    ) is None

    domain = _additive_group(35)
    codomain = _additive_group(7)
    infinite_samples = special.IsogenyTranscript(
        degree=5,
        domain_order=35,
        codomain_order=7,
        kernel_generator=7,
        domain_group=domain,
        codomain_group=codomain,
        point_map=lambda point: point % 7,
        image_witness=1,
        homomorphism_samples=itertools.repeat((1, 9)),
    )
    assert special.validate_isogeny_transcript(infinite_samples) is None

    def failing_samples():
        yield 1, 9
        raise RuntimeError("mid-iteration failure")

    failing_sample_transcript = special.IsogenyTranscript(
        **{**infinite_samples.__dict__, "homomorphism_samples": failing_samples()}
    )
    assert special.validate_isogeny_transcript(failing_sample_transcript) is None
    exploding_map = special.IsogenyTranscript(
        **{
            **infinite_samples.__dict__,
            "homomorphism_samples": ((1, 9), (8, 22), (14, 27)),
            "point_map": lambda _point: (_ for _ in ()).throw(RuntimeError("boom")),
        }
    )
    assert special.validate_isogeny_transcript(exploding_map) is None

    def infinite_neighbors(_node):
        while True:
            yield "B", 2, "proof"

    assert special.recover_unique_small_degree_isogeny_path(
        "A",
        "D",
        infinite_neighbors,
        lambda *_args: True,
        max_nodes=8,
    ) is None
    graph = {"A": (("D", 2, "proof"),), "D": ()}
    assert special.recover_unique_small_degree_isogeny_path(
        "A", "D", lambda node: graph[node], lambda *_args: "yes"
    ) is None
    assert special.recover_unique_small_degree_isogeny_path(
        "A",
        "D",
        lambda _node: (_ for _ in ()).throw(RuntimeError("boom")),
        lambda *_args: True,
    ) is None

    rows = itertools.repeat(_twist_observations(13)[0])
    generator = (11, 15)
    public = special.ec_mul(13, generator, 43, 1)
    assert special.recover_quadratic_twist_private_scalar(
        rows, 43, 1, 1, generator, public, 17
    ) is None

    def failing_twist_rows():
        yield _twist_observations(13)[0]
        raise RuntimeError("mid-iteration failure")

    assert special.recover_quadratic_twist_private_scalar(
        failing_twist_rows(), 43, 1, 1, generator, public, 17
    ) is None
