"""Bounded toy SIDH/SIKE/CSIDH and pairing-protocol attack helpers.

This module is intentionally a *toy-parameter structural suite*, not a claim
against production SIDH/SIKE, CSIDH, BLS, or IBE parameters.  Analyzer functions
return explicit audit records.  Recovery functions return a scalar, vector,
message, or path only after every supplied public/action/pairing equation is
replayed and exactly one witness survives.

No networking is performed.  All caller iterables, graph searches, exponent
boxes, subgroup enumerations, messages, and callback invocations are bounded.
Generic group and DLP machinery is reused from :mod:`special_curves` rather
than duplicated here.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import itertools
import math
from typing import Any, Callable, Iterable, Optional, Sequence

try:  # Package import from repository root.
    from . import special_curves as _special
except ImportError:  # Direct legacy import with solvers/common on sys.path.
    import special_curves as _special


GroupOps = _special.GroupOps
IsogenyPath = _special.IsogenyPath

MAX_TORSION_ORDER = 1 << 14
MAX_TORSION_ENUM = 1 << 16
MAX_TRANSCRIPT_ROWS = 64
MAX_LEAK_MODULUS = 1 << 14
MAX_LEAK_CANDIDATES = 1 << 16
MAX_CSIDH_DIMENSION = 12
MAX_CSIDH_WORK = 1 << 16
MAX_CSIDH_ACTION_WORK = 1 << 20
MAX_PAIRING_EQUATIONS = 64
MAX_PAIRING_SCALAR_WORK = 1 << 16
MAX_PAIRING_TOTAL_WORK = 1 << 18
MAX_BLS_PARTICIPANTS = 64
MAX_IBE_TRANSCRIPTS = 64
MAX_MESSAGE_BYTES = 1 << 20
MAX_TOTAL_MESSAGE_BYTES = 1 << 21


def _plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _strict_bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise TypeError("callback must return bool")
    return value


def _same(group: GroupOps, left: Any, right: Any) -> bool:
    return _strict_bool(group.equal(left, right))


def _bounded(iterable: Iterable[Any], cap: int) -> Optional[list[Any]]:
    try:
        values = list(itertools.islice(iter(iterable), cap + 1))
    except Exception:
        return None
    return values if len(values) <= cap else None


def _exact_order(element: Any, order: int, group: GroupOps) -> bool:
    if not _plain_int(order) or not (1 < order <= _special.MAX_ORDER):
        return False
    try:
        return _special._has_exact_order(element, order, group)
    except Exception:
        return False


def _in_subgroup(element: Any, order: int, group: GroupOps, *, nonidentity: bool = False) -> bool:
    try:
        if not _same(group, group.power(element, order), group.identity):
            return False
        return not nonidentity or not _same(group, element, group.identity)
    except Exception:
        return False


def _has_prime_order(element: Any, order: int, group: GroupOps) -> bool:
    """Check exact prime order without repeatedly factoring the same order."""

    if not _special._is_prime(order):
        return False
    try:
        return _same(group, group.power(element, order), group.identity) and not _same(
            group, element, group.identity
        )
    except Exception:
        return False


def _bounded_messages(
    iterable: Iterable[Any], count_cap: int
) -> Optional[list[bytes]]:
    """Materialize byte strings under both per-item and aggregate byte caps."""

    rows = _bounded(iterable, count_cap)
    if rows is None:
        return None
    encoded: list[bytes] = []
    total = 0
    for row in rows:
        message = _message(row)
        if message is None:
            return None
        total += len(message)
        if total > MAX_TOTAL_MESSAGE_BYTES:
            return None
        encoded.append(message)
    return encoded


# ---------------------------------------------------------------------------
# SIDH/SIKE-style torsion and public transcript audits


@dataclass(frozen=True)
class TorsionBasisAudit:
    order: int
    enumerated_points: int
    pairing_checked: bool
    verified: bool = True


def audit_torsion_basis(
    first: Any,
    second: Any,
    order: int,
    group: GroupOps,
    *,
    pairing: Optional[Callable[[Any, Any], Any]] = None,
    target_group: Optional[GroupOps] = None,
    max_enumeration: int = MAX_TORSION_ENUM,
) -> Optional[TorsionBasisAudit]:
    """Prove two points form a toy ``(Z/order)^2`` torsion basis.

    Small bases are proven by exhaustive injectivity of ``aP+bQ``.  Larger
    bases require an alternating, non-degenerate pairing of exact order.
    """

    if (
        not _plain_int(order)
        or not (1 < order <= MAX_TORSION_ORDER)
        or not _plain_int(max_enumeration)
        or not (1 <= max_enumeration <= MAX_TORSION_ENUM)
        or not _exact_order(first, order, group)
        or not _exact_order(second, order, group)
    ):
        return None
    required = order * order
    # A direct product requires commuting generators.  Injectivity of the
    # fixed-order words alone is not enough in a non-abelian group (two
    # transpositions in S3 are the smallest counterexample).
    try:
        if not _same(
            group,
            group.combine(first, second),
            group.combine(second, first),
        ):
            return None
    except Exception:
        return None
    enumerated = 0
    if required <= max_enumeration:
        seen: set[Any] = set()
        try:
            for left in range(order):
                left_point = group.power(first, left)
                for right in range(order):
                    point = group.combine(left_point, group.power(second, right))
                    encoded = group.encode(point)
                    hash(encoded)
                    if encoded in seen:
                        return None
                    seen.add(encoded)
            if len(seen) != required:
                return None
            enumerated = required
        except Exception:
            return None
    else:
        # A few pairing samples cannot prove independence: a dependent point
        # can be hidden at an unqueried scalar.  Conservatively require the
        # complete bounded direct-product enumeration even when a pairing was
        # supplied.
        return None

    pairing_checked = pairing is not None
    if pairing is not None:
        if target_group is None or not callable(pairing):
            return None
        try:
            diagonal_first = pairing(first, first)
            diagonal_second = pairing(second, second)
            forward = pairing(first, second)
            reverse = pairing(second, first)
            if not _same(target_group, diagonal_first, target_group.identity):
                return None
            if not _same(target_group, diagonal_second, target_group.identity):
                return None
            if not _exact_order(forward, order, target_group):
                return None
            if not _same(target_group, reverse, target_group.inverse(forward)):
                return None
            # Exhaust the two cyclic axes.  Independence was already proved
            # directly above; these checks make ``pairing_checked`` mean that
            # alternating bilinearity was established on the supplied basis,
            # rather than inferred from the scalars 2 and 3.
            for left in range(order):
                first_left = group.power(first, left)
                second_left = group.power(second, left)
                for right in range(order):
                    first_right = group.power(first, right)
                    second_right = group.power(second, right)
                    exponent = left * right
                    expected = target_group.power(forward, exponent)
                    reverse_expected = target_group.inverse(expected)
                    if not _same(
                        target_group,
                        pairing(first_left, second_right),
                        expected,
                    ):
                        return None
                    if not _same(
                        target_group,
                        pairing(second_left, first_right),
                        reverse_expected,
                    ):
                        return None
                    if not _same(
                        target_group,
                        pairing(first_left, first_right),
                        target_group.identity,
                    ):
                        return None
                    if not _same(
                        target_group,
                        pairing(second_left, second_right),
                        target_group.identity,
                    ):
                        return None
        except Exception:
            return None
    return TorsionBasisAudit(order, enumerated, pairing_checked, True)


@dataclass(frozen=True)
class SIDHPublicTranscriptAudit:
    degree: int
    torsion_order: int
    checked_samples: int
    verified: bool = True


def audit_sidh_public_transcript(
    degree: int,
    kernel_generator: Any,
    domain_basis: tuple[Any, Any],
    image_basis: tuple[Any, Any],
    torsion_order: int,
    domain_group: GroupOps,
    codomain_group: GroupOps,
    point_map: Callable[[Any], Any],
    homomorphism_samples: Iterable[tuple[Any, Any]],
) -> Optional[SIDHPublicTranscriptAudit]:
    """Validate a toy SIDH public key as mapped coprime-torsion basis images."""

    rows = _bounded(homomorphism_samples, MAX_TRANSCRIPT_ROWS)
    if (
        rows is None
        or len(rows) < 3
        or not _plain_int(degree)
        or not (1 < degree <= MAX_TORSION_ORDER)
        or not _plain_int(torsion_order)
        or not (1 < torsion_order <= MAX_TORSION_ORDER)
        or not callable(point_map)
        or not isinstance(domain_basis, tuple)
        or len(domain_basis) != 2
        or not isinstance(image_basis, tuple)
        or len(image_basis) != 2
        or math.gcd(degree, torsion_order) != 1
        or not _exact_order(kernel_generator, degree, domain_group)
        or audit_torsion_basis(*domain_basis, torsion_order, domain_group) is None
        or audit_torsion_basis(*image_basis, torsion_order, codomain_group) is None
    ):
        return None
    try:
        if not _same(codomain_group, point_map(domain_group.identity), codomain_group.identity):
            return None
        if not _same(codomain_group, point_map(kernel_generator), codomain_group.identity):
            return None
        for original, image in zip(domain_basis, image_basis):
            if not _same(codomain_group, point_map(original), image):
                return None
        seen: set[Any] = set()
        for left, right in rows:
            key = (domain_group.encode(left), domain_group.encode(right))
            hash(key)
            if key in seen:
                return None
            seen.add(key)
            mapped_sum = point_map(domain_group.combine(left, right))
            sum_mapped = codomain_group.combine(point_map(left), point_map(right))
            if not _same(codomain_group, mapped_sum, sum_mapped):
                return None
    except Exception:
        return None
    return SIDHPublicTranscriptAudit(degree, torsion_order, len(rows), True)


@dataclass(frozen=True)
class SIKEPublicKEMAudit:
    public_transcript: SIDHPublicTranscriptAudit
    ciphertext_components: int
    domain_tag: bytes
    toy_parameters_only: bool = True
    verified: bool = True


def audit_sike_public_kem_structure(
    degree: int,
    kernel_generator: Any,
    domain_basis: tuple[Any, Any],
    image_basis: tuple[Any, Any],
    torsion_order: int,
    domain_group: GroupOps,
    codomain_group: GroupOps,
    point_map: Callable[[Any], Any],
    homomorphism_samples: Iterable[tuple[Any, Any]],
    ciphertext_components: Iterable[Any],
    component_validator: Callable[[Any], bool],
    domain_tag: Any,
) -> Optional[SIKEPublicKEMAudit]:
    """Audit a toy SIKE-shaped public transcript and KEM component envelope.

    This is structural validation for deliberately small fixtures.  It never
    claims a break or validation of production SIKE parameter sets.
    """

    public_audit = audit_sidh_public_transcript(
        degree,
        kernel_generator,
        domain_basis,
        image_basis,
        torsion_order,
        domain_group,
        codomain_group,
        point_map,
        homomorphism_samples,
    )
    components = _bounded(ciphertext_components, 8)
    tag = _message(domain_tag)
    if (
        public_audit is None
        or components is None
        or not components
        or tag is None
        or not tag
        or not callable(component_validator)
    ):
        return None
    try:
        if not all(_strict_bool(component_validator(component)) for component in components):
            return None
    except Exception:
        return None
    return SIKEPublicKEMAudit(public_audit, len(components), tag, True, True)


# ---------------------------------------------------------------------------
# Invalid-isogeny / auxiliary-point leakage transcripts


@dataclass(frozen=True)
class AuxiliaryLeakObservation:
    modulus: int
    auxiliary_point: Any
    auxiliary_group: GroupOps
    response: Any
    evaluate: Callable[[int, Any], Any]
    response_equal: Callable[[Any, Any], bool] = lambda left, right: left == right


def _recover_leak_residue(observation: AuxiliaryLeakObservation) -> Optional[tuple[int, int]]:
    if (
        not isinstance(observation, AuxiliaryLeakObservation)
        or not _plain_int(observation.modulus)
        or not (1 < observation.modulus <= MAX_LEAK_MODULUS)
        or not callable(observation.evaluate)
        or not callable(observation.response_equal)
        or not _exact_order(
            observation.auxiliary_point,
            observation.modulus,
            observation.auxiliary_group,
        )
    ):
        return None
    matches: list[int] = []
    try:
        for residue in range(observation.modulus):
            verdict = observation.response_equal(
                observation.evaluate(residue, observation.auxiliary_point),
                observation.response,
            )
            if _strict_bool(verdict):
                matches.append(residue)
    except Exception:
        return None
    return (matches[0], observation.modulus) if len(matches) == 1 else None


def recover_invalid_isogeny_auxiliary_secret(
    observations: Iterable[AuxiliaryLeakObservation],
    secret_order: int,
    public_key: Any,
    public_action: Callable[[int], Any],
    *,
    public_equal: Callable[[Any, Any], bool] = lambda left, right: left == right,
    max_candidates: int = MAX_LEAK_CANDIDATES,
) -> Optional[int]:
    """CRT-combine unique auxiliary leaks and replay the original public action."""

    rows = _bounded(observations, MAX_TRANSCRIPT_ROWS)
    if (
        rows is None
        or not rows
        or not _plain_int(secret_order)
        or not (1 < secret_order <= _special.MAX_ORDER)
        or not _plain_int(max_candidates)
        or not (0 < max_candidates <= MAX_LEAK_CANDIDATES)
        or not callable(public_action)
        or not callable(public_equal)
    ):
        return None
    combined = (0, 1)
    for row in rows:
        residue = _recover_leak_residue(row)
        if residue is None:
            return None
        combined = _special._crt_merge(combined, residue)
        if combined is None:
            return None
    residue, modulus = combined
    first = residue
    count = 0 if first >= secret_order else 1 + (secret_order - 1 - first) // modulus
    if count == 0 or count > max_candidates:
        return None
    matches: list[int] = []
    try:
        for candidate in range(first, secret_order, modulus):
            if not _strict_bool(public_equal(public_action(candidate), public_key)):
                continue
            if all(
                _strict_bool(
                    row.response_equal(
                        row.evaluate(candidate % row.modulus, row.auxiliary_point),
                        row.response,
                    )
                )
                for row in rows
            ):
                matches.append(candidate)
    except Exception:
        return None
    return matches[0] if len(matches) == 1 else None


def recover_unique_isogeny_secret_path(
    source: Any,
    target: Any,
    neighbors: Callable[[Any], Iterable[tuple[Any, int, Any]]],
    edge_validator: Callable[[Any, Any, int, Any], bool],
    replay_path: Callable[[tuple[Any, ...], tuple[int, ...]], Any],
    expected_public: Any,
    *,
    public_equal: Callable[[Any, Any], bool] = lambda left, right: left == right,
    max_depth: int = 8,
    max_degree: int = 13,
    max_nodes: int = 4096,
) -> Optional[IsogenyPath]:
    """Return the sole replay-valid walk in the complete bounded graph.

    This intentionally does not stop at a unique shortest path.  A longer
    bounded path that produces the same public transcript is still ambiguous
    secret evidence and forces a decline.
    """

    if (
        not callable(neighbors)
        or not callable(edge_validator)
        or not callable(replay_path)
        or not callable(public_equal)
        or not _plain_int(max_depth)
        or not (1 <= max_depth <= 32)
        or not _plain_int(max_degree)
        or not (2 <= max_degree <= 64)
        or not _plain_int(max_nodes)
        or not (1 <= max_nodes <= 4096)
    ):
        return None
    try:
        if source == target:
            return None
        queue = deque([(source, (source,), (), ())])
        explored = 0
        matches: list[tuple[tuple[Any, ...], tuple[int, ...], tuple[Any, ...]]] = []
        while queue:
            node, nodes, degrees, proofs = queue.popleft()
            if node == target:
                if _strict_bool(
                    public_equal(replay_path(nodes, degrees), expected_public)
                ):
                    matches.append((nodes, degrees, proofs))
                    if len(matches) > 1:
                        return None
            if len(degrees) >= max_depth:
                continue
            edges = _bounded(neighbors(node), max_nodes)
            if edges is None:
                return None
            for edge in edges:
                explored += 1
                if explored > max_nodes:
                    return None
                if not isinstance(edge, tuple) or len(edge) != 3:
                    return None
                next_node, degree, proof = edge
                if not _plain_int(degree) or not (2 <= degree <= max_degree):
                    return None
                verdict = edge_validator(node, next_node, degree, proof)
                if not _strict_bool(verdict):
                    continue
                queue.append(
                    (
                        next_node,
                        nodes + (next_node,),
                        degrees + (degree,),
                        proofs + (proof,),
                    )
                )
        if len(matches) != 1:
            return None
        nodes, degrees, proofs = matches[0]
        # Replay both the edge evidence and the original public transcript at
        # emission time so stateful/failing callbacks cannot leave stale proof.
        for left, right, degree, proof in zip(
            nodes, nodes[1:], degrees, proofs
        ):
            if not _strict_bool(edge_validator(left, right, degree, proof)):
                return None
        if not _strict_bool(
            public_equal(replay_path(nodes, degrees), expected_public)
        ):
            return None
        return IsogenyPath(nodes, degrees, math.prod(degrees), True)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CSIDH toy action audits and exponent-vector recovery


@dataclass(frozen=True)
class CSIDHActionAudit:
    dimension: int
    search_space: int
    inverse_checks: int
    commutativity_checks: int
    verified: bool = True


def _csidh_parameters(
    primes: Iterable[int], bounds: Iterable[int]
) -> Optional[tuple[tuple[int, ...], tuple[int, ...], int]]:
    prime_rows = _bounded(primes, MAX_CSIDH_DIMENSION)
    bound_rows = _bounded(bounds, MAX_CSIDH_DIMENSION)
    if (
        prime_rows is None
        or bound_rows is None
        or not prime_rows
        or len(prime_rows) != len(bound_rows)
        or any(
            not _plain_int(prime)
            or prime == 2
            or not _special._is_prime(prime)
            for prime in prime_rows
        )
        or len(set(prime_rows)) != len(prime_rows)
        or any(not _plain_int(bound) or not (0 <= bound <= 8) for bound in bound_rows)
    ):
        return None
    work = math.prod(2 * bound + 1 for bound in bound_rows)
    if work > MAX_CSIDH_WORK:
        return None
    return tuple(prime_rows), tuple(bound_rows), work


def audit_csidh_toy_action(
    base_state: Any,
    primes: Iterable[int],
    bounds: Iterable[int],
    apply_action: Callable[[Any, int, int], Any],
    *,
    state_equal: Callable[[Any, Any], bool] = lambda left, right: left == right,
) -> Optional[CSIDHActionAudit]:
    """Audit action laws at every state reachable inside the exponent box."""

    parsed = _csidh_parameters(primes, bounds)
    if parsed is None or not callable(apply_action) or not callable(state_equal):
        return None
    prime_rows, bound_rows, work = parsed
    active = tuple(index for index, bound in enumerate(bound_rows) if bound)
    pairs = len(active) * (len(active) - 1) // 2
    # Count a conservative upper bound on callback invocations: two complete
    # vector replays, both inverse directions, and all signed commuting pairs
    # at every reachable vector.
    estimated_work = work * (
        2 * sum(bound_rows) + 1 + 6 * len(active) + 20 * pairs
    )
    if estimated_work > MAX_CSIDH_ACTION_WORK:
        return None
    inverse_checks = 0
    commutativity_checks = 0
    try:
        indices = tuple(range(len(prime_rows)))
        reverse_indices = tuple(reversed(indices))
        ranges = [range(-bound, bound + 1) for bound in bound_rows]
        for vector in itertools.product(*ranges):
            state = _apply_vector(base_state, vector, apply_action, indices)
            reverse_state = _apply_vector(
                base_state, vector, apply_action, reverse_indices
            )
            if not _strict_bool(state_equal(state, reverse_state)):
                return None
            for index in active:
                for direction in (-1, 1):
                    moved = apply_action(state, index, direction)
                    restored = apply_action(moved, index, -direction)
                    if not _strict_bool(state_equal(restored, state)):
                        return None
                    inverse_checks += 1
            for offset, left in enumerate(active):
                for right in active[offset + 1 :]:
                    for left_direction in (-1, 1):
                        for right_direction in (-1, 1):
                            first = apply_action(
                                apply_action(state, left, left_direction),
                                right,
                                right_direction,
                            )
                            second = apply_action(
                                apply_action(state, right, right_direction),
                                left,
                                left_direction,
                            )
                            if not _strict_bool(state_equal(first, second)):
                                return None
                            commutativity_checks += 1
    except Exception:
        return None
    return CSIDHActionAudit(
        len(prime_rows), work, inverse_checks, commutativity_checks, True
    )


def _apply_vector(
    state: Any,
    vector: Sequence[int],
    apply_action: Callable[[Any, int, int], Any],
    order: Sequence[int],
) -> Any:
    current = state
    for index in order:
        exponent = vector[index]
        direction = 1 if exponent >= 0 else -1
        for _ in range(abs(exponent)):
            current = apply_action(current, index, direction)
    return current


def recover_csidh_small_exponent_vector(
    base_state: Any,
    public_state: Any,
    primes: Iterable[int],
    bounds: Iterable[int],
    apply_action: Callable[[Any, int, int], Any],
    *,
    state_equal: Callable[[Any, Any], bool] = lambda left, right: left == right,
) -> Optional[tuple[int, ...]]:
    """Exhaust a capped toy exponent box and return one uniquely replayed vector."""

    parsed = _csidh_parameters(primes, bounds)
    if parsed is None:
        return None
    prime_rows, bound_rows, work = parsed
    active_count = sum(bound > 0 for bound in bound_rows)
    pairs = active_count * (active_count - 1) // 2
    audit_work = work * (
        2 * sum(bound_rows) + 1 + 6 * active_count + 20 * pairs
    )
    recovery_work = work * (4 * sum(bound_rows) + 4)
    if audit_work + recovery_work > MAX_CSIDH_ACTION_WORK:
        return None
    audit = audit_csidh_toy_action(
        base_state, prime_rows, bound_rows, apply_action, state_equal=state_equal
    )
    if audit is None:
        return None
    matches: list[tuple[int, ...]] = []
    indices = tuple(range(len(prime_rows)))
    reverse_indices = tuple(reversed(indices))
    try:
        ranges = [range(-bound, bound + 1) for bound in bound_rows]
        for vector in itertools.product(*ranges):
            forward = _apply_vector(base_state, vector, apply_action, indices)
            if not _strict_bool(state_equal(forward, public_state)):
                continue
            reverse = _apply_vector(base_state, vector, apply_action, reverse_indices)
            if not _strict_bool(state_equal(reverse, public_state)):
                continue
            inverse_vector = tuple(-value for value in vector)
            undo_forward = _apply_vector(
                public_state, inverse_vector, apply_action, reverse_indices
            )
            undo_reverse = _apply_vector(
                public_state, inverse_vector, apply_action, indices
            )
            if not _strict_bool(state_equal(undo_forward, base_state)):
                continue
            if not _strict_bool(state_equal(undo_reverse, base_state)):
                continue
            matches.append(tuple(vector))
            if len(matches) > 1:
                return None
    except Exception:
        return None
    return matches[0] if len(matches) == 1 else None


# ---------------------------------------------------------------------------
# Generic bilinear contexts and equations


@dataclass(frozen=True)
class BilinearContext:
    order: int
    g1: Any
    g2: Any
    g1_group: GroupOps
    g2_group: GroupOps
    target_group: GroupOps
    pairing: Callable[[Any, Any], Any]


@dataclass(frozen=True)
class BilinearContextAudit:
    order: int
    bilinearity_checks: int
    verified: bool = True


def audit_bilinear_context(context: BilinearContext) -> Optional[BilinearContextAudit]:
    if (
        not isinstance(context, BilinearContext)
        or not _plain_int(context.order)
        or not _special._is_prime(context.order)
        or context.order * context.order > MAX_PAIRING_SCALAR_WORK
        or not callable(context.pairing)
        or not _has_prime_order(context.g1, context.order, context.g1_group)
        or not _has_prime_order(context.g2, context.order, context.g2_group)
    ):
        return None
    checks = 0
    try:
        base = context.pairing(context.g1, context.g2)
        if not _has_prime_order(base, context.order, context.target_group):
            return None
        first_multiples = tuple(
            context.g1_group.power(context.g1, scalar)
            for scalar in range(context.order)
        )
        second_multiples = tuple(
            context.g2_group.power(context.g2, scalar)
            for scalar in range(context.order)
        )
        for left, first in enumerate(first_multiples):
            for right, second in enumerate(second_multiples):
                paired = context.pairing(first, second)
                expected = context.target_group.power(base, left * right)
                if not _same(context.target_group, paired, expected):
                    return None
                checks += 1
    except Exception:
        return None
    return BilinearContextAudit(context.order, checks, True)


def _declared_subgroup_scalar(
    element: Any, generator: Any, order: int, group: GroupOps
) -> Optional[int]:
    """Prove membership in the declared cyclic subgroup by full toy enumeration."""

    matches: list[int] = []
    try:
        for scalar in range(order):
            if _same(group, group.power(generator, scalar), element):
                matches.append(scalar)
                if len(matches) > 1:
                    return None
    except Exception:
        return None
    return matches[0] if len(matches) == 1 else None


def _verified_pairing_product(
    context: BilinearContext, rows: Sequence[tuple[Any, Any]]
) -> tuple[bool, Any]:
    """Pair declared-subgroup elements and replay the scalar pairing equation."""

    try:
        base = context.pairing(context.g1, context.g2)
        result = context.target_group.identity
        for first, second in rows:
            left = _declared_subgroup_scalar(
                first, context.g1, context.order, context.g1_group
            )
            right = _declared_subgroup_scalar(
                second, context.g2, context.order, context.g2_group
            )
            if left is None or right is None:
                return False, context.target_group.identity
            paired = context.pairing(first, second)
            expected = context.target_group.power(base, left * right)
            if not _same(context.target_group, paired, expected):
                return False, context.target_group.identity
            result = context.target_group.combine(result, paired)
        return True, result
    except Exception:
        return False, context.target_group.identity


def _verify_bilinear_equation_audited(
    context: BilinearContext,
    left: Sequence[tuple[Any, Any]],
    right: Sequence[tuple[Any, Any]],
) -> bool:
    if (
        context.order * context.order
        + (len(left) + len(right)) * context.order
        > MAX_PAIRING_TOTAL_WORK
    ):
        return False
    left_ok, left_product = _verified_pairing_product(context, left)
    right_ok, right_product = _verified_pairing_product(context, right)
    if not left_ok or not right_ok:
        return False
    try:
        return _same(context.target_group, left_product, right_product)
    except Exception:
        return False


def verify_bilinear_equation(
    context: BilinearContext,
    left_pairs: Iterable[tuple[Any, Any]],
    right_pairs: Iterable[tuple[Any, Any]],
) -> bool:
    """Check ``prod e(P_i,Q_i) == prod e(R_j,S_j)`` with subgroup validation."""

    if audit_bilinear_context(context) is None:
        return False
    left = _bounded(left_pairs, MAX_PAIRING_EQUATIONS)
    right = _bounded(right_pairs, MAX_PAIRING_EQUATIONS)
    if left is None or right is None or (not left and not right):
        return False
    return _verify_bilinear_equation_audited(context, left, right)


def bilinear_ddh_check(
    context: BilinearContext, a_g1: Any, b_g2: Any, ab_g1: Any
) -> bool:
    """Decide the asymmetric co-DDH equation ``e(aG1,bG2)=e(abG1,G2)``."""

    if not isinstance(context, BilinearContext):
        return False
    return verify_bilinear_equation(
        context, ((a_g1, b_g2),), ((ab_g1, context.g2),)
    )


def bilinear_co_ddh_check(
    context: BilinearContext, a_g1: Any, b_g2: Any, candidate_ab_g1: Any
) -> bool:
    """Explicit co-DDH spelling for :func:`bilinear_ddh_check`."""

    return bilinear_ddh_check(context, a_g1, b_g2, candidate_ab_g1)


def verify_co_cdh_candidate(
    context: BilinearContext, a_g1: Any, b_g2: Any, candidate_ab_g1: Any
) -> bool:
    """Verify a proposed co-CDH output through the non-degenerate pairing."""

    return bilinear_ddh_check(context, a_g1, b_g2, candidate_ab_g1)


def recover_unique_pairing_scalar(
    context: BilinearContext,
    public_element: Any,
    auxiliary: Any,
    *,
    source: str = "g1",
) -> Optional[int]:
    """Transfer a public DLP through a pairing, then replay it in the source group."""

    if audit_bilinear_context(context) is None or source not in ("g1", "g2"):
        return None
    if source == "g1":
        source_group, generator = context.g1_group, context.g1
        auxiliary_group, auxiliary_generator = context.g2_group, context.g2
        pair = lambda value: context.pairing(value, auxiliary)
    else:
        source_group, generator = context.g2_group, context.g2
        auxiliary_group, auxiliary_generator = context.g1_group, context.g1
        pair = lambda value: context.pairing(auxiliary, value)
    if (
        not _has_prime_order(public_element, context.order, source_group)
        or not _has_prime_order(auxiliary, context.order, auxiliary_group)
        or _declared_subgroup_scalar(
            public_element, generator, context.order, source_group
        )
        is None
        or _declared_subgroup_scalar(
            auxiliary, auxiliary_generator, context.order, auxiliary_group
        )
        is None
    ):
        return None
    try:
        base = pair(generator)
        target = pair(public_element)
        if not _has_prime_order(base, context.order, context.target_group):
            return None
        scalar = _special.verified_pohlig_hellman(
            base, target, context.order, context.target_group
        )
        if scalar is None:
            return None
        if not _same(source_group, source_group.power(generator, scalar), public_element):
            return None
        if not _same(context.target_group, context.target_group.power(base, scalar), target):
            return None
        return scalar
    except Exception:
        return None


# ---------------------------------------------------------------------------
# BLS aggregate / rogue-key / duplicate-message structure


def _message(value: Any) -> Optional[bytes]:
    if isinstance(value, bytearray):
        value = bytes(value)
    return value if isinstance(value, bytes) and len(value) <= MAX_MESSAGE_BYTES else None


def verify_bls_signature(
    context: BilinearContext,
    signature: Any,
    public_key: Any,
    message: Any,
    hash_to_g1: Callable[[bytes], Any],
) -> bool:
    if audit_bilinear_context(context) is None or not callable(hash_to_g1):
        return False
    encoded = _message(message)
    if encoded is None:
        return False
    try:
        hashed = hash_to_g1(encoded)
        if not _has_prime_order(signature, context.order, context.g1_group):
            return False
        if not _has_prime_order(public_key, context.order, context.g2_group):
            return False
        if not _has_prime_order(hashed, context.order, context.g1_group):
            return False
        return _verify_bilinear_equation_audited(
            context,
            ((signature, context.g2),),
            ((hashed, public_key),),
        )
    except Exception:
        return False


def _verify_bls_aggregate_rows(
    context: BilinearContext,
    aggregate_signature: Any,
    keys: Sequence[Any],
    messages: Sequence[bytes],
    hash_to_g1: Callable[[bytes], Any],
) -> bool:
    """Verify already-bounded rows under an already-audited context."""

    if not _has_prime_order(
        aggregate_signature, context.order, context.g1_group
    ):
        return False
    right: list[tuple[Any, Any]] = []
    try:
        for key, message in zip(keys, messages):
            if not _has_prime_order(key, context.order, context.g2_group):
                return False
            hashed = hash_to_g1(message)
            if not _has_prime_order(hashed, context.order, context.g1_group):
                return False
            right.append((hashed, key))
    except Exception:
        return False
    return _verify_bilinear_equation_audited(
        context, ((aggregate_signature, context.g2),), right
    )


def verify_bls_aggregate_equation(
    context: BilinearContext,
    aggregate_signature: Any,
    public_keys: Iterable[Any],
    messages: Iterable[Any],
    hash_to_g1: Callable[[bytes], Any],
) -> bool:
    keys = _bounded(public_keys, MAX_BLS_PARTICIPANTS)
    message_rows = _bounded_messages(messages, MAX_BLS_PARTICIPANTS)
    if (
        keys is None
        or message_rows is None
        or not keys
        or len(keys) != len(message_rows)
        or audit_bilinear_context(context) is None
        or not callable(hash_to_g1)
    ):
        return False
    return _verify_bls_aggregate_rows(
        context, aggregate_signature, keys, message_rows, hash_to_g1
    )


@dataclass(frozen=True)
class BLSAggregateAudit:
    participants: int
    duplicate_messages: tuple[tuple[int, int], ...]
    proof_of_possession_checked: bool
    rogue_key_risk: bool
    verified: bool = True


def audit_bls_aggregate(
    context: BilinearContext,
    aggregate_signature: Any,
    public_keys: Iterable[Any],
    messages: Iterable[Any],
    hash_to_g1: Callable[[bytes], Any],
    *,
    pop_proofs: Optional[Iterable[Any]] = None,
    pop_verifier: Optional[Callable[[Any, Any], bool]] = None,
) -> Optional[BLSAggregateAudit]:
    keys = _bounded(public_keys, MAX_BLS_PARTICIPANTS)
    encoded = _bounded_messages(messages, MAX_BLS_PARTICIPANTS)
    if keys is None or encoded is None or not keys or len(keys) != len(encoded):
        return None
    if audit_bilinear_context(context) is None or not callable(hash_to_g1):
        return None
    if not _verify_bls_aggregate_rows(
        context, aggregate_signature, keys, encoded, hash_to_g1
    ):
        return None
    duplicates = tuple(
        (left, right)
        for left in range(len(encoded))
        for right in range(left + 1, len(encoded))
        if encoded[left] == encoded[right]
    )
    pop_checked = False
    if pop_proofs is not None or pop_verifier is not None:
        proofs = _bounded(pop_proofs, MAX_BLS_PARTICIPANTS) if pop_proofs is not None else None
        if proofs is None or len(proofs) != len(keys) or not callable(pop_verifier):
            return None
        try:
            if not all(
                _strict_bool(pop_verifier(key, proof))
                for key, proof in zip(keys, proofs)
            ):
                return None
        except Exception:
            return None
        pop_checked = True
    return BLSAggregateAudit(
        len(keys), duplicates, pop_checked, bool(duplicates and not pop_checked), True
    )


@dataclass(frozen=True)
class BLSRogueKeyWitness:
    rogue_public_key: Any
    aggregate_signature: Any
    attacker_total_public: Any
    verified: bool = True


def build_bls_rogue_key_witness(
    context: BilinearContext,
    victim_public_key: Any,
    attacker_scalar: int,
    message: Any,
    hash_to_g1: Callable[[bytes], Any],
) -> Optional[BLSRogueKeyWitness]:
    """Build a toy same-message rogue-key witness and verify its aggregate equation."""

    encoded = _message(message)
    if (
        encoded is None
        or not isinstance(context, BilinearContext)
        or not _plain_int(attacker_scalar)
        or audit_bilinear_context(context) is None
        or not (0 < attacker_scalar < context.order)
        or not _has_prime_order(victim_public_key, context.order, context.g2_group)
        or _declared_subgroup_scalar(
            victim_public_key, context.g2, context.order, context.g2_group
        )
        is None
        or not callable(hash_to_g1)
    ):
        return None
    try:
        attacker_total = context.g2_group.power(context.g2, attacker_scalar)
        rogue = context.g2_group.combine(
            attacker_total, context.g2_group.inverse(victim_public_key)
        )
        hashed = hash_to_g1(encoded)
        aggregate = context.g1_group.power(hashed, attacker_scalar)
        if not _has_prime_order(rogue, context.order, context.g2_group):
            return None
        if not _verify_bls_aggregate_rows(
            context,
            aggregate,
            (victim_public_key, rogue),
            (encoded, encoded),
            hash_to_g1,
        ):
            return None
        if not _same(
            context.g2_group,
            context.g2_group.combine(victim_public_key, rogue),
            attacker_total,
        ):
            return None
        return BLSRogueKeyWitness(rogue, aggregate, attacker_total, True)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Reused nonce/scalar in pairing-adjacent Schnorr proofs


@dataclass(frozen=True)
class LinearProof:
    commitment: Any
    response: int
    challenge: int


def _verify_linear_proof(
    proof: LinearProof, public_key: Any, generator: Any, order: int, group: GroupOps
) -> bool:
    if (
        not isinstance(proof, LinearProof)
        or not _plain_int(proof.response)
        or not _plain_int(proof.challenge)
        or not (0 <= proof.response < order)
        or not (0 <= proof.challenge < order)
        or not _in_subgroup(proof.commitment, order, group)
    ):
        return False
    try:
        left = group.power(generator, proof.response)
        right = group.combine(
            proof.commitment, group.power(public_key, proof.challenge)
        )
        return _same(group, left, right)
    except Exception:
        return False


def recover_reused_linear_proof_scalar(
    proof1: LinearProof,
    proof2: LinearProof,
    public_key: Any,
    generator: Any,
    order: int,
    group: GroupOps,
) -> Optional[int]:
    """Recover a Schnorr-style scalar from a reused commitment, with replay."""

    if (
        not _special._is_prime(order)
        or not _has_prime_order(generator, order, group)
        or not _has_prime_order(public_key, order, group)
        or not _verify_linear_proof(proof1, public_key, generator, order, group)
        or not _verify_linear_proof(proof2, public_key, generator, order, group)
    ):
        return None
    try:
        if not _same(group, proof1.commitment, proof2.commitment):
            return None
        denominator = (proof1.challenge - proof2.challenge) % order
        if denominator == 0:
            return None
        scalar = (
            (proof1.response - proof2.response)
            * pow(denominator, -1, order)
        ) % order
        nonce1 = (proof1.response - proof1.challenge * scalar) % order
        nonce2 = (proof2.response - proof2.challenge * scalar) % order
        if nonce1 != nonce2:
            return None
        if not _same(group, group.power(generator, nonce1), proof1.commitment):
            return None
        if not _same(group, group.power(generator, scalar), public_key):
            return None
        return scalar
    except Exception:
        return None


# ---------------------------------------------------------------------------
# IBE identity/domain separation and ephemeral-reuse structure


@dataclass(frozen=True)
class IBETranscript:
    identity: bytes
    domain: bytes
    identity_point: Any
    ephemeral_public: Any


@dataclass(frozen=True)
class IBEAudit:
    transcripts: int
    identity_point_collisions: tuple[tuple[int, int], ...]
    domain_separation_failures: tuple[tuple[int, int], ...]
    ephemeral_reuse: tuple[tuple[int, int], ...]
    verified: bool = True


def audit_ibe_structure(
    transcripts: Iterable[IBETranscript],
    group: GroupOps,
    order: int,
    hash_identity: Callable[[bytes, bytes], Any],
) -> Optional[IBEAudit]:
    rows = _bounded(transcripts, MAX_IBE_TRANSCRIPTS)
    if (
        rows is None
        or not rows
        or not _special._is_prime(order)
        or not callable(hash_identity)
        or any(not isinstance(row, IBETranscript) for row in rows)
    ):
        return None
    try:
        normalized: list[tuple[bytes, bytes]] = []
        total_bytes = 0
        for row in rows:
            identity = _message(row.identity)
            domain = _message(row.domain)
            if identity is None or domain is None:
                return None
            total_bytes += len(identity) + len(domain)
            if total_bytes > MAX_TOTAL_MESSAGE_BYTES:
                return None
            normalized.append((identity, domain))
            expected = hash_identity(domain, identity)
            if not _has_prime_order(expected, order, group):
                return None
            if not _same(group, expected, row.identity_point):
                return None
            if not _has_prime_order(row.ephemeral_public, order, group):
                return None
        collisions: list[tuple[int, int]] = []
        domain_failures: list[tuple[int, int]] = []
        reuse: list[tuple[int, int]] = []
        for left in range(len(rows)):
            for right in range(left + 1, len(rows)):
                if _same(group, rows[left].identity_point, rows[right].identity_point):
                    if (
                        normalized[left][0] != normalized[right][0]
                        or normalized[left][1] != normalized[right][1]
                    ):
                        collisions.append((left, right))
                    if (
                        normalized[left][0] == normalized[right][0]
                        and normalized[left][1] != normalized[right][1]
                    ):
                        domain_failures.append((left, right))
                if _same(
                    group, rows[left].ephemeral_public, rows[right].ephemeral_public
                ):
                    reuse.append((left, right))
        return IBEAudit(
            len(rows), tuple(collisions), tuple(domain_failures), tuple(reuse), True
        )
    except Exception:
        return None


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def recover_ibe_reused_ephemeral_message(
    known_transcript: IBETranscript,
    target_transcript: IBETranscript,
    known_plaintext: Any,
    known_ciphertext: Any,
    target_ciphertext: Any,
    group: GroupOps,
    order: int,
    hash_identity: Callable[[bytes, bytes], Any],
    *,
    message_verifier: Optional[Callable[[bytes], bool]] = None,
    negative_control: Any = None,
) -> Optional[bytes]:
    """Recover a same-identity two-time-pad message and replay both XOR equations.

    Algebraic uniqueness requires the known plaintext to expose a keystream
    prefix at least as long as the target ciphertext.  Shorter prefixes decline.
    A strict original-problem verifier and a caller-supplied known-invalid
    negative control are mandatory.  This prevents the two algebraically
    tautological XOR replays from being treated as independent evidence.
    """

    if not isinstance(known_transcript, IBETranscript) or not isinstance(
        target_transcript, IBETranscript
    ):
        return None
    if not all(
        isinstance(value, (bytes, bytearray))
        for value in (known_plaintext, known_ciphertext, target_ciphertext)
    ) or not isinstance(negative_control, (bytes, bytearray)):
        return None
    if not callable(message_verifier):
        return None
    known_plaintext = bytes(known_plaintext)
    known_ciphertext = bytes(known_ciphertext)
    target_ciphertext = bytes(target_ciphertext)
    negative_control = bytes(negative_control)
    if (
        max(
            len(known_plaintext),
            len(known_ciphertext),
            len(target_ciphertext),
            len(negative_control),
        )
        > MAX_MESSAGE_BYTES
        or sum(
            map(
                len,
                (
                    known_plaintext,
                    known_ciphertext,
                    target_ciphertext,
                    negative_control,
                ),
            )
        )
        > MAX_TOTAL_MESSAGE_BYTES
        or len(known_plaintext) != len(known_ciphertext)
        or len(target_ciphertext) > len(known_ciphertext)
        or known_transcript.identity != target_transcript.identity
        or known_transcript.domain != target_transcript.domain
        or audit_ibe_structure(
            (known_transcript, target_transcript), group, order, hash_identity
        )
        is None
    ):
        return None
    try:
        if not _same(
            group,
            known_transcript.ephemeral_public,
            target_transcript.ephemeral_public,
        ):
            return None
        pad = _xor(known_plaintext, known_ciphertext)
        recovered = _xor(target_ciphertext, pad[: len(target_ciphertext)])
        if _xor(known_plaintext, pad) != known_ciphertext:
            return None
        if _xor(recovered, pad[: len(recovered)]) != target_ciphertext:
            return None
        if negative_control == recovered:
            return None
        if not _strict_bool(message_verifier(recovered)):
            return None
        if _strict_bool(message_verifier(negative_control)):
            return None
        return recovered
    except Exception:
        return None


__all__ = [
    "AuxiliaryLeakObservation",
    "BLSAggregateAudit",
    "BLSRogueKeyWitness",
    "BilinearContext",
    "BilinearContextAudit",
    "CSIDHActionAudit",
    "GroupOps",
    "IBEAudit",
    "IBETranscript",
    "IsogenyPath",
    "LinearProof",
    "SIDHPublicTranscriptAudit",
    "SIKEPublicKEMAudit",
    "TorsionBasisAudit",
    "audit_bilinear_context",
    "audit_bls_aggregate",
    "audit_csidh_toy_action",
    "audit_ibe_structure",
    "audit_sidh_public_transcript",
    "audit_sike_public_kem_structure",
    "audit_torsion_basis",
    "bilinear_ddh_check",
    "bilinear_co_ddh_check",
    "build_bls_rogue_key_witness",
    "recover_csidh_small_exponent_vector",
    "recover_ibe_reused_ephemeral_message",
    "recover_invalid_isogeny_auxiliary_secret",
    "recover_reused_linear_proof_scalar",
    "recover_unique_isogeny_secret_path",
    "recover_unique_pairing_scalar",
    "verify_bilinear_equation",
    "verify_co_cdh_candidate",
    "verify_bls_aggregate_equation",
    "verify_bls_signature",
]
