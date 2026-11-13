"""Deterministic success and ambiguity tests for r5c hash structures."""

from __future__ import annotations

import hashlib
import importlib
import itertools
from pathlib import Path
import random
import sys


COMMON = Path(__file__).resolve().parents[1] / "solvers" / "common"
sys.path.insert(0, str(COMMON))

import hash_structures as attack  # noqa: E402
import oracle_aead as existing_oracles  # noqa: E402


def test_package_and_direct_imports_agree():
    packaged = importlib.import_module("solvers.common.hash_structures")
    assert packaged.crc_msb(b"123456789", 8, 0x07) == attack.crc_msb(
        b"123456789", 8, 0x07
    )
    assert set(packaged.__all__) == set(attack.__all__)


def test_chosen_prefix_collision_unique_bridge_and_ambiguity_decline():
    # Toy digest deliberately exposes a collision for one supplied bridge.
    digest = lambda message: bytes([sum(message) % 17])
    result = attack.recover_chosen_prefix_collision(
        b"LEFT:",
        b"RIGHT:",
        [(b"A", b"2"), (b"bad", b"worse")],
        digest,
        verify=lambda left, right, value: digest(left) == digest(right) == value,
    )
    assert result is not None
    assert result.left_message != result.right_message
    assert digest(result.left_message) == digest(result.right_message) == result.digest

    constant = lambda _message: b"same"
    assert attack.recover_chosen_prefix_collision(
        b"a", b"b", [(b"1", b"1"), (b"2", b"2")], constant
    ) is None
    assert attack.recover_chosen_prefix_collision(
        b"same", b"same", [(b"1", b"2")], constant
    ) is None


def test_verified_multicollision_replays_every_path_and_declines_bad_pair():
    # Compression ignores the low bit, giving paired blocks a controlled collision.
    compress = lambda state, block: (state * 5 + (block[0] >> 1)) % 257
    pairs = [(bytes([2]), bytes([3])), (bytes([8]), bytes([9])), (bytes([20]), bytes([21]))]
    result = attack.build_verified_multicollision(7, pairs, compress)
    assert result is not None and len(result.messages) == 8
    assert len(set(result.messages)) == 8
    for message in result.messages:
        state = 7
        for block in message:
            state = compress(state, bytes([block]))
        assert state == result.final_state

    assert attack.build_verified_multicollision(
        7, [(b"x", b"x")], compress
    ) is None
    assert attack.build_verified_multicollision(
        7, [(b"\x02", b"\x04")], compress
    ) is None
    assert attack.build_verified_multicollision(
        7, [(b"a" * 4097, b"b" * 4097)], compress
    ) is None


def _poly_tag(blocks, key=(37, 19), modulus=257):
    return attack.polynomial_hash(blocks, key[0], modulus, offset=key[1])


def test_polynomial_hash_key_recovery_forgery_and_ambiguity_decline():
    observations = [
        ((1, 2, 3), _poly_tag((1, 2, 3))),
        ((7, 11), _poly_tag((7, 11))),
        ((9, 8, 7, 6), _poly_tag((9, 8, 7, 6))),
    ]
    assert attack.recover_polynomial_hash_key(observations, 257) == (37, 19)

    verify = lambda blocks, tag: _poly_tag(tuple(blocks)) == tag
    forged = attack.forge_polynomial_hash(observations, (42, 99), 257, verify)
    assert forged == (_poly_tag((42, 99)), 37, 19)
    assert attack.forge_polynomial_hash(
        observations, (42, 99), 257, lambda _blocks, _tag: True
    ) is None

    # Equal one-block observations leave every multiplier possible.
    ambiguous = [((5,), 12), ((5,), 12)]
    assert attack.recover_polynomial_hash_key(ambiguous, 257) is None
    tampered = observations[:-1] + [(observations[-1][0], observations[-1][1] ^ 1)]
    assert attack.recover_polynomial_hash_key(tampered, 257) is None
    assert attack.forge_polynomial_hash(observations, (1,), "257", verify) is None


def test_crc_known_vector_unique_patch_and_rank_ambiguity_decline():
    assert attack.crc_msb(b"123456789", 8, 0x07) == 0xF4
    original = b"role=user;X"
    target = 0xA5
    verify = lambda message, checksum: attack.crc_msb(message, 8, 0x07) == checksum
    forged = attack.forge_crc_patch(
        original, target, len(original) - 1, 1, 8, 0x07, verify=verify
    )
    assert forged is not None
    assert forged[:-1] == original[:-1]
    assert attack.crc_msb(forged, 8, 0x07) == target

    # Sixteen patch bits for an eight-bit CRC have a non-trivial nullspace.
    assert attack.forge_crc_patch(
        b"prefix??suffix", target, 6, 2, 8, 0x07
    ) is None
    assert attack.forge_crc_patch(
        original, target, len(original) - 1, 1, 8, 0x07,
        verify=lambda _message, _checksum: True,
    ) is None


def test_length_extension_stays_in_existing_oracle_module():
    secret, message, append = b"key", b"a=1", b"&admin=1"
    digest = hashlib.sha256(secret + message).digest()
    verify = lambda candidate, tag: hashlib.sha256(secret + candidate).digest() == tag
    result = existing_oracles.forge_prefix_mac_length_extension(
        "sha256", digest, message, append, range(1, 8), verify
    )
    assert result is not None and result[2] == len(secret)


def test_iterators_and_aggregate_work_are_bounded_and_fail_closed():
    digest = lambda message: bytes([sum(message) % 17])
    assert attack.recover_chosen_prefix_collision(
        b"a", b"b", itertools.repeat((b"x", b"y")), digest
    ) is None
    assert attack.recover_polynomial_hash_key(
        itertools.repeat(((1,), 1)), 257
    ) is None

    def broken():
        yield (b"x", b"y")
        raise RuntimeError("malformed iterator")

    assert attack.recover_chosen_prefix_collision(b"a", b"b", broken(), digest) is None
    large = b"z" * (9 * 1024 * 1024)
    assert attack.forge_crc_patch(large, 0, 0, 1, 8, 0x07) is None
    assert attack.build_verified_multicollision(
        0,
        [(b"a" * 4096, b"b" * 4096)] * 12,
        lambda _state, _block: 0,
    ) is None


def test_seeded_polynomial_and_crc_recoveries_match_exhaustive_oracles():
    rng = random.Random(0x5C7F)
    for _case in range(40):
        modulus = rng.choice((5, 7, 11, 13, 17, 19))
        key = rng.randrange(1, modulus), rng.randrange(modulus)
        observations = []
        for _ in range(rng.randint(2, 4)):
            blocks = tuple(
                rng.randrange(modulus) for _ in range(rng.randint(1, 4))
            )
            observations.append(
                (
                    blocks,
                    attack.polynomial_hash(
                        blocks, key[0], modulus, offset=key[1]
                    ),
                )
            )
        truth = [
            (multiplier, offset)
            for multiplier in range(1, modulus)
            for offset in range(modulus)
            if all(
                attack.polynomial_hash(
                    blocks, multiplier, modulus, offset=offset
                )
                == tag
                for blocks, tag in observations
            )
        ]
        expected = truth[0] if len(truth) == 1 else None
        assert attack.recover_polynomial_hash_key(observations, modulus) == expected

    for _case in range(40):
        width = rng.randrange(3, 9)
        polynomial = rng.randrange(1, 1 << width)
        message = bytes(rng.randrange(256) for _ in range(4))
        target = rng.randrange(1 << width)
        truth = [
            message[:2] + bytes([patch]) + message[3:]
            for patch in range(256)
            if attack.crc_msb(
                message[:2] + bytes([patch]) + message[3:], width, polynomial
            )
            == target
        ]
        expected = truth[0] if len(truth) == 1 else None
        assert (
            attack.forge_crc_patch(
                message, target, 2, 1, width, polynomial
            )
            == expected
        )
