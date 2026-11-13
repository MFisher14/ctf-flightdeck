from __future__ import annotations

import dataclasses
import itertools
import sys
from collections.abc import Sequence
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import exotic_ecc as ecc  # noqa: E402


PAYLOAD = b"CSCTF{exotic_ecc_depth}"


def _flip(bits: tuple[int, ...], *indices: int) -> tuple[int, ...]:
    changed = list(bits)
    for index in indices:
        changed[index] ^= 1
    return tuple(changed)


def test_bit_helpers_are_strict_and_byte_aligned() -> None:
    bits = ecc.bytes_to_bits(b"\xa5")
    assert bits == (1, 0, 1, 0, 0, 1, 0, 1)
    assert ecc.bits_to_bytes(bits) == b"\xa5"
    assert ecc.bits_to_bytes([0, 1, 0]) is None
    assert ecc.bits_to_bytes([0, True, 0, 0, 0, 0, 0, 0]) is None
    assert ecc.bytes_to_bits("not bytes") is None


def test_general_extended_hamming_blocks_and_double_error_decline() -> None:
    for m in (3, 4, 5):
        k = (1 << m) - m - 1
        data = tuple((index * 3 + 1) & 1 for index in range(k))
        word = ecc.extended_hamming_encode_block(data, m=m)
        assert word is not None and ecc.extended_hamming_decode_block(word, m=m) == data
        for bit in range(len(word)):
            assert ecc.extended_hamming_decode_block(_flip(word, bit), m=m) == data
        assert ecc.extended_hamming_decode_block(_flip(word, 1, 4), m=m) is None

    assert ecc.extended_hamming_encode_block([0] * 10, m=4) is None
    assert ecc.extended_hamming_decode_block([0] * 16, m=True) is None
    assert ecc.extended_hamming_decode_block([0, 2] + [0] * 14, m=4) is None


def test_general_extended_hamming_framed_crc_proves_payload() -> None:
    encoded = ecc.extended_hamming_encode(PAYLOAD, m=4)
    assert encoded is not None and ecc.extended_hamming_decode(encoded, m=4) == PAYLOAD
    corrected = list(encoded)
    for offset in range(0, min(len(corrected), 16 * 5), 16):
        corrected[offset + 3] ^= 1
    assert ecc.extended_hamming_decode(tuple(corrected), m=4) == PAYLOAD
    assert ecc.extended_hamming_decode(_flip(encoded, 2, 5), m=4) is None
    assert ecc.extended_hamming_decode(encoded[:-1], m=4) is None


def test_golay_polynomial_known_vectors_and_minimum_distance() -> None:
    assert ecc.golay24_encode_word(0) == 0
    assert ecc.golay24_encode_word(1) == 0x0015C7
    assert ecc.golay24_encode_word(0xFFF) == 0xFFFFFF
    weights = [ecc.golay24_encode_word(message).bit_count() for message in range(1, 1 << 12)]
    assert min(weights) == 8
    for message in (1, 2, 0x123, 0xACE, 0xFFF):
        word = ecc.golay24_encode_word(message)
        cyclic = word >> 1
        assert ecc._poly_remainder(cyclic, ecc._GOLAY_GENERATOR) == 0
        assert word.bit_count() % 2 == 0


def test_golay_corrects_three_and_declines_outside_radius() -> None:
    message = 0xA53
    word = ecc.golay24_encode_word(message)
    assert ecc.golay24_decode_word(word) == (message, 0)
    for errors in ((0,), (1, 17), (2, 9, 23)):
        damaged = word
        for bit in errors:
            damaged ^= 1 << bit
        assert ecc.golay24_decode_word(damaged) == (message, len(errors))
    damaged = word ^ sum(1 << bit for bit in (0, 1, 2, 3))
    assert ecc.golay24_decode_word(damaged) is None
    assert ecc.golay24_decode_word(True) is None
    assert ecc.golay24_decode_word(1 << 24) is None


def test_golay_framed_payload_correction_and_crc_decline() -> None:
    encoded = ecc.golay24_encode(PAYLOAD)
    assert encoded is not None and ecc.golay24_decode(encoded) == PAYLOAD
    corrected = _flip(encoded, 0, 5, 11, 24 + 3, 24 + 9)
    assert ecc.golay24_decode(corrected) == PAYLOAD
    assert ecc.golay24_decode(_flip(encoded, 0, 1, 2, 3)) is None
    assert ecc.golay24_decode(encoded + (0,)) is None


def test_reed_muller_rm1_exhaustive_small_code_and_radius() -> None:
    m = 3
    words: set[tuple[int, ...]] = set()
    for message in itertools.product((0, 1), repeat=m + 1):
        word = ecc.reed_muller_encode_block(message, m=m)
        assert word is not None and word not in words
        words.add(word)
        assert ecc.reed_muller_decode_block(word, m=m) == message
        for bit in range(len(word)):
            assert ecc.reed_muller_decode_block(_flip(word, bit), m=m) == message
    assert min(sum(a != b for a, b in zip(left, right))
               for index, left in enumerate(words)
               for right in tuple(words)[index + 1:]) == 4
    word = ecc.reed_muller_encode_block((1, 0, 1, 1), m=3)
    assert ecc.reed_muller_decode_block(_flip(word, 0, 1), m=3) is None
    assert ecc.reed_muller_decode_block([0] * 7, m=3) is None


def test_reed_muller_framed_payload_and_overradius_decline() -> None:
    encoded = ecc.reed_muller_encode(PAYLOAD, m=5)
    assert encoded is not None and ecc.reed_muller_decode(encoded, m=5) == PAYLOAD
    corrected = _flip(encoded, 0, 2, 4, 6, 8, 10, 12)
    assert ecc.reed_muller_decode(corrected, m=5) == PAYLOAD
    assert ecc.reed_muller_decode(_flip(encoded, 0, 1, 2, 3, 4, 5, 6, 7), m=5) is None
    assert ecc.reed_muller_decode(encoded[:-1], m=5) is None


def test_lt_systematic_and_fountain_equations_recover_and_verify() -> None:
    bundle = ecc.lt_encode(PAYLOAD, block_size=5, packet_count=40, seed=91)
    assert bundle is not None and bundle.source_count > 1
    assert ecc.lt_decode(bundle) == PAYLOAD

    # Remove several systematic packets. Robust-soliton equations still have full rank.
    reduced = ecc.LTBundle(bundle.source_count, bundle.block_size, bundle.packets[5:])
    assert ecc.lt_decode(reduced) == PAYLOAD

    serialized = ecc.serialize_lt(reduced)
    assert serialized is not None
    parsed = ecc.parse_lt(serialized)
    assert parsed == reduced
    assert ecc.decode_lt(serialized) == PAYLOAD


def test_lt_packet_checksum_conflict_rank_and_container_declines() -> None:
    bundle = ecc.lt_encode(PAYLOAD, block_size=4, packet_count=50, seed=12)
    assert bundle is not None
    first = bundle.packets[0]
    changed_payload = bytes([first.payload[0] ^ 1]) + first.payload[1:]
    bad_checksum = dataclasses.replace(first, payload=changed_payload)
    assert ecc.lt_decode(dataclasses.replace(bundle, packets=(bad_checksum,) + bundle.packets[1:])) is None

    # A forged but internally checksummed contradictory duplicate is rejected by equation consistency.
    checksum = ecc._packet_checksum(bundle.source_count, bundle.block_size, first.seed,
                                    first.indices, changed_payload)
    contradictory = ecc.LTPacket(first.seed, first.indices, changed_payload, checksum)
    conflict = dataclasses.replace(bundle, packets=bundle.packets + (contradictory,))
    assert ecc.lt_decode(conflict) is None

    rank_deficient = dataclasses.replace(bundle, packets=bundle.packets[:bundle.source_count])
    rank_deficient = dataclasses.replace(rank_deficient, packets=rank_deficient.packets[1:])
    assert ecc.lt_decode(rank_deficient) is None

    raw = ecc.serialize_lt(bundle)
    assert raw is not None
    assert ecc.parse_lt(raw[:-1]) is None
    assert ecc.parse_lt(raw + b"x") is None
    assert ecc.decode_lt(b"not an LT artifact") is None


def test_lt_wrong_types_forged_records_and_caps_decline() -> None:
    bundle = ecc.lt_encode(PAYLOAD, block_size=4)
    assert bundle is not None
    packet = bundle.packets[0]
    assert ecc.lt_decode(dataclasses.replace(bundle, source_count=True)) is None
    assert ecc.lt_decode(dataclasses.replace(bundle, block_size=0)) is None
    assert ecc.lt_decode(dataclasses.replace(bundle, packets=list(bundle.packets))) is None
    assert ecc.lt_decode(dataclasses.replace(bundle, packets=(dataclasses.replace(packet, indices=(0, 0)),)
                                                             + bundle.packets[1:])) is None
    assert ecc.lt_decode(dataclasses.replace(bundle, packets=(dataclasses.replace(packet, indices=(-1,)),)
                                                             + bundle.packets[1:])) is None
    assert ecc.lt_decode(dataclasses.replace(bundle, packets=(dataclasses.replace(packet, checksum=True),)
                                                             + bundle.packets[1:])) is None
    assert ecc.lt_encode(PAYLOAD, block_size=True) is None
    assert ecc.lt_encode(PAYLOAD, block_size=4, packet_count=1) is None
    assert ecc.lt_encode(PAYLOAD, seed=-1) is None
    assert ecc.parse_lt(None) is None


class _RaisingSequence(Sequence):
    def __len__(self):
        return 16

    def __getitem__(self, index):
        raise RuntimeError("broken sequence")


class _DishonestSequence(Sequence):
    def __len__(self):
        return 8

    def __getitem__(self, index):
        return 0

    def __iter__(self):
        while True:
            yield 0


def test_public_sequences_and_aggregate_caps_fail_closed(monkeypatch) -> None:
    broken = _RaisingSequence()
    assert ecc.bits_to_bytes(broken) is None
    assert ecc.bits_to_bytes(_DishonestSequence()) is None
    assert ecc.extended_hamming_decode_block(broken, m=4) is None
    assert ecc.extended_hamming_decode(broken, m=4) is None

    monkeypatch.setattr(ecc, "MAX_CODEWORDS", 1)
    assert ecc.golay24_encode(PAYLOAD) is None
    monkeypatch.setattr(ecc, "MAX_LT_ARTIFACT", 32)
    assert ecc.lt_encode(PAYLOAD, block_size=4) is None


def test_lt_uint64_seed_wrap_and_index_types() -> None:
    for seed in (2**64 - 1, 2**64 - 2, 2**64 - 10, 2**64 - 100):
        bundle = ecc.lt_encode(PAYLOAD, block_size=3, packet_count=40, seed=seed)
        assert bundle is not None and ecc.lt_decode(bundle) == PAYLOAD
        for number, packet in enumerate(bundle.packets[bundle.source_count:], bundle.source_count):
            derived = (packet.seed + bundle.source_count) & 0xFFFFFFFFFFFFFFFF
            assert packet.indices == ecc._lt_indices(bundle.source_count, derived,
                                                     allow_systematic=False)
    assert ecc._lt_indices(True, 0) is None
    assert ecc._lt_indices(4, 1.2) is None
    assert ecc._lt_indices(4, 1, c=float("nan")) is None
    assert ecc._lt_indices(4, 1, allow_systematic=1) is None

