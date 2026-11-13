from __future__ import annotations

import importlib.util
import itertools
import sys
import zlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import ecc as ecc  # noqa: E402


PAYLOAD = b"CSCTF{checked_ecc}"


def test_bit_helpers_are_msb_first_and_reject_nonbits():
    assert ecc.bytes_to_bits(b"\xa1") == [1, 0, 1, 0, 0, 0, 0, 1]
    assert ecc.bits_to_bytes([1, 0, 1, 0, 0, 0, 0, 1]) == b"\xa1"
    assert ecc.bits_to_bytes([1, 0, 1]) == b"\xa0"
    with pytest.raises(ValueError):
        ecc.bits_to_bytes([0, 2])


def test_extended_hamming_corrects_singles_and_declines_doubles():
    encoded = bytearray(ecc.hamming_secded_encode(PAYLOAD))
    assert ecc.hamming_secded_decode(encoded) == PAYLOAD

    encoded[0] ^= 1 << 2
    encoded[7] ^= 1 << 7
    assert ecc.hamming_secded_decode(encoded) == PAYLOAD

    damaged = bytearray(ecc.hamming_secded_encode(PAYLOAD))
    damaged[3] ^= (1 << 1) | (1 << 4)
    assert ecc.hamming_secded_decode(damaged) is None
    assert ecc.hamming_secded_decode(b"\0") is None


def test_raw_hamming_api_needs_no_synthetic_frame_and_preserves_nibbles():
    raw = bytearray(ecc.hamming84_encode_raw(b"raw"))
    for bit in range(8):
        damaged = raw[:]
        damaged[0] ^= 1 << bit
        assert ecc.hamming84_decode_raw(damaged) == b"raw"
    for left, right in itertools.combinations(range(8), 2):
        damaged = raw[:]
        damaged[0] ^= (1 << left) | (1 << right)
        assert ecc.hamming84_decode_raw(damaged) is None
    assert ecc.hamming84_decode_nibbles(raw[:1]) == (ord("r") >> 4,)
    assert ecc.hamming84_decode_raw(raw[:1]) is None
    assert ecc.hamming84_decode_raw(["bad", 0]) is None


def test_rs_gf256_corrects_four_symbols_and_declines_five():
    codec = ecc.ReedSolomon(nsym=8)
    encoded = bytearray(codec.encode(PAYLOAD))
    assert not any(codec.syndromes(encoded))
    for position, delta in zip((0, 4, len(PAYLOAD), len(encoded) - 1), (1, 0x52, 0xA7, 7)):
        encoded[position] ^= delta
    assert codec.decode(bytes(encoded)) == PAYLOAD

    beyond = bytearray(codec.encode(PAYLOAD))
    for position, delta in zip(range(5), range(1, 6)):
        beyond[position] ^= delta
    assert codec.decode(bytes(beyond)) is None


def test_rs_combines_known_erasures_and_unknown_errors_at_2e_plus_s_radius():
    codec = ecc.ReedSolomon(nsym=8)
    encoded = bytearray(codec.encode(PAYLOAD))
    erasures = (0, 3, 7, len(encoded) - 1)
    unknown = (9, 13)
    for position, delta in zip(erasures + unknown, (1, 2, 4, 8, 16, 32)):
        encoded[position] ^= delta
    assert codec.decode(encoded, erasures=erasures) == PAYLOAD

    beyond = bytearray(codec.encode(PAYLOAD))
    for position, delta in zip(erasures + (9, 13, 15), (1, 2, 4, 8, 16, 32, 64)):
        beyond[position] ^= delta
    assert codec.decode(beyond, erasures=erasures) is None
    assert codec.decode(encoded, erasures=(0, 0)) is None
    assert codec.decode(encoded, erasures=(len(encoded),)) is None


def test_rs_arbitrary_gf16_and_nondefault_first_root():
    # x^4+x+1 (0x13) is primitive; this also exercises non-byte symbols.
    codec = ecc.ReedSolomon(nsym=4, m=4, primitive_polynomial=0x13,
                            first_consecutive_root=3)
    message = (1, 2, 3, 4, 5, 6)
    encoded = list(codec.encode_symbols(message))
    encoded[1] ^= 0x3
    encoded[-2] ^= 0x7
    assert codec.decode_symbols(encoded) == message

    encoded = list(codec.encode_symbols(message))
    for position, delta in zip((0, 1, 2), (1, 2, 4)):
        encoded[position] ^= delta
    assert codec.decode_symbols(encoded) is None
    with pytest.raises(ValueError):
        ecc.GF2m(4, 0x1F)  # irreducible/primitive validation is intentional


def test_rs_supports_non_x_generator_and_rejects_bad_configuration():
    # AES's 0x11b modulus is irreducible but x itself is not primitive.  A
    # separately configurable primitive element makes the full field usable.
    with pytest.raises(ValueError):
        ecc.GF2m(8, 0x11B, generator=2)
    field = ecc.GF2m(8, 0x11B, generator=3)
    assert len(set(field.exp[:field.period])) == 255

    codec = ecc.ReedSolomon(10, m=8, primitive_polynomial=0x11B,
                            first_consecutive_root=5, field_generator=3)
    encoded = bytearray(codec.encode(PAYLOAD))
    for position, delta in zip((0, 3, 8, 14, len(encoded) - 1), (1, 3, 7, 31, 0xA5)):
        encoded[position] ^= delta
    assert codec.decode(encoded) == PAYLOAD
    assert codec.decode_symbols([1, "not-a-symbol", 2]) is None
    with pytest.raises(ValueError):
        ecc.ReedSolomon(0)
    with pytest.raises(ValueError):
        ecc.ReedSolomon(255)


@pytest.mark.skipif(importlib.util.find_spec("reedsolo") is None,
                    reason="optional reedsolo library is not installed")
def test_rs_cross_checks_reedsolo_when_installed():
    import reedsolo

    ours = ecc.ReedSolomon(nsym=8, first_consecutive_root=0)
    theirs = reedsolo.RSCodec(8, nsize=255, fcr=0, prim=0x11D, generator=2, c_exp=8)
    assert ours.encode(PAYLOAD) == bytes(theirs.encode(PAYLOAD))
    damaged = bytearray(ours.encode(PAYLOAD))
    damaged[2] ^= 0x44
    assert ours.decode(damaged) == bytes(theirs.decode(damaged)[0]) == PAYLOAD


def test_binary_bch_shortening_correction_and_decline():
    # Primitive BCH(31,21), designed distance >= 5, shortened to 26 bits for 16 data bits.
    codec = ecc.BCH(m=5, primitive_polynomial=0x25, t=2)
    assert (codec.n, codec.k, codec.parity_bits) == (31, 21, 10)
    encoded = list(codec.encode(b"OK"))
    assert len(encoded) == 26
    encoded[3] ^= 1
    encoded[-1] ^= 1
    assert codec.decode(encoded) == b"OK"

    damaged = list(codec.encode(b"OK"))
    for position in (0, 1, 2):
        damaged[position] ^= 1
    assert codec.decode(damaged) is None
    assert codec.decode([0] * codec.parity_bits) is None
    assert codec.decode([0, "bad"] + [0] * codec.parity_bits) is None
    with pytest.raises(ValueError):
        ecc.BCH(m=5, primitive_polynomial=0x25, t=0)


def test_small_rs_and_bch_exhaust_their_claimed_error_radius():
    rs = ecc.ReedSolomon(4, m=4, primitive_polynomial=0x13,
                         first_consecutive_root=0)
    message = (1, 4, 7, 9, 12, 15)
    encoded = list(rs.encode_symbols(message))
    for weight in range(3):
        for positions in itertools.combinations(range(len(encoded)), weight):
            damaged = encoded[:]
            for index, position in enumerate(positions):
                damaged[position] ^= ((position + index) % 15) + 1
            assert rs.decode_symbols(damaged) == message

    bch = ecc.BCH(5, 0x25, 2)
    bch_encoded = list(bch.encode(b"OK"))
    for weight in range(3):
        for positions in itertools.combinations(range(len(bch_encoded)), weight):
            damaged = bch_encoded[:]
            for position in positions:
                damaged[position] ^= 1
            assert bch.decode(damaged) == b"OK"


def test_viterbi_corrects_bounded_noise_and_requires_crc_and_tail():
    encoded = list(ecc.convolutional_encode(PAYLOAD))
    encoded[10] ^= 1
    encoded[77] ^= 1
    assert ecc.viterbi_decode(encoded, max_bit_errors=2) == PAYLOAD
    assert ecc.viterbi_decode(encoded, max_bit_errors=1) is None

    corrupt = list(ecc.convolutional_encode(PAYLOAD))
    for position in (1, 15, 49, 88, 127):
        corrupt[position] ^= 1
    assert ecc.viterbi_decode(corrupt, max_bit_errors=2) is None
    assert ecc.viterbi_decode(corrupt[:-1], max_bit_errors=8) is None
    assert ecc.viterbi_decode(corrupt, generators=(0, 0o5), max_bit_errors=8) is None
    assert ecc.viterbi_decode(corrupt, constraint=13, max_bit_errors=8) is None
    assert ecc.viterbi_decode(corrupt, max_bit_errors=8, max_trellis_cells=1) is None


def test_raw_viterbi_candidate_api_does_not_require_synthetic_frame():
    bits = (1, 0, 1, 1, 0, 0, 1)
    encoded = list(ecc.convolutional_encode_bits(bits))
    encoded[4] ^= 1
    assert ecc.viterbi_decode_bits(encoded, max_bit_errors=1) == bits
    assert ecc.viterbi_decode(encoded, max_bit_errors=1) is None
    encoded[8] ^= 1
    assert ecc.viterbi_decode_bits(encoded, max_bit_errors=1) is None
    assert ecc.viterbi_decode_bits(encoded[:-1], max_bit_errors=9) is None


def test_crc_known_answers_cross_check_stdlib_and_recovery_is_checked():
    crc8 = ecc.CRCParameters(8, 0x07)
    ccitt = ecc.CRCParameters(16, 0x1021, 0xFFFF)
    crc32 = ecc.CRCParameters(32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True)
    crc3_gsm = ecc.CRCParameters(3, 0x3, 0, 0x7)
    crc4_itu = ecc.CRCParameters(4, 0x3, 0, 0, True, True)
    assert ecc.crc_value(b"123456789", crc3_gsm) == 0x4
    assert ecc.crc_value(b"123456789", crc4_itu) == 0x7
    assert ecc.crc_value(b"123456789", crc8) == 0xF4
    assert ecc.crc_value(b"123456789", ccitt) == 0x29B1
    assert ecc.crc_value(PAYLOAD, crc32) == zlib.crc32(PAYLOAD) & 0xFFFFFFFF

    samples = [(item, ecc.crc_value(item, crc8))
               for item in (b"123456789", b"alpha", b"\0\xfftest")]
    assert ecc.recover_crc_parameters(samples, exhaustive_width=8) == (crc8,)

    inconsistent = samples[:-1] + [(samples[-1][0], samples[-1][1] ^ 1)]
    assert ecc.recover_crc_parameters(inconsistent, candidates=[crc8]) == ()
    with pytest.raises(ValueError):
        ecc.recover_crc_parameters(samples, exhaustive_width=17)


def test_crc_single_bit_reverse_repairs_unique_and_declines_double_damage():
    params = ecc.CRCParameters(8, 0x07)
    original = b"CRC-reverse"
    expected = ecc.crc_value(original, params)
    damaged = bytearray(original)
    damaged[3] ^= 0x20
    assert ecc.repair_crc_single_bit(bytes(damaged), expected, params) == original

    damaged[5] ^= 0x04
    assert ecc.repair_crc_single_bit(bytes(damaged), expected, params) is None
    assert ecc.repair_crc_single_bit(original, expected, params, max_bits=1) is None
    with pytest.raises(ValueError):
        ecc.crc_value(original, ecc.CRCParameters(8, 0x06))


def _ldpc() -> ecc.LDPCCode:
    # Sparse systematic H=[A|I], non-perfect so some double syndromes are not columns.
    return ecc.LDPCCode((
        (1, 1, 0, 0, 1, 0, 0, 0),
        (1, 0, 1, 0, 0, 1, 0, 0),
        (0, 1, 1, 0, 0, 0, 1, 0),
        (1, 1, 1, 1, 0, 0, 0, 1),
    ), data_bits=4)


def test_ldpc_bounded_and_min_sum_decoders_verify_parity():
    codec = _ldpc()
    encoded = list(codec.encode_bits((1, 0, 1, 1)))
    assert codec.decode(encoded, max_flips=1) == b"\xb0"
    encoded[2] ^= 1
    assert codec.decode(encoded, max_flips=1) == b"\xb0"

    llrs = [6.0 if bit == 0 else -6.0 for bit in codec.encode_bits((1, 0, 1, 1))]
    llrs[2] *= -0.15
    assert codec.decode_min_sum(llrs) == b"\xb0"

    damaged = list(codec.encode_bits((1, 0, 1, 1)))
    damaged[0] ^= 1
    damaged[1] ^= 1
    assert codec.decode(damaged, max_flips=1) is None
    assert codec.decode_min_sum([0.0] * codec.n, iterations=2) is None
    assert codec.decode(damaged, max_flips=2, max_trials=1) is None
    assert codec.decode_min_sum([float("nan")] * codec.n) is None


def test_turbo_chase_decoder_corrects_checked_frame_and_declines_over_budget():
    encoded = list(ecc.turbo_encode(b"turbo"))
    encoded[3 * 20] ^= 1       # systematic-stream error
    encoded[3 * 40 + 1] ^= 1   # first constituent parity error
    assert ecc.turbo_decode(encoded, max_systematic_flips=1,
                            max_bit_errors=2) == b"turbo"

    over = list(ecc.turbo_encode(b"turbo"))
    for position in (3 * 8, 3 * 24, 3 * 40 + 1, 3 * 50 + 2):
        over[position] ^= 1
    assert ecc.turbo_decode(over, max_systematic_flips=1,
                            max_bit_errors=2) is None
    assert ecc.turbo_decode(over + [0], max_bit_errors=99) is None
    assert ecc.turbo_decode(ecc.turbo_encode(b"x"), max_systematic_flips=2,
                            max_candidates=1) is None
    assert ecc.turbo_decode(ecc.turbo_encode(b"x"),
                            interleaver=[0, "bad"] + list(range(2, 88))) is None


def test_parity_blocks_accept_only_complete_verified_blocks():
    payload = b"abcdefghABCDEFGH"
    encoded = ecc.parity_encode(payload, block_size=4)
    assert ecc.parity_decode(encoded, block_size=4) == payload
    damaged = bytearray(encoded)
    damaged[1] ^= 1
    assert ecc.parity_decode(damaged, block_size=4) is None
    assert ecc.parity_decode(encoded[:-1], block_size=4) is None


@pytest.mark.parametrize("odd", [False, True])
def test_character_parity_roundtrip_and_declines_corruption(odd):
    payload = b"ASCII parity"
    encoded = bytearray(ecc.character_parity_encode(payload, odd=odd))
    assert ecc.character_parity_decode(encoded, odd=odd) == payload
    encoded[2] ^= 0x04
    assert ecc.character_parity_decode(encoded, odd=odd) is None
    assert ecc.character_parity_decode(b"", odd=odd) is None
    with pytest.raises(ValueError):
        ecc.character_parity_encode(b"\x80", odd=odd)


@pytest.mark.parametrize("family", [
    "xor8", "sum8", "sum16", "fletcher16", "fletcher32", "internet16",
    "bsd16", "sysv16", "adler32", "crc32",
])
def test_checksum_families_roundtrip_and_decline_corruption(family):
    encoded = ecc.checksum_encode(PAYLOAD, family)
    assert ecc.checksum_decode(encoded, family) == PAYLOAD
    damaged = bytearray(encoded)
    damaged[0] ^= 0x80
    assert ecc.checksum_decode(damaged, family) is None


def test_configuration_and_shape_guards_decline_instead_of_guessing():
    with pytest.raises(ValueError):
        ecc.parity_encode(b"short", block_size=4)
    with pytest.raises(ValueError):
        ecc.checksum_encode(b"x", "unknown")
    with pytest.raises(ValueError):
        ecc.LDPCCode(((1, 0),), data_bits=1)  # right side is not identity
    assert ecc.turbo_decode([0, 1]) is None
    assert ecc.viterbi_decode([]) is None

