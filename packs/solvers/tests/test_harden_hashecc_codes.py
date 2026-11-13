"""Independent ECC vector locks and deterministic malformed-input contracts.

Hamming codewords below are hand-computed with data at positions 3,5,6,7,
even parity checks 1/2/4 and overall parity in position 8. BCH generator
polynomials are published at:
https://www.mathworks.com/help/comm/ug/block-codes.html (15,5)
https://www.mathworks.com/help/comm/ref/bchgenpoly.html (15,11)
https://eprint.iacr.org/2015/886.pdf (15,7)
The BCH oracle is integer-polynomial division and exhaustive codebook search,
not the tested engine's encoder. Convolutional/Viterbi reference uses explicit
XOR tap equations and exhaustive messages, not register or trellis code.
"""
import itertools
import random

import pytest

import ecc_codes as E


H84 = (0x00, 0xD2, 0x55, 0x87, 0x99, 0x4B, 0xCC, 0x1E,
       0xE1, 0x33, 0xB4, 0x66, 0x78, 0xAA, 0x2D, 0xFF)


def bits(value, width):
    return tuple(int(digit) for digit in f"{value:0{width}b}")


def assert_closed(function, *args, **kwargs):
    """Only the engine's declared error is allowed, never stdlib leaks."""
    try:
        return function(*args, **kwargs)
    except E.ECCError:
        return None


@pytest.mark.parametrize("nibble,word", list(enumerate(H84)))
def test_hand_computed_hamming84_and_secded_lock(nibble, word):
    data, code = bits(nibble, 4), bits(word, 8)
    assert E.hamming84_encode(nibble) == word
    assert E.hamming_secded_encode(data) == list(code)
    for decode, fixture in ((E.hamming84_decode, word), (E.hamming_secded_decode, code)):
        result = decode(fixture)
        assert result.data == data
        assert result.codeword == code
        assert result.status == "clean"
        assert result.corrected_position is None
        assert result.zero_syndrome and result.reencoded and result.value_verified


@pytest.mark.parametrize("nibble,word", list(enumerate(H84)))
def test_hamming_corrects_every_single_bit_and_detects_every_double(nibble, word):
    for bit in range(8):
        damaged = word ^ (1 << bit)
        for decode, fixture in ((E.hamming84_decode, damaged),
                                (E.hamming_secded_decode, bits(damaged, 8))):
            result = decode(fixture)
            assert result.data == bits(nibble, 4)
            assert result.codeword == bits(word, 8)
            assert result.corrected_position == 8 - bit
            assert result.value_verified is False
    for left, right in itertools.combinations(range(8), 2):
        damaged = word ^ (1 << left) ^ (1 << right)
        assert E.hamming84_decode(damaged) is None
        assert E.hamming_secded_decode(bits(damaged, 8)) is None


@pytest.mark.parametrize("data_length,word_length", [(1, 4), (11, 16), (26, 32)])
@pytest.mark.parametrize("value", [0, 1])
def test_general_secded_constant_codewords(data_length, word_length, value):
    # Each parity check contains an even number of identical bits. No encoder
    # is involved in establishing these expected larger SECDED codewords.
    data, code = (value,) * data_length, (value,) * word_length
    assert E.hamming_secded_encode(data) == list(code)
    for position in (0, word_length // 2, word_length - 1):
        damaged = list(code)
        damaged[position] ^= 1
        result = E.hamming_secded_decode(damaged)
        assert result.data == data
        assert result.codeword == code


def polynomial_remainder(dividend, divisor):
    while dividend.bit_length() >= divisor.bit_length():
        dividend ^= divisor << (dividend.bit_length() - divisor.bit_length())
    return dividend


def reference_bch(value, payload_bits, generator):
    parity = generator.bit_length() - 1
    shifted = value << parity
    return bits(shifted ^ polynomial_remainder(shifted, generator), payload_bits + parity)


@pytest.mark.parametrize("t,generator,payload_bits", [(1, 0x13, 11), (2, 0x1D1, 7), (3, 0x537, 5)])
def test_bch_published_generator_and_independent_integer_division(t, generator, payload_bits):
    assert E.bch_generator(4, t, 0x13) == list(bits(generator, generator.bit_length()))
    for value in (0, 1, 5, (1 << payload_bits) - 1):
        data = bits(value, payload_bits)
        expected = reference_bch(value, payload_bits, generator)
        assert E.bch_encode(data, 4, t, 0x13) == list(expected)
        for error_count in range(t + 1):
            damaged = list(expected)
            positions = (0, 5, 10)[:error_count]
            for position in positions:
                damaged[position] ^= 1
            decoded = E.bch_decode(damaged, 4, t, 0x13)
            assert decoded.data == data
            assert decoded.codeword == expected
            assert decoded.corrected_positions == positions
            assert decoded.value_verified is (error_count == 0)


def test_bch_against_full_independent_codebook():
    # All possible (15,7) codewords derived from the published polynomial.
    codebook = [(bits(value, 7), reference_bch(value, 7, 0x1D1)) for value in range(128)]
    rng = random.Random(0xBC15)
    for _ in range(48):
        received = bits(rng.randrange(1 << 15), 15)
        winners = [(data, code) for data, code in codebook
                   if sum(a != b for a, b in zip(received, code)) <= 2]
        decoded = E.bch_decode(received, 4, 2, 0x13)
        if not winners:
            assert decoded is None
        else:
            assert len(winners) == 1
            assert (decoded.data, decoded.codeword) == winners[0]


def taps_75(data, previous=0, before_previous=0, terminate=False):
    """Direct equations y0=u[t]+u[t-1]+u[t-2], y1=u[t]+u[t-2]."""
    output = []
    for current in tuple(data) + ((0, 0) if terminate else ()):
        output += [current ^ previous ^ before_previous, current ^ before_previous]
        before_previous, previous = previous, current
    return tuple(output)


@pytest.mark.parametrize("data", [(1,), (0, 1, 0), (1, 0, 1, 1, 0), (0,) * 8, (1,) * 8])
@pytest.mark.parametrize("terminate", [False, True])
def test_convolutional_explicit_tap_equations(data, terminate):
    expected = taps_75(data, terminate=terminate)
    assert E.convolutional_encode(data, terminate=terminate) == list(expected)
    result = E.viterbi_decode(expected, terminated=terminate, final_state=0 if terminate else None)
    assert result.data == data
    assert result.path_metric == 0
    assert result.unique_ml and result.reencoded_exact and result.value_verified


def test_viterbi_random_vectors_against_exhaustive_independent_codebook():
    codebook = [(bits(value, 5), taps_75(bits(value, 5))) for value in range(32)]
    rng = random.Random(0x7575)
    for _ in range(40):
        received = bits(rng.randrange(1 << 10), 10)
        distances = [(sum(a != b for a, b in zip(received, wire)), data) for data, wire in codebook]
        metric = min(distance for distance, _ in distances)
        winners = [data for distance, data in distances if distance == metric]
        result = E.viterbi_decode(received)
        assert result.data in winners
        assert result.path_metric == metric
        assert result.unique_ml == (len(winners) == 1)
        assert result.reencoded_exact == (metric == 0)


def test_viterbi_supplied_initial_state_data_lock():
    wire = taps_75((0,), previous=1)
    assert wire == (1, 0)
    result = E.viterbi_decode(wire, initial_state=1)
    assert (result.data, result.path_metric, result.unique_ml) == ((0,), 0, True)


def test_viterbi_supplied_initial_state_verification_lock():
    result = E.viterbi_decode((1, 0), initial_state=1)
    assert (result.reencoded_exact, result.value_verified) == (True, True)


@pytest.mark.parametrize("initial_state", range(4))
@pytest.mark.parametrize("terminate", [False, True])
def test_viterbi_replay_preserves_initial_state_and_tail(initial_state, terminate):
    data = (1, 0, 1, 1)
    wire = taps_75(data, previous=initial_state & 1,
                   before_previous=initial_state >> 1, terminate=terminate)
    result = E.viterbi_decode(wire, initial_state=initial_state,
                              final_state=0 if terminate else None, terminated=terminate)
    assert result.data == data
    assert (result.path_metric, result.reencoded_exact, result.value_verified) == (0, True, True)


CHECK = ((1, 1, 0, 0), (0, 1, 1, 0), (0, 0, 1, 1))
REPETITION_CODEBOOK = ((0, 0, 0, 0), (1, 1, 1, 1))


@pytest.mark.parametrize("received", [bits(value, 4) for value in range(16)])
def test_syndrome_ldpc_against_direct_repetition_codebook(received):
    expected_syndrome = (received[0] ^ received[1], received[1] ^ received[2], received[2] ^ received[3])
    assert E.syndrome(received, CHECK) == expected_syndrome
    distances = [(sum(a != b for a, b in zip(received, code)), code) for code in REPETITION_CODEBOOK]
    minimum = min(distance for distance, _ in distances)
    winners = [code for distance, code in distances if distance == minimum]
    result = E.ldpc_decode_exact(received, CHECK, max_distance=2)
    if len(winners) != 1:
        assert result is None
    else:
        assert result.codeword == winners[0]
        assert result.distance == minimum
        assert result.zero_syndrome and result.unique_nearest
        assert result.value_verified == (minimum == 0)


BIT_FUNCTIONS = (
    ("hamming_secded_encode", lambda data: E.hamming_secded_encode(data)),
    ("hamming_secded_decode", lambda data: E.hamming_secded_decode(data)),
    ("bch_encode", lambda data: E.bch_encode(data, 4, 2, 0x13)),
    ("bch_decode", lambda data: E.bch_decode(data, 4, 2, 0x13)),
    ("convolutional_encode", lambda data: E.convolutional_encode(data)),
    ("viterbi_decode", lambda data: E.viterbi_decode(data)),
    ("ldpc_decode_exact", lambda data: E.ldpc_decode_exact(data, CHECK)),
)


@pytest.mark.parametrize("name,function", BIT_FUNCTIONS, ids=[entry[0] for entry in BIT_FUNCTIONS])
def test_fail_closed_bitstream_fuzz(name, function):
    rng = random.Random(0x20261105)
    malformed = [None, 0, [], (), "", "0101", b"0101", {}, [None], [2], [-1], [True], [object()]]
    malformed += [[rng.randrange(-2, 4) for _ in range(rng.randrange(20))] for _ in range(40)]
    malformed += [[rng.randrange(2) for _ in range(rng.randrange(20))] for _ in range(40)]
    for data in malformed:
        assert_closed(function, data)


@pytest.mark.parametrize("name", ["hamming84_encode", "hamming84_decode"])
def test_fail_closed_hamming_scalars(name):
    rng = random.Random(84)
    for value in (None, [], {}, "1", True, 0.0, -1, 1 << 100, *[rng.randrange(-100, 512) for _ in range(60)]):
        assert_closed(getattr(E, name), value)


def test_fail_closed_bch_generator_integer_ranges():
    for m, t, primitive in ((0, 1, 0), (4, 0, 0x13), (4, 100, 0x13), (5, 2, 0x13),
                            (4, -1, 0x13), (4, 2, -1), (4, 2, 0x12)):
        assert_closed(E.bch_generator, m, t, primitive)


def test_fail_closed_syndrome_and_ldpc_shape_fuzz():
    rng = random.Random(124)
    matrices = [[], [[]], [[2]], [[0, 1]], [[-1]], [[1], [1, 0]]]
    matrices += [[[rng.randrange(-2, 3) for _ in range(rng.randrange(6))]
                  for _ in range(rng.randrange(5))] for _ in range(30)]
    for matrix in matrices:
        assert_closed(E.syndrome, [0, 1, 0, 1], matrix)
        assert_closed(E.ldpc_decode_exact, [0, 1, 0, 1], matrix)


def test_turbo_stub_is_explicit_for_empty_and_arbitrary_input():
    # No decoding oracle is applicable to an intentionally unsupported API.
    for args in ((), (None,), (b"",), ([0, 1],), (object(), {})):
        result = assert_closed(E.turbo_decode, *args)
        assert (result["supported"], result["candidate"]) == (False, None)
        assert "interleaver" in result["reason"]


@pytest.mark.parametrize("function,args", [
    pytest.param(E.hamming_secded_encode, ([0.0] * 4,), id="hamming_encode_float_bits"),
    pytest.param(E.hamming_secded_decode, ([0.0] * 8,), id="hamming_decode_float_bits"),
    pytest.param(E.bch_encode, ([1.0] * 7, 4, 2, 0x13), id="bch_encode_float_bits"),
    pytest.param(E.bch_decode, ([1.0] * 15, 4, 2, 0x13), id="bch_decode_float_bits"),
    pytest.param(E.convolutional_encode, ([0.0],), id="convolution_float_bits"),
    pytest.param(E.ldpc_decode_exact, ([0.0] * 4, CHECK), id="ldpc_float_bits"),
])
def test_float_bitstream_contract_bug(function, args):
    assert_closed(function, *args)


@pytest.mark.parametrize("function,args,kwargs", [
    pytest.param(E.bch_generator, (4, 2.0, 0x13), {}, id="bch_generator_float_t"),
    pytest.param(E.bch_encode, ([1] * 7, 4, 2.0, 0x13), {}, id="bch_encode_float_t"),
    pytest.param(E.bch_decode, ([1] * 15, 4, 2.0, 0x13), {}, id="bch_decode_float_t"),
    pytest.param(E.convolutional_encode, ([0],), {"constraint": None}, id="convolution_none_constraint"),
    pytest.param(E.viterbi_decode, ([0, 0],), {"constraint": None}, id="viterbi_none_constraint"),
    pytest.param(E.viterbi_decode, ([0, 0],), {"initial_state": "0"}, id="viterbi_string_state"),
    pytest.param(E.syndrome, (None, CHECK), {}, id="syndrome_none_bits"),
    pytest.param(E.syndrome, ([0], [None]), {}, id="syndrome_none_row"),
    pytest.param(E.ldpc_decode_exact, ([0], [None]), {}, id="ldpc_none_row"),
    pytest.param(E.ldpc_decode_exact, ([0], [[1]]), {"max_distance": 1.5}, id="ldpc_float_distance"),
])
def test_malformed_parameter_contract_bug(function, args, kwargs):
    assert_closed(function, *args, **kwargs)
