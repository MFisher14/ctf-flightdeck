"""Independent Reed-Solomon/GF locks and deterministic fail-closed probes.

Oracle: reedsolo 1.7.0 (https://github.com/tomerfiliba-org/reedsolomon).
Fixtures are always encoded by reedsolo, never by the engine under test.
More than floor(nsym/2) errors cannot universally be detected: these tests lock
specific over-budget words that the independent decoder also rejects.
"""
import random

import pytest
import reedsolo

import ecc_codes as engine


FIELDS = [(0x13, 2, 4), (0x11D, 2, 8), (0x11B, 3, 8), (0x211, 2, 9)]


@pytest.fixture(autouse=True)
def restore_reedsolo_globals():
    # reedsolo's low-level functions deliberately use mutable global tables.
    reedsolo.init_tables()
    yield
    reedsolo.init_tables()


def oracle_field(primitive, generator, degree):
    reedsolo.init_tables(prim=primitive, generator=generator, c_exp=degree)


@pytest.mark.parametrize("primitive,generator,degree", FIELDS)
def test_gf_constructor_and_arithmetic_against_reedsolo(primitive, generator, degree):
    oracle_field(primitive, generator, degree)
    field = engine.GF2m(primitive, generator)
    assert field.m == degree
    assert field.size == 2 ** degree
    assert field.order == 2 ** degree - 1
    assert field.exp[:field.order] == list(reedsolo.gf_exp[:field.order])
    rng = random.Random(0xC5C7F + degree)
    pairs = [(0, 0), (0, 1), (1, 0), (1, 1), (field.order, field.order)]
    pairs += [(rng.randrange(field.size), rng.randrange(field.size)) for _ in range(80)]
    for left, right in pairs:
        assert field.add(left, right) == reedsolo.gf_add(left, right)
        assert field.mul(left, right) == reedsolo.gf_mul(left, right)
        if right:
            assert field.div(left, right) == reedsolo.gf_div(left, right)
        # reedsolo's low-level gf_pow does not special-case zero. Restrict that
        # oracle to its nonzero domain; zero's identity is fixed algebra below.
        if left:
            for exponent in (-17, -1, 0, 1, 2, 19, field.order):
                assert field.pow(left, exponent) == reedsolo.gf_pow(left, exponent)
    assert field.pow(0, 1) == 0
    assert field.pow(0, 2) == 0
    assert field.pow(0, 0) == 1


@pytest.mark.parametrize("primitive,generator,degree", FIELDS)
@pytest.mark.parametrize("fcr", [0, 1, 7])
def test_rs_symbol_entrypoints_against_independent_oracle(primitive, generator, degree, fcr):
    oracle_field(primitive, generator, degree)
    field = engine.GF2m(primitive, generator)
    data = [0, 1, 2, 3, 7, (1 << degree) - 1]
    nsym = 8
    expected_generator = list(reedsolo.rs_generator_poly(nsym, fcr=fcr, generator=generator))
    encoded = list(reedsolo.rs_encode_msg(data, nsym, fcr=fcr, generator=generator))
    assert engine.rs_generator(nsym, field, fcr) == expected_generator
    options = dict(primitive=primitive, generator=generator, fcr=fcr)
    assert engine.rs_encode_symbols(data, nsym, **options) == encoded
    # Exercise every correctable unknown-error count, including exactly t.
    for count in range(nsym // 2 + 1):
        damaged = encoded[:]
        positions = list(range(count))
        for position in positions:
            damaged[position] ^= position + 1
        decoded, parity, locations = reedsolo.rs_correct_msg(
            damaged, nsym, fcr=fcr, generator=generator)
        result = engine.rs_decode_symbols(damaged, nsym, **options)
        assert result is not None
        assert result.data == tuple(decoded) == tuple(data)
        assert result.codeword == tuple(decoded) + tuple(parity) == tuple(encoded)
        assert result.corrected_positions == tuple(sorted(locations)) == tuple(positions)
        assert result.zero_syndrome and result.reencoded
        if count:
            assert result.value_verified is False


@pytest.mark.parametrize("nsym", [2, 4, 8, 12, 16])
def test_rs_bytes_corrects_entire_declared_radius(nsym):
    data = b"CSCTF{independent_rs_oracle}"
    encoded = bytes(reedsolo.rs_encode_msg(data, nsym))
    assert engine.rs_encode(data, nsym) == encoded
    rng = random.Random(1700 + nsym)
    for count in range(nsym // 2 + 1):
        positions = sorted(rng.sample(range(len(encoded)), count))
        damaged = bytearray(encoded)
        for position in positions:
            damaged[position] ^= rng.randrange(1, 256)
        expected, parity, locations = reedsolo.rs_correct_msg(damaged, nsym)
        result = engine.rs_decode(bytes(damaged), nsym)
        assert result is not None
        assert result.data == tuple(expected) == tuple(data)
        assert result.codeword == tuple(expected) + tuple(parity) == tuple(encoded)
        assert result.corrected_positions == tuple(sorted(locations)) == tuple(positions)


@pytest.mark.parametrize("nsym", [4, 8, 12])
def test_specific_over_budget_words_are_flagged(nsym):
    data = b"CSCTF{independent_rs_oracle}"
    damaged = bytearray(reedsolo.rs_encode_msg(data, nsym))
    for index in range(nsym // 2 + 1):
        damaged[index] ^= index + 1
    with pytest.raises(reedsolo.ReedSolomonError):
        reedsolo.rs_correct_msg(damaged, nsym)
    assert engine.rs_decode(bytes(damaged), nsym) is None
    assert engine.rs_decode_symbols(list(damaged), nsym) is None


@pytest.mark.parametrize("erasures,errors", [(8, 0), (6, 1), (4, 2), (2, 3), (0, 4)])
def test_mixed_erasures_and_errors_at_budget(erasures, errors):
    data = b"CSCTF{eight_parity_symbols}"
    encoded = bytes(reedsolo.rs_encode_msg(data, 8))
    damaged = bytearray(encoded)
    positions = list(range(erasures + errors))
    for index in positions:
        damaged[index] ^= index + 17
    declared = positions[:erasures]
    decoded, parity, locations = reedsolo.rs_correct_msg(damaged, 8, erase_pos=declared)
    result = engine.rs_decode(bytes(damaged), 8, erasures=declared)
    assert result is not None
    assert result.data == tuple(decoded) == tuple(data)
    assert result.codeword == tuple(decoded) + tuple(parity) == tuple(encoded)
    assert result.corrected_positions == tuple(sorted(locations)) == tuple(positions)


@pytest.mark.parametrize("primitive", [None, "285", [], {}, 0, -1, 1, 2, 0x100000000])
def test_gf_constructor_malformed_polynomial_is_closed(primitive):
    try:
        engine.GF2m(primitive)
    except engine.ECCError:
        pass


def test_rs_random_words_and_malformed_streams_are_closed():
    rng = random.Random(9564)
    streams = [None, 0, "", "not symbols", [], (), [True], [-1], [256], [1.5], [None], [{}]]
    streams += [[rng.randrange(256) for _ in range(rng.randrange(0, 64))] for _ in range(90)]
    for stream in streams:
        for parity in (-1, 0, 1, 4, 8, 255, 256):
            for function in (engine.rs_encode_symbols, engine.rs_decode_symbols):
                try:
                    function(stream, parity)
                except engine.ECCError:
                    pass
    for data in [b"", b"\x00", None, [], bytearray(b"test")]:
        for function in (engine.rs_encode, engine.rs_decode):
            try:
                function(data, 4)
            except engine.ECCError:
                pass


@pytest.mark.parametrize("erasures", [None, 3, [-1], [100], list(range(12)), [float("inf")], ["bad"], [[1]]])
def test_rs_malformed_erasure_lists_are_closed(erasures):
    encoded = bytes(reedsolo.rs_encode_msg(b"test", 4))
    try:
        result = engine.rs_decode(encoded, 4, erasures=erasures)
        assert result is None
    except engine.ECCError:
        pass


def test_rs_generator_random_valid_and_invalid_integer_parity_closed():
    field = engine.GF2m(0x11D)
    for parity in (-100, -1, 0, 1, 2, 8, 32, 254, 255, 256):
        try:
            engine.rs_generator(parity, field)
        except engine.ECCError:
            pass


def _contract_probe(case):
    """Small exact repros; success or ECCError is the requested safe contract."""
    field = engine.GF2m(0x11D)
    calls = {
        "constructor-generator-none": lambda: engine.GF2m(0x11D, None),
        "constructor-generator-float": lambda: engine.GF2m(0x11D, 2.5),
        "add-none": lambda: field.add(None, 1),
        "mul-outside-field": lambda: field.mul(256, 1),
        "mul-none": lambda: field.mul(None, 1),
        "div-zero": lambda: field.div(1, 0),
        "div-outside-field": lambda: field.div(256, 1),
        "pow-none": lambda: field.pow(None, 1),
        "pow-float-exponent": lambda: field.pow(2, 1.2),
        "generator-none-parity": lambda: engine.rs_generator(None, field),
        "generator-float-parity": lambda: engine.rs_generator(3.5, field),
        "generator-none-field": lambda: engine.rs_generator(3, None),
        "generator-string-fcr": lambda: engine.rs_generator(3, field, "x"),
        "encode-none-parity": lambda: engine.rs_encode(b"x", None),
        "encode-symbols-none-parity": lambda: engine.rs_encode_symbols([1], None),
        "decode-none-parity": lambda: engine.rs_decode(b"xxx", None),
        "decode-symbols-none-parity": lambda: engine.rs_decode_symbols([1, 2, 3], None),
        "decode-none-generator": lambda: engine.rs_decode(b"xxxx", 2, generator=None),
        "encode-nine-bit-field": lambda: engine.rs_encode(b"abcd", 8, primitive=0x211),
    }
    try:
        calls[case]()
    except engine.ECCError:
        pass


LEAKS = [
    ("constructor-generator-none", TypeError, "GF2m constructor does not validate generator type"),
    ("constructor-generator-float", TypeError, "GF2m constructor passes float generator into bit arithmetic"),
    ("add-none", TypeError, "GF2m.add leaks TypeError for malformed operands"),
    ("mul-outside-field", IndexError, "GF2m.mul indexes outside field for symbol 256"),
    ("mul-none", TypeError, "GF2m.mul leaks TypeError for malformed operands"),
    ("div-zero", ZeroDivisionError, "GF2m.div raises undeclared ZeroDivisionError"),
    ("div-outside-field", IndexError, "GF2m.div indexes outside field for symbol 256"),
    ("pow-none", TypeError, "GF2m.pow leaks TypeError for malformed operands"),
    ("pow-float-exponent", TypeError, "GF2m.pow accepts float exponent until table indexing"),
    ("generator-none-parity", TypeError, "rs_generator compares None parity with integers"),
    ("generator-float-parity", TypeError, "rs_generator passes float parity to range"),
    ("generator-none-field", AttributeError, "rs_generator dereferences malformed field"),
    ("generator-string-fcr", TypeError, "rs_generator does not validate first-root type"),
    ("encode-none-parity", TypeError, "rs_encode leaks TypeError for None parity"),
    ("encode-symbols-none-parity", TypeError, "rs_encode_symbols leaks TypeError for None parity"),
    ("decode-none-parity", TypeError, "rs_decode leaks TypeError for None parity"),
    ("decode-symbols-none-parity", TypeError, "rs_decode_symbols leaks TypeError for None parity"),
    ("decode-none-generator", TypeError, "rs_decode leaks constructor TypeError for malformed generator"),
    ("encode-nine-bit-field", ValueError, "byte rs_encode accepts GF512 then leaks bytes range ValueError"),
]


@pytest.mark.parametrize("case", [
    pytest.param(case, id=case)
    for case, error, description in LEAKS
])
def test_known_fail_closed_contract_bugs(case):
    _contract_probe(case)
