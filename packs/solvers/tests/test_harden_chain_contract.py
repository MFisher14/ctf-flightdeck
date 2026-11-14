"""Tests only: immutable payload contract, struct/bytes reference operations.

contract.py is a payload result model, not a blockchain smart-contract decoder.
Expected byte placements come from Python's independent struct implementation.
Only BuildError satisfies its public fail-closed exception contract.
"""
import random
import struct

import pytest

from contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes


def _closed(call):
    try:
        return call()
    except Exception as error:
        assert isinstance(error, BuildError), f"leaked {type(error).__name__}: {error}"


def test_payloadbuild_struct_oracle_and_public_views():
    address = 0x123456789ABCDEF0
    reference = struct.pack("<Q", address) + b"CSCTF{inert}"
    offsets = {"text": struct.calcsize("<Q"), "address": 0}
    widths = {"address": struct.calcsize("<Q"), "text": len(b"CSCTF{inert}")}
    value = PayloadBuild(reference, offsets, widths, "amd64", "test", 0x4000,
                         {"note": "serialized data only"})
    offsets["address"] = 3
    widths["address"] = 1
    payload, positions = value
    assert payload == reference
    assert dict(positions) == {"address": 0, "text": 8}
    assert value.slice("address") == struct.pack("<Q", address)
    assert value.slice("text") == b"CSCTF{inert}"
    assert dict(value.absolute_placements()) == {"address": 0x4000, "text": 0x4008}
    assert value.as_dict() == {
        "payload_hex": reference.hex(), "length": len(reference),
        "placements": {"address": 0, "text": 8}, "widths": {"address": 8, "text": 12},
        "architecture": "amd64", "strategy": "test", "base_address": 0x4000,
        "metadata": {"note": "serialized data only"},
    }
    with pytest.raises(TypeError):
        positions["address"] = 1


@pytest.mark.parametrize("bits,format", [(8, "B"), (16, "H"), (32, "I"), (64, "Q")])
def test_ensure_uint_struct_range_oracle(bits, format):
    rng = random.Random(0xC7F + bits)
    for value in [0, 1, (1 << bits) - 1, *[rng.randrange(1 << bits) for _ in range(20)]]:
        expected = struct.unpack("<" + format, struct.pack("<" + format, value))[0]
        assert ensure_uint(value, bits, name="address") == expected
    for value in (-1, 1 << bits):
        with pytest.raises(struct.error):
            struct.pack("<" + format, value)
        with pytest.raises(BuildError):
            ensure_uint(value, bits, name="address")


def test_reject_bad_bytes_independent_octet_membership():
    rng = random.Random(1024)
    for _ in range(100):
        payload = rng.randbytes(rng.randrange(32))
        forbidden = rng.sample(range(256), rng.randrange(12))
        if any(octet in payload for octet in forbidden):
            with pytest.raises(BuildError):
                reject_bad_bytes(payload, forbidden)
        else:
            assert reject_bad_bytes(payload, forbidden) == tuple(sorted(forbidden))


def test_constructor_and_uint_malformed_fuzz():
    rng = random.Random(731)
    for data in (b"", *[rng.randbytes(n) for n in range(20)]):
        _closed(lambda: PayloadBuild(data, {"field": len(data) + 1}))
        _closed(lambda: PayloadBuild(data, {"field": 0}, {"field": len(data) + 1}))
        _closed(lambda: PayloadBuild(data, {"field": -1}))
    for bad in (None, [], {}, "", b"", True, 1.1):
        _closed(lambda: PayloadBuild(b"x", bad))
        _closed(lambda: PayloadBuild(b"x", {}, metadata=bad))
        _closed(lambda: ensure_uint(bad, 64, name="address"))
        _closed(lambda: ensure_uint(0, bad, name="address"))
        _closed(lambda: reject_bad_bytes(b"x", bad))


def test_slice_unknown_label_fail_closed():
    _closed(lambda: PayloadBuild(b"x", {"known": 0}, {"known": 1}).slice("missing"))


def test_reject_bad_bytes_invalid_payload_fail_closed():
    _closed(lambda: reject_bad_bytes(None, (0,)))


def test_reject_bad_bytes_fractional_octet_is_not_an_octet():
    with pytest.raises(BuildError):
        reject_bad_bytes(b"abc", [1.5])


@pytest.mark.parametrize("octet", [True, False, 1.0, "1", None, -1, 256])
def test_reject_bad_bytes_requires_integer_octets(octet):
    with pytest.raises(BuildError):
        reject_bad_bytes(b"abc", [octet])


def test_reject_bad_bytes_bounds_even_duplicate_iterables():
    def forever():
        while True:
            yield 0
    with pytest.raises(BuildError):
        reject_bad_bytes(b"abc", forever())
    assert reject_bad_bytes(bytearray(b"abc"), b"\0\n") == (0, 10)


@pytest.mark.parametrize("label", [None, [], {}, 1])
def test_slice_invalid_label_is_declared_error(label):
    with pytest.raises(BuildError):
        PayloadBuild(b"x", {"known": 0}, {"known": 1}).slice(label)
