"""ABI vectors from eth-abi/eth-utils and Solidity's ABI specification.

https://docs.soliditylang.org/en/latest/abi-spec.html
Expected calldata is always encoded by eth_abi, never blockchain.routines.
"""
import random

import eth_abi
import pytest
from eth_hash.auto import keccak
from eth_utils import abi_to_signature, function_abi_to_4byte_selector

import blockchain as chain


def clean_call(fn, *args):
    try:
        return fn(*args)
    except chain._Bad:
        return None


def nested_lists(value):
    return [nested_lists(x) for x in value] if isinstance(value, (tuple, list)) else value


VECTORS = [
    (["uint256"], [0]),
    (["uint256", "int256"], [(1 << 256) - 1, -(1 << 255)]),
    (["uint8", "int8", "bool", "bool"], [255, -128, False, True]),
    (["address", "bytes4"], ["0x000000000000000000000000000000000000dead", bytes.fromhex("12345678")]),
    (["bytes", "string"], [b"\0\xffCSCTF{abi}", "Snowman \u2603"]),
    (["bytes", "string"], [b"", ""]),
    (["uint256[]"], [[0, 123, (1 << 256) - 1]]),
    (["uint16[2][2]"], [[[0, 1], [65535, 42]]]),
    (["uint8[2][]", "bytes32"], [[[1, 2], [3, 4]], bytes(range(32))]),
    (["bytes3[2]", "bool[]"], [[b"abc", b"xyz"], [True, False, True]]),
]


@pytest.mark.parametrize("types,values", VECTORS)
def test_abi_decode_and_calldata_against_eth_abi(types, values):
    data = eth_abi.encode(types, values)
    expected = nested_lists(eth_abi.decode(types, data))
    assert chain.abi_decode(types, data) == expected
    entry = {"name": "exercise", "type": "function",
             "inputs": [{"name": f"arg{i}", "type": t} for i, t in enumerate(types)]}
    sig = abi_to_signature(entry)
    sel = function_abi_to_4byte_selector(entry)
    assert chain.signature_of(entry) == sig
    assert chain.selector_of_signature(sig) == sel == keccak(sig.encode())[:4]
    parsed = chain.parse_abi([entry])
    assert parsed["functions"][0]["signature"] == sig
    assert parsed["functions"][0]["sel"] == sel.hex()
    result = chain.decode_calldata(parsed, sel + data)
    assert result[1] == [(f"arg{i}", t, expected[i]) for i, t in enumerate(types)]
    assert chain.data_sel(sel + data) == sel.hex()


def test_known_selectors_event_topic_and_collision_rejection():
    assert chain.selector_of_signature("transfer(address,uint256)").hex() == "a9059cbb"
    event = {"name": "Transfer", "type": "event", "inputs": [
        {"name": "from", "type": "address", "indexed": True},
        {"name": "to", "type": "address", "indexed": True},
        {"name": "value", "type": "uint256", "indexed": False}]}
    expected = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    assert chain.parse_abi({"abi": [event]})["events"][0]["topic"] == expected
    assert keccak(abi_to_signature(event).encode()).hex() == expected
    for sel, signatures in chain.common_selector_table().items():
        for signature in signatures:
            assert keccak(signature.encode())[:4].hex() == sel
    entry = {"name": "f", "type": "function", "inputs": [{"type": "uint256"}]}
    duplicated = chain.parse_abi([entry, entry])
    calldata = function_abi_to_4byte_selector(entry) + eth_abi.encode(["uint256"], [123])
    assert chain.decode_calldata(duplicated, calldata) is None


def test_tuple_signature_via_json_abi():
    entry = {"name": "f", "type": "function", "inputs": [{"type": "tuple", "components": [
        {"type": "uint256"}, {"type": "address"}]}]}
    assert chain.signature_of(entry) == abi_to_signature(entry) == "f((uint256,address))"
    assert chain.parse_abi([entry])["functions"][0]["sel"] == function_abi_to_4byte_selector(entry).hex()


def test_tuple_selector_is_supported_since_b243():
    # B-243 added tuple ABI support: a canonical tuple signature hashes like any other,
    # and a non-canonical spelling (space, uint alias, empty tuple) is still declined.
    signature = "f((uint256,address))"
    assert chain.selector_of_signature(signature) == keccak(signature.encode())[:4]
    for bad in ("f((uint256, address))", "f((uint,address))", "f(())", "f((uint256,address)"):
        assert chain.selector_of_signature(bad) is None


@pytest.mark.parametrize("typ,value", [("bytes", b"a"), ("string", "a")])
def test_reject_nonzero_dynamic_padding(typ, value):
    bad = bytearray(eth_abi.encode([typ], [value]))
    bad[-1] = 1
    with pytest.raises(eth_abi.exceptions.NonEmptyPaddingBytes):
        eth_abi.decode([typ], bytes(bad))
    assert chain.abi_decode([typ], bytes(bad)) is None


def test_reject_dynamic_pointer_into_head():
    bad = bytes(32)
    with pytest.raises(eth_abi.exceptions.InvalidPointer):
        eth_abi.decode(["bytes"], bad)
    assert chain.abi_decode(["bytes"], bad) is None


def test_reject_static_trailing_garbage():
    canonical = eth_abi.encode(["uint256"], [7])
    assert chain.abi_decode(["uint256"], canonical + b"garbage") is None


def test_abi_deterministic_malformed_fuzz():
    rng = random.Random(39144)
    for length in range(129):
        data = rng.randbytes(length)
        for types in (["uint256"], ["int8"], ["bool"], ["bytes4"], ["address"],
                      ["bytes"], ["string"], ["uint256[]"], ["uint16[2]"]):
            clean_call(chain.abi_decode, types, data)
        clean_call(chain.selector_of_signature, data.decode("latin-1"))
        clean_call(chain.signature_of, {"name": "f", "inputs": [{"type": data.decode("latin-1")}]})
        clean_call(chain.parse_abi, {"abi": [{"name": "f", "inputs": [{"type": data.decode("latin-1")}]}]})
        clean_call(chain.decode_calldata, {"functions": []}, data)
        clean_call(chain.data_sel, data)
    for value in (None, [], {}, "bad", 1, [None], [{"type": "function"}]):
        clean_call(chain.parse_abi, value)
        clean_call(chain.signature_of, value)


@pytest.mark.parametrize("fn,args", [
    (chain.selector_of_signature, (None,)),
    (chain.abi_decode, ([None], b"")),
    (chain.abi_decode, (["uint256"], None)),
    (chain.decode_calldata, ({}, bytes(4))),
    (chain.decode_calldata, ({"functions": [None]}, bytes(4))),
    (chain.data_sel, (None,)),
], ids=lambda v: getattr(v, "__name__", None))
def test_abi_malformed_type_contract(fn, args):
    clean_call(fn, *args)
