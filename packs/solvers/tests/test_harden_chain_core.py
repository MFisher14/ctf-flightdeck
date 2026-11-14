"""Independent blockchain primitives; no engine encoder supplies expected data.

Oracles: eth-hash/eth-utils, eth-keys, base58, pyrlp, hashlib; fixed ERC-55,
BIP173 and BIP350 published vectors. Only blockchain._Bad is a declared parser
exception; incidental TypeError/IndexError/etc are separate strict regressions.
"""
import hashlib
import random

import base58
import pytest
import rlp
from eth_hash.auto import keccak
from eth_keys import keys
from eth_utils import to_checksum_address

import blockchain as chain

EIP55 = [
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    "0xde709f2102306220921060314715629080e2fb77",
    "0x27b1fdb04752bbc536007a920d24acb045561c26",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]
G = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")


def clean_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except chain._Bad:
        return None


@pytest.mark.parametrize("message,digest", [
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
])
def test_keccak_fixed_vectors_not_sha3(message, digest):
    assert chain.keccak(message) == keccak(message) == bytes.fromhex(digest)
    assert chain.keccak(message) != hashlib.sha3_256(message).digest()


@pytest.mark.parametrize("size", [0, 1, 31, 32, 64, 135, 136, 137, 271, 272, 273, 4096])
def test_hash_rate_boundaries_and_random_bytes(size):
    data = random.Random(103 + size).randbytes(size)
    assert chain.keccak(data) == keccak(data)
    assert chain.sha256d(data) == hashlib.sha256(hashlib.sha256(data).digest()).digest()
    assert chain.hash160(data) == hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


@pytest.mark.parametrize("address", EIP55)
def test_published_eip55_and_classification(address):
    raw = bytes.fromhex(address[2:])
    assert chain.eip55(raw) == to_checksum_address(raw) == address
    expected = "none" if address[2:].islower() or address[2:].isupper() else "valid"
    assert chain.classify_eth_address(address) == {
        "bytes": raw, "checksum": expected, "checksummed": address}
    for plain in ("0x" + address[2:].lower(), "0x" + address[2:].upper()):
        assert chain.classify_eth_address(plain)["checksum"] == "none"


def test_mixed_case_wrong_checksum():
    address = "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    assert to_checksum_address(address) == EIP55[4] != address
    assert chain.classify_eth_address(address)["checksum"] == "invalid"


def test_missing_keccak_backend_never_substitutes_sha3(monkeypatch):
    monkeypatch.setattr(chain, "_keccak_mod", None)
    assert chain.keccak(b"abc") is None
    assert chain.eip55(bytes(20)) is None
    assert chain.classify_eth_address(EIP55[4]) is None
    assert chain.selector_of_signature("transfer(address,uint256)") is None
    assert chain.pub_to_address((int.from_bytes(G[:32], "big"), int.from_bytes(G[32:], "big"))) is None


@pytest.mark.parametrize("secret", [1, 2, 3, 0x123456789abcdef])
def test_pubkey_formats_and_derived_address_against_eth_keys(secret):
    pub = keys.PrivateKey(secret.to_bytes(32, "big")).public_key
    raw = pub.to_bytes()
    point = (int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    if secret == 1:
        assert raw == G  # SEC2/BIP173 generator, independent fixed lock.
        assert pub.to_checksum_address() == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    for encoded in (raw, b"\x04" + raw, pub.to_compressed_bytes()):
        assert chain.parse_pubkey(encoded) == point
    assert chain.pub_to_address(point) == pub.to_canonical_address()


@pytest.mark.parametrize("encoded", [b"", b"\0" * 64, b"\x04" + b"\0" * 64,
    b"\x02" + b"\xff" * 32, b"\x06" + G, b"\x05" + G[:32]])
def test_invalid_public_points_decline(encoded):
    assert chain.parse_pubkey(encoded) is None


# Published BIP350 addresses and their scriptPubKeys (includes BIP173 v0).
SEGWIT = [
    ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6", "p2wpkh", "mainnet"),
    ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", "p2wsh", "testnet"),
    ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "p2tr", "mainnet"),
    ("BC1SW50QGDZ25J", "6002751e", "segwit_other", "mainnet"),
]


@pytest.mark.parametrize("address,script,kind,network", SEGWIT)
def test_bip173_bip350_address_vectors(address, script, kind, network):
    raw = bytes.fromhex(script)
    version = 0 if raw[0] == 0 else raw[0] - 0x50
    hrp = address.lower().split("1")[0]
    spec = "bech32" if version == 0 else "bech32m"
    assert chain.segwit_decode(address) == {"hrp": hrp, "version": version, "program": raw[2:], "spec": spec}
    assert chain.segwit_encode(hrp, version, raw[2:]) == address.lower()
    parsed = chain.classify_btc_address(address)
    assert (parsed["kind"], parsed["network"], parsed["payload"], parsed["encoding"]) == (kind, network, raw[2:], spec)
    if kind != "segwit_other":
        assert chain.script_type(raw) == (kind, raw[2:])
        assert chain.address_of(kind, raw[2:], hrp) == address.lower()


@pytest.mark.parametrize("address", [
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",  # wrong variant
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",  # v0 wrong variant
    "bc1pw5dgrnzv",  # one-byte witness program
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",  # mixed case
    "bc1gmk9yu",  # empty data section
])
def test_published_invalid_witness_addresses(address):
    assert chain.segwit_decode(address) is None
    assert chain.classify_btc_address(address) is None


@pytest.mark.parametrize("encoded,spec", [("A12UEL5L", "bech32"), ("A1LQFN3A", "bech32m")])
def test_published_generic_bech32_vectors(encoded, spec):
    assert chain.bech32_decode(encoded) == ("a", [], spec)
    assert chain.bech32_encode("a", [], spec) == encoded.lower()


@pytest.mark.parametrize("address,version,kind", [
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0, "p2pkh"),
    ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", 5, "p2sh"),
])
def test_known_base58_addresses_against_independent_library(address, version, kind):
    raw = base58.b58decode_check(address)
    assert raw[0] == version
    assert chain.b58check_decode(address) == (version, raw[1:])
    assert chain.b58check_encode(version, raw[1:]) == address
    parsed = chain.classify_btc_address(address)
    assert parsed == {"kind": kind, "network": "mainnet", "payload": raw[1:],
                      "encoding": "base58check", "version_byte": version}
    assert chain.address_of(kind, raw[1:]) == address


def test_base58_and_rlp_library_vectors():
    for data in (b"\0", b"\0\0hello", b"CSCTF{base58}", bytes(range(256))):
        assert chain.b58encode(data) == base58.b58encode(data).decode()
        assert chain.b58decode(base58.b58encode(data).decode()) == data
    for value in (b"", b"dog", [b"cat", b"dog"], [], [[], [[]]], b"x" * 56, b"x" * 256):
        encoded = rlp.encode(value)
        assert chain.rlp_decode(encoded) == rlp.decode(encoded) == value
        assert chain.rlp_encode(value) == encoded


def test_expected_type_random_fuzz():
    rng = random.Random(0xC5C7F)
    for size in range(129):
        data = rng.randbytes(size)
        for fn in (chain.keccak, chain.sha256d, chain.hash160, chain.parse_pubkey,
                   chain.rlp_decode, chain.rlp_encode, chain.b58encode, chain.script_type):
            clean_call(fn, data)
        text = data.decode("latin-1")
        for fn in (chain.classify_eth_address, chain.classify_btc_address, chain.b58decode,
                   chain.b58check_decode, chain.bech32_decode, chain.segwit_decode):
            clean_call(fn, text)
    assert chain.rlp_decode(b"\x81\x00") is None  # noncanonical single byte
    assert chain.rlp_decode(b"\xb8\x01a") is None  # long form for short string


@pytest.mark.parametrize("data", [b"", b"\x01" * 19, b"\x02" * 21, b"\x03" * 32])
def test_eip55_rejects_wrong_width(data):
    assert clean_call(chain.eip55, data) is None


def test_eip55_long_input_fail_closed():
    clean_call(chain.eip55, bytes(33))


@pytest.mark.parametrize("fn,args", [
    (chain.keccak, ("bad",)), (chain.sha256d, (None,)), (chain.hash160, (None,)),
    (chain.parse_pubkey, (None,)), (chain.pub_to_address, ((-1, 0),)),
    (chain.rlp_decode, ("bad",)), (chain.rlp_encode, (-1,)),
    (chain.eip55, (None,)), (chain.classify_eth_address, (None,)),
    (chain.b58decode, (123,)), (chain.b58encode, (None,)),
    (chain.b58check_decode, (None,)), (chain.b58check_encode, (256, b"")),
    (chain.bech32_decode, (123,)), (chain.bech32_encode, ("bc", [32], "bech32")),
    (chain.segwit_decode, (123,)), (chain.segwit_encode, ("bc", 32, b"xx")),
    (chain.classify_btc_address, (None,)), (chain.script_type, (None,)),
    (chain.address_of, ("p2tr", None)),
], ids=lambda value: getattr(value, "__name__", None))
def test_primitive_malformed_type_contract(fn, args):
    clean_call(fn, *args)
