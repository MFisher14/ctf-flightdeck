"""Independent wallet/transaction locks; no engine encoders are used as oracles.

Primary vectors: BIP32, Trezor python-mnemonic vectors.json, EIP-155, and
Solidity's documented mapping layout. Producers/oracles: bip32 (libsecp256k1),
mnemonic, eth-account/eth-keys, eth-abi, base58 and python-bitcoinlib.
All keys and signatures here are deterministic public test material.
"""
from __future__ import annotations

import hashlib
import random

import base58
from bip32 import BIP32
from bitcoin.core import COutPoint, CTransaction, CTxIn, CTxOut, CTxWitness, CTxInWitness
from bitcoin.core.script import CScript, CScriptWitness, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak
from eth_keys import keys
from eth_keys.exceptions import BadSignature
from eth_keyfile import keyfile
from mnemonic import Mnemonic
import pytest
import rlp

import blockchain as chain


PHRASE = "abandon " * 11 + "about"
SEED = bytes(range(16))  # BIP32 vector 1.
PRIV = (1).to_bytes(32, "big")
MNEMONIC_SEED = bytes.fromhex(
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6"
    "987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)
RAW155 = bytes.fromhex(
    "f86c098504a817c800825208943535353535353535353535353535353535353535"
    "880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c"
    "71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc"
    "64214b297fb1966a3b6d83"
)


def oracle_node(seed=SEED, path="m"):
    oracle = BIP32.from_seed(seed)
    raw = base58.b58decode_check(oracle.get_xpriv_from_path(path))
    return {"private": int.from_bytes(raw[-32:], "big"), "chain_code": raw[13:45],
            "depth": raw[4], "index": int.from_bytes(raw[9:13], "big"),
            "parent_fingerprint": raw[5:9]}


def test_bip39_published_and_library_oracles():
    # https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    assert chain.bip39_seed(PHRASE, "TREZOR") == MNEMONIC_SEED
    oracle = Mnemonic("english")
    assert chain.bip39_seed(PHRASE, "TREZOR", oracle.wordlist) == MNEMONIC_SEED
    unicode_password = "pássphrase é"
    assert chain.bip39_seed(PHRASE, unicode_password) == oracle.to_seed(PHRASE, unicode_password)
    assert chain.bip39_seed("abandon " * 12, wordlist=oracle.wordlist) is None


@pytest.mark.parametrize("path", ["m", "m/0'", "m/0'/1", "m/0'/1/2'", "m/0'/1/2'/2/1000000000"])
def test_bip32_paths_master_derive_and_extended_keys(path):
    oracle = BIP32.from_seed(SEED)
    expected_node = oracle_node(path=path)
    assert chain.bip32_master(SEED) == oracle_node()
    assert chain.bip32_derive(SEED, path) == expected_node
    # Extended-key input comes from the independent library, never chain's derive.
    assert chain.bip32_extended(expected_node) == oracle.get_xpriv_from_path(path)
    assert chain.bip32_extended(expected_node, private=False) == oracle.get_xpub_from_path(path)


@pytest.mark.parametrize("index", [0, 1, 0x80000000, 0xffffffff])
def test_bip32_child(index):
    assert chain.bip32_child(oracle_node(), index) == oracle_node(path=[index])


@pytest.mark.parametrize("path,expected", [("m", []), ("m/0'/1/2h", [2**31, 1, 2**31 + 2]),
                                             ("M/44H/60'/0'/0/0", [2**31 + 44, 2**31 + 60, 2**31, 0, 0])])
def test_bip32_path_syntax(path, expected):
    # Hardened-index representation is the BIP32 published convention.
    assert chain.parse_bip32_path(path) == expected


@pytest.mark.parametrize("private", [1, 2, 0x4646464646464646464646464646464646464646464646464646464646464646])
def test_private_address_against_eth_account(private):
    assert chain.private_to_eth_address(private) == Account.from_key(private.to_bytes(32, "big")).address


@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize("testnet", [False, True])
def test_wif_against_base58_library(compressed, testnet):
    payload = bytes([0xef if testnet else 0x80]) + PRIV + (b"\x01" if compressed else b"")
    expected = base58.b58encode_check(payload).decode()
    assert chain.wif_encode(1, compressed=compressed, testnet=testnet) == expected
    assert chain.wif_decode(expected) == {"private": 1, "compressed": compressed,
                                           "network": "testnet" if testnet else "mainnet"}


@pytest.mark.parametrize("compressed", [False, True])
def test_brainwallet_independent_hash_key_and_base58(compressed):
    private = hashlib.sha256(b"CSCTF{test_material}").digest()
    public = keys.PrivateKey(private).public_key
    pub_bytes = public.to_compressed_bytes() if compressed else b"\x04" + public.to_bytes()
    h160 = hashlib.new("ripemd160", hashlib.sha256(pub_bytes).digest()).digest()
    expected_wif = base58.b58encode_check(b"\x80" + private + (b"\x01" if compressed else b"")).decode()
    actual = chain.brainwallet("CSCTF{test_material}", compressed=compressed)
    assert actual == {"private": int.from_bytes(private, "big"), "wif": expected_wif,
                      "bitcoin": base58.b58encode_check(b"\x00" + h160).decode(),
                      "ethereum": Account.from_key(private).address}


def test_derive_wallet_against_mnemonic_and_bip32():
    seed = Mnemonic.to_seed(PHRASE)
    oracle = BIP32.from_seed(seed)
    path = "m/44'/60'/0'/0/0"
    actual = chain.derive_wallet(PHRASE, paths=[path])
    assert actual["seed"] == seed
    assert actual["master_xprv"] == oracle.get_xpriv()
    assert actual["master_xpub"] == oracle.get_xpub()
    [row] = actual["derived"]
    private, public = oracle.get_privkey_from_path(path), oracle.get_pubkey_from_path(path)
    assert row["private"] == private
    assert row["public"] == public
    assert row["ethereum"] == Account.from_key(private).address
    assert row["xprv"] == oracle.get_xpriv_from_path(path)
    assert row["xpub"] == oracle.get_xpub_from_path(path)
    assert row["wif"] == base58.b58encode_check(b"\x80" + private + b"\x01").decode()
    h160 = hashlib.new("ripemd160", hashlib.sha256(public).digest()).digest()
    assert row["bitcoin_p2pkh"] == base58.b58encode_check(b"\x00" + h160).decode()


@pytest.fixture
def keystore(monkeypatch):
    # Deterministic independently produced Web3 v3 document; never engine output.
    monkeypatch.setattr(keyfile.Random, "get_random_bytes", lambda n: bytes(range(n)))
    monkeypatch.setattr(keyfile, "uuid4", lambda: "00000000-0000-4000-8000-000000000001")
    return Account.encrypt(PRIV, "test password", kdf="pbkdf2", iterations=1000)


def test_keystore_against_eth_account(keystore):
    assert Account.decrypt(keystore, "test password") == PRIV
    assert chain.decrypt_keystore_v3(keystore, "test password") == {
        "private": PRIV, "ethereum": Account.from_key(PRIV).address,
        "verified_mac": True, "kdf": "pbkdf2", "cipher": "aes-128-ctr"}
    assert chain.decrypt_keystore_v3(keystore, "wrong") is None


@pytest.mark.parametrize("kind,value", [("uint256", 4), ("int256", -1),
    ("address", "0x" + "35" * 20), ("bytes32", bytes(range(32))), ("string", "CSCTF{mapping}"), ("bytes", b"\x00\xff")])
def test_mapping_slots_against_eth_abi_and_keccak(kind, value):
    # Solidity storage rule: dynamic string/bytes keys are unpadded raw bytes.
    encoded = value.encode() if kind == "string" else value if kind == "bytes" else encode([kind], [value])
    assert chain.storage_slot(value, 7, key_type=kind) == keccak(encoded + encode(["uint256"], [7]))


def test_nested_mapping_against_documented_hash_composition():
    first = keccak(encode(["uint256", "uint256"], [4, 1]))
    expected = keccak(encode(["uint256"], [9]) + first)
    assert chain.nested_storage_slot([(4, "uint256"), {"value": 9, "type": "uint256"}], 1) == expected


def test_published_eip155_and_eth_account_recovery():
    # https://eips.ethereum.org/EIPS/eip-155#example
    actual = chain.decode_evm_tx(RAW155)
    assert actual["nonce"] == 9
    assert actual["gas_price"] == 20 * 10**9
    assert actual["gas_limit"] == 21000
    assert actual["value"] == 10**18
    assert actual["to"] == "35" * 20
    assert actual["chain_id"] == 1
    assert actual["signing_hash"] == "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    assert actual["hash"] == keccak(RAW155).hex()
    assert actual["from"] == Account.recover_transaction(RAW155).lower().removeprefix("0x")


@pytest.mark.parametrize("transaction_type", [1, 2, 3])
def test_typed_transactions_produced_by_eth_account(transaction_type):
    tx = {"type": transaction_type, "chainId": 1, "nonce": 3, "gas": 30000,
          "to": "0x" + "35" * 20, "value": 120, "data": b"\xde\xad\xbe\xef", "accessList": []}
    if transaction_type == 1:
        tx["gasPrice"] = 100
    else:
        tx.update(maxPriorityFeePerGas=3, maxFeePerGas=100)
    if transaction_type == 3:
        tx.update(maxFeePerBlobGas=40, blobVersionedHashes=[b"\x01" + bytes(31)])
    signed = Account.sign_transaction(tx, PRIV)
    actual = chain.decode_evm_tx(bytes(signed.raw_transaction))
    assert actual["type"] == transaction_type
    assert actual["hash"] == signed.hash.hex()
    assert actual["from"] == Account.from_key(PRIV).address.lower().removeprefix("0x")
    assert actual["data"] == tx["data"]
    assert actual["selector"] == "deadbeef"
    assert actual["access_list_len"] == 0
    assert actual["gas_limit"] == 30000 and actual["nonce"] == 3
    if transaction_type == 3:
        assert actual["blob_versioned_hashes"] == 1 and actual["max_fee_per_blob_gas"] == 40


def test_ecrecover_and_signature_artifact_with_eth_keys():
    private = keys.PrivateKey(PRIV)
    digest = keccak(b"CSCTF{recovery}")
    signature = private.sign_msg_hash(digest)
    pub = private.public_key.to_bytes()
    assert chain.ecrecover_pub(digest, signature.r, signature.s, signature.v) == (
        int.from_bytes(pub[:32], "big"), int.from_bytes(pub[32:], "big"))
    assert chain.recover_signature({"sig": signature.to_bytes(), "hash": digest}) == (
        private.public_key.to_canonical_address(), "hash")
    personal = Account.sign_message(encode_defunct(text="CSCTF{recovery}"), PRIV)
    assert chain.recover_signature({"sig": bytes(personal.signature), "hash": None,
        "message": "CSCTF{recovery}", "claimed": private.public_key.to_canonical_address()}) == (
        private.public_key.to_canonical_address(), "eip191")


@pytest.mark.parametrize("witness", [False, True])
def test_btc_transaction_against_python_bitcoinlib(witness):
    public_hash = bytes(range(20))
    script = CScript([OP_DUP, OP_HASH160, public_hash, OP_EQUALVERIFY, OP_CHECKSIG])
    args = {"witness": CTxWitness([CTxInWitness(CScriptWitness([b"test signature", b"test pubkey"]))])} if witness else {}
    oracle = CTransaction([CTxIn(COutPoint(bytes(range(32)), 7), CScript(b""), 0xfffffffe)],
                          [CTxOut(1234567, script)], 123, 2, **args)
    raw = oracle.serialize()
    actual = chain.decode_btc_tx(raw)
    base = CTransaction(oracle.vin, oracle.vout, oracle.nLockTime, oracle.nVersion).serialize()
    assert actual["txid"] == oracle.GetTxid()[::-1].hex()
    assert actual["wtxid"] == oracle.GetHash()[::-1].hex()
    assert actual["weight"] == len(base) * 3 + len(raw)
    assert actual["segwit"] is witness
    assert actual["version"] == oracle.nVersion
    assert actual["locktime"] == oracle.nLockTime
    assert actual["inputs"][0]["vout"] == 7
    assert actual["outputs"][0]["value"] == 1234567
    assert actual["outputs"][0]["address"] == base58.b58encode_check(b"\x00" + public_hash).decode()


@pytest.mark.parametrize("entrypoint", ["bip39_seed", "bip32_master", "parse_bip32_path", "private_to_eth_address", "wif_encode", "wif_decode", "brainwallet", "derive_wallet"])
def test_public_wallet_empty_random_malformed_values_fail_closed(entrypoint):
    rng = random.Random(20261105)
    values = [None, b"", "", [], {}, -1, 0, 1.5, True, "not a mnemonic",
              *[rng.randbytes(n) for n in (1, 3, 7, 15, 17, 65, 97)]]
    for value in values:
        getattr(chain, entrypoint)(value)  # No public exception is declared: clean return is required.


def test_bip32_children_and_extended_typed_malformed_nodes_fail_closed():
    for node in ({}, {"private": 0}, {"private": 1, "chain_code": b""}, oracle_node() | {"private": 0},
                 oracle_node() | {"depth": 256}, oracle_node() | {"chain_code": bytes(31)}):
        chain.bip32_child(node, 0)
        chain.bip32_extended(node)
    for index in (-1, 2**32):
        assert chain.bip32_child(oracle_node(), index) is None
    for path in ("", "x/0", "m/01", "m//1", "m/-1", "m/2147483648", "m/1.0"):
        assert chain.bip32_derive(SEED, path) is None


def test_keystore_random_types_and_corrupted_fields_fail_closed(keystore):
    for document in (None, [], "", b"", {}, {"version": 3}, {"version": 3, "crypto": {}},
                     {"version": 3, "crypto": {"ciphertext": "zz"}}):
        assert chain.decrypt_keystore_v3(document, "x") is None
    for field in ("ciphertext", "mac"):
        damaged = dict(keystore, crypto=dict(keystore["crypto"], **{field: "ff"}))
        assert chain.decrypt_keystore_v3(damaged, "test password") is None


def test_storage_empty_and_random_malformed_values_fail_closed():
    rng = random.Random(92)
    for value in (None, [], {}, "", "not int", *[rng.randbytes(n) for n in (0, 1, 31, 33)]):
        chain.storage_slot(value, 1)
    for value in (None, [], {}, "", [None], [[1]], [[1, "no-such-type"]]):
        assert chain.nested_storage_slot(value, 1) is None
    for slot in (-1, 2**256, False, "0"):
        assert chain.storage_slot(1, slot) is None


def test_transaction_and_ecrecover_binary_fuzz_returns_cleanly():
    rng = random.Random(771)
    for data in [b"", *[rng.randbytes(n) for n in range(100)]]:
        chain.decode_evm_tx(data)
        chain.decode_btc_tx(data)
        chain.ecrecover_pub(data, 0, 0, 0)
    for length in range(len(RAW155)):
        assert chain.decode_evm_tx(RAW155[:length]) is None


def test_bug_bip39_unhashable_wordlist_is_rejected():
    assert chain.bip39_seed(PHRASE, wordlist=[[]] * 2048) is None


def test_bug_bip32_derive_none_is_rejected():
    assert chain.bip32_derive(None, "m") is None


def test_bug_bip32_child_string_index_is_rejected():
    assert chain.bip32_child(oracle_node(), "0") is None


def test_bug_bip32_extended_negative_index_is_rejected():
    assert chain.bip32_extended(oracle_node() | {"index": -1}) is None


def test_bug_bip32_negative_depth_is_rejected():
    assert chain.bip32_child(oracle_node() | {"depth": -1}, 0) is None


@pytest.mark.parametrize("fn,args", [("bip39_seed", (PHRASE, "\ud800")), ("brainwallet", ("\ud800",)),
    ("decrypt_keystore_v3", ("fixture", "\ud800")), ("storage_slot", ("\ud800", 0))])
def test_bug_surrogate_inputs_fail_closed(fn, args, keystore):
    if fn == "decrypt_keystore_v3":
        args = (keystore, args[1])
    kwargs = {"key_type": "string"} if fn == "storage_slot" else {}
    assert getattr(chain, fn)(*args, **kwargs) is None


@pytest.mark.parametrize("value", [{}, {"sig": b""}, {"sig": bytes(65), "hash": None, "message": None, "claimed": bytes(20)}])
def test_bug_malformed_signature_artifact_is_rejected(value):
    assert chain.recover_signature(value) == (None, None)


@pytest.mark.parametrize("entrypoint", ["decode_btc_tx", "ecrecover_pub"])
def test_bug_none_binary_inputs_fail_closed(entrypoint):
    if entrypoint == "ecrecover_pub":
        assert chain.ecrecover_pub(None, 1, 1, 0) is None
    else:
        assert chain.decode_btc_tx(None) is None


def test_bug_evm_zero_signature_scalar_is_rejected():
    fields = rlp.decode(RAW155)
    fields[-2] = b""
    bad = rlp.encode(fields)
    with pytest.raises(BadSignature):
        Account.recover_transaction(bad)
    assert chain.decode_evm_tx(bad) is None


def test_bug_btc_negative_amount_is_not_reinterpreted_unsigned():
    # CAmount is a signed int64 in Bitcoin Core; negative amounts are invalid
    # transactions but must not become enormous positive amounts in a parser.
    oracle = CTransaction([CTxIn(COutPoint(bytes(32), 0), CScript(b""), 0xffffffff)],
                          [CTxOut(-1, CScript([OP_DUP]))], 0, 1)
    actual = chain.decode_btc_tx(oracle.serialize())
    assert actual is None or actual["outputs"][0]["value"] == oracle.vout[0].nValue
