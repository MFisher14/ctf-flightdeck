"""Independent Solana/Move vectors and deterministic fail-closed probes.

Oracles: solders' Rust transaction serializer, base58, tomllib, official Solana
short-vec Rust tests and the published Move empty_script.mv fixture. Nothing is
sent to a network or executed by these tests.

Sources:
https://github.com/anza-xyz/solana-sdk/blob/master/short-vec/src/lib.rs
https://github.com/aptos-labs/aptos-core/blob/main/third_party/move/move-binary-format/src/unit_tests/empty_script.mv
https://github.com/aptos-labs/aptos-core/blob/main/third_party/move/move-binary-format/src/serializer.rs
https://www.anchor-lang.com/docs/basics/idl
https://move-language.github.io/move/modules-and-scripts.html
"""
import base64
import json
import random
import tomllib

import base58
import pytest
from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message, MessageV0
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction, VersionedTransaction

import multichain_depth as engine


def _closed(call):
    try:
        return call()
    except Exception as error:
        assert isinstance(error, ValueError), f"leaked {type(error).__name__}: {error}"


def _solders_transaction(versioned=False):
    payer = Keypair.from_seed(bytes(range(32)))
    recipient = Pubkey.from_bytes(bytes([7]) * 32)
    blockhash = Hash.from_bytes(bytes([9]) * 32)
    instruction = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=recipient,
                                         lamports=123456789))
    if versioned:
        message = MessageV0.try_compile(payer.pubkey(), [instruction], [], blockhash)
        transaction = VersionedTransaction(message, [payer])
    else:
        message = Message.new_with_blockhash([instruction], payer.pubkey(), blockhash)
        transaction = Transaction([payer], message, blockhash)
    return transaction, message, instruction


def test_base58_reference_library():
    rng = random.Random(210)
    for blob in [b"", bytes(32), b"CSCTF{base58}", *[rng.randbytes(n) for n in range(70)]]:
        encoded = base58.b58encode(blob).decode()
        assert engine.b58decode(encoded) == base58.b58decode(encoded) == blob


@pytest.mark.parametrize("value,encoded", [(0, b"\x00"), (127, b"\x7f"),
    (128, b"\x80\x01"), (255, b"\xff\x01"), (256, b"\x80\x02"),
    (32767, b"\xff\xff\x01"), (65535, b"\xff\xff\x03")])
def test_official_solana_shortvec_vectors(value, encoded):
    assert engine.decode_compact_u16(encoded) == (value, len(encoded))
    assert engine.decode_compact_u16(b"XX" + encoded, 2) == (value, 2 + len(encoded))


@pytest.mark.parametrize("versioned", [False, True])
def test_solders_wire_transaction_oracle(versioned):
    transaction, message, _ = _solders_transaction(versioned)
    actual = engine.parse_solana_wire_transaction(bytes(transaction))
    compiled = message.instructions[0]
    assert actual["version"] == (0 if versioned else "legacy")
    assert actual["signatures"] == [bytes(sig).hex() for sig in transaction.signatures]
    assert actual["accounts_hex"] == [bytes(key).hex() for key in message.account_keys]
    assert actual["recent_blockhash_hex"] == bytes(message.recent_blockhash).hex()
    assert actual["header"] == {"numRequiredSignatures": message.header.num_required_signatures,
        "numReadonlySignedAccounts": message.header.num_readonly_signed_accounts,
        "numReadonlyUnsignedAccounts": message.header.num_readonly_unsigned_accounts}
    assert actual["instructions"] == [{"index": 0, "program_id_index": compiled.program_id_index,
        "account_indexes": list(compiled.accounts), "data_hex": bytes(compiled.data).hex()}]
    assert engine.analyze_artifact(bytes(transaction), "capture.soltx")["accounts_hex"] == [
        bytes(key).hex() for key in message.account_keys]


def test_solders_json_transaction_and_instruction_oracle():
    _, message, instruction = _solders_transaction()
    compiled = message.instructions[0]
    artifact = {"message": {"header": {"numRequiredSignatures": 1,
        "numReadonlySignedAccounts": 0, "numReadonlyUnsignedAccounts": 1},
        "accountKeys": [str(key) for key in message.account_keys],
        "recentBlockhash": str(message.recent_blockhash), "instructions": [{
            "programIdIndex": compiled.program_id_index, "accounts": list(compiled.accounts),
            "data": [base64.b64encode(bytes(instruction.data)).decode(), "base64"]}]}}
    actual = engine.analyze_solana_transaction(artifact)
    assert [row["pubkey"] for row in actual["accounts"]] == [str(key) for key in message.account_keys]
    assert [row["signer"] for row in actual["accounts"]] == [True, False, False]
    assert [row["writable"] for row in actual["accounts"]] == [True, True, False]
    assert actual["instructions"][0]["decoded"]["lamports"] == 123456789
    assert actual["instructions"][0]["decoded"]["operation"] == "transfer"
    assert actual["instructions"][0]["program"] == str(instruction.program_id)
    assert engine.analyze_artifact(json.dumps(artifact).encode())["recent_blockhash"] == str(message.recent_blockhash)


def test_anchor_idl_schema_vector():
    # Anchor's published IDL account schema distinguishes signer/writable flags.
    text = '{"name":"counter","instructions":[{"name":"increment","accounts":[{"name":"counter","writable":true},{"name":"authority","signer":true}],"args":[]}]}'
    fixture = json.loads(text)
    expected = fixture["instructions"][0]
    actual = engine.analyze_anchor_idl(fixture)
    assert actual["name"] == fixture["name"]
    assert actual["instructions"] == [expected]
    assert not any(f["kind"] == "anchor-mutation-without-signer" for f in actual["findings"])
    assert engine.analyze_artifact(text.encode())["instructions"] == [expected]


def test_move_source_language_vector():
    # Explicit Move module/entry/signer syntax; structural facts, not vulnerability claims.
    source = "module 0x42::example {\nstruct Resource has key { value: u64 }\npublic entry fun create(account: &signer) { move_to(account, Resource { value: 1 }); }\n}"
    actual = engine.analyze_move_source(source)
    assert actual["modules"] == ["0x42::example"]
    assert actual["resources"] == ["Resource"]
    assert actual["functions"] == [{"name": "create", "line": 3, "public_entry": True,
        "has_signer": True, "global_mutation": True, "capability_construction": False}]
    assert engine.analyze_artifact(source.encode(), "example.move")["modules"] == ["0x42::example"]


def test_move_book_published_module_vector():
    # Exact module example (spacing aside) from Move Book /modules-and-scripts.
    source = """module 0x42::test {
    struct Example has copy, drop { i: u64 }

    use std::debug;
    friend 0x42::another_test;

    const ONE: u64 = 1;

    public fun print(x: u64) {
        let sum = x + ONE;
        let example = Example { i: sum };
        debug::print(&sum)
    }
}"""
    actual = engine.analyze_move_source(source)
    assert actual["modules"] == ["0x42::test"]
    assert actual["friends"] == ["0x42::another_test"]
    assert actual["functions"] == [{"name": "print", "line": 9, "public_entry": True,
        "has_signer": False, "global_mutation": False, "capability_construction": False}]


def test_b58_explicit_type_error_contract():
    # This one API explicitly declares TypeError by design, unlike leaks below.
    with pytest.raises(TypeError, match="base58 value must be text"):
        engine.b58decode(None)


@pytest.mark.parametrize("parser", [engine.parse_move_bytecode,
    lambda raw: engine.analyze_artifact(raw, "empty_script.mv")], ids=["parse_move_bytecode", "analyze_artifact"])
def test_published_move_binary_vector(parser):
    # Exact 18 bytes from Aptos's checked-in empty_script.mv; table kind 5 is
    # SIGNATURES, offset 0, byte count 1. No engine-generated bytes are used.
    blob = bytes.fromhex("a11ceb0b0100000001050001000000000102")
    assert parser(blob)["tables"] == [{"kind": 5, "offset": 0, "count": 1}]


def test_manifest_tomllib_oracle():
    text = '[package]\nname = "Example"\n[addresses]\nexample = "0x42"\n[dependencies]\nMoveStdlib = { git = "https://example.test/move", rev = "' + "a" * 40 + '" }\n'
    expected = tomllib.loads(text)
    actual = engine.analyze_move_manifest(text)
    assert actual["addresses"] == expected["addresses"]
    for dependency in actual["dependencies"]:
        assert tomllib.loads("item=" + dependency["value"])["item"] == expected["dependencies"][dependency["name"]]
    assert actual["findings"] == []


def test_manifest_hash_inside_toml_string():
    text = '[addresses]\nexample = "0x42#comment-is-data"\n'
    assert engine.analyze_move_manifest(text)["addresses"] == tomllib.loads(text)["addresses"]


def test_move_transaction_json_schema_vector():
    # Aptos entry_function_payload and write_resource shape; values are JSON data.
    text = '{"sender":"0x42","success":true,"payload":{"type":"entry_function_payload","function":"0x1::coin::transfer","arguments":["0x99","100"],"type_arguments":["0x1::aptos_coin::AptosCoin"]},"changes":[{"type":"write_resource","address":"0x42"}]}'
    fixture = json.loads(text)
    actual = engine.analyze_move_transaction(fixture)
    assert actual["function"] == fixture["payload"]["function"]
    assert actual["arguments"] == fixture["payload"]["arguments"]
    assert actual["type_arguments"] == fixture["payload"]["type_arguments"]
    assert actual["signers"] == [fixture["sender"]]
    assert actual["mutations"] == [{"type": "write_resource", "address": "0x42", "owner": None}]
    assert actual["status"] is True
    assert engine.analyze_artifact(text.encode())["function"] == fixture["payload"]["function"]


def test_binary_and_text_failclosed_fuzz():
    rng = random.Random(20261105)
    blobs = [b"", *[rng.randbytes(n) for n in range(256)]]
    for blob in blobs:
        for parser in (engine.decode_compact_u16, engine.parse_solana_wire_transaction,
                       engine.parse_move_bytecode, engine.analyze_artifact):
            _closed(lambda: parser(blob))
        text = blob.decode("latin1")
        for parser in (engine.b58decode, engine.analyze_move_source, engine.analyze_move_manifest):
            _closed(lambda: parser(text))
    transaction, _, _ = _solders_transaction()
    wire = bytes(transaction)
    for size in range(len(wire)):
        _closed(lambda: engine.parse_solana_wire_transaction(wire[:size]))


def test_mapping_failclosed_fuzz():
    for artifact in ({}, {"instructions": None}, {"instructions": "bad"},
                     {"message": None}, {"accountKeys": "bad"},
                     {"payload": []}, {"changes": None}):
        for parser in (engine.analyze_anchor_idl, engine.analyze_solana_transaction, engine.analyze_move_transaction):
            _closed(lambda: parser(artifact))


@pytest.mark.parametrize("parser", [engine.decode_compact_u16, engine.parse_solana_wire_transaction,
    engine.parse_move_bytecode, engine.analyze_solana_transaction, engine.analyze_anchor_idl,
    engine.analyze_move_source, engine.analyze_move_manifest, engine.analyze_move_transaction,
    engine.analyze_artifact], ids=lambda f: f.__name__)
def test_invalid_root_type_fail_closed(parser):
    _closed(lambda: parser(None))


def test_cli_vector(tmp_path, capsys):
    transaction, message, _ = _solders_transaction()
    path = tmp_path / "transfer.soltx"
    path.write_bytes(bytes(transaction))
    assert engine.main([str(path)]) == 0
    actual = json.loads(capsys.readouterr().out)
    assert actual["accounts_hex"] == [bytes(key).hex() for key in message.account_keys]


def test_cli_failclosed_argparse():
    assert engine.main([]) == 2


def test_cli_failclosed_missing_file(tmp_path):
    assert engine.main([str(tmp_path / "missing")]) == 2
