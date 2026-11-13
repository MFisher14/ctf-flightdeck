import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import multichain_depth as multi


def kinds(report):
    return {item["kind"] for item in report["findings"]}


def b58encode(data):
    zeros = len(data) - len(data.lstrip(b"\0"))
    value = int.from_bytes(data, "big")
    chars = ""
    while value:
        value, remainder = divmod(value, 58)
        chars = multi._B58[remainder] + chars
    return "1" * zeros + chars


def compact(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def test_base58_and_compact_u16_are_strict_and_canonical():
    for payload in (b"", b"\0", b"\0\0abc", bytes(range(32))):
        assert multi.b58decode(b58encode(payload)) == payload
    assert multi.decode_compact_u16(b"\xac\x02") == (300, 2)
    with pytest.raises(ValueError, match="character"):
        multi.b58decode("0OIl")
    with pytest.raises(ValueError, match="non-canonical"):
        multi.decode_compact_u16(b"\x80\x00")
    with pytest.raises(ValueError, match="truncated"):
        multi.decode_compact_u16(b"\x80")


def test_solana_transaction_resolves_accounts_and_decodes_system_transfer():
    payload = (2).to_bytes(4, "little") + (123456).to_bytes(8, "little")
    artifact = {
        "transaction": {"message": {
            "header": {"numRequiredSignatures": 1, "numReadonlySignedAccounts": 0,
                       "numReadonlyUnsignedAccounts": 1},
            "accountKeys": ["payer", "receiver", multi.SYSTEM_PROGRAM],
            "recentBlockhash": "blockhash",
            "instructions": [{"programIdIndex": 2, "accounts": [0, 1],
                              "data": b58encode(payload)}],
        }},
        "meta": {"err": None, "logMessages": ["Program 111 invoke [1]"]},
    }
    report = multi.analyze_solana_transaction(artifact)
    assert report["accounts"][0]["signer"] is True
    assert report["accounts"][1]["writable"] is True
    decoded = report["instructions"][0]["decoded"]
    assert decoded == {"raw_hex": payload.hex(), "length": 12, "family": "system",
                       "opcode": 2, "operation": "transfer", "lamports": 123456}
    assert report["findings"] == []


def test_solana_token_mutation_without_signer_and_runtime_evidence():
    token_program = next(iter(multi.TOKEN_PROGRAMS))
    data = bytes([3]) + (55).to_bytes(8, "little")
    report = multi.analyze_solana_transaction({
        "message": {
            "header": {"numRequiredSignatures": 0, "numReadonlySignedAccounts": 0,
                       "numReadonlyUnsignedAccounts": 1},
            "accountKeys": ["source", "destination", token_program],
            "instructions": [{"programIdIndex": 2, "accounts": [0, 1],
                              "data": [base64.b64encode(data).decode(), "base64"]}],
        },
        "meta": {"logMessages": ["Program failed: writable privilege escalated"]},
    })
    assert {"token-authority-not-transaction-signer", "runtime-privilege-escalation",
            "program-failure"} <= kinds(report)
    assert report["instructions"][0]["decoded"]["amount"] == 55


def test_solana_legacy_wire_transaction_parser_and_bounds():
    signature = bytes([7]) * 64
    accounts = bytes([1]) * 32 + bytes([2]) * 32
    payload = b"abc"
    wire = (
        compact(1) + signature + bytes([1, 0, 1]) + compact(2) + accounts + bytes([3]) * 32
        + compact(1) + bytes([1]) + compact(1) + bytes([0]) + compact(len(payload)) + payload
    )
    report = multi.parse_solana_wire_transaction(wire)
    assert report["version"] == "legacy"
    assert report["signatures"] == [signature.hex()]
    assert report["instructions"] == [{"index": 0, "program_id_index": 1,
                                       "account_indexes": [0], "data_hex": payload.hex()}]
    with pytest.raises(ValueError, match="truncated"):
        multi.parse_solana_wire_transaction(wire[:-1])
    corrupt = bytearray(wire)
    corrupt[-5] = 9  # account index immediately before compact payload length
    with pytest.raises(ValueError, match="unknown account"):
        multi.parse_solana_wire_transaction(bytes(corrupt))


def test_anchor_idl_finds_mutation_and_unchecked_account_constraints():
    idl = {
        "name": "unsafe",
        "instructions": [{
            "name": "drain",
            "accounts": [
                {"name": "vault", "isMut": True, "isSigner": False,
                 "type": "UncheckedAccount"},
                {"name": "authority", "isMut": False, "isSigner": True},
            ],
            "args": [],
        }, {
            "name": "mutateWithoutAuthority",
            "accounts": [{"name": "state", "writable": True, "type": "Account<State>"}],
        }],
    }
    report = multi.analyze_anchor_idl(idl)
    assert {"unchecked-writable-account", "readonly-authority",
            "anchor-mutation-without-signer"} <= kinds(report)
    assert [item["name"] for item in report["instructions"]] == ["drain", "mutateWithoutAuthority"]


def test_move_source_capabilities_signers_and_global_mutation():
    source = r"""
      module 0x1::Vault {
        struct AdminCap has key, store { id: UID }
        struct Vault has key { balance: u64 }
        public entry fun steal(address: address) acquires Vault {
          let vault = borrow_global_mut<Vault>(address);
          vault.balance = 0;
        }
        public fun mint_cap(): AdminCap { AdminCap { id: object::new() } }
        public entry fun guarded(account: &signer, address: address) acquires Vault {
          let vault = borrow_global_mut<Vault>(address);
          vault.balance = 1;
        }
        public entry fun bounded(account: &signer, v: &mut vector<u8>, i: u64) {
          assert!(i < vector::length(v), 1); vector::borrow_mut(v, i);
        }
      }
    """
    report = multi.analyze_move_source(source)
    assert report["modules"] == ["0x1::Vault"]
    assert report["capability_types"] == ["AdminCap"]
    assert {"move-global-mutation-without-signer", "move-unrestricted-capability-mint",
            "move-signer-not-bound-to-resource"} <= kinds(report)
    assert "move-vector-index-validation" not in kinds(report)


def test_move_binary_directory_and_duplicate_table_evidence():
    header = multi.MOVE_MAGIC + (7).to_bytes(4, "little") + bytes([2])
    # Move table directory entries are kind + ULEB128 offset + ULEB128 count.
    directory = bytes([1, 0, 2]) + bytes([1, 0, 3])
    report = multi.parse_move_bytecode(header + directory)
    assert report["version"] == 7
    assert report["duplicate_table_kinds"] is True
    assert kinds(report) == {"duplicate-move-table"}
    with pytest.raises(ValueError, match="not a Move"):
        multi.parse_move_bytecode(b"nope")


def test_move_manifest_and_transaction_artifact_routing():
    manifest = b"""
[package]
name = "demo"
[addresses]
demo = "_"
[dependencies]
Framework = { git = "https://example.invalid/framework.git" }
Local = { local = "../local" }
"""
    report = multi.analyze_artifact(manifest, "Move.toml")
    assert {"move-unassigned-address", "move-unpinned-git-dependency",
            "move-local-dependency"} <= kinds(report)
    transaction = {"payload": {"function": "0x1::vault::withdraw", "arguments": [10]},
                   "sender": "0xabc", "changes": [{"type": "write_resource", "address": "0x1"}],
                   "vm_status": "Move abort 7"}
    tx_report = multi.analyze_artifact(json.dumps(transaction).encode(), "aptos.json")
    assert tx_report["function"] == "0x1::vault::withdraw"
    assert tx_report["signers"] == ["0xabc"]
    assert kinds(tx_report) == {"move-transaction-failure"}
