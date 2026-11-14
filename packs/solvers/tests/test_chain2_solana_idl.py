"""Non-circular vectors for the chain2 Solana IDL/account engine.

Primary fixture and published discriminators:
https://github.com/solana-foundation/idl-spec/blob/main/examples/counter.json
https://www.anchor-lang.com/docs/basics/idl

Borsh bytes below are packed directly with :mod:`struct`; the engine never
produces its own expected input.
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct

import base58
import pytest

import chain2_solana_idl as engine


PROGRAM = "D85Kq6fNENDLeyRPBdLMVXDyrkEgnq5a7vFPoscvq5bX"
SYSTEM = "11111111111111111111111111111111"
INCREMENT = bytes([11, 18, 104, 9, 104, 174, 59, 33])
INITIALIZE = bytes([175, 175, 109, 31, 13, 152, 155, 237])
COUNTER = bytes([255, 176, 4, 245, 188, 253, 124, 25])


def counter_idl() -> dict:
    """Return the Solana Foundation's published IDL 0.1.0 counter example."""

    return {
        "$schema": "../schema/v0.1.0.json",
        "address": PROGRAM,
        "metadata": {
            "name": "counter", "version": "0.1.0", "spec": "0.1.0",
            "description": "Created with Anchor",
        },
        "instructions": [
            {
                "name": "increment", "discriminator": list(INCREMENT),
                "accounts": [
                    {
                        "name": "counter", "writable": True,
                        "pda": {"seeds": [
                            {"kind": "const", "value": list(b"counter")},
                            {"kind": "account", "path": "authority"},
                        ]},
                    },
                    {"name": "authority", "signer": True, "relations": ["counter"]},
                ],
                "args": [{"name": "amount", "type": "u64"}],
            },
            {
                "name": "initialize", "discriminator": list(INITIALIZE),
                "accounts": [
                    {
                        "name": "counter", "writable": True,
                        "pda": {"seeds": [
                            {"kind": "const", "value": list(b"counter")},
                            {"kind": "account", "path": "authority"},
                        ]},
                    },
                    {"name": "authority", "writable": True, "signer": True},
                    {"name": "system_program", "address": SYSTEM},
                ],
                "args": [],
            },
        ],
        "accounts": [{"name": "Counter", "discriminator": list(COUNTER)}],
        "events": [{
            "name": "CounterUpdated",
            "discriminator": [56, 210, 136, 13, 88, 67, 151, 167],
        }],
        "errors": [{"code": 6000, "name": "Overflow", "msg": "Counter overflow"}],
        "types": [
            {
                "name": "Counter", "type": {"kind": "struct", "fields": [
                    {"name": "authority", "type": "pubkey"},
                    {"name": "count", "type": "u64"},
                    {"name": "bump", "type": "u8"},
                ]},
            },
            {
                "name": "CounterUpdated", "type": {"kind": "struct", "fields": [
                    {"name": "counter", "type": "pubkey"},
                    {"name": "authority", "type": "pubkey"},
                    {"name": "old_value", "type": "u64"},
                    {"name": "new_value", "type": "u64"},
                ]},
            },
        ],
        "constants": [{
            "name": "COUNTER_SEED", "type": "bytes",
            "value": "[99, 111, 117, 110, 116, 101, 114]",
        }],
    }


def issue_kinds(report: dict) -> set[str]:
    return {str(item["kind"]) for item in report["findings"]}


def test_published_counter_catalog_and_anchor_hash_vector():
    # Anchor documents the default derivation as sha256("global:" + name)[:8].
    assert hashlib.sha256(b"global:initialize").digest()[:8] == INITIALIZE

    report = engine.analyze_idl(counter_idl())
    assert report["kind"] == "solana-idl-0.1.0"
    assert report["program_address"] == PROGRAM
    assert report["metadata"] == {"name": "counter", "version": "0.1.0", "spec": "0.1.0"}
    assert [(row["name"], row["discriminator_hex"]) for row in report["instructions"]] == [
        ("increment", INCREMENT.hex()), ("initialize", INITIALIZE.hex())]
    assert report["accounts"] == [{"name": "Counter", "discriminator_hex": COUNTER.hex()}]
    assert report["discriminator_issues"] == []

    metas = report["instructions"][0]["accounts"]
    assert [row["path"] for row in metas] == ["counter", "authority"]
    assert metas[0]["pda"]["seeds"] == [
        {"kind": "const", "value_hex": b"counter".hex(), "resolved": True},
        {"kind": "account", "path": "authority", "resolved": False},
    ]
    assert metas[0]["pda"]["seed_framing_ambiguous"] is True
    assert report["authenticity_verified"] is False


def test_increment_instruction_uses_hand_packed_borsh_and_checks_metas():
    # u64 is little-endian in Borsh; this encoding does not call the engine.
    data = INCREMENT + struct.pack("<Q", 42)
    report = engine.match_instruction(counter_idl(), data, account_metas=[
        {"address": SYSTEM, "signer": True, "writable": False},
        {"address": PROGRAM, "signer": False, "writable": False},
    ])
    assert report is not None
    assert report["instruction"] == "increment"
    assert report["arguments"] == {"amount": 42}
    assert report["consumed"] == len(data)
    assert {item["kind"] for item in report["account_findings"]} == {
        "unexpected-signer-privilege", "missing-writable-privilege", "missing-signer-privilege"
    }
    assert report["execution_verified"] is False
    assert engine.match_instruction(counter_idl(), b"\x99" * 8) is None


def test_counter_program_account_uses_hand_packed_borsh_and_envelope_facts():
    authority_raw = bytes(range(32))
    authority = base58.b58encode(authority_raw).decode("ascii")
    # Published Counter layout: pubkey, u64, u8.
    account_data = COUNTER + authority_raw + struct.pack("<Q", 9) + b"\x07"
    report = engine.analyze_program_account(
        counter_idl(), account_data, owner=SYSTEM, executable=True,
    )
    assert report["account_type"] == "Counter"
    assert report["discriminator_hex"] == COUNTER.hex()
    assert report["value"] == {"authority": authority, "count": 9, "bump": 7}
    assert report["owner_matches"] is False
    assert issue_kinds(report) == {"owner-mismatch", "unexpected-executable-data-account"}
    assert report["authenticity_verified"] is False


def test_variable_length_discriminators_and_prefix_ambiguity_decline_matching():
    idl = counter_idl()
    idl["instructions"][0]["discriminator"] = [1]
    idl["instructions"][1]["discriminator"] = [1, 2, 3]
    report = engine.analyze_idl(idl)
    assert report["discriminator_issues"] == [{
        "namespace": "instruction", "kind": "prefix-ambiguity",
        "names": ["increment", "initialize"], "prefix_hex": "01", "longer_hex": "010203",
    }]
    with pytest.raises(engine.SolanaIDLAnalysisError, match="ambiguous"):
        engine.match_instruction(idl, b"\x01" + struct.pack("<Q", 1))

    duplicate = counter_idl()
    duplicate["instructions"][0]["discriminator"] = [7, 8]
    duplicate["instructions"][1]["discriminator"] = [7, 8]
    assert engine.analyze_idl(duplicate)["discriminator_issues"][0]["kind"] == "duplicate"


def test_borsh_struct_containers_and_enum_against_manual_reference():
    idl = counter_idl()
    idl["types"].extend([
        {
            "name": "Choice", "type": {"kind": "enum", "variants": [
                {"name": "None"},
                {"name": "Value", "fields": [{"name": "amount", "type": "i16"}]},
            ]},
        },
        {
            "name": "Complex", "type": {"kind": "struct", "fields": [
                {"name": "flag", "type": "bool"},
                {"name": "nums", "type": {"vec": "u16"}},
                {"name": "maybe", "type": {"option": "u32"}},
                {"name": "label", "type": "string"},
                {"name": "choice", "type": {"defined": {"name": "Choice"}}},
            ]},
        },
    ])
    # bool; vec<u16>; Some(u32); UTF-8 string; enum tag 1 + named i16 field.
    raw = (b"\x01" + struct.pack("<I", 3) + struct.pack("<HHH", 2, 3, 65535)
           + b"\x01" + struct.pack("<I", 99)
           + struct.pack("<I", 2) + b"hi"
           + b"\x01" + struct.pack("<h", -7))
    report = engine.decode_borsh(idl, "Complex", raw)
    assert report["value"] == {
        "flag": True, "nums": [2, 3, 65535], "maybe": 99, "label": "hi",
        "choice": {"variant": "Value", "value": {"amount": -7}},
    }
    assert report["consumed"] == len(raw) and report["trailing"] == 0

    with pytest.raises(engine.SolanaIDLAnalysisError, match="bool"):
        engine.decode_borsh(idl, "Complex", b"\x02" + raw[1:])
    with pytest.raises(engine.SolanaIDLAnalysisError, match="trailing"):
        engine.decode_borsh(idl, "Complex", raw + b"\x00")


def test_non_borsh_and_unknown_spec_are_explicitly_declined():
    idl = counter_idl()
    idl["types"][0]["serialization"] = "bytemuck"
    report = engine.analyze_idl(idl)
    counter = next(row for row in report["types"] if row["name"] == "Counter")
    assert counter["borsh_decodable"] is False
    assert report["decoding_declines"] == [{
        "type": "Counter", "reasons": ["serialization='bytemuck'"]}]
    with pytest.raises(engine.SolanaIDLAnalysisError, match="non-Borsh"):
        engine.decode_borsh(idl, "Counter", bytes(41))

    legacy = counter_idl()
    legacy["metadata"]["spec"] = "0.0.0"
    with pytest.raises(engine.SolanaIDLAnalysisError, match="0.1.0"):
        engine.analyze_idl(legacy)


def test_public_apis_never_leak_stdlib_exceptions_on_malformed_inputs():
    calls = [
        lambda: engine.analyze_idl(None),
        lambda: engine.analyze_idl({}),
        lambda: engine.decode_borsh(counter_idl(), "Counter", None),
        lambda: engine.decode_borsh(counter_idl(), "Missing", b""),
        lambda: engine.match_instruction(counter_idl(), None),
        lambda: engine.match_instruction(counter_idl(), INCREMENT + b"\x00", account_metas="bad"),
        lambda: engine.analyze_program_account(counter_idl(), None),
        lambda: engine.analyze_program_account(counter_idl(), COUNTER, owner="not-base58"),
    ]
    for call in calls:
        with pytest.raises(engine.SolanaIDLAnalysisError):
            call()


def test_guarded_cli_catalog_instruction_and_argparse(tmp_path, capsys):
    idl_path = tmp_path / "counter.json"
    idl_path.write_text(json.dumps(counter_idl()), encoding="utf-8")

    assert engine.main(["catalog", str(idl_path)]) == 0
    assert json.loads(capsys.readouterr().out)["program_address"] == PROGRAM

    artifact = (INCREMENT + struct.pack("<Q", 123)).hex()
    assert engine.main(["instruction", str(idl_path), artifact, "--hex"]) == 0
    assert json.loads(capsys.readouterr().out)["arguments"] == {"amount": 123}

    assert engine.main([]) == 2
    assert engine.main(["catalog", str(tmp_path / "missing.json")]) == 2
