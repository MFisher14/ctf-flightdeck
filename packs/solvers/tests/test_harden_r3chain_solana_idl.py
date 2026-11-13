"""Independent hardening vectors for :mod:`chain2_solana_idl`.

Oracles:

* Solana Foundation IDL 0.1.0 schema and specification:
  https://github.com/solana-foundation/idl-spec/tree/main
* Anchor's published ``initialize``, ``NewAccount`` and ``NewEvent``
  discriminator examples:
  https://www.anchor-lang.com/docs/basics/idl
* Borsh's documented little-endian, u32-length, option/vector and enum layout:
  https://borsh.io/

All wire bytes are packed here with :mod:`struct`; no output from the engine is
used to create an expected value.  ``solders`` independently renders public-key
bytes.  Tests never contact RPC or any other network service.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import random
import struct

import pytest
from solders.pubkey import Pubkey

import chain2_solana_idl as engine


PROGRAM_RAW = bytes([7]) * 32
PROGRAM = str(Pubkey.from_bytes(PROGRAM_RAW))
SYSTEM_RAW = bytes(32)
SYSTEM = str(Pubkey.from_bytes(SYSTEM_RAW))
OWNER_RAW = bytes(range(32))
OWNER = str(Pubkey.from_bytes(OWNER_RAW))
PAYER_RAW = bytes(range(32, 64))
PAYER = str(Pubkey.from_bytes(PAYER_RAW))

# Published Anchor documentation vectors, independently reproduced by hashlib.
INITIALIZE = bytes.fromhex("afaf6d1f0d989bed")
NEW_ACCOUNT = bytes.fromhex("b05f04765bb17de8")
NEW_EVENT = bytes.fromhex("7115b946a463e8c9")


def fixture_idl() -> dict[str, object]:
    """A schema-shaped IDL using only independently documented constructs."""

    return {
        "address": PROGRAM,
        "metadata": {"name": "hardened", "version": "1.2.3", "spec": "0.1.0"},
        "instructions": [
            {
                "name": "initialize",
                "discriminator": list(INITIALIZE),
                "accounts": [
                    {
                        "name": "authorityGroup",
                        "accounts": [
                            {"name": "payer", "writable": True, "signer": True},
                            {"name": "systemProgram", "address": SYSTEM},
                        ],
                    }
                ],
                "args": [
                    {"name": "amount", "type": "u64"},
                    {"name": "memo", "type": "string"},
                    {"name": "flags", "type": {"array": ["u8", 3]}},
                    {"name": "maybe", "type": {"option": "u16"}},
                ],
            }
        ],
        "accounts": [{"name": "NewAccount", "discriminator": list(NEW_ACCOUNT)}],
        "events": [{"name": "NewEvent", "discriminator": list(NEW_EVENT)}],
        "types": [
            {
                "name": "Status",
                "type": {
                    "kind": "enum",
                    "variants": [
                        {"name": "Empty"},
                        {
                            "name": "Ready",
                            "fields": [{"name": "code", "type": "u16"}],
                        },
                    ],
                },
            },
            {
                "name": "NewAccount",
                "type": {
                    "kind": "struct",
                    "fields": [
                        {"name": "owner", "type": "pubkey"},
                        {"name": "amount", "type": "u64"},
                        {"name": "active", "type": "bool"},
                        {"name": "delta", "type": "i32"},
                        {"name": "ratio", "type": "f32"},
                        {"name": "memo", "type": "string"},
                        {"name": "blob", "type": "bytes"},
                        {"name": "maybe", "type": {"option": "u16"}},
                        {"name": "samples", "type": {"vec": "i16"}},
                        {"name": "fixed", "type": {"array": ["u8", 3]}},
                        {"name": "status", "type": {"defined": {"name": "Status"}}},
                    ],
                },
            },
            {
                "name": "NewEvent",
                "type": {
                    "kind": "struct",
                    "fields": [{"name": "value", "type": "u64"}],
                },
            },
        ],
    }


def instruction_bytes() -> bytes:
    memo = "war-room".encode("utf-8")
    return b"".join(
        [
            INITIALIZE,
            struct.pack("<Q", 0x0102030405060708),
            struct.pack("<I", len(memo)),
            memo,
            bytes([1, 2, 255]),
            b"\x01",
            struct.pack("<H", 500),
        ]
    )


def account_value_bytes() -> bytes:
    memo = "λ-war".encode("utf-8")
    blob = b"\x00\xff\x10"
    return b"".join(
        [
            OWNER_RAW,
            struct.pack("<Q", 9_876_543_210),
            b"\x01",
            struct.pack("<i", -123456),
            struct.pack("<f", 1.5),
            struct.pack("<I", len(memo)),
            memo,
            struct.pack("<I", len(blob)),
            blob,
            b"\x01",
            struct.pack("<H", 65000),
            struct.pack("<I", 3),
            struct.pack("<hhh", -1, 2, -3),
            bytes([4, 5, 6]),
            b"\x01",
            struct.pack("<H", 0xBEEF),
        ]
    )


def expected_account_value() -> dict[str, object]:
    return {
        "owner": OWNER,
        "amount": 9_876_543_210,
        "active": True,
        "delta": -123456,
        "ratio": 1.5,
        "memo": "λ-war",
        "blob": "0x00ff10",
        "maybe": 65000,
        "samples": [-1, 2, -3],
        "fixed": [4, 5, 6],
        "status": {"variant": "Ready", "value": {"code": 0xBEEF}},
    }


def assert_declared_or_clean(call) -> None:
    """Assert the public boundary cannot leak an implementation exception."""

    try:
        result = call()
    except Exception as exc:  # deliberately catches leaks for a type-exact check
        assert type(exc) is engine.SolanaIDLAnalysisError
    else:
        assert result is None or isinstance(result, (dict, int))


def test_analyze_idl_matches_published_anchor_discriminators_and_schema_defaults():
    assert hashlib.sha256(b"global:initialize").digest()[:8] == INITIALIZE
    assert hashlib.sha256(b"account:NewAccount").digest()[:8] == NEW_ACCOUNT
    assert hashlib.sha256(b"event:NewEvent").digest()[:8] == NEW_EVENT

    report = engine.analyze_idl(fixture_idl())
    assert report["program_address"] == PROGRAM
    assert report["instructions"][0]["discriminator_hex"] == INITIALIZE.hex()
    assert report["accounts"] == [
        {"name": "NewAccount", "discriminator_hex": NEW_ACCOUNT.hex()}
    ]
    assert report["events"] == [
        {"name": "NewEvent", "discriminator_hex": NEW_EVENT.hex()}
    ]
    flattened = report["instructions"][0]["accounts"]
    assert [(row["name"], row["path"]) for row in flattened] == [
        ("payer", "authorityGroup.payer"),
        ("systemProgram", "authorityGroup.systemProgram"),
    ]
    assert flattened[0]["writable"] is True and flattened[0]["signer"] is True
    assert flattened[1]["address"] == SYSTEM
    assert report["discriminator_issues"] == []
    assert report["authenticity_verified"] is False


def test_decode_borsh_matches_hand_packed_spec_and_solders_pubkey_oracle():
    raw = account_value_bytes()
    report = engine.decode_borsh(fixture_idl(), "NewAccount", raw)
    assert report == {
        "kind": "borsh-value",
        "type": "NewAccount",
        "value": expected_account_value(),
        "consumed": len(raw),
        "trailing": 0,
    }


def test_match_instruction_matches_published_discriminator_and_manual_borsh():
    raw = instruction_bytes()
    report = engine.match_instruction(
        fixture_idl(),
        raw,
        account_metas=[
            {"pubkey": PAYER, "isSigner": True, "isWritable": True},
            {"pubkey": SYSTEM, "isSigner": False, "isWritable": False},
        ],
    )
    assert report is not None
    assert report["instruction"] == "initialize"
    assert report["discriminator_hex"] == INITIALIZE.hex()
    assert report["arguments"] == {
        "amount": 0x0102030405060708,
        "memo": "war-room",
        "flags": [1, 2, 255],
        "maybe": 500,
    }
    assert report["account_findings"] == []
    assert report["consumed"] == len(raw)
    assert report["execution_verified"] is False


def test_program_account_matches_published_discriminator_manual_borsh_and_owner():
    raw = NEW_ACCOUNT + account_value_bytes()
    report = engine.analyze_program_account(
        fixture_idl(), raw, owner=PROGRAM, executable=False
    )
    assert report["account_type"] == "NewAccount"
    assert report["discriminator_hex"] == NEW_ACCOUNT.hex()
    assert report["value"] == expected_account_value()
    assert report["owner_matches"] is True
    assert report["findings"] == []
    assert report["authenticity_verified"] is False


def test_spec_tuple_field_may_be_an_object_valued_defined_type():
    # IDL schema IdlDefinedFields explicitly permits an array of *IdlType*
    # values, including object-valued `defined` types.  This is a one-element
    # tuple struct containing a NewEvent.
    idl = fixture_idl()
    idl["types"].append(
        {
            "name": "TupleWrapper",
            "type": {
                "kind": "struct",
                "fields": [{"defined": {"name": "NewEvent"}}],
            },
        }
    )
    report = engine.analyze_idl(idl)
    assert next(row for row in report["types"] if row["name"] == "TupleWrapper") == {
        "name": "TupleWrapper",
        "kind": "struct",
        "serialization": "borsh",
        "generic": False,
        "borsh_decodable": True,
    }


def test_borsh_rejects_nan_invalid_tags_trailing_truncated_and_oversized_values_fail_closed(
    monkeypatch,
):
    idl = fixture_idl()
    idl["types"].append(
        {
            "name": "FloatOnly",
            "type": {"kind": "struct", "fields": [{"name": "value", "type": "f64"}]},
        }
    )
    with pytest.raises(engine.SolanaIDLAnalysisError, match="NaN"):
        engine.decode_borsh(idl, "FloatOnly", struct.pack("<d", math.nan))

    valid = account_value_bytes()
    cases = [
        b"",
        b"\xff" * len(valid),
        random.Random(0x501A).randbytes(len(valid)),
        valid[:-1],
        valid + b"\x00",
        valid[:40] + bytes([valid[40] ^ 0x80]) + valid[41:],
    ]
    for sample in cases:
        assert_declared_or_clean(lambda sample=sample: engine.decode_borsh(
            fixture_idl(), "NewAccount", sample
        ))

    monkeypatch.setattr(engine, "MAX_DATA_BYTES", 8)
    assert_declared_or_clean(
        lambda: engine.decode_borsh(fixture_idl(), "NewAccount", valid)
    )


def test_fail_closed_fuzz_analyze_idl_mapping_boundary(monkeypatch):
    truncated = fixture_idl()
    del truncated["instructions"][0]["args"]
    bit_flipped = fixture_idl()
    bit_flipped["metadata"]["spec"] = "0.1.1"
    samples = [
        None,
        {},
        b"",
        b"\xff" * 64,
        random.Random(0x1D1).randbytes(64),
        truncated,
        bit_flipped,
    ]
    for sample in samples:
        assert_declared_or_clean(lambda sample=sample: engine.analyze_idl(sample))

    monkeypatch.setattr(engine, "MAX_IDL_BYTES", 64)
    assert_declared_or_clean(lambda: engine.analyze_idl(fixture_idl()))


@pytest.mark.parametrize(
    ("entrypoint", "valid"),
    [
        ("instruction", instruction_bytes()),
        ("account", NEW_ACCOUNT + account_value_bytes()),
    ],
)
def test_fail_closed_fuzz_binary_entrypoints(entrypoint, valid, monkeypatch):
    rng = random.Random(0x4337)
    changed = bytearray(valid)
    changed[min(8, len(changed) - 1)] ^= 0x80
    samples = [
        b"",
        rng.randbytes(len(valid)),
        b"\xff" * len(valid),
        valid[:-1],
        bytes(changed),
    ]
    for sample in samples:
        if entrypoint == "instruction":
            call = lambda sample=sample: engine.match_instruction(fixture_idl(), sample)
        else:
            call = lambda sample=sample: engine.analyze_program_account(
                fixture_idl(), sample
            )
        assert_declared_or_clean(call)

    monkeypatch.setattr(engine, "MAX_DATA_BYTES", 8)
    if entrypoint == "instruction":
        call = lambda: engine.match_instruction(fixture_idl(), valid)
    else:
        call = lambda: engine.analyze_program_account(fixture_idl(), valid)
    assert_declared_or_clean(call)


def test_released_memoryview_and_bad_optional_arguments_never_leak_stdlib_errors():
    released = memoryview(b"payload")
    released.release()
    calls = [
        lambda: engine.decode_borsh(fixture_idl(), "NewAccount", released),
        lambda: engine.match_instruction(fixture_idl(), released),
        lambda: engine.analyze_program_account(fixture_idl(), released),
        lambda: engine.match_instruction(
            fixture_idl(), instruction_bytes(), account_metas=[object(), object()]
        ),
        lambda: engine.analyze_program_account(
            fixture_idl(), NEW_ACCOUNT + account_value_bytes(), executable="yes"
        ),
    ]
    for call in calls:
        assert_declared_or_clean(call)


def test_cli_uses_only_local_files_and_is_guarded(tmp_path, capsys, monkeypatch):
    idl_path = tmp_path / "fixture.json"
    idl_path.write_text(json.dumps(fixture_idl()), encoding="utf-8")
    artifact = instruction_bytes().hex()

    assert engine.main(["instruction", str(idl_path), artifact, "--hex"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["arguments"]["amount"] == 0x0102030405060708

    broken = tmp_path / "broken.json"
    broken.write_bytes(b'{"address":')
    assert engine.main(["catalog", str(broken)]) == 2
    capsys.readouterr()
    assert engine.main([]) == 2
    capsys.readouterr()
    assert engine.main(["--help"]) == 0

    oversized = tmp_path / "oversized.bin"
    oversized.write_bytes(b"x" * 9)
    monkeypatch.setattr(engine, "MAX_DATA_BYTES", 8)
    assert engine.main(["account", str(idl_path), str(oversized)]) == 2

