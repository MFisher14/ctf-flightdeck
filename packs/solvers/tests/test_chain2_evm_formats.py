"""Independent vectors for the chain2 OP/Nitro/ERC-4337 decoder.

The engine never supplies bytes used as an expected value here.  ``rlp`` is the
wire oracle for the published OP and OffchainLabs Go struct field orders;
``eth_abi`` is the oracle for the tagged eth-infinitism EntryPoint tuple schemas;
and ``eth_utils.keccak`` independently derives both handleOps selectors.

Primary vector sources:
https://specs.optimism.io/protocol/deposits.html
https://github.com/ethereum-optimism/op-geth/blob/optimism/core/types/transaction_marshalling_test.go
https://github.com/OffchainLabs/go-ethereum/blob/master/core/types/arb_types.go
https://github.com/eth-infinitism/account-abstraction/blob/v0.6.0/test/UserOp.ts
https://github.com/eth-infinitism/account-abstraction/blob/v0.7.0/test/UserOp.ts
"""
from __future__ import annotations

import json
import random

import pytest
import rlp
from eth_abi import encode as abi_encode
from eth_utils import keccak

import chain2_evm_formats as engine


V06_TUPLE = "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)"
PACKED_TUPLE = "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)"
V06_SIGNATURE = f"handleOps({V06_TUPLE}[],address)"
PACKED_SIGNATURE = f"handleOps({PACKED_TUPLE}[],address)"


def _be(value: int) -> bytes:
    """Reference RLP integer payload; rlp performs only the envelope encoding."""

    assert value >= 0
    return value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""


def _typed(type_byte: int, fields: list[bytes]) -> bytes:
    return bytes([type_byte]) + rlp.encode(fields)


def _kinds(result: dict) -> str:
    return str(result["kind"])


def _assert_closed(call) -> None:
    try:
        call()
    except Exception as error:  # noqa: BLE001 - this probes the public contract
        assert isinstance(error, engine.Chain2FormatError), (
            f"leaked {type(error).__name__}: {error}"
        )


def test_selectors_are_independently_derived_from_published_signatures():
    assert keccak(text=V06_SIGNATURE)[:4] == bytes.fromhex("1fad948c")
    assert keccak(text=PACKED_SIGNATURE)[:4] == bytes.fromhex("765e827f")
    assert engine.HANDLE_OPS_V06_SELECTOR == keccak(text=V06_SIGNATURE)[:4]
    assert engine.HANDLE_OPS_PACKED_SELECTOR == keccak(text=PACKED_SIGNATURE)[:4]


def test_op_geth_published_json_fields_encoded_by_rlp_oracle():
    # op-geth's checked-in JSON test publishes these source/from/to/value/gas/data
    # values.  Mint and isSystemTx are zero under the protocol's uint/bool RLP
    # schema.  The engine is not involved in constructing this wire value.
    raw = _typed(0x7E, [
        bytes(32),
        (1).to_bytes(20, "big"),
        b"",                    # contract creation
        _be(0),                 # mint
        _be(1),                 # value
        _be(0x1234),            # gas
        b"",                    # false
        b"abcdef",
    ])
    result = engine.decode_op_deposit(raw, post_regolith=True)
    assert result == {
        "kind": "op-deposited-transaction",
        "family": "optimism",
        "type": "0x7e",
        "source_hash": "0x" + "00" * 32,
        "from": "0x0000000000000000000000000000000000000001",
        "to": None,
        "contract_creation": True,
        "mint": 0,
        "value": 1,
        "gas": 0x1234,
        "is_system_tx": False,
        "data": "0x616263646566",
        "signed": False,
        "validity": "structure-only",
    }


def test_op_fjord_published_source_hash_and_explicit_fork_rule():
    source = bytes.fromhex(
        "1e6bb0c28bfab3dc9b36ffb0f721f00d6937f33577606325692db0965a7d58c6"
    )
    fields = [source, bytes.fromhex("11" * 20), bytes.fromhex("22" * 20),
              _be(9), _be(7), _be(1_000_000), b"\x01", b"\xca\xfe"]
    raw = _typed(0x7E, fields)
    result = engine.decode_l2_envelope(raw)
    assert result["source_hash"] == "0x" + source.hex()
    assert result["is_system_tx"] is True
    with pytest.raises(engine.Chain2FormatError, match="post-Regolith"):
        engine.decode_l2_envelope(raw, post_regolith=True)


@pytest.mark.parametrize(
    "type_byte,fields,expected_kind,checks",
    [
        (0x64,
         [_be(42161), bytes.fromhex("01" * 32), bytes.fromhex("02" * 20),
          bytes.fromhex("03" * 20), _be(44)],
         "arbitrum-deposit-transaction",
         {"chain_id": 42161, "value": 44, "to": "0x0303030303030303030303030303030303030303"}),
        (0x65,
         [_be(42161), bytes.fromhex("04" * 20), _be(8), _be(99), _be(50_000),
          b"", _be(5), b"\xde\xad"],
         "arbitrum-unsigned-transaction",
         {"nonce": 8, "gas": 50_000, "to": None, "data": "0xdead"}),
        (0x66,
         [_be(42161), bytes.fromhex("05" * 32), bytes.fromhex("06" * 20),
          _be(12), _be(60_000), bytes.fromhex("07" * 20), _be(6), b"contract"],
         "arbitrum-contract-transaction",
         {"gas_fee_cap": 12, "gas": 60_000, "value": 6}),
        (0x68,
         [_be(42161), _be(11), bytes.fromhex("08" * 20), _be(13), _be(70_000),
          b"", _be(7), b"retry", bytes.fromhex("09" * 32),
          bytes.fromhex("0a" * 20), _be(14), _be(15)],
         "arbitrum-retry-transaction",
         {"nonce": 11, "to": None, "max_refund": 14,
          "submission_fee_refund": 15}),
        (0x69,
         [_be(42161), bytes.fromhex("0b" * 32), bytes.fromhex("0c" * 20),
          _be(16), _be(17), _be(18), _be(80_000), b"", _be(19),
          bytes.fromhex("0d" * 20), _be(20), bytes.fromhex("0e" * 20), b"ticket"],
         "arbitrum-submit-retryable-transaction",
         {"l1_base_fee": 16, "deposit_value": 17, "retry_to": None,
          "retry_value": 19, "retry_data": "0x7469636b6574"}),
        (0x6A,
         [_be(42161), b"internal"],
         "arbitrum-internal-transaction",
         {"chain_id": 42161, "data": "0x696e7465726e616c"}),
    ],
)
def test_offchainlabs_nitro_go_struct_schemas_via_rlp_oracle(
        type_byte, fields, expected_kind, checks):
    result = engine.decode_arbitrum_nitro(_typed(type_byte, fields))
    assert _kinds(result) == expected_kind
    assert result["family"] == "arbitrum-nitro"
    assert result["type"] == f"0x{type_byte:02x}"
    assert result["signed"] is False and result["validity"] == "structure-only"
    for key, expected in checks.items():
        assert result[key] == expected


def test_l2_declines_versioned_unknown_and_malformed_forms():
    for raw, message in (
        (b"\x7dopaque", "Lagoon"),
        (b"\x78\xc0", "legacy"),
        (b"\x67\xc0", "unsupported"),
    ):
        with pytest.raises(engine.Chain2FormatError, match=message):
            engine.decode_l2_envelope(raw)

    # Wrong fixed widths, leading-zero uint, noncanonical RLP, and gas overflow.
    malformed = [
        _typed(0x7E, [bytes(31), bytes(20), b"", b"", b"", b"", b"", b""]),
        _typed(0x64, [_be(1), bytes(32), bytes(20), bytes(19), _be(1)]),
        _typed(0x65, [b"\x00\x01", bytes(20), b"", b"", b"", b"", b"", b""]),
        _typed(0x65, [_be(1), bytes(20), b"", b"", _be(1 << 64), b"", b"", b""]),
        b"\x7e\xf8\x01\x80",  # long-list form for a one-byte body is noncanonical
    ]
    for raw in malformed:
        with pytest.raises(engine.Chain2FormatError):
            engine.decode_l2_envelope(raw)


def test_v06_official_default_userop_encoded_by_eth_abi():
    # Tagged v0.6 UserOp.ts defaults: verification=150000, preVerification=21000,
    # maxPriorityFee=1e9, with all other scalar/dynamic values zero/empty.
    operation = (
        "0x" + "00" * 20, 0, b"", b"", 0, 150_000, 21_000,
        0, 1_000_000_000, b"", b"",
    )
    beneficiary = "0x" + "42" * 20
    body = abi_encode([V06_TUPLE + "[]", "address"], [[operation], beneficiary])
    raw = keccak(text=V06_SIGNATURE)[:4] + body
    result = engine.decode_handle_ops(raw, version="0.6")
    assert result["version"] == "0.6" and result["packed"] is False
    assert result["beneficiary"] == "0x4242424242424242424242424242424242424242"
    assert result["operation_count"] == 1
    decoded = result["operations"][0]
    assert decoded["verification_gas_limit"] == 150_000
    assert decoded["pre_verification_gas"] == 21_000
    assert decoded["max_priority_fee_per_gas"] == 1_000_000_000
    assert decoded["nonce_key"] == decoded["nonce_sequence"] == 0
    assert decoded["factory"] is None and decoded["paymaster"] is None


def test_packed_v07_fields_unpacked_from_eth_abi_reference():
    factory = bytes.fromhex("11" * 20)
    paymaster = bytes.fromhex("22" * 20)
    nonce = (0x1234 << 64) | 9
    verification_gas, call_gas = 150_000, 55_000
    priority_fee, max_fee = 1_000_000_000, 2_000_000_000
    account_gas = ((verification_gas << 128) | call_gas).to_bytes(32, "big")
    gas_fees = ((priority_fee << 128) | max_fee).to_bytes(32, "big")
    paymaster_data = (paymaster + (300_000).to_bytes(16, "big")
                      + (45_000).to_bytes(16, "big") + b"pm-data")
    operation = (
        "0x" + "33" * 20, nonce, factory + b"factory-data", b"\xde\xad\xbe\xef",
        account_gas, 21_000, gas_fees, paymaster_data, bytes.fromhex("44" * 65),
    )
    body = abi_encode([PACKED_TUPLE + "[]", "address"], [[operation], "0x" + "55" * 20])
    raw = keccak(text=PACKED_SIGNATURE)[:4] + body
    result = engine.decode_erc4337_handle_ops(raw, version="0.7")
    decoded = result["operations"][0]
    assert (decoded["nonce_key"], decoded["nonce_sequence"]) == (0x1234, 9)
    assert decoded["verification_gas_limit"] == verification_gas
    assert decoded["call_gas_limit"] == call_gas
    assert decoded["max_priority_fee_per_gas"] == priority_fee
    assert decoded["max_fee_per_gas"] == max_fee
    assert decoded["factory"] == {
        "address": "0x1111111111111111111111111111111111111111",
        "data": "0x666163746f72792d64617461",
    }
    assert decoded["paymaster"] == {
        "address": "0x2222222222222222222222222222222222222222",
        "verification_gas_limit": 300_000,
        "post_op_gas_limit": 45_000,
        "data": "0x706d2d64617461",
        "signature": None,
        "signature_magic": None,
    }


def test_v09_paymaster_signature_suffix_is_version_gated():
    prefix = (bytes.fromhex("66" * 20) + (90_000).to_bytes(16, "big")
              + (12_000).to_bytes(16, "big"))
    signature = b"\xaa\xbb\xcc\xdd"
    packed = (prefix + b"opaque" + signature + len(signature).to_bytes(2, "big")
              + bytes.fromhex("22e325a297439656"))
    operation = (
        "0x" + "77" * 20, 0, b"", b"", bytes(32), 21_000,
        bytes(32), packed, b"sig",
    )
    body = abi_encode([PACKED_TUPLE + "[]", "address"], [[operation], "0x" + "88" * 20])
    raw = keccak(text=PACKED_SIGNATURE)[:4] + body
    v09 = engine.decode_handle_ops(raw, version="0.9")["operations"][0]["paymaster"]
    assert v09["data"] == "0x6f7061717565"
    assert v09["signature"] == "0xaabbccdd"
    assert v09["signature_magic"] == "0x22e325a297439656"
    v08 = engine.decode_handle_ops(raw, version="0.8")["operations"][0]["paymaster"]
    assert v08["signature"] is None
    assert v08["data"].endswith("000422e325a297439656")


def test_handleops_requires_explicit_matching_version_and_canonical_complete_abi():
    operation = ("0x" + "00" * 20, 0, b"", b"", bytes(32), 21_000,
                 bytes(32), b"", b"")
    body = abi_encode([PACKED_TUPLE + "[]", "address"], [[operation], "0x" + "00" * 20])
    raw = keccak(text=PACKED_SIGNATURE)[:4] + body
    with pytest.raises(engine.Chain2FormatError, match="version"):
        engine.decode_handle_ops(raw, version="1.0")
    with pytest.raises(engine.Chain2FormatError, match="does not match"):
        engine.decode_handle_ops(raw, version="0.6")
    with pytest.raises(engine.Chain2FormatError, match="canonical"):
        engine.decode_handle_ops(raw + bytes(32), version="0.7")

    corrupted = bytearray(raw)
    corrupted[4:36] = (1 << 255).to_bytes(32, "big")
    with pytest.raises(engine.Chain2FormatError):
        engine.decode_handle_ops(bytes(corrupted), version="0.7")


def test_public_entrypoints_never_leak_dependency_or_stdlib_exceptions():
    rng = random.Random(0x4337)
    values: list[object] = [None, True, 7, "", "0x0", "not-hex", b"", memoryview(b"")]
    values += [rng.randbytes(length) for length in range(1, 96)]
    for value in values:
        _assert_closed(lambda value=value: engine.decode_l2_envelope(value))
        for version in ("0.6", "0.7", "0.8", "0.9", None):
            _assert_closed(lambda value=value, version=version:
                           engine.decode_handle_ops(value, version=version))


def test_cli_op_vector_and_argparse_guard(tmp_path, capsys):
    raw = _typed(0x7E, [bytes(32), bytes.fromhex("12" * 20), b"", b"", _be(1),
                        _be(21_000), b"", b"cli"])
    path = tmp_path / "deposit.raw"
    path.write_bytes(raw)
    assert engine.main(["l2", str(path), "--post-regolith"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["family"] == "optimism" and result["data"] == "0x636c69"
    assert engine.main([]) == 2
    assert "chain2_evm_formats" in capsys.readouterr().err
