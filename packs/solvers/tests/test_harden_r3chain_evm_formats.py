"""Independent vector locks and fail-closed fuzz for ``chain2_evm_formats``.

The wire fixtures are built outside the engine with ``rlp``, ``eth_abi`` and
``eth_utils``.  Their schemas come from the OP deposit specification,
OffchainLabs' published Nitro transaction structs, and the eth-infinitism
EntryPoint/UserOperation definitions.  No test performs RPC or any network I/O.
"""
from __future__ import annotations

import json
import random

from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address
import pytest
import rlp

import chain2_evm_formats as engine


V06_TUPLE = (
    "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)"
)
PACKED_TUPLE = "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)"
V06_SIGNATURE = f"handleOps({V06_TUPLE}[],address)"
PACKED_SIGNATURE = f"handleOps({PACKED_TUPLE}[],address)"


def _uint(value: int) -> bytes:
    """Canonical RLP integer payload, independently of the engine."""

    assert value >= 0
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _typed(type_byte: int, fields: list[bytes]) -> bytes:
    return bytes([type_byte]) + rlp.encode(fields)


def _op_vector() -> bytes:
    # OP DepositTx wire order: sourceHash, from, to, mint, value, gas,
    # isSystemTransaction, data.  False is the canonical empty RLP integer.
    return _typed(0x7E, [
        bytes.fromhex("9a" * 32),
        bytes.fromhex("1234567890abcdef1234567890abcdef12345678"),
        bytes.fromhex("4200000000000000000000000000000000000015"),
        _uint(0x1234),
        _uint(0x55),
        _uint(1_500_000),
        b"",
        bytes.fromhex("deadbeef00"),
    ])


def _arbitrum_retryable_vector() -> bytes:
    # Field order is the published ArbitrumSubmitRetryableTx Go struct order.
    return _typed(0x69, [
        _uint(42161),
        bytes.fromhex("ab" * 32),
        bytes.fromhex("1111111111111111111111111111111111111111"),
        _uint(30_000_000_000),
        _uint(10**18),
        _uint(20_000_000_000),
        _uint(750_000),
        b"",  # nil retry target means contract creation
        _uint(123),
        bytes.fromhex("2222222222222222222222222222222222222222"),
        _uint(99_999),
        bytes.fromhex("3333333333333333333333333333333333333333"),
        b"published-schema-vector",
    ])


def _v06_vector() -> bytes:
    # eth-infinitism v0.6 test defaults include verificationGasLimit=150000,
    # preVerificationGas=21000, and maxPriorityFeePerGas=1 gwei.
    operation = (
        "0x1234567890abcdef1234567890abcdef12345678",
        (7 << 64) | 11,
        b"",
        bytes.fromhex("a9059cbb"),
        55_000,
        150_000,
        21_000,
        2_000_000_000,
        1_000_000_000,
        b"",
        bytes.fromhex("99" * 65),
    )
    body = abi_encode(
        [V06_TUPLE + "[]", "address"],
        [[operation], "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"],
    )
    return keccak(text=V06_SIGNATURE)[:4] + body


def _packed_vector() -> bytes:
    verification_gas = 180_000
    call_gas = 65_000
    priority_fee = 1_500_000_000
    max_fee = 3_000_000_000
    account_gas = ((verification_gas << 128) | call_gas).to_bytes(32, "big")
    gas_fees = ((priority_fee << 128) | max_fee).to_bytes(32, "big")
    factory = bytes.fromhex("44" * 20)
    paymaster = bytes.fromhex("55" * 20)
    paymaster_data = (
        paymaster
        + (300_000).to_bytes(16, "big")
        + (40_000).to_bytes(16, "big")
        + b"oracle-paymaster-data"
    )
    operation = (
        "0x9999999999999999999999999999999999999999",
        (0xBEEF << 64) | 17,
        factory + bytes.fromhex("010203"),
        bytes.fromhex("cafebabe"),
        account_gas,
        25_000,
        gas_fees,
        paymaster_data,
        bytes.fromhex("77" * 65),
    )
    body = abi_encode(
        [PACKED_TUPLE + "[]", "address"],
        [[operation], "0x8888888888888888888888888888888888888888"],
    )
    return keccak(text=PACKED_SIGNATURE)[:4] + body


def _assert_declared_or_dict(call) -> None:
    try:
        result = call()
    except Exception as exc:  # the contract assertion intentionally catches all
        assert type(exc) is engine.Chain2FormatError, (
            f"leaked {type(exc).__name__}: {exc}"
        )
    else:
        assert isinstance(result, dict)


def test_op_deposit_vector_locked_to_rlp_and_eth_utils() -> None:
    raw = _op_vector()
    expected = {
        "kind": "op-deposited-transaction",
        "family": "optimism",
        "type": "0x7e",
        "source_hash": "0x" + "9a" * 32,
        "from": to_checksum_address("0x1234567890abcdef1234567890abcdef12345678"),
        "to": to_checksum_address("0x4200000000000000000000000000000000000015"),
        "contract_creation": False,
        "mint": 0x1234,
        "value": 0x55,
        "gas": 1_500_000,
        "is_system_tx": False,
        "data": "0xdeadbeef00",
        "signed": False,
        "validity": "structure-only",
    }
    assert engine.decode_l2_envelope(raw, post_regolith=True) == expected
    assert engine.decode_op_deposit("0x" + raw.hex(), post_regolith=True) == expected


def test_arbitrum_retryable_vector_locked_to_published_go_struct() -> None:
    result = engine.decode_arbitrum_nitro(_arbitrum_retryable_vector())
    assert result == {
        "kind": "arbitrum-submit-retryable-transaction",
        "family": "arbitrum-nitro",
        "type": "0x69",
        "chain_id": 42161,
        "request_id": "0x" + "ab" * 32,
        "from": to_checksum_address("0x" + "11" * 20),
        "l1_base_fee": 30_000_000_000,
        "deposit_value": 10**18,
        "gas_fee_cap": 20_000_000_000,
        "gas": 750_000,
        "retry_to": None,
        "retry_value": 123,
        "beneficiary": to_checksum_address("0x" + "22" * 20),
        "max_submission_fee": 99_999,
        "fee_refund_address": to_checksum_address("0x" + "33" * 20),
        "retry_data": "0x" + b"published-schema-vector".hex(),
        "signed": False,
        "validity": "structure-only",
    }


def test_v06_handle_ops_vector_locked_to_eth_abi_and_eth_utils() -> None:
    raw = _v06_vector()
    assert raw[:4] == keccak(text=V06_SIGNATURE)[:4]
    result = engine.decode_handle_ops(raw, version="0.6")
    assert result == {
        "kind": "erc-4337-handle-ops",
        "version": "0.6",
        "selector": "0x" + keccak(text=V06_SIGNATURE)[:4].hex(),
        "packed": False,
        "beneficiary": to_checksum_address(
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        ),
        "operation_count": 1,
        "operations": [{
            "index": 0,
            "sender": to_checksum_address(
                "0x1234567890abcdef1234567890abcdef12345678"
            ),
            "nonce": (7 << 64) | 11,
            "nonce_key": 7,
            "nonce_sequence": 11,
            "init_code": "0x",
            "factory": None,
            "call_data": "0xa9059cbb",
            "call_gas_limit": 55_000,
            "verification_gas_limit": 150_000,
            "pre_verification_gas": 21_000,
            "max_fee_per_gas": 2_000_000_000,
            "max_priority_fee_per_gas": 1_000_000_000,
            "paymaster_and_data": "0x",
            "paymaster": None,
            "signature": "0x" + "99" * 65,
        }],
        "validity": "structure-only",
        "signature_validity": None,
        "state_validity": None,
    }


def test_packed_alias_vector_locked_to_eth_abi_word_packing() -> None:
    raw = _packed_vector()
    assert raw[:4] == keccak(text=PACKED_SIGNATURE)[:4]
    result = engine.decode_erc4337_handle_ops(raw, version="0.7")
    operation = result["operations"][0]
    assert result["selector"] == "0x" + keccak(text=PACKED_SIGNATURE)[:4].hex()
    assert result["version"] == "0.7" and result["packed"] is True
    assert result["beneficiary"] == to_checksum_address("0x" + "88" * 20)
    assert (operation["nonce_key"], operation["nonce_sequence"]) == (0xBEEF, 17)
    assert operation["verification_gas_limit"] == 180_000
    assert operation["call_gas_limit"] == 65_000
    assert operation["max_priority_fee_per_gas"] == 1_500_000_000
    assert operation["max_fee_per_gas"] == 3_000_000_000
    assert operation["factory"] == {
        "address": to_checksum_address("0x" + "44" * 20),
        "data": "0x010203",
    }
    assert operation["paymaster"] == {
        "address": to_checksum_address("0x" + "55" * 20),
        "verification_gas_limit": 300_000,
        "post_op_gas_limit": 40_000,
        "data": "0x" + b"oracle-paymaster-data".hex(),
        "signature": None,
        "signature_magic": None,
    }


@pytest.mark.parametrize(
    ("name", "decoder", "valid"),
    [
        ("l2", lambda value: engine.decode_l2_envelope(value), _op_vector()),
        ("op", lambda value: engine.decode_op_deposit(value), _op_vector()),
        (
            "arbitrum",
            lambda value: engine.decode_arbitrum_nitro(value),
            _arbitrum_retryable_vector(),
        ),
        (
            "handleOps-v06",
            lambda value: engine.decode_handle_ops(value, version="0.6"),
            _v06_vector(),
        ),
        (
            "handleOps-alias",
            lambda value: engine.decode_erc4337_handle_ops(value, version="0.7"),
            _packed_vector(),
        ),
    ],
)
def test_public_decoders_fail_closed_for_malformed_families(
        name, decoder, valid) -> None:
    del name
    random_bytes = random.Random(0x4337A11).randbytes(257)
    flipped = bytearray(valid)
    flipped[min(17, len(flipped) - 1)] ^= 0x80
    samples: list[object] = [
        None,
        7,
        "",
        "0x0",
        "not hexadecimal",
        b"",
        b"\xff" * 257,
        random_bytes,
        valid[:1],
        valid[:-1],
        bytes(flipped),
    ]
    for sample in samples:
        _assert_declared_or_dict(lambda sample=sample: decoder(sample))


def test_all_public_decoders_reject_oversized_with_declared_error(monkeypatch) -> None:
    monkeypatch.setattr(engine, "MAX_INPUT", 64)
    oversized = b"\xaa" * 65
    calls = [
        lambda: engine.decode_l2_envelope(oversized),
        lambda: engine.decode_op_deposit(oversized),
        lambda: engine.decode_arbitrum_nitro(oversized),
        lambda: engine.decode_handle_ops(oversized, version="0.6"),
        lambda: engine.decode_erc4337_handle_ops(oversized, version="0.7"),
    ]
    for call in calls:
        with pytest.raises(engine.Chain2FormatError, match="cap"):
            call()


def test_cli_vector_and_guarded_argparse(tmp_path, capsys, monkeypatch) -> None:
    artifact = tmp_path / "op-deposit.bin"
    artifact.write_bytes(_op_vector())
    assert engine.main(["l2", str(artifact), "--post-regolith"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["source_hash"] == "0x" + "9a" * 32
    assert result["data"] == "0xdeadbeef00"

    assert engine.main([]) == 2
    assert engine.main(["--help"]) == 0
    assert engine.main(["l2", str(tmp_path / "missing")]) == 2
    capsys.readouterr()

    def non_integer_exit(*args, **kwargs):
        raise SystemExit("non-integer")

    monkeypatch.setattr(engine._Parser, "parse_args", non_integer_exit)
    assert engine.main([]) == 2
