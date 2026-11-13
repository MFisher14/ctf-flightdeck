#!/usr/bin/env python3
"""Strict offline OP/Nitro envelope and ERC-4337 ``handleOps`` decoding.

Only caller-supplied bytes are inspected.  The module does not use RPC, recover
signers, validate signatures, simulate operations, or infer chain acceptance.
Generic RLP, Keccak, and address handling are intentionally delegated to the
existing :mod:`blockchain` engine; generic ABI tuple handling is delegated to
``eth_abi`` and constrained to the two published ``handleOps`` schemas.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

import blockchain
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode


MAX_INPUT = 4 * 1024 * 1024
MAX_DYNAMIC_FIELD = 2 * 1024 * 1024
MAX_USER_OPERATIONS = 1024

OP_DEPOSIT_TYPE = 0x7E
OP_POST_EXEC_TYPE = 0x7D
ARBITRUM_TYPES = frozenset({0x64, 0x65, 0x66, 0x68, 0x69, 0x6A})
ARBITRUM_LEGACY_TYPE = 0x78

HANDLE_OPS_V06_SELECTOR = bytes.fromhex("1fad948c")
HANDLE_OPS_PACKED_SELECTOR = bytes.fromhex("765e827f")
PAYMASTER_SIGNATURE_MAGIC = bytes.fromhex("22e325a297439656")

_V06_OPERATION_TYPE = (
    "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)"
)
_PACKED_OPERATION_TYPE = (
    "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)"
)


class Chain2FormatError(ValueError):
    """The supplied offline artifact is malformed, ambiguous, or unsupported."""


def _closed(function: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
    """Ensure public decoding entry points expose only ``Chain2FormatError``."""

    def wrapped(*args: object, **kwargs: object) -> dict[str, Any]:
        try:
            return function(*args, **kwargs)
        except Chain2FormatError:
            raise
        except Exception as exc:  # dependency/stdlib failures are part of the contract
            raise Chain2FormatError(f"{function.__name__} could not decode the artifact") from exc

    wrapped.__name__ = function.__name__
    wrapped.__doc__ = function.__doc__
    return wrapped


def _artifact_bytes(value: object, *, label: str) -> bytes:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
    elif isinstance(value, str):
        text = value.strip()
        if text.startswith(("0x", "0X")):
            text = text[2:]
        if not text or len(text) % 2 or re.fullmatch(r"[0-9a-fA-F]+", text) is None:
            raise Chain2FormatError(f"{label} must be even-length hexadecimal")
        data = bytes.fromhex(text)
    else:
        raise Chain2FormatError(f"{label} must be bytes or hexadecimal text")
    if not data:
        raise Chain2FormatError(f"{label} is empty")
    if len(data) > MAX_INPUT:
        raise Chain2FormatError(f"{label} exceeds the {MAX_INPUT}-byte cap")
    return data


def _items(value: object, count: int, *, schema: str) -> list[bytes]:
    if not isinstance(value, list) or len(value) != count:
        raise Chain2FormatError(f"{schema} requires exactly {count} RLP fields")
    if not all(isinstance(item, bytes) for item in value):
        raise Chain2FormatError(f"{schema} fields must be RLP byte strings")
    return value


def _fixed(value: bytes, size: int, *, name: str) -> bytes:
    if len(value) != size:
        raise Chain2FormatError(f"{name} must be exactly {size} bytes")
    return value


def _uint(value: bytes, *, name: str, bits: int = 256) -> int:
    if not isinstance(value, bytes):
        raise Chain2FormatError(f"{name} must be an RLP byte string")
    if value[:1] == b"\0":
        raise Chain2FormatError(f"{name} is not a minimally encoded RLP integer")
    number = int.from_bytes(value, "big")
    if number.bit_length() > bits:
        raise Chain2FormatError(f"{name} exceeds uint{bits}")
    return number


def _bool(value: bytes, *, name: str) -> bool:
    if value == b"":
        return False
    if value == b"\x01":
        return True
    raise Chain2FormatError(f"{name} must use canonical RLP false/true encoding")


def _address(value: bytes, *, name: str, optional: bool = False) -> str | None:
    if optional and value == b"":
        return None
    _fixed(value, 20, name=name)
    rendered = blockchain.eip55(value)
    if not isinstance(rendered, str):
        raise Chain2FormatError(f"could not render {name}")
    return rendered


def _hash32(value: bytes, *, name: str) -> str:
    return "0x" + _fixed(value, 32, name=name).hex()


def _data(value: bytes, *, name: str) -> str:
    if len(value) > MAX_DYNAMIC_FIELD:
        raise Chain2FormatError(f"{name} exceeds the dynamic-field cap")
    return "0x" + value.hex()


def _decode_op(body: object, *, post_regolith: bool) -> dict[str, Any]:
    fields = _items(body, 8, schema="OP deposited transaction")
    source_hash, sender, destination, mint, value, gas, system, data = fields
    is_system = _bool(system, name="isSystemTx")
    if post_regolith and is_system:
        raise Chain2FormatError("post-Regolith OP deposits require isSystemTx=false")
    return {
        "kind": "op-deposited-transaction",
        "family": "optimism",
        "type": "0x7e",
        "source_hash": _hash32(source_hash, name="sourceHash"),
        "from": _address(sender, name="from"),
        "to": _address(destination, name="to", optional=True),
        "contract_creation": destination == b"",
        "mint": _uint(mint, name="mint"),
        "value": _uint(value, name="value"),
        "gas": _uint(gas, name="gas", bits=64),
        "is_system_tx": is_system,
        "data": _data(data, name="data"),
        "signed": False,
        "validity": "structure-only",
    }


def _decode_arb_64(body: object) -> dict[str, Any]:
    chain_id, request_id, sender, destination, value = _items(
        body, 5, schema="Arbitrum deposit transaction"
    )
    return {
        "kind": "arbitrum-deposit-transaction",
        "family": "arbitrum-nitro",
        "type": "0x64",
        "chain_id": _uint(chain_id, name="chainId"),
        "l1_request_id": _hash32(request_id, name="l1RequestId"),
        "from": _address(sender, name="from"),
        "to": _address(destination, name="to"),
        "value": _uint(value, name="value"),
    }


def _decode_arb_65(body: object) -> dict[str, Any]:
    chain_id, sender, nonce, fee_cap, gas, destination, value, data = _items(
        body, 8, schema="Arbitrum unsigned transaction"
    )
    return {
        "kind": "arbitrum-unsigned-transaction",
        "family": "arbitrum-nitro",
        "type": "0x65",
        "chain_id": _uint(chain_id, name="chainId"),
        "from": _address(sender, name="from"),
        "nonce": _uint(nonce, name="nonce", bits=64),
        "gas_fee_cap": _uint(fee_cap, name="gasFeeCap"),
        "gas": _uint(gas, name="gas", bits=64),
        "to": _address(destination, name="to", optional=True),
        "value": _uint(value, name="value"),
        "data": _data(data, name="data"),
    }


def _decode_arb_66(body: object) -> dict[str, Any]:
    chain_id, request_id, sender, fee_cap, gas, destination, value, data = _items(
        body, 8, schema="Arbitrum contract transaction"
    )
    return {
        "kind": "arbitrum-contract-transaction",
        "family": "arbitrum-nitro",
        "type": "0x66",
        "chain_id": _uint(chain_id, name="chainId"),
        "request_id": _hash32(request_id, name="requestId"),
        "from": _address(sender, name="from"),
        "gas_fee_cap": _uint(fee_cap, name="gasFeeCap"),
        "gas": _uint(gas, name="gas", bits=64),
        "to": _address(destination, name="to", optional=True),
        "value": _uint(value, name="value"),
        "data": _data(data, name="data"),
    }


def _decode_arb_68(body: object) -> dict[str, Any]:
    (chain_id, nonce, sender, fee_cap, gas, destination, value, data, ticket_id,
     refund_to, max_refund, submission_refund) = _items(
        body, 12, schema="Arbitrum retry transaction"
    )
    return {
        "kind": "arbitrum-retry-transaction",
        "family": "arbitrum-nitro",
        "type": "0x68",
        "chain_id": _uint(chain_id, name="chainId"),
        "nonce": _uint(nonce, name="nonce", bits=64),
        "from": _address(sender, name="from"),
        "gas_fee_cap": _uint(fee_cap, name="gasFeeCap"),
        "gas": _uint(gas, name="gas", bits=64),
        "to": _address(destination, name="to", optional=True),
        "value": _uint(value, name="value"),
        "data": _data(data, name="data"),
        "ticket_id": _hash32(ticket_id, name="ticketId"),
        "refund_to": _address(refund_to, name="refundTo"),
        "max_refund": _uint(max_refund, name="maxRefund"),
        "submission_fee_refund": _uint(submission_refund, name="submissionFeeRefund"),
    }


def _decode_arb_69(body: object) -> dict[str, Any]:
    (chain_id, request_id, sender, l1_base_fee, deposit_value, fee_cap, gas,
     retry_to, retry_value, beneficiary, max_submission_fee, fee_refund,
     retry_data) = _items(body, 13, schema="Arbitrum submit-retryable transaction")
    return {
        "kind": "arbitrum-submit-retryable-transaction",
        "family": "arbitrum-nitro",
        "type": "0x69",
        "chain_id": _uint(chain_id, name="chainId"),
        "request_id": _hash32(request_id, name="requestId"),
        "from": _address(sender, name="from"),
        "l1_base_fee": _uint(l1_base_fee, name="l1BaseFee"),
        "deposit_value": _uint(deposit_value, name="depositValue"),
        "gas_fee_cap": _uint(fee_cap, name="gasFeeCap"),
        "gas": _uint(gas, name="gas", bits=64),
        "retry_to": _address(retry_to, name="retryTo", optional=True),
        "retry_value": _uint(retry_value, name="retryValue"),
        "beneficiary": _address(beneficiary, name="beneficiary"),
        "max_submission_fee": _uint(max_submission_fee, name="maxSubmissionFee"),
        "fee_refund_address": _address(fee_refund, name="feeRefundAddr"),
        "retry_data": _data(retry_data, name="retryData"),
    }


def _decode_arb_6a(body: object) -> dict[str, Any]:
    chain_id, data = _items(body, 2, schema="Arbitrum internal transaction")
    return {
        "kind": "arbitrum-internal-transaction",
        "family": "arbitrum-nitro",
        "type": "0x6a",
        "chain_id": _uint(chain_id, name="chainId"),
        "data": _data(data, name="data"),
    }


_ARBITRUM_DECODERS: dict[int, Callable[[object], dict[str, Any]]] = {
    0x64: _decode_arb_64,
    0x65: _decode_arb_65,
    0x66: _decode_arb_66,
    0x68: _decode_arb_68,
    0x69: _decode_arb_69,
    0x6A: _decode_arb_6a,
}


@_closed
def decode_l2_envelope(value: object, *, post_regolith: bool = False) -> dict[str, Any]:
    """Decode one strict OP or Arbitrum Nitro typed transaction envelope.

    ``post_regolith`` is caller-supplied fork context.  It only enforces that an OP
    deposited transaction's ``isSystemTx`` field is false; no other chain validity
    or execution property is inferred.
    """

    if not isinstance(post_regolith, bool):
        raise Chain2FormatError("post_regolith must be boolean")
    raw = _artifact_bytes(value, label="L2 envelope")
    transaction_type = raw[0]
    if transaction_type == OP_POST_EXEC_TYPE:
        raise Chain2FormatError("OP 0x7d post-execution envelopes require the Lagoon schema and are unsupported")
    if transaction_type == ARBITRUM_LEGACY_TYPE:
        raise Chain2FormatError("Arbitrum 0x78 legacy envelopes require a versioned legacy schema")
    if transaction_type != OP_DEPOSIT_TYPE and transaction_type not in ARBITRUM_TYPES:
        raise Chain2FormatError(f"unsupported L2 transaction type 0x{transaction_type:02x}")
    body = blockchain.rlp_decode(raw[1:])
    if body is None:
        raise Chain2FormatError("typed transaction payload is not one canonical complete RLP item")
    if transaction_type == OP_DEPOSIT_TYPE:
        return _decode_op(body, post_regolith=post_regolith)
    result = _ARBITRUM_DECODERS[transaction_type](body)
    result.update({"signed": False, "validity": "structure-only"})
    return result


@_closed
def decode_op_deposit(value: object, *, post_regolith: bool = False) -> dict[str, Any]:
    """Decode exactly an OP ``0x7e`` deposited transaction envelope."""

    result = decode_l2_envelope(value, post_regolith=post_regolith)
    if result.get("family") != "optimism":
        raise Chain2FormatError("artifact is not an OP deposited transaction")
    return result


@_closed
def decode_arbitrum_nitro(value: object) -> dict[str, Any]:
    """Decode one implemented Arbitrum Nitro special typed envelope."""

    result = decode_l2_envelope(value)
    if result.get("family") != "arbitrum-nitro":
        raise Chain2FormatError("artifact is not an implemented Arbitrum Nitro transaction")
    return result


def _hex_field(value: object, *, name: str) -> str:
    if not isinstance(value, bytes):
        raise Chain2FormatError(f"decoded {name} is not bytes")
    if len(value) > MAX_DYNAMIC_FIELD:
        raise Chain2FormatError(f"{name} exceeds the dynamic-field cap")
    return "0x" + value.hex()


def _abi_address(value: object, *, name: str) -> str:
    if not isinstance(value, str):
        raise Chain2FormatError(f"decoded {name} is not an address")
    parsed = blockchain.classify_eth_address(value)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("checksummed"), str):
        raise Chain2FormatError(f"decoded {name} is not a canonical 20-byte address")
    return parsed["checksummed"]


def _factory(init_code: bytes) -> dict[str, Any] | None:
    if not init_code:
        return None
    if len(init_code) < 20:
        raise Chain2FormatError("nonempty initCode is shorter than its 20-byte factory prefix")
    return {
        "address": _address(init_code[:20], name="factory"),
        "data": _data(init_code[20:], name="factoryData"),
    }


def _paymaster_v06(raw: bytes) -> dict[str, Any] | None:
    if not raw:
        return None
    if len(raw) < 20:
        raise Chain2FormatError("v0.6 paymasterAndData is shorter than its address prefix")
    return {
        "address": _address(raw[:20], name="paymaster"),
        "data": _data(raw[20:], name="paymasterData"),
    }


def _paymaster_packed(raw: bytes, *, version: str) -> dict[str, Any] | None:
    if not raw:
        return None
    if len(raw) < 52:
        raise Chain2FormatError("packed paymasterAndData is shorter than 52-byte fixed prefix")
    payload_end = len(raw)
    signature: bytes | None = None
    if version == "0.9" and raw.endswith(PAYMASTER_SIGNATURE_MAGIC):
        if len(raw) < 62:
            raise Chain2FormatError("v0.9 paymaster signature suffix is truncated")
        signature_length = int.from_bytes(raw[-10:-8], "big")
        signature_start = len(raw) - 10 - signature_length
        if signature_start < 52:
            raise Chain2FormatError("v0.9 paymaster signature length overlaps fixed fields")
        signature = raw[signature_start:signature_start + signature_length]
        payload_end = signature_start
    return {
        "address": _address(raw[:20], name="paymaster"),
        "verification_gas_limit": int.from_bytes(raw[20:36], "big"),
        "post_op_gas_limit": int.from_bytes(raw[36:52], "big"),
        "data": _data(raw[52:payload_end], name="paymasterData"),
        "signature": None if signature is None else _data(signature, name="paymasterSignature"),
        "signature_magic": "0x" + PAYMASTER_SIGNATURE_MAGIC.hex() if signature is not None else None,
    }


def _preflight_user_ops(encoded: bytes) -> int:
    if len(encoded) < 96:
        raise Chain2FormatError("handleOps ABI body is truncated")
    operations_offset = int.from_bytes(encoded[:32], "big")
    if operations_offset % 32 or operations_offset < 64 or operations_offset + 32 > len(encoded):
        raise Chain2FormatError("handleOps operations offset is invalid")
    count = int.from_bytes(encoded[operations_offset:operations_offset + 32], "big")
    if count > MAX_USER_OPERATIONS:
        raise Chain2FormatError(f"handleOps operation count exceeds {MAX_USER_OPERATIONS}")
    return count


def _decode_userop_v06(operation: tuple[Any, ...], index: int) -> dict[str, Any]:
    if len(operation) != 11:
        raise Chain2FormatError(f"v0.6 operation {index} has the wrong arity")
    (sender, nonce, init_code, call_data, call_gas, verification_gas,
     pre_verification_gas, max_fee, max_priority, paymaster_data, signature) = operation
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in (
            nonce, call_gas, verification_gas, pre_verification_gas, max_fee, max_priority)):
        raise Chain2FormatError(f"v0.6 operation {index} has a non-integer numeric field")
    if not all(isinstance(value, bytes) for value in (init_code, call_data, paymaster_data, signature)):
        raise Chain2FormatError(f"v0.6 operation {index} has a non-byte dynamic field")
    return {
        "index": index,
        "sender": _abi_address(sender, name="sender"),
        "nonce": nonce,
        "nonce_key": nonce >> 64,
        "nonce_sequence": nonce & ((1 << 64) - 1),
        "init_code": _hex_field(init_code, name="initCode"),
        "factory": _factory(init_code),
        "call_data": _hex_field(call_data, name="callData"),
        "call_gas_limit": call_gas,
        "verification_gas_limit": verification_gas,
        "pre_verification_gas": pre_verification_gas,
        "max_fee_per_gas": max_fee,
        "max_priority_fee_per_gas": max_priority,
        "paymaster_and_data": _hex_field(paymaster_data, name="paymasterAndData"),
        "paymaster": _paymaster_v06(paymaster_data),
        "signature": _hex_field(signature, name="signature"),
    }


def _decode_userop_packed(operation: tuple[Any, ...], index: int, *, version: str) -> dict[str, Any]:
    if len(operation) != 9:
        raise Chain2FormatError(f"packed operation {index} has the wrong arity")
    (sender, nonce, init_code, call_data, account_gas_limits,
     pre_verification_gas, gas_fees, paymaster_data, signature) = operation
    if not isinstance(nonce, int) or isinstance(nonce, bool) or not isinstance(pre_verification_gas, int):
        raise Chain2FormatError(f"packed operation {index} has a non-integer numeric field")
    if not all(isinstance(value, bytes) for value in (
            init_code, call_data, account_gas_limits, gas_fees, paymaster_data, signature)):
        raise Chain2FormatError(f"packed operation {index} has a non-byte field")
    _fixed(account_gas_limits, 32, name="accountGasLimits")
    _fixed(gas_fees, 32, name="gasFees")
    gas_word = int.from_bytes(account_gas_limits, "big")
    fee_word = int.from_bytes(gas_fees, "big")
    return {
        "index": index,
        "sender": _abi_address(sender, name="sender"),
        "nonce": nonce,
        "nonce_key": nonce >> 64,
        "nonce_sequence": nonce & ((1 << 64) - 1),
        "init_code": _hex_field(init_code, name="initCode"),
        "factory": _factory(init_code),
        "call_data": _hex_field(call_data, name="callData"),
        "account_gas_limits": "0x" + account_gas_limits.hex(),
        "verification_gas_limit": gas_word >> 128,
        "call_gas_limit": gas_word & ((1 << 128) - 1),
        "pre_verification_gas": pre_verification_gas,
        "gas_fees": "0x" + gas_fees.hex(),
        "max_priority_fee_per_gas": fee_word >> 128,
        "max_fee_per_gas": fee_word & ((1 << 128) - 1),
        "paymaster_and_data": _hex_field(paymaster_data, name="paymasterAndData"),
        "paymaster": _paymaster_packed(paymaster_data, version=version),
        "signature": _hex_field(signature, name="signature"),
    }


@_closed
def decode_handle_ops(value: object, *, version: str) -> dict[str, Any]:
    """Decode canonical EntryPoint ``handleOps`` calldata for an explicit version.

    Supported versions are ``0.6``, ``0.7``, ``0.8``, and ``0.9``.  The packed
    selector is shared by the last three, so the caller must supply the semantic
    version; this function never guesses it.  Hashing and signature/state validity
    are intentionally out of scope.
    """

    if version not in {"0.6", "0.7", "0.8", "0.9"}:
        raise Chain2FormatError("version must be one of 0.6, 0.7, 0.8, or 0.9")
    raw = _artifact_bytes(value, label="handleOps calldata")
    if len(raw) < 4:
        raise Chain2FormatError("handleOps calldata is shorter than its selector")
    expected_selector = HANDLE_OPS_V06_SELECTOR if version == "0.6" else HANDLE_OPS_PACKED_SELECTOR
    if raw[:4] != expected_selector:
        raise Chain2FormatError(
            f"selector 0x{raw[:4].hex()} does not match ERC-4337 v{version} handleOps"
        )
    encoded = raw[4:]
    preflight_count = _preflight_user_ops(encoded)
    operation_type = _V06_OPERATION_TYPE if version == "0.6" else _PACKED_OPERATION_TYPE
    abi_types = [operation_type + "[]", "address"]
    try:
        decoded = abi_decode(abi_types, encoded, strict=True)
    except Exception as exc:
        raise Chain2FormatError("handleOps tuple-array ABI is malformed") from exc
    if abi_encode(abi_types, decoded) != encoded:
        raise Chain2FormatError("handleOps ABI is not the canonical complete encoding")
    operations, beneficiary = decoded
    if not isinstance(operations, tuple) or len(operations) != preflight_count:
        raise Chain2FormatError("handleOps decoded operation count is inconsistent")
    parsed = []
    for index, operation in enumerate(operations):
        if not isinstance(operation, tuple):
            raise Chain2FormatError(f"operation {index} is not a tuple")
        parsed.append(
            _decode_userop_v06(operation, index)
            if version == "0.6"
            else _decode_userop_packed(operation, index, version=version)
        )
    return {
        "kind": "erc-4337-handle-ops",
        "version": version,
        "selector": "0x" + expected_selector.hex(),
        "packed": version != "0.6",
        "beneficiary": _abi_address(beneficiary, name="beneficiary"),
        "operation_count": len(parsed),
        "operations": parsed,
        "validity": "structure-only",
        "signature_validity": None,
        "state_validity": None,
    }


decode_erc4337_handle_ops = decode_handle_ops


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Chain2FormatError(message)


def _read_artifact(path: str) -> bytes:
    data = Path(path).read_bytes()
    if not data or len(data) > MAX_INPUT:
        raise Chain2FormatError("input file is empty or exceeds the size cap")
    stripped = data.strip()
    if re.fullmatch(rb"(?:0[xX])?[0-9a-fA-F]+", stripped):
        text = stripped.decode("ascii")
        if text.startswith(("0x", "0X")):
            text = text[2:]
        if len(text) % 2:
            raise Chain2FormatError("hexadecimal input file has odd length")
        return bytes.fromhex(text)
    return data


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline OP/Nitro/ERC-4337 structure decoder")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    l2 = subparsers.add_parser("l2", help="decode OP or Arbitrum typed envelope")
    l2.add_argument("artifact")
    l2.add_argument("--post-regolith", action="store_true")
    userop = subparsers.add_parser("userop", help="decode EntryPoint handleOps calldata")
    userop.add_argument("artifact")
    userop.add_argument("--version", required=True, choices=("0.6", "0.7", "0.8", "0.9"))
    try:
        args = parser.parse_args(argv)
        raw = _read_artifact(args.artifact)
        if args.operation == "l2":
            result = decode_l2_envelope(raw, post_regolith=args.post_regolith)
        else:
            result = decode_handle_ops(raw, version=args.version)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (Chain2FormatError, OSError) as exc:
        print(f"chain2_evm_formats: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
