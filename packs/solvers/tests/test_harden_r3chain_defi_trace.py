"""Independent hardening vectors for :mod:`chain2_defi_trace`.

Selectors are derived with ``eth-utils`` from the published ERC-3156, Aave V3,
Uniswap and ERC-4626 signatures.  Calldata is encoded by ``eth-abi`` and EVM
dispatcher bytes are assembled directly from documented opcodes; no engine
output is used to construct an oracle.  Every test is offline.
"""
from __future__ import annotations

import json
import random

from eth_abi import encode
from eth_utils import keccak
import pytest

import chain2_defi_trace as engine


USER = "0x" + "11" * 20
LENDER = "0x" + "22" * 20
BORROWER = "0x" + "33" * 20
TOKEN = "0x" + "44" * 20
POOL = "0x" + "55" * 20
VAULT = "0x" + "66" * 20


def _selector(signature: str) -> bytes:
    """Ethereum ABI selector oracle: first four bytes of legacy Keccak-256."""
    return keccak(text=signature)[:4]


def _calldata(signature: str, types: list[str], values: list[object]) -> str:
    return "0x" + (_selector(signature) + encode(types, values)).hex()


def _frame(sender: str, target: str, calldata: str, *, call_type: str = "CALL",
           calls: list[dict] | None = None) -> dict:
    return {
        "type": call_type,
        "from": sender,
        "to": target,
        "input": calldata,
        "calls": [] if calls is None else calls,
    }


def _published_trace() -> list[dict]:
    """Documented ERC-3156 -> AMM spot read -> ERC-4626 call sequence."""
    amount = 10**18
    return [
        _frame(
            USER,
            LENDER,
            _calldata(
                "flashLoan(address,address,uint256,bytes)",
                ["address", "address", "uint256", "bytes"],
                [BORROWER, TOKEN, amount, b"total-warfare"],
            ),
        ),
        _frame(
            LENDER,
            BORROWER,
            _calldata(
                "onFlashLoan(address,address,uint256,uint256,bytes)",
                ["address", "address", "uint256", "uint256", "bytes"],
                [USER, TOKEN, amount, 10**15, b"total-warfare"],
            ),
        ),
        _frame(
            BORROWER,
            POOL,
            _calldata(
                "swap(uint256,uint256,address,bytes)",
                ["uint256", "uint256", "address", "bytes"],
                [0, 123, BORROWER, b""],
            ),
        ),
        _frame(VAULT, POOL, _calldata("getReserves()", [], []), call_type="STATICCALL"),
        _frame(
            BORROWER,
            VAULT,
            _calldata(
                "deposit(uint256,address)",
                ["uint256", "address"],
                [123, BORROWER],
            ),
        ),
    ]


def _dispatcher_vector() -> bytes:
    flash = _selector("flashLoan(address,address,uint256,bytes)")
    callback = _selector("onFlashLoan(address,address,uint256,uint256,bytes)")
    # PUSH4 selector; EQ; PUSH2 destination; JUMPI, twice.  The same bytes then
    # occur inside a PUSH32 immediate and must not be treated as instructions.
    return (
        b"\x63" + flash + b"\x14\x61\x00\x10\x57"
        + b"\x63" + callback + b"\x14\x61\x00\x20\x57"
        + b"\x7f" + flash + callback + bytes(24) + b"\x00"
    )


def _declared_or_clean(call) -> None:
    try:
        result = call()
    except BaseException as exc:  # contract check intentionally catches leaks
        assert type(exc) is engine.Chain2DeFiError
    else:
        assert isinstance(result, dict)


@pytest.mark.parametrize(
    ("signature", "name", "category"),
    [
        ("flashLoan(address,address,uint256,bytes)", "erc3156.flashLoan", "flash-loan"),
        (
            "onFlashLoan(address,address,uint256,uint256,bytes)",
            "erc3156.onFlashLoan",
            "flash-callback",
        ),
        (
            "flashLoanSimple(address,address,uint256,bytes,uint16)",
            "aave-v3.flashLoanSimple",
            "flash-loan",
        ),
        (
            "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",
            "aave-v3.flashLoan",
            "flash-loan",
        ),
        (
            "executeOperation(address,uint256,uint256,address,bytes)",
            "aave-v3.executeOperation-simple",
            "flash-callback",
        ),
        (
            "executeOperation(address[],uint256[],uint256[],address,bytes)",
            "aave-v3.executeOperation-multi",
            "flash-callback",
        ),
        (
            "uniswapV2Call(address,uint256,uint256,bytes)",
            "uniswap-v2.uniswapV2Call",
            "flash-callback",
        ),
        (
            "uniswapV3FlashCallback(uint256,uint256,bytes)",
            "uniswap-v3.uniswapV3FlashCallback",
            "flash-callback",
        ),
        (
            "uniswapV3SwapCallback(int256,int256,bytes)",
            "uniswap-v3.uniswapV3SwapCallback",
            "flash-callback",
        ),
    ],
)
def test_published_flash_interfaces_lock_catalog_with_eth_utils(
    signature: str, name: str, category: str
) -> None:
    derived = _selector(signature).hex()
    assert engine.SELECTOR_CATALOG[derived] == {"name": name, "category": category}


def test_analyze_bytecode_locks_real_push4_dispatch_boundaries() -> None:
    report = engine.analyze_bytecode(_dispatcher_vector())
    assert report["kind"] == "defi-bytecode-selector-catalog"
    assert report["byte_length"] == 54
    assert report["instruction_count"] == 10
    assert report["categories"] == ["flash-callback", "flash-loan"]
    assert report["selector_occurrences"] == [
        {
            "pc": 0,
            "selector": "0x" + _selector("flashLoan(address,address,uint256,bytes)").hex(),
            "name": "erc3156.flashLoan",
            "category": "flash-loan",
            "evidence": "dispatcher",
            "interface_capability_only": True,
        },
        {
            "pc": 10,
            "selector": "0x"
            + _selector("onFlashLoan(address,address,uint256,uint256,bytes)").hex(),
            "name": "erc3156.onFlashLoan",
            "category": "flash-callback",
            "evidence": "dispatcher",
            "interface_capability_only": True,
        },
    ]


def test_analyze_call_trace_locks_abi_encoded_flash_price_sequence() -> None:
    report = engine.analyze_call_trace(_published_trace(), pool_addresses=[POOL])
    assert report["node_count"] == 5
    assert [row["selector"] for row in report["calls"]] == [
        "0x" + _selector("flashLoan(address,address,uint256,bytes)").hex(),
        "0x" + _selector("onFlashLoan(address,address,uint256,uint256,bytes)").hex(),
        "0x" + _selector("swap(uint256,uint256,address,bytes)").hex(),
        "0x" + _selector("getReserves()").hex(),
        "0x" + _selector("deposit(uint256,address)").hex(),
    ]
    assert [row["category"] for row in report["calls"]] == [
        "flash-loan",
        "flash-callback",
        "pool-mutation",
        "pool-spot-read",
        "sensitive-action",
    ]
    candidate = next(
        row for row in report["findings"]
        if row["kind"] == "flash-price-manipulation-candidate"
    )
    assert candidate["pool"] == POOL
    assert candidate["steps"] == {
        "flash": {"index": 1, "selector": "0x" + _selector(
            "onFlashLoan(address,address,uint256,uint256,bytes)"
        ).hex()},
        "mutation": {"index": 2, "selector": "0x" + _selector(
            "swap(uint256,uint256,address,bytes)"
        ).hex()},
        "spot_read": {"index": 3, "selector": "0x" + _selector("getReserves()").hex()},
        "sensitive_action": {
            "index": 4,
            "selector": "0x" + _selector("deposit(uint256,address)").hex(),
            "custom": False,
        },
        "reverse_mutation": None,
        "repayment": None,
    }
    assert candidate["exploit_verified"] is False
    assert report["pool_filter"] == [POOL]


def test_analyze_artifact_locks_both_explicit_modes() -> None:
    bytecode = _dispatcher_vector()
    bytecode_report = engine.analyze_artifact(("0x" + bytecode.hex()).encode(), "bytecode")
    assert [row["pc"] for row in bytecode_report["selector_occurrences"]] == [0, 10]

    trace_report = engine.analyze_artifact(
        json.dumps(_published_trace(), separators=(",", ":")).encode(),
        "trace",
        pool_addresses=[POOL],
    )
    assert trace_report["node_count"] == 5
    assert any(
        row["kind"] == "flash-price-manipulation-candidate"
        for row in trace_report["findings"]
    )


def test_main_vector_lock_and_guarded_argparse(tmp_path, capsys, monkeypatch) -> None:
    artifact = tmp_path / "erc3156.hex"
    artifact.write_text(_dispatcher_vector().hex(), encoding="ascii")
    assert engine.main(["bytecode", str(artifact), "--pretty"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [row["selector"] for row in report["selector_occurrences"]] == [
        "0x5cffe9de",
        "0x23e30c8b",
    ]

    assert engine.main([]) == 2
    capsys.readouterr()
    assert engine.main(["trace", str(tmp_path / "missing.json")]) == 2
    capsys.readouterr()

    def non_integer_exit(*args, **kwargs):
        raise SystemExit("not-an-integer")

    monkeypatch.setattr(engine.argparse.ArgumentParser, "parse_args", non_integer_exit)
    assert engine.main([]) == 2


def test_analyze_bytecode_fail_closed_fuzz(monkeypatch) -> None:
    valid = _dispatcher_vector()
    bit_flipped = bytearray(valid)
    bit_flipped[1] ^= 0x80
    rng = random.Random(0xC3156)
    samples = [
        b"",
        rng.randbytes(257),
        b"\xff" * 257,
        valid[:3],
        bytes(bit_flipped),
        None,
        memoryview(valid),
    ]
    for sample in samples:
        _declared_or_clean(lambda sample=sample: engine.analyze_bytecode(sample))

    monkeypatch.setattr(engine, "MAX_BYTECODE", 32)
    _declared_or_clean(lambda: engine.analyze_bytecode(b"\xff" * 33))


def test_analyze_call_trace_fail_closed_fuzz(monkeypatch) -> None:
    valid = _published_trace()[0]
    truncated = dict(valid)
    truncated.pop("to")
    bit_flipped = dict(valid)
    bit_flipped["input"] = bit_flipped["input"][:-1] + "g"
    randomish = {
        "type": "CALL",
        "from": "0x" + random.Random(0x4337).randbytes(20).hex(),
        "to": "0x" + "ff" * 20,
        "input": "0xffff",
        "calls": "not-an-array",
    }
    samples = [
        {},
        [],
        b"\xff" * 32,
        randomish,
        truncated,
        bit_flipped,
        [valid, None],
    ]
    for sample in samples:
        _declared_or_clean(lambda sample=sample: engine.analyze_call_trace(sample))

    monkeypatch.setattr(engine, "MAX_CHILDREN", 2)
    oversized = dict(valid)
    oversized["calls"] = [valid, valid, valid]
    _declared_or_clean(lambda: engine.analyze_call_trace(oversized))


@pytest.mark.parametrize("mode", ["bytecode", "trace", "unknown"])
def test_analyze_artifact_fail_closed_fuzz(mode: str, monkeypatch) -> None:
    valid_json = json.dumps(_published_trace()).encode()
    bit_flipped = bytearray(valid_json)
    bit_flipped[len(bit_flipped) // 2] ^= 0x80
    rng = random.Random(0xA11CE)
    samples = [
        b"",
        rng.randbytes(257),
        b"\xff" * 257,
        valid_json[:-1],
        bytes(bit_flipped),
    ]
    for sample in samples:
        _declared_or_clean(
            lambda sample=sample, mode=mode: engine.analyze_artifact(sample, mode)
        )

    _declared_or_clean(lambda: engine.analyze_artifact(bytearray(b"00"), mode))
    monkeypatch.setattr(engine, "MAX_JSON", 32)
    _declared_or_clean(lambda: engine.analyze_artifact(b"x" * 33, mode))


def test_main_fail_closed_fuzz_returns_codes(tmp_path, monkeypatch) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_bytes(b"{\"type\":")
    oversized = tmp_path / "oversized.bin"
    oversized.write_bytes(b"x" * 33)
    monkeypatch.setattr(engine, "MAX_JSON", 32)
    for argv in (
        ["trace", str(malformed)],
        ["bytecode", str(oversized)],
        ["not-a-mode", str(malformed)],
        ["trace", str(tmp_path / "absent")],
    ):
        try:
            code = engine.main(argv)
        except BaseException as exc:  # CLI must absorb parser/domain/file failures
            pytest.fail(f"main leaked {type(exc).__name__}: {exc}")
        assert isinstance(code, int)
        assert code in {0, 2}
