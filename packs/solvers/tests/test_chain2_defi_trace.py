"""Non-circular vectors for the strict offline DeFi trace/catalog engine.

Selector values are derived in the test with eth-utils. Bytecode is assembled by
hand from EVM opcodes, and call trees are caller-supplied Geth callTracer shapes;
the engine's output is never used to construct an input oracle.
"""
from __future__ import annotations

import json

import pytest
from eth_utils import keccak

import chain2_defi_trace as engine


VAULT = "0x" + "11" * 20
ATTACKER = "0x" + "22" * 20
POOL = "0x" + "33" * 20
OTHER_POOL = "0x" + "44" * 20
LENDER = "0x" + "55" * 20
LIBRARY = "0x" + "66" * 20
USER = "0x" + "77" * 20


def selector(signature: str) -> str:
    return keccak(text=signature)[:4].hex()


def frame(to: str, signature_or_selector: str, *, sender: str = USER,
          call_type: str = "CALL", calls: list[dict] | None = None,
          failed: bool = False) -> dict:
    chosen = (signature_or_selector if len(signature_or_selector) == 8
              else selector(signature_or_selector))
    result = {
        "type": call_type,
        "from": sender,
        "to": to,
        "input": "0x" + chosen,
        "calls": [] if calls is None else calls,
    }
    if failed:
        result["error"] = "execution reverted"
    return result


def kinds(report: dict) -> set[str]:
    return {finding["kind"] for finding in report["findings"]}


def test_selector_catalog_anchors_are_keccak_reference_values():
    expected = {
        "flashLoan(address,address,uint256,bytes)": "erc3156.flashLoan",
        "onFlashLoan(address,address,uint256,uint256,bytes)": "erc3156.onFlashLoan",
        "swap(uint256,uint256,address,bytes)": "uniswap-v2.swap",
        "uniswapV2Call(address,uint256,uint256,bytes)": "uniswap-v2.uniswapV2Call",
        "getReserves()": "uniswap-v2.getReserves",
        "latestRoundData()": "chainlink.latestRoundData",
        "observe(uint32[])": "uniswap-v3.observe",
        "borrow(address,uint256,uint256,uint16,address)": "aave.borrow",
        "liquidateBorrow(address,uint256,address)": "compound.liquidateBorrow",
    }
    for signature, name in expected.items():
        derived = selector(signature)
        assert engine.SELECTOR_CATALOG[derived]["name"] == name


def test_opcode_boundaries_dispatch_and_constant_evidence_are_distinct():
    flash = bytes.fromhex(selector("flashLoan(address,address,uint256,bytes)"))
    reserve = bytes.fromhex(selector("getReserves()"))
    # PUSH4 flash; EQ; PUSH1 0x0a; JUMPI is the dispatch shape recognized by
    # evm_audit. A later identical PUSH4 is merely a constant, not a dispatcher.
    bytecode = (b"\x63" + flash + b"\x14\x60\x0a\x57"
                + b"\x63" + flash + b"\x50"
                + b"\x63" + reserve + b"\x50\x00")
    report = engine.analyze_bytecode(bytecode)
    hits = report["selector_occurrences"]
    assert [row["selector"] for row in hits] == ["0x" + flash.hex(),
                                                  "0x" + flash.hex(),
                                                  "0x" + reserve.hex()]
    assert [row["evidence"] for row in hits] == ["dispatcher", "push4-constant",
                                                  "push4-constant"]
    assert report["instruction_count"] == 9


def test_push32_immediate_is_not_reinterpreted_as_selectors():
    flash = bytes.fromhex(selector("flashLoan(address,address,uint256,bytes)"))
    reserve = bytes.fromhex(selector("getReserves()"))
    immediate = flash + reserve + bytes(24)
    report = engine.analyze_bytecode(b"\x7f" + immediate + b"\x00")
    assert report["selector_occurrences"] == []
    assert report["categories"] == []


def test_truncated_push_is_declared_malformed_input():
    with pytest.raises(engine.Chain2DeFiError, match="truncated PUSH"):
        engine.analyze_bytecode(b"\x63\x5c\xff")


def test_same_entry_and_cross_function_reentry_are_observed_separately():
    same = frame(VAULT, "11111111", calls=[
        frame(ATTACKER, "22222222", sender=VAULT, calls=[
            frame(VAULT, "11111111", sender=ATTACKER),
        ]),
    ])
    same_report = engine.analyze_call_trace(same)
    assert "observed-same-entry-reentrancy" in kinds(same_report)
    finding = next(row for row in same_report["findings"]
                   if row["kind"] == "observed-same-entry-reentrancy")
    assert finding["context"] == VAULT
    assert finding["structural_evidence_verified"] is True
    assert finding["exploit_verified"] is False

    cross = frame(VAULT, "11111111", calls=[
        frame(ATTACKER, "22222222", sender=VAULT, calls=[
            frame(VAULT, "33333333", sender=ATTACKER),
        ]),
    ])
    cross_report = engine.analyze_call_trace(cross)
    assert "observed-cross-function-reentrancy" in kinds(cross_report)
    assert "observed-same-entry-reentrancy" not in kinds(cross_report)


def test_static_and_delegate_execution_context_semantics():
    read_only = frame(VAULT, "11111111", calls=[
        frame(ATTACKER, "22222222", sender=VAULT, calls=[
            frame(VAULT, "33333333", sender=ATTACKER, call_type="STATICCALL"),
        ]),
    ])
    read_report = engine.analyze_call_trace(read_only)
    read_finding = next(row for row in read_report["findings"]
                        if row["kind"] == "observed-read-only-reentrancy")
    assert read_finding["read_only"] is True
    assert read_finding["style"] == "cross-function"

    delegated = frame(VAULT, "11111111", calls=[
        frame(LIBRARY, "22222222", sender=VAULT, call_type="DELEGATECALL", calls=[
            frame(VAULT, "33333333", sender=LIBRARY),
        ]),
    ])
    delegate_report = engine.analyze_call_trace(delegated)
    callbacks = [row for row in delegate_report["findings"]
                 if row["kind"] == "observed-cross-function-reentrancy"]
    assert len(callbacks) == 1
    assert callbacks[0]["context"] == VAULT
    assert callbacks[0]["path"] == [0, 0, 0]


def test_ordered_same_pool_flash_manipulation_candidate():
    trace = [
        frame(LENDER, "flashLoan(address,address,uint256,bytes)"),
        frame(ATTACKER, "onFlashLoan(address,address,uint256,uint256,bytes)", sender=LENDER),
        frame(POOL, "swap(uint256,uint256,address,bytes)", sender=ATTACKER),
        frame(POOL, "getReserves()", sender=VAULT, call_type="STATICCALL"),
        frame(VAULT, "deposit(uint256,address)", sender=ATTACKER),
        frame(POOL, "swap(uint256,uint256,address,bytes)", sender=ATTACKER),
    ]
    report = engine.analyze_call_trace(trace, pool_addresses=[POOL])
    assert {"observed-flash-composition", "flash-price-manipulation-candidate"} <= kinds(report)
    candidate = next(row for row in report["findings"]
                     if row["kind"] == "flash-price-manipulation-candidate")
    assert candidate["pool"] == POOL
    assert candidate["same_pool_correlation_verified"] is True
    assert candidate["steps"]["reverse_mutation"]["index"] == 5
    assert candidate["exploit_verified"] is False


def test_flash_composition_negatives_do_not_claim_manipulation():
    benign = [
        frame(LENDER, "flashLoan(address,address,uint256,bytes)"),
        frame(ATTACKER, "onFlashLoan(address,address,uint256,uint256,bytes)", sender=LENDER),
        frame(POOL, "swap(uint256,uint256,address,bytes)", sender=ATTACKER),
    ]
    report = engine.analyze_call_trace(benign)
    assert "observed-flash-composition" in kinds(report)
    assert "flash-price-manipulation-candidate" not in kinds(report)

    wrong_pool = benign + [
        frame(OTHER_POOL, "getReserves()", sender=VAULT, call_type="STATICCALL"),
        frame(VAULT, "deposit(uint256,address)", sender=ATTACKER),
    ]
    assert "flash-price-manipulation-candidate" not in kinds(
        engine.analyze_call_trace(wrong_pool))

    reverted = [
        frame(LENDER, "flashLoan(address,address,uint256,bytes)"),
        frame(POOL, "swap(uint256,uint256,address,bytes)", failed=True),
        frame(POOL, "getReserves()", call_type="STATICCALL"),
        frame(VAULT, "deposit(uint256,address)"),
    ]
    assert "flash-price-manipulation-candidate" not in kinds(
        engine.analyze_call_trace(reverted))


@pytest.mark.parametrize("trace", [
    {},
    {"type": "CALL", "from": "bad", "to": VAULT, "input": "0x"},
    {"type": "CALL", "from": USER, "to": VAULT, "input": "0x1"},
    {"type": "CALL", "from": USER, "to": VAULT, "input": "0x", "calls": {}},
    {"type": "CALL", "from": USER, "to": VAULT, "input": "0x", "gas": "0x00"},
    [None],
])
def test_malformed_trace_raises_only_declared_error(trace):
    with pytest.raises(engine.Chain2DeFiError):
        engine.analyze_call_trace(trace)


def test_cycles_and_artifact_json_fail_closed():
    cyclic = frame(VAULT, "11111111")
    cyclic["calls"].append(cyclic)
    with pytest.raises(engine.Chain2DeFiError, match="cyclic"):
        engine.analyze_call_trace(cyclic)
    with pytest.raises(engine.Chain2DeFiError):
        engine.analyze_artifact(b"{", "trace")
    for value in (None, object(), 1, [], {}):
        with pytest.raises(engine.Chain2DeFiError):
            engine.analyze_bytecode(value)


def test_guarded_cli_success_and_failures(tmp_path, capsys):
    flash = bytes.fromhex(selector("flashLoan(address,address,uint256,bytes)"))
    artifact = tmp_path / "contract.hex"
    artifact.write_text((b"\x63" + flash + b"\x50\x00").hex())
    assert engine.main(["bytecode", str(artifact), "--pretty"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["selector_occurrences"][0]["name"] == "erc3156.flashLoan"
    assert engine.main([]) == 2
    capsys.readouterr()
    assert engine.main(["trace", str(tmp_path / "missing.json")]) == 2
    assert "chain2_defi_trace" in capsys.readouterr().err
