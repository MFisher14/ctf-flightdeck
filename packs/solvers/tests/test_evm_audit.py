import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import evm_audit as evm


def kinds(report):
    return {item["kind"] for item in report["findings"]}


def test_solidity_source_finds_requested_vulnerability_families():
    source = r'''
        pragma solidity ^0.7.6;
        contract BadProxy {
            mapping(address => uint256) public balances;
            address public implementation;
            function withdraw(address payable target, uint256 amount) external {
                target.call{value: amount}("");
                balances[msg.sender] -= amount;
            }
            function forward(bytes memory payload) external {
                implementation.delegatecall(payload);
            }
            function auth() external view returns (bool) { return tx.origin == msg.sender; }
            function kill() external { selfdestruct(payable(msg.sender)); }
            function add(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }
            function initialize(address x) external { implementation = x; }
        }
    '''
    report = evm.analyze_solidity_source(source)
    found = kinds(report)
    assert report["pragma_overflow_checked"] is False
    assert {"tx-origin-auth", "selfdestruct", "delegatecall", "reentrancy-order",
            "unrestricted-delegatecall", "unrestricted-selfdestruct",
            "legacy-arithmetic-overflow", "proxy-storage-collision",
            "unprotected-initializer"} <= found
    assert report["state_variables"] == ["balances", "implementation"]
    assert {item["name"] for item in report["functions"]} >= {"withdraw", "forward", "kill"}


def test_comments_strings_access_control_and_checked_arithmetic_reduce_noise():
    source = r'''
        pragma solidity ^0.8.20;
        contract Safer {
            uint256 private balance;
            // tx.origin; selfdestruct(msg.sender); implementation.delegatecall(x)
            string constant note = "tx.origin selfdestruct delegatecall";
            modifier onlyOwner() { _; }
            function kill() external onlyOwner { selfdestruct(payable(msg.sender)); }
            function debit(address payable t, uint256 n) external {
                balance -= n;
                (bool ok,) = t.call{value:n}(""); require(ok);
            }
            function math(uint x) external pure returns(uint) { unchecked { return x + 1; } }
        }
    '''
    report = evm.analyze_solidity_source(source)
    found = kinds(report)
    assert "tx-origin-auth" not in found
    assert "reentrancy-order" not in found
    assert "unrestricted-selfdestruct" not in found
    assert "unchecked-low-level-call" not in found
    assert "unchecked-arithmetic" in found
    assert "legacy-arithmetic-overflow" not in found


def test_internal_dangerous_primitive_is_not_called_unrestricted_entrypoint():
    source = """
      pragma solidity ^0.8.0;
      contract C {
        function internalForward(address x, bytes memory d) internal { x.delegatecall(d); }
        function guarded(address x, bytes memory d) external onlyOwner { x.delegatecall(d); }
      }
    """
    report = evm.analyze_solidity_source(source)
    assert "delegatecall" in kinds(report)
    assert "unrestricted-delegatecall" not in kinds(report)


def test_disassembly_cfg_selector_and_bytecode_findings():
    # dispatcher, ORIGIN, CALL followed by SSTORE, DELEGATECALL, arithmetic, SELFDESTRUCT
    code = bytes.fromhex("63a9059cbb1460105732f1600055f401ff")
    instructions = evm.disassemble(code)
    assert instructions[0]["name"] == "PUSH4"
    assert evm.function_selectors(instructions) == [
        {"selector": "0xa9059cbb", "destination": 16, "offset": 0}
    ]
    report = evm.analyze_evm_bytecode(code)
    found = kinds(report)
    assert {"tx-origin", "selfdestruct", "delegate-context-call", "reentrancy-order",
            "proxy-storage-collision", "arithmetic-overflow-context"} <= found
    assert report["instruction_count"] == len(instructions)
    assert report["basic_block_count"] >= 2


def test_panic_marker_and_malformed_bytecode_behavior():
    report = evm.analyze_evm_bytecode(bytes.fromhex("634e487b710100"))
    assert "arithmetic-overflow-context" not in kinds(report)
    truncated = evm.disassemble(b"\x7f\x01\x02")
    assert truncated[0]["truncated"] is True
    with pytest.raises(ValueError):
        evm.parse_bytecode("0xabc")
    with pytest.raises(ValueError):
        evm.parse_bytecode("not hex")


def test_bytecode_direct_api_enforces_bound_before_hex_decode(monkeypatch):
    monkeypatch.setattr(evm, "MAX_INPUT", 4)
    with pytest.raises(ValueError, match="cap"):
        evm.parse_bytecode("00" * 20)


def test_artifact_routing_and_cli(tmp_path):
    source = tmp_path / "sample.sol"
    source.write_text("pragma solidity 0.8.0; contract C { function a() external { tx.origin; } }")
    assert evm.analyze_artifact(source.read_bytes(), source.name)["kind"] == "solidity-source"
    bytecode = tmp_path / "code.hex"
    bytecode.write_text("0x32ff")
    assert evm.analyze_artifact(bytecode.read_bytes(), bytecode.name)["kind"] == "evm-bytecode"
    proc = subprocess.run([sys.executable, str(ROOT / "solvers/toolkits/evm_audit.py"),
                           str(bytecode)], check=True, capture_output=True, text=True)
    assert json.loads(proc.stdout)["size"] == 2
