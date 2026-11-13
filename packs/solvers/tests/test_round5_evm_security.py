from __future__ import annotations

import random
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "solvers" / "toolkits"))
import evm_security as E  # noqa: E402
from ctf import triage  # noqa: E402


def test_bytecode_exact_evidence_but_no_vulnerability_verdict():
    code = bytes.fromhex("3214601057f150f155ff")
    report = E.analyze_bytecode(code)
    kinds = {row["kind"] for row in report["findings"]}
    assert {"tx-origin-auth", "external-call", "unchecked-call-result",
            "reentrancy-order-candidate", "selfdestruct"}.issubset(kinds)
    assert report["vulnerability_verdict"] is None
    assert all(row["vulnerability_verified"] is False for row in report["findings"])


def test_source_masks_comments_strings_and_reports_real_tokens_only():
    source = '''contract C {
      string x = "tx.origin selfdestruct(x)"; // .delegatecall(ignored)
      function f(address a) public { require(tx.origin == msg.sender); a.delegatecall(""); }
    }'''
    report = E.analyze_source(source)
    kinds = [row["kind"] for row in report["findings"]]
    assert kinds.count("tx-origin-auth") == 1
    assert kinds.count("delegatecall") == 1
    assert "selfdestruct" not in kinds


def test_source_does_not_call_plain_tx_origin_use_authentication():
    report = E.analyze_source("contract C { function f() public { emit Seen(tx.origin); } }")
    kinds = [row["kind"] for row in report["findings"]]
    assert kinds.count("tx-origin-use") == 1
    assert "tx-origin-auth" not in kinds


def test_storage_collision_is_exact_overlap_not_exploit_verdict():
    proxy = {"storage": [{"label": "admin", "slot": "0", "offset": 0,
                           "bytes": 20, "type": "address"}]}
    impl = {"storage": [{"label": "balance", "slot": "0x0", "offset": 0,
                          "bytes": 32, "type": "uint256"}]}
    report = E.compare_storage_layout(proxy, impl)
    assert report["collisions"][0]["overlap_verified"] is True
    assert report["collisions"][0]["vulnerability_verified"] is False
    assert report["safe_verdict"] is None


def test_cli_guard(capsys):
    assert E.main([]) == 2
    assert "evm_security:" in capsys.readouterr().err


def test_misc_triage_routes_generic_evm_descriptions():
    for description in ("Solidity smart contract", "EVM bytecode audit"):
        suggested = triage.suggest("misc", description)
        assert suggested["engines"][0] == "solvers/toolkits/evm_security.py"


def test_evm_bytecode_mutation_fuzz_5000_cases():
    rng = random.Random(0xE7C7F)
    for _ in range(5000):
        data = rng.randbytes(rng.randrange(1, 220))
        report = E.analyze_bytecode(data)
        assert report["instruction_count"] <= len(data)
        assert report["vulnerability_verdict"] is None
