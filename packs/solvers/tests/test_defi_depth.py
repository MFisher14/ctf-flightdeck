import json
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import defi_depth as defi


def kinds(report):
    return {item["kind"] for item in report["findings"]}


def test_defi_source_finds_cross_function_oracle_flash_permit_and_proxy_depth():
    source = r"""
        pragma solidity ^0.8.20;
        contract Vault {
            mapping(address => uint256) public balances;
            uint256 public totalSupply;
            uint256 public totalAssets;
            address public implementation;

            function withdraw(address payable target, uint256 amount) external {
                uint256 beforeBalance = balances[msg.sender];
                target.call{value: amount}("");
                balances[msg.sender] = beforeBalance - amount;
            }
            function emergencyDebit(address who) external { balances[who] = 0; }
            function borrow(uint amount) external {
                (, int256 answer,, uint256 updatedAt,) = feed.latestRoundData();
                pool.getReserves();
                balances[msg.sender] += amount * uint(answer);
            }
            function swapNow(address router) external { router.swap(); }
            function executeOperation(bytes calldata data) external { balances[msg.sender] += 1; }
            function permit(address owner, bytes calldata sig) external { recover(sig); balances[owner] += 1; }
            function upgradeTo(address next) external { implementation = next; }
            function deposit(uint assets) external {
                if (totalSupply == 0) { totalSupply = totalAssets == 0 ? assets : assets / totalAssets; }
            }
        }
    """
    report = defi.analyze_defi_source(source)
    found = kinds(report)
    assert {
        "intra-function-reentrancy", "cross-function-reentrancy",
        "spot-oracle-manipulation", "oracle-staleness", "oracle-round-validation",
        "missing-slippage-bound", "missing-deadline", "unauthenticated-flash-callback",
        "permit-replay", "permit-no-expiry", "permit-domain-separation",
        "unprotected-upgrade-path", "first-depositor-inflation",
    } <= found
    cross = next(item for item in report["findings"] if item["kind"] == "cross-function-reentrancy")
    assert cross["chain"][0] == "withdraw"
    assert "balances" in cross["shared_state"]
    assert report["oracle_sources"] == ["amm-reserves", "single-feed"]
    assert report["call_graph"]["withdraw"] == []


def test_guards_twap_checks_and_comments_reduce_noise():
    source = r"""
        pragma solidity ^0.8.20;
        contract Safer {
            mapping(address => uint) balances;
            modifier nonReentrant() { _; }
            // feed.latestRoundData(); pool.getReserves(); router.swap();
            function withdraw(address payable target, uint n) external nonReentrant {
                balances[msg.sender] -= n;
                (bool ok,) = target.call{value:n}(""); require(ok);
            }
            function price() external view returns (uint) {
                feed.latestRoundData(); require(updatedAt + maxDelay > block.timestamp);
                require(answeredInRound >= roundId); feed.decimals(); oracle.observe();
                return 1;
            }
            function swap(uint amountOutMin, uint deadline) external { require(deadline >= block.timestamp); router.swap(); }
        }
    """
    found = kinds(defi.analyze_defi_source(source))
    assert "intra-function-reentrancy" not in found
    assert "cross-function-reentrancy" not in found
    assert "spot-oracle-manipulation" not in found
    assert "oracle-staleness" not in found
    assert "oracle-round-validation" not in found
    assert "oracle-decimal-assumption" not in found
    assert "missing-slippage-bound" not in found
    assert "missing-deadline" not in found


def test_storage_layout_comparison_reports_type_move_replacement_and_removal():
    old = {
        "storage": [
            {"label": "owner", "slot": "0", "offset": 0, "type": "t_address"},
            {"label": "balances", "slot": "1", "offset": 0, "type": "t_mapping"},
            {"label": "paused", "slot": "2", "offset": 0, "type": "t_bool"},
        ],
        "types": {"t_address": {"numberOfBytes": "20"}, "t_mapping": {"numberOfBytes": "32"},
                  "t_bool": {"numberOfBytes": "1"}},
    }
    new = {
        "storage": [
            {"label": "admin", "slot": "0", "offset": 0, "type": "t_uint"},
            {"label": "paused", "slot": "1", "offset": 0, "type": "t_bool"},
            {"label": "balances", "slot": "3", "offset": 0, "type": "t_mapping"},
        ],
        "types": {"t_uint": {"numberOfBytes": "32"}, "t_mapping": {"numberOfBytes": "32"},
                  "t_bool": {"numberOfBytes": "1"}},
    }
    report = defi.compare_storage_layouts(old, new)
    assert report["compatible"] is False
    assert {"storage-type-collision", "storage-variable-moved", "storage-replacement"} <= kinds(report)
    moved = [item["variable"] for item in report["findings"] if item["kind"] == "storage-variable-moved"]
    assert moved == ["balances", "paused"]


def test_storage_layout_append_is_compatible():
    old = [{"label": "owner", "slot": "0", "offset": 0, "type": "address"}]
    new = old + [{"label": "value", "slot": "1", "offset": 0, "type": "uint256"}]
    report = defi.compare_storage_layouts(old, new)
    assert report["compatible"] is True
    assert report["findings"] == []


def test_call_trace_detects_recursive_entry_and_semantic_oracle_order():
    nested = {
        "to": "0xVault", "function": "withdraw", "input": "0x12345678",
        "calls": [{"to": "0xAttacker", "function": "receive", "calls": [
            {"to": "0xVAULT", "function": "withdraw", "input": "0x12345678"}
        ]}],
    }
    report = defi.analyze_call_trace(nested)
    assert report["node_count"] == 3
    assert "observed-reentrant-call" in kinds(report)
    sequence = defi.analyze_call_trace([
        {"op": "oracle_update", "contract": "oracle"},
        {"op": "swap", "contract": "pool"},
    ])
    assert "observed-oracle-update-then-action" in kinds(sequence)


def test_price_observation_outliers_and_artifact_routing():
    observations = [
        {"block": 1, "source": "a", "price": 100},
        {"block": 1, "source": "b", "price": 101},
        {"block": 2, "source": "pool", "price": 220},
        {"block": 3, "source": "a", "price": 99},
    ]
    report = defi.analyze_price_observations(observations, threshold=0.25)
    assert report["median"] == 100.5
    assert {"price-outlier", "abrupt-price-change"} <= kinds(report)
    routed = defi.analyze_artifact(json.dumps(observations).encode(), "prices.json")
    assert routed["kind"] == "price-observation-analysis"
    with pytest.raises(ValueError, match="positive"):
        defi.analyze_price_observations([{"price": 0}])


def test_trace_and_source_caps_are_enforced(monkeypatch):
    monkeypatch.setattr(defi, "MAX_TRACE_NODES", 1)
    with pytest.raises(ValueError, match="cap"):
        defi.analyze_call_trace({"to": "a", "calls": [{"to": "b"}]})
    monkeypatch.setattr(defi, "MAX_INPUT", 3)
    with pytest.raises(ValueError, match="cap"):
        defi.analyze_defi_source("contract X {}")


def test_access_control_is_not_reentrancy_guard_and_user_state_mutations_are_tracked():
    source = """
      contract V {
        struct State { uint256 x; }
        State state;
        uint256[] queue;
        modifier onlyOwner() { _; }
        function memberWrite(address t) external onlyOwner { t.call(""); state.x = 1; }
        function deletion(address t) external { t.call(""); delete state; }
        function pushValue(address t) external { t.call(""); queue.push(1); }
      }
    """
    report = defi.analyze_defi_source(source)
    assert report["state_variables"] == ["queue", "state"]
    vulnerable = {item["function"] for item in report["findings"]
                  if item["kind"] == "intra-function-reentrancy"}
    assert vulnerable == {"memberWrite", "deletion", "pushValue"}


def test_storage_gap_consumption_is_not_a_collision():
    old = {"storage": [
        {"label": "owner", "slot": "0", "offset": 0, "type": "address"},
        {"label": "__gap", "slot": "1", "offset": 0, "type": "uint256[50]"},
    ]}
    new = {"storage": [
        {"label": "owner", "slot": "0", "offset": 0, "type": "address"},
        {"label": "value", "slot": "1", "offset": 0, "type": "uint256"},
        {"label": "__gap", "slot": "2", "offset": 0, "type": "uint256[49]"},
    ]}
    report = defi.compare_storage_layouts(old, new)
    assert report["compatible"] is True
    assert report["findings"] == []


def test_permit_requires_nonce_consumption_expiry_validation_and_domain_hashing():
    bad = """
      contract P {
        mapping(address => uint) nonces;
        bytes32 DOMAIN_SEPARATOR;
        function permit(address owner, uint deadline) external {
          uint observed = nonces[owner]; DOMAIN_SEPARATOR; deadline; observed;
        }
      }
    """
    assert {"permit-replay", "permit-no-expiry", "permit-domain-separation"} <= kinds(
        defi.analyze_defi_source(bad))
    good = """
      contract P {
        function permit(address owner, uint deadline, bytes32 structHash) external {
          _useNonce(owner); require(block.timestamp <= deadline);
          bytes32 digest = _hashTypedDataV4(structHash); digest;
        }
      }
    """
    found = kinds(defi.analyze_defi_source(good))
    assert not ({"permit-replay", "permit-no-expiry", "permit-domain-separation"} & found)


def test_twap_in_unrelated_function_does_not_hide_spot_oracle_and_overloads_survive():
    source = """
      contract O {
        function safeView() external view { oracle.observe(); }
        function borrow(uint amount) external { pool.getReserves(); mint(amount); }
        function quote(uint x) external pure returns(uint) { return x; }
        function quote(address x) external pure returns(address) { return x; }
      }
    """
    report = defi.analyze_defi_source(source)
    assert "spot-oracle-manipulation" in kinds(report)
    assert len([key for key in report["function_summaries"] if key.startswith("quote")]) == 2


def test_prices_and_recursive_traces_reject_nonfinite_malformed_and_cycles():
    for value in (math.nan, math.inf, None, [], {}):
        with pytest.raises(ValueError):
            defi.analyze_price_observations([{"price": value}])
    trace = {"to": "a", "calls": []}
    trace["calls"].append(trace)
    with pytest.raises(ValueError, match="cyclic"):
        defi.analyze_call_trace(trace)
