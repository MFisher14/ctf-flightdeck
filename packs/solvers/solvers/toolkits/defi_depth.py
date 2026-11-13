#!/usr/bin/env python3
"""Offline DeFi and upgradeability analysis for supplied source and trace artifacts.

The engine is deliberately chain-disconnected: it never compiles, executes, deploys,
or queries a node.  Reports are evidence-led static triage, not exploitability claims.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from pathlib import Path
from typing import Iterable, Mapping, Sequence

MAX_INPUT = 32 * 1024 * 1024
MAX_FUNCTIONS = 10_000
MAX_TRACE_NODES = 200_000
MAX_NESTING = 256

_SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _finding(kind: str, severity: str, message: str, confidence: str = "medium", **evidence: object) -> dict:
    item = {"kind": kind, "severity": severity, "confidence": confidence, "message": message}
    item.update({key: value for key, value in evidence.items() if value is not None})
    return item


def _sorted(findings: Iterable[dict]) -> list[dict]:
    unique: dict[str, dict] = {}
    for item in findings:
        unique[json.dumps(item, sort_keys=True, default=str)] = item
    return sorted(unique.values(), key=lambda item: (
        -_SEVERITY.get(str(item.get("severity")), 0), str(item.get("kind")),
        str(item.get("function", "")), int(item.get("line", 0)),
    ))


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _mask_comments_and_strings(text: str) -> str:
    """Replace comments and string contents while retaining offsets/newlines."""
    out = list(text)
    state, quote, index = "code", "", 0
    while index < len(text):
        ch = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out[index] = out[index + 1] = " "
                index += 2
                state = "line"
                continue
            if ch == "/" and nxt == "*":
                out[index] = out[index + 1] = " "
                index += 2
                state = "block"
                continue
            if ch in {'"', "'"}:
                quote, state, out[index] = ch, "string", " "
        elif state == "line":
            if ch == "\n":
                state = "code"
            else:
                out[index] = " "
        elif state == "block":
            if ch == "*" and nxt == "/":
                out[index] = out[index + 1] = " "
                index += 2
                state = "code"
                continue
            if ch != "\n":
                out[index] = " "
        else:
            if ch == "\\" and index + 1 < len(text):
                out[index] = " "
                if text[index + 1] != "\n":
                    out[index + 1] = " "
                index += 2
                continue
            if ch == quote:
                state = "code"
            if ch != "\n":
                out[index] = " "
        index += 1
    return "".join(out)


def _balanced_end(text: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


_FUNCTION = re.compile(
    r"\b(function\s+([A-Za-z_$][\w$]*)|constructor|fallback|receive)\b([^;{]*)\{", re.I
)


def solidity_functions(source: str) -> list[dict]:
    """Extract balanced Solidity functions and useful static features."""
    masked = _mask_comments_and_strings(source)
    records: list[dict] = []
    cursor = 0
    while len(records) < MAX_FUNCTIONS:
        match = _FUNCTION.search(masked, cursor)
        if not match:
            break
        opening = masked.find("{", match.start(), match.end())
        end = _balanced_end(masked, opening)
        if end is None:
            break
        token = match.group(1).lower()
        name = match.group(2) if token.startswith("function") else token
        header = masked[match.start():opening]
        body = masked[opening + 1:end - 1]
        records.append({
            "name": name,
            "start": match.start(),
            "line": _line(masked, match.start()),
            "header": header,
            "body": body,
            "visibility": next((value for value in ("external", "public", "internal", "private")
                                if re.search(rf"\b{value}\b", header)), "implicit"),
            # Caller authorization and a reentrancy mutex are different controls: an
            # authorized contract can still call back while the first frame is live.
            "reentrancy_guarded": bool(re.search(
                r"\b(?:nonReentrant\w*|reentrancyGuard\w*|mutex\w*|locked\w*)\b", header, re.I)),
            "access_controlled": bool(re.search(
                r"\b(?:onlyOwner\w*|onlyAdmin\w*|onlyRole\w*|onlyGovernance\w*|auth\w*)\b", header, re.I)),
        })
        cursor = end
    return records


_STATE_DECL = re.compile(
    r"(?m)^\s*(?:mapping\s*\([^;]+\)|(?:u?int(?:8|16|32|64|128|256)?|address|bool|bytes(?:\d+)?|string)"
    r"(?:\s*\[[^\]]*\])?)\s+(?:(?:public|private|internal|constant|immutable)\s+)*"
    r"([A-Za-z_$][\w$]*)\b[^;]*;"
)


def _state_variables(masked: str, functions: Sequence[dict]) -> list[str]:
    top = list(masked)
    for fn in functions:
        opening = masked.find("{", fn["start"])
        end = opening + len(fn["body"]) + 2
        for index in range(max(0, fn["start"]), min(len(top), end)):
            if top[index] != "\n":
                top[index] = " "
    top_text = "".join(top)
    names: set[str] = set()
    depth, start = 0, 0
    statements = []
    for index, char in enumerate(top_text):
        if char == "{":
            depth += 1
            if depth == 1:
                start = index + 1
        elif char == "}":
            if depth == 2:
                start = index + 1
            depth = max(0, depth - 1)
        elif char == ";" and depth == 1:
            statements.append(top_text[start:index + 1])
            start = index + 1
    declaration = re.compile(
        r"^\s*(?!event\b|error\b|using\b|type\b|modifier\b|function\b)"
        r"(?:mapping\s*\([\s\S]+\)|[A-Za-z_$][\w$.]*(?:\s*\[[^\]]*\])*)\s+"
        r"(?:(?:public|private|internal|constant|immutable|transient|override)\s+)*"
        r"([A-Za-z_$][\w$]*)\s*(?:=[\s\S]*)?;\s*$", re.I
    )
    for statement in statements:
        match = declaration.match(statement)
        if match:
            names.add(match.group(1))
    return sorted(names)


def _state_write_matches(body: str, name: str) -> list[re.Match[str]]:
    access = rf"\b{re.escape(name)}\b(?:\s*(?:\[[^;]+?\]|\.\s*[A-Za-z_$][\w$]*))*"
    return list(re.finditer(
        rf"(?:\bdelete\s+{access}|{access}\s*(?:\+\+|--|[+\-*/%]?=(?!=))|"
        rf"{access}\s*\.\s*(?:push|pop)\s*\()", body,
    ))


def _written_state(body: str, state_variables: Sequence[str]) -> set[str]:
    return {name for name in state_variables if _state_write_matches(body, name)}


def _read_state(body: str, state_variables: Sequence[str]) -> set[str]:
    return {name for name in state_variables if re.search(rf"\b{re.escape(name)}\b", body)}


_EXTERNAL_CALL = re.compile(
    r"\.(?:call|delegatecall|staticcall|send|transfer|safeTransfer|safeTransferFrom|"
    r"swap|flashLoan|flash|borrow|mint|redeem)\b\s*(?:\{|\()", re.I
)


def analyze_defi_source(source: str) -> dict:
    """Find composability, oracle, reentrancy, signature, and proxy risks."""
    if not isinstance(source, str):
        raise TypeError("source must be text")
    if len(source.encode("utf-8", "replace")) > MAX_INPUT:
        raise ValueError("source exceeds input cap")
    masked = _mask_comments_and_strings(source)
    functions = solidity_functions(source)
    states = _state_variables(masked, functions)
    names = {fn["name"] for fn in functions}
    findings: list[dict] = []
    summaries: dict[str, dict] = {}
    summary_name_counts: dict[str, int] = {}

    for fn in functions:
        body = fn["body"]
        calls = list(_EXTERNAL_CALL.finditer(body))
        writes = _written_state(body, states)
        reads = _read_state(body, states)
        internal_calls = sorted(name for name in names - {fn["name"]}
                                if re.search(rf"(?<![.\w]){re.escape(name)}\s*\(", body))
        ordinal = summary_name_counts.get(fn["name"], 0)
        summary_name_counts[fn["name"]] = ordinal + 1
        summary_key = fn["name"] if ordinal == 0 else f"{fn['name']}@{fn['line']}"
        summaries[summary_key] = {
            "visibility": fn["visibility"], "guarded": fn["reentrancy_guarded"],
            "access_controlled": fn["access_controlled"],
            "external_calls": len(calls), "reads": sorted(reads),
            "writes": sorted(writes), "internal_calls": internal_calls,
        }

        if calls and writes and not fn["reentrancy_guarded"]:
            first_call = calls[0]
            later_writes = [name for name in writes
                            if _state_write_matches(body[first_call.end():], name)]
            if later_writes:
                findings.append(_finding(
                    "intra-function-reentrancy", "high",
                    "external control transfer precedes a state update",
                    "high", function=fn["name"], line=fn["line"] + body.count("\n", 0, first_call.start()),
                    state=sorted(later_writes),
                ))

        if re.search(r"\b(?:swap|exactInput|exactOutput|addLiquidity|removeLiquidity)\b", body, re.I):
            signature_and_body = fn["header"] + " " + body
            if not re.search(r"\b(?:amountOutMin|amountInMax|minAmount|minimum|slippage)\b",
                             signature_and_body, re.I):
                findings.append(_finding(
                    "missing-slippage-bound", "high", "swap/liquidity action has no evident caller-controlled bound",
                    function=fn["name"], line=fn["line"],
                ))
            if not re.search(r"\b(?:deadline|block\.timestamp\s*[<>]=?)\b", signature_and_body, re.I):
                findings.append(_finding(
                    "missing-deadline", "medium", "swap/liquidity action has no evident expiry check",
                    function=fn["name"], line=fn["line"],
                ))

        if re.search(r"\b(?:permit|permitTransferFrom)\b", fn["name"] + " " + body, re.I):
            nonce_consumed = bool(re.search(
                r"\b(?:nonces?|_nonces)\b\s*(?:\[[^]]+\])?\s*(?:\+\+|--|[+\-]?=(?!=))|"
                r"\b_useNonce\s*\(", body, re.I))
            if not nonce_consumed:
                findings.append(_finding("permit-replay", "critical", "permit path has no evident nonce consumption",
                                         function=fn["name"], line=fn["line"]))
            deadline_checked = bool(re.search(
                # A deadline guard compares `deadline` against the current time in
                # either order: `deadline >= block.timestamp` or `block.timestamp <= deadline`.
                r"(?:require|if)\s*\([^;{}]*\bdeadline\b[^;{}]*\bblock\.timestamp\b|"
                r"(?:require|if)\s*\([^;{}]*\bblock\.timestamp\b[^;{}]*\bdeadline\b|"
                r"\bdeadline\b\s*[<>]=?\s*block\.timestamp|"
                r"\bblock\.timestamp\s*[<>]=?\s*\bdeadline\b", body, re.I))
            if not deadline_checked:
                findings.append(_finding("permit-no-expiry", "high", "permit path has no evident deadline check",
                                         function=fn["name"], line=fn["line"]))
            domain_bound = bool(re.search(
                r"\b_hashTypedDataV4\s*\(|\bDOMAIN_SEPARATOR\b[\s\S]{0,160}"
                r"(?:abi\.encode|keccak256|ecrecover)|(?:abi\.encode|keccak256)"
                r"[\s\S]{0,160}\b(?:DOMAIN_SEPARATOR|block\.chainid|chainid)\b",
                body, re.I))
            if not domain_bound:
                findings.append(_finding("permit-domain-separation", "high",
                                         "permit path has no evident chain/contract domain separation",
                                         function=fn["name"], line=fn["line"]))

        if re.search(r"\b(?:initialize|upgradeTo|upgradeToAndCall|setImplementation)\b", fn["name"], re.I):
            if (fn["visibility"] in {"external", "public", "implicit"}
                    and not fn["access_controlled"] and not re.search(
                    r"\b(?:initializer|reinitializer|_authorizeUpgrade|require\s*\([^)]*msg\.sender)",
                    fn["header"] + body, re.I)):
                findings.append(_finding("unprotected-upgrade-path", "critical",
                                         "initializer or implementation-changing entry point lacks an evident guard",
                                         function=fn["name"], line=fn["line"]))

    # Cross-function reentrancy: an unguarded entry point yields control while a second
    # unguarded entry point can mutate state observed by the first.
    public = {name: summary for name, summary in summaries.items()
              if summary["visibility"] in {"public", "external", "implicit"}}
    for outer_name, outer in public.items():
        if not outer["external_calls"] or outer["guarded"]:
            continue
        outer_state = set(outer["reads"]) | set(outer["writes"])
        for inner_name, inner in public.items():
            if inner_name == outer_name or inner["guarded"]:
                continue
            shared = sorted(outer_state & set(inner["writes"]))
            if shared:
                findings.append(_finding(
                    "cross-function-reentrancy", "high",
                    "an external call can reenter another entry point that mutates shared state",
                    chain=[outer_name, inner_name], shared_state=shared,
                ))

    spot_patterns = {
        "amm-reserves": r"\bgetReserves\s*\(",
        "amm-slot0": r"\bslot0\s*\(",
        "pool-balance": r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)",
        "single-feed": r"\b(?:latestAnswer|latestRoundData)\s*\(",
    }
    oracle_evidence = sorted(name for name, pattern in spot_patterns.items() if re.search(pattern, masked, re.I))
    twap = bool(re.search(r"\b(?:observe|consult|timeWeightedAverage|TWAP)\b", masked, re.I))
    sensitive = bool(re.search(r"\b(?:borrow|liquidat|mint|redeem|swap|collateral|healthFactor)\w*\s*\(", masked, re.I))
    unprotected_functions = []
    for fn in functions:
        local_sources = sorted(name for name, pattern in spot_patterns.items()
                               if re.search(pattern, fn["body"], re.I))
        local_sensitive = bool(re.search(
            r"\b(?:borrow|liquidat|mint|redeem|swap|collateral|healthFactor)\w*\s*\(",
            fn["name"] + " " + fn["body"], re.I))
        local_twap = bool(re.search(r"\b(?:observe|consult|timeWeightedAverage|TWAP)\b", fn["body"], re.I))
        if local_sources and local_sensitive and not local_twap:
            unprotected_functions.append({"function": fn["name"], "sources": local_sources})
    if unprotected_functions or (oracle_evidence and sensitive and not twap):
        findings.append(_finding(
            "spot-oracle-manipulation", "critical",
            "price-sensitive logic consumes a spot/single-observation source without evident TWAP aggregation",
            "high", oracle_sources=oracle_evidence,
            functions=unprotected_functions or None,
        ))
    if "single-feed" in oracle_evidence:
        if not re.search(r"\bupdatedAt\b[^;]*(?:block\.timestamp|maxDelay|stale|heartbeat)", masked, re.I):
            findings.append(_finding("oracle-staleness", "high", "feed result has no evident freshness bound"))
        if not re.search(r"\bansweredInRound\b", masked):
            findings.append(_finding("oracle-round-validation", "medium", "feed round completeness is not evidently checked"))
        if not re.search(r"\b(?:decimals\s*\(|1e\d+|10\s*\*\*)", masked, re.I):
            findings.append(_finding("oracle-decimal-assumption", "medium", "feed decimal normalization is not evident"))

    flash_callbacks = [fn for fn in functions if re.search(
        r"(?:executeOperation|uniswapV\d+Call|uniswapV\d+FlashCallback|onFlashLoan|receiveFlashLoan)",
        fn["name"], re.I)]
    for fn in flash_callbacks:
        if not re.search(r"\b(?:require|if)\s*\([^;{}]*(?:msg\.sender|initiator)", fn["body"], re.I):
            findings.append(_finding("unauthenticated-flash-callback", "critical",
                                     "flash-loan callback lacks an evident lender/initiator check",
                                     function=fn["name"], line=fn["line"]))

    if re.search(r"\btotalSupply\s*(?:\(\s*\))?\s*==\s*0", masked) and re.search(
            r"\b(?:totalAssets|balanceOf\s*\(\s*address\s*\(\s*this\s*\))", masked, re.I):
        if not re.search(r"\b(?:virtualShares|virtualAssets|MINIMUM_LIQUIDITY|dead\s+shares)", masked, re.I):
            findings.append(_finding("first-depositor-inflation", "high",
                                     "share bootstrap appears donation-sensitive without virtual/dead shares"))

    return {
        "kind": "defi-source-analysis",
        "function_count": len(functions),
        "state_variables": states,
        "call_graph": {name: summary["internal_calls"] for name, summary in sorted(summaries.items())},
        "function_summaries": dict(sorted(summaries.items())),
        "oracle_sources": oracle_evidence,
        "twap_evidence": twap,
        "findings": _sorted(findings),
    }


def _layout_records(layout: Mapping[str, object] | Sequence[Mapping[str, object]]) -> list[dict]:
    if isinstance(layout, Mapping):
        raw = layout.get("storage", [])
        types = layout.get("types", {})
    else:
        raw, types = layout, {}
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValueError("storage layout must contain a storage array")
    records = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        type_id = str(item.get("type", ""))
        type_info = types.get(type_id, {}) if isinstance(types, Mapping) else {}
        records.append({
            "label": str(item.get("label", "")), "slot": str(item.get("slot", "")),
            "offset": int(item.get("offset", 0)), "type": type_id,
            "bytes": int(type_info.get("numberOfBytes", 0)) if isinstance(type_info, Mapping) else 0,
            "contract": str(item.get("contract", "")),
        })
    return records


def compare_storage_layouts(old: Mapping[str, object] | Sequence[Mapping[str, object]],
                            new: Mapping[str, object] | Sequence[Mapping[str, object]]) -> dict:
    """Compare supplied compiler storage-layout artifacts for upgrade collisions."""
    old_records, new_records = _layout_records(old), _layout_records(new)
    old_by_pos = {(item["slot"], item["offset"]): item for item in old_records}
    new_by_pos = {(item["slot"], item["offset"]): item for item in new_records}
    new_by_label = {item["label"]: item for item in new_records}
    findings: list[dict] = []
    for position, before in old_by_pos.items():
        after = new_by_pos.get(position)
        reserved_gap = before["label"].startswith("__gap")
        if after and before["type"] != after["type"] and not reserved_gap:
            findings.append(_finding("storage-type-collision", "critical",
                                     "an occupied slot/offset changes type across implementations", "high",
                                     slot=position[0], offset=position[1], before=before, after=after))
        if after and before["label"] != after["label"] and not reserved_gap:
            findings.append(_finding("storage-replacement", "high",
                                     "an existing storage position is assigned to a different variable", "high",
                                     slot=position[0], offset=position[1], before=before, after=after))
        moved = new_by_label.get(before["label"])
        if moved and (moved["slot"], moved["offset"]) != position and not reserved_gap:
            findings.append(_finding("storage-variable-moved", "critical",
                                     "an existing variable moved to a different storage position", "high",
                                     variable=before["label"], before=before, after=moved))
        if not after and before["label"] not in new_by_label and not reserved_gap:
            findings.append(_finding("storage-variable-removed", "high",
                                     "an existing storage variable is absent in the new layout", "high",
                                     variable=before["label"], before=before))
    max_old_slot = max((int(item["slot"], 0) for item in old_records if item["slot"]), default=-1)
    inserted = [item for item in new_records if (item["slot"], item["offset"]) not in old_by_pos
                and item["slot"] and int(item["slot"], 0) <= max_old_slot
                and not item["label"].startswith("__gap")]
    if inserted:
        findings.append(_finding("storage-inserted-before-tail", "high",
                                 "new variables occupy positions within the prior layout span",
                                 variables=inserted))
    return {"kind": "storage-layout-comparison", "old": old_records, "new": new_records,
            "compatible": not any(item["severity"] in {"critical", "high"} for item in findings),
            "findings": _sorted(findings)}


def _trace_children(node: Mapping[str, object]) -> list[Mapping[str, object]]:
    children = node.get("calls", node.get("children", []))
    return [item for item in children if isinstance(item, Mapping)] if isinstance(children, Sequence) else []


def analyze_call_trace(trace: Mapping[str, object] | Sequence[Mapping[str, object]]) -> dict:
    """Analyze supplied callTracer-like trees or semantic event sequences."""
    roots = [trace] if isinstance(trace, Mapping) else list(trace)
    findings: list[dict] = []
    flattened: list[dict] = []
    count = 0

    def visit(node: Mapping[str, object], ancestors: list[dict], path: list[int], active: set[int]) -> None:
        nonlocal count
        if len(path) > MAX_NESTING:
            raise ValueError("trace nesting exceeds cap")
        identity = id(node)
        if identity in active:
            raise ValueError("cyclic trace structure")
        count += 1
        if count > MAX_TRACE_NODES:
            raise ValueError("trace exceeds node cap")
        address = str(node.get("to", node.get("contract", ""))).lower()
        function = str(node.get("function", node.get("method", "")))
        input_data = str(node.get("input", ""))
        selector = input_data[:10].lower() if input_data.startswith("0x") and len(input_data) >= 10 else ""
        record = {"path": path, "from": str(node.get("from", "")).lower(), "to": address,
                  "function": function, "selector": selector,
                  "type": str(node.get("type", node.get("op", "CALL"))).upper()}
        flattened.append(record)
        for ancestor in ancestors:
            same_target = address and address == ancestor["to"]
            same_entry = (function and function == ancestor["function"]) or (selector and selector == ancestor["selector"])
            if same_target and same_entry:
                findings.append(_finding("observed-reentrant-call", "critical",
                                         "call trace re-enters the same contract entry point before return", "high",
                                         chain=[item["to"] + ":" + (item["function"] or item["selector"])
                                                for item in ancestors + [record]], path=path))
                break
        active.add(identity)
        try:
            for index, child in enumerate(_trace_children(node)):
                visit(child, ancestors + [record], path + [index], active)
        finally:
            active.remove(identity)

    for index, root in enumerate(roots):
        if not isinstance(root, Mapping):
            continue
        visit(root, [], [index], set())

    # Semantic traces may label oracle writes/reads and trades.  Report only observed order.
    oracle_updates = [index for index, node in enumerate(roots) if isinstance(node, Mapping)
                      and str(node.get("op", "")).lower() in {"oracle_update", "price_update"}]
    trades = [index for index, node in enumerate(roots) if isinstance(node, Mapping)
              and str(node.get("op", "")).lower() in {"swap", "borrow", "liquidate", "mint", "redeem"}]
    if oracle_updates and trades and min(trades) > min(oracle_updates):
        findings.append(_finding("observed-oracle-update-then-action", "high",
                                 "trace records an oracle update immediately preceding a price-sensitive action",
                                 "high", oracle_index=min(oracle_updates), action_index=min(trades)))
    return {"kind": "defi-call-trace", "node_count": count, "calls": flattened,
            "findings": _sorted(findings)}


def analyze_price_observations(observations: Sequence[Mapping[str, object]], threshold: float = 0.25) -> dict:
    """Flag abrupt supplied price observations without fetching market data."""
    if not math.isfinite(threshold) or not 0 < threshold:
        raise ValueError("threshold must be positive")
    values = []
    normalized = []
    for index, item in enumerate(observations):
        if not isinstance(item, Mapping):
            raise ValueError("each observation must be an object")
        try:
            value = float(item["price"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("each observation must contain a numeric price") from error
        if not math.isfinite(value) or value <= 0:
            raise ValueError("prices must be positive")
        values.append(value)
        normalized.append({"index": index, "price": value, "block": item.get("block"),
                           "source": item.get("source")})
    median = statistics.median(values) if values else None
    findings = []
    if median:
        for item in normalized:
            deviation = abs(item["price"] - median) / median
            if deviation >= threshold:
                findings.append(_finding("price-outlier", "high",
                                         "observation deviates materially from the supplied-series median", "high",
                                         index=item["index"], price=item["price"], median=median,
                                         deviation=round(deviation, 12), source=item["source"]))
    for previous, current in zip(normalized, normalized[1:]):
        change = abs(current["price"] - previous["price"]) / previous["price"]
        if change >= threshold:
            findings.append(_finding("abrupt-price-change", "high",
                                     "adjacent supplied observations show a material price jump", "high",
                                     before=previous, after=current, change=round(change, 12)))
    return {"kind": "price-observation-analysis", "count": len(normalized), "median": median,
            "threshold": threshold, "findings": _sorted(findings)}


def analyze_artifact(data: bytes, name: str = "artifact") -> dict:
    if len(data) > MAX_INPUT:
        raise ValueError("artifact exceeds input cap")
    suffix = Path(name).suffix.lower()
    if suffix in {".sol", ".vy"}:
        return analyze_defi_source(data.decode("utf-8", "replace"))
    try:
        parsed = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return analyze_defi_source(data.decode("utf-8", "replace"))
    if isinstance(parsed, Mapping) and "old" in parsed and "new" in parsed:
        return compare_storage_layouts(parsed["old"], parsed["new"])
    if isinstance(parsed, Mapping) and ("calls" in parsed or "to" in parsed):
        return analyze_call_trace(parsed)
    if isinstance(parsed, Sequence) and parsed and isinstance(parsed[0], Mapping):
        if "price" in parsed[0]:
            return analyze_price_observations(parsed)
        return analyze_call_trace(parsed)
    raise ValueError("unrecognized DeFi artifact")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="supplied Solidity/JSON artifact")
    args = parser.parse_args(argv)
    data = args.artifact.read_bytes()
    print(json.dumps(analyze_artifact(data, args.artifact.name), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
