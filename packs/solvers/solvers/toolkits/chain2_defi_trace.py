#!/usr/bin/env python3
"""Strict offline DeFi selector and supplied-call-trace analysis.

This module fills a narrow gap left by the generic EVM and source analyzers: it
classifies protocol selectors in already-supplied bytecode/callTracer trees and
reports observed callback/reentry structure and ordered economic-pattern evidence.
It never contacts a node, executes bytecode, or treats a heuristic as proof of an
exploit.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any

import evm_audit


MAX_BYTECODE = 4 * 1024 * 1024
MAX_JSON = 32 * 1024 * 1024
MAX_TRACE_NODES = 100_000
MAX_TRACE_DEPTH = 128
MAX_CHILDREN = 50_000
MAX_CUSTOM_SELECTORS = 1_024
MAX_FINDINGS = 2_000


class Chain2DeFiError(ValueError):
    """The supplied offline DeFi artifact is malformed, ambiguous, or over-limit."""


_CATALOG = {
    # Loan entry points.
    "5cffe9de": ("erc3156.flashLoan", "flash-loan"),
    "42b0b77c": ("aave-v3.flashLoanSimple", "flash-loan"),
    "ab9c4b5d": ("aave-v3.flashLoan", "flash-loan"),
    # Callback surfaces.  Presence is composability evidence, not a vulnerability.
    "23e30c8b": ("erc3156.onFlashLoan", "flash-callback"),
    "10d1e85c": ("uniswap-v2.uniswapV2Call", "flash-callback"),
    "e9cbafb0": ("uniswap-v3.uniswapV3FlashCallback", "flash-callback"),
    "fa461e33": ("uniswap-v3.uniswapV3SwapCallback", "flash-callback"),
    "1b11d0ff": ("aave-v3.executeOperation-simple", "flash-callback"),
    "920f5c84": ("aave-v3.executeOperation-multi", "flash-callback"),
    "0023de29": ("erc777.tokensReceived", "token-callback"),
    # Pool-changing actions.
    "022c0d9f": ("uniswap-v2.swap", "pool-mutation"),
    "128acb08": ("uniswap-v3.swap", "pool-mutation"),
    "fff6cae9": ("uniswap-v2.sync", "pool-mutation"),
    "bc25cf77": ("uniswap-v2.skim", "pool-mutation"),
    # Direct spot state, router quotes, external feeds, and a TWAP signal.
    "0902f1ac": ("uniswap-v2.getReserves", "pool-spot-read"),
    "3850c7bd": ("uniswap-v3.slot0", "pool-spot-read"),
    "d06ca61f": ("router.getAmountsOut", "quote-read"),
    "feaf968c": ("chainlink.latestRoundData", "oracle-read"),
    "50d25bcd": ("chainlink.latestAnswer", "oracle-read"),
    "883bdbfd": ("uniswap-v3.observe", "twap-read"),
    # Common price-sensitive consumers.  These are deliberately candidates only:
    # selector collisions and protocol-specific semantics still need human review.
    "d0e30db0": ("vault.deposit()", "sensitive-action"),
    "b6b55f25": ("vault.deposit(uint256)", "sensitive-action"),
    "6e553f65": ("erc4626.deposit", "sensitive-action"),
    "40c10f19": ("token.mint(address,uint256)", "sensitive-action"),
    "94bf804d": ("erc4626.mint", "sensitive-action"),
    "a0712d68": ("vault.mint(uint256)", "sensitive-action"),
    "c5ebeaec": ("lending.borrow(uint256)", "sensitive-action"),
    "a415bcad": ("aave.borrow", "sensitive-action"),
    "db006a75": ("vault.redeem(uint256)", "sensitive-action"),
    "ba087652": ("erc4626.redeem", "sensitive-action"),
    "2e1a7d4d": ("vault.withdraw(uint256)", "sensitive-action"),
    "b460af94": ("erc4626.withdraw", "sensitive-action"),
    "f5e3c462": ("compound.liquidateBorrow", "sensitive-action"),
    "00a718a9": ("aave.liquidationCall", "sensitive-action"),
    # Repayment anchors are recorded but are not required for a candidate.
    "573ade81": ("aave.repay", "repayment"),
    "0e752702": ("compound.repayBorrow", "repayment"),
}

SELECTOR_CATALOG = MappingProxyType({
    selector: MappingProxyType({"name": name, "category": category})
    for selector, (name, category) in sorted(_CATALOG.items())
})

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_HEX_DATA = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
_HEX_QUANTITY = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\Z")
_CALL_TYPES = {"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"}
_CREATE_TYPES = {"CREATE", "CREATE2"}


def _selector(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise Chain2DeFiError(f"{label} must be a four-byte hexadecimal selector")
    compact = value[2:] if value.startswith(("0x", "0X")) else value
    if not re.fullmatch(r"[0-9a-fA-F]{8}", compact):
        raise Chain2DeFiError(f"{label} must be a four-byte hexadecimal selector")
    return compact.lower()


def _selector_set(values: object) -> set[str]:
    if values is None:
        return set()
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Iterable):
        raise Chain2DeFiError("sensitive_selectors must be a bounded iterable")
    result: set[str] = set()
    for index, value in enumerate(values):
        if index >= MAX_CUSTOM_SELECTORS:
            raise Chain2DeFiError("sensitive selector list exceeds cap")
        result.add(_selector(value, label=f"sensitive_selectors[{index}]"))
    return result


def _address(value: object, *, label: str, optional: bool = False) -> str | None:
    if optional and value in (None, ""):
        return None
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        raise Chain2DeFiError(f"{label} must be a 20-byte 0x-prefixed address")
    return value.lower()


def _address_set(values: object) -> set[str] | None:
    if values is None:
        return None
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Iterable):
        raise Chain2DeFiError("pool_addresses must be a bounded iterable")
    result: set[str] = set()
    for index, value in enumerate(values):
        if index >= MAX_CUSTOM_SELECTORS:
            raise Chain2DeFiError("pool address list exceeds cap")
        normalized = _address(value, label=f"pool_addresses[{index}]")
        assert normalized is not None
        result.add(normalized)
    return result


def _finding(kind: str, severity: str, confidence: str, message: str, **evidence: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "kind": kind,
        "severity": severity,
        "confidence": confidence,
        "message": message,
        "exploit_verified": False,
        "requires_human_review": True,
    }
    result.update(evidence)
    return result


def analyze_bytecode(value: bytes | bytearray | str) -> dict[str, Any]:
    """Catalog known DeFi selectors at real ``PUSH4`` instruction boundaries.

    A dispatch-table hit is stronger interface evidence than a bare constant.  A
    constant remains only possible capability evidence; neither proves reachability
    or exploitability.
    """
    try:
        if isinstance(value, str):
            compact = re.sub(r"\s+", "", value)
            if compact.startswith(("0x", "0X")):
                compact = compact[2:]
            if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
                raise Chain2DeFiError("bytecode text must be nonempty even-length hexadecimal")
            if len(compact) // 2 > MAX_BYTECODE:
                raise Chain2DeFiError("bytecode exceeds size cap")
        elif isinstance(value, (bytes, bytearray)):
            if not value or len(value) > MAX_BYTECODE:
                raise Chain2DeFiError("bytecode must contain 1..4 MiB bytes")
        else:
            raise Chain2DeFiError("bytecode must be bytes or hexadecimal text")

        instructions = evm_audit.disassemble(value)
        if not instructions:
            raise Chain2DeFiError("bytecode contains no instructions")
        if any(bool(row.get("truncated")) for row in instructions):
            raise Chain2DeFiError("truncated PUSH immediate")
        dispatched = {
            (str(row["selector"])[2:].lower(), int(row["offset"]))
            for row in evm_audit.function_selectors(instructions)
        }
        occurrences: list[dict[str, Any]] = []
        for row in instructions:
            if row.get("name") != "PUSH4":
                continue
            selector = str(row.get("immediate", "")).lower()
            if selector not in _CATALOG:
                continue
            name, category = _CATALOG[selector]
            is_dispatch = (selector, int(row["offset"])) in dispatched
            occurrences.append({
                "pc": int(row["offset"]),
                "selector": "0x" + selector,
                "name": name,
                "category": category,
                "evidence": "dispatcher" if is_dispatch else "push4-constant",
                "interface_capability_only": True,
            })
        return {
            "kind": "defi-bytecode-selector-catalog",
            "byte_length": (len(bytes(value)) if isinstance(value, (bytes, bytearray))
                            else len(re.sub(r"\s+", "", value).removeprefix("0x").removeprefix("0X")) // 2),
            "instruction_count": len(instructions),
            "selector_occurrences": occurrences,
            "categories": sorted({row["category"] for row in occurrences}),
            "finding_semantics": "catalog evidence only; reachability and exploitability are not established",
        }
    except Chain2DeFiError:
        raise
    except (TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError, MemoryError) as exc:
        raise Chain2DeFiError(f"invalid bytecode artifact: {exc}") from exc


def _quantity(value: object, *, label: str) -> None:
    if isinstance(value, bool):
        raise Chain2DeFiError(f"{label} must be a nonnegative quantity")
    if isinstance(value, int):
        if value < 0:
            raise Chain2DeFiError(f"{label} must be a nonnegative quantity")
        return
    if isinstance(value, str) and _HEX_QUANTITY.fullmatch(value):
        return
    raise Chain2DeFiError(f"{label} must be an integer or canonical hexadecimal quantity")


def _normalize_frame(node: Mapping[str, object], *, path: tuple[int, ...],
                     parent_context: str | None, inherited_static: bool) -> dict[str, Any]:
    type_value = node.get("type")
    if not isinstance(type_value, str):
        raise Chain2DeFiError(f"frame {path} requires a call type")
    call_type = type_value.upper()
    if call_type not in _CALL_TYPES | _CREATE_TYPES:
        raise Chain2DeFiError(f"frame {path} has unsupported call type {call_type!r}")
    sender = _address(node.get("from"), label=f"frame {path} from")
    target = _address(node.get("to"), label=f"frame {path} to",
                      optional=call_type in _CREATE_TYPES)
    raw_input = node.get("input", "0x")
    if not isinstance(raw_input, str) or not _HEX_DATA.fullmatch(raw_input):
        raise Chain2DeFiError(f"frame {path} input must be even-length 0x-prefixed hexadecimal")
    raw_input = raw_input.lower()
    for key in ("gas", "gasUsed", "value"):
        if key in node:
            _quantity(node[key], label=f"frame {path} {key}")
    for key in ("error", "revertReason"):
        if key in node and not isinstance(node[key], str):
            raise Chain2DeFiError(f"frame {path} {key} must be text")
    children = node.get("calls", [])
    if not isinstance(children, Sequence) or isinstance(children, (str, bytes, bytearray)):
        raise Chain2DeFiError(f"frame {path} calls must be an array")
    if len(children) > MAX_CHILDREN:
        raise Chain2DeFiError(f"frame {path} child count exceeds cap")
    if any(not isinstance(child, Mapping) for child in children):
        raise Chain2DeFiError(f"frame {path} contains a non-object child")
    if call_type in {"DELEGATECALL", "CALLCODE"}:
        context = parent_context if parent_context is not None else sender
    else:
        context = target
    selector = raw_input[2:10] if len(raw_input) >= 10 else None
    catalog = _CATALOG.get(selector) if selector is not None else None
    return {
        "path": list(path),
        "type": call_type,
        "from": sender,
        "to": target,
        "execution_context": context,
        "input": raw_input,
        "selector": "0x" + selector if selector is not None else None,
        "selector_hex": selector,
        "catalog_name": catalog[0] if catalog else None,
        "category": catalog[1] if catalog else None,
        "static_context": inherited_static or call_type == "STATICCALL",
        "failed": "error" in node,
        "children": list(children),
    }


def analyze_call_trace(
    trace: Mapping[str, object] | Sequence[Mapping[str, object]],
    *,
    sensitive_selectors: Iterable[str] | None = None,
    pool_addresses: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Analyze a bounded supplied Geth callTracer tree in deterministic entry order.

    ``sensitive_selectors`` augments the built-in candidate catalog.  When
    ``pool_addresses`` is supplied, manipulation correlation is restricted to those
    caller-selected pools.  No address is inferred from a live chain.
    """
    try:
        custom_sensitive = _selector_set(sensitive_selectors)
        pools = _address_set(pool_addresses)
        if isinstance(trace, Mapping):
            roots: list[Mapping[str, object]] = [trace]
        elif (isinstance(trace, Sequence)
              and not isinstance(trace, (str, bytes, bytearray))):
            if len(trace) > MAX_CHILDREN or any(not isinstance(root, Mapping) for root in trace):
                raise Chain2DeFiError("trace roots must be a bounded array of objects")
            roots = list(trace)
        else:
            raise Chain2DeFiError("trace must be an object or bounded array of objects")
        if not roots:
            raise Chain2DeFiError("trace must contain at least one root")

        records: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        active: set[int] = set()

        def visit(node: Mapping[str, object], path: tuple[int, ...], ancestors: list[dict[str, Any]],
                  parent_context: str | None, inherited_static: bool) -> None:
            if len(path) > MAX_TRACE_DEPTH:
                raise Chain2DeFiError("trace nesting exceeds cap")
            identity = id(node)
            if identity in active:
                raise Chain2DeFiError("trace contains a cyclic object graph")
            if len(records) >= MAX_TRACE_NODES:
                raise Chain2DeFiError("trace node count exceeds cap")
            record = _normalize_frame(node, path=path, parent_context=parent_context,
                                      inherited_static=inherited_static)
            record["index"] = len(records)
            children = record.pop("children")
            records.append(record)

            # DELEGATECALL/CALLCODE inherit an execution context and are not by
            # themselves callbacks into it.  A descendant CALL back to that context
            # is still detected against the active path.
            if record["type"] in {"CALL", "STATICCALL"} and record["execution_context"]:
                matching = [ancestor for ancestor in ancestors
                            if ancestor["execution_context"] == record["execution_context"]]
                if matching:
                    same = next((ancestor for ancestor in reversed(matching)
                                 if record["selector"] is not None
                                 and ancestor["selector"] == record["selector"]), None)
                    prior = same or matching[-1]
                    style = "same-entry" if same is not None else "cross-function"
                    read_only = bool(record["static_context"])
                    kind = ("observed-read-only-reentrancy" if read_only else
                            f"observed-{style}-reentrancy")
                    findings.append(_finding(
                        kind, "high" if read_only or style == "cross-function" else "critical", "high",
                        "active execution context is entered again before its older frame returns",
                        style=style, read_only=read_only, context=record["execution_context"],
                        prior_path=prior["path"], path=record["path"],
                        prior_selector=prior["selector"], selector=record["selector"],
                        structural_evidence_verified=True,
                    ))

            active.add(identity)
            try:
                for child_index, child in enumerate(children):
                    visit(child, path + (child_index,), ancestors + [record],
                          record["execution_context"], bool(record["static_context"]))
            finally:
                active.remove(identity)

        for root_index, root in enumerate(roots):
            visit(root, (root_index,), [], None, False)

        # Reverted frames are useful trace facts, but cannot establish a completed
        # economic step. Keep them in ``calls`` while excluding them from the
        # manipulation ordering candidate.
        flash = [row for row in records
                 if not row["failed"] and row["category"] in {"flash-loan", "flash-callback"}]
        mutations = [row for row in records if row["category"] == "pool-mutation"
                     and not row["failed"] and (pools is None or row["to"] in pools)]
        spot_reads = [row for row in records if row["category"] == "pool-spot-read"
                      and not row["failed"] and (pools is None or row["to"] in pools)]
        sensitive = [row for row in records
                     if not row["failed"] and (row["category"] == "sensitive-action"
                                                or row["selector_hex"] in custom_sensitive)]
        twap = [row for row in records if not row["failed"] and row["category"] == "twap-read"]
        repayments = [row for row in records if not row["failed"] and row["category"] == "repayment"]

        if flash:
            findings.append(_finding(
                "observed-flash-composition", "info", "high",
                "supplied trace enters a known flash-loan or callback selector",
                call_indices=[row["index"] for row in flash],
                selectors=[row["selector"] for row in flash],
                structural_evidence_verified=True,
            ))

        candidates = 0
        for mutation in mutations:
            prior_flash = next((row for row in reversed(flash) if row["index"] < mutation["index"]), None)
            if prior_flash is None or mutation["to"] is None:
                continue
            read = next((row for row in spot_reads
                         if row["index"] > mutation["index"] and row["to"] == mutation["to"]), None)
            if read is None:
                continue
            action = next((row for row in sensitive if row["index"] > read["index"]), None)
            if action is None:
                continue
            reverse = next((row for row in mutations
                            if row["index"] > action["index"] and row["to"] == mutation["to"]), None)
            repayment = next((row for row in repayments if row["index"] > action["index"]), None)
            findings.append(_finding(
                "flash-price-manipulation-candidate", "critical", "medium",
                "trace entry order shows flash composition, a pool mutation, a same-pool spot read, and a price-sensitive action",
                pool=mutation["to"],
                steps={
                    "flash": {"index": prior_flash["index"], "selector": prior_flash["selector"]},
                    "mutation": {"index": mutation["index"], "selector": mutation["selector"]},
                    "spot_read": {"index": read["index"], "selector": read["selector"]},
                    "sensitive_action": {"index": action["index"], "selector": action["selector"],
                                         "custom": action["selector_hex"] in custom_sensitive},
                    "reverse_mutation": ({"index": reverse["index"], "selector": reverse["selector"]}
                                         if reverse else None),
                    "repayment": ({"index": repayment["index"], "selector": repayment["selector"]}
                                  if repayment else None),
                },
                same_pool_correlation_verified=True,
                ordered_entry_evidence_verified=True,
            ))
            candidates += 1
            if candidates >= 256 or len(findings) >= MAX_FINDINGS:
                break

        if twap:
            findings.append(_finding(
                "observed-twap-read", "info", "high",
                "supplied trace calls a TWAP observation interface; this is mitigation evidence, not proof of safety",
                call_indices=[row["index"] for row in twap],
                structural_evidence_verified=True,
            ))

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        findings.sort(key=lambda row: (-severity_order.get(str(row["severity"]), -1),
                                       str(row["kind"]), str(row.get("path", ""))))
        public_records = [{key: value for key, value in row.items() if key != "selector_hex"}
                          for row in records]
        return {
            "kind": "defi-call-trace-analysis",
            "node_count": len(records),
            "calls": public_records,
            "catalog_hits": [row for row in public_records if row["catalog_name"] is not None],
            "findings": findings[:MAX_FINDINGS],
            "pool_filter": sorted(pools) if pools is not None else None,
            "custom_sensitive_selectors": ["0x" + value for value in sorted(custom_sensitive)],
            "order_semantics": "depth-first call entry order; values and successful repayment are not inferred",
        }
    except Chain2DeFiError:
        raise
    except (TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError, MemoryError) as exc:
        raise Chain2DeFiError(f"invalid call trace: {exc}") from exc


def analyze_artifact(
    data: bytes,
    mode: str,
    *,
    sensitive_selectors: Iterable[str] | None = None,
    pool_addresses: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Analyze supplied bytes as explicit ``bytecode`` or ``trace`` input."""
    try:
        if not isinstance(data, bytes):
            raise Chain2DeFiError("artifact must be immutable bytes")
        if len(data) > MAX_JSON:
            raise Chain2DeFiError("artifact exceeds size cap")
        if mode == "bytecode":
            stripped = data.strip()
            if re.fullmatch(rb"(?:0[xX])?[0-9a-fA-F\s]+", stripped):
                return analyze_bytecode(stripped.decode("ascii"))
            return analyze_bytecode(data)
        if mode == "trace":
            try:
                parsed = json.loads(data)
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                raise Chain2DeFiError("trace artifact must be valid JSON") from exc
            return analyze_call_trace(parsed, sensitive_selectors=sensitive_selectors,
                                      pool_addresses=pool_addresses)
        raise Chain2DeFiError("mode must be 'bytecode' or 'trace'")
    except Chain2DeFiError:
        raise
    except (TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError, MemoryError) as exc:
        raise Chain2DeFiError(f"invalid artifact: {exc}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="strict offline DeFi selector/call-trace evidence")
    parser.add_argument("mode", choices=("bytecode", "trace"))
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--sensitive-selector", action="append", default=[])
    parser.add_argument("--pool", action="append", default=[])
    parser.add_argument("--pretty", action="store_true")
    try:
        args = parser.parse_args(argv)
        result = analyze_artifact(
            args.artifact.read_bytes(), args.mode,
            sensitive_selectors=args.sensitive_selector,
            pool_addresses=args.pool or None,
        )
        print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (OSError, Chain2DeFiError) as exc:
        print(f"chain2_defi_trace: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
