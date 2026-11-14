#!/usr/bin/env python3
"""Offline Solidity/EVM vulnerability evidence and storage-layout comparison.

This engine never deploys, calls, signs, simulates, or opens RPC. Exact observations are separated
from vulnerability verdicts: heuristic findings always retain ``vulnerability_verified=False``.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
MAX_CODE = 4 << 20
MAX_SOURCE = 8 << 20
MAX_LAYOUT = 100_000


def _load_blockchain():
    name = "csctf_blockchain_for_evm_security"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HERE / "blockchain.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("blockchain disassembler unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


chain = _load_blockchain()
TERMINATORS = {"STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT", "JUMP"}
CALLS = {"CALL", "CALLCODE", "DELEGATECALL"}
_KECCAK_IMPL = chain.keccak(b"eip1967.proxy.implementation")
_KECCAK_ADMIN = chain.keccak(b"eip1967.proxy.admin")
EIP1967_IMPLEMENTATION = int.from_bytes(_KECCAK_IMPL, "big") - 1 if _KECCAK_IMPL else None
EIP1967_ADMIN = int.from_bytes(_KECCAK_ADMIN, "big") - 1 if _KECCAK_ADMIN else None


def _finding(kind: str, score: int, pc: int | None, evidence: Any, reason: str,
             *, exact: bool = True) -> dict[str, Any]:
    return {"kind": kind, "score": int(score), "pc": pc, "evidence": evidence, "reason": reason,
            "evidence_verified": bool(exact), "vulnerability_verified": False,
            "requires_human_review": True}


def _basic_block_after(instructions, index: int, limit: int = 64):
    rows = []
    for row in instructions[index + 1:index + 1 + limit]:
        if row[2] == "JUMPDEST":
            break
        rows.append(row)
        if row[2] in TERMINATORS or row[2] == "JUMPI":
            break
    return rows


def analyze_bytecode(code: bytes) -> dict[str, Any]:
    """Return exact opcode facts plus conservative vulnerability candidates."""
    if not isinstance(code, bytes) or not code or len(code) > MAX_CODE:
        raise ValueError("bytecode must be 1..4 MiB bytes")
    instructions = chain.disassemble(code)
    if not instructions or len(instructions) >= chain.MAX_INSNS:
        raise ValueError("bytecode instruction cap reached")
    findings = []
    for index, (pc, opcode, name, push) in enumerate(instructions):
        del opcode, push
        after = _basic_block_after(instructions, index)
        names = [row[2] for row in after]
        if name == "ORIGIN":
            auth = "EQ" in names[:8] and "JUMPI" in names[:14]
            findings.append(_finding("tx-origin-auth" if auth else "tx-origin-use", 96 if auth else 65,
                                     pc, names[:14], "ORIGIN participates in a nearby comparison/branch"
                                     if auth else "ORIGIN opcode is present"))
        if name in CALLS:
            findings.append(_finding("delegatecall" if name == "DELEGATECALL" else "external-call",
                                     82 if name == "DELEGATECALL" else 55, pc, name,
                                     "low-level external execution opcode is present"))
            if "SSTORE" in names:
                findings.append(_finding("reentrancy-order-candidate", 90, pc,
                                         {"call": name, "later_sstore_pc": after[names.index("SSTORE")][0]},
                                         "external call precedes a state write in the same basic block"))
            if not any(row[2] in {"ISZERO", "JUMPI", "REVERT"} for row in after[:8]):
                findings.append(_finding("unchecked-call-result", 75, pc, names[:8],
                                         "no nearby branch/revert consumes the low-level call result"))
        if name == "SELFDESTRUCT":
            findings.append(_finding("selfdestruct", 92, pc, name,
                                     "SELFDESTRUCT is present; authorization/fork semantics need review"))
        if name == "SSTORE":
            before = instructions[max(0, index - 14):index]
            if any(row[2] == "CALLDATALOAD" for row in before):
                findings.append(_finding("calldata-to-storage-candidate", 70, pc,
                                         [row[2] for row in before],
                                         "CALLDATALOAD occurs near SSTORE; exact stack flow is not proven"))
        if name in {"TIMESTAMP", "NUMBER", "PREVRANDAO", "BLOCKHASH"} and any(
                row[2] in {"EQ", "LT", "GT", "SLT", "SGT", "MOD"} for row in after[:10]):
            findings.append(_finding("block-value-control-candidate", 62, pc, name,
                                     "block-controlled value participates in nearby comparison/arithmetic"))
        if name in {"ADD", "SUB", "MUL"} and not any(
                row[2] in {"LT", "GT", "SLT", "SGT", "JUMPI", "REVERT"} for row in after[:10]):
            findings.append(_finding("unchecked-arithmetic-candidate", 35, pc, name,
                                     "no local check pattern; compiler version and data flow are unknown"))
    known_slots = {slot for slot in (EIP1967_IMPLEMENTATION, EIP1967_ADMIN) if slot is not None}
    for pc, op, _name, data in instructions:
        if op == 0x7F and data is not None and int.from_bytes(data, "big") in known_slots:
            findings.append(_finding("eip1967-slot", 45, pc, data.hex(),
                                     "standard proxy storage slot observed; not itself a vulnerability"))
    findings.sort(key=lambda row: (-row["score"], row["pc"] if row["pc"] is not None else -1,
                                   row["kind"]))
    report = chain.bytecode_report(code)
    return {"length": len(code), "instruction_count": len(instructions),
            "selectors": (report or {}).get("selectors", []), "solc": (report or {}).get("solc"),
            "findings": findings[:2000], "vulnerability_verdict": None}


def _mask_solidity(source: str) -> str:
    """Blank comments and quoted strings while preserving offsets/newlines."""
    out, i, n = list(source), 0, len(source)
    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i + 2); end = n if end < 0 else end
            for j in range(i, end): out[j] = " "
            i = end
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2); end = n if end < 0 else min(n, end + 2)
            for j in range(i, end):
                if out[j] != "\n": out[j] = " "
            i = end
        elif source[i] in "'\"":
            quote, end = source[i], i + 1
            while end < n:
                if source[end] == "\\": end += 2; continue
                if source[end] == quote: end += 1; break
                end += 1
            for j in range(i, min(end, n)):
                if out[j] != "\n": out[j] = " "
            i = end
        else:
            i += 1
    return "".join(out)


SOURCE_PATTERNS = (
    ("delegatecall", 84, re.compile(r"\.\s*delegatecall\s*\("), "delegatecall target/layout need review"),
    ("value-call", 75, re.compile(r"\.\s*call\s*\{[^}]{0,500}\bvalue\s*:"), "value-bearing call is present"),
    ("selfdestruct", 92, re.compile(r"\b(?:selfdestruct|suicide)\s*\("), "destruction primitive is present"),
    ("unchecked-block", 50, re.compile(r"\bunchecked\s*\{"), "unchecked arithmetic block is present"),
    ("timestamp-dependence", 55, re.compile(r"\b(?:block\s*\.\s*timestamp|now)\b"), "timestamp is used"),
    ("assembly", 45, re.compile(r"\bassembly\s*\{"), "inline assembly is present"),
)
TX_ORIGIN = re.compile(r"\btx\s*\.\s*origin\b")
TX_ORIGIN_COMPARISON = re.compile(
    r"(?:\btx\s*\.\s*origin\b\s*(?:==|!=)|(?:==|!=)\s*\btx\s*\.\s*origin\b)")


def analyze_source(source: str) -> dict[str, Any]:
    if not isinstance(source, str) or len(source.encode("utf-8", "surrogatepass")) > MAX_SOURCE:
        raise ValueError("Solidity source exceeds 8 MiB cap")
    masked, findings = _mask_solidity(source), []
    auth_spans = [match.span() for match in TX_ORIGIN_COMPARISON.finditer(masked)]
    for match in TX_ORIGIN.finditer(masked):
        auth = any(start <= match.start() < end for start, end in auth_spans)
        findings.append(_finding(
            "tx-origin-auth" if auth else "tx-origin-use", 96 if auth else 65, None,
            {"line": source.count("\n", 0, match.start()) + 1, "text": match.group(0)},
            "tx.origin participates in an equality/inequality comparison; inspect authorization"
            if auth else "tx.origin is present, but no authorization comparison is established"))
    for kind, score, pattern, reason in SOURCE_PATTERNS:
        for match in pattern.finditer(masked):
            findings.append(_finding(kind, score, None,
                                     {"line": source.count("\n", 0, match.start()) + 1,
                                      "text": match.group(0)}, reason))
            if len(findings) >= 2000: break
    for match in re.finditer(r"\.\s*call(?:\s*\{[^}]{0,500}\})?\s*\([^;]{0,2000};", masked):
        tail = masked[match.end():match.end() + 2000]
        if re.search(r"\b[A-Za-z_]\w*\s*(?:\[[^]]+\])?\s*(?:=|\+=|-=)", tail):
            findings.append(_finding("source-reentrancy-order-candidate", 72, None,
                                     {"line": source.count("\n", 0, match.start()) + 1},
                                     "low-level call precedes assignment in a lexical window", exact=False))
    findings.sort(key=lambda row: (-row["score"], row["evidence"].get("line", 0)))
    return {"findings": findings, "vulnerability_verdict": None,
            "source_bytes": len(source.encode("utf-8", "surrogatepass"))}


def _layout_entries(value: Any, side: str) -> list[dict[str, Any]]:
    if isinstance(value, dict): value = value.get("storage", value.get("layout", value.get("entries")))
    if not isinstance(value, list) or len(value) > MAX_LAYOUT:
        raise ValueError(f"{side} layout must be a bounded list")
    rows = []
    for index, row in enumerate(value):
        if not isinstance(row, dict): raise ValueError(f"{side} layout entry {index} is not an object")
        try:
            slot = int(str(row.get("slot", "")), 0); offset = int(row.get("offset", 0))
            size = int(row.get("bytes", row.get("size", 32)))
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"invalid {side} layout coordinates") from exc
        if slot < 0 or not 0 <= offset < 32 or not 1 <= size <= 32 or offset + size > 32:
            raise ValueError(f"invalid {side} layout range")
        rows.append({"label": str(row.get("label", row.get("name", f"{side}[{index}]")))[:256],
                     "slot": slot, "offset": offset, "bytes": size,
                     "type": str(row.get("type", "unknown"))[:256]})
    return rows


def compare_storage_layout(proxy: Any, implementation: Any) -> dict[str, Any]:
    """Return exact overlapping slot byte ranges; exploitability remains a human judgment."""
    left, right = _layout_entries(proxy, "proxy"), _layout_entries(implementation, "implementation")
    # Index the 32 possible byte positions in each slot.  A naive all-pairs walk is attacker-
    # controlled quadratic work on compiler JSON containing many deliberately duplicated entries.
    occupied: dict[tuple[int, int], list[int]] = {}
    for index, row in enumerate(right):
        for byte in range(row["offset"], row["offset"] + row["bytes"]):
            occupied.setdefault((row["slot"], byte), []).append(index)
    collisions, seen = [], set()
    for a in left:
        candidates = set()
        for byte in range(a["offset"], a["offset"] + a["bytes"]):
            candidates.update(occupied.get((a["slot"], byte), ()))
        for index in sorted(candidates):
            b = right[index]
            key = (id(a), index)
            if key not in seen and (a["label"], a["type"], a["offset"], a["bytes"]) != (
                    b["label"], b["type"], b["offset"], b["bytes"]):
                seen.add(key)
                collisions.append({"slot": a["slot"], "proxy": a, "implementation": b,
                                   "overlap_verified": True, "vulnerability_verified": False,
                                   "requires_human_review": True})
                if len(collisions) >= MAX_LAYOUT:
                    return {"proxy_entries": len(left), "implementation_entries": len(right),
                            "collisions": collisions, "collisions_capped": True, "safe_verdict": None}
    return {"proxy_entries": len(left), "implementation_entries": len(right),
            "collisions": collisions, "collisions_capped": False, "safe_verdict": None}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None: raise ValueError(message)


def _read(path: str, cap: int) -> bytes:
    raw = Path(path).read_bytes()
    if len(raw) > cap: raise ValueError("input exceeds size cap")
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline Solidity/EVM evidence; never calls a chain")
    parser.add_argument("operation", choices=("bytecode", "source", "layout"))
    parser.add_argument("input"); parser.add_argument("second", nargs="?")
    try:
        args = parser.parse_args(argv)
        if args.operation == "bytecode":
            raw = _read(args.input, MAX_CODE).strip()
            if re.fullmatch(rb"(?:0x)?[0-9A-Fa-f]+", raw):
                raw = bytes.fromhex(raw.removeprefix(b"0x").decode())
            result = analyze_bytecode(raw)
        elif args.operation == "source":
            result = analyze_source(_read(args.input, MAX_SOURCE).decode("utf-8", "replace"))
        else:
            if not args.second: raise ValueError("layout requires proxy and implementation JSON files")
            result = compare_storage_layout(json.loads(_read(args.input, MAX_SOURCE)),
                                            json.loads(_read(args.second, MAX_SOURCE)))
        print(json.dumps(result, indent=2, default=str)); return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError,
            RecursionError, MemoryError, OverflowError) as exc:
        print(f"evm_security: {exc}", file=sys.stderr); return 2


if __name__ == "__main__": raise SystemExit(main())
