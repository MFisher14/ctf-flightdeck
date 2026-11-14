#!/usr/bin/env python3
"""Deterministic, offline Solidity and EVM vulnerability triage.

This module never compiles, deploys, emulates, or contacts a chain.  It accepts source
text or already-supplied bytecode and returns evidence-backed static findings.  The
analysis is intentionally conservative: findings distinguish direct opcode/source
evidence from control-flow heuristics and never claim exploitability.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable

MAX_INPUT = 16 * 1024 * 1024
MAX_INSTRUCTIONS = 1_000_000

_SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _finding(kind: str, severity: str, confidence: str, message: str, **evidence) -> dict:
    out = {"kind": kind, "severity": severity, "confidence": confidence, "message": message}
    out.update({key: value for key, value in evidence.items() if value is not None})
    return out


def _sort(findings: Iterable[dict]) -> list[dict]:
    unique: dict[tuple, dict] = {}
    for item in findings:
        key = (item.get("kind"), item.get("offset"), item.get("line"), item.get("function"), item.get("message"))
        unique[key] = item
    return sorted(unique.values(), key=lambda item: (
        -_SEVERITY_ORDER.get(str(item.get("severity")), 0),
        str(item.get("kind")), int(item.get("line", 0)), int(item.get("offset", 0)),
    ))


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def sanitize_solidity(text: str) -> str:
    """Mask comments and quoted strings while preserving length and newlines."""
    out = list(text)
    i, state, quote = 0, "code", ""
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "line"
                continue
            if ch == "/" and nxt == "*":
                out[i] = out[i + 1] = " "
                i += 2
                state = "block"
                continue
            if ch in "'\"":
                quote, state, out[i] = ch, "string", " "
        elif state == "line":
            if ch == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block":
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "code"
                continue
            if ch != "\n":
                out[i] = " "
        else:
            if ch == "\\" and i + 1 < len(text):
                out[i] = " "
                if text[i + 1] != "\n":
                    out[i + 1] = " "
                i += 2
                continue
            if ch == quote:
                state = "code"
            if ch != "\n":
                out[i] = " "
        i += 1
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


_FN_HEAD = re.compile(r"\b(function\s+([A-Za-z_$][\w$]*)|constructor|fallback|receive)\b[^;{]*\{", re.I)


def solidity_functions(masked: str) -> list[dict]:
    """Return balanced function bodies with stable source offsets."""
    out, cursor = [], 0
    while cursor < len(masked):
        match = _FN_HEAD.search(masked, cursor)
        if not match:
            break
        opening = masked.find("{", match.start(), match.end())
        end = _balanced_end(masked, opening)
        if end is None:
            break
        token = match.group(1).lower()
        name = match.group(2) if token.startswith("function") else token
        out.append({"name": name, "start": match.start(), "body_start": opening + 1,
                    "end": end, "header": masked[match.start():opening],
                    "body": masked[opening + 1:end - 1]})
        cursor = end
    return out


_STATE_DECL = re.compile(
    r"(?m)^\s*(?:mapping\s*\([^;]+\)|(?:u?int(?:8|16|32|64|128|256)?|address(?:\s+payable)?|bool|bytes(?:32)?|string)"
    r"(?:\s*\[\s*\])?)\s+(?:(?:public|private|internal|constant|immutable)\s+)*([A-Za-z_$][\w$]*)\b[^;]*;"
)


def _state_variables(masked: str, functions: list[dict]) -> list[str]:
    top = list(masked)
    for fn in functions:
        for index in range(fn["start"], fn["end"]):
            if top[index] != "\n":
                top[index] = " "
    return sorted({match.group(1) for match in _STATE_DECL.finditer("".join(top))})


def _version_tuple(value: str) -> tuple[int, int, int]:
    parts = [int(x) for x in value.split(".")[:3]]
    return tuple((parts + [0, 0, 0])[:3])


def _compiler_overflow_checked(masked: str) -> bool | None:
    match = re.search(r"\bpragma\s+solidity\s+([^;]+);", masked)
    if not match:
        return None
    # A version mentioned only as an upper bound does not establish checked
    # arithmetic: '<0.8.0' exclusively permits unchecked compiler versions.
    # Every alternative must have a lower-bound or exact-version constraint at
    # 0.8.0 or later. This is a conservative proof, not a full semver validator.
    clauses = match.group(1).split("||")
    for clause in clauses:
        terms = list(re.finditer(r"(\^|~|>=|<=|>|<|=)?\s*(\d+\.\d+(?:\.\d+)?)", clause))
        if not terms:
            return None
        if not any(term.group(1) not in ("<", "<=") and _version_tuple(term.group(2)) >= (0, 8, 0)
                   for term in terms):
            return False
    return True


def _has_access_control(header: str, body: str) -> bool:
    return bool(re.search(r"\bonly(?:Owner|Admin|Role|Governance|Proxy|Authorized)\w*\b", header, re.I)
                or re.search(r"\b(?:require|if)\s*\([^;{}]*(?:msg\.sender|_msgSender\(\))\s*(?:==|!=)", body))


# ---- B-243: source sinks for access control and reentrancy beyond the per-primitive checks above.
# All lexical and conservative: a finding names the function and line and never claims exploitability;
# the logic review (is the guard right, is the write reachable) stays the agent's reasoning.

_SENDER_CHECK = re.compile(
    r"(?:msg\.sender|_msgSender\(\)|tx\.origin)\s*(?:==|!=)|(?:==|!=)\s*(?:msg\.sender|_msgSender\(\)|tx\.origin)"
    r"|\b(?:hasRole|_checkOwner|_checkRole|isOwner|_onlyOwner|isAuthorized|isAdmin)\s*\(")
_MODIFIER_HEAD = re.compile(r"\bmodifier\s+([A-Za-z_$][\w$]*)\s*(?:\([^)]*\))?[^;{]*\{")
# A reentrancy lock by name. Not a bare "...lock" suffix or "lock..." prefix: onlyTimelock, whenUnlocked,
# lockable are access or state modifiers, not reentrancy locks (a flag lock is found from its body instead).
_LOCK_NAME = re.compile(r"(?i)non_?reentrant|no_?reentr|reentrancy|mutex|^_?(?:lock|locked|with_?lock|lock_?guard)$")
_PRIVILEGED_VAR = re.compile(
    r"(?i)owner|admin|governance|governor|operator|authority|authori[sz]ed|controller|implementation|minter|"
    r"guardian|whitelist|allowlist|signer")
_WEAK_SOURCE = re.compile(r"\bblock\s*\.\s*(?:timestamp|difficulty|prevrandao|number|coinbase|gaslimit)\b"
                          r"|\bblockhash\s*\(|\bblock\s*\.\s*blockhash\s*\(|\bnow\b")
_BALANCE_DRAIN = re.compile(
    r"\.(?:transfer|send)\s*\(\s*address\s*\(\s*this\s*\)\s*\.\s*balance\s*\)"
    r"|\.call\s*\{[^}]*\bvalue\s*:\s*address\s*\(\s*this\s*\)\s*\.\s*balance\b")
_SECRET_NAME = re.compile(r"(?i)password|passwd|secret|seed|passphrase|private_?key|\bkey\b|_key\b|flag|\bpin\b")
_HIDDEN_DECL = re.compile(
    r"(?m)^\s*(?:u?int(?:8|16|32|64|128|256)?|address(?:\s+payable)?|bool|bytes(?:[1-9]|[12][0-9]|3[0-2])?|string)"
    r"(?:\s*\[\s*\d*\s*\])?\s+((?:(?:private|internal|public|constant|immutable)\s+)*)([A-Za-z_$][\w$]*)\s*[=;]")
_LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "4": "a"})


def _source_modifiers(masked: str) -> dict[str, dict]:
    """Modifiers defined in the source: {name: {'access': checks the caller, 'lock': a reentrancy lock}}."""
    out: dict[str, dict] = {}
    for match in _MODIFIER_HEAD.finditer(masked):
        opening = masked.find("{", match.start(), match.end())
        end = _balanced_end(masked, opening)
        if end is None:
            continue
        body = masked[opening + 1:end - 1]
        lock = bool(_LOCK_NAME.search(match.group(1)))
        for var in re.findall(r"\brequire\s*\(\s*!?\s*([A-Za-z_$][\w$]*)\s*(?:[!=]=|\)|,)", body):
            if re.search(rf"\b{re.escape(var)}\s*=(?!=)", body):
                lock = True            # a modifier that checks a flag and sets it is a lock
        out[match.group(1)] = {"access": bool(_SENDER_CHECK.search(body)), "lock": lock}
    return out


def _header_uses(header: str, name: str) -> bool:
    return bool(re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", header))


def _reentrancy_guarded(header: str, guards: dict[str, dict]) -> bool:
    return bool(re.search(r"\bnonReentrant\b", header)) or any(
        g["lock"] and _header_uses(header, name) for name, g in guards.items())


def _caller_restricted(header: str, body: str, guards: dict[str, dict]) -> bool:
    return (_has_access_control(header, body) or bool(_SENDER_CHECK.search(body))
            or any(g["access"] and _header_uses(header, name) for name, g in guards.items()))


def _contracts(masked: str) -> list[tuple[str, int, int]]:
    out = []
    for match in re.finditer(r"\b(?:contract|abstract\s+contract)\s+([A-Za-z_$][\w$]*)[^;{]*\{", masked):
        opening = masked.find("{", match.start(), match.end())
        end = _balanced_end(masked, opening)
        if end is not None:
            out.append((match.group(1), opening, end))
    return out


def _paren_args(text: str, opening: int) -> str:
    depth = 0
    for index in range(opening, min(len(text), opening + 4000)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[opening + 1:index]
    return text[opening + 1:opening + 4000]


def _sink_findings(masked: str, functions: list[dict], state_vars: list[str], guards: dict[str, dict]) -> list[dict]:
    findings: list[dict] = []
    privileged = [name for name in state_vars if _PRIVILEGED_VAR.search(name)]
    contracts = _contracts(masked)
    for fn in functions:
        header, body, absolute = fn["header"], fn["body"], fn["body_start"]
        name = fn["name"]
        special = name.lower() in {"fallback", "receive"}
        external = special or bool(re.search(r"\b(?:public|external)\b", header))
        mutating = not re.search(r"\b(?:view|pure)\b", header)
        restricted = _caller_restricted(header, body, guards)
        if external and mutating and not restricted and name != "constructor" \
                and not name.lower().startswith(("init", "initialize")):
            for var in privileged:
                write = re.search(rf"\b{re.escape(var)}\b(?:\s*\[[^;]+?\])?\s*(?:[+\-*/%]?=(?!=)|\.push\s*\()", body)
                if write:
                    findings.append(_finding(
                        "unprotected-privileged-write", "critical", "medium",
                        f"externally callable function writes privileged state '{var}' with no evident caller check",
                        function=name, variable=var, line=_line(masked, absolute + write.start())))
                    break
        drain = _BALANCE_DRAIN.search(body)
        if drain and external and not restricted:
            findings.append(_finding(
                "unrestricted-balance-drain", "critical", "medium",
                "externally callable function sends the whole contract balance with no evident caller check",
                function=name, line=_line(masked, absolute + drain.start())))
        owner = next((c for c in contracts if c[1] < fn["start"] < c[2]), None)
        if owner and name not in {"constructor", "fallback", "receive"} and name != owner[0] \
                and name.lower().translate(_LOOKALIKE) == owner[0].lower().translate(_LOOKALIKE) \
                and not re.search(r"\b(?:internal|private)\b", header):
            findings.append(_finding(
                "constructor-name-mismatch", "critical", "high",
                f"function '{name}' looks like the constructor of contract '{owner[0]}' but its name differs, "
                "so it is an ordinary callable function",
                function=name, contract=owner[0], line=_line(masked, fn["start"])))

    for match in re.finditer(r"\bblock\s*\.\s*(?:prevrandao|difficulty)\b|\bblockhash\s*\(", masked):
        findings.append(_finding("weak-randomness", "high", "medium",
                                 "block hash / prevrandao is used; it is known to every transaction in the block",
                                 source=re.sub(r"[\s(]+", "", match.group(0)), line=_line(masked, match.start())))
    for match in re.finditer(r"\bkeccak256\s*\(|\bsha256\s*\(", masked):
        args = _paren_args(masked, match.end() - 1)
        source = _WEAK_SOURCE.search(args)
        if source:
            findings.append(_finding(
                "weak-randomness", "high", "medium",
                "block data feeds a hash that looks like a random draw; miners/validators and callers in "
                "the same block can predict it", source=re.sub(r"\s+", "", source.group(0)),
                line=_line(masked, match.start())))
    for match in re.finditer(r"(?:\bblock\s*\.\s*(?:timestamp|difficulty|prevrandao|number)\b|\bnow\b)\s*%", masked):
        findings.append(_finding("weak-randomness", "high", "medium",
                                 "block data taken modulo a range looks like a random draw",
                                 source=re.sub(r"[\s%]+", "", match.group(0)), line=_line(masked, match.start())))

    top = list(masked)
    for fn in functions:
        for index in range(fn["start"], fn["end"]):
            if top[index] != "\n":
                top[index] = " "
    for match in _HIDDEN_DECL.finditer("".join(top)):
        mods, var = match.group(1).split(), match.group(2)
        if "public" in mods or not _SECRET_NAME.search(var):
            continue
        where = ("is a constant, compiled into the bytecode" if {"constant", "immutable"} & set(mods)
                 else "has no public getter, but its storage slot is readable by anyone (eth_getStorageAt)")
        findings.append(_finding(
            "private-storage-readable", "medium", "high",
            f"'{var}' looks secret and {where}; Solidity visibility hides nothing on chain",
            variable=var, line=_line(masked, match.start())))
    return findings


def analyze_solidity_source(source: str) -> dict:
    if not isinstance(source, str):
        raise TypeError("source must be text")
    if len(source.encode("utf-8", "replace")) > MAX_INPUT:
        raise ValueError("source exceeds input cap")
    masked = sanitize_solidity(source)
    functions = solidity_functions(masked)
    state_vars = _state_variables(masked, functions)
    findings: list[dict] = []
    checked = _compiler_overflow_checked(masked)
    guards = _source_modifiers(masked)

    for pattern, kind, severity, message in (
        (r"\btx\.origin\b", "tx-origin-auth", "high", "tx.origin is used and can make authorization phishing-prone"),
        (r"\b(?:selfdestruct|suicide)\s*\(", "selfdestruct", "high", "contract destruction opcode is reachable from source"),
        (r"\bdelegatecall\s*\(", "delegatecall", "high", "delegatecall executes foreign code in this storage context"),
    ):
        for match in re.finditer(pattern, masked, re.I):
            findings.append(_finding(kind, severity, "high", message, line=_line(masked, match.start())))

    if re.search(r"\bdelegatecall\s*\(", masked, re.I):
        implementation_slots = re.findall(r"(?i)(?:implementation|impl|target)\s*;", masked)
        standardized = bool(re.search(r"(?i)360894a13ba1a321|eip1967|ERC1967", source))
        if state_vars and not standardized:
            findings.append(_finding(
                "proxy-storage-collision", "high", "medium",
                "delegatecall proxy declares ordinary state without an evident standardized implementation slot",
                state_variables=state_vars[:32], implementation_like_declarations=len(implementation_slots),
            ))

    for fn in functions:
        body, absolute = fn["body"], fn["body_start"]
        externally_reachable = (fn["name"].lower() in {"fallback", "receive"}
                                or bool(re.search(r"\b(?:public|external)\b", fn["header"])))
        # `.call.value(n)(...)` / `.call.gas(g).value(n)(...)` is the pre-0.6 spelling of a value call (B-243)
        calls = list(re.finditer(r"\.(?:call|send|transfer)\b\s*(?:\{|\()|\.call\s*(?:\.\s*gas\s*\([^;()]*\)\s*)?\.\s*value\s*\(",
                                 body, re.I))
        delegates = list(re.finditer(r"\.delegatecall\s*\(", body, re.I))
        state_writes = []
        for name in state_vars:
            expression = re.compile(rf"\b{re.escape(name)}\b(?:\s*\[[^;]+?\])?\s*(?:\+\+|--|[+\-*/%]?=(?!=))")
            state_writes.extend(expression.finditer(body))
        state_writes.sort(key=lambda item: item.start())
        if calls and state_writes:
            # B-243: a reentrancy guard on the function (nonReentrant, or a source modifier that sets and
            # checks a lock) keeps the ordering finding but lowers it and says why
            guarded = _reentrancy_guarded(fn["header"], guards)
            for call in calls:
                later = next((write for write in state_writes if write.start() > call.start()), None)
                if later:
                    findings.append(_finding(
                        "reentrancy-order", "low" if guarded else "high", "medium",
                        "external value/control call precedes a state write in the same function"
                        + (" (the function carries a reentrancy guard)" if guarded else ""),
                        function=fn["name"], line=_line(masked, absolute + call.start()),
                        state_write_line=_line(masked, absolute + later.start()),
                        guarded=True if guarded else None,
                    ))
                    break
        for call in calls:
            prefix = body[max(0, call.start() - 48):call.start()]
            statement_end = body.find(";", call.end())
            statement = body[max(0, body.rfind(";", 0, call.start()) + 1):statement_end + 1]
            if not re.search(r"(?:require\s*\(|assert\s*\(|\bbool\b|\bsuccess\b|\bok\b|=)", prefix + statement, re.I):
                findings.append(_finding(
                    "unchecked-low-level-call", "medium", "medium",
                    "low-level call result is not evidently checked",
                    function=fn["name"], line=_line(masked, absolute + call.start()),
                ))
        if calls and re.search(r"\b(?:for|while)\s*\(", body[:calls[-1].end()]):
            findings.append(_finding("external-call-in-loop", "medium", "medium",
                                     "external call appears inside or after a loop construct",
                                     function=fn["name"], line=_line(masked, absolute + calls[0].start())))
        if delegates and externally_reachable and not _has_access_control(fn["header"], body):
            findings.append(_finding("unrestricted-delegatecall", "critical", "medium",
                                     "delegatecall-bearing function has no evident caller restriction",
                                     function=fn["name"], line=_line(masked, absolute + delegates[0].start())))
        destructive = re.search(r"\b(?:selfdestruct|suicide)\s*\(", body, re.I)
        if destructive and externally_reachable and not _has_access_control(fn["header"], body):
            findings.append(_finding("unrestricted-selfdestruct", "critical", "medium",
                                     "destructive function has no evident caller restriction",
                                     function=fn["name"], line=_line(masked, absolute + destructive.start())))
        if fn["name"].lower().startswith(("init", "initialize")) and re.search(r"\b(?:public|external)\b", fn["header"]):
            if not re.search(r"\b(?:initializer|reinitializer)\b", fn["header"], re.I):
                findings.append(_finding("unprotected-initializer", "high", "medium",
                                         "initializer-like public function lacks an initializer guard",
                                         function=fn["name"], line=_line(masked, fn["start"])))

    unchecked = list(re.finditer(r"\bunchecked\s*\{", masked))
    for match in unchecked:
        end = _balanced_end(masked, masked.find("{", match.start(), match.end()))
        region = masked[match.end():end - 1] if end else ""
        if re.search(r"(?:\+\+|--|[+\-*])", region):
            findings.append(_finding("unchecked-arithmetic", "medium", "high",
                                     "arithmetic occurs inside an unchecked block",
                                     line=_line(masked, match.start())))
    if checked is False:
        arithmetic = re.search(r"(?:\+\+|--|\+=|-=|\*=|\b\w+\s*[+\-*]\s*\w+)", masked)
        if arithmetic:
            findings.append(_finding("legacy-arithmetic-overflow", "medium", "medium",
                                     "pragma permits a pre-0.8 compiler where arithmetic is unchecked by default",
                                     line=_line(masked, arithmetic.start())))

    for match in re.finditer(r"\babi\.encodePacked\s*\(([^;)]*)\)", masked):
        args = match.group(1)
        dynamic = sum(bool(re.search(rf"\b{kind}\b", args)) for kind in ("string", "bytes"))
        if args.count(",") >= 1 and (dynamic or re.search(r"\bkeccak256\s*\(", masked[max(0, match.start()-20):match.start()])):
            findings.append(_finding("packed-encoding-collision", "low", "low",
                                     "multiple packed values may be ambiguous when dynamic-width inputs are used",
                                     line=_line(masked, match.start())))

    findings.extend(_sink_findings(masked, functions, state_vars, guards))

    return {
        "kind": "solidity-source", "pragma_overflow_checked": checked,
        "functions": [{"name": fn["name"], "line": _line(masked, fn["start"])} for fn in functions],
        "state_variables": state_vars, "findings": _sort(findings),
    }


_NAMES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV",
    0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP", 0x0B: "SIGNEXTEND",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND",
    0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR",
    0x20: "SHA3", 0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE",
    0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
    0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH", 0x40: "BLOCKHASH",
    0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT",
    0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x49: "BLOBHASH", 0x4A: "BLOBBASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD", 0x55: "SSTORE",
    0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
    0x5C: "TLOAD", 0x5D: "TSTORE", 0x5E: "MCOPY", 0x5F: "PUSH0",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL",
    0xF5: "CREATE2", 0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}
for _value in range(0x80, 0x90):
    _NAMES[_value] = f"DUP{_value - 0x7F}"
for _value in range(0x90, 0xA0):
    _NAMES[_value] = f"SWAP{_value - 0x8F}"
for _value in range(0xA0, 0xA5):
    _NAMES[_value] = f"LOG{_value - 0xA0}"


def parse_bytecode(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
    elif isinstance(value, str):
        if len(value) > MAX_INPUT * 3:
            raise ValueError("bytecode text exceeds input cap")
        compact = re.sub(r"\s+", "", value)
        if compact.startswith(("0x", "0X")):
            compact = compact[2:]
        if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
            raise ValueError("bytecode text must be even-length hexadecimal")
        data = bytes.fromhex(compact)
    else:
        raise TypeError("bytecode must be bytes or hexadecimal text")
    if len(data) > MAX_INPUT:
        raise ValueError("bytecode exceeds input cap")
    return data


def disassemble(value: bytes | bytearray | str) -> list[dict]:
    data = parse_bytecode(value)
    instructions, offset = [], 0
    while offset < len(data):
        if len(instructions) >= MAX_INSTRUCTIONS:
            raise ValueError("instruction cap exceeded")
        opcode, start = data[offset], offset
        offset += 1
        immediate = b""
        truncated = False
        if 0x60 <= opcode <= 0x7F:
            size = opcode - 0x5F
            immediate = data[offset:offset + size]
            truncated = len(immediate) != size
            offset += len(immediate)
            name = f"PUSH{size}"
        else:
            name = _NAMES.get(opcode, f"OP_{opcode:02X}")
        instructions.append({"offset": start, "opcode": opcode, "name": name,
                             "immediate": immediate.hex(), "truncated": truncated})
        if truncated:
            break
    return instructions


_TERMINATORS = {"STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT", "JUMP", "JUMPI"}


def _validate_instructions(instructions: list[dict]) -> None:
    """Validate the fields consumed by block and selector analysis."""
    if not isinstance(instructions, list) or len(instructions) > MAX_INSTRUCTIONS:
        raise ValueError("instructions must be a bounded list")
    for row in instructions:
        if not isinstance(row, dict) or type(row.get("offset")) is not int or row["offset"] < 0:
            raise ValueError("instruction requires a nonnegative integer offset")
        name = row.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("instruction requires a name")
        if name.startswith("PUSH"):
            immediate = row.get("immediate")
            if not re.fullmatch(r"PUSH(?:[0-9]|[12][0-9]|3[0-2])", name) or not isinstance(immediate, str):
                raise ValueError("invalid PUSH instruction")
            if len(immediate) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", immediate):
                raise ValueError("PUSH immediate must be hexadecimal bytes")
            if len(immediate) > 2 * int(name[4:]):
                raise ValueError("PUSH immediate exceeds opcode width")


def basic_blocks(instructions: list[dict]) -> list[dict]:
    _validate_instructions(instructions)
    if not instructions:
        return []
    leaders = {instructions[0]["offset"]}
    for index, instruction in enumerate(instructions):
        if instruction["name"] == "JUMPDEST":
            leaders.add(instruction["offset"])
        if instruction["name"] in _TERMINATORS and index + 1 < len(instructions):
            leaders.add(instructions[index + 1]["offset"])
    blocks, current = [], []
    for instruction in instructions:
        if current and instruction["offset"] in leaders:
            blocks.append(current)
            current = []
        current.append(instruction)
    if current:
        blocks.append(current)
    result = []
    for index, block in enumerate(blocks):
        edges, last = [], block[-1]
        if last["name"] in {"JUMP", "JUMPI"} and len(block) >= 2 and block[-2]["name"].startswith("PUSH"):
            edges.append(int(block[-2]["immediate"] or "0", 16))
        if last["name"] not in _TERMINATORS or last["name"] == "JUMPI":
            if index + 1 < len(blocks):
                edges.append(blocks[index + 1][0]["offset"])
        result.append({"start": block[0]["offset"], "end": block[-1]["offset"],
                       "instructions": block, "edges": sorted(set(edges))})
    return result


def function_selectors(instructions: list[dict]) -> list[dict]:
    _validate_instructions(instructions)
    out = []
    for index, instruction in enumerate(instructions):
        if instruction["name"] == "PUSH4" and len(instruction["immediate"]) == 8:
            window = instructions[index + 1:index + 5]
            eq = next((pos for pos, item in enumerate(window) if item["name"] == "EQ"), None)
            if eq is None:
                continue
            tail = window[eq + 1:]
            dest = next((int(item["immediate"], 16) for item in tail if item["name"].startswith("PUSH") and item["immediate"]), None)
            if dest is not None and any(item["name"] == "JUMPI" for item in tail):
                out.append({"selector": "0x" + instruction["immediate"], "destination": dest,
                            "offset": instruction["offset"]})
    return out


def analyze_evm_bytecode(value: bytes | bytearray | str) -> dict:
    code = parse_bytecode(value)
    ins = disassemble(code)
    blocks = basic_blocks(ins)
    findings: list[dict] = []
    names = [item["name"] for item in ins]
    for instruction in ins:
        name = instruction["name"]
        if name == "ORIGIN":
            findings.append(_finding("tx-origin", "high", "high", "ORIGIN opcode is present",
                                     offset=instruction["offset"]))
        elif name == "SELFDESTRUCT":
            findings.append(_finding("selfdestruct", "high", "high", "SELFDESTRUCT opcode is present",
                                     offset=instruction["offset"]))
        elif name in {"DELEGATECALL", "CALLCODE"}:
            findings.append(_finding("delegate-context-call", "high", "high",
                                     f"{name} executes code in caller storage context",
                                     offset=instruction["offset"], opcode=name))
    for block in blocks:
        block_names = [item["name"] for item in block["instructions"]]
        for call_name in ("CALL", "CALLCODE", "DELEGATECALL"):
            if call_name in block_names:
                call_index = block_names.index(call_name)
                if "SSTORE" in block_names[call_index + 1:]:
                    findings.append(_finding("reentrancy-order", "high", "medium",
                                             "external-control opcode precedes SSTORE in one basic block",
                                             offset=block["instructions"][call_index]["offset"], block=block["start"]))
                tail = block_names[call_index + 1:call_index + 4]
                if not any(name in {"ISZERO", "JUMPI", "REVERT"} for name in tail):
                    findings.append(_finding("unchecked-call-result", "medium", "low",
                                             "call success value is not immediately checked in its basic block",
                                             offset=block["instructions"][call_index]["offset"], opcode=call_name))
    panic_selector = bytes.fromhex("4e487b71") in code
    arithmetic = [item for item in ins if item["name"] in {"ADD", "SUB", "MUL", "EXP"}]
    if arithmetic and not panic_selector:
        findings.append(_finding("arithmetic-overflow-context", "medium", "low",
                                 "arithmetic opcodes exist without the Solidity panic selector; compiler checks are unproven",
                                 offset=arithmetic[0]["offset"], opcodes=sorted({x["name"] for x in arithmetic})))
    if "DELEGATECALL" in names and "SSTORE" in names:
        slots = []
        for index, item in enumerate(ins):
            if item["name"] == "SSTORE" and index and ins[index - 1]["name"].startswith("PUSH"):
                slots.append(int(ins[index - 1]["immediate"] or "0", 16))
        findings.append(_finding("proxy-storage-collision", "high", "low",
                                 "bytecode combines delegatecall with storage writes; proxy/implementation layout must match",
                                 storage_slots=sorted(set(slots))[:32]))
    return {
        "kind": "evm-bytecode", "size": len(code), "instruction_count": len(ins),
        "basic_block_count": len(blocks), "selectors": function_selectors(ins),
        "opcodes": {name: names.count(name) for name in sorted(set(names))},
        "findings": _sort(findings),
    }


def analyze_artifact(data: bytes, name: str = "") -> dict:
    if not isinstance(data, (bytes, bytearray)) or not isinstance(name, str):
        raise TypeError("artifact must be bytes and name must be text")
    if len(data) > MAX_INPUT:
        raise ValueError("artifact exceeds input cap")
    text = data.decode("utf-8", "replace")
    if name.lower().endswith(".sol") or re.search(r"\b(?:pragma\s+solidity|contract\s+\w+)", sanitize_solidity(text)):
        return analyze_solidity_source(text)
    return analyze_evm_bytecode(text.strip() if re.fullmatch(r"\s*(?:0x)?[0-9a-fA-F\s]+\s*", text) else data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Solidity/EVM vulnerability triage")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--pretty", action="store_true")
    try:
        args = parser.parse_args(argv)
        data = args.artifact.read_bytes()
        report = analyze_artifact(data, args.artifact.name)
        print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (OSError, ValueError, TypeError, OverflowError) as exc:
        print(f"evm_audit: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
