#!/usr/bin/env python3
"""Offline Solana and Move artifact decoders and security triage.

Only caller-supplied bytes, JSON, IDLs, manifests, source, and transaction records are
accepted.  There is intentionally no RPC client, wallet integration, signing, or code
execution in this module.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from pathlib import Path
from typing import Iterable, Mapping, Sequence

MAX_INPUT = 32 * 1024 * 1024
MAX_ACCOUNTS = 65_536
MAX_INSTRUCTIONS = 100_000
MAX_TABLES = 255
MAX_NESTING = 256
MAX_TABLE_ITEMS = 1_000_000
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {char: index for index, char in enumerate(_B58)}
_SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

SYSTEM_PROGRAM = "11111111111111111111111111111111"
TOKEN_PROGRAMS = {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "spl-token",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "token-2022",
}


def _finding(kind: str, severity: str, message: str, confidence: str = "medium", **evidence: object) -> dict:
    item = {"kind": kind, "severity": severity, "confidence": confidence, "message": message}
    item.update({key: value for key, value in evidence.items() if value is not None})
    return item


def _sort(findings: Iterable[dict]) -> list[dict]:
    unique: dict[str, dict] = {}
    for item in findings:
        unique[json.dumps(item, sort_keys=True, default=str)] = item
    return sorted(unique.values(), key=lambda item: (
        -_SEVERITY.get(str(item.get("severity")), 0), str(item.get("kind")),
        str(item.get("instruction", "")), str(item.get("function", "")),
    ))


def b58decode(value: str) -> bytes:
    """Decode canonical Bitcoin/Solana base58 without a third-party dependency."""
    if not isinstance(value, str):
        raise TypeError("base58 value must be text")
    number = 0
    for char in value:
        try:
            digit = _B58_INDEX[char]
        except KeyError as error:
            raise ValueError(f"invalid base58 character {char!r}") from error
        number = number * 58 + digit
    encoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + encoded


def decode_compact_u16(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode Solana's short-vector integer, rejecting non-canonical/overflow forms."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("compact-u16 input must be bytes")
    if offset < 0 or offset > len(data):
        raise ValueError("compact-u16 offset is outside the buffer")
    value, shift, cursor = 0, 0, offset
    for index in range(3):
        if cursor >= len(data):
            raise ValueError("truncated compact-u16")
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if value > 0xFFFF or (index and value < (1 << (7 * index))):
                raise ValueError("non-canonical or overflowing compact-u16")
            return value, cursor
        shift += 7
    raise ValueError("compact-u16 exceeds three bytes")


def _read_uleb128(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a Move/LEB128 unsigned varint, bounding the width to a u64."""
    if offset < 0 or offset > len(data):
        raise ValueError("uleb128 offset is outside the buffer")
    value, shift, cursor = 0, 0, offset
    while True:
        if cursor >= len(data):
            raise ValueError("truncated uleb128")
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, cursor
        shift += 7
        if shift > 63:
            raise ValueError("uleb128 exceeds 64 bits")


def _decode_ix_data(value: object) -> tuple[bytes, str]:
    if value in (None, ""):
        return b"", "empty"
    encoding = "base58"
    text = value
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        if len(value) != 2:
            raise ValueError("encoded instruction data must have value and encoding")
        text, encoding = value
    if not isinstance(text, str):
        raise ValueError("instruction data must be encoded text")
    if encoding == "base64":
        try:
            return base64.b64decode(text, validate=True), "base64"
        except ValueError as error:
            raise ValueError("invalid base64 instruction data") from error
    if encoding == "hex":
        try:
            return bytes.fromhex(text.removeprefix("0x")), "hex"
        except ValueError as error:
            raise ValueError("invalid hexadecimal instruction data") from error
    if encoding not in {"base58", "binary"}:
        raise ValueError(f"unsupported instruction encoding {encoding!r}")
    return b58decode(text), "base58"


def _account_records(message: Mapping[str, object], meta: Mapping[str, object]) -> list[dict]:
    raw_keys = message.get("accountKeys", message.get("staticAccountKeys", []))
    if not isinstance(raw_keys, Sequence) or isinstance(raw_keys, (str, bytes)):
        raise ValueError("message accountKeys must be an array")
    header = message.get("header", {})
    header = header if isinstance(header, Mapping) else {}
    required = int(header.get("numRequiredSignatures", 0))
    ro_signed = int(header.get("numReadonlySignedAccounts", 0))
    ro_unsigned = int(header.get("numReadonlyUnsignedAccounts", 0))
    records = []
    for index, item in enumerate(raw_keys):
        if isinstance(item, Mapping):
            key = str(item.get("pubkey", item.get("address", "")))
            signer = bool(item.get("signer", item.get("isSigner", False)))
            writable = bool(item.get("writable", item.get("isWritable", False)))
        else:
            key = str(item)
            signer = index < required
            if signer:
                writable = index < required - ro_signed
            else:
                writable = index < len(raw_keys) - ro_unsigned
        records.append({"index": index, "pubkey": key, "signer": signer,
                        "writable": writable, "source": "static"})
    loaded = meta.get("loadedAddresses", {})
    if isinstance(loaded, Mapping):
        for writable, group in ((True, loaded.get("writable", [])), (False, loaded.get("readonly", []))):
            if isinstance(group, Sequence) and not isinstance(group, (str, bytes)):
                for key in group:
                    records.append({"index": len(records), "pubkey": str(key), "signer": False,
                                    "writable": writable, "source": "lookup"})
    if len(records) > MAX_ACCOUNTS:
        raise ValueError("account list exceeds cap")
    return records


def _decode_known_instruction(program: str, data: bytes) -> dict:
    decoded: dict[str, object] = {"raw_hex": data.hex(), "length": len(data)}
    if program == SYSTEM_PROGRAM and len(data) >= 4:
        operation = int.from_bytes(data[:4], "little")
        names = {0: "create-account", 1: "assign", 2: "transfer", 3: "create-account-with-seed",
                 4: "advance-nonce", 5: "withdraw-nonce", 6: "initialize-nonce",
                 7: "authorize-nonce", 8: "allocate", 9: "allocate-with-seed",
                 10: "assign-with-seed", 11: "transfer-with-seed", 12: "upgrade-nonce"}
        decoded.update({"family": "system", "opcode": operation, "operation": names.get(operation, "unknown")})
        if operation == 2 and len(data) >= 12:
            decoded["lamports"] = int.from_bytes(data[4:12], "little")
    elif program in TOKEN_PROGRAMS and data:
        operation = data[0]
        names = {1: "initialize-account", 3: "transfer", 4: "approve", 5: "revoke",
                 6: "set-authority", 7: "mint-to", 8: "burn", 9: "close-account",
                 12: "transfer-checked", 13: "approve-checked", 14: "mint-to-checked",
                 15: "burn-checked", 17: "sync-native"}
        if TOKEN_PROGRAMS[program] == "token-2022":
            names.update({25: "mint-close-authority", 26: "transfer-fee-extension",
                          27: "confidential-transfer-extension", 28: "default-account-state",
                          29: "reallocate", 30: "memo-transfer", 31: "create-native-mint",
                          32: "non-transferable-mint", 33: "interest-bearing-mint",
                          34: "cpi-guard", 35: "permanent-delegate", 36: "transfer-hook",
                          37: "confidential-transfer-fee", 38: "withdraw-excess-lamports",
                          39: "metadata-pointer", 40: "group-pointer",
                          41: "group-member-pointer", 42: "confidential-mint-burn",
                          43: "scaled-ui-amount", 44: "pausable"})
        decoded.update({"family": TOKEN_PROGRAMS[program], "opcode": operation,
                        "operation": names.get(operation, "unknown")})
        if operation in {3, 4, 7, 8} and len(data) >= 9:
            decoded["amount"] = int.from_bytes(data[1:9], "little")
        if operation in {12, 13, 14, 15} and len(data) >= 10:
            decoded.update({"amount": int.from_bytes(data[1:9], "little"), "decimals": data[9]})
    return decoded


def analyze_solana_transaction(artifact: Mapping[str, object]) -> dict:
    """Resolve and decode a supplied Solana JSON transaction without RPC."""
    if not isinstance(artifact, Mapping):
        raise ValueError("Solana transaction artifact must be an object")
    transaction = artifact.get("transaction", artifact)
    if not isinstance(transaction, Mapping):
        raise ValueError("transaction must be an object")
    message = transaction.get("message", artifact.get("message", transaction))
    if not isinstance(message, Mapping):
        raise ValueError("transaction message must be an object")
    meta = artifact.get("meta", {})
    meta = meta if isinstance(meta, Mapping) else {}
    accounts = _account_records(message, meta)
    raw_ixs = message.get("instructions", message.get("compiledInstructions", []))
    if not isinstance(raw_ixs, Sequence) or isinstance(raw_ixs, (str, bytes)):
        raise ValueError("instructions must be an array")
    if len(raw_ixs) > MAX_INSTRUCTIONS:
        raise ValueError("instruction list exceeds cap")
    instructions, findings = [], []
    work_items: list[tuple[int | str, Mapping[str, object], int | None]] = [
        (index, raw, None) for index, raw in enumerate(raw_ixs) if isinstance(raw, Mapping)
    ]
    inner_groups = meta.get("innerInstructions", [])
    if isinstance(inner_groups, Sequence) and not isinstance(inner_groups, (str, bytes)):
        for group in inner_groups:
            if not isinstance(group, Mapping):
                continue
            parent = int(group.get("index", -1))
            nested = group.get("instructions", [])
            if not isinstance(nested, Sequence) or isinstance(nested, (str, bytes)):
                continue
            for inner_index, raw in enumerate(nested):
                if isinstance(raw, Mapping):
                    work_items.append((f"{parent}.{inner_index}", raw, parent))
    if len(work_items) > MAX_INSTRUCTIONS:
        raise ValueError("combined instruction list exceeds cap")
    for index, raw, parent in work_items:
        if not isinstance(raw, Mapping):
            continue
        if "parsed" in raw:
            instructions.append({"index": index, "program": str(raw.get("programId", raw.get("program", ""))),
                                 "parsed": raw["parsed"], "accounts": raw.get("accounts", []),
                                 "inner": parent is not None, "parent_index": parent})
            continue
        program_index = raw.get("programIdIndex")
        if program_index is not None:
            program_index = int(program_index)
            if not 0 <= program_index < len(accounts):
                raise ValueError("programIdIndex is outside the resolved account list")
            program = accounts[program_index]["pubkey"]
        else:
            program = str(raw.get("programId", ""))
        raw_account_indexes = raw.get("accounts", raw.get("accountKeyIndexes", []))
        resolved = []
        if isinstance(raw_account_indexes, Sequence) and not isinstance(raw_account_indexes, (str, bytes)):
            for account_index in raw_account_indexes:
                if isinstance(account_index, int) or str(account_index).isdigit():
                    account_index = int(account_index)
                    if not 0 <= account_index < len(accounts):
                        raise ValueError("instruction account index is outside the account list")
                    resolved.append(accounts[account_index])
                else:
                    resolved.append({"pubkey": str(account_index), "signer": False,
                                     "writable": False, "source": "literal"})
        data, encoding = _decode_ix_data(raw.get("data", ""))
        record = {"index": index, "program": program, "accounts": resolved,
                  "encoding": encoding, "decoded": _decode_known_instruction(program, data),
                  "inner": parent is not None, "parent_index": parent}
        instructions.append(record)
        decoded = record["decoded"]
        if decoded.get("family") in {"spl-token", "token-2022"} and decoded.get("operation") in {
                "transfer", "approve", "set-authority", "mint-to", "burn", "close-account",
                "transfer-checked", "approve-checked", "mint-to-checked", "burn-checked"}:
            if resolved and not any(item["signer"] for item in resolved):
                findings.append(_finding("token-authority-not-transaction-signer", "high",
                                         "token mutation has no signer among its resolved accounts",
                                         instruction=index, program=program))
    def token_balances(raw: object) -> dict[tuple[int, str, str], dict]:
        balances = {}
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
            return balances
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            amount_info = item.get("uiTokenAmount", {})
            amount_info = amount_info if isinstance(amount_info, Mapping) else {}
            try:
                account_index = int(item.get("accountIndex"))
                amount = int(str(amount_info.get("amount")))
            except (TypeError, ValueError):
                continue
            key = (account_index, str(item.get("mint", "")), str(item.get("owner", "")))
            balances[key] = {"amount": amount, "decimals": amount_info.get("decimals")}
        return balances

    before = token_balances(meta.get("preTokenBalances", []))
    after = token_balances(meta.get("postTokenBalances", []))
    token_deltas = []
    for key in sorted(set(before) | set(after)):
        prior, later = before.get(key, {"amount": 0}), after.get(key, {"amount": 0})
        token_deltas.append({"account_index": key[0], "mint": key[1], "owner": key[2],
                             "before": prior["amount"], "after": later["amount"],
                             "delta": later["amount"] - prior["amount"],
                             "decimals": later.get("decimals", prior.get("decimals"))})
    logs = meta.get("logMessages", [])
    if isinstance(logs, Sequence) and not isinstance(logs, (str, bytes)):
        for log in logs:
            text = str(log)
            if re.search(r"unauthorized signer|writable privilege escalated", text, re.I):
                findings.append(_finding("runtime-privilege-escalation", "high",
                                         "supplied runtime log records a signer/writable privilege error", "high",
                                         log=text))
            if re.search(r"\bProgram(?:\s+[^:]*)?\s+failed\b", text, re.I):
                findings.append(_finding("program-failure", "info", "supplied runtime log records failure",
                                         "high", log=text))
    return {"kind": "solana-transaction", "version": message.get("version", transaction.get("version")),
            "recent_blockhash": message.get("recentBlockhash"), "accounts": accounts,
            "instructions": instructions, "token_balance_deltas": token_deltas,
            "status": meta.get("err"), "findings": _sort(findings)}


def parse_solana_wire_transaction(data: bytes) -> dict:
    """Parse a legacy/v0 Solana wire transaction with strict bounds."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("wire transaction input must be bytes")
    if len(data) > MAX_INPUT:
        raise ValueError("wire transaction exceeds input cap")
    signature_count, cursor = decode_compact_u16(data, 0)
    signature_bytes = signature_count * 64
    if cursor + signature_bytes + 3 > len(data):
        raise ValueError("truncated signatures or message header")
    signatures = [data[cursor + index * 64:cursor + (index + 1) * 64].hex()
                  for index in range(signature_count)]
    cursor += signature_bytes
    version = "legacy"
    if data[cursor] & 0x80:
        version = data[cursor] & 0x7F
        cursor += 1
        if version != 0:
            raise ValueError(f"unsupported Solana message version {version}")
    if cursor + 3 > len(data):
        raise ValueError("truncated message header")
    header = {"numRequiredSignatures": data[cursor],
              "numReadonlySignedAccounts": data[cursor + 1],
              "numReadonlyUnsignedAccounts": data[cursor + 2]}
    cursor += 3
    if header["numRequiredSignatures"] != signature_count:
        raise ValueError("signature vector count does not match message header")
    account_count, cursor = decode_compact_u16(data, cursor)
    if account_count > MAX_ACCOUNTS or cursor + account_count * 32 + 32 > len(data):
        raise ValueError("truncated or excessive account list")
    accounts = [data[cursor + index * 32:cursor + (index + 1) * 32].hex()
                for index in range(account_count)]
    cursor += account_count * 32
    recent_blockhash = data[cursor:cursor + 32].hex()
    cursor += 32
    instruction_count, cursor = decode_compact_u16(data, cursor)
    if instruction_count > MAX_INSTRUCTIONS:
        raise ValueError("instruction count exceeds cap")
    instructions = []
    for index in range(instruction_count):
        if cursor >= len(data):
            raise ValueError("truncated compiled instruction")
        program_index = data[cursor]
        cursor += 1
        account_indexes_count, cursor = decode_compact_u16(data, cursor)
        if cursor + account_indexes_count > len(data):
            raise ValueError("truncated instruction account indexes")
        account_indexes = list(data[cursor:cursor + account_indexes_count])
        cursor += account_indexes_count
        payload_size, cursor = decode_compact_u16(data, cursor)
        if cursor + payload_size > len(data):
            raise ValueError("truncated instruction data")
        payload = data[cursor:cursor + payload_size]
        cursor += payload_size
        instructions.append({"index": index, "program_id_index": program_index,
                             "account_indexes": account_indexes, "data_hex": payload.hex()})
    lookups = []
    if version != "legacy":
        lookup_count, cursor = decode_compact_u16(data, cursor)
        for _ in range(lookup_count):
            if cursor + 32 > len(data):
                raise ValueError("truncated address-table lookup")
            account_key = data[cursor:cursor + 32].hex()
            cursor += 32
            writable_count, cursor = decode_compact_u16(data, cursor)
            if cursor + writable_count > len(data):
                raise ValueError("truncated writable lookup indexes")
            writable = list(data[cursor:cursor + writable_count])
            cursor += writable_count
            readonly_count, cursor = decode_compact_u16(data, cursor)
            if cursor + readonly_count > len(data):
                raise ValueError("truncated readonly lookup indexes")
            readonly = list(data[cursor:cursor + readonly_count])
            cursor += readonly_count
            lookups.append({"account_key": account_key, "writable_indexes": writable,
                            "readonly_indexes": readonly})
    resolved_account_count = account_count + sum(
        len(item["writable_indexes"]) + len(item["readonly_indexes"]) for item in lookups
    )
    for instruction in instructions:
        if (instruction["program_id_index"] >= resolved_account_count
                or any(value >= resolved_account_count for value in instruction["account_indexes"])):
            raise ValueError("compiled instruction references an unknown account")
    if cursor != len(data):
        raise ValueError("trailing bytes after Solana transaction")
    return {"kind": "solana-wire-transaction", "version": version, "signatures": signatures,
            "header": header, "accounts_hex": accounts, "recent_blockhash_hex": recent_blockhash,
            "instructions": instructions, "address_table_lookups": lookups}


def analyze_anchor_idl(idl: Mapping[str, object]) -> dict:
    """Audit supplied Anchor-style IDL account constraints."""
    if not isinstance(idl, Mapping):
        raise ValueError("Anchor IDL must be an object")
    findings, instructions = [], []
    raw_instructions = idl.get("instructions", [])
    if not isinstance(raw_instructions, Sequence) or isinstance(raw_instructions, (str, bytes)):
        raise ValueError("IDL instructions must be an array")
    for raw in raw_instructions:
        if not isinstance(raw, Mapping):
            continue
        name = str(raw.get("name", ""))
        flat_accounts = []

        def flatten(items: object, depth: int = 0, active: set[int] | None = None) -> None:
            if depth > MAX_NESTING:
                raise ValueError("IDL account nesting exceeds cap")
            if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
                return
            active = active if active is not None else set()
            identity = id(items)
            if identity in active:
                raise ValueError("cyclic IDL account groups")
            active.add(identity)
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                nested = item.get("accounts")
                if nested is not None:
                    flatten(nested, depth + 1, active)
                else:
                    flat_accounts.append(dict(item))
            active.remove(identity)

        flatten(raw.get("accounts", []))
        instructions.append({"name": name, "accounts": flat_accounts, "args": raw.get("args", [])})
        mutating = any(bool(account.get("isMut", account.get("writable", False))) for account in flat_accounts)
        signers = [str(account.get("name", "")) for account in flat_accounts
                   if account.get("isSigner", account.get("signer", False))]
        if mutating and not signers:
            findings.append(_finding("anchor-mutation-without-signer", "high",
                                     "mutating instruction declares no signer account",
                                     instruction=name))
        for account in flat_accounts:
            account_type = str(account.get("type", account.get("accountType", "")))
            docs = " ".join(str(value) for value in account.get("docs", [])) if isinstance(account.get("docs"), list) else ""
            unchecked = re.search(r"UncheckedAccount|AccountInfo", account_type + " " + docs, re.I)
            constrained = any(key in account for key in ("address", "pda", "seeds", "relations"))
            if unchecked and bool(account.get("isMut", account.get("writable", False))) and not constrained:
                findings.append(_finding("unchecked-writable-account", "high",
                                         "writable generic account has no evident address/PDA relation",
                                         instruction=name, account=account.get("name")))
            if account.get("isSigner", account.get("signer", False)) and not bool(account.get("isMut", account.get("writable", False))):
                # Informational: often intentional, but useful for authority review.
                findings.append(_finding("readonly-authority", "info",
                                         "signer authority is read-only in the supplied IDL",
                                         instruction=name, account=account.get("name")))
    return {"kind": "anchor-idl-analysis", "name": idl.get("name"),
            "instructions": instructions, "findings": _sort(findings)}


def _strip_move_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", lambda match: "".join("\n" if char == "\n" else " " for char in match.group()),
                    source, flags=re.S)
    return re.sub(r"//[^\n]*", lambda match: " " * len(match.group()), source)


def _move_functions(source: str) -> list[dict]:
    masked = _strip_move_comments(source)
    pattern = re.compile(r"(?m)(?P<header>(?:(?:public(?:\([^)]*\))?|entry|native|inline)\s+)*fun\s+"
                         r"(?P<name>[A-Za-z_]\w*)\s*(?:<[^>{}]*>)?\s*\((?P<params>[^)]*)\)"
                         r"\s*(?::\s*[^\{;]+)?(?:\s+acquires\s+[^\{;]+)?\s*)\{")
    records = []
    for match in pattern.finditer(masked):
        opening = match.end() - 1
        depth, end = 0, None
        for index in range(opening, len(masked)):
            if masked[index] == "{":
                depth += 1
            elif masked[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        if end is None:
            continue
        records.append({"name": match.group("name"), "header": match.group("header"),
                        "params": match.group("params"), "body": masked[opening + 1:end],
                        "line": masked.count("\n", 0, match.start()) + 1})
    return records


def analyze_move_source(source: str) -> dict:
    """Analyze Move source capabilities, signer checks, and global-state access."""
    if not isinstance(source, str):
        raise ValueError("Move source must be text")
    if len(source.encode("utf-8", "replace")) > MAX_INPUT:
        raise ValueError("Move source exceeds input cap")
    masked = _strip_move_comments(source)
    functions = _move_functions(source)
    resources = sorted(set(re.findall(r"\bstruct\s+([A-Za-z_]\w*)\s+has\s+[^\{]*(?:key|store)", masked)))
    capability_types = sorted(name for name in resources if re.search(r"(?:Cap|Capability|Admin|Authority)", name, re.I))
    findings = []
    records = []
    for fn in functions:
        public_entry = bool(re.search(r"\bentry\b|\bpublic\b(?!\s*\()", fn["header"]))
        signer = bool(re.search(r"(?:&\s*(?:mut\s+)?)?signer\b", fn["params"]))
        global_mutation = bool(re.search(r"\b(?:borrow_global_mut|move_from|move_to|table::(?:add|remove|borrow_mut))\b", fn["body"]))
        assertions = bool(re.search(r"\b(?:assert!|signer::address_of|object::is_owner|borrow_global)\b", fn["body"]))
        returns_cap = any(re.search(rf"\b{re.escape(name)}\s*\{{", fn["body"]) for name in capability_types)
        records.append({"name": fn["name"], "line": fn["line"], "public_entry": public_entry,
                        "has_signer": signer, "global_mutation": global_mutation,
                        "capability_construction": returns_cap})
        if public_entry and global_mutation and not signer:
            findings.append(_finding("move-global-mutation-without-signer", "critical",
                                     "public/entry function mutates global state without a signer parameter",
                                     "high", function=fn["name"], line=fn["line"]))
        if public_entry and returns_cap and not signer:
            findings.append(_finding("move-unrestricted-capability-mint", "critical",
                                     "public function constructs an authority-like resource without signer gating",
                                     "high", function=fn["name"], line=fn["line"],
                                     capabilities=capability_types))
        if public_entry and signer and global_mutation and not assertions:
            findings.append(_finding("move-signer-not-bound-to-resource", "medium",
                                     "state mutation accepts a signer but no address/ownership relation is evident",
                                     function=fn["name"], line=fn["line"]))
        if re.search(r"\bvector::borrow_mut\b", fn["body"]) and not re.search(r"\bvector::length\b|<\s*[^=]", fn["body"]):
            findings.append(_finding("move-vector-index-validation", "low",
                                     "mutable vector borrow has no evident local bounds validation",
                                     function=fn["name"], line=fn["line"]))
    friends = re.findall(r"\bfriend\s+([^;]+);", masked)
    return {"kind": "move-source-analysis", "modules": re.findall(r"\bmodule\s+([^\s{]+)", masked),
            "friends": friends, "resources": resources, "capability_types": capability_types,
            "functions": records, "findings": _sort(findings)}


MOVE_MAGIC = bytes.fromhex("a11ceb0b")


def parse_move_bytecode(data: bytes) -> dict:
    """Parse the Move binary header/table directory without executing bytecode."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Move bytecode input must be bytes")
    if len(data) > MAX_INPUT:
        raise ValueError("Move bytecode exceeds input cap")
    if len(data) < 9 or data[:4] != MOVE_MAGIC:
        raise ValueError("not a Move binary")
    version = int.from_bytes(data[4:8], "little")
    table_count, cursor = _read_uleb128(data, 8)
    if table_count > MAX_TABLES:
        raise ValueError("truncated Move table directory")
    tables = []
    for _ in range(table_count):
        if cursor >= len(data):
            raise ValueError("truncated Move table directory")
        kind = data[cursor]
        offset, cursor = _read_uleb128(data, cursor + 1)
        count, cursor = _read_uleb128(data, cursor)
        if offset > len(data):
            raise ValueError("Move table offset is outside artifact")
        if count > MAX_TABLE_ITEMS:
            raise ValueError("Move table item count exceeds cap")
        tables.append({"kind": kind, "offset": offset, "count": count})
    overlaps = len({item["kind"] for item in tables}) != len(tables)
    return {"kind": "move-bytecode", "version": version, "size": len(data), "tables": tables,
            "duplicate_table_kinds": overlaps,
            "findings": ([_finding("duplicate-move-table", "medium",
                                   "Move binary declares a table kind more than once", "high")]
                         if overlaps else [])}


def _strip_toml_comment(line: str) -> str:
    """Drop a trailing TOML ``#`` comment, but keep any ``#`` inside a quoted string."""
    result: list[str] = []
    quote: str | None = None
    for char in line:
        if quote is not None:
            result.append(char)
            if char == quote:
                quote = None
        elif char == "#":
            break
        else:
            if char in ("'", '"'):
                quote = char
            result.append(char)
    return "".join(result)


def analyze_move_manifest(text: str) -> dict:
    """Inspect supplied Move.toml dependency pins and address placeholders."""
    if not isinstance(text, str):
        raise ValueError("Move manifest must be text")
    if len(text.encode("utf-8", "replace")) > MAX_INPUT:
        raise ValueError("manifest exceeds input cap")
    section = ""
    dependencies, addresses, findings = [], {}, []
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = _strip_toml_comment(raw).strip()
        section_match = re.fullmatch(r"\[([^]]+)]", line)
        if section_match:
            section = section_match.group(1).lower()
            continue
        assignment = re.match(r"([A-Za-z_][\w.-]*)\s*=\s*(.+)", line)
        if not assignment:
            continue
        name, value = assignment.groups()
        if section in {"dependencies", "dev-dependencies"}:
            dependencies.append({"name": name, "value": value, "line": line_number, "section": section})
            revision = re.search(r"\brev\s*=\s*['\"]([^'\"]+)['\"]", value)
            if "git" in value and (not revision or not re.fullmatch(r"[0-9a-fA-F]{40,64}", revision.group(1))):
                findings.append(_finding("move-unpinned-git-dependency", "high",
                                         "git dependency has no immutable revision",
                                         dependency=name, line=line_number))
            if re.search(r"\blocal\s*=", value):
                findings.append(_finding("move-local-dependency", "low",
                                         "local dependency makes the package build context-dependent",
                                         dependency=name, line=line_number))
        elif section in {"addresses", "dev-addresses"}:
            addresses[name] = value.strip().strip('"')
            if addresses[name] in {"_", "0x0", "0x"}:
                findings.append(_finding("move-unassigned-address", "medium",
                                         "named address is unset or zero-valued", address=name,
                                         line=line_number))
    return {"kind": "move-manifest", "dependencies": dependencies,
            "addresses": dict(sorted(addresses.items())), "findings": _sort(findings)}


def analyze_move_transaction(artifact: Mapping[str, object]) -> dict:
    """Normalize supplied Aptos/Sui transaction JSON and mutation evidence."""
    if not isinstance(artifact, Mapping):
        raise ValueError("Move transaction artifact must be an object")
    payload = artifact.get("payload", artifact.get("transaction", artifact))
    effects = artifact.get("effects", artifact.get("changes", []))
    function = ""
    arguments: object = []
    type_arguments: object = []
    if isinstance(payload, Mapping):
        function = str(payload.get("function", payload.get("target", payload.get("kind", ""))))
        arguments = payload.get("arguments", payload.get("args", payload.get("inputs", [])))
        type_arguments = payload.get("type_arguments", payload.get("typeArguments", []))
    signers = artifact.get("signatures", artifact.get("sender", []))
    if isinstance(signers, str):
        signers = [signers]
    mutations = []
    if isinstance(effects, Sequence) and not isinstance(effects, (str, bytes)):
        for effect in effects:
            if isinstance(effect, Mapping):
                mutations.append({"type": effect.get("type", effect.get("changeType")),
                                  "address": effect.get("address", effect.get("objectId")),
                                  "owner": effect.get("owner")})
    findings = []
    status = artifact.get("success", artifact.get("vm_status", artifact.get("status")))
    if status is False or (isinstance(status, str) and re.search(r"abort|fail|error", status, re.I)):
        findings.append(_finding("move-transaction-failure", "info",
                                 "supplied transaction record reports VM failure", "high", status=status))
    return {"kind": "move-transaction", "function": function, "arguments": arguments,
            "type_arguments": type_arguments, "signers": signers, "mutations": mutations,
            "status": status, "findings": _sort(findings)}


def analyze_artifact(data: bytes, name: str = "artifact") -> dict:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("artifact input must be bytes")
    if len(data) > MAX_INPUT:
        raise ValueError("artifact exceeds input cap")
    lower = name.lower()
    if data.startswith(MOVE_MAGIC):
        return parse_move_bytecode(data)
    if lower.endswith(".move"):
        return analyze_move_source(data.decode("utf-8", "replace"))
    if Path(lower).name == "move.toml" or lower.endswith(".toml"):
        return analyze_move_manifest(data.decode("utf-8", "replace"))
    if lower.endswith((".tx", ".wire", ".soltx")):
        return parse_solana_wire_transaction(data)
    try:
        parsed = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("unrecognized multichain artifact") from error
    if not isinstance(parsed, Mapping):
        raise ValueError("multichain JSON artifact must be an object")
    if ("instructions" in parsed and not any(key in parsed for key in ("transaction", "message", "accountKeys"))
            and ("name" in parsed or "metadata" in parsed or "accounts" in parsed or "types" in parsed)):
        return analyze_anchor_idl(parsed)
    if "transaction" in parsed or "message" in parsed or "accountKeys" in parsed:
        return analyze_solana_transaction(parsed)
    if "payload" in parsed or "effects" in parsed or "changes" in parsed:
        return analyze_move_transaction(parsed)
    raise ValueError("unrecognized multichain JSON artifact")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="supplied Solana/Move artifact")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        result = analyze_artifact(args.artifact.read_bytes(), args.artifact.name)
    except (OSError, ValueError) as exc:
        print(f"multichain_depth: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
