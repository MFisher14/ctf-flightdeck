#!/usr/bin/env python3
"""Offline wallet, chain-artifact, calldata, event, PSBT and Solana decoders.

The module deliberately reports public metadata only.  Seed phrases, private keys,
keystore ciphertext and wallet passwords are neither decrypted nor returned.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

try:
    from Crypto.Hash import keccak as _keccak
except ImportError:  # pragma: no cover - environment fallback is explicit
    _keccak = None

MAX_INPUT = 16 * 1024 * 1024
MAX_ITEMS = 100_000


def keccak256(data: bytes) -> bytes:
    if _keccak is None:
        raise RuntimeError("pycryptodome keccak is required for Ethereum hashes")
    return _keccak.new(digest_bits=256, data=data).digest()


def _hex_bytes(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
        if len(data) > MAX_INPUT:
            raise ValueError("binary value exceeds input cap")
        return data
    if not isinstance(value, str):
        raise TypeError("value must be bytes or hex text")
    if len(value) > MAX_INPUT * 3:
        raise ValueError("hex value exceeds input cap")
    value = re.sub(r"\s+", "", value)
    if value.startswith(("0x", "0X")):
        value = value[2:]
    if len(value) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", value):
        raise ValueError("invalid hexadecimal value")
    return bytes.fromhex(value)


def _word(data: bytes, offset: int) -> bytes:
    if offset < 0 or offset + 32 > len(data):
        raise ValueError("ABI word outside payload")
    return data[offset:offset + 32]


def _split_types(text: str) -> list[str]:
    out, start, depth = [], 0, 0
    for index, char in enumerate(text):
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "," and depth == 0:
            out.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        out.append(tail)
    return out


def canonical_signature(signature: str) -> tuple[str, list[str]]:
    match = re.fullmatch(r"\s*([A-Za-z_$][\w$]*)\s*\((.*)\)\s*", signature)
    if not match:
        raise ValueError("invalid function signature")
    types = _split_types(match.group(2)) if match.group(2).strip() else []
    for typ in types:
        if not re.fullmatch(r"(?:address|bool|string|bytes|bytes(?:[1-9]|[12]\d|3[0-2])|u?int(?:8|16|32|64|128|256)?)(?:\[[0-9]*\])*", typ):
            raise ValueError(f"unsupported ABI type: {typ}")
        if typ in {"uint", "int"}:
            raise ValueError("use canonical uint256/int256 spelling")
    return match.group(1) + "(" + ",".join(types) + ")", types


def selector(signature: str) -> bytes:
    canonical, _ = canonical_signature(signature)
    return keccak256(canonical.encode())[:4]


MAX_ABI_DEPTH = 32


def _dynamic(typ: str) -> bool:
    array = re.fullmatch(r"(.+)\[([0-9]*)\]", typ)
    if array:
        inner, count_text = array.groups()
        # T[] is dynamic; a fixed-size T[k] is dynamic iff its element type is dynamic.
        return not count_text or _dynamic(inner)
    return typ in {"bytes", "string"}


def _head_size(typ: str) -> int:
    """Static head width in bytes for a static type (32 for a scalar, k*inner for T[k])."""
    array = re.fullmatch(r"(.+)\[([0-9]*)\]", typ)
    if array:
        inner, count_text = array.groups()
        return int(count_text) * _head_size(inner)
    return 32


def _array_depth(typ: str) -> int:
    depth = 0
    while True:
        array = re.fullmatch(r"(.+)\[([0-9]*)\]", typ)
        if not array:
            return depth
        typ = array.group(1)
        depth += 1
        if depth > MAX_ABI_DEPTH:
            raise ValueError("ABI type nesting too deep")


def _decode_scalar(typ: str, word: bytes):
    number = int.from_bytes(word, "big")
    if typ == "address":
        if word[:12] != b"\0" * 12:
            raise ValueError("non-canonical address padding")
        return "0x" + word[12:].hex()
    if typ == "bool":
        if number not in (0, 1):
            raise ValueError("non-canonical bool")
        return bool(number)
    if typ.startswith("uint"):
        bits = int(typ[4:] or "256")
        if number >= 1 << bits:
            raise ValueError("uint exceeds declared width")
        return number
    if typ.startswith("int"):
        bits = int(typ[3:] or "256")
        if bits < 256:
            # The bytes above the declared width must be sign extension of the value's sign bit:
            # all zero for a non-negative value, all one for a negative one.
            sign = (number >> (bits - 1)) & 1
            expected_upper = ((1 << (256 - bits)) - 1) if sign else 0
            if number >> bits != expected_upper:
                raise ValueError("int padding invalid")
        mask = (1 << bits) - 1
        value = number & mask
        return value - (1 << bits) if value & (1 << (bits - 1)) else value
    if typ.startswith("bytes") and typ != "bytes":
        size = int(typ[5:])
        if word[size:] != b"\0" * (32 - size):
            raise ValueError("fixed-bytes padding invalid")
        return "0x" + word[:size].hex()
    raise ValueError(f"unsupported scalar {typ}")


def _decode_static(typ: str, payload: bytes, pos: int):
    """Decode a STATIC type encoded inline beginning at ``pos``."""
    array = re.fullmatch(r"(.+)\[([0-9]*)\]", typ)
    if array:
        inner, count_text = array.groups()
        count = int(count_text)
        if count > MAX_ITEMS:
            raise ValueError("ABI array exceeds item cap")
        width = _head_size(inner)
        return [_decode_static(inner, payload, pos + width * i) for i in range(count)]
    return _decode_scalar(typ, _word(payload, pos))


def _decode_dynamic(typ: str, payload: bytes, start: int):
    """Decode a DYNAMIC value whose encoding begins at ``start`` (its head slot already resolved)."""
    array = re.fullmatch(r"(.+)\[([0-9]*)\]", typ)
    if array:
        inner, count_text = array.groups()
        if count_text:
            count, region = int(count_text), start
        else:
            count = int.from_bytes(_word(payload, start), "big")
            region = start + 32
        if count > MAX_ITEMS:
            raise ValueError("ABI array exceeds item cap")
        return _decode_sequence([inner] * count, payload, region)
    offset = start
    length = int.from_bytes(_word(payload, offset), "big")
    if length > MAX_INPUT or offset + 32 + length > len(payload):
        raise ValueError("dynamic ABI value outside payload")
    raw = payload[offset + 32:offset + 32 + length]
    return raw.decode("utf-8", "replace") if typ == "string" else "0x" + raw.hex()


def _decode_sequence(types: list[str], payload: bytes, base: int) -> list:
    """Decode a head/tail-encoded tuple (or array elements) that start at ``base``."""
    head = base
    out = []
    for typ in types:
        if _dynamic(typ):
            offset = int.from_bytes(_word(payload, head), "big")
            out.append(_decode_dynamic(typ, payload, base + offset))
            head += 32
        else:
            out.append(_decode_static(typ, payload, head))
            head += _head_size(typ)
    return out


def abi_decode(types: list[str], payload: bytes) -> list:
    if len(types) > MAX_ITEMS or len(payload) > MAX_INPUT or len(payload) < 32 * len(types):
        raise ValueError("invalid ABI payload size")
    for typ in types:
        _array_depth(typ)                 # bound nesting before any recursion
    return _decode_sequence(list(types), payload, 0)


_KNOWN_FUNCTIONS = (
    "transfer(address,uint256)", "approve(address,uint256)", "transferFrom(address,address,uint256)",
    "balanceOf(address)", "allowance(address,address)", "totalSupply()", "ownerOf(uint256)",
    "safeTransferFrom(address,address,uint256)", "safeTransferFrom(address,address,uint256,bytes)",
    "setApprovalForAll(address,bool)", "isApprovedForAll(address,address)", "supportsInterface(bytes4)",
    "safeTransferFrom(address,address,uint256,uint256,bytes)",
    "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
    "upgradeTo(address)", "upgradeToAndCall(address,bytes)", "changeAdmin(address)",
    "multicall(bytes[])", "execute(address,uint256,bytes)", "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
)


def known_selectors() -> dict[str, str]:
    return {selector(signature).hex(): signature for signature in _KNOWN_FUNCTIONS}


def decode_calldata(value: bytes | bytearray | str, signature: str | None = None) -> dict:
    data = _hex_bytes(value)
    if len(data) < 4:
        raise ValueError("calldata is shorter than selector")
    selector_hex = data[:4].hex()
    matched = signature
    if matched is None:
        matched = known_selectors().get(selector_hex)
    if matched is None:
        return {"selector": "0x" + selector_hex, "signature": None, "arguments": None,
                "argument_data": "0x" + data[4:].hex()}
    canonical, types = canonical_signature(matched)
    if selector(canonical) != data[:4]:
        raise ValueError("provided signature does not match selector")
    values = abi_decode(types, data[4:])
    return {"selector": "0x" + selector_hex, "signature": canonical,
            "name": canonical.split("(", 1)[0], "types": types, "arguments": values}


_PANICS = {
    0x00: "generic compiler panic", 0x01: "assertion failed", 0x11: "arithmetic overflow/underflow",
    0x12: "division or modulo by zero", 0x21: "invalid enum conversion", 0x22: "invalid storage byte array",
    0x31: "pop on empty array", 0x32: "array index out of bounds", 0x41: "memory allocation overflow",
    0x51: "call to uninitialized internal function",
}


def decode_revert(value: bytes | bytearray | str, custom_errors: dict[str, str] | None = None) -> dict:
    data = _hex_bytes(value)
    if len(data) < 4:
        return {"kind": "empty-or-short", "data": "0x" + data.hex()}
    ident, body = data[:4].hex(), data[4:]
    if ident == "08c379a0":
        values = abi_decode(["string"], body)
        return {"kind": "Error(string)", "reason": values[0], "selector": "0x" + ident}
    if ident == "4e487b71":
        code = abi_decode(["uint256"], body)[0]
        return {"kind": "Panic(uint256)", "code": code, "reason": _PANICS.get(code, "unknown panic"),
                "selector": "0x" + ident}
    signature = (custom_errors or {}).get(ident) or (custom_errors or {}).get("0x" + ident)
    if signature:
        decoded = decode_calldata(data, signature)
        decoded["kind"] = "custom-error"
        return decoded
    return {"kind": "custom-or-unknown", "selector": "0x" + ident, "argument_data": "0x" + body.hex()}


_EVENT_SIGNATURES = (
    "Transfer(address,address,uint256)", "Approval(address,address,uint256)",
    "ApprovalForAll(address,address,bool)", "OwnershipTransferred(address,address)",
    "Upgraded(address)", "AdminChanged(address,address)",
    "TransferSingle(address,address,address,uint256,uint256)",
)


def event_topics() -> dict[str, str]:
    return {keccak256(signature.encode()).hex(): signature for signature in _EVENT_SIGNATURES}


def _topic_value(typ: str, value: bytes):
    if typ in {"string", "bytes"} or typ.endswith("[]"):
        return {"indexed_hash": "0x" + value.hex()}
    return _decode_scalar(typ, value)


def decode_event(topics: list[str | bytes], data: str | bytes = b"",
                 signature: str | None = None) -> dict:
    if len(topics) > MAX_ITEMS:
        raise ValueError("event topic count exceeds cap")
    raw_topics = [_hex_bytes(topic) for topic in topics]
    if not raw_topics or any(len(topic) != 32 for topic in raw_topics):
        raise ValueError("event topics must be 32 bytes")
    topic0 = raw_topics[0].hex()
    signature = signature or event_topics().get(topic0)
    if signature is None:
        return {"topic0": "0x" + topic0, "signature": None, "topics": ["0x" + x.hex() for x in raw_topics[1:]],
                "data": "0x" + _hex_bytes(data).hex()}
    canonical, types = canonical_signature(signature)
    if keccak256(canonical.encode()) != raw_topics[0]:
        raise ValueError("event signature does not match topic0")
    indexed_count = len(raw_topics) - 1
    if indexed_count > len(types):
        raise ValueError("more indexed topics than event parameters")
    indexed = [_topic_value(types[index], raw_topics[index + 1]) for index in range(indexed_count)]
    nonindexed_types = types[indexed_count:]
    nonindexed = abi_decode(nonindexed_types, _hex_bytes(data)) if nonindexed_types else []
    return {"topic0": "0x" + topic0, "signature": canonical, "name": canonical.split("(", 1)[0],
            "indexed": indexed, "data_values": nonindexed,
            "note": "indexed positions are inferred from topic count for known standard events"}


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    number, out = int.from_bytes(data, "big"), ""
    while number:
        number, remainder = divmod(number, 58)
        out = _B58[remainder] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + (out or ("" if data else ""))


def base58_decode(value: str) -> bytes:
    if len(value) > 256:
        raise ValueError("base58 value exceeds cap")
    number = 0
    for char in value:
        if char not in _B58:
            raise ValueError("invalid base58 character")
        number = number * 58 + _B58.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + body


_XPUB_VERSIONS = {
    0x0488B21E: ("xpub", "mainnet", "public"), 0x0488ADE4: ("xprv", "mainnet", "private"),
    0x043587CF: ("tpub", "testnet", "public"), 0x04358394: ("tprv", "testnet", "private"),
    0x049D7CB2: ("ypub", "mainnet", "public"), 0x04B24746: ("zpub", "mainnet", "public"),
    0x044A5262: ("upub", "testnet", "public"), 0x045F1CF6: ("vpub", "testnet", "public"),
}


def classify_extended_key(value: str) -> dict | None:
    try:
        raw = base58_decode(value)
    except ValueError:
        return None
    if len(raw) != 82 or hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        return None
    meta = _XPUB_VERSIONS.get(int.from_bytes(raw[:4], "big"))
    if meta is None:
        return None
    prefix, network, key_kind = meta
    return {"format": "bip32-extended-key", "prefix": prefix, "network": network, "key_kind": key_kind,
            "depth": raw[4], "parent_fingerprint": raw[5:9].hex(), "child_number": int.from_bytes(raw[9:13], "big"),
            "chain_code_fingerprint": hashlib.sha256(raw[13:45]).hexdigest()[:16]}


_DESC_INPUT = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
_DESC_CHECKSUM = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _desc_polymod(c: int, value: int) -> int:
    top = c >> 35
    c = ((c & 0x7FFFFFFFF) << 5) ^ value
    for index, generator in enumerate((0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD)):
        if (top >> index) & 1:
            c ^= generator
    return c


def descriptor_checksum(descriptor: str) -> str:
    if len(descriptor) > 16_384:
        raise ValueError("descriptor exceeds cap")
    body = descriptor.split("#", 1)[0]
    c, cls, count = 1, 0, 0
    for char in body:
        pos = _DESC_INPUT.find(char)
        if pos < 0:
            raise ValueError("unsupported descriptor character")
        c = _desc_polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        count += 1
        if count == 3:
            c = _desc_polymod(c, cls)
            cls = count = 0
    if count:
        c = _desc_polymod(c, cls)
    for _ in range(8):
        c = _desc_polymod(c, 0)
    c ^= 1
    return "".join(_DESC_CHECKSUM[(c >> (5 * (7 - index))) & 31] for index in range(8))


def classify_descriptor(value: str) -> dict | None:
    body, marker, supplied = value.strip().partition("#")
    if not re.match(r"^(?:pkh|wpkh|sh|wsh|tr|combo|addr|raw)\(", body):
        return None
    expected = descriptor_checksum(body)
    return {"format": "bitcoin-output-descriptor", "script": body.split("(", 1)[0],
            "checksum": supplied if marker else None, "checksum_valid": supplied == expected if marker else None,
            "expected_checksum": expected, "ranged": "*" in body,
            "contains_private_material": bool(re.search(r"\b(?:xprv|tprv|L[1-9A-HJ-NP-Za-km-z]{50,51}|K[1-9A-HJ-NP-Za-km-z]{50,51})", body))}


def _compact(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated compact integer")
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    if offset + 1 + size > len(data):
        raise ValueError("truncated compact integer")
    value = int.from_bytes(data[offset + 1:offset + 1 + size], "little")
    if value < {2: 0xFD, 4: 0x10000, 8: 0x100000000}[size]:
        raise ValueError("non-canonical compact integer")
    return value, offset + 1 + size


def _psbt_map(data: bytes, offset: int) -> tuple[list[tuple[bytes, bytes]], int]:
    out = []
    while True:
        key_len, offset = _compact(data, offset)
        if key_len == 0:
            return out, offset
        if key_len > MAX_INPUT or offset + key_len > len(data):
            raise ValueError("PSBT key outside input")
        key, offset = data[offset:offset + key_len], offset + key_len
        value_len, offset = _compact(data, offset)
        if value_len > MAX_INPUT or offset + value_len > len(data):
            raise ValueError("PSBT value outside input")
        value, offset = data[offset:offset + value_len], offset + value_len
        if any(old_key == key for old_key, _ in out):
            raise ValueError("duplicate PSBT key")
        out.append((key, value))
        if len(out) > MAX_ITEMS:
            raise ValueError("PSBT map exceeds item cap")


def _btc_tx_counts(tx: bytes) -> tuple[int, int]:
    if len(tx) < 10:
        raise ValueError("truncated unsigned transaction")
    offset = 4
    if tx[offset:offset + 2] == b"\0\x01":
        raise ValueError("PSBT unsigned transaction must not contain witness serialization")
    inputs, offset = _compact(tx, offset)
    for _ in range(inputs):
        if offset + 36 > len(tx):
            raise ValueError("truncated transaction input")
        offset += 36
        length, offset = _compact(tx, offset)
        if length:
            raise ValueError("PSBT unsigned transaction input has a scriptSig")
        offset += length + 4
        if offset > len(tx):
            raise ValueError("truncated transaction input script")
    outputs, offset = _compact(tx, offset)
    for _ in range(outputs):
        if offset + 8 > len(tx):
            raise ValueError("truncated transaction output")
        offset += 8
        length, offset = _compact(tx, offset)
        offset += length
        if offset > len(tx):
            raise ValueError("truncated transaction output script")
    if offset + 4 != len(tx):
        raise ValueError("truncated or trailing unsigned transaction data")
    return inputs, outputs


def parse_psbt(value: bytes | str) -> dict:
    if isinstance(value, str):
        if len(value) > MAX_INPUT * 3:
            raise ValueError("PSBT text exceeds cap")
        compact = "".join(value.split())
        try:
            data = base64.b64decode(compact, validate=True)
        except Exception:
            data = _hex_bytes(compact)
    else:
        data = bytes(value)
    if len(data) > MAX_INPUT or not data.startswith(b"psbt\xff"):
        raise ValueError("not a bounded PSBT")
    global_map, offset = _psbt_map(data, 5)
    version, inputs, outputs = 0, None, None
    key_types = []
    for key, payload in global_map:
        key_types.append(key[0])
        if key == b"\xfb" and len(payload) <= 4:
            version = int.from_bytes(payload, "little")
        elif key == b"\x00":
            inputs, outputs = _btc_tx_counts(payload)
        elif key == b"\x04":
            inputs, consumed = _compact(payload, 0)
            if consumed != len(payload):
                raise ValueError("invalid PSBTv2 input count")
        elif key == b"\x05":
            outputs, consumed = _compact(payload, 0)
            if consumed != len(payload):
                raise ValueError("invalid PSBTv2 output count")
    if inputs is None or outputs is None or inputs > MAX_ITEMS or outputs > MAX_ITEMS:
        raise ValueError("PSBT has no bounded input/output counts")
    input_maps = []
    for _ in range(inputs):
        mapping, offset = _psbt_map(data, offset)
        input_maps.append(mapping)
    output_maps = []
    for _ in range(outputs):
        mapping, offset = _psbt_map(data, offset)
        output_maps.append(mapping)
    if offset != len(data):
        raise ValueError("trailing PSBT bytes")
    return {"format": "psbt", "version": version, "inputs": inputs, "outputs": outputs,
            "global_key_types": key_types,
            "input_key_types": [[key[0] for key, _ in mapping] for mapping in input_maps],
            "output_key_types": [[key[0] for key, _ in mapping] for mapping in output_maps],
            "finalized_inputs": sum(any(key[0] in (7, 8) for key, _ in mapping) for mapping in input_maps)}


def _shortvec(data: bytes, offset: int) -> tuple[int, int]:
    value, shift = 0, 0
    for _ in range(3):
        if offset >= len(data):
            raise ValueError("truncated Solana shortvec")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if value > MAX_ITEMS:
                raise ValueError("Solana shortvec exceeds cap")
            return value, offset
        shift += 7
    raise ValueError("non-canonical Solana shortvec")


def parse_solana_transaction(value: bytes | str) -> dict:
    if isinstance(value, str):
        if len(value) > MAX_INPUT * 2:
            raise ValueError("Solana transaction text exceeds cap")
        data = base64.b64decode("".join(value.split()), validate=True)
    else:
        data = bytes(value)
    if not data or len(data) > MAX_INPUT:
        raise ValueError("invalid Solana transaction size")
    signatures, offset = _shortvec(data, 0)
    sig_bytes = 64 * signatures
    if offset + sig_bytes + 3 > len(data):
        raise ValueError("truncated Solana signatures/message")
    offset += sig_bytes
    version = "legacy"
    if data[offset] & 0x80:
        version = data[offset] & 0x7F
        offset += 1
    required, readonly_signed, readonly_unsigned = data[offset:offset + 3]
    offset += 3
    accounts, offset = _shortvec(data, offset)
    if offset + accounts * 32 + 32 > len(data):
        raise ValueError("truncated Solana accounts/blockhash")
    account_keys = [base58_encode(data[offset + 32 * i:offset + 32 * (i + 1)]) for i in range(accounts)]
    offset += accounts * 32
    blockhash = base58_encode(data[offset:offset + 32])
    offset += 32
    count, offset = _shortvec(data, offset)
    instructions = []
    for _ in range(count):
        if offset >= len(data):
            raise ValueError("truncated Solana instruction")
        program_index = data[offset]
        offset += 1
        n_accounts, offset = _shortvec(data, offset)
        if offset + n_accounts > len(data):
            raise ValueError("truncated Solana instruction accounts")
        indices = list(data[offset:offset + n_accounts])
        offset += n_accounts
        size, offset = _shortvec(data, offset)
        if offset + size > len(data):
            raise ValueError("truncated Solana instruction data")
        payload = data[offset:offset + size]
        offset += size
        instructions.append({"program_index": program_index,
                             "program": account_keys[program_index] if program_index < len(account_keys) else None,
                             "account_indices": indices, "data_base58": base58_encode(payload)})
    lookups = []
    if version != "legacy":
        lookup_count, offset = _shortvec(data, offset)
        for _ in range(lookup_count):
            if offset + 32 > len(data):
                raise ValueError("truncated address-table lookup")
            key = base58_encode(data[offset:offset + 32]); offset += 32
            writable_count, offset = _shortvec(data, offset)
            writable = list(data[offset:offset + writable_count]); offset += writable_count
            readonly_count, offset = _shortvec(data, offset)
            readonly = list(data[offset:offset + readonly_count]); offset += readonly_count
            lookups.append({"account": key, "writable": writable, "readonly": readonly})
    if offset != len(data):
        raise ValueError("trailing Solana transaction bytes")
    return {"format": "solana-transaction", "version": version, "signature_count": signatures,
            "header": {"required_signatures": required, "readonly_signed": readonly_signed,
                       "readonly_unsigned": readonly_unsigned},
            "accounts": account_keys, "recent_blockhash": blockhash,
            "instructions": instructions, "address_table_lookups": lookups}


def classify_wallet(document) -> dict | None:
    if isinstance(document, list) and len(document) in (32, 64) and all(isinstance(x, int) and 0 <= x < 256 for x in document):
        raw = bytes(document)
        public = raw[-32:] if len(raw) == 64 else None
        return {"format": "solana-keypair-array", "private_material_present": True,
                "public_key": base58_encode(public) if public else None, "secret_length": len(raw)}
    if not isinstance(document, dict):
        return None
    lower = {str(key).lower(): value for key, value in document.items()}
    crypto = lower.get("crypto") or lower.get("crypto")
    if str(lower.get("version")) == "3" and isinstance(crypto, dict) and "ciphertext" in {str(k).lower() for k in crypto}:
        kdf = crypto.get("kdf") or crypto.get("KDF")
        return {"format": "ethereum-keystore-v3", "address": lower.get("address"),
                "cipher": crypto.get("cipher"), "kdf": kdf, "encrypted_private_material": True}
    if str(lower.get("version")) == "4" and isinstance(crypto, dict) and lower.get("pubkey"):
        return {"format": "eip-2335-keystore", "pubkey": lower.get("pubkey"), "path": lower.get("path"),
                "uuid": lower.get("uuid"), "encrypted_private_material": True}
    if "wallet_type" in lower or "seed_version" in lower:
        keystore = lower.get("keystore") if isinstance(lower.get("keystore"), dict) else {}
        return {"format": "electrum-wallet", "wallet_type": lower.get("wallet_type"),
                "seed_version": lower.get("seed_version"), "keystore_type": keystore.get("type"),
                "watching_only": bool(keystore.get("xpub") and not keystore.get("xprv")),
                "private_material_present": bool(keystore.get("xprv") or keystore.get("seed"))}
    if any(key in lower for key in ("vault", "data")) and any(key in lower for key in ("salt", "iv")):
        return {"format": "browser-wallet-vault", "encrypted_private_material": True,
                "cipher_fields": sorted(key for key in lower if key in {"data", "vault", "salt", "iv"})}
    if "mnemonic" in lower or "seed" in lower or "privatekey" in lower or "private_key" in lower:
        return {"format": "generic-wallet-json", "private_material_present": True,
                "sensitive_fields": sorted(key for key in lower if key in {"mnemonic", "seed", "privatekey", "private_key"})}
    return None


def parse_walletconnect_uri(uri: str) -> dict | None:
    if len(uri) > 8192:
        raise ValueError("WalletConnect URI exceeds cap")
    if not uri.startswith("wc:"):
        return None
    match = re.fullmatch(r"wc:([^@?]+)@(\d+)\?(.*)", uri)
    if not match:
        raise ValueError("malformed WalletConnect URI")
    query = parse_qs(match.group(3), keep_blank_values=True)
    relay = query.get("relay-protocol", [None])[0]
    return {"format": "walletconnect-uri", "topic": match.group(1), "version": int(match.group(2)),
            "relay_protocol": relay, "symmetric_key_present": "symKey" in query or "key" in query}


def analyze_chain_artifact(data: bytes, name: str = "") -> dict:
    if len(data) > MAX_INPUT:
        raise ValueError("artifact exceeds input cap")
    if data.startswith(b"psbt\xff"):
        return parse_psbt(data)
    text = data.decode("utf-8", "replace").strip()
    if text.startswith("wc:"):
        parsed = parse_walletconnect_uri(text)
        assert parsed is not None
        return parsed
    descriptor = classify_descriptor(text)
    if descriptor:
        return descriptor
    extended = classify_extended_key(text)
    if extended:
        return extended
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        document = None
    wallet = classify_wallet(document)
    if wallet:
        return wallet
    if isinstance(document, dict) and isinstance(document.get("input"), str):
        decoded = (decode_calldata(document["input"])
                   if document["input"].lower() not in {"", "0x"}
                   else {"selector": None, "signature": None, "arguments": [], "argument_data": "0x"})
        return {"format": "ethereum-transaction-json", "chain_id": document.get("chainId"),
                "from": document.get("from"), "to": document.get("to"), "value": document.get("value"),
                "calldata": decoded, "typed_transaction": document.get("type"),
                "access_list_entries": len(document.get("accessList", [])) if isinstance(document.get("accessList"), list) else 0,
                "blob_hashes": list(document.get("blobVersionedHashes", []))[:MAX_ITEMS] if isinstance(document.get("blobVersionedHashes"), list) else []}
    if name.lower().endswith((".soltx", ".solana")):
        return parse_solana_transaction(text)
    raise ValueError("unrecognized supported chain artifact")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline wallet/chain artifact and calldata decoder")
    parser.add_argument("artifact", nargs="?", type=Path)
    parser.add_argument("--calldata")
    parser.add_argument("--signature")
    parser.add_argument("--revert")
    parser.add_argument("--pretty", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    if args.calldata:
        report = decode_calldata(args.calldata, args.signature)
    elif args.revert:
        report = decode_revert(args.revert)
    elif args.artifact:
        report = analyze_chain_artifact(args.artifact.read_bytes(), args.artifact.name)
    else:
        parser.print_usage()
        return 2
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
