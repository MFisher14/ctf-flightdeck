#!/usr/bin/env python3
"""Bounded static deobfuscation for saved scripts and managed-code text.

The module never evaluates source, imports an artifact, or invokes a language
runtime.  It recognizes constant-only encodings in supplied JS, PHP,
PowerShell, VBA, and .NET source/decompiler text, reverses explicitly supplied
string ciphers, and reconstructs switch-based control-flow flattening into a
small readable IR.  Compression is capped before output is materialized.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import re
from typing import Iterable
import zlib


MAX_SOURCE = 2 * 1024 * 1024
MAX_LITERAL = 256 * 1024
MAX_DECODED = 4 * 1024 * 1024
MAX_VALUES = 512
MAX_CASES = 512
MAX_NUMBERS = 4096


class DeobfuscationInputError(ValueError):
    """Raised when static input is malformed or exceeds a hard cap."""


@dataclass(frozen=True, slots=True)
class ObfuscationFinding:
    language: str
    technique: str
    evidence: str
    offset: int
    confidence: str
    next_step: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DecodedValue:
    language: str
    technique: str
    value: str
    offset: int
    encoding: str
    confidence: str = "high"

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"offline": True, "executed": False})
        return row


@dataclass(frozen=True, slots=True)
class DecodedLayer:
    index: int
    parent: int | None
    depth: int
    language: str
    technique: str
    value: str
    encoding: str

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"offline": True, "executed": False})
        return row


@dataclass(frozen=True, slots=True)
class FlattenedBlock:
    label: int
    body: str
    successors: tuple[int, ...]
    terminal: bool


@dataclass(frozen=True, slots=True)
class ControlFlowRecovery:
    state_variable: str
    entry: int | None
    blocks: tuple[FlattenedBlock, ...]
    reachable: tuple[int, ...]
    unreachable: tuple[int, ...]
    linear_prefix: tuple[int, ...]
    external_targets: tuple[int, ...]
    readable_ir: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DeobfuscationReport:
    language_leads: tuple[str, ...]
    findings: tuple[ObfuscationFinding, ...]
    decoded_values: tuple[DecodedValue, ...]
    decoded_layers: tuple[DecodedLayer, ...]
    control_flow: ControlFlowRecovery | None

    def to_dict(self) -> dict[str, object]:
        return {
            "language_leads": self.language_leads,
            "findings": tuple(row.to_dict() for row in self.findings),
            "decoded_values": tuple(row.to_dict() for row in self.decoded_values),
            "decoded_layers": tuple(row.to_dict() for row in self.decoded_layers),
            "control_flow": self.control_flow.to_dict() if self.control_flow else None,
            "offline": True,
            "executed": False,
        }


_LANGUAGES = ("javascript", "php", "powershell", "vba", "dotnet")
_TOKEN = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,127}$")
_INTEGER = re.compile(r"(?<![A-Za-z0-9_])(?:0[xX][0-9A-Fa-f]{1,16}|\d{1,20})(?![A-Za-z0-9_])")


def _text(value: str | bytes | bytearray, label: str = "source") -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", "replace")
    else:
        raise DeobfuscationInputError(f"{label} must be text or bytes")
    if len(text.encode("utf-8", "replace")) > MAX_SOURCE:
        raise DeobfuscationInputError(f"{label} exceeds {MAX_SOURCE} bytes")
    return text


def _language(value: str) -> str:
    if not isinstance(value, str):
        raise DeobfuscationInputError("language must be text")
    normalized = value.strip().lower()
    aliases = {"js": "javascript", "ps": "powershell", "ps1": "powershell", "vb": "vba", "csharp": "dotnet", "c#": "dotnet"}
    normalized = aliases.get(normalized, normalized)
    if normalized not in (*_LANGUAGES, "auto"):
        raise DeobfuscationInputError(f"unsupported language {value!r}")
    return normalized


_LANGUAGE_MARKERS: dict[str, tuple[re.Pattern[str], ...]] = {
    "javascript": (
        re.compile(r"\b(?:String\.fromCharCode|atob|unescape|document|window)\b"),
        re.compile(r"\b(?:var|let|const)\s+[A-Za-z_$]"),
    ),
    "php": (
        re.compile(r"<\?php|\$(?:GLOBALS|_[A-Z]+)|\b(?:gzinflate|base64_decode|str_rot13)\s*\(", re.I),
        re.compile(r"\$[A-Za-z_]\w*\s*\.="),
    ),
    "powershell": (
        re.compile(r"\b(?:Invoke-Expression|IEX|FromBase64String|New-Object|Write-Host)\b", re.I),
        re.compile(r"\$(?:env:)?[A-Za-z_]\w*\s*=|\[char\]", re.I),
    ),
    "vba": (
        re.compile(r"\b(?:Sub|Function|End Sub|CreateObject|ChrW?|StrReverse)\b", re.I),
        re.compile(r"\bDim\s+[A-Za-z_]\w*\s+As\b", re.I),
    ),
    "dotnet": (
        re.compile(r"\b(?:System\.(?:Text|Reflection)|Convert\.FromBase64String|Assembly\.Load|IL_[0-9A-Fa-f]{4})\b"),
        re.compile(r"\b(?:ConfuserEx|Dotfuscator|SmartAssembly|Babel\.Obfuscator)\b", re.I),
    ),
}


def detect_languages(source: str | bytes | bytearray) -> tuple[str, ...]:
    """Return language leads only when supplied text contains language markers."""

    text = _text(source)
    scored = []
    for language, patterns in _LANGUAGE_MARKERS.items():
        score = sum(1 for pattern in patterns if pattern.search(text))
        if score:
            scored.append((score, language))
    return tuple(language for _score, language in sorted(scored, key=lambda row: (-row[0], row[1])))


_TECHNIQUES: dict[str, tuple[tuple[str, re.Pattern[str], str, str], ...]] = {
    "javascript": (
        ("dynamic_eval", re.compile(r"\b(?:eval|Function)\s*\("), "high", "Recover constants and review the generated source; do not evaluate it."),
        ("string_array", re.compile(r"\b(?:String\.fromCharCode|atob|unescape)\s*\("), "high", "Decode constant arguments and replace only exact call sites."),
        ("array_rotation", re.compile(r"\b(?:push\s*\(\s*\w+\.shift\s*\(|unshift\s*\(\s*\w+\.pop\s*\()"), "medium", "Reconstruct the bounded literal array and rotation count statically."),
        ("jsfuck_shape", re.compile(r"(?:!\[\]|\+\[\]|\[\]\[\"filter\"\])"), "medium", "Use a token-level decoder in the sandbox; never run the expression."),
    ),
    "php": (
        ("dynamic_eval", re.compile(r"\b(?:eval|assert|create_function)\s*\(", re.I), "high", "Decode the constant argument without invoking PHP."),
        ("layered_decoder", re.compile(r"\b(?:gzinflate|gzdecode|base64_decode|str_rot13)\s*\(", re.I), "high", "Peel only literal, bounded transforms."),
        ("variable_variables", re.compile(r"\$\$|\$\{\$"), "medium", "Resolve literal variable names and keep dynamic names unresolved."),
    ),
    "powershell": (
        ("encoded_command", re.compile(r"(?i)(?:^|\s)-(?:e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{8,}"), "high", "Base64-decode as UTF-16LE and inspect the resulting text."),
        ("dynamic_eval", re.compile(r"\b(?:IEX|Invoke-Expression)\b", re.I), "high", "Recover the expression text but never invoke PowerShell."),
        ("format_operator", re.compile(r"\s-f\s|\[char\]|-join|-bxor", re.I), "medium", "Fold constant formatting, character, and XOR expressions."),
    ),
    "vba": (
        ("character_builder", re.compile(r"\b(?:Chr|ChrW|ChrB|StrReverse)\s*\(", re.I), "high", "Fold constant character and reverse operations."),
        ("dynamic_dispatch", re.compile(r"\b(?:CallByName|Application\.Run|ExecuteGlobal)\b", re.I), "medium", "Resolve literal method names while leaving dynamic dispatch inert."),
        ("xor_loop", re.compile(r"\bXor\b[^\n]{0,160}\bAsc", re.I), "medium", "Extract the literal key and reverse the byte loop with a cap."),
    ),
    "dotnet": (
        ("known_obfuscator", re.compile(r"\b(?:ConfuserEx|ConfusedByAttribute|Dotfuscator|SmartAssembly|Babel\.Obfuscator)\b", re.I), "high", "Use metadata-aware deobfuscation in the networkless Docker sandbox."),
        ("runtime_string_decode", re.compile(r"\b(?:FromBase64String|GetString|String\.Intern)\s*\("), "medium", "Fold constant byte/string transforms only."),
        ("reflection_dispatch", re.compile(r"\b(?:Assembly\.Load|GetMethod|InvokeMember|MethodInfo\.Invoke)\b"), "medium", "Resolve literal metadata tokens and names; do not load the assembly."),
    ),
}


def detect_obfuscation(
    source: str | bytes | bytearray, language: str = "auto"
) -> tuple[ObfuscationFinding, ...]:
    text = _text(source)
    selected = _language(language)
    languages = detect_languages(text) if selected == "auto" else (selected,)
    findings: list[ObfuscationFinding] = []
    for lang in languages:
        for technique, pattern, confidence, next_step in _TECHNIQUES[lang]:
            match = pattern.search(text)
            if match:
                findings.append(
                    ObfuscationFinding(
                        lang,
                        technique,
                        text[max(0, match.start() - 40) : min(len(text), match.end() + 80)],
                        match.start(),
                        confidence,
                        next_step,
                    )
                )
    return tuple(sorted(findings, key=lambda row: (row.offset, row.language, row.technique)))


def _decode_base64(value: str) -> bytes | None:
    if not 4 <= len(value) <= MAX_LITERAL or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value):
        return None
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return None
    return data if len(data) <= MAX_DECODED else None


def _printable(text: str) -> bool:
    if not text:
        return False
    visible = sum(char.isprintable() or char in "\r\n\t" for char in text)
    return visible / len(text) >= 0.85


def _text_decodings(data: bytes, preferred: str | None = None) -> tuple[tuple[str, str], ...]:
    encodings = [preferred] if preferred else []
    encodings.extend(("utf-8", "utf-16le", "utf-16be"))
    rows: list[tuple[str, str]] = []
    for encoding in encodings:
        if not encoding or any(encoding == seen for seen, _text_value in rows):
            continue
        if encoding.startswith("utf-16") and len(data) % 2:
            continue
        try:
            value = data.decode(encoding)
        except UnicodeError:
            continue
        value = value.lstrip("\ufeff")
        if _printable(value) and value not in {item[1] for item in rows}:
            rows.append((encoding, value))
    return tuple(rows)


def _inflate(data: bytes, wbits: int) -> bytes | None:
    try:
        stream = zlib.decompressobj(wbits)
        out = stream.decompress(data, MAX_DECODED + 1)
        if len(out) > MAX_DECODED or stream.unconsumed_tail or not stream.eof:
            return None
        tail = stream.flush(MAX_DECODED + 1 - len(out))
        out += tail
    except zlib.error:
        return None
    return out if len(out) <= MAX_DECODED else None


def _rot13(value: str) -> str:
    lower = "abcdefghijklmnopqrstuvwxyz"
    upper = lower.upper()
    table = str.maketrans(lower + upper, lower[13:] + lower[:13] + upper[13:] + upper[:13])
    return value.translate(table)


def _decode_escapes(value: str) -> str | None:
    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        if index + 1 >= len(value):
            return None
        kind = value[index + 1]
        if kind == "x" and index + 3 < len(value) and re.fullmatch(r"[0-9A-Fa-f]{2}", value[index + 2 : index + 4]):
            out.append(chr(int(value[index + 2 : index + 4], 16)))
            index += 4
        elif kind == "u" and index + 5 < len(value) and re.fullmatch(r"[0-9A-Fa-f]{4}", value[index + 2 : index + 6]):
            out.append(chr(int(value[index + 2 : index + 6], 16)))
            index += 6
        elif kind in "nrt\\\"'":
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(kind, kind))
            index += 2
        else:
            return None
        if len(out) > MAX_DECODED:
            return None
    return "".join(out)


def _numbers(value: str) -> tuple[int, ...] | None:
    tokens = re.findall(r"0[xX][0-9A-Fa-f]+|\d+", value)
    if not tokens or len(tokens) > MAX_NUMBERS:
        return None
    numbers = tuple(int(token, 0) for token in tokens)
    return numbers if all(0 <= number <= 0x10FFFF for number in numbers) else None


def _add_decoded(
    rows: list[DecodedValue], language: str, technique: str, value: str,
    offset: int, encoding: str, confidence: str = "high",
) -> None:
    if not value or len(value.encode("utf-8", "replace")) > MAX_DECODED:
        return
    key = (language, technique, value, offset, encoding)
    if key not in {(row.language, row.technique, row.value, row.offset, row.encoding) for row in rows}:
        rows.append(DecodedValue(language, technique, value, offset, encoding, confidence))


def recover_constant_strings(
    source: str | bytes | bytearray, language: str = "auto"
) -> tuple[DecodedValue, ...]:
    """Recover constant-only encoded strings without evaluating source."""

    text = _text(source)
    selected = _language(language)
    languages = detect_languages(text) if selected == "auto" else (selected,)
    rows: list[DecodedValue] = []

    for lang in languages:
        if lang in {"javascript", "php", "powershell", "dotnet"}:
            patterns = {
                "javascript": r"\batob\s*\(\s*(['\"])([A-Za-z0-9+/]{4,}={0,2})\1\s*\)",
                "php": r"\bbase64_decode\s*\(\s*(['\"])([A-Za-z0-9+/]{4,}={0,2})\1\s*\)",
                "powershell": r"\bFromBase64String\s*\(\s*(['\"])([A-Za-z0-9+/]{4,}={0,2})\1\s*\)",
                "dotnet": r"\bFromBase64String\s*\(\s*(['\"])([A-Za-z0-9+/]{4,}={0,2})\1\s*\)",
            }
            for match in re.finditer(patterns[lang], text, re.I):
                data = _decode_base64(match.group(2))
                if data is not None:
                    preferred = "utf-16le" if lang == "powershell" else None
                    for encoding, value in _text_decodings(data, preferred):
                        _add_decoded(rows, lang, "base64_literal", value, match.start(), encoding)

        if lang == "powershell":
            for match in re.finditer(r"(?i)(?:^|\s)-(?:e|en|enc|enco|encodedcommand)\s+([A-Za-z0-9+/]{8,}={0,2})", text):
                data = _decode_base64(match.group(1))
                if data is not None:
                    for encoding, value in _text_decodings(data, "utf-16le"):
                        _add_decoded(rows, lang, "encoded_command", value, match.start(1), encoding)

        if lang == "php":
            layered = re.compile(
                r"(?i)\bgzinflate\s*\(\s*base64_decode\s*\(\s*(['\"])([A-Za-z0-9+/]{8,}={0,2})\1\s*\)\s*\)"
            )
            for match in layered.finditer(text):
                encoded = _decode_base64(match.group(2))
                inflated = _inflate(encoded, -zlib.MAX_WBITS) if encoded is not None else None
                if inflated is not None:
                    for encoding, value in _text_decodings(inflated):
                        _add_decoded(rows, lang, "base64_gzinflate", value, match.start(), encoding)
            for match in re.finditer(r"(?i)\bstr_rot13\s*\(\s*(['\"])([^'\"\r\n]{1,262144})\1\s*\)", text):
                _add_decoded(rows, lang, "rot13_literal", _rot13(match.group(2)), match.start(), "rot13")

        if lang in {"javascript", "vba", "php", "powershell", "dotnet"}:
            char_patterns = {
                "javascript": r"\bString\.fromCharCode\s*\(([^)]{1,262144})\)",
                "vba": r"(?i)((?:ChrW?\s*\(\s*(?:0[xX][0-9A-Fa-f]+|\d+)\s*\)\s*(?:&|\+)\s*)+ChrW?\s*\(\s*(?:0[xX][0-9A-Fa-f]+|\d+)\s*\))",
                "php": r"(?i)((?:chr\s*\(\s*(?:0[xX][0-9A-Fa-f]+|\d+)\s*\)\s*\.\s*)+chr\s*\(\s*(?:0[xX][0-9A-Fa-f]+|\d+)\s*\))",
                "powershell": r"(?i)((?:\[char\]\s*(?:0[xX][0-9A-Fa-f]+|\d+)\s*\+\s*)+\[char\]\s*(?:0[xX][0-9A-Fa-f]+|\d+))",
                "dotnet": r"(?i)new\s+char\s*\[\s*\]\s*\{([^}]{1,262144})\}",
            }
            for match in re.finditer(char_patterns[lang], text):
                numbers = _numbers(match.group(1))
                if numbers is not None:
                    value = "".join(chr(number) for number in numbers)
                    if _printable(value):
                        _add_decoded(rows, lang, "character_constants", value, match.start(), "codepoints")

        if lang == "vba":
            for match in re.finditer(r"(?i)\bStrReverse\s*\(\s*(['\"])([^'\"\r\n]{1,262144})\1\s*\)", text):
                _add_decoded(rows, lang, "reverse_literal", match.group(2)[::-1], match.start(), "reverse")

        if lang == "javascript":
            for match in re.finditer(r"(['\"])((?:(?:\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4})){2,})\1", text):
                value = _decode_escapes(match.group(2))
                if value is not None:
                    _add_decoded(rows, lang, "escaped_literal", value, match.start(), "js-escapes")

        if len(rows) >= MAX_VALUES:
            break
    rows.extend(recover_xor_array_strings(text, selected))
    unique: dict[tuple[str, str, str, int, str], DecodedValue] = {}
    for row in rows:
        unique.setdefault((row.language, row.technique, row.value, row.offset, row.encoding), row)
    return tuple(
        sorted(unique.values(), key=lambda row: (row.offset, row.language, row.technique, row.value))[:MAX_VALUES]
    )


_NUMBER_TOKEN = r"(?:0[xX][0-9A-Fa-f]{1,2}|\d{1,3})"
_NUMBER_LIST = rf"({_NUMBER_TOKEN}(?:\s*,\s*{_NUMBER_TOKEN}){{1,4095}})"
_XOR_ARRAY_PATTERNS: dict[str, re.Pattern[str]] = {
    "javascript": re.compile(
        rf"\[{_NUMBER_LIST}\]\s*\.map\s*\([^)]{{1,256}}?\^\s*({_NUMBER_TOKEN})[^)]*\)", re.I
    ),
    "php": re.compile(
        rf"\barray\s*\({_NUMBER_LIST}\)[^\n]{{0,256}}?\^\s*({_NUMBER_TOKEN})", re.I
    ),
    "powershell": re.compile(
        rf"@\({_NUMBER_LIST}\)[^\n]{{0,256}}?-bxor\s*({_NUMBER_TOKEN})", re.I
    ),
    "vba": re.compile(
        rf"\bArray\s*\({_NUMBER_LIST}\)[^\n]{{0,256}}?\bXor\s*({_NUMBER_TOKEN})", re.I
    ),
    "dotnet": re.compile(
        rf"new\s+byte\s*\[\s*\]\s*\{{{_NUMBER_LIST}\}}[^\n]{{0,256}}?\^\s*({_NUMBER_TOKEN})",
        re.I,
    ),
}


def recover_xor_array_strings(
    source: str | bytes | bytearray, language: str = "auto"
) -> tuple[DecodedValue, ...]:
    """Recover constant numeric byte arrays paired with a literal XOR key."""

    text = _text(source)
    selected = _language(language)
    languages = detect_languages(text) if selected == "auto" else (selected,)
    rows: list[DecodedValue] = []
    for lang in languages:
        pattern = _XOR_ARRAY_PATTERNS.get(lang)
        if pattern is None:
            continue
        for match in pattern.finditer(text):
            values = _numbers(match.group(1))
            if values is None or any(value > 255 for value in values):
                continue
            key = int(match.group(2), 0)
            if not 0 <= key <= 255:
                continue
            decoded = bytes(value ^ key for value in values)
            candidates = list(_text_decodings(decoded, "utf-8"))
            if not candidates:
                latin = decoded.decode("latin-1")
                candidates = [("latin-1", latin)] if _printable(latin) else []
            for encoding, value in candidates:
                _add_decoded(rows, lang, "xor_numeric_array", value, match.start(), f"{encoding}+xor-0x{key:02x}")
            if len(rows) >= MAX_VALUES:
                break
    return tuple(sorted(rows[:MAX_VALUES], key=lambda row: (row.offset, row.language, row.value)))


def peel_constant_layers(
    source: str | bytes | bytearray,
    *,
    language: str = "auto",
    max_depth: int = 4,
    max_nodes: int = 128,
) -> tuple[DecodedLayer, ...]:
    """Breadth-first peel nested constant encodings with strict depth/size caps."""

    root = _text(source)
    selected = _language(language)
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 1 <= max_depth <= 8:
        raise DeobfuscationInputError("max_depth must be an integer from 1 to 8")
    if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or not 1 <= max_nodes <= 512:
        raise DeobfuscationInputError("max_nodes must be an integer from 1 to 512")
    queue: list[tuple[str, int, int | None]] = [(root, 0, None)]
    seen = {root}
    layers: list[DecodedLayer] = []
    total = len(root.encode("utf-8", "replace"))
    while queue and len(layers) < max_nodes:
        current, depth, parent = queue.pop(0)
        if depth >= max_depth:
            continue
        rows = recover_constant_strings(current, selected)
        for row in rows:
            if row.value in seen:
                continue
            encoded_size = len(row.value.encode("utf-8", "replace"))
            if total + encoded_size > MAX_DECODED * 2:
                return tuple(layers)
            seen.add(row.value)
            index = len(layers)
            layer = DecodedLayer(
                index,
                parent,
                depth + 1,
                row.language,
                row.technique,
                row.value,
                row.encoding,
            )
            layers.append(layer)
            total += encoded_size
            if len(layers) >= max_nodes:
                break
            queue.append((row.value, depth + 1, index))
    return tuple(layers)


def reverse_string_cipher(
    ciphertext: bytes | bytearray | str,
    *,
    scheme: str,
    key: bytes | bytearray | str | int,
    seed: int = 0,
    multiplier: int = 1103515245,
    increment: int = 12345,
) -> bytes:
    """Reverse explicit XOR/add/sub/rolling-XOR string transforms."""

    if isinstance(ciphertext, str):
        data = ciphertext.encode("latin-1", "strict")
    elif isinstance(ciphertext, (bytes, bytearray)):
        data = bytes(ciphertext)
    else:
        raise DeobfuscationInputError("ciphertext must be bytes or Latin-1 text")
    if len(data) > MAX_DECODED:
        raise DeobfuscationInputError("ciphertext exceeds the decoded-output cap")
    normalized = scheme.strip().lower() if isinstance(scheme, str) else ""
    if isinstance(key, int) and not isinstance(key, bool):
        if not 0 <= key <= 255:
            raise DeobfuscationInputError("integer key must be a byte")
        key_bytes = bytes((key,))
    elif isinstance(key, str):
        key_bytes = key.encode("utf-8")
    elif isinstance(key, (bytes, bytearray)):
        key_bytes = bytes(key)
    else:
        raise DeobfuscationInputError("key must be an integer byte, text, or bytes")
    if not key_bytes or len(key_bytes) > 4096:
        raise DeobfuscationInputError("key must contain 1..4096 bytes")
    if normalized in {"xor", "repeating_xor"}:
        return bytes(value ^ key_bytes[index % len(key_bytes)] for index, value in enumerate(data))
    if normalized == "add":
        return bytes((value - key_bytes[index % len(key_bytes)]) & 0xFF for index, value in enumerate(data))
    if normalized == "sub":
        return bytes((value + key_bytes[index % len(key_bytes)]) & 0xFF for index, value in enumerate(data))
    if normalized == "rolling_xor":
        if any(not isinstance(item, int) or isinstance(item, bool) for item in (seed, multiplier, increment)):
            raise DeobfuscationInputError("rolling parameters must be integers")
        state = seed & 0xFFFFFFFF
        out = bytearray()
        for value in data:
            state = (state * multiplier + increment) & 0xFFFFFFFF
            out.append(value ^ (state & 0xFF))
        return bytes(out)
    raise DeobfuscationInputError(f"unsupported string cipher {scheme!r}")


_CASE = re.compile(r"(?im)^\s*case\s+(0[xX][0-9A-Fa-f]+|\d+)\s*:\s*")


def recover_flattened_switch(
    supplied_ir: str | bytes | bytearray,
    *,
    state_variable: str = "state",
    entry: int | None = None,
) -> ControlFlowRecovery:
    """Recover literal state edges from a saved switch-dispatch IR listing."""

    text = _text(supplied_ir, "supplied_ir")
    if not isinstance(state_variable, str) or not _TOKEN.fullmatch(state_variable):
        raise DeobfuscationInputError("state_variable must be a conservative identifier")
    matches = list(_CASE.finditer(text))
    if not matches:
        return ControlFlowRecovery(state_variable, entry, (), (), (), (), (), "")
    if len(matches) > MAX_CASES:
        raise DeobfuscationInputError(f"switch exceeds {MAX_CASES} cases")
    labels = [int(match.group(1), 0) for match in matches]
    if len(labels) != len(set(labels)):
        raise DeobfuscationInputError("switch contains duplicate literal case labels")
    blocks: list[FlattenedBlock] = []
    assignment = re.compile(
        rf"\b{re.escape(state_variable)}\s*=\s*(0[xX][0-9A-Fa-f]+|\d+)\s*;?"
    )
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[match.end() : end]
        default = re.search(r"(?im)^\s*default\s*:", body)
        if default:
            body = body[: default.start()]
        successors = tuple(dict.fromkeys(int(item.group(1), 0) for item in assignment.finditer(body)))
        terminal = bool(re.search(r"(?m)\b(?:return|throw|exit|ret)\b", body)) and not successors
        cleaned = "\n".join(line.rstrip() for line in body.strip().splitlines())[:MAX_LITERAL]
        blocks.append(FlattenedBlock(labels[index], cleaned, successors, terminal))

    if entry is not None:
        if isinstance(entry, bool) or not isinstance(entry, int) or entry < 0:
            raise DeobfuscationInputError("entry must be a non-negative integer")
        chosen_entry = entry
    else:
        before = text[: matches[0].start()]
        initializers = list(assignment.finditer(before))
        chosen_entry = int(initializers[-1].group(1), 0) if initializers else labels[0]

    table = {block.label: block for block in blocks}
    reachable: list[int] = []
    queue = [chosen_entry] if chosen_entry in table else []
    while queue:
        label = queue.pop(0)
        if label in reachable:
            continue
        reachable.append(label)
        queue.extend(target for target in table[label].successors if target in table and target not in reachable)
    unreachable = tuple(label for label in labels if label not in reachable)
    external = tuple(sorted({target for block in blocks for target in block.successors if target not in table}))
    linear: list[int] = []
    cursor = chosen_entry
    while cursor in table and cursor not in linear:
        linear.append(cursor)
        successors = tuple(target for target in table[cursor].successors if target in table)
        if len(successors) != 1:
            break
        cursor = successors[0]

    ir_rows: list[str] = []
    for block in blocks:
        ir_rows.append(f"block_0x{block.label:x}:")
        for line in block.body.splitlines():
            if not assignment.fullmatch(line.strip()):
                ir_rows.append("  " + line.strip())
        if block.successors:
            rendered = ", ".join(f"block_0x{target:x}" for target in block.successors)
            ir_rows.append(("  goto " if len(block.successors) == 1 else "  branch ") + rendered)
        elif block.terminal:
            ir_rows.append("  terminal")
        else:
            ir_rows.append("  fallthrough_unknown")
    return ControlFlowRecovery(
        state_variable,
        chosen_entry,
        tuple(blocks),
        tuple(reachable),
        unreachable,
        tuple(linear),
        external,
        "\n".join(ir_rows),
    )


_OPAQUE: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("constant_true", re.compile(r"(?i)\bif\s*\(\s*(?:1\s*==\s*1|true)\s*\)"), "always true"),
    ("constant_false", re.compile(r"(?i)\bif\s*\(\s*(?:1\s*==\s*0|false)\s*\)"), "always false"),
    ("self_xor_zero", re.compile(r"\bif\s*\(\s*\(?\s*([A-Za-z_$]\w*)\s*\^\s*\1\s*\)?\s*==\s*0\s*\)"), "always true for integer operands"),
    ("consecutive_product_even", re.compile(r"\bif\s*\([^\n]{0,80}\b([A-Za-z_$]\w*)\s*\*\s*\(\s*\1\s*\+\s*1\s*\)[^\n]{0,80}%\s*2\s*==\s*0\s*\)"), "always true for integer operands"),
)


def find_opaque_predicates(
    supplied_ir: str | bytes | bytearray,
) -> tuple[ObfuscationFinding, ...]:
    text = _text(supplied_ir, "supplied_ir")
    rows = []
    for name, pattern, proof in _OPAQUE:
        for match in pattern.finditer(text):
            rows.append(
                ObfuscationFinding(
                    "ir",
                    name,
                    match.group(0)[:240],
                    match.start(),
                    "high",
                    f"Replace this branch with its proven outcome ({proof}) in a copy of the IR.",
                )
            )
            if len(rows) >= MAX_VALUES:
                break
    return tuple(sorted(rows, key=lambda row: (row.offset, row.technique)))


def deobfuscate_source(
    source: str | bytes | bytearray,
    *,
    language: str = "auto",
    state_variable: str | None = None,
) -> DeobfuscationReport:
    """Run the bounded static passes and return evidence, never executable output."""

    text = _text(source)
    selected = _language(language)
    languages = detect_languages(text) if selected == "auto" else (selected,)
    findings = list(detect_obfuscation(text, selected))
    findings.extend(find_opaque_predicates(text))
    control_flow = None
    if _CASE.search(text):
        control_flow = recover_flattened_switch(text, state_variable=state_variable or "state")
    return DeobfuscationReport(
        languages,
        tuple(sorted(findings, key=lambda row: (row.offset, row.language, row.technique))),
        recover_constant_strings(text, selected),
        peel_constant_layers(text, language=selected),
        control_flow,
    )


def rows_as_dicts(
    rows: Iterable[ObfuscationFinding | DecodedValue | DecodedLayer],
) -> tuple[dict[str, object], ...]:
    return tuple(row.to_dict() for row in rows)
