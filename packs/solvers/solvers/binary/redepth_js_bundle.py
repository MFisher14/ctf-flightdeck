#!/usr/bin/env python3
"""Static recovery for modern JavaScript string arrays and webpack bundles.

The input is treated as text only.  This module never invokes Node, a browser,
``eval`` or a JavaScript VM.  It recognizes a deliberately bounded subset that
is common in javascript-obfuscator/obfuscator.io output:

* literal string-array providers;
* numeric index wrappers with optional Base64 or RC4 decoding;
* the array-rotation checksum loop emitted by javascript-obfuscator; and
* webpack 4/5 chunk/module registries.

Anything outside that subset is preserved as an unsupported lead instead of
being executed.  Every public parser either succeeds or raises only
``RedepthJSError``.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Callable


MAX_SOURCE = 8 << 20
MAX_ARRAYS = 128
MAX_ARRAY_VALUES = 16_384
MAX_LITERAL_BYTES = 1 << 20
MAX_MODULES = 16_384
MAX_NESTING = 512
MAX_EXPRESSION_TOKENS = 4096
MAX_ROTATIONS = 4_096
_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"


class RedepthJSError(ValueError):
    """Malformed, unsupported, ambiguous, or cap-exceeding static JS input."""


@dataclass(frozen=True)
class StringArray:
    name: str
    provider: str | None
    offset: int
    raw_values: tuple[str, ...]
    rotation: int | None
    values: tuple[str, ...]


@dataclass(frozen=True)
class Decoder:
    name: str
    array_name: str
    index_base: int
    encoding: str
    offset: int


@dataclass(frozen=True)
class DecodedCall:
    decoder: str
    offset: int
    argument: int
    key: str | None
    array_index: int
    value: str


@dataclass(frozen=True)
class WebpackModule:
    module_id: str
    chunk_ids: tuple[str, ...]
    offset: int
    size: int
    sha256: str
    strings: tuple[str, ...]
    requires: tuple[str, ...]


@dataclass(frozen=True)
class JSBundleReport:
    string_arrays: tuple[StringArray, ...]
    decoders: tuple[Decoder, ...]
    decoded_calls: tuple[DecodedCall, ...]
    webpack_modules: tuple[WebpackModule, ...]
    indicators: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _source(value: str | bytes) -> str:
    if isinstance(value, bytes):
        if len(value) > MAX_SOURCE:
            raise RedepthJSError("JavaScript source exceeds the 8 MiB cap")
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RedepthJSError("JavaScript source is not UTF-8") from exc
    if not isinstance(value, str):
        raise RedepthJSError("JavaScript source must be str or bytes")
    if len(value.encode("utf-8", "surrogatepass")) > MAX_SOURCE:
        raise RedepthJSError("JavaScript source exceeds the 8 MiB cap")
    return value


def _skip_space(text: str, at: int, end: int | None = None) -> int:
    stop = len(text) if end is None else end
    while at < stop:
        if text[at].isspace():
            at += 1
            continue
        if text.startswith("//", at):
            line = text.find("\n", at + 2, stop)
            at = stop if line < 0 else line + 1
            continue
        if text.startswith("/*", at):
            close = text.find("*/", at + 2, stop)
            if close < 0:
                raise RedepthJSError("unterminated JavaScript block comment")
            at = close + 2
            continue
        break
    return at


def _skip_quoted(text: str, at: int, quote: str) -> int:
    cursor = at + 1
    while cursor < len(text):
        char = text[cursor]
        if char == "\\":
            cursor += 2
            continue
        if char == quote:
            return cursor + 1
        if char in "\r\n" and quote != "`":
            raise RedepthJSError("newline in JavaScript string literal")
        cursor += 1
    raise RedepthJSError("unterminated JavaScript literal")


def _regex_context(text: str, slash: int) -> bool:
    """Conservative test for a regex literal rather than division."""
    cursor = slash - 1
    while cursor >= 0 and text[cursor].isspace():
        cursor -= 1
    if cursor < 0 or text[cursor] in "([{,:;=!?&|+-*%^~<>\n":
        return True
    prefix = text[max(0, cursor - 12):cursor + 1]
    return bool(re.search(r"(?:^|\W)(?:return|throw|case|delete|void|typeof|instanceof|in|of)$", prefix))


def _skip_regex(text: str, at: int) -> int:
    cursor, in_class = at + 1, False
    while cursor < len(text):
        char = text[cursor]
        if char == "\\":
            cursor += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            cursor += 1
            while cursor < len(text) and text[cursor].isalpha():
                cursor += 1
            return cursor
        elif char in "\r\n":
            raise RedepthJSError("unterminated JavaScript regex literal")
        cursor += 1
    raise RedepthJSError("unterminated JavaScript regex literal")


_PAIRS = {"(": ")", "[": "]", "{": "}"}


def _matching(text: str, at: int) -> int:
    """Return the offset just after a balanced JS delimiter."""
    if at < 0 or at >= len(text) or text[at] not in _PAIRS:
        raise RedepthJSError("matching scan did not start on a delimiter")
    stack = [text[at]]
    cursor = at + 1
    while cursor < len(text):
        char = text[cursor]
        if char in "'\"`":
            cursor = _skip_quoted(text, cursor, char)
            continue
        if text.startswith("//", cursor):
            line = text.find("\n", cursor + 2)
            cursor = len(text) if line < 0 else line + 1
            continue
        if text.startswith("/*", cursor):
            close = text.find("*/", cursor + 2)
            if close < 0:
                raise RedepthJSError("unterminated JavaScript block comment")
            cursor = close + 2
            continue
        if char == "/" and _regex_context(text, cursor):
            cursor = _skip_regex(text, cursor)
            continue
        if char in _PAIRS:
            stack.append(char)
            if len(stack) > MAX_NESTING:
                raise RedepthJSError("JavaScript nesting exceeds cap")
        elif char in ")]}":
            if not stack or _PAIRS[stack[-1]] != char:
                raise RedepthJSError("unbalanced JavaScript delimiters")
            stack.pop()
            if not stack:
                return cursor + 1
        cursor += 1
    raise RedepthJSError("unterminated JavaScript delimiter")


def _js_string(token: str) -> str:
    if len(token) < 2 or token[0] not in "'\"" or token[-1] != token[0]:
        raise RedepthJSError("unsupported JavaScript string token")
    out: list[str] = []
    cursor = 1
    output_length = 0
    while cursor < len(token) - 1:
        char = token[cursor]
        if char != "\\":
            out.append(char)
            output_length += 1
            if output_length > MAX_LITERAL_BYTES:
                raise RedepthJSError("decoded JavaScript literal exceeds cap")
            cursor += 1
            continue
        cursor += 1
        if cursor >= len(token) - 1:
            raise RedepthJSError("truncated JavaScript escape")
        esc = token[cursor]
        cursor += 1
        old_count = len(out)
        simple = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v",
                  "0": "\0", "\\": "\\", "'": "'", '"': '"'}
        if esc in simple:
            out.append(simple[esc])
        elif esc == "x":
            raw = token[cursor:cursor + 2]
            if len(raw) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{2}", raw):
                raise RedepthJSError("invalid JavaScript hex escape")
            out.append(chr(int(raw, 16)))
            cursor += 2
        elif esc == "u":
            if cursor < len(token) - 1 and token[cursor] == "{":
                close = token.find("}", cursor + 1, len(token) - 1)
                if close < 0 or not re.fullmatch(r"[0-9A-Fa-f]{1,6}", token[cursor + 1:close]):
                    raise RedepthJSError("invalid JavaScript Unicode escape")
                value = int(token[cursor + 1:close], 16)
                cursor = close + 1
            else:
                raw = token[cursor:cursor + 4]
                if len(raw) != 4 or not re.fullmatch(r"[0-9A-Fa-f]{4}", raw):
                    raise RedepthJSError("invalid JavaScript Unicode escape")
                value = int(raw, 16)
                cursor += 4
            if value > 0x10FFFF:
                raise RedepthJSError("JavaScript Unicode escape is out of range")
            out.append(chr(value))
        elif esc in "\r\n":
            if esc == "\r" and cursor < len(token) - 1 and token[cursor] == "\n":
                cursor += 1
        else:
            # ECMAScript NonEscapeCharacter: the backslash is removed.
            out.append(esc)
        output_length += len(out) - old_count
        if output_length > MAX_LITERAL_BYTES:
            raise RedepthJSError("decoded JavaScript literal exceeds cap")
    return "".join(out)


def _literal_array(text: str, opening: int) -> tuple[tuple[str, ...], int] | None:
    close = _matching(text, opening)
    cursor, values = opening + 1, []
    while True:
        cursor = _skip_space(text, cursor, close - 1)
        if cursor >= close - 1:
            break
        if text[cursor] not in "'\"":
            return None
        end = _skip_quoted(text, cursor, text[cursor])
        values.append(_js_string(text[cursor:end]))
        if len(values) > MAX_ARRAY_VALUES:
            raise RedepthJSError("JavaScript string array exceeds value cap")
        cursor = _skip_space(text, end, close - 1)
        if cursor < close - 1:
            if text[cursor] != ",":
                return None
            cursor += 1
    return tuple(values), close


def _arrays(text: str) -> tuple[dict[str, StringArray], dict[str, str]]:
    found: dict[str, StringArray] = {}
    providers: dict[str, str] = {}
    declaration = re.compile(rf"\b(?:var|let|const)\s+({_IDENT})\s*=\s*\[")
    for match in declaration.finditer(text):
        parsed = _literal_array(text, match.end() - 1)
        if parsed is None:
            continue
        values, _close = parsed
        if not values:
            continue
        name = match.group(1)
        found.setdefault(name, StringArray(name, None, match.start(), values, 0, values))
        if len(found) > MAX_ARRAYS:
            raise RedepthJSError("JavaScript string-array count exceeds cap")
    # javascript-obfuscator puts the array in a provider that redefines itself.
    function = re.compile(rf"\bfunction\s+({_IDENT})\s*\([^)]*\)\s*\{{")
    for match in function.finditer(text):
        body_end = _matching(text, match.end() - 1)
        body = text[match.end():body_end - 1]
        provider = match.group(1)
        array_name = next((name for name in found if re.search(
            rf"\b{re.escape(provider)}\s*=\s*function\s*\([^)]*\)\s*\{{\s*return\s+{re.escape(name)}\s*;?",
            body,
        )), None)
        if array_name is not None:
            providers[provider] = array_name
            row = found[array_name]
            found[array_name] = StringArray(row.name, provider, row.offset, row.raw_values,
                                            None, row.values)
    return found, providers


def _integer(token: str) -> int:
    raw = token.strip()
    if not re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|\d+)", raw):
        raise RedepthJSError("unsupported JavaScript integer")
    value = int(raw, 0)
    if not 0 <= value < (1 << 53):
        raise RedepthJSError("JavaScript integer exceeds exact range")
    return value


def _decoders(text: str, providers: dict[str, str], arrays: dict[str, StringArray]) -> dict[str, Decoder]:
    found: dict[str, Decoder] = {}
    function = re.compile(rf"\bfunction\s+({_IDENT})\s*\(\s*({_IDENT})(?:\s*,\s*({_IDENT}))?\s*\)\s*\{{")
    for match in function.finditer(text):
        end = _matching(text, match.end() - 1)
        body = text[match.end():end - 1]
        name, index_name = match.group(1), match.group(2)
        base_match = re.search(
            rf"\b{re.escape(index_name)}\s*(?:=\s*{re.escape(index_name)}\s*-|-=)\s*(0[xX][0-9A-Fa-f]+|\d+)",
            body,
        )
        base = _integer(base_match.group(1)) if base_match else 0
        provider = next((item for item in providers if re.search(rf"\b{re.escape(item)}\s*\(\s*\)", body)), None)
        array_name = providers.get(provider) if provider else next((item for item in arrays if re.search(
            rf"\b{re.escape(item)}\s*\[\s*{re.escape(index_name)}\s*\]", body)), None)
        if array_name is None:
            continue
        if not (re.search(rf"\[\s*{re.escape(index_name)}\s*\]", body)
                or re.search(rf"\[\s*{re.escape(index_name)}\s*-", body)):
            continue
        encoding = "plain"
        if "decodeURIComponent" in body or "atob" in body:
            encoding = "base64"
        if (encoding == "base64" and "charCodeAt" in body
                and re.search(r"(?:0x100|256)", body)
                and match.group(3) is not None):
            encoding = "rc4"
        found[name] = Decoder(name, array_name, base, encoding, match.start())
    return found


_OBFUSCATOR_B64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
_STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_OBFUSCATOR_B64_TRANS = str.maketrans(_OBFUSCATOR_B64, _STANDARD_B64)


def _base64_bytes(value: str) -> bytes:
    try:
        # javascript-obfuscator's helper uses a lowercase-first alphabet.  It
        # is Base64 by index, but is not RFC 4648's letter ordering.
        raw = value.translate(_OBFUSCATOR_B64_TRANS).encode("ascii")
        raw += b"=" * (-len(raw) % 4)
        return base64.b64decode(raw, validate=True)
    except (UnicodeError, ValueError) as exc:
        raise RedepthJSError("invalid Base64 string-array entry") from exc


def _base64(value: str) -> str:
    try:
        return _base64_bytes(value).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RedepthJSError("Base64 string-array output is not UTF-8") from exc


def _rc4(value: str, key: str) -> str:
    try:
        data = _base64_bytes(value)
        key_bytes = key.encode("utf-8")
    except (UnicodeError, ValueError) as exc:
        raise RedepthJSError("invalid RC4 string-array input") from exc
    if not key_bytes or len(key_bytes) > 4096:
        raise RedepthJSError("RC4 key is empty or over cap")
    box = list(range(256))
    cursor = 0
    for index in range(256):
        cursor = (cursor + box[index] + key_bytes[index % len(key_bytes)]) & 0xFF
        box[index], box[cursor] = box[cursor], box[index]
    left = right = 0
    output = bytearray()
    for byte in data:
        left = (left + 1) & 0xFF
        right = (right + box[left]) & 0xFF
        box[left], box[right] = box[right], box[left]
        output.append(byte ^ box[(box[left] + box[right]) & 0xFF])
    try:
        return bytes(output).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RedepthJSError("RC4 string-array output is not UTF-8") from exc


def _decode_value(value: str, encoding: str, key: str | None) -> str:
    if encoding == "plain":
        return value
    if encoding == "base64":
        return _base64(value)
    if encoding == "rc4" and key is not None:
        return _rc4(value, key)
    raise RedepthJSError("RC4 decoder call lacks a literal key")


@dataclass(frozen=True)
class _ExprToken:
    kind: str
    value: str


def _expr_tokens(text: str) -> tuple[_ExprToken, ...]:
    rows: list[_ExprToken] = []
    cursor = 0
    while cursor < len(text):
        if text[cursor].isspace():
            cursor += 1
            continue
        if text[cursor] in "'\"":
            end = _skip_quoted(text, cursor, text[cursor])
            rows.append(_ExprToken("string", text[cursor:end]))
            cursor = end
        else:
            match = re.match(r"0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?|[A-Za-z_$][A-Za-z0-9_$]*|===|!==|==|!=|[()+\-*/%,]", text[cursor:])
            if not match:
                raise RedepthJSError("unsupported token in rotation checksum")
            value = match.group(0)
            kind = "number" if re.fullmatch(r"0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?", value) else "ident" if re.fullmatch(_IDENT, value) else "punct"
            rows.append(_ExprToken(kind, value))
            cursor += len(value)
        if len(rows) > MAX_EXPRESSION_TOKENS:
            raise RedepthJSError("rotation checksum exceeds token cap")
    rows.append(_ExprToken("eof", ""))
    return tuple(rows)


class _Expression:
    def __init__(self, expression: str, calls: dict[str, Callable[[int, str | None], str]]):
        self.tokens = _expr_tokens(expression)
        self.index = 0
        self.calls = calls

    def _peek(self, value: str | None = None) -> _ExprToken:
        token = self.tokens[self.index]
        if value is not None and token.value != value:
            raise RedepthJSError(f"expected {value!r} in rotation checksum")
        return token

    def _take(self, value: str | None = None) -> _ExprToken:
        token = self._peek(value)
        self.index += 1
        return token

    def parse(self) -> float | str:
        result = self._sum()
        if self._peek().kind != "eof":
            raise RedepthJSError("trailing rotation-checksum expression")
        return result

    def _sum(self) -> float | str:
        left = self._product()
        while self._peek().value in {"+", "-"}:
            op = self._take().value
            right = self._product()
            if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
                raise RedepthJSError("non-numeric checksum arithmetic")
            left = left + right if op == "+" else left - right
        return left

    def _product(self) -> float | str:
        left = self._unary()
        while self._peek().value in {"*", "/", "%"}:
            op = self._take().value
            right = self._unary()
            if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
                raise RedepthJSError("non-numeric checksum arithmetic")
            if right == 0 and op in {"/", "%"}:
                raise RedepthJSError("zero divisor in rotation checksum")
            left = left * right if op == "*" else left / right if op == "/" else left % right
        return left

    def _unary(self) -> float | str:
        if self._peek().value in {"+", "-"}:
            op = self._take().value
            value = self._unary()
            if not isinstance(value, (int, float)):
                raise RedepthJSError("non-numeric unary checksum operand")
            return value if op == "+" else -value
        return self._primary()

    def _primary(self) -> float | str:
        token = self._take()
        if token.kind == "number":
            return float(token.value) if "." in token.value else int(token.value, 0)
        if token.kind == "string":
            return _js_string(token.value)
        if token.value == "(":
            value = self._sum()
            self._take(")")
            return value
        if token.kind != "ident" or self._peek().value != "(":
            raise RedepthJSError("unsupported checksum primary")
        self._take("(")
        args: list[float | str] = []
        if self._peek().value != ")":
            while True:
                args.append(self._sum())
                if self._peek().value != ",":
                    break
                self._take(",")
        self._take(")")
        if token.value == "parseInt":
            if len(args) != 1:
                raise RedepthJSError("parseInt checksum call has unsupported arity")
            return _js_parse_int(args[0])
        function = self.calls.get(token.value)
        if function is None or not args or not isinstance(args[0], (int, float)) or int(args[0]) != args[0]:
            raise RedepthJSError("unsupported checksum function call")
        key = str(args[1]) if len(args) > 1 else None
        if len(args) > 2:
            raise RedepthJSError("decoder checksum call has unsupported arity")
        return function(int(args[0]), key)


def _js_parse_int(value: float | str) -> int:
    text = str(value).lstrip()
    match = re.match(r"[+-]?(?:0[xX][0-9A-Fa-f]+|\d+)", text)
    if not match:
        raise RedepthJSError("parseInt checksum input is not numeric")
    raw = match.group(0)
    sign = -1 if raw.startswith("-") else 1
    unsigned = raw.lstrip("+-")
    return sign * int(unsigned, 16 if unsigned.lower().startswith("0x") else 10)


def _aliases(text: str, decoders: dict[str, Decoder]) -> dict[str, str]:
    result = {name: name for name in decoders}
    changed = True
    while changed:
        changed = False
        for match in re.finditer(rf"\b(?:var|let|const)\s+({_IDENT})\s*=\s*({_IDENT})\s*;?", text):
            target = result.get(match.group(2))
            if target is not None and result.get(match.group(1)) != target:
                result[match.group(1)] = target
                changed = True
    return result


def _decoder_call(decoder: Decoder, values: tuple[str, ...], argument: int, key: str | None) -> tuple[int, str]:
    index = argument - decoder.index_base
    if not 0 <= index < len(values):
        raise RedepthJSError("decoder index is outside its string array")
    return index, _decode_value(values[index], decoder.encoding, key)


def _solve_rotations(text: str, arrays: dict[str, StringArray], providers: dict[str, str],
                     decoders: dict[str, Decoder], aliases: dict[str, str]) -> dict[str, int]:
    solved: dict[str, int] = {}
    # A javascript-obfuscator loop computes one numeric checksum, rotating on mismatch.
    for provider, array_name in providers.items():
        row = arrays[array_name]
        if len(row.raw_values) > MAX_ROTATIONS:
            continue
        iife = re.compile(rf"\}}\s*\(\s*{re.escape(provider)}\s*,\s*(0[xX][0-9A-Fa-f]+|\d+)\s*\)\s*\)")
        for tail in iife.finditer(text):
            start = text.rfind("(function", 0, tail.start())
            if start < 0:
                continue
            block_open = text.find("{", start, tail.start())
            if block_open < 0:
                continue
            try:
                block_end = _matching(text, block_open)
            except RedepthJSError:
                continue
            if block_end > tail.start() + 1:
                continue
            body = text[block_open + 1:block_end - 1]
            header = text[start:block_open]
            params_match = re.search(r"\(\s*function\s*\(\s*([^)]*)\)", header)
            params = [item.strip() for item in params_match.group(1).split(",")] if params_match else []
            assignment = re.search(
                rf"\b(?:const|let|var)\s+({_IDENT})\s*=\s*(.+?);\s*if\s*\(\s*\1\s*===\s*"
                rf"(0[xX][0-9A-Fa-f]+|\d+|{_IDENT})\s*\)",
                body,
                re.S,
            )
            if assignment is None or not re.search(r"\[['\"]push['\"]\]\s*\([^)]*\[['\"]shift['\"]\]", body):
                continue
            expression = assignment.group(2)
            target_token = assignment.group(3)
            if re.fullmatch(r"0[xX][0-9A-Fa-f]+|\d+", target_token):
                target = _integer(target_token)
            elif len(params) >= 2 and target_token == params[1]:
                target = _integer(tail.group(1))
            else:
                continue
            candidates = []
            for rotation in range(len(row.raw_values)):
                values = row.raw_values[rotation:] + row.raw_values[:rotation]
                functions: dict[str, Callable[[int, str | None], str]] = {}
                for alias, canonical in aliases.items():
                    decoder = decoders[canonical]
                    if decoder.array_name != array_name:
                        continue
                    functions[alias] = lambda argument, key, decoder=decoder, values=values: _decoder_call(
                        decoder, values, argument, key
                    )[1]
                try:
                    result = _Expression(expression, functions).parse()
                except RedepthJSError:
                    # The real loop catches decoder/parse failures and rotates
                    # again, so an invalid intermediate alignment is expected.
                    continue
                if isinstance(result, (int, float)) and math.isfinite(float(result)) and result == target:
                    candidates.append(rotation)
            if len(candidates) == 1:
                solved[array_name] = candidates[0]
            break
    return solved


def _call_arguments(text: str, opening: int) -> tuple[list[str], int]:
    end = _matching(text, opening)
    content = text[opening + 1:end - 1]
    return _split_top(content), end


def _split_top(text: str) -> list[str]:
    rows: list[str] = []
    start = cursor = 0
    stack: list[str] = []
    while cursor < len(text):
        char = text[cursor]
        if char in "'\"`":
            cursor = _skip_quoted(text, cursor, char)
            continue
        if text.startswith("//", cursor):
            line = text.find("\n", cursor + 2)
            cursor = len(text) if line < 0 else line + 1
            continue
        if text.startswith("/*", cursor):
            close = text.find("*/", cursor + 2)
            if close < 0:
                raise RedepthJSError("unterminated JavaScript block comment")
            cursor = close + 2
            continue
        if char in _PAIRS:
            stack.append(char)
        elif char in ")]}":
            if not stack or _PAIRS[stack[-1]] != char:
                raise RedepthJSError("unbalanced JavaScript expression")
            stack.pop()
        elif char == "," and not stack:
            rows.append(text[start:cursor].strip())
            start = cursor + 1
        cursor += 1
    if stack:
        raise RedepthJSError("unterminated JavaScript expression")
    tail = text[start:].strip()
    if tail or rows:
        rows.append(tail)
    return rows


def _decoded_calls(text: str, arrays: dict[str, StringArray], decoders: dict[str, Decoder],
                   aliases: dict[str, str]) -> tuple[DecodedCall, ...]:
    rows: list[DecodedCall] = []
    names = sorted(aliases, key=len, reverse=True)
    if not names:
        return ()
    call = re.compile(rf"(?<![A-Za-z0-9_$])({'|'.join(re.escape(name) for name in names)})\s*\(")
    for match in call.finditer(text):
        try:
            args, _end = _call_arguments(text, match.end() - 1)
        except RedepthJSError:
            continue
        if not args or not re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|\d+)", args[0]):
            continue
        key = None
        if len(args) == 2 and len(args[1]) >= 2 and args[1][0] in "'\"" and args[1][-1] == args[1][0]:
            key = _js_string(args[1])
        elif len(args) != 1:
            continue
        canonical = aliases[match.group(1)]
        decoder = decoders[canonical]
        array = arrays[decoder.array_name]
        try:
            index, value = _decoder_call(decoder, array.values, _integer(args[0]), key)
        except RedepthJSError:
            continue
        rows.append(DecodedCall(match.group(1), match.start(), _integer(args[0]), key, index, value))
        if len(rows) >= MAX_ARRAY_VALUES:
            raise RedepthJSError("decoded-call count exceeds cap")
    unique = {(row.decoder, row.offset, row.argument, row.key, row.array_index, row.value): row for row in rows}
    return tuple(sorted(unique.values(), key=lambda row: (row.offset, row.decoder)))


def _string_leads(body: str, limit: int = 64) -> tuple[str, ...]:
    rows: list[str] = []
    cursor = 0
    while cursor < len(body) and len(rows) < limit:
        if body[cursor] in "'\"":
            end = _skip_quoted(body, cursor, body[cursor])
            try:
                value = _js_string(body[cursor:end])
            except RedepthJSError:
                value = ""
            if len(value) >= 4 and value not in rows:
                rows.append(value[:1024])
            cursor = end
        else:
            cursor += 1
    return tuple(rows)


def _module_object(source: str, object_text: str, base: int, chunk_ids: tuple[str, ...]) -> list[WebpackModule]:
    stripped = object_text.strip()
    leading = len(object_text) - len(object_text.lstrip())
    if not stripped.startswith("{"):
        return []
    opening = base + leading
    if _matching(source, opening) != opening + len(stripped):
        return []
    cursor, end, rows = opening + 1, opening + len(stripped) - 1, []
    while cursor < end:
        cursor = _skip_space(source, cursor, end)
        if cursor >= end:
            break
        key_match = re.match(r"(?:0[xX][0-9A-Fa-f]+|\d+|[A-Za-z_$][A-Za-z0-9_$]*|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")", source[cursor:end])
        if key_match is None:
            return []
        raw_key = key_match.group(0)
        module_id = _js_string(raw_key) if raw_key[0] in "'\"" else str(_integer(raw_key)) if raw_key[0].isdigit() else raw_key
        cursor = _skip_space(source, cursor + len(raw_key), end)
        if cursor >= end or source[cursor] != ":":
            return []
        cursor = _skip_space(source, cursor + 1, end)
        value_start = cursor
        function = re.match(r"(?:function\s*(?:[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\)|\([^)]*\)\s*=>|[A-Za-z_$][A-Za-z0-9_$]*\s*=>)\s*\{", source[cursor:end])
        if function is None:
            # Webpack may use an identifier for an externally defined factory; keep parsing but no body.
            ident = re.match(_IDENT, source[cursor:end])
            if ident is None:
                return []
            value_end = cursor + len(ident.group(0))
            body = source[cursor:value_end]
        else:
            brace = cursor + function.group(0).rfind("{")
            value_end = _matching(source, brace)
            body = source[value_start:value_end]
        requires = tuple(dict.fromkeys(re.findall(r"__webpack_require__\s*\(\s*(0[xX][0-9A-Fa-f]+|\d+|'[^']+'|\"[^\"]+\")\s*\)", body)))
        rows.append(WebpackModule(module_id, chunk_ids, value_start, value_end - value_start,
                                  hashlib.sha256(body.encode()).hexdigest(), _string_leads(body), requires))
        if len(rows) > MAX_MODULES:
            raise RedepthJSError("webpack module count exceeds cap")
        cursor = _skip_space(source, value_end, end)
        if cursor < end:
            if source[cursor] != ",":
                return []
            cursor += 1
    return rows


def _chunk_ids(value: str) -> tuple[str, ...]:
    raw = value.strip()
    if not raw.startswith("["):
        return ()
    rows = []
    for part in _split_top(raw[1:-1]):
        part = part.strip()
        if re.fullmatch(r"0[xX][0-9A-Fa-f]+|\d+", part):
            rows.append(str(_integer(part)))
        elif len(part) >= 2 and part[0] in "'\"" and part[-1] == part[0]:
            rows.append(_js_string(part))
    return tuple(rows)


def _webpack(source: str) -> tuple[WebpackModule, ...]:
    rows: list[WebpackModule] = []
    # Webpack 4/5 JSONP form: webpackChunk*.push([[ids], {factories}, runtime]).
    for match in re.finditer(r"\.push\s*\(", source):
        context = source[max(0, match.start() - 512):match.start()]
        if "webpackChunk" not in context and "webpackJsonp" not in context:
            continue
        args, _end = _call_arguments(source, match.end() - 1)
        if len(args) != 1:
            continue
        outer = args[0].strip()
        if not outer.startswith("[") or not outer.endswith("]"):
            continue
        elements = _split_top(outer[1:-1])
        if len(elements) < 2:
            continue
        module_text = elements[1]
        module_offset = source.find(module_text, match.end() - 1)
        if module_offset >= 0:
            rows.extend(_module_object(source, module_text, module_offset, _chunk_ids(elements[0])))
    # Bootstrap form: var __webpack_modules__ = ({ ... });
    for match in re.finditer(r"\b__webpack_modules__\s*=\s*\(?\s*\{", source):
        opening = match.end() - 1
        close = _matching(source, opening)
        rows.extend(_module_object(source, source[opening:close], opening, ()))
    unique = {(row.module_id, row.chunk_ids, row.offset, row.sha256): row for row in rows}
    return tuple(sorted(unique.values(), key=lambda row: (row.offset, row.module_id)))


def inspect_javascript(source: str | bytes) -> JSBundleReport:
    """Inspect one saved JavaScript bundle without executing any of it."""
    try:
        text = _source(source)
        arrays, providers = _arrays(text)
        decoders = _decoders(text, providers, arrays)
        aliases = _aliases(text, decoders)
        rotations = _solve_rotations(text, arrays, providers, decoders, aliases)
        for name, row in tuple(arrays.items()):
            rotation = rotations.get(name, row.rotation)
            values = row.raw_values if not rotation else row.raw_values[rotation:] + row.raw_values[:rotation]
            arrays[name] = StringArray(row.name, row.provider, row.offset, row.raw_values, rotation, values)
        calls = _decoded_calls(text, arrays, decoders, aliases)
        modules = _webpack(text)
        indicators = []
        for marker in ("__webpack_require__", "webpackChunk", "sourceMappingURL=", "decodeURIComponent", "charCodeAt"):
            if marker in text:
                indicators.append(marker)
        if providers and decoders:
            indicators.append("javascript-obfuscator string-array provider/index wrapper")
        warnings = []
        for row in arrays.values():
            if row.provider and row.rotation is None:
                warnings.append(f"rotation for string array {row.name} was not uniquely solved")
        return JSBundleReport(tuple(sorted(arrays.values(), key=lambda row: row.offset)),
                              tuple(sorted(decoders.values(), key=lambda row: row.offset)), calls,
                              modules, tuple(indicators), tuple(warnings))
    except RedepthJSError:
        raise
    except Exception as exc:
        raise RedepthJSError(f"malformed JavaScript input: {exc}") from exc


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RedepthJSError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="redepth_js_bundle.py", description="static obfuscator.io/webpack extractor")
    parser.add_argument("input")
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        try:
            raw = Path(args.input).read_bytes()
        except (OSError, OverflowError) as exc:
            raise RedepthJSError(f"cannot read input: {exc}") from exc
        report = inspect_javascript(raw)
        print(json.dumps(report.to_dict(), sort_keys=True, indent=None if args.compact else 2))
        return 0
    except RedepthJSError as exc:
        print(f"redepth_js_bundle: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "RedepthJSError", "StringArray", "Decoder", "DecodedCall", "WebpackModule",
    "JSBundleReport", "inspect_javascript", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
