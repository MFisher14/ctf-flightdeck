#!/usr/bin/env python3
"""Bounded, schema-aware GraphQL execution-cost analysis.

This engine consumes saved SDL and a saved GraphQL-over-HTTP JSON request (or
an implementation-specific array batch).  It never opens a socket and never
executes a resolver.  Unlike the repository's lexical GraphQL heuristics, it
selects the operation that would execute, expands fragments, applies the
standard ``@skip``/``@include`` directives, collects duplicate response keys,
and uses schema return types to apply list multipliers.

The cost model is intentionally simple and inspectable::

    field cost = list_multiplier * (configured_field_weight + child_cost)

Non-list fields have a multiplier of one.  A list multiplier comes from a
bounded pagination argument (``first``, ``last``, ``limit``, ``take``,
``pageSize`` or ``perPage``), then a schema default, and finally the configured
conservative default.  Nested list wrappers apply the multiplier once per list
level.  Every result is evidence for human review, not proof of a vulnerability.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping, Sequence


MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_TOKENS = 250_000
MAX_TYPES = 20_000
MAX_FIELDS = 100_000
MAX_SELECTION_DEPTH = 96
MAX_VALUE_DEPTH = 48
MAX_BATCH = 256
MAX_JSON_ITEMS = 500_000
MAX_EXPANDED_FIELDS = 250_000
MAX_LIST_FACTOR = 1_000_000
MAX_FIELD_WEIGHT = 1_000_000
MAX_COST = 10**18

_NAME = re.compile(r"^[_A-Za-z][_0-9A-Za-z]*$")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_PAGINATION = frozenset({"first", "last", "limit", "take", "pagesize", "perpage"})
_MISSING = object()
_UNKNOWN = object()


class WebDepthGraphQLError(ValueError):
    """The sole public failure type for malformed or over-limit inputs."""


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    offset: int


@dataclass(frozen=True)
class _Variable:
    name: str


@dataclass(frozen=True)
class _Enum:
    name: str


@dataclass(frozen=True)
class _TypeRef:
    kind: str
    name: str | None = None
    inner: "_TypeRef | None" = None


@dataclass(frozen=True)
class _Directive:
    name: str
    arguments: tuple[tuple[str, Any], ...]


@dataclass(frozen=True)
class _FieldSelection:
    name: str
    alias: str | None
    arguments: tuple[tuple[str, Any], ...]
    directives: tuple[_Directive, ...]
    selections: tuple[Any, ...]


@dataclass(frozen=True)
class _FragmentSpread:
    name: str
    directives: tuple[_Directive, ...]


@dataclass(frozen=True)
class _InlineFragment:
    type_condition: str | None
    directives: tuple[_Directive, ...]
    selections: tuple[Any, ...]


@dataclass(frozen=True)
class _VariableDefinition:
    name: str
    type_ref: _TypeRef
    default: Any = _MISSING


@dataclass(frozen=True)
class _Operation:
    kind: str
    name: str | None
    variables: tuple[_VariableDefinition, ...]
    directives: tuple[_Directive, ...]
    selections: tuple[Any, ...]


@dataclass(frozen=True)
class _Fragment:
    name: str
    type_condition: str
    directives: tuple[_Directive, ...]
    selections: tuple[Any, ...]


@dataclass(frozen=True)
class _Document:
    operations: tuple[_Operation, ...]
    fragments: Mapping[str, _Fragment]


@dataclass(frozen=True)
class _ArgumentDef:
    name: str
    type_ref: _TypeRef
    default: Any = _MISSING


@dataclass(frozen=True)
class _FieldDef:
    name: str
    type_ref: _TypeRef
    arguments: Mapping[str, _ArgumentDef]


@dataclass
class _TypeDef:
    name: str
    kind: str
    fields: dict[str, _FieldDef] = field(default_factory=dict)


@dataclass(frozen=True)
class _Schema:
    types: Mapping[str, _TypeDef]
    roots: Mapping[str, str]


def _source_text(value: Any, label: str, maximum: int = MAX_SOURCE_BYTES) -> str:
    if isinstance(value, str):
        text = value
        try:
            size = len(value.encode("utf-8", "strict"))
        except UnicodeError as exc:
            raise WebDepthGraphQLError(f"{label} is not valid Unicode") from exc
    elif isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
        size = len(data)
        try:
            text = data.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise WebDepthGraphQLError(f"{label} is not UTF-8") from exc
    else:
        raise WebDepthGraphQLError(f"{label} must be text or bytes")
    if not text.strip():
        raise WebDepthGraphQLError(f"{label} is empty")
    if size > maximum:
        raise WebDepthGraphQLError(f"{label} exceeds {maximum} bytes")
    if "\x00" in text:
        raise WebDepthGraphQLError(f"{label} contains NUL")
    return text


def _tokenize(value: Any, label: str) -> tuple[_Token, ...]:
    text = _source_text(value, label)
    tokens: list[_Token] = []
    at = 0
    while at < len(text):
        char = text[at]
        if char.isspace() or char == "," or char == "\ufeff":
            at += 1
            continue
        if char == "#":
            end = text.find("\n", at + 1)
            at = len(text) if end < 0 else end + 1
            continue
        start = at
        if text.startswith("...", at):
            tokens.append(_Token("PUNCT", "...", start))
            at += 3
        elif text.startswith('"""', at):
            at += 3
            pieces: list[str] = []
            while at < len(text):
                if text.startswith('\\"""', at):
                    pieces.append('"""')
                    at += 4
                elif text.startswith('"""', at):
                    at += 3
                    break
                else:
                    pieces.append(text[at])
                    at += 1
            else:
                raise WebDepthGraphQLError(f"unterminated block string in {label} at byte {start}")
            tokens.append(_Token("STRING", "".join(pieces), start))
        elif char == '"':
            at += 1
            escaped = False
            while at < len(text):
                current = text[at]
                if current in "\r\n" and not escaped:
                    raise WebDepthGraphQLError(f"newline in string in {label} at byte {start}")
                if escaped:
                    escaped = False
                    at += 1
                elif current == "\\":
                    escaped = True
                    at += 1
                elif current == '"':
                    at += 1
                    break
                else:
                    at += 1
            else:
                raise WebDepthGraphQLError(f"unterminated string in {label} at byte {start}")
            raw = text[start:at]
            try:
                decoded = json.loads(raw)
            except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
                raise WebDepthGraphQLError(f"invalid string escape in {label} at byte {start}") from exc
            if not isinstance(decoded, str):
                raise WebDepthGraphQLError(f"invalid string in {label} at byte {start}")
            tokens.append(_Token("STRING", decoded, start))
        elif char.isalpha() or char == "_":
            end = at + 1
            while end < len(text) and (text[end].isalnum() or text[end] == "_"):
                end += 1
            tokens.append(_Token("NAME", text[at:end], start))
            at = end
        elif char == "-" or char.isdigit():
            match = _NUMBER.match(text, at)
            if match is None:
                raise WebDepthGraphQLError(f"invalid number in {label} at byte {start}")
            spelling = match.group(0)
            end = match.end()
            if end < len(text) and (text[end].isalnum() or text[end] in "_."):
                raise WebDepthGraphQLError(f"invalid number boundary in {label} at byte {start}")
            if len(spelling) > 128:
                raise WebDepthGraphQLError(f"number is too long in {label} at byte {start}")
            tokens.append(_Token("FLOAT" if any(ch in spelling for ch in ".eE") else "INT",
                                 spelling, start))
            at = end
        elif char in "!$():=@[]{|}&":
            tokens.append(_Token("PUNCT", char, start))
            at += 1
        else:
            raise WebDepthGraphQLError(f"unexpected character {char!r} in {label} at byte {start}")
        if len(tokens) > MAX_TOKENS:
            raise WebDepthGraphQLError(f"{label} token count exceeds {MAX_TOKENS}")
    return tuple(tokens)


class _Cursor:
    def __init__(self, tokens: Sequence[_Token], label: str):
        self.tokens = tokens
        self.label = label
        self.at = 0

    def current(self) -> _Token | None:
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    def peek(self, value: str | None = None, kind: str | None = None) -> bool:
        token = self.current()
        if token is None:
            return False
        return (value is None or token.value == value) and (kind is None or token.kind == kind)

    def take(self, value: str | None = None, kind: str | None = None) -> _Token:
        token = self.current()
        if token is None or (value is not None and token.value != value) \
                or (kind is not None and token.kind != kind):
            wanted = value if value is not None else (kind or "token")
            offset = token.offset if token is not None else "EOF"
            raise WebDepthGraphQLError(f"expected {wanted} in {self.label} at {offset}")
        self.at += 1
        return token

    def consume(self, value: str) -> bool:
        if self.peek(value):
            self.at += 1
            return True
        return False

    def name(self) -> str:
        return self.take(kind="NAME").value


def _parse_type_ref(cursor: _Cursor, depth: int = 0) -> _TypeRef:
    if depth > MAX_VALUE_DEPTH:
        raise WebDepthGraphQLError("type-reference nesting cap exceeded")
    if cursor.consume("["):
        inner = _parse_type_ref(cursor, depth + 1)
        cursor.take("]")
        result = _TypeRef("list", inner=inner)
    else:
        result = _TypeRef("named", name=cursor.name())
    if cursor.consume("!"):
        if result.kind == "non_null":
            raise WebDepthGraphQLError("duplicate non-null marker")
        result = _TypeRef("non_null", inner=result)
    return result


def _parse_value(cursor: _Cursor, depth: int = 0, *, variables: bool = True) -> Any:
    if depth > MAX_VALUE_DEPTH:
        raise WebDepthGraphQLError("GraphQL value nesting cap exceeded")
    token = cursor.current()
    if token is None:
        raise WebDepthGraphQLError(f"expected value in {cursor.label} at EOF")
    if cursor.consume("$"):
        if not variables:
            raise WebDepthGraphQLError("variables are not permitted in this value")
        return _Variable(cursor.name())
    if token.kind == "STRING":
        cursor.at += 1
        return token.value
    if token.kind == "INT":
        cursor.at += 1
        try:
            return int(token.value, 10)
        except (ValueError, OverflowError) as exc:
            raise WebDepthGraphQLError("invalid GraphQL integer") from exc
    if token.kind == "FLOAT":
        cursor.at += 1
        try:
            value = float(token.value)
        except (ValueError, OverflowError) as exc:
            raise WebDepthGraphQLError("invalid GraphQL float") from exc
        if value != value or value in (float("inf"), float("-inf")):
            raise WebDepthGraphQLError("non-finite GraphQL float")
        return value
    if token.kind == "NAME":
        cursor.at += 1
        if token.value == "true":
            return True
        if token.value == "false":
            return False
        if token.value == "null":
            return None
        return _Enum(token.value)
    if cursor.consume("["):
        values = []
        while not cursor.consume("]"):
            if cursor.current() is None:
                raise WebDepthGraphQLError("unterminated GraphQL list value")
            values.append(_parse_value(cursor, depth + 1, variables=variables))
            if len(values) > MAX_FIELDS:
                raise WebDepthGraphQLError("GraphQL list value exceeds item cap")
        return tuple(values)
    if cursor.consume("{"):
        values: list[tuple[str, Any]] = []
        seen: set[str] = set()
        while not cursor.consume("}"):
            name = cursor.name()
            if name in seen:
                raise WebDepthGraphQLError(f"duplicate GraphQL object key {name!r}")
            seen.add(name)
            cursor.take(":")
            values.append((name, _parse_value(cursor, depth + 1, variables=variables)))
            if len(values) > MAX_FIELDS:
                raise WebDepthGraphQLError("GraphQL object value exceeds field cap")
        return tuple(values)
    raise WebDepthGraphQLError(f"expected value in {cursor.label} at {token.offset}")


def _parse_arguments(cursor: _Cursor, *, variables: bool = True) -> tuple[tuple[str, Any], ...]:
    if not cursor.consume("("):
        return ()
    rows: list[tuple[str, Any]] = []
    seen: set[str] = set()
    while not cursor.consume(")"):
        if cursor.current() is None:
            raise WebDepthGraphQLError("unterminated GraphQL argument list")
        name = cursor.name()
        if name in seen:
            raise WebDepthGraphQLError(f"duplicate argument {name!r}")
        seen.add(name)
        cursor.take(":")
        rows.append((name, _parse_value(cursor, variables=variables)))
        if len(rows) > MAX_FIELDS:
            raise WebDepthGraphQLError("GraphQL argument count exceeds cap")
    return tuple(rows)


def _parse_directives(cursor: _Cursor, *, variables: bool = True) -> tuple[_Directive, ...]:
    rows: list[_Directive] = []
    while cursor.consume("@"):
        rows.append(_Directive(cursor.name(), _parse_arguments(cursor, variables=variables)))
        if len(rows) > MAX_FIELDS:
            raise WebDepthGraphQLError("GraphQL directive count exceeds cap")
    return tuple(rows)


def _parse_argument_definitions(cursor: _Cursor) -> dict[str, _ArgumentDef]:
    if not cursor.consume("("):
        return {}
    rows: dict[str, _ArgumentDef] = {}
    while not cursor.consume(")"):
        name = cursor.name()
        if name in rows:
            raise WebDepthGraphQLError(f"duplicate schema argument {name!r}")
        cursor.take(":")
        type_ref = _parse_type_ref(cursor)
        default = _parse_value(cursor, variables=False) if cursor.consume("=") else _MISSING
        _parse_directives(cursor, variables=False)
        rows[name] = _ArgumentDef(name, type_ref, default)
        if len(rows) > MAX_FIELDS:
            raise WebDepthGraphQLError("schema argument count exceeds cap")
    return rows


def _skip_description(cursor: _Cursor) -> None:
    if cursor.peek(kind="STRING"):
        cursor.at += 1


def _parse_schema_impl(sdl: Any) -> _Schema:
    cursor = _Cursor(_tokenize(sdl, "GraphQL SDL"), "GraphQL SDL")
    types: dict[str, _TypeDef] = {
        name: _TypeDef(name, "scalar")
        for name in ("Int", "Float", "String", "Boolean", "ID")
    }
    explicit_roots: dict[str, str] = {}
    total_fields = 0

    def merge_type(name: str, kind: str, fields: Mapping[str, _FieldDef]) -> None:
        nonlocal total_fields
        existing = types.get(name)
        if existing is None:
            if len(types) >= MAX_TYPES:
                raise WebDepthGraphQLError(f"schema type count exceeds {MAX_TYPES}")
            existing = _TypeDef(name, kind)
            types[name] = existing
        elif existing.kind != kind:
            raise WebDepthGraphQLError(f"type {name!r} changes kind")
        for field_name, definition in fields.items():
            if field_name in existing.fields:
                raise WebDepthGraphQLError(f"duplicate schema field {name}.{field_name}")
            existing.fields[field_name] = definition
            total_fields += 1
            if total_fields > MAX_FIELDS:
                raise WebDepthGraphQLError(f"schema field count exceeds {MAX_FIELDS}")

    while cursor.current() is not None:
        _skip_description(cursor)
        if cursor.current() is None:
            break
        extended = cursor.consume("extend")
        kind = cursor.name()
        if kind == "schema":
            _parse_directives(cursor, variables=False)
            cursor.take("{")
            while not cursor.consume("}"):
                operation = cursor.name()
                if operation not in {"query", "mutation", "subscription"}:
                    raise WebDepthGraphQLError(f"unknown schema root {operation!r}")
                cursor.take(":")
                root_name = cursor.name()
                if operation in explicit_roots and explicit_roots[operation] != root_name:
                    raise WebDepthGraphQLError(f"conflicting {operation} root")
                explicit_roots[operation] = root_name
            continue
        if kind == "scalar":
            name = cursor.name()
            _parse_directives(cursor, variables=False)
            existing = types.get(name)
            if existing is not None and existing.kind != "scalar":
                raise WebDepthGraphQLError(f"type {name!r} changes kind")
            types.setdefault(name, _TypeDef(name, "scalar"))
            continue
        if kind == "enum":
            name = cursor.name()
            _parse_directives(cursor, variables=False)
            cursor.take("{")
            values = 0
            while not cursor.consume("}"):
                _skip_description(cursor)
                cursor.name()
                _parse_directives(cursor, variables=False)
                values += 1
                if values > MAX_FIELDS:
                    raise WebDepthGraphQLError("enum value count exceeds cap")
            if name in types and types[name].kind != "enum":
                raise WebDepthGraphQLError(f"type {name!r} changes kind")
            types.setdefault(name, _TypeDef(name, "enum"))
            continue
        if kind == "union":
            name = cursor.name()
            _parse_directives(cursor, variables=False)
            cursor.take("=")
            cursor.consume("|")
            members = 0
            while cursor.peek(kind="NAME"):
                cursor.name()
                members += 1
                if not cursor.consume("|"):
                    break
            if members == 0:
                raise WebDepthGraphQLError(f"union {name!r} has no members")
            if name in types and types[name].kind != "union":
                raise WebDepthGraphQLError(f"type {name!r} changes kind")
            types.setdefault(name, _TypeDef(name, "union"))
            continue
        if kind == "directive":
            cursor.take("@")
            cursor.name()
            _parse_argument_definitions(cursor)
            cursor.consume("repeatable")
            cursor.take("on")
            cursor.consume("|")
            cursor.name()
            while cursor.consume("|"):
                cursor.name()
            continue
        if kind not in {"type", "interface", "input"}:
            suffix = " after extend" if extended else ""
            raise WebDepthGraphQLError(f"unsupported SDL definition {kind!r}{suffix}")
        name = cursor.name()
        type_kind = "input" if kind == "input" else kind
        if kind in {"type", "interface"} and cursor.consume("implements"):
            cursor.consume("&")
            cursor.name()
            while cursor.consume("&"):
                cursor.name()
        _parse_directives(cursor, variables=False)
        cursor.take("{")
        fields: dict[str, _FieldDef] = {}
        while not cursor.consume("}"):
            _skip_description(cursor)
            field_name = cursor.name()
            if field_name in fields:
                raise WebDepthGraphQLError(f"duplicate schema field {name}.{field_name}")
            arguments = _parse_argument_definitions(cursor) if kind != "input" else {}
            cursor.take(":")
            type_ref = _parse_type_ref(cursor)
            if kind == "input" and cursor.consume("="):
                _parse_value(cursor, variables=False)
            _parse_directives(cursor, variables=False)
            fields[field_name] = _FieldDef(field_name, type_ref, arguments)
        merge_type(name, type_kind, fields)

    roots = dict(explicit_roots)
    for operation, conventional in (("query", "Query"), ("mutation", "Mutation"),
                                    ("subscription", "Subscription")):
        if operation not in roots and conventional in types:
            roots[operation] = conventional
    for operation, name in roots.items():
        definition = types.get(name)
        if definition is None or definition.kind not in {"type", "interface"}:
            raise WebDepthGraphQLError(f"{operation} root {name!r} is not an object type")
    if not roots:
        raise WebDepthGraphQLError("schema has no operation root")
    return _Schema(types, roots)


class _ExecutableParser:
    def __init__(self, source: Any):
        self.cursor = _Cursor(_tokenize(source, "GraphQL document"), "GraphQL document")
        self.selection_count = 0

    def variable_definitions(self) -> tuple[_VariableDefinition, ...]:
        if not self.cursor.consume("("):
            return ()
        rows: list[_VariableDefinition] = []
        seen: set[str] = set()
        while not self.cursor.consume(")"):
            self.cursor.take("$")
            name = self.cursor.name()
            if name in seen:
                raise WebDepthGraphQLError(f"duplicate variable definition ${name}")
            seen.add(name)
            self.cursor.take(":")
            type_ref = _parse_type_ref(self.cursor)
            default = _parse_value(self.cursor, variables=False) if self.cursor.consume("=") else _MISSING
            _parse_directives(self.cursor, variables=True)
            rows.append(_VariableDefinition(name, type_ref, default))
        return tuple(rows)

    def selection_set(self, depth: int = 0) -> tuple[Any, ...]:
        if depth > MAX_SELECTION_DEPTH:
            raise WebDepthGraphQLError("selection nesting cap exceeded")
        self.cursor.take("{")
        rows: list[Any] = []
        while not self.cursor.consume("}"):
            if self.cursor.current() is None:
                raise WebDepthGraphQLError("unterminated selection set")
            self.selection_count += 1
            if self.selection_count > MAX_FIELDS:
                raise WebDepthGraphQLError(f"selection count exceeds {MAX_FIELDS}")
            if self.cursor.consume("..."):
                if self.cursor.consume("on"):
                    condition = self.cursor.name()
                    directives = _parse_directives(self.cursor)
                    rows.append(_InlineFragment(condition, directives, self.selection_set(depth + 1)))
                elif self.cursor.peek("@") or self.cursor.peek("{"):
                    directives = _parse_directives(self.cursor)
                    rows.append(_InlineFragment(None, directives, self.selection_set(depth + 1)))
                else:
                    rows.append(_FragmentSpread(self.cursor.name(), _parse_directives(self.cursor)))
                continue
            first = self.cursor.name()
            if self.cursor.consume(":"):
                alias, name = first, self.cursor.name()
            else:
                alias, name = None, first
            arguments = _parse_arguments(self.cursor)
            directives = _parse_directives(self.cursor)
            child = self.selection_set(depth + 1) if self.cursor.peek("{") else ()
            rows.append(_FieldSelection(name, alias, arguments, directives, child))
        if not rows:
            raise WebDepthGraphQLError("empty selection set")
        return tuple(rows)

    def parse(self) -> _Document:
        operations: list[_Operation] = []
        fragments: dict[str, _Fragment] = {}
        operation_names: set[str] = set()
        while self.cursor.current() is not None:
            if self.cursor.consume("fragment"):
                name = self.cursor.name()
                if name == "on" or name in fragments:
                    raise WebDepthGraphQLError(f"invalid or duplicate fragment {name!r}")
                self.cursor.take("on")
                condition = self.cursor.name()
                directives = _parse_directives(self.cursor)
                fragments[name] = _Fragment(name, condition, directives, self.selection_set())
                continue
            if self.cursor.peek("{"):
                operation = _Operation("query", None, (), (), self.selection_set())
            else:
                kind = self.cursor.name()
                if kind not in {"query", "mutation", "subscription"}:
                    raise WebDepthGraphQLError(f"unknown operation kind {kind!r}")
                name = None
                if self.cursor.peek(kind="NAME"):
                    name = self.cursor.name()
                    if name in operation_names:
                        raise WebDepthGraphQLError(f"duplicate operation name {name!r}")
                    operation_names.add(name)
                variables = self.variable_definitions()
                directives = _parse_directives(self.cursor)
                operation = _Operation(kind, name, variables, directives, self.selection_set())
            operations.append(operation)
        if not operations:
            raise WebDepthGraphQLError("document contains no operation")
        if len(operations) > 1 and any(operation.name is None for operation in operations):
            raise WebDepthGraphQLError("anonymous operation must be the only operation")
        return _Document(tuple(operations), fragments)


def _named_type(type_ref: _TypeRef) -> str:
    current = type_ref
    while current.kind != "named":
        if current.inner is None:
            raise WebDepthGraphQLError("malformed internal type reference")
        current = current.inner
    if current.name is None:
        raise WebDepthGraphQLError("malformed internal named type")
    return current.name


def _list_levels(type_ref: _TypeRef) -> int:
    levels = 0
    current = type_ref
    while current.kind != "named":
        if current.kind == "list":
            levels += 1
        if current.inner is None:
            raise WebDepthGraphQLError("malformed internal type reference")
        current = current.inner
    return levels


def _required(type_ref: _TypeRef) -> bool:
    return type_ref.kind == "non_null"


def _freeze(value: Any) -> Any:
    if isinstance(value, _Variable):
        return ("variable", value.name)
    if isinstance(value, _Enum):
        return ("enum", value.name)
    if isinstance(value, tuple):
        if value and all(isinstance(item, tuple) and len(item) == 2
                         and isinstance(item[0], str) for item in value):
            return ("object", tuple(sorted((key, _freeze(item)) for key, item in value)))
        return ("list", tuple(_freeze(item) for item in value))
    if isinstance(value, (str, int, float, bool)) or value is None:
        return (type(value).__name__, value)
    raise WebDepthGraphQLError("unsupported GraphQL value")


def _fragment_spreads(selections: Iterable[Any]) -> set[str]:
    found: set[str] = set()
    stack = list(selections)
    while stack:
        selection = stack.pop()
        if isinstance(selection, _FragmentSpread):
            found.add(selection.name)
        elif isinstance(selection, (_FieldSelection, _InlineFragment)):
            stack.extend(selection.selections)
    return found


def _validate_fragments(document: _Document) -> None:
    all_spreads = set()
    for operation in document.operations:
        all_spreads.update(_fragment_spreads(operation.selections))
    for fragment in document.fragments.values():
        all_spreads.update(_fragment_spreads(fragment.selections))
    missing = sorted(all_spreads - set(document.fragments))
    if missing:
        raise WebDepthGraphQLError(f"undefined fragments: {', '.join(missing)}")
    visiting: set[str] = set()
    done: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            raise WebDepthGraphQLError(f"fragment cycle includes {name!r}")
        if name in done:
            return
        visiting.add(name)
        for child in _fragment_spreads(document.fragments[name].selections):
            visit(child)
        visiting.remove(name)
        done.add(name)

    for name in document.fragments:
        visit(name)


def _bounded_json(value: Any, label: str) -> None:
    budget = [MAX_JSON_ITEMS]
    active: set[int] = set()

    def walk(item: Any, depth: int) -> None:
        if depth > MAX_VALUE_DEPTH:
            raise WebDepthGraphQLError(f"{label} nesting exceeds {MAX_VALUE_DEPTH}")
        budget[0] -= 1
        if budget[0] < 0:
            raise WebDepthGraphQLError(f"{label} item count exceeds {MAX_JSON_ITEMS}")
        if isinstance(item, dict):
            identity = id(item)
            if identity in active:
                raise WebDepthGraphQLError(f"{label} contains a cycle")
            active.add(identity)
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 4096:
                    raise WebDepthGraphQLError(f"{label} has an invalid object key")
                walk(child, depth + 1)
            active.remove(identity)
        elif isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in active:
                raise WebDepthGraphQLError(f"{label} contains a cycle")
            active.add(identity)
            for child in item:
                walk(child, depth + 1)
            active.remove(identity)
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            raise WebDepthGraphQLError(f"{label} contains unsupported {type(item).__name__}")

    walk(value, 0)


def _strict_json(text: Any, label: str) -> Any:
    source = _source_text(text, label, MAX_JSON_BYTES)

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise WebDepthGraphQLError(f"duplicate JSON key {key!r} in {label}")
            result[key] = value
        return result

    def parse_int(spelling: str) -> int:
        if len(spelling) > 128:
            raise WebDepthGraphQLError(f"integer is too long in {label}")
        return int(spelling, 10)

    def reject_constant(spelling: str) -> Any:
        raise WebDepthGraphQLError(f"non-finite number {spelling!r} in {label}")

    try:
        value = json.loads(source, object_pairs_hook=object_pairs,
                           parse_int=parse_int, parse_constant=reject_constant)
    except WebDepthGraphQLError:
        raise
    except (json.JSONDecodeError, UnicodeError, ValueError, TypeError, OverflowError) as exc:
        raise WebDepthGraphQLError(f"{label} is not strict JSON") from exc
    _bounded_json(value, label)
    return value


def _weights(value: Any) -> dict[str, int]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise WebDepthGraphQLError("field_weights must be an object")
    rows: dict[str, int] = {}
    for key, weight in value.items():
        if not isinstance(key, str) or not re.fullmatch(
                r"[_A-Za-z][_0-9A-Za-z]*(?:\.[_A-Za-z][_0-9A-Za-z]*)?", key):
            raise WebDepthGraphQLError(f"invalid field weight key {key!r}")
        if isinstance(weight, bool) or not isinstance(weight, int) or not 0 <= weight <= MAX_FIELD_WEIGHT:
            raise WebDepthGraphQLError(f"weight for {key!r} must be 0..{MAX_FIELD_WEIGHT}")
        rows[key] = weight
    return rows


@dataclass
class _Metrics:
    field_count: int = 0
    alias_count: int = 0
    max_depth: int = 0
    max_breadth: int = 0
    max_list_depth: int = 0
    conditional_inclusions: int = 0
    custom_directives: int = 0
    expanded_fields: int = 0
    cost_capped: bool = False
    list_factors: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class _ExpandedField:
    selection: _FieldSelection
    parent_type: str


@dataclass
class _Context:
    schema: _Schema
    document: _Document
    variables: Mapping[str, Any]
    defaults: Mapping[str, Any]
    declared_variables: frozenset[str]
    weights: Mapping[str, int]
    default_list_size: int
    max_list_size: int
    metrics: _Metrics


def _resolved(value: Any, context: _Context) -> Any:
    if isinstance(value, _Variable):
        if value.name not in context.declared_variables:
            raise WebDepthGraphQLError(f"variable ${value.name} is not declared by the operation")
        if value.name in context.variables:
            return context.variables[value.name]
        if value.name in context.defaults:
            return context.defaults[value.name]
        return _UNKNOWN
    return value


def _included(directives: Sequence[_Directive], context: _Context) -> bool:
    significant: dict[str, _Directive] = {}
    for directive in directives:
        if directive.name not in {"skip", "include"}:
            context.metrics.custom_directives += 1
            continue
        if directive.name in significant:
            raise WebDepthGraphQLError(f"duplicate @{directive.name} directive")
        significant[directive.name] = directive
    for name, directive in significant.items():
        arguments = dict(directive.arguments)
        if set(arguments) != {"if"}:
            raise WebDepthGraphQLError(f"@{name} requires exactly one if argument")
        condition = _resolved(arguments["if"], context)
        if condition is _UNKNOWN:
            context.metrics.conditional_inclusions += 1
            continue
        if not isinstance(condition, bool):
            raise WebDepthGraphQLError(f"@{name}(if:) did not resolve to Boolean")
        if (name == "skip" and condition) or (name == "include" and not condition):
            return False
    return True


def _effective_parent(condition: str | None, current: str, schema: _Schema) -> str:
    if condition is None or condition == current:
        return current
    definition = schema.types.get(condition)
    if definition is None or definition.kind not in {"type", "interface"}:
        raise WebDepthGraphQLError(f"fragment type condition {condition!r} is not an object type")
    # Full interface/union runtime type reasoning is outside this focused
    # engine.  Object conditions remain useful for ordinary named fragments;
    # different object conditions are retained and conservatively rejected if
    # they collide on one response key later.
    return condition


def _expand(selections: Sequence[Any], parent_type: str, context: _Context,
            active: tuple[str, ...] = ()) -> list[_ExpandedField]:
    rows: list[_ExpandedField] = []
    for selection in selections:
        context.metrics.expanded_fields += 1
        if context.metrics.expanded_fields > MAX_EXPANDED_FIELDS:
            raise WebDepthGraphQLError(f"expanded selection count exceeds {MAX_EXPANDED_FIELDS}")
        if isinstance(selection, _FieldSelection):
            if _included(selection.directives, context):
                rows.append(_ExpandedField(selection, parent_type))
        elif isinstance(selection, _FragmentSpread):
            if not _included(selection.directives, context):
                continue
            fragment = context.document.fragments[selection.name]
            if not _included(fragment.directives, context):
                continue
            if fragment.name in active:
                raise WebDepthGraphQLError(f"fragment cycle includes {fragment.name!r}")
            nested_parent = _effective_parent(fragment.type_condition, parent_type, context.schema)
            rows.extend(_expand(fragment.selections, nested_parent, context,
                                active + (fragment.name,)))
        elif isinstance(selection, _InlineFragment):
            if _included(selection.directives, context):
                nested_parent = _effective_parent(selection.type_condition, parent_type, context.schema)
                rows.extend(_expand(selection.selections, nested_parent, context, active))
        else:
            raise WebDepthGraphQLError("unknown selection node")
    return rows


def _safe_add(left: int, right: int, metrics: _Metrics) -> int:
    if left >= MAX_COST - right:
        metrics.cost_capped = True
        return MAX_COST
    return left + right


def _safe_mul(left: int, right: int, metrics: _Metrics) -> int:
    if left and right > MAX_COST // left:
        metrics.cost_capped = True
        return MAX_COST
    return left * right


def _field_weight(parent: str, field_name: str, weights: Mapping[str, int]) -> int:
    return weights.get(f"{parent}.{field_name}", weights.get(field_name, 1))


def _positive_factor(value: Any, context: _Context) -> int | None:
    resolved = _resolved(value, context)
    if resolved is _UNKNOWN:
        return None
    if isinstance(resolved, bool) or not isinstance(resolved, int):
        raise WebDepthGraphQLError("pagination factor did not resolve to an integer")
    return max(0, min(resolved, context.max_list_size))


def _list_factor(selection: _FieldSelection, definition: _FieldDef,
                 levels: int, context: _Context, path: str) -> int:
    if levels == 0:
        return 1
    supplied = dict(selection.arguments)
    candidates: list[tuple[int, str]] = []
    unresolved = False
    for name, value in supplied.items():
        if name.casefold() in _PAGINATION:
            factor = _positive_factor(value, context)
            if factor is None:
                unresolved = True
            else:
                candidates.append((factor, f"argument:{name}"))
    if candidates:
        factor, source = max(candidates, key=lambda row: row[0])
    else:
        defaults: list[tuple[int, str]] = []
        for name, argument in definition.arguments.items():
            if name.casefold() not in _PAGINATION or argument.default is _MISSING:
                continue
            factor = _positive_factor(argument.default, context)
            if factor is not None:
                defaults.append((factor, f"schema-default:{name}"))
        if defaults and not unresolved:
            factor, source = max(defaults, key=lambda row: row[0])
        else:
            factor, source = context.default_list_size, (
                "conservative-unknown-variable" if unresolved else "conservative-default")
    multiplier = 1
    for _ in range(levels):
        multiplier = _safe_mul(multiplier, factor, context.metrics)
    context.metrics.list_factors.append({
        "path": path,
        "list_levels": levels,
        "factor": factor,
        "multiplier": multiplier,
        "source": source,
    })
    return multiplier


def _validate_field_arguments(selection: _FieldSelection, definition: _FieldDef) -> None:
    supplied = {name for name, _value in selection.arguments}
    unknown = supplied - set(definition.arguments)
    if unknown:
        raise WebDepthGraphQLError(
            f"unknown arguments for {definition.name}: {', '.join(sorted(unknown))}")
    missing = [name for name, argument in definition.arguments.items()
               if _required(argument.type_ref) and argument.default is _MISSING and name not in supplied]
    if missing:
        raise WebDepthGraphQLError(
            f"missing required arguments for {definition.name}: {', '.join(sorted(missing))}")


def _cost_selection_set(selections: Sequence[Any], parent_type: str, context: _Context,
                        depth: int, cumulative_lists: int, path: tuple[str, ...]) -> tuple[int, int]:
    if depth > MAX_SELECTION_DEPTH:
        raise WebDepthGraphQLError("expanded execution depth exceeds cap")
    expanded = _expand(selections, parent_type, context)
    grouped: dict[str, list[_ExpandedField]] = {}
    order: list[str] = []
    for item in expanded:
        key = item.selection.alias or item.selection.name
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(item)
    context.metrics.max_breadth = max(context.metrics.max_breadth, len(grouped))
    total = 0
    for response_key in order:
        items = grouped[response_key]
        first = items[0]
        signature = (first.parent_type, first.selection.name, _freeze(first.selection.arguments))
        for item in items[1:]:
            other = (item.parent_type, item.selection.name, _freeze(item.selection.arguments))
            if other != signature:
                raise WebDepthGraphQLError(
                    f"conflicting fields share response key {response_key!r}")
        parent = first.parent_type
        type_def = context.schema.types.get(parent)
        if type_def is None or type_def.kind not in {"type", "interface"}:
            raise WebDepthGraphQLError(f"selection parent {parent!r} is not an object type")
        if first.selection.name == "__typename":
            definition = _FieldDef("__typename", _TypeRef("named", "String"), {})
        else:
            definition = type_def.fields.get(first.selection.name)
            if definition is None:
                raise WebDepthGraphQLError(f"field {parent}.{first.selection.name} is not in the schema")
        _validate_field_arguments(first.selection, definition)
        combined_children = tuple(child for item in items for child in item.selection.selections)
        named = _named_type(definition.type_ref)
        child_type = context.schema.types.get(named)
        composite = child_type is not None and child_type.kind in {"type", "interface"}
        if combined_children and not composite:
            raise WebDepthGraphQLError(f"scalar field {parent}.{definition.name} has a selection set")
        if not combined_children and composite:
            raise WebDepthGraphQLError(f"object field {parent}.{definition.name} lacks a selection set")
        levels = _list_levels(definition.type_ref)
        current_path = path + (response_key,)
        rendered_path = ".".join(current_path)
        multiplier = _list_factor(first.selection, definition, levels, context, rendered_path)
        child_cost = 0
        if combined_children:
            child_cost, _ = _cost_selection_set(
                combined_children, named, context, depth + 1,
                cumulative_lists + levels, current_path)
        weight = _field_weight(parent, definition.name, context.weights)
        own = _safe_add(weight, child_cost, context.metrics)
        total = _safe_add(total, _safe_mul(multiplier, own, context.metrics), context.metrics)
        context.metrics.field_count += 1
        if first.selection.alias is not None:
            context.metrics.alias_count += 1
        context.metrics.max_depth = max(context.metrics.max_depth, depth)
        context.metrics.max_list_depth = max(
            context.metrics.max_list_depth, cumulative_lists + levels)
    return total, len(grouped)


def _select_operation(document: _Document, operation_name: Any) -> _Operation:
    if operation_name is not None and (not isinstance(operation_name, str)
                                       or not _NAME.fullmatch(operation_name)):
        raise WebDepthGraphQLError("operationName must be a GraphQL name or null")
    if operation_name is None:
        if len(document.operations) != 1:
            raise WebDepthGraphQLError("operationName is required for a multi-operation document")
        return document.operations[0]
    matches = [operation for operation in document.operations if operation.name == operation_name]
    if len(matches) != 1:
        raise WebDepthGraphQLError(f"operationName {operation_name!r} does not select one operation")
    return matches[0]


def _analyze_one(schema: _Schema, request: Any, index: int, weights: Mapping[str, int],
                 default_list_size: int, max_list_size: int) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        raise WebDepthGraphQLError(f"batch member {index} must be an object")
    query = request.get("query")
    if not isinstance(query, (str, bytes, bytearray, memoryview)):
        raise WebDepthGraphQLError(f"batch member {index} has no text query")
    document = _ExecutableParser(query).parse()
    _validate_fragments(document)
    operation = _select_operation(document, request.get("operationName"))
    variables = request.get("variables")
    if variables is None:
        variables = {}
    if not isinstance(variables, Mapping) or any(not isinstance(key, str) for key in variables):
        raise WebDepthGraphQLError(f"batch member {index} variables must be an object")
    _bounded_json(variables, f"batch member {index} variables")
    definitions = {definition.name: definition for definition in operation.variables}
    unknown_variables = set(variables) - set(definitions)
    if unknown_variables:
        raise WebDepthGraphQLError(
            f"batch member {index} supplies undeclared variables: {', '.join(sorted(unknown_variables))}")
    defaults = {definition.name: definition.default for definition in operation.variables
                if definition.default is not _MISSING}
    root = schema.roots.get(operation.kind)
    if root is None:
        raise WebDepthGraphQLError(f"schema has no {operation.kind} root")
    metrics = _Metrics()
    context = _Context(schema, document, variables, defaults, frozenset(definitions), weights,
                       default_list_size, max_list_size, metrics)
    # Operation directives are not execution directives in the base GraphQL
    # spec, but count custom directives so the report preserves uncertainty.
    if not _included(operation.directives, context):
        raise WebDepthGraphQLError("standard include/skip directive is invalid on an operation")
    cost, root_fields = _cost_selection_set(operation.selections, root, context, 1, 0, ())
    return {
        "index": index,
        "operation_kind": operation.kind,
        "operation_name": operation.name,
        "root_type": root,
        "weighted_cost": cost,
        "field_count": metrics.field_count,
        "root_field_count": root_fields,
        "alias_count": metrics.alias_count,
        "max_depth": metrics.max_depth,
        "max_breadth": metrics.max_breadth,
        "max_list_depth": metrics.max_list_depth,
        "conditional_inclusions": metrics.conditional_inclusions,
        "custom_directives": metrics.custom_directives,
        "list_factors": metrics.list_factors,
        "cost_capped": metrics.cost_capped,
    }


def _analyze_impl(schema_sdl: Any, request: Any, *, field_weights: Any = None,
                  default_list_size: int = 10,
                  max_list_size: int = MAX_LIST_FACTOR) -> dict[str, Any]:
    if isinstance(default_list_size, bool) or not isinstance(default_list_size, int) \
            or not 1 <= default_list_size <= MAX_LIST_FACTOR:
        raise WebDepthGraphQLError(f"default_list_size must be 1..{MAX_LIST_FACTOR}")
    if isinstance(max_list_size, bool) or not isinstance(max_list_size, int) \
            or not default_list_size <= max_list_size <= MAX_LIST_FACTOR:
        raise WebDepthGraphQLError(
            f"max_list_size must be {default_list_size}..{MAX_LIST_FACTOR}")
    schema = _parse_schema_impl(schema_sdl)
    _bounded_json(request, "GraphQL HTTP request")
    is_batch = isinstance(request, (list, tuple))
    members = list(request) if is_batch else [request]
    if not members:
        raise WebDepthGraphQLError("GraphQL HTTP batch is empty")
    if len(members) > MAX_BATCH:
        raise WebDepthGraphQLError(f"GraphQL HTTP batch exceeds {MAX_BATCH} members")
    weight_map = _weights(field_weights)
    operations = [_analyze_one(schema, member, index, weight_map,
                               default_list_size, max_list_size)
                  for index, member in enumerate(members)]
    total = 0
    total_capped = False
    for row in operations:
        if total >= MAX_COST - row["weighted_cost"]:
            total, total_capped = MAX_COST, True
        else:
            total += row["weighted_cost"]
        total_capped = total_capped or row["cost_capped"]
    return {
        "transport_batch": is_batch,
        "batch_count": len(operations),
        "aggregate_weighted_cost": total,
        "aggregate_cost_capped": total_capped,
        "max_depth": max(row["max_depth"] for row in operations),
        "max_breadth": max(row["max_breadth"] for row in operations),
        "max_list_depth": max(row["max_list_depth"] for row in operations),
        "total_aliases": sum(row["alias_count"] for row in operations),
        "operations": operations,
        "cost_model": "list_multiplier * (field_weight + child_cost)",
        "default_list_size": default_list_size,
        "max_list_size": max_list_size,
        "offline": True,
        "network_requests": 0,
    }


def analyze_graphql_request(schema_sdl: Any, request: Any, *, field_weights: Any = None,
                            default_list_size: int = 10,
                            max_list_size: int = MAX_LIST_FACTOR) -> dict[str, Any]:
    """Analyze one saved request object or an implementation-specific array batch.

    Every malformed public input raises :class:`WebDepthGraphQLError`; parser,
    JSON, arithmetic, indexing, and decoding exceptions are never exposed.
    """

    try:
        return _analyze_impl(schema_sdl, request, field_weights=field_weights,
                             default_list_size=default_list_size,
                             max_list_size=max_list_size)
    except WebDepthGraphQLError:
        raise
    except Exception as exc:  # fail-closed public boundary
        raise WebDepthGraphQLError("GraphQL cost analysis failed closed") from exc


def analyze_graphql_json(schema_sdl: Any, request_json: Any, *, field_weights: Any = None,
                         default_list_size: int = 10,
                         max_list_size: int = MAX_LIST_FACTOR) -> dict[str, Any]:
    """Parse strict saved request JSON, then call :func:`analyze_graphql_request`."""

    try:
        request = _strict_json(request_json, "GraphQL HTTP request JSON")
        return _analyze_impl(schema_sdl, request, field_weights=field_weights,
                             default_list_size=default_list_size,
                             max_list_size=max_list_size)
    except WebDepthGraphQLError:
        raise
    except Exception as exc:  # fail-closed public boundary
        raise WebDepthGraphQLError("GraphQL JSON cost analysis failed closed") from exc


def _read_bounded(path_value: str, label: str, maximum: int) -> str:
    try:
        path = Path(path_value)
        if not path.is_file() or path.stat().st_size > maximum:
            raise WebDepthGraphQLError(f"{label} is absent or exceeds {maximum} bytes")
        return path.read_text("utf-8", errors="strict")
    except WebDepthGraphQLError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise WebDepthGraphQLError(f"cannot read {label}") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webdepth_graphql_cost.py",
        description="Offline schema-aware GraphQL request cost analyzer",
    )
    parser.add_argument("schema", help="GraphQL SDL file")
    parser.add_argument("request", help="GraphQL HTTP request JSON object/array file")
    parser.add_argument("--weights", help="optional JSON object mapping field or Type.field to weight")
    parser.add_argument("--default-list-size", type=int, default=10)
    parser.add_argument("--max-list-size", type=int, default=MAX_LIST_FACTOR)
    parser.add_argument("--compact", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        try:
            args = _build_parser().parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        schema = _read_bounded(args.schema, "schema file", MAX_SOURCE_BYTES)
        request_text = _read_bounded(args.request, "request file", MAX_JSON_BYTES)
        weights = None
        if args.weights:
            weight_text = _read_bounded(args.weights, "weights file", MAX_JSON_BYTES)
            weights = _strict_json(weight_text, "field weights JSON")
        result = analyze_graphql_json(
            schema, request_text, field_weights=weights,
            default_list_size=args.default_list_size,
            max_list_size=args.max_list_size,
        )
        print(json.dumps(result, sort_keys=True, ensure_ascii=False,
                         indent=None if args.compact else 2))
        return 0
    except WebDepthGraphQLError as exc:
        print(f"webdepth_graphql_cost: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # CLI must fail closed without a traceback
        print(f"webdepth_graphql_cost: internal failure ({type(exc).__name__})", file=sys.stderr)
        return 2


__all__ = [
    "MAX_BATCH", "MAX_COST", "MAX_LIST_FACTOR", "WebDepthGraphQLError",
    "analyze_graphql_json", "analyze_graphql_request", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
