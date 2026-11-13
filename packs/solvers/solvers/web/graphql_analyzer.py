#!/usr/bin/env python3
"""Offline GraphQL schema/document analysis and reviewable query plans.

Existing CSCTF helpers emit generic introspection and alias bodies.  This lane
consumes *saved* introspection JSON, SDL-like operation documents, and captured
JSON request bodies to identify sensitive fields, recursive graph edges,
unbounded list arguments, alias/batch amplification, and mutation surfaces.
Nothing here opens a URL or submits a query.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_FILE = 16 * 1024 * 1024
MAX_TOKENS = 500_000
MAX_DEPTH = 128
MAX_FIELDS = 100_000
MAX_TYPES = 50_000
MAX_PLANS = 128


class GraphQLError(ValueError):
    pass


_SENSITIVE = re.compile(
    r"(?i)(?:pass(?:word|wd)?|secret|token|flag|admin|private|internal|debug|api.?key|credential|"
    r"reset|invite|ssn|credit|card|salary|medical|download|export|backup|config|env)"
)
_PAGINATION = {"first", "last", "limit", "offset", "after", "before", "page", "perPage", "take", "skip"}


def _bounded(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [MAX_FIELDS * 4]
    if depth > MAX_DEPTH or budget[0] <= 0:
        raise GraphQLError("JSON nesting/item cap exceeded")
    budget[0] -= 1
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 4096:
                raise GraphQLError("invalid JSON object key")
            _bounded(item, depth + 1, budget)
    elif isinstance(value, list):
        for item in value:
            _bounded(item, depth + 1, budget)


def _type_ref(value: Any, depth: int = 0) -> dict[str, Any] | None:
    if not isinstance(value, dict) or depth > 16:
        return None
    kind, name = value.get("kind"), value.get("name")
    nested = _type_ref(value.get("ofType"), depth + 1)
    if not isinstance(kind, str):
        return nested
    out: dict[str, Any] = {"kind": kind, "name": name if isinstance(name, str) else None}
    if nested is not None:
        out["of_type"] = nested
    return out


def _named_type(ref: dict[str, Any] | None) -> str | None:
    while ref:
        if ref.get("name"):
            return ref["name"]
        ref = ref.get("of_type")
    return None


def _is_list(ref: dict[str, Any] | None) -> bool:
    while ref:
        if ref.get("kind") == "LIST":
            return True
        ref = ref.get("of_type")
    return False


def analyze_introspection(value: Any) -> dict[str, Any]:
    """Analyze a standard introspection result without trusting semantic names."""
    _bounded(value)
    if isinstance(value, dict) and isinstance(value.get("data"), dict):
        value = value["data"]
    schema = value.get("__schema") if isinstance(value, dict) else None
    if schema is None and isinstance(value, dict) and "types" in value:
        schema = value
    if not isinstance(schema, dict) or not isinstance(schema.get("types"), list):
        raise GraphQLError("JSON does not contain an introspection __schema")
    if len(schema["types"]) > MAX_TYPES:
        raise GraphQLError("GraphQL type cap exceeded")
    roots = {}
    for key, label in (("queryType", "query"), ("mutationType", "mutation"),
                       ("subscriptionType", "subscription")):
        item = schema.get(key)
        roots[label] = item.get("name") if isinstance(item, dict) and isinstance(item.get("name"), str) else None
    types: dict[str, dict[str, Any]] = {}
    sensitive, list_fields, deprecated, edges = [], [], [], []
    field_count = 0
    for raw_type in schema["types"]:
        if not isinstance(raw_type, dict) or not isinstance(raw_type.get("name"), str):
            continue
        name = raw_type["name"]
        fields = []
        for raw_field in raw_type.get("fields") or []:
            if not isinstance(raw_field, dict) or not isinstance(raw_field.get("name"), str):
                continue
            field_count += 1
            if field_count > MAX_FIELDS:
                raise GraphQLError("GraphQL field cap exceeded")
            field_name = raw_field["name"]
            ref = _type_ref(raw_field.get("type"))
            args = []
            for raw_arg in raw_field.get("args") or []:
                if isinstance(raw_arg, dict) and isinstance(raw_arg.get("name"), str):
                    args.append({"name": raw_arg["name"], "type": _type_ref(raw_arg.get("type")),
                                 "default": raw_arg.get("defaultValue")})
            row = {"name": field_name, "type": ref, "named_type": _named_type(ref),
                   "list": _is_list(ref), "arguments": args,
                   "deprecated": bool(raw_field.get("isDeprecated")),
                   "deprecation_reason": raw_field.get("deprecationReason")}
            fields.append(row)
            path = f"{name}.{field_name}"
            if _SENSITIVE.search(path):
                sensitive.append({"path": path, "type": row["named_type"],
                                  "reason": "sensitive-name heuristic"})
            if row["list"]:
                names = {arg["name"] for arg in args}
                finding = {"path": path, "pagination_arguments": sorted(names & _PAGINATION)}
                if not finding["pagination_arguments"]:
                    finding["risk"] = "list field exposes no conventional pagination argument"
                list_fields.append(finding)
            if row["deprecated"]:
                deprecated.append({"path": path, "reason": row["deprecation_reason"]})
            if row["named_type"]:
                edges.append((name, row["named_type"], field_name))
        types[name] = {"kind": raw_type.get("kind"), "fields": fields,
                       "interfaces": [item.get("name") for item in raw_type.get("interfaces") or []
                                      if isinstance(item, dict) and isinstance(item.get("name"), str)],
                       "possible_types": [item.get("name") for item in raw_type.get("possibleTypes") or []
                                          if isinstance(item, dict) and isinstance(item.get("name"), str)]}
    cycles = []
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for source, target, field in edges:
        if target in types:
            adjacency.setdefault(source, []).append((target, field))
    for start in adjacency:
        stack = [(start, [], {start})]
        while stack and len(cycles) < 256:
            node, path, seen = stack.pop()
            if len(path) >= 12:
                continue
            for target, field in adjacency.get(node, []):
                step = path + [f"{node}.{field}"]
                if target == start:
                    cycles.append({"type": start, "path": step})
                elif target not in seen:
                    stack.append((target, step, seen | {target}))
    # De-duplicate cycle renderings while retaining deterministic ordering.
    unique_cycles, seen_cycles = [], set()
    for row in cycles:
        key = tuple(row["path"])
        if key not in seen_cycles:
            seen_cycles.add(key)
            unique_cycles.append(row)
    mutations = types.get(roots["mutation"] or "", {}).get("fields", [])
    subscriptions = types.get(roots["subscription"] or "", {}).get("fields", [])
    plans = build_review_plans(roots, types, sensitive)
    return {"roots": roots, "type_count": len(types), "field_count": field_count,
            "types": types, "sensitive_fields": sensitive, "list_fields": list_fields,
            "deprecated_fields": deprecated, "recursive_paths": unique_cycles,
            "mutations": mutations, "subscriptions": subscriptions,
            "review_plans": plans, "offline": True, "requests_sent": 0}


def build_review_plans(roots: dict[str, str | None], types: dict[str, Any],
                       sensitive: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [{"rank": 1, "name": "typename_baseline", "value": "query { __typename }",
             "purpose": "minimal parser/GraphQL confirmation", "candidate_only": True,
             "sent": False}]
    rank = 2
    query_root = roots.get("query")
    if query_root in types:
        for finding in sensitive[:MAX_PLANS - 1]:
            parent, field = finding["path"].split(".", 1)
            if parent != query_root:
                continue
            details = next((row for row in types[parent]["fields"] if row["name"] == field), None)
            if details is None or details["arguments"]:
                continue
            target = types.get(details["named_type"] or "")
            selection = " { __typename }" if target and target.get("kind") in {
                "OBJECT", "INTERFACE", "UNION"
            } else ""
            rows.append({"rank": rank, "name": f"review_{field}",
                         "value": f"query OfflineReview {{ {field}{selection} }}",
                         "purpose": "human-reviewed sensitive root field", "candidate_only": True,
                         "sent": False})
            rank += 1
            if len(rows) >= MAX_PLANS:
                break
    return rows


@dataclass(frozen=True)
class Token:
    value: str
    offset: int


def tokenize(document: str) -> list[Token]:
    if not isinstance(document, str) or len(document.encode("utf-8", "surrogatepass")) > MAX_FILE:
        raise GraphQLError("GraphQL document exceeds the file cap")
    out, offset = [], 0
    while offset < len(document):
        char = document[offset]
        if char.isspace() or char == ",":
            offset += 1
            continue
        if char == "#":
            end = document.find("\n", offset)
            offset = len(document) if end < 0 else end + 1
            continue
        start = offset
        if document.startswith('"""', offset):
            end = document.find('"""', offset + 3)
            if end < 0:
                raise GraphQLError("unterminated block string")
            offset = end + 3
            out.append(Token("<string>", start))
        elif char == '"':
            offset += 1
            while offset < len(document):
                if document[offset] == "\\":
                    offset += 2
                elif document[offset] == '"':
                    offset += 1
                    break
                else:
                    offset += 1
            else:
                raise GraphQLError("unterminated string")
            out.append(Token("<string>", start))
        elif document.startswith("...", offset):
            out.append(Token("...", offset)); offset += 3
        elif re.match(r"[_A-Za-z]", char):
            match = re.match(r"[_0-9A-Za-z]+", document[offset:])
            assert match is not None
            out.append(Token(match.group(), offset)); offset += len(match.group())
        elif char in "!$():=@[]{|}&":
            out.append(Token(char, offset)); offset += 1
        elif char == "-" or char.isdigit():
            match = re.match(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", document[offset:])
            if match is None:
                raise GraphQLError(f"invalid number at byte {offset}")
            out.append(Token("<number>", offset)); offset += len(match.group())
        else:
            raise GraphQLError(f"unexpected character at byte {offset}")
        if len(out) > MAX_TOKENS:
            raise GraphQLError("GraphQL token cap exceeded")
    return out


class _DocumentParser:
    def __init__(self, tokens: list[Token]):
        self.tokens, self.at = tokens, 0
        self.fields: list[dict[str, Any]] = []
        self.fragments: dict[str, dict[str, Any]] = {}
        self.operations: list[dict[str, Any]] = []
        self.aliases = 0
        self.spreads: list[str] = []
        self.directives: list[str] = []

    def peek(self, value: str | None = None):
        if self.at >= len(self.tokens):
            return False if value is not None else None
        return self.tokens[self.at].value == value if value is not None else self.tokens[self.at].value

    def take(self, value: str | None = None) -> str:
        got = self.peek()
        if got is None or (value is not None and got != value):
            offset = self.tokens[self.at].offset if self.at < len(self.tokens) else -1
            raise GraphQLError(f"expected {value or 'token'} at byte {offset}")
        self.at += 1
        return got

    def balanced(self, opening: str, closing: str):
        self.take(opening); depth = 1
        while depth:
            got = self.take()
            if got == opening:
                depth += 1
            elif got == closing:
                depth -= 1
            if depth > MAX_DEPTH:
                raise GraphQLError("GraphQL delimiter nesting cap exceeded")

    def skip_directives(self):
        while self.peek("@"):
            self.take("@"); name = self.take(); self.directives.append(name)
            if self.peek("("):
                self.balanced("(", ")")

    def selection(self, depth: int, operation: str):
        if depth > MAX_DEPTH:
            raise GraphQLError("GraphQL selection depth cap exceeded")
        self.take("{")
        count = 0
        while not self.peek("}"):
            if self.peek() is None:
                raise GraphQLError("unterminated selection set")
            if self.peek("..."):
                self.take("...")
                if self.peek("on"):
                    self.take("on"); type_condition = self.take(); self.skip_directives()
                    self.selection(depth + 1, operation)
                    self.spreads.append(f"inline:{type_condition}")
                else:
                    name = self.take(); self.spreads.append(name); self.skip_directives()
                continue
            first = self.take()
            alias, field = None, first
            if self.peek(":"):
                self.take(":"); alias, field = first, self.take(); self.aliases += 1
            if self.peek("("):
                self.balanced("(", ")")
            self.skip_directives()
            row = {"operation": operation, "field": field, "alias": alias, "depth": depth}
            self.fields.append(row); count += 1
            if len(self.fields) > MAX_FIELDS:
                raise GraphQLError("GraphQL field cap exceeded")
            if self.peek("{"):
                self.selection(depth + 1, operation)
        self.take("}")
        return count

    def parse(self):
        while self.peek() is not None:
            if self.peek("fragment"):
                self.take("fragment"); name = self.take(); self.take("on"); type_name = self.take()
                self.skip_directives(); before = len(self.fields); self.selection(1, f"fragment:{name}")
                self.fragments[name] = {"type": type_name, "field_count": len(self.fields) - before}
                continue
            operation, name = "query", None
            if self.peek() in ("query", "mutation", "subscription"):
                operation = self.take()
                if self.peek() not in ("{", "(", "@"):
                    name = self.take()
                if self.peek("("):
                    self.balanced("(", ")")
                self.skip_directives()
            elif not self.peek("{"):
                raise GraphQLError("document must contain an operation or fragment")
            before = len(self.fields)
            self.selection(1, operation)
            self.operations.append({"kind": operation, "name": name,
                                    "field_count": len(self.fields) - before})
        return {"operations": self.operations, "fragments": self.fragments, "fields": self.fields,
                "field_count": len(self.fields), "alias_count": self.aliases,
                "max_depth": max((row["depth"] for row in self.fields), default=0),
                "fragment_spreads": self.spreads, "directives": self.directives}


def analyze_document(document: str) -> dict[str, Any]:
    parsed = _DocumentParser(tokenize(document)).parse()
    counts: dict[str, int] = {}
    for row in parsed["fields"]:
        key = f"{row['operation']}:{row['field']}"
        counts[key] = counts.get(key, 0) + 1
    findings = []
    if parsed["max_depth"] > 12:
        findings.append({"kind": "deep_query", "value": parsed["max_depth"]})
    if parsed["alias_count"] > 20:
        findings.append({"kind": "alias_amplification", "value": parsed["alias_count"]})
    for key, count in counts.items():
        if count > 20:
            findings.append({"kind": "repeated_field", "field": key, "value": count})
    unresolved = sorted({name for name in parsed["fragment_spreads"]
                         if not name.startswith("inline:") and name not in parsed["fragments"]})
    if unresolved:
        findings.append({"kind": "undefined_fragments", "names": unresolved})
    parsed.update(findings=findings, offline=True, requests_sent=0)
    return parsed


def analyze_request_json(value: Any) -> dict[str, Any]:
    _bounded(value)
    requests = value if isinstance(value, list) else [value]
    if not requests or len(requests) > 1000 or not all(isinstance(item, dict) for item in requests):
        raise GraphQLError("GraphQL request JSON must be an object or bounded object list")
    rows = []
    for index, item in enumerate(requests):
        query = item.get("query")
        if not isinstance(query, str):
            raise GraphQLError(f"request {index} has no text query")
        rows.append({"index": index, "operation_name": item.get("operationName"),
                     "variables": item.get("variables"), "document": analyze_document(query)})
    findings = []
    if len(rows) > 1:
        findings.append({"kind": "http_batch", "count": len(rows)})
    return {"requests": rows, "batch_count": len(rows), "findings": findings,
            "offline": True, "requests_sent": 0}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise GraphQLError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="graphql_analyzer.py")
    parser.add_argument("input")
    parser.add_argument("--kind", choices=("auto", "schema", "document", "request"), default="auto")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        path = Path(args.input)
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            raise GraphQLError("input is absent or exceeds the file cap")
        text = path.read_text("utf-8", errors="strict")
        kind, parsed = args.kind, None
        if kind in ("auto", "schema", "request"):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                if kind != "auto":
                    raise GraphQLError("input is not strict JSON") from None
        if kind == "schema" or (kind == "auto" and isinstance(parsed, dict) and
                                ("__schema" in parsed or isinstance(parsed.get("data"), dict) and
                                 "__schema" in parsed["data"])):
            result = analyze_introspection(parsed)
        elif kind == "request" or (kind == "auto" and parsed is not None):
            result = analyze_request_json(parsed)
        else:
            result = analyze_document(text)
        print(json.dumps(result, sort_keys=True, default=str, indent=2 if args.json else None))
        return 0
    except Exception as exc:
        print(f"graphql_analyzer: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
