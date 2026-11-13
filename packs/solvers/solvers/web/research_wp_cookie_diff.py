#!/usr/bin/env python3
"""Offline request-Cookie parser-differential analyzer.

The input is a saved HTTP request/header block containing one or more
``Cookie`` fields.  The analyzer preserves those fields, then derives bounded
views for several documented parsing choices:

* modern semicolon parsing with separate, semicolon-joined, and comma-joined
  duplicate fields;
* RFC 2109-style ``$Version=1`` parsing with quoted spans and comma separators;
* Python ``SimpleCookie``-style quoted octal unescaping, implemented locally;
* Unicode whitespace trimming plus NFKC cookie-name normalization.

Every result is static evidence.  A parser difference does not prove that a
deployed front end, framework, or application uses either modeled policy, and
the report therefore never declares exploitability.  The module has no HTTP
client, process launcher, dynamic execution, or deserializer.

Research vectors modeled here are documented in PortSwigger Research:

* https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie
* https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique
* https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Iterable, Sequence
import unicodedata


MAX_INPUT_BYTES = 256 * 1024
MAX_HEADER_LINES = 2048
MAX_COOKIE_FIELDS = 64
MAX_HEADER_LINE_BYTES = 32 * 1024
MAX_COOKIE_PAIRS = 512
MAX_NAME_CHARS = 1024
MAX_VALUE_CHARS = 64 * 1024
MAX_FINDINGS = 256

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_REQUEST_LINE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+\s+\S+\s+HTTP/\d(?:\.\d)?$", re.I)
_STATUS_LINE = re.compile(r"^HTTP/\d(?:\.\d)?\s+\d{3}(?:\s+.*)?$", re.I)
_OCTAL_ESCAPE = re.compile(r"\\[0-3][0-7][0-7]")
_PROTECTED_PREFIXES = ("__Host-", "__Secure-")
_LEGACY_CONTROLS = frozenset({"$version", "$path", "$domain", "$port"})


class ResearchWPCookieError(ValueError):
    """Saved cookie evidence is malformed, ambiguous, or exceeds a bound."""


@dataclass(frozen=True, slots=True)
class CookieHeaderField:
    index: int
    line_number: int
    raw_name: str
    raw_value: str
    value: str

    def as_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "line_number": self.line_number,
            "raw_name": self.raw_name,
            "raw_value": self.raw_value,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class CookieObservation:
    index: int
    raw_name: str
    name: str
    raw_value: str
    value: str
    source_fields: tuple[int, ...]
    transformations: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "raw_name": self.raw_name,
            "name": self.name,
            "raw_value": self.raw_value,
            "value": self.value,
            "source_fields": list(self.source_fields),
            "transformations": list(self.transformations),
        }


@dataclass(frozen=True, slots=True)
class EffectiveCookie:
    name: str
    value: str
    observation_index: int

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "value": self.value,
            "observation_index": self.observation_index,
        }


@dataclass(frozen=True, slots=True)
class CookieParserView:
    name: str
    parser: str
    join_policy: str
    active: bool
    observations: tuple[CookieObservation, ...]
    first_wins: tuple[EffectiveCookie, ...]
    last_wins: tuple[EffectiveCookie, ...]
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "parser": self.parser,
            "join_policy": self.join_policy,
            "active": self.active,
            "observations": [item.as_dict() for item in self.observations],
            "first_wins": [item.as_dict() for item in self.first_wins],
            "last_wins": [item.as_dict() for item in self.last_wins],
            "notes": list(self.notes),
        }


@dataclass(frozen=True, slots=True)
class CookieFinding:
    code: str
    severity: str
    confidence: str
    summary: str
    evidence: tuple[str, ...]
    deployment_precondition: str
    vulnerability_confirmed: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "confidence": self.confidence,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "deployment_precondition": self.deployment_precondition,
            "vulnerability_confirmed": self.vulnerability_confirmed,
        }


@dataclass(frozen=True, slots=True)
class CookieDifferentialReport:
    input_encoding: str
    fields: tuple[CookieHeaderField, ...]
    views: tuple[CookieParserView, ...]
    findings: tuple[CookieFinding, ...]
    offline: bool = True
    network_requests: int = 0
    vulnerability_confirmed: bool = False
    runtime_confirmation_required: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "input_encoding": self.input_encoding,
            "fields": [item.as_dict() for item in self.fields],
            "views": [item.as_dict() for item in self.views],
            "findings": [item.as_dict() for item in self.findings],
            "offline": self.offline,
            "network_requests": self.network_requests,
            "vulnerability_confirmed": self.vulnerability_confirmed,
            "runtime_confirmation_required": self.runtime_confirmation_required,
        }


def _bounded_text(value: object) -> tuple[str, str]:
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise ResearchWPCookieError("saved headers are not valid Unicode text") from exc
        text, encoding = value, "unicode-text"
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            text, encoding = raw.decode("utf-8", "strict"), "utf-8"
        except UnicodeDecodeError:
            text, encoding = raw.decode("latin-1"), "latin-1"
    else:
        raise ResearchWPCookieError("saved headers must be text or bytes")
    if not raw:
        raise ResearchWPCookieError("saved headers are empty")
    if len(raw) > MAX_INPUT_BYTES:
        raise ResearchWPCookieError(f"saved headers exceed {MAX_INPUT_BYTES} bytes")
    if "\x00" in text:
        raise ResearchWPCookieError("saved headers contain NUL")
    return text, encoding


def _extract_cookie_fields(text: str) -> tuple[CookieHeaderField, ...]:
    normalized = text.replace("\r\n", "\n")
    if "\r" in normalized:
        raise ResearchWPCookieError("saved headers contain bare CR")
    lines = normalized.split("\n")
    if len(lines) > MAX_HEADER_LINES:
        raise ResearchWPCookieError(f"saved header line count exceeds {MAX_HEADER_LINES}")
    fields: list[CookieHeaderField] = []
    saw_header = False
    for line_number, line in enumerate(lines, 1):
        if len(line.encode("utf-8", "strict")) > MAX_HEADER_LINE_BYTES:
            raise ResearchWPCookieError(
                f"saved header line {line_number} exceeds {MAX_HEADER_LINE_BYTES} bytes"
            )
        if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in line):
            raise ResearchWPCookieError(f"saved header line {line_number} contains a control character")
        if line_number == 1 and (_REQUEST_LINE.fullmatch(line) or _STATUS_LINE.fullmatch(line)):
            continue
        if line == "":
            if saw_header or fields:
                break
            continue
        if line.startswith((" ", "\t")):
            raise ResearchWPCookieError(
                f"obsolete folded header at line {line_number} is ambiguous"
            )
        if ":" not in line:
            raise ResearchWPCookieError(f"saved header line {line_number} has no colon")
        raw_name, raw_value = line.split(":", 1)
        if not _HEADER_NAME.fullmatch(raw_name):
            raise ResearchWPCookieError(f"saved header name at line {line_number} is invalid")
        saw_header = True
        if raw_name.casefold() != "cookie":
            continue
        if len(fields) >= MAX_COOKIE_FIELDS:
            raise ResearchWPCookieError(f"Cookie field count exceeds {MAX_COOKIE_FIELDS}")
        fields.append(CookieHeaderField(
            index=len(fields) + 1,
            line_number=line_number,
            raw_name=raw_name,
            raw_value=raw_value,
            value=raw_value.strip(" \t"),
        ))
    if not fields:
        raise ResearchWPCookieError("saved headers contain no Cookie field")
    return tuple(fields)


def _split_segments(value: str, *, quote_aware: bool,
                    comma_separator: bool = False) -> tuple[list[str], bool]:
    segments: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in value:
        if quote_aware and quoted and escaped:
            current.append(char)
            escaped = False
            continue
        if quote_aware and quoted and char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote_aware and char == '"':
            current.append(char)
            quoted = not quoted
            continue
        if char == ";" and not quoted:
            segments.append("".join(current))
            current = []
            continue
        if comma_separator and char == "," and not quoted:
            segments.append("".join(current))
            current = []
            continue
        current.append(char)
    segments.append("".join(current))
    return segments, quoted


def _unquote_basic(value: str) -> tuple[str, tuple[str, ...]]:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        inner = value[1:-1]
        out: list[str] = []
        escaped = False
        changed = False
        for char in inner:
            if escaped:
                out.append(char)
                escaped = False
                changed = True
            elif char == "\\":
                escaped = True
            else:
                out.append(char)
        if escaped:
            out.append("\\")
        return "".join(out), (("quoted_pair_unescape",) if changed else ("quoted_value",))
    return value, ()


def _unquote_simplecookie(value: str) -> tuple[str, tuple[str, ...]]:
    """Decode the documented SimpleCookie quoted-pair/octal subset locally."""

    if not (len(value) >= 2 and value.startswith('"') and value.endswith('"')):
        return value, ()
    inner = value[1:-1]
    out: list[str] = []
    transforms: list[str] = ["quoted_value"]
    index = 0
    while index < len(inner):
        char = inner[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        if index + 3 < len(inner):
            digits = inner[index + 1:index + 4]
            if digits[0] in "0123" and all(item in "01234567" for item in digits[1:]):
                out.append(chr(int(digits, 8)))
                if "simplecookie_octal_escape" not in transforms:
                    transforms.append("simplecookie_octal_escape")
                index += 4
                continue
        if index + 1 < len(inner):
            out.append(inner[index + 1])
            if "quoted_pair_unescape" not in transforms:
                transforms.append("quoted_pair_unescape")
            index += 2
            continue
        out.append("\\")
        index += 1
    return "".join(out), tuple(transforms)


def _parse_cookie_value(
    value: str,
    *,
    source_fields: tuple[int, ...],
    quote_aware: bool,
    comma_separator: bool = False,
    unicode_names: bool = False,
    simplecookie: bool = False,
    skip_legacy_controls: bool = False,
) -> tuple[tuple[CookieObservation, ...], tuple[str, ...]]:
    segments, unterminated = _split_segments(
        value, quote_aware=quote_aware, comma_separator=comma_separator,
    )
    notes: list[str] = []
    if unterminated:
        notes.append("quoted value is unterminated in this parser view")
    rows: list[CookieObservation] = []
    for segment_index, segment in enumerate(segments, 1):
        # Keep non-ASCII leading characters in ``raw_name`` so the report can
        # prove exactly what the Unicode-normalized view changed.
        trimmed = segment.strip(" \t")
        if not trimmed:
            continue
        if "=" not in trimmed:
            notes.append(f"segment {segment_index} has no equals sign")
            continue
        raw_name, raw_value = trimmed.split("=", 1)
        ascii_name = raw_name.strip(" \t")
        name = unicodedata.normalize("NFKC", raw_name.strip()) if unicode_names else ascii_name
        raw_value = raw_value.strip() if unicode_names else raw_value.strip(" \t")
        if not name:
            notes.append(f"segment {segment_index} has an empty cookie name")
            continue
        if len(name) > MAX_NAME_CHARS:
            raise ResearchWPCookieError(f"cookie name exceeds {MAX_NAME_CHARS} characters")
        if len(raw_value) > MAX_VALUE_CHARS:
            raise ResearchWPCookieError(f"cookie value exceeds {MAX_VALUE_CHARS} characters")
        if skip_legacy_controls and name.casefold() in _LEGACY_CONTROLS:
            notes.append(f"legacy control {name!r} is not exposed as a cookie in this view")
            continue
        decoded, transforms = (
            _unquote_simplecookie(raw_value) if simplecookie else _unquote_basic(raw_value)
        )
        if unicode_names and name != ascii_name:
            transforms = transforms + ("unicode_name_trim_nfkc",)
        if len(decoded) > MAX_VALUE_CHARS:
            raise ResearchWPCookieError(f"decoded cookie value exceeds {MAX_VALUE_CHARS} characters")
        if len(rows) >= MAX_COOKIE_PAIRS:
            raise ResearchWPCookieError(f"cookie pair count exceeds {MAX_COOKIE_PAIRS}")
        rows.append(CookieObservation(
            index=len(rows) + 1,
            raw_name=raw_name,
            name=name,
            raw_value=raw_value,
            value=decoded,
            source_fields=source_fields,
            transformations=transforms,
        ))
    return tuple(rows), tuple(notes)


def _effective(rows: Sequence[CookieObservation], *, first: bool) -> tuple[EffectiveCookie, ...]:
    selected: dict[str, CookieObservation] = {}
    for row in rows:
        if first:
            selected.setdefault(row.name, row)
        else:
            selected[row.name] = row
    return tuple(
        EffectiveCookie(name, selected[name].value, selected[name].index)
        for name in sorted(selected)
    )


def _view(name: str, parser: str, join_policy: str, active: bool,
          observations: Sequence[CookieObservation], notes: Sequence[str]) -> CookieParserView:
    rows = tuple(observations) if active else ()
    return CookieParserView(
        name=name,
        parser=parser,
        join_policy=join_policy,
        active=active,
        observations=rows,
        first_wins=_effective(rows, first=True),
        last_wins=_effective(rows, first=False),
        notes=tuple(notes),
    )


def _version_one(value: str) -> bool:
    segments, _unterminated = _split_segments(value, quote_aware=True, comma_separator=True)
    for segment in segments:
        segment = segment.strip(" \t")
        if not segment:
            continue
        if "=" not in segment:
            return False
        name, raw_value = segment.split("=", 1)
        decoded, _ = _unquote_basic(raw_value.strip(" \t"))
        return name.strip(" \t").casefold() == "$version" and decoded == "1"
    return False


def _build_views(fields: tuple[CookieHeaderField, ...]) -> tuple[CookieParserView, ...]:
    separate_rows: list[CookieObservation] = []
    separate_notes: list[str] = []
    for field in fields:
        rows, notes = _parse_cookie_value(
            field.value,
            source_fields=(field.index,),
            quote_aware=False,
        )
        for row in rows:
            separate_rows.append(CookieObservation(
                index=len(separate_rows) + 1,
                raw_name=row.raw_name,
                name=row.name,
                raw_value=row.raw_value,
                value=row.value,
                source_fields=row.source_fields,
                transformations=row.transformations,
            ))
        separate_notes.extend(f"field {field.index}: {note}" for note in notes)

    all_fields = tuple(field.index for field in fields)
    semicolon_value = "; ".join(field.value for field in fields)
    comma_value = ", ".join(field.value for field in fields)
    semicolon_rows, semicolon_notes = _parse_cookie_value(
        semicolon_value, source_fields=all_fields, quote_aware=False,
    )
    comma_rows, comma_notes = _parse_cookie_value(
        comma_value, source_fields=all_fields, quote_aware=False,
    )
    versioned = _version_one(semicolon_value)
    legacy_rows: tuple[CookieObservation, ...] = ()
    legacy_notes: tuple[str, ...] = ("view inactive because the combined field does not begin with $Version=1",)
    if versioned:
        legacy_rows, legacy_notes = _parse_cookie_value(
            semicolon_value,
            source_fields=all_fields,
            quote_aware=True,
            comma_separator=True,
            skip_legacy_controls=True,
        )
    simple_rows, simple_notes = _parse_cookie_value(
        semicolon_value,
        source_fields=all_fields,
        quote_aware=True,
        simplecookie=True,
        skip_legacy_controls=True,
    )
    unicode_rows, unicode_notes = _parse_cookie_value(
        semicolon_value,
        source_fields=all_fields,
        quote_aware=False,
        unicode_names=True,
    )
    return (
        _view("modern-separate", "modern-semicolon", "keep-fields-separate", True,
              separate_rows, separate_notes),
        _view("modern-semicolon-join", "modern-semicolon", "join-with-semicolon", True,
              semicolon_rows, semicolon_notes),
        _view("modern-comma-join", "modern-semicolon", "join-with-comma", True,
              comma_rows, comma_notes),
        _view("legacy-versioned", "rfc2109-quoted", "join-with-semicolon", versioned,
              legacy_rows, legacy_notes),
        _view("python-simplecookie-style", "quoted-octal-subset", "join-with-semicolon", True,
              simple_rows, simple_notes),
        _view("unicode-trim-nfkc", "modern-semicolon-plus-name-normalization",
              "join-with-semicolon", True, unicode_rows, unicode_notes),
    )


def _visible(value: str, limit: int = 240) -> str:
    clipped = value[:limit]
    rendered = clipped.encode("unicode_escape", "backslashreplace").decode("ascii")
    return rendered + ("..." if len(value) > limit else "")


def _pairs(rows: Iterable[CookieObservation], limit: int = 24) -> str:
    values = [f"{_visible(row.name, 80)}={_visible(row.value, 120)}" for row in rows]
    suffix = " ..." if len(values) > limit else ""
    return "; ".join(values[:limit]) + suffix


def _codepoints(value: str) -> str:
    return " ".join(f"U+{ord(char):04X}" for char in value[:64])


def _finding(code: str, severity: str, confidence: str, summary: str,
             evidence: Sequence[str], precondition: str) -> CookieFinding:
    return CookieFinding(
        code=code,
        severity=severity,
        confidence=confidence,
        summary=summary,
        evidence=tuple(item[:1024] for item in evidence),
        deployment_precondition=precondition[:1024],
    )


def _append(findings: list[CookieFinding], finding: CookieFinding) -> None:
    if len(findings) >= MAX_FINDINGS:
        raise ResearchWPCookieError(f"finding count exceeds {MAX_FINDINGS}")
    findings.append(finding)


def _findings(fields: tuple[CookieHeaderField, ...],
              views: tuple[CookieParserView, ...]) -> tuple[CookieFinding, ...]:
    by_name = {view.name: view for view in views}
    modern = by_name["modern-separate"]
    semicolon = by_name["modern-semicolon-join"]
    comma = by_name["modern-comma-join"]
    legacy = by_name["legacy-versioned"]
    simple = by_name["python-simplecookie-style"]
    unicode_view = by_name["unicode-trim-nfkc"]
    findings: list[CookieFinding] = []

    if len(fields) > 1:
        _append(findings, _finding(
            "duplicate-cookie-fields", "info", "high",
            "The saved request contains multiple Cookie header fields.",
            (f"field lines: {[field.line_number for field in fields]!r}",),
            "A deployed intermediary or framework must choose a duplicate-header joining policy.",
        ))
        signatures = {
            view.name: tuple((item.name, item.value) for item in view.observations)
            for view in (modern, semicolon, comma)
        }
        if len(set(signatures.values())) > 1:
            _append(findings, _finding(
                "header-join-policy-difference", "medium", "high",
                "Separate, semicolon-joined, and comma-joined Cookie fields yield different static views.",
                tuple(f"{view.name}: {_pairs(view.observations)}" for view in (modern, semicolon, comma)),
                "The actual request path must preserve duplicate fields and select one of these join policies.",
            ))

    duplicates: dict[str, list[CookieObservation]] = {}
    for row in modern.observations:
        if not row.name.startswith("$"):
            duplicates.setdefault(row.name, []).append(row)
    for name in sorted(duplicates):
        rows = duplicates[name]
        if len(rows) > 1 and len({row.value for row in rows}) > 1:
            _append(findings, _finding(
                "duplicate-cookie-order-consequence", "high", "high",
                "A repeated cookie name has different first-wins and last-wins values.",
                (
                    f"name: {_visible(name)}",
                    f"ordered values: {[ _visible(row.value) for row in rows ]!r}",
                    f"first-wins: {_visible(rows[0].value)}",
                    f"last-wins: {_visible(rows[-1].value)}",
                ),
                "An application must select this cookie by name using an order-sensitive duplicate policy.",
            ))

    if legacy.active:
        modern_signature = tuple((row.name, row.value) for row in semicolon.observations
                                 if row.name.casefold() not in _LEGACY_CONTROLS)
        legacy_signature = tuple((row.name, row.value) for row in legacy.observations)
        if modern_signature != legacy_signature:
            _append(findings, _finding(
                "legacy-parser-view-difference", "medium", "high",
                "$Version=1 activates a quoted legacy model that differs from modern semicolon parsing.",
                (f"modern: {_pairs(semicolon.observations)}", f"legacy: {_pairs(legacy.observations)}"),
                "The deployed cookie parser must honor the leading $Version=1 control.",
            ))
        legacy_names = {row.name for row in legacy.observations}
        for candidate in semicolon.observations:
            if candidate.name.startswith("$") or candidate.name in legacy_names:
                continue
            pattern = re.compile(r"(?:^|[;,]\s*)" + re.escape(candidate.name) + r"\s*=")
            for container in legacy.observations:
                if pattern.search(container.value):
                    _append(findings, _finding(
                        "legacy-quoted-span-absorbs-cookie", "high", "high",
                        "A modern cookie pair is text inside another cookie's legacy quoted value.",
                        (
                            f"modern pair: {_visible(candidate.name)}={_visible(candidate.value)}",
                            f"legacy outer cookie: {_visible(container.name)}={_visible(container.value)}",
                        ),
                        "A legacy parser must be active and application logic must consume or reflect the outer value.",
                    ))
                    break

    for row in simple.observations:
        if "simplecookie_octal_escape" in row.transformations:
            _append(findings, _finding(
                "simplecookie-octal-decoding", "medium", "high",
                "A quoted cookie value changes when three-digit octal escapes are decoded.",
                (
                    f"cookie: {_visible(row.name)}",
                    f"raw value: {_visible(row.raw_value)}",
                    f"decoded value: {_visible(row.value)}",
                ),
                "The deployed parser must implement Python SimpleCookie-compatible quoted octal decoding.",
            ))

    normalized_groups: dict[str, list[CookieObservation]] = {}
    for row in unicode_view.observations:
        ascii_name = row.raw_name.strip(" \t")
        normalized_groups.setdefault(row.name, []).append(row)
        if row.name != ascii_name:
            _append(findings, _finding(
                "unicode-cookie-name-normalization", "medium", "high",
                "Unicode trimming or NFKC changes a saved cookie name.",
                (
                    f"raw name: {_visible(ascii_name)}",
                    f"raw code points: {_codepoints(ascii_name)}",
                    f"normalized name: {_visible(row.name)}",
                ),
                "The server-side framework must decode the header to Unicode and apply the modeled normalization.",
            ))
            for prefix in _PROTECTED_PREFIXES:
                if row.name.startswith(prefix) and not ascii_name.startswith(prefix):
                    _append(findings, _finding(
                        "protected-prefix-emerges-after-normalization", "high", "high",
                        "A __Host- or __Secure- cookie name appears only after Unicode normalization.",
                        (
                            f"raw name: {_visible(ascii_name)}",
                            f"normalized name: {_visible(row.name)}",
                            f"prefix: {prefix}",
                        ),
                        "Browser acceptance and the server's byte-to-Unicode plus trimming policy must match this path.",
                    ))
    for name in sorted(normalized_groups):
        rows = normalized_groups[name]
        raw_names = {row.raw_name.strip(" \t") for row in rows}
        if len(raw_names) > 1:
            _append(findings, _finding(
                "unicode-normalized-name-collision", "high", "high",
                "Distinct raw cookie names collapse to one Unicode-normalized name.",
                (
                    f"normalized name: {_visible(name)}",
                    f"raw names: {[ _visible(item) for item in sorted(raw_names) ]!r}",
                    f"ordered values: {[ _visible(row.value) for row in rows ]!r}",
                ),
                "The deployed framework must normalize names before duplicate selection.",
            ))

    return tuple(findings)


def _analyze(value: object) -> CookieDifferentialReport:
    text, encoding = _bounded_text(value)
    fields = _extract_cookie_fields(text)
    views = _build_views(fields)
    if not next(view for view in views if view.name == "modern-separate").observations:
        raise ResearchWPCookieError("Cookie fields contain no parseable name=value pairs")
    return CookieDifferentialReport(
        input_encoding=encoding,
        fields=fields,
        views=views,
        findings=_findings(fields, views),
    )


def analyze_cookie_headers(value: object) -> CookieDifferentialReport:
    """Analyze saved Cookie fields and convert every hostile-input failure.

    This is the public untrusted-input boundary.  It never opens a file, sends a
    request, or allows a standard-library parsing exception to escape.
    """

    try:
        return _analyze(value)
    except ResearchWPCookieError:
        raise
    except Exception as exc:
        raise ResearchWPCookieError("unable to analyze saved Cookie fields safely") from exc


class _Parser(argparse.ArgumentParser):
    pass


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="research_wp_cookie_diff.py",
        description="Analyze saved request Cookie parser differentials without network access",
    )
    parser.add_argument("artifact", help="saved header text, or a path with --file")
    parser.add_argument("--file", action="store_true", help="read saved header bytes from a local file")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    return parser


def _read_file(path_text: str) -> bytes:
    try:
        path = Path(path_text)
        if not path.is_file():
            raise ResearchWPCookieError("input file is absent")
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ResearchWPCookieError(f"input file exceeds {MAX_INPUT_BYTES} bytes")
        return path.read_bytes()
    except ResearchWPCookieError:
        raise
    except OSError as exc:
        raise ResearchWPCookieError("unable to read input file") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        artifact: object = _read_file(args.artifact) if args.file else args.artifact
        report = analyze_cookie_headers(artifact)
        print(json.dumps(report.as_dict(), sort_keys=True, indent=2 if args.pretty else None))
        return 0
    except ResearchWPCookieError as exc:
        print(f"research_wp_cookie_diff: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        print(f"research_wp_cookie_diff: malformed input ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
