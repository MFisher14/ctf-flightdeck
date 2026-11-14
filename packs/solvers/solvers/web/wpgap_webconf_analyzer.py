#!/usr/bin/env python3
"""Offline Apache/Nginx confusion and Windows best-fit evidence analyzer.

Only caller-supplied text is parsed.  The module never follows ``include``
directives, inspects configured paths, sends requests, or executes programs.
Every finding is structural evidence with explicit runtime prerequisites.

The Windows mapping is a curated security oracle from Microsoft's published
WindowsBestFit tables, not Unicode normalization or a complete NLS emulator.
Unknown non-ASCII input makes a projection incomplete instead of being guessed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Iterable, Sequence


MAX_INPUT_BYTES = 512 * 1024
MAX_LINES = 8192
MAX_LINE_BYTES = 32 * 1024
MAX_TOKENS = 65_536
MAX_TOKEN_CHARS = 32 * 1024
MAX_NESTING = 64
MAX_DIRECTIVES = 8192
MAX_FINDINGS = 512
MAX_BEST_FIT_CHARS = 4096

APACHE_CONFUSION_REFERENCE = "https://blog.orange.tw/posts/2024-08-confusion-attacks-en/"
APACHE_SECURITY_REFERENCE = "https://httpd.apache.org/security/vulnerabilities_24.html"
NGINX_URI_REFERENCE = "https://nginx.org/en/docs/http/ngx_http_core_module.html#var_uri"
NGINX_MERGE_REFERENCE = "https://nginx.org/en/docs/http/ngx_http_core_module.html#merge_slashes"
NGINX_PROXY_REFERENCE = "https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass"
NGINX_SPLIT_REFERENCE = "https://reversebrain.github.io/2021/03/29/The-story-of-Nginx-and-uri-variable/"
NGINX_GIXY_ALIAS_REFERENCE = "https://github.com/yandex/gixy/blob/master/docs/en/plugins/aliastraversal.md"
WORSTFIT_REFERENCE = "https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/"
WINDOWS_BEST_FIT_REFERENCE = "https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WindowsBestFit/"
WINDOWS_CONVERSION_REFERENCE = (
    "https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/"
    "nf-stringapiset-widechartomultibyte"
)


class WPGAPWebConfError(ValueError):
    """A supplied config or best-fit request is malformed or exceeds a bound."""


@dataclass(frozen=True, slots=True)
class Directive:
    server: str
    name: str
    arguments: tuple[str, ...]
    line: int
    context: tuple[str, ...]
    raw: str
    opens_block: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "server": self.server,
            "name": self.name,
            "arguments": list(self.arguments),
            "line": self.line,
            "context": list(self.context),
            "raw": self.raw,
            "opens_block": self.opens_block,
        }


@dataclass(frozen=True, slots=True)
class ConfigFinding:
    code: str
    severity: str
    confidence: str
    line: int
    context: tuple[str, ...]
    directive: str
    summary: str
    evidence: tuple[str, ...]
    prerequisites: tuple[str, ...]
    references: tuple[str, ...]
    vulnerability_confirmed: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "confidence": self.confidence,
            "line": self.line,
            "context": list(self.context),
            "directive": self.directive,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "prerequisites": list(self.prerequisites),
            "references": list(self.references),
            "vulnerability_confirmed": self.vulnerability_confirmed,
        }


@dataclass(frozen=True, slots=True)
class ConfigReport:
    server: str
    platform: str
    directives: tuple[Directive, ...]
    findings: tuple[ConfigFinding, ...]
    notes: tuple[str, ...]
    offline: bool = True
    network_requests: int = 0
    vulnerability_confirmed: bool = False
    runtime_confirmation_required: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "server": self.server,
            "platform": self.platform,
            "directives": [item.as_dict() for item in self.directives],
            "findings": [item.as_dict() for item in self.findings],
            "notes": list(self.notes),
            "offline": self.offline,
            "network_requests": self.network_requests,
            "vulnerability_confirmed": self.vulnerability_confirmed,
            "runtime_confirmation_required": self.runtime_confirmation_required,
        }


@dataclass(frozen=True, slots=True)
class BestFitMapping:
    code_page: str
    source: str
    source_codepoint: str
    replacement_bytes: tuple[int, ...]
    replacement: str
    category: str
    description: str
    reference: str = WINDOWS_BEST_FIT_REFERENCE

    @property
    def input_character(self) -> str:
        return self.source

    @property
    def input_codepoint(self) -> str:
        return self.source_codepoint

    @property
    def output_bytes(self) -> tuple[int, ...]:
        return self.replacement_bytes

    @property
    def output_text(self) -> str:
        return self.replacement

    def as_dict(self) -> dict[str, object]:
        return {
            "code_page": self.code_page,
            "source": self.source,
            "source_codepoint": self.source_codepoint,
            "replacement_bytes": list(self.replacement_bytes),
            "replacement_hex": " ".join(f"{item:02X}" for item in self.replacement_bytes),
            "replacement": self.replacement,
            "category": self.category,
            "description": self.description,
            "reference": self.reference,
        }


@dataclass(frozen=True, slots=True)
class BestFitOccurrence:
    offset: int
    code_page: str
    source: str
    source_codepoint: str
    replacement_bytes: tuple[int, ...]
    replacement: str
    category: str
    description: str

    @property
    def index(self) -> int:
        return self.offset

    @property
    def input_character(self) -> str:
        return self.source

    @property
    def input_codepoint(self) -> str:
        return self.source_codepoint

    @property
    def output_bytes(self) -> tuple[int, ...]:
        return self.replacement_bytes

    @property
    def output_text(self) -> str:
        return self.replacement

    def as_dict(self) -> dict[str, object]:
        return {
            "offset": self.offset,
            "code_page": self.code_page,
            "source": self.source,
            "source_codepoint": self.source_codepoint,
            "replacement_bytes": list(self.replacement_bytes),
            "replacement_hex": " ".join(f"{item:02X}" for item in self.replacement_bytes),
            "replacement": self.replacement,
            "category": self.category,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class BestFitFinding:
    code: str
    severity: str
    confidence: str
    offset: int
    summary: str
    evidence: tuple[str, ...]
    prerequisites: tuple[str, ...]
    references: tuple[str, ...]
    vulnerability_confirmed: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "confidence": self.confidence,
            "offset": self.offset,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "prerequisites": list(self.prerequisites),
            "references": list(self.references),
            "vulnerability_confirmed": self.vulnerability_confirmed,
        }


@dataclass(frozen=True, slots=True)
class BestFitReport:
    code_page: str
    input_text: str
    projected_text: str | None
    complete: bool
    mappings: tuple[BestFitOccurrence, ...]
    unknown_codepoints: tuple[str, ...]
    findings: tuple[BestFitFinding, ...]
    notes: tuple[str, ...]
    offline: bool = True
    network_requests: int = 0
    vulnerability_confirmed: bool = False
    runtime_confirmation_required: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "code_page": self.code_page,
            "input_text": self.input_text,
            "projected_text": self.projected_text,
            "complete": self.complete,
            "mappings": [item.as_dict() for item in self.mappings],
            "unknown_codepoints": list(self.unknown_codepoints),
            "findings": [item.as_dict() for item in self.findings],
            "notes": list(self.notes),
            "offline": self.offline,
            "network_requests": self.network_requests,
            "vulnerability_confirmed": self.vulnerability_confirmed,
            "runtime_confirmation_required": self.runtime_confirmation_required,
        }


def _codepoint(character: str) -> str:
    return f"U+{ord(character):04X}"


def _mapping(
    code_page: int,
    codepoint: int,
    replacement: str,
    category: str,
    description: str,
) -> BestFitMapping:
    return BestFitMapping(
        code_page=f"cp{code_page}",
        source=chr(codepoint),
        source_codepoint=f"U+{codepoint:04X}",
        replacement_bytes=tuple(replacement.encode("ascii", "strict")),
        replacement=replacement,
        category=category,
        description=description,
    )


_RAW_BEST_FIT: tuple[tuple[tuple[int, ...], int, str, str, str], ...] = (
    ((874, *range(1250, 1259)), 0xFF02, '"', "argument_quote", "fullwidth quotation mark becomes an ASCII quotation mark"),
    ((874, *range(1250, 1259)), 0xFF0F, "/", "path_separator", "fullwidth solidus becomes an ASCII path separator"),
    ((874, *range(1250, 1259)), 0xFF3C, "\\", "path_separator", "fullwidth reverse solidus becomes an ASCII path separator or escape"),
    ((932,), 0x00A5, "\\", "path_separator", "yen sign becomes an ASCII backslash"),
    ((932,), 0x00AD, "-", "option_prefix", "soft hyphen becomes an ASCII hyphen"),
    ((936,), 0x00AD, "-", "option_prefix", "soft hyphen becomes an ASCII hyphen"),
    ((949,), 0x20A9, "\\", "path_separator", "won sign becomes an ASCII backslash"),
    ((950,), 0x00AD, "-", "option_prefix", "soft hyphen becomes an ASCII hyphen"),
    ((1250,), 0x00E0, "a", "identifier_collision", "a-grave becomes ASCII a"),
    ((1252,), 0x0100, "A", "identifier_collision", "A-macron becomes ASCII A"),
    ((1252,), 0x02BA, '"', "argument_quote", "modifier double-prime becomes an ASCII quote"),
    ((1252,), 0x2010, "-", "option_prefix", "Unicode hyphen becomes an ASCII hyphen"),
    ((1252,), 0x2212, "-", "option_prefix", "minus sign becomes an ASCII hyphen"),
    ((1252,), 0x2215, "/", "path_separator", "division slash becomes an ASCII slash"),
    ((1252,), 0x2216, "\\", "path_separator", "set-minus becomes an ASCII backslash"),
    ((1252,), 0x221A, "v", "identifier_collision", "square root becomes ASCII v"),
    ((1252,), 0x03C0, "p", "identifier_collision", "Greek pi becomes ASCII p"),
    ((1252,), 0x2077, "7", "identifier_collision", "superscript seven becomes ASCII 7"),
    ((1252,), 0x2264, "=", "identifier_collision", "less-than-or-equal becomes ASCII equals"),
    ((1252,), 0x221E, "8", "identifier_collision", "infinity becomes ASCII 8"),
    ((1252,), 0xFF0D, "-", "option_prefix", "fullwidth hyphen-minus becomes ASCII hyphen"),
    ((1252,), 0xFF1A, ":", "path_separator", "fullwidth colon becomes ASCII colon"),
)


def _build_best_fit_rows() -> tuple[BestFitMapping, ...]:
    rows: list[BestFitMapping] = []
    for pages, codepoint, replacement, category, description in _RAW_BEST_FIT:
        rows.extend(_mapping(page, codepoint, replacement, category, description) for page in pages)
    return tuple(sorted(rows, key=lambda item: (int(item.code_page[2:]), ord(item.source))))


_BEST_FIT_ROWS = _build_best_fit_rows()
_BEST_FIT_INDEX = {
    (int(item.code_page[2:]), ord(item.source)): item for item in _BEST_FIT_ROWS
}
_SUPPORTED_CODE_PAGES = frozenset(int(item.code_page[2:]) for item in _BEST_FIT_ROWS)
_EAST_ASIAN_FULLWIDTH_NEGATIVE = {
    page: frozenset((0xFF02, 0xFF0F, 0xFF3C)) for page in (932, 936, 949, 950)
}


def _validate_code_page(code_page: object) -> int:
    page: int
    if isinstance(code_page, bool):
        raise WPGAPWebConfError("code_page must name a page from the curated table")
    if isinstance(code_page, int):
        page = code_page
    elif isinstance(code_page, str):
        match = re.fullmatch(r"(?i)(?:cp)?([0-9]{3,5})", code_page.strip())
        if match is None:
            raise WPGAPWebConfError("code_page must look like 1252 or 'cp1252'")
        page = int(match.group(1), 10)
    else:
        raise WPGAPWebConfError("code_page must name a page from the curated table")
    if page not in _SUPPORTED_CODE_PAGES:
        supported = ", ".join(f"cp{item}" for item in sorted(_SUPPORTED_CODE_PAGES))
        raise WPGAPWebConfError(f"unsupported code page cp{page}; curated pages: {supported}")
    return page


def best_fit_table(code_page: int | str | None = None) -> tuple[BestFitMapping, ...]:
    """Return stable rows while exposing only :class:`WPGAPWebConfError`."""

    try:
        if code_page is None:
            return _BEST_FIT_ROWS
        page = _validate_code_page(code_page)
        return tuple(
            item for item in _BEST_FIT_ROWS if item.code_page == f"cp{page}"
        )
    except WPGAPWebConfError:
        raise
    except Exception as exc:
        raise WPGAPWebConfError("unable to select best-fit table safely") from exc


_BEST_FIT_PREREQUISITES = (
    "the target uses this exact Windows ANSI code page at the conversion boundary",
    "attacker-controlled Unicode reaches a wide-to-ANSI conversion with best-fit enabled",
    "security validation or escaping occurs before the lossy conversion",
    "a downstream path, argv, CGI, or identifier parser gives the introduced byte syntax",
)


def _best_fit_finding(item: BestFitOccurrence) -> BestFitFinding:
    codes = {
        "path_separator": ("bestfit-path-separator", "high", "best-fit introduces path syntax"),
        "argument_quote": ("bestfit-quote-introduction", "high", "best-fit introduces a quote delimiter"),
        "option_prefix": ("bestfit-option-prefix", "high", "best-fit introduces an option prefix"),
        "identifier_collision": ("bestfit-identifier-collision", "medium", "best-fit collapses an identifier character"),
    }
    code, severity, summary = codes[item.category]
    return BestFitFinding(
        code=code,
        severity=severity,
        confidence="high",
        offset=item.offset,
        summary=summary,
        evidence=(
            f"{item.code_page}: {item.source_codepoint} -> "
            f"{' '.join(f'{byte:02X}' for byte in item.replacement_bytes)} ({item.replacement!r})",
            item.description,
        ),
        prerequisites=_BEST_FIT_PREREQUISITES,
        references=(WINDOWS_BEST_FIT_REFERENCE, WORSTFIT_REFERENCE, WINDOWS_CONVERSION_REFERENCE),
    )


def _analyze_best_fit(text: object, code_page: object) -> BestFitReport:
    if not isinstance(text, str):
        raise WPGAPWebConfError("best-fit input must be Unicode text")
    if not text or len(text) > MAX_BEST_FIT_CHARS:
        raise WPGAPWebConfError(f"best-fit input must contain 1..{MAX_BEST_FIT_CHARS} characters")
    if "\x00" in text:
        raise WPGAPWebConfError("best-fit input must not contain NUL")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in text):
        raise WPGAPWebConfError("best-fit input contains an unpaired surrogate")
    page = _validate_code_page(code_page)
    canonical_page = f"cp{page}"

    projected: list[str] = []
    occurrences: list[BestFitOccurrence] = []
    unknown: list[str] = []
    unknown_offsets: list[int] = []
    notes: list[str] = [
        "curated published mapping evidence only; this is not a complete Windows NLS conversion",
    ]
    for offset, character in enumerate(text):
        value = ord(character)
        if value <= 0x7F:
            projected.append(character)
            continue
        mapping = _BEST_FIT_INDEX.get((page, value))
        if mapping is None:
            label = _codepoint(character)
            if label not in unknown:
                unknown.append(label)
            unknown_offsets.append(offset)
            if value in _EAST_ASIAN_FULLWIDTH_NEGATIVE.get(page, frozenset()):
                note = (
                    f"negative oracle: {label} on {canonical_page} does not collapse to the "
                    "corresponding ASCII character in the published table"
                )
                if note not in notes:
                    notes.append(note)
            continue
        projected.append(mapping.replacement)
        occurrences.append(BestFitOccurrence(
            offset=offset,
            code_page=canonical_page,
            source=character,
            source_codepoint=mapping.source_codepoint,
            replacement_bytes=mapping.replacement_bytes,
            replacement=mapping.replacement,
            category=mapping.category,
            description=mapping.description,
        ))

    complete = not unknown
    findings = [_best_fit_finding(item) for item in occurrences]
    if unknown:
        notes.append("projection withheld because non-ASCII characters have no curated row")
        findings.append(BestFitFinding(
            code="bestfit-incomplete-projection",
            severity="informational",
            confidence="high",
            offset=unknown_offsets[0],
            summary="the curated table cannot establish a complete conversion",
            evidence=(f"unknown code points: {', '.join(unknown)}",),
            prerequisites=("obtain the target Windows build/code-page conversion behavior",),
            references=(WINDOWS_BEST_FIT_REFERENCE,),
        ))
    return BestFitReport(
        code_page=canonical_page,
        input_text=text,
        projected_text="".join(projected) if complete else None,
        complete=complete,
        mappings=tuple(occurrences),
        unknown_codepoints=tuple(unknown),
        findings=tuple(findings),
        notes=tuple(notes),
    )


def analyze_best_fit(text: object, code_page: object) -> BestFitReport:
    """Project only curated rows and expose only the declared exception."""

    try:
        return _analyze_best_fit(text, code_page)
    except WPGAPWebConfError:
        raise
    except Exception as exc:
        raise WPGAPWebConfError("unable to analyze best-fit input safely") from exc


def _bounded_config_text(value: object) -> str:
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise WPGAPWebConfError("configuration is not valid Unicode text") from exc
        text = value
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise WPGAPWebConfError("configuration bytes are not valid UTF-8") from exc
    else:
        raise WPGAPWebConfError("configuration must be text or bytes")
    if not raw:
        raise WPGAPWebConfError("configuration is empty")
    if len(raw) > MAX_INPUT_BYTES:
        raise WPGAPWebConfError(f"configuration exceeds {MAX_INPUT_BYTES} bytes")
    if "\x00" in text:
        raise WPGAPWebConfError("configuration contains NUL")
    if text.startswith("\ufeff"):
        text = text[1:]
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        raise WPGAPWebConfError("configuration contains a bare carriage return")
    lines = text.split("\n")
    if len(lines) > MAX_LINES:
        raise WPGAPWebConfError(f"configuration exceeds {MAX_LINES} lines")
    for line_number, line in enumerate(lines, 1):
        if len(line.encode("utf-8", "strict")) > MAX_LINE_BYTES:
            raise WPGAPWebConfError(
                f"configuration line {line_number} exceeds {MAX_LINE_BYTES} bytes"
            )
    if not text.strip():
        raise WPGAPWebConfError("configuration contains no text")
    return text


def _split_words(value: str, line: int) -> tuple[str, ...]:
    words: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(value):
        character = value[index]
        if quote is not None:
            if character == quote:
                quote = None
            elif (
                character == "\\"
                and index + 1 < len(value)
                and value[index + 1] in (quote, "\\")
            ):
                current.append(value[index + 1])
                index += 1
            else:
                current.append(character)
        elif character in ('"', "'"):
            quote = character
        elif character.isspace():
            if current:
                words.append("".join(current))
                current = []
        else:
            current.append(character)
        if len(current) > MAX_TOKEN_CHARS:
            raise WPGAPWebConfError(
                f"token at line {line} exceeds {MAX_TOKEN_CHARS} characters"
            )
        index += 1
    if quote is not None:
        raise WPGAPWebConfError(f"unterminated quote at line {line}")
    if current:
        words.append("".join(current))
    if len(words) > MAX_TOKENS:
        raise WPGAPWebConfError(f"too many tokens at line {line}")
    return tuple(words)


def _strip_apache_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in ('"', "'"):
            quote = character
        elif character == "#":
            return value[:index]
    return value


def _apache_logical_lines(text: str) -> tuple[tuple[int, str], ...]:
    logical: list[tuple[int, str]] = []
    pieces: list[str] = []
    start = 0
    for line_number, physical in enumerate(text.split("\n"), 1):
        clean = _strip_apache_comment(physical).rstrip()
        if not pieces and not clean.strip():
            continue
        if not pieces:
            start = line_number
        trailing = len(clean) - len(clean.rstrip("\\"))
        if trailing % 2:
            pieces.append(clean[:-1].strip())
            continue
        pieces.append(clean.strip())
        joined = " ".join(piece for piece in pieces if piece)
        if joined:
            logical.append((start, joined))
        pieces = []
    if pieces:
        raise WPGAPWebConfError(f"unterminated Apache continuation at line {start}")
    return tuple(logical)


def _parse_apache(text: str) -> tuple[Directive, ...]:
    directives: list[Directive] = []
    contexts: list[tuple[str, int]] = []
    for line, raw in _apache_logical_lines(text):
        if raw.startswith("<"):
            if not raw.endswith(">"):
                raise WPGAPWebConfError(f"malformed Apache section tag at line {line}")
            inner = raw[1:-1].strip()
            if inner.startswith("/"):
                words = _split_words(inner[1:].strip(), line)
                if len(words) != 1:
                    raise WPGAPWebConfError(f"malformed Apache closing tag at line {line}")
                if (
                    not contexts
                    or contexts[-1][0].split(" ", 1)[0].casefold()
                    != words[0].casefold()
                ):
                    raise WPGAPWebConfError(f"unbalanced Apache closing tag at line {line}")
                contexts.pop()
                continue
            words = _split_words(inner, line)
            if not words:
                raise WPGAPWebConfError(f"empty Apache section tag at line {line}")
            if len(contexts) >= MAX_NESTING:
                raise WPGAPWebConfError(
                    f"Apache nesting exceeds {MAX_NESTING} at line {line}"
                )
            # The opening line is part of the internal context identity.  Two
            # separate ``<VirtualHost *:80>`` blocks must never be correlated
            # merely because their textual selectors are identical.
            contexts.append((f"{' '.join(words)} (line {line})", line))
            continue
        words = _split_words(raw, line)
        if not words:
            continue
        if len(directives) >= MAX_DIRECTIVES:
            raise WPGAPWebConfError(
                f"Apache directive count exceeds {MAX_DIRECTIVES}"
            )
        directives.append(Directive(
            server="apache",
            name=words[0].casefold(),
            arguments=words[1:],
            line=line,
            context=tuple(item[0] for item in contexts),
            raw=raw,
        ))
    if contexts:
        label, line = contexts[-1]
        raise WPGAPWebConfError(
            f"unclosed Apache section {label!r} from line {line}"
        )
    return tuple(directives)


@dataclass(frozen=True, slots=True)
class _NginxToken:
    kind: str
    value: str
    line: int


def _lex_nginx(text: str) -> tuple[_NginxToken, ...]:
    tokens: list[_NginxToken] = []
    index = 0
    line = 1
    length = len(text)

    def append(kind: str, value: str, token_line: int) -> None:
        if len(value) > MAX_TOKEN_CHARS:
            raise WPGAPWebConfError(
                f"Nginx token at line {token_line} exceeds {MAX_TOKEN_CHARS} characters"
            )
        if len(tokens) >= MAX_TOKENS:
            raise WPGAPWebConfError(f"Nginx token count exceeds {MAX_TOKENS}")
        tokens.append(_NginxToken(kind, value, token_line))

    while index < length:
        character = text[index]
        if character in " \t\v\f":
            index += 1
            continue
        if character == "\n":
            line += 1
            index += 1
            continue
        if character == "#":
            while index < length and text[index] != "\n":
                index += 1
            continue
        if character in "{};":
            append(
                {"{": "lbrace", "}": "rbrace", ";": "semicolon"}[character],
                character,
                line,
            )
            index += 1
            continue

        token_line = line
        current: list[str] = []
        quote: str | None = None
        quoted_token = False
        if character in ('"', "'"):
            quote = character
            quoted_token = True
            index += 1
        while index < length:
            character = text[index]
            if quote is not None:
                if character == quote:
                    index += 1
                    quote = None
                    break
                if character == "\n":
                    raise WPGAPWebConfError(
                        f"newline inside Nginx quote at line {token_line}"
                    )
                if character == "\\" and index + 1 < length:
                    following = text[index + 1]
                    if following in (
                        quote, "\\", '"', "'", " ", "\t", ";", "{", "}", "#"
                    ):
                        current.append(following)
                    else:
                        current.extend(("\\", following))
                    index += 2
                    continue
                current.append(character)
                index += 1
                continue
            if character == "$" and index + 1 < length and text[index + 1] == "{":
                closing = text.find("}", index + 2)
                if closing < 0:
                    raise WPGAPWebConfError(
                        f"unterminated braced Nginx variable at line {token_line}"
                    )
                current.extend(text[index:closing + 1])
                index = closing + 1
                continue
            if character.isspace() or character in "{};#":
                break
            if character == "\\" and index + 1 < length:
                following = text[index + 1]
                if following in (" ", "\t", ";", "{", "}", "#", "\\", '"', "'"):
                    current.append(following)
                else:
                    current.extend(("\\", following))
                index += 2
                continue
            current.append(character)
            index += 1
            if len(current) > MAX_TOKEN_CHARS:
                raise WPGAPWebConfError(
                    f"Nginx token at line {token_line} exceeds {MAX_TOKEN_CHARS} characters"
                )
        if quote is not None:
            raise WPGAPWebConfError(
                f"unterminated Nginx quote at line {token_line}"
            )
        if not current and not quoted_token:
            raise WPGAPWebConfError(
                f"empty or malformed Nginx token at line {token_line}"
            )
        append("word", "".join(current), token_line)
    return tuple(tokens)


@dataclass(frozen=True, slots=True)
class _NginxContext:
    name: str
    arguments: tuple[str, ...]
    line: int

    @property
    def label(self) -> str:
        return " ".join((self.name, *self.arguments))


def _parse_nginx(text: str) -> tuple[Directive, ...]:
    directives: list[Directive] = []
    contexts: list[_NginxContext] = []
    pending: list[_NginxToken] = []

    def add_directive(opens_block: bool) -> None:
        if not pending:
            line = contexts[-1].line if contexts else 1
            raise WPGAPWebConfError(f"empty Nginx directive near line {line}")
        if len(directives) >= MAX_DIRECTIVES:
            raise WPGAPWebConfError(
                f"Nginx directive count exceeds {MAX_DIRECTIVES}"
            )
        directives.append(Directive(
            server="nginx",
            name=pending[0].value.casefold(),
            arguments=tuple(item.value for item in pending[1:]),
            line=pending[0].line,
            context=tuple(item.label for item in contexts),
            raw=" ".join(item.value for item in pending)
            + (" {" if opens_block else ";"),
            opens_block=opens_block,
        ))

    for token in _lex_nginx(text):
        if token.kind == "word":
            pending.append(token)
            continue
        if token.kind == "semicolon":
            add_directive(False)
            pending = []
            continue
        if token.kind == "lbrace":
            add_directive(True)
            if len(contexts) >= MAX_NESTING:
                raise WPGAPWebConfError(
                    f"Nginx nesting exceeds {MAX_NESTING} at line {token.line}"
                )
            contexts.append(_NginxContext(
                name=pending[0].value.casefold(),
                arguments=tuple(item.value for item in pending[1:]),
                line=pending[0].line,
            ))
            pending = []
            continue
        if pending:
            raise WPGAPWebConfError(
                f"Nginx directive lacks semicolon before line {token.line}"
            )
        if not contexts:
            raise WPGAPWebConfError(
                f"unbalanced Nginx closing brace at line {token.line}"
            )
        contexts.pop()
    if pending:
        raise WPGAPWebConfError(
            f"unterminated Nginx directive at line {pending[0].line}"
        )
    if contexts:
        context = contexts[-1]
        raise WPGAPWebConfError(
            f"unclosed Nginx block {context.label!r} from line {context.line}"
        )
    if not directives:
        raise WPGAPWebConfError("Nginx configuration contains no directives")
    return tuple(directives)


_APACHE_CUES = re.compile(
    r"(?im)^\s*(?:<\/?(?:virtualhost|directory|files|location)\b|"
    r"rewriterule\b|rewritecond\b|documentroot\b|sethandler\b|"
    r"allowencodedslashes\b|addtype\b)"
)
_NGINX_CUES = re.compile(
    r"(?im)^\s*(?:http\s*\{|server\s*\{|location\b[^\n]*\{|"
    r"proxy_pass\b|proxy_set_header\b|add_header\b|add_trailer\b|"
    r"merge_slashes\b|alias\b)[^\n]*(?:[;{])"
)


def _detect_server(text: str) -> str:
    apache = bool(_APACHE_CUES.search(text))
    nginx = bool(_NGINX_CUES.search(text))
    if apache and nginx:
        raise WPGAPWebConfError(
            "configuration has both Apache and Nginx syntax cues"
        )
    if apache:
        return "apache"
    if nginx:
        return "nginx"
    raise WPGAPWebConfError(
        "unable to identify server; supply server='apache' or server='nginx'"
    )


def _append_config_finding(
    rows: list[ConfigFinding],
    *,
    code: str,
    severity: str,
    confidence: str,
    directive: Directive,
    summary: str,
    evidence: Iterable[str],
    prerequisites: Iterable[str],
    references: Iterable[str],
) -> None:
    finding = ConfigFinding(
        code=code,
        severity=severity,
        confidence=confidence,
        line=directive.line,
        context=directive.context,
        directive=directive.raw,
        summary=summary,
        evidence=tuple(evidence),
        prerequisites=tuple(prerequisites),
        references=tuple(references),
    )
    key = (finding.code, finding.line, finding.context, finding.evidence)
    if any(
        (item.code, item.line, item.context, item.evidence) == key for item in rows
    ):
        return
    if len(rows) >= MAX_FINDINGS:
        raise WPGAPWebConfError(f"finding count exceeds {MAX_FINDINGS}")
    rows.append(finding)


_NUMERIC_BACKREF = re.compile(r"(?:\$[1-9][0-9]*|%[1-9][0-9]*)")
_ANY_EXPANSION = re.compile(
    r"(?:\$[1-9][0-9]*|%[1-9][0-9]*|\$\{[^}]+\}|%\{[^}]+\})"
)
_UNTYPED_PREFIX = re.compile(
    r"^(?:\$[1-9][0-9]*|%[1-9][0-9]*|\$\{[^}]+\}|%\{[^}]+\})"
)
_DECODED_URI = re.compile(
    r"\$(?:\{(?:uri|document_uri)\}|(?:uri|document_uri)\b)"
)


def _apache_flag_names(arguments: tuple[str, ...]) -> frozenset[str]:
    value = " ".join(arguments).strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return frozenset(
        part.strip().split("=", 1)[0].casefold()
        for part in value.split(",")
        if part.strip()
    )


def _apache_server_scope(context: tuple[str, ...]) -> bool:
    per_directory = (
        "directory", "directorymatch", "files", "filesmatch", "location", "locationmatch"
    )
    return not any(
        item.split(" ", 1)[0].casefold() in per_directory for item in context
    )


def _context_has(context: tuple[str, ...], kind: str) -> bool:
    expected = kind.casefold()
    return any(
        item.split(" ", 1)[0].casefold() == expected for item in context
    )


def _apache_vhost_scope(context: tuple[str, ...]) -> str | None:
    for item in reversed(context):
        if item.split(" ", 1)[0].casefold() == "virtualhost":
            return item
    return None


def _apache_same_scope_pairs(
    left: tuple[Directive, ...], right: tuple[Directive, ...]
) -> tuple[tuple[Directive, Directive], ...]:
    """Pair only evidence declared in the same concrete server/vhost scope."""

    return tuple(
        (first, second)
        for first in left
        for second in right
        if _apache_vhost_scope(first.context) == _apache_vhost_scope(second.context)
    )


def _apache_effective_for_scope(
    candidates: tuple[Directive, ...], scope: str | None
) -> Directive | None:
    """Select the last same-scope value, else the main-server inherited value."""

    local = tuple(
        item for item in candidates if _apache_vhost_scope(item.context) == scope
    )
    if local:
        return max(local, key=lambda item: item.line)
    if scope is not None:
        global_values = tuple(
            item
            for item in candidates
            if _apache_vhost_scope(item.context) is None
        )
        if global_values:
            return max(global_values, key=lambda item: item.line)
    return None


def _analyze_apache(
    directives: tuple[Directive, ...], platform: str
) -> tuple[ConfigFinding, ...]:
    findings: list[ConfigFinding] = []
    document_roots = tuple(
        item for item in directives if item.name == "documentroot"
    )

    for item in directives:
        if item.name == "rewriterule" and len(item.arguments) >= 2:
            pattern, substitution = item.arguments[:2]
            flags = _apache_flag_names(item.arguments[2:])
            backref = _NUMERIC_BACKREF.search(substitution)
            suffix = substitution[backref.end():] if backref is not None else ""
            literal_suffix = _ANY_EXPANSION.sub("", suffix)
            effective_root = _apache_effective_for_scope(
                document_roots, _apache_vhost_scope(item.context)
            )
            if (
                backref is not None
                and "(" in pattern
                and literal_suffix
            ):
                _append_config_finding(
                    findings,
                    code="apache-encoded-question-suffix",
                    severity="high",
                    confidence="high",
                    directive=item,
                    summary="attacker backreference is followed by a literal rewrite suffix",
                    evidence=(
                        f"directive: {item.raw}",
                        f"backreference {backref.group(0)!r} is followed by non-expansion suffix {suffix!r}",
                        "CVE-2024-38474 uses an encoded question mark to truncate that suffix",
                    ),
                    prerequisites=(
                        "the capture is attacker-controlled and may contain an encoded question mark",
                        "the Apache version or UnsafeAllow3F behavior permits the substitution",
                        "the rewritten filename reaches a security-relevant resource or handler",
                    ),
                    references=(APACHE_CONFUSION_REFERENCE, APACHE_SECURITY_REFERENCE),
                )
            if (
                flags.intersection(("h", "t"))
                and backref is not None
                and "(" in pattern
            ):
                _append_config_finding(
                    findings,
                    code="apache-handler-flag-confusion",
                    severity="high",
                    confidence="high" if backref is not None else "medium",
                    directive=item,
                    summary="a rule assigns handler/type metadata before final filename interpretation",
                    evidence=(
                        f"directive: {item.raw}",
                        f"rewrite flags include {sorted(flags.intersection(('h', 't')))!r}",
                    ),
                    prerequisites=(
                        "attacker input satisfies the rule before its final filename interpretation",
                        "the handler or media type remains attached after rewrite processing",
                    ),
                    references=(APACHE_CONFUSION_REFERENCE,),
                )
            unsafe = flags.intersection(("unsafeallow3f", "unsafeprefixstat"))
            if unsafe:
                _append_config_finding(
                    findings,
                    code="apache-unsafe-compatibility-flag",
                    severity="high",
                    confidence="high",
                    directive=item,
                    summary="a compatibility flag restores legacy unsafe rewrite behavior",
                    evidence=(
                        f"directive: {item.raw}",
                        f"enabled flags: {sorted(unsafe)!r}",
                    ),
                    prerequisites=(
                        "this rule is reachable by attacker-controlled request paths",
                    ),
                    references=(APACHE_CONFUSION_REFERENCE, APACHE_SECURITY_REFERENCE),
                )
            if _UNTYPED_PREFIX.search(substitution) and "p" not in flags:
                _append_config_finding(
                    findings,
                    code="apache-untyped-backreference-prefix",
                    severity="high",
                    confidence="high",
                    directive=item,
                    summary="attacker expansion chooses the semantic prefix of the substitution",
                    evidence=(
                        f"directive: {item.raw}",
                        f"substitution starts without a fixed type: {substitution!r}",
                    ),
                    prerequisites=(
                        "the leading expansion is attacker-controlled",
                        "the Apache build dispatches a scheme-like result such as proxy:",
                    ),
                    references=(APACHE_CONFUSION_REFERENCE, APACHE_SECURITY_REFERENCE),
                )
            if (
                effective_root is not None
                and _apache_server_scope(item.context)
                and re.match(r"^/(?:\$[1-9][0-9]*|%[1-9][0-9]*)", substitution)
            ):
                _append_config_finding(
                    findings,
                    code="apache-documentroot-dual-interpretation",
                    severity="high",
                    confidence="high",
                    directive=item,
                    summary="server/vhost output can be absolute or DocumentRoot-relative",
                    evidence=(
                        f"directive: {item.raw}",
                        "DocumentRoot evidence: "
                        + f"line {effective_root.line}: "
                        + repr(" ".join(effective_root.arguments)),
                    ),
                    prerequisites=(
                        "this is an effective server/vhost rule, not per-directory rewriting",
                        "attacker input controls the leading rewritten path component",
                        "Apache 2.4.0-2.4.59 behavior or UnsafePrefixStat permits the documented lookup ambiguity",
                    ),
                    references=(APACHE_CONFUSION_REFERENCE, APACHE_SECURITY_REFERENCE),
                )

        if item.name == "addtype" and item.arguments:
            handler = item.arguments[0].casefold()
            if (
                handler.startswith("application/x-httpd-")
                or handler.startswith("proxy:")
                or handler in ("server-status", "cgi-script")
            ):
                _append_config_finding(
                    findings,
                    code="apache-legacy-addtype-handler",
                    severity="high",
                    confidence="high",
                    directive=item,
                    summary="AddType carries a handler-shaped legacy value",
                    evidence=(f"directive: {item.raw}",),
                    prerequisites=(
                        "the effective version/module path treats content type as a handler",
                        "an indirect or rewritten request reaches a matching extension",
                    ),
                    references=(APACHE_CONFUSION_REFERENCE, APACHE_SECURITY_REFERENCE),
                )

    protected_files = tuple(
        item
        for item in directives
        if _context_has(item.context, "files")
        and item.name in ("authtype", "require", "authname", "authuserfile")
    )
    proxy_file_handlers = tuple(
        item
        for item in directives
        if _context_has(item.context, "filesmatch")
        and item.name == "sethandler"
        and any(
            marker in " ".join(item.arguments).casefold()
            for marker in ("proxy:", "fcgi://")
        )
    )
    for protected, handler in _apache_same_scope_pairs(
        protected_files, proxy_file_handlers
    ):
        _append_config_finding(
            findings,
            code="apache-files-proxy-handler-split",
            severity="high",
            confidence="medium",
            directive=handler,
            summary="basename ACL and proxy/FCGI handler use different filename contexts",
            evidence=(
                f"protected <Files> directive at line {protected.line}",
                f"directive: {handler.raw}",
            ),
            prerequisites=(
                "the <Files> and <FilesMatch> expressions overlap after different interpretations",
                "the proxy/FastCGI backend resolves an encoded-question suffix differently",
                "Apache 2.4.0-2.4.59 behavior or UnsafeAllow3F permits the relevant encoded-question path",
                "the protected resource is otherwise reachable",
            ),
            references=(APACHE_CONFUSION_REFERENCE, APACHE_SECURITY_REFERENCE),
        )

    if platform == "windows":
        encoded_slash_directives = tuple(
            item
            for item in directives
            if item.name == "allowencodedslashes"
        )
        merge_directives = tuple(
            item
            for item in directives
            if item.name == "mergeslashes"
        )
        scopes = {None}
        scopes.update(
            scope
            for scope in (
                _apache_vhost_scope(item.context) for item in directives
            )
            if scope is not None
        )
        for scope in sorted(scopes, key=lambda item: "" if item is None else item):
            encoded = _apache_effective_for_scope(
                encoded_slash_directives, scope
            )
            merged = _apache_effective_for_scope(merge_directives, scope)
            if (
                encoded is None
                or merged is None
                or not encoded.arguments
                or not merged.arguments
                or encoded.arguments[0].casefold() not in ("on", "nodecode")
                or merged.arguments[0].casefold() != "off"
            ):
                continue
            anchor = merged if _apache_vhost_scope(merged.context) is not None else encoded
            _append_config_finding(
                findings,
                code="apache-windows-unc-surface",
                severity="high",
                confidence="high",
                directive=anchor,
                summary="Windows path processing preserves the encoded UNC request shape",
                evidence=(
                    f"AllowEncodedSlashes enabled at line {encoded.line}",
                    f"MergeSlashes effective value at line {merged.line}: {merged.raw}",
                    "platform was explicitly supplied as windows",
                ),
                prerequisites=(
                    "the request reaches Windows filesystem or UNC interpretation",
                    "outbound UNC authentication or remote resource access is possible",
                    "version-specific Apache UNC restrictions do not block the path",
                ),
                references=(APACHE_CONFUSION_REFERENCE, APACHE_SECURITY_REFERENCE),
            )

    return tuple(
        sorted(findings, key=lambda item: (item.line, item.code, item.evidence))
    )


def _contains_decoded_uri(arguments: Iterable[str]) -> bool:
    return bool(_DECODED_URI.search(" ".join(arguments)))


def _nearest_location(context: tuple[str, ...]) -> tuple[str, str] | None:
    for label in reversed(context):
        if label.casefold().startswith("location "):
            spec = label.split(" ", 1)[1].strip()
            parts = spec.split()
            if not parts:
                return None
            if parts[0] in ("=", "^~", "~", "~*"):
                if len(parts) < 2:
                    return None
                kind = {
                    "=": "exact",
                    "^~": "prefix",
                    "~": "regex",
                    "~*": "regex",
                }[parts[0]]
                return kind, parts[1]
            if parts[0].startswith("@"):
                return "named", parts[0]
            if parts[0].startswith("$"):
                return "predicate", parts[0]
            return "prefix", parts[0]
    return None


def _proxy_uri_component(arguments: tuple[str, ...]) -> bool:
    if not arguments:
        return False
    target = arguments[0]
    if "$" in target:
        return False
    match = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", target)
    if match is None:
        return False
    remainder = target[match.end():]
    slash = remainder.find("/")
    return slash >= 0 and bool(remainder[slash:])


def _proxy_uri_component_ends_slash(arguments: tuple[str, ...]) -> bool:
    if not _proxy_uri_component(arguments):
        return False
    target = arguments[0]
    match = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", target)
    if match is None:
        return False
    remainder = target[match.end():]
    path = remainder[remainder.find("/"):].split("?", 1)[0].split("#", 1)[0]
    return path.endswith("/")


def _local_break_rewrite(item: Directive) -> bool:
    if (
        item.name != "rewrite"
        or len(item.arguments) < 3
        or item.arguments[-1].casefold() != "break"
    ):
        return False
    replacement = item.arguments[1]
    return replacement != "-" and not replacement.startswith(
        ("http://", "https://", "$scheme")
    )


def _redirect_return(arguments: tuple[str, ...]) -> bool:
    if not arguments:
        return False
    if arguments[0] in ("301", "302", "303", "307", "308"):
        return len(arguments) >= 2
    return len(arguments) == 1 and arguments[0].startswith(
        ("http://", "https://", "$scheme", "//")
    )


def _analyze_nginx(
    directives: tuple[Directive, ...]
) -> tuple[ConfigFinding, ...]:
    findings: list[ConfigFinding] = []
    by_context: dict[tuple[str, ...], list[Directive]] = {}
    for item in directives:
        by_context.setdefault(item.context, []).append(item)

    for item in directives:
        if (
            item.name == "return"
            and _redirect_return(item.arguments)
            and _contains_decoded_uri(item.arguments)
        ):
            _append_config_finding(
                findings,
                code="nginx-decoded-uri-response-field",
                severity="high",
                confidence="high",
                directive=item,
                summary="decoded normalized URI is interpolated into a Location field",
                evidence=(
                    f"directive: {item.raw}",
                    "$uri/$document_uri is decoded before this redirect is serialized",
                ),
                prerequisites=(
                    "attacker-controlled percent-encoded CR/LF reaches the normalized URI",
                    "the Nginx build does not reject controls during serialization",
                ),
                references=(NGINX_URI_REFERENCE, NGINX_SPLIT_REFERENCE),
            )
        if (
            item.name in ("add_header", "add_trailer")
            and len(item.arguments) >= 2
            and _contains_decoded_uri(item.arguments[1:])
        ):
            _append_config_finding(
                findings,
                code="nginx-decoded-uri-response-field",
                severity="high",
                confidence="high",
                directive=item,
                summary="decoded normalized URI is interpolated into a response field",
                evidence=(
                    f"directive: {item.raw}",
                    f"$uri/$document_uri reaches {item.name}",
                ),
                prerequisites=(
                    "the directive is emitted for the selected response status",
                    *(
                        ("the response/protocol path emits HTTP trailers",)
                        if item.name == "add_trailer"
                        else ()
                    ),
                    "the Nginx build does not reject controls during serialization",
                ),
                references=(NGINX_URI_REFERENCE, NGINX_SPLIT_REFERENCE),
            )
        if (
            item.name == "proxy_set_header"
            and len(item.arguments) >= 2
            and _contains_decoded_uri(item.arguments[1:])
        ):
            _append_config_finding(
                findings,
                code="nginx-decoded-uri-upstream-field",
                severity="high",
                confidence="high",
                directive=item,
                summary="decoded normalized URI is interpolated into an upstream header",
                evidence=(f"directive: {item.raw}",),
                prerequisites=(
                    "attacker-controlled percent-encoded controls reach the normalized URI",
                    "the Nginx build serializes the value without rejecting controls",
                ),
                references=(NGINX_URI_REFERENCE, NGINX_PROXY_REFERENCE),
            )
        if item.name == "proxy_pass" and _contains_decoded_uri(item.arguments):
            _append_config_finding(
                findings,
                code="nginx-decoded-uri-upstream-target",
                severity="high",
                confidence="high",
                directive=item,
                summary="decoded normalized URI is interpolated into an upstream request target",
                evidence=(f"directive: {item.raw}",),
                prerequisites=(
                    "attacker-controlled percent-encoded controls reach the normalized URI",
                    "the Nginx build/upstream path preserves the injected bytes",
                ),
                references=(NGINX_URI_REFERENCE, NGINX_PROXY_REFERENCE),
            )

        location = _nearest_location(item.context)
        if item.name == "alias" and item.arguments and location is not None:
            kind, expression = location
            if (
                kind == "prefix"
                and not expression.endswith("/")
                and item.arguments[0].endswith("/")
            ):
                _append_config_finding(
                    findings,
                    code="nginx-alias-prefix-traversal",
                    severity="high",
                    confidence="high",
                    directive=item,
                    summary="location/alias boundary matches published alias traversal",
                    evidence=(
                        f"directive: {item.raw}",
                        f"prefix location {expression!r} lacks a trailing slash",
                        f"directory alias {item.arguments[0]!r} ends with a slash",
                    ),
                    prerequisites=(
                        "attacker input appends a parent segment after the location prefix",
                        "the resolved path reaches a file outside the intended directory",
                    ),
                    references=(NGINX_URI_REFERENCE, NGINX_GIXY_ALIAS_REFERENCE),
                )
        if item.name == "proxy_pass" and location is not None:
            kind, expression = location
            has_uri = _proxy_uri_component(item.arguments)
            if (
                kind == "prefix"
                and not expression.endswith("/")
                and _proxy_uri_component_ends_slash(item.arguments)
            ):
                _append_config_finding(
                    findings,
                    code="nginx-proxy-off-by-slash",
                    severity="medium",
                    confidence="medium",
                    directive=item,
                    summary="location/proxy boundaries permit off-by-slash transformation",
                    evidence=(
                        f"directive: {item.raw}",
                        f"prefix location {expression!r} lacks a trailing slash",
                    ),
                    prerequisites=(
                        "the backend normalizes dot segments or repeated slashes",
                        "the transformed path reaches an unintended upstream resource",
                    ),
                    references=(NGINX_PROXY_REFERENCE,),
                )
            if kind in ("regex", "named") and has_uri:
                _append_config_finding(
                    findings,
                    code="nginx-regex-location-proxy-uri",
                    severity="medium",
                    confidence="high",
                    directive=item,
                    summary="proxy_pass has a URI where replacement prefix is indeterminate",
                    evidence=(
                        f"directive: {item.raw}",
                        f"{kind} location expression: {expression!r}",
                    ),
                    prerequisites=(
                        "this directive belongs to the effective running configuration",
                    ),
                    references=(NGINX_PROXY_REFERENCE,),
                )

        if (
            item.name == "merge_slashes"
            and item.arguments
            and item.arguments[0].casefold() == "off"
        ):
            _append_config_finding(
                findings,
                code="nginx-merge-slashes-off",
                severity="medium",
                confidence="high",
                directive=item,
                summary="slash merging is disabled despite the documented warning",
                evidence=(
                    f"directive: {item.raw}",
                    "merge_slashes off can preserve paths that miss protected prefixes",
                ),
                prerequisites=(
                    "security policy assumes adjacent slashes are merged",
                    "the setting is not intentionally required for base64-like URI data",
                ),
                references=(NGINX_MERGE_REFERENCE,),
            )

    for scoped in by_context.values():
        rewrites = tuple(
            item
            for item in scoped
            if _local_break_rewrite(item)
        )
        proxies = tuple(
            item
            for item in scoped
            if item.name == "proxy_pass" and _proxy_uri_component(item.arguments)
        )
        for proxy in proxies:
            if not rewrites:
                break
            _append_config_finding(
                findings,
                code="nginx-rewrite-break-proxy-uri",
                severity="medium",
                confidence="high",
                directive=proxy,
                summary="rewrite break makes the proxy_pass URI component ineffective",
                evidence=(
                    "rewrite with break at lines "
                    + ", ".join(str(item.line) for item in rewrites),
                    f"proxy_pass directive: {proxy.raw}",
                ),
                prerequisites=(
                    "a security rule assumes the configured proxy URI prefix remains effective",
                    "the rewritten full URI reaches an unintended upstream resource",
                ),
                references=(NGINX_PROXY_REFERENCE,),
            )

    return tuple(
        sorted(findings, key=lambda item: (item.line, item.code, item.evidence))
    )


def _analyze_server_config(
    value: object,
    *,
    server: object = "auto",
    platform: object = "unknown",
) -> ConfigReport:
    if (
        not isinstance(server, str)
        or server.casefold() not in ("auto", "apache", "nginx")
    ):
        raise WPGAPWebConfError("server must be 'auto', 'apache', or 'nginx'")
    if not isinstance(platform, str):
        raise WPGAPWebConfError(
            "platform must be 'unknown', 'windows', 'unix', or 'posix'"
        )
    normalized_platform = platform.casefold()
    if normalized_platform == "posix":
        normalized_platform = "unix"
    if normalized_platform not in ("unknown", "windows", "unix"):
        raise WPGAPWebConfError(
            "platform must be 'unknown', 'windows', 'unix', or 'posix'"
        )
    normalized_server = server.casefold()
    text = _bounded_config_text(value)
    if normalized_server == "auto":
        normalized_server = _detect_server(text)
    directives = (
        _parse_apache(text)
        if normalized_server == "apache"
        else _parse_nginx(text)
    )
    findings = (
        _analyze_apache(directives, normalized_platform)
        if normalized_server == "apache"
        else _analyze_nginx(directives)
    )
    notes = [
        "static configuration evidence only; no request was sent and exploitability was not confirmed",
        "include directives are recorded but never resolved or opened",
    ]
    if any(
        item.name in ("include", "includeoptional") for item in directives
    ):
        notes.append(
            "one or more includes were not followed; effective configuration may differ"
        )
    if normalized_server == "apache" and normalized_platform == "unknown":
        notes.append(
            "platform is unknown; Windows-only UNC consequences were not inferred"
        )
    return ConfigReport(
        server=normalized_server,
        platform=normalized_platform,
        directives=directives,
        findings=findings,
        notes=tuple(notes),
    )


def analyze_server_config(
    value: object,
    *,
    server: object = "auto",
    platform: object = "unknown",
) -> ConfigReport:
    """Parse supplied config and expose only the declared exception."""

    try:
        return _analyze_server_config(
            value, server=server, platform=platform
        )
    except WPGAPWebConfError:
        raise
    except Exception as exc:
        raise WPGAPWebConfError(
            "unable to analyze server configuration safely"
        ) from exc


def _read_bounded_file(path_text: object) -> bytes:
    if not isinstance(path_text, str) or not path_text:
        raise WPGAPWebConfError("configuration path must be non-empty text")
    try:
        path = Path(path_text)
        if not path.is_file():
            raise WPGAPWebConfError("configuration file is absent")
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise WPGAPWebConfError(
                f"configuration file exceeds {MAX_INPUT_BYTES} bytes"
            )
        with path.open("rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise WPGAPWebConfError(
                f"configuration file exceeds {MAX_INPUT_BYTES} bytes"
            )
        return raw
    except WPGAPWebConfError:
        raise
    except (OSError, ValueError, TypeError, OverflowError) as exc:
        raise WPGAPWebConfError("unable to read configuration file") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wpgap_webconf_analyzer.py",
        description=(
            "Offline Apache/Nginx confusion and Windows best-fit evidence analyzer"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    config = subparsers.add_parser(
        "config", help="analyze a supplied local server config"
    )
    config.add_argument(
        "artifact", help="path to an httpd.conf/nginx.conf-style artifact"
    )
    config.add_argument(
        "--server", choices=("auto", "apache", "nginx"), default="auto"
    )
    config.add_argument(
        "--platform",
        choices=("unknown", "windows", "unix", "posix"),
        default="unknown",
    )
    config.add_argument(
        "--pretty", action="store_true", help="indent JSON output"
    )

    bestfit = subparsers.add_parser(
        "bestfit", help="analyze text with the curated best-fit table"
    )
    bestfit.add_argument("text", help="Unicode text to project")
    bestfit.add_argument("--code-page", required=True)
    bestfit.add_argument(
        "--pretty", action="store_true", help="indent JSON output"
    )

    table = subparsers.add_parser(
        "table", help="print curated best-fit rows"
    )
    table.add_argument("--code-page")
    table.add_argument(
        "--pretty", action="store_true", help="indent JSON output"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2

        if args.command == "config":
            result: object = analyze_server_config(
                _read_bounded_file(args.artifact),
                server=args.server,
                platform=args.platform,
            ).as_dict()
        elif args.command == "bestfit":
            result = analyze_best_fit(args.text, args.code_page).as_dict()
        else:
            result = {
                "rows": [
                    item.as_dict() for item in best_fit_table(args.code_page)
                ],
                "offline": True,
                "network_requests": 0,
            }
        print(
            json.dumps(
                result,
                sort_keys=True,
                indent=2 if args.pretty else None,
            )
        )
        return 0
    except WPGAPWebConfError as exc:
        print(f"wpgap_webconf_analyzer: {exc}", file=sys.stderr)
        return 2
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
    ) as exc:
        print(
            f"wpgap_webconf_analyzer: malformed input ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
