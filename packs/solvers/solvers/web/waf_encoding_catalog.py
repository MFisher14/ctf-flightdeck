#!/usr/bin/env python3
"""Deterministic WAF-normalization and encoding catalog, entirely offline.

Candidates are inert strings.  The module neither sends them nor evaluates the
decoded result.  Its static analyzer searches bounded supplied source or saved
responses for normalization order and product evidence without parsing them.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import html
import re
from typing import Callable, Iterable, Sequence
import unicodedata
import urllib.parse


MAX_INPUT = 4096
MAX_OUTPUT = 65_536
MAX_TEXT = 256_000
MAX_PIPELINE = 4


class WAFEncodingInputError(ValueError):
    """Raised when a catalog request is malformed or unbounded."""


@dataclass(frozen=True, slots=True)
class EncodingCandidate:
    family: str
    name: str
    value: str
    decode_pipeline: tuple[str, ...]
    purpose: str
    lossy: bool = False

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"inert": True, "offline": True, "network_requests": 0})
        return row


@dataclass(frozen=True, slots=True)
class WAFFinding:
    category: str
    name: str
    evidence: str
    offset: int
    confidence: str
    implication: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _input(value: str) -> str:
    if not isinstance(value, str):
        raise WAFEncodingInputError("value must be text")
    if not value or len(value) > MAX_INPUT:
        raise WAFEncodingInputError(f"value must contain 1..{MAX_INPUT} characters")
    if "\x00" in value:
        raise WAFEncodingInputError("value must not contain NUL")
    return value


def _bounded_output(value: str) -> str:
    if len(value) > MAX_OUTPUT:
        raise WAFEncodingInputError(f"encoded output exceeds {MAX_OUTPUT} characters")
    return value


def _percent_all(value: str) -> str:
    return "".join(f"%{byte:02X}" for byte in value.encode("utf-8"))


def _percent_mixed(value: str) -> str:
    rows = []
    for index, byte in enumerate(value.encode("utf-8")):
        digits = f"{byte:02x}" if index % 2 == 0 else f"{byte:02X}"
        rows.append("%" + digits)
    return "".join(rows)


def _unicode_escape(value: str) -> str:
    return "".join(
        f"\\u{ord(char):04x}" if ord(char) <= 0xFFFF else f"\\U{ord(char):08x}"
        for char in value
    )


def _json_escape(value: str) -> str:
    replacements = {
        '"': '\\"',
        "\\": "\\\\",
        "\b": "\\b",
        "\f": "\\f",
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
    }
    return "".join(
        replacements.get(char, f"\\u{ord(char):04x}" if ord(char) < 32 else char)
        for char in value
    )


def _html_decimal(value: str) -> str:
    return "".join(f"&#{ord(char)};" for char in value)


def _html_hex(value: str) -> str:
    return "".join(f"&#x{ord(char):x};" for char in value)


def _fullwidth(value: str) -> str:
    return "".join(
        "\u3000" if char == " " else chr(ord(char) + 0xFEE0) if "!" <= char <= "~" else char
        for char in value
    )


def _backslash_x(value: str) -> str:
    return "".join(f"\\x{byte:02x}" for byte in value.encode("utf-8"))


def _css_escape(value: str) -> str:
    return "".join(f"\\{ord(char):x} " for char in value)


def _iis_unicode(value: str) -> str:
    return "".join(f"%u{ord(char):04X}" if ord(char) <= 0xFFFF else char for char in value)


def _utf16le_percent(value: str) -> str:
    return "".join(f"%{byte:02X}" for byte in value.encode("utf-16le"))


def _base64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _base64url(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


_TRANSFORMS: dict[str, Callable[[str], str]] = {
    "url_component": lambda value: urllib.parse.quote(value, safe=""),
    "url_path": lambda value: urllib.parse.quote(value, safe="/"),
    "form": urllib.parse.quote_plus,
    "percent_all": _percent_all,
    "unicode_escape": _unicode_escape,
    "json_escape": _json_escape,
    "html_named": html.escape,
    "html_decimal": _html_decimal,
    "html_hex": _html_hex,
    "fullwidth": _fullwidth,
    "backslash_x": _backslash_x,
    "css_escape": _css_escape,
    "iis_unicode": _iis_unicode,
    "utf16le_percent": _utf16le_percent,
    "base64": _base64,
    "base64url": _base64url,
    "hex_utf8": lambda value: value.encode("utf-8").hex(),
    "nfc": lambda value: unicodedata.normalize("NFC", value),
    "nfd": lambda value: unicodedata.normalize("NFD", value),
    "nfkc": lambda value: unicodedata.normalize("NFKC", value),
    "casefold": str.casefold,
}


def apply_pipeline(value: str, steps: Sequence[str]) -> str:
    """Apply a named encoding pipeline without dynamic lookup or evaluation."""

    current = _input(value)
    if isinstance(steps, str):
        raise WAFEncodingInputError("steps must be a sequence of transform names")
    try:
        iterator = iter(steps)
    except TypeError as exc:
        raise WAFEncodingInputError("steps must be a sequence of transform names") from exc
    collected: list[str] = []
    for step in iterator:
        if len(collected) >= MAX_PIPELINE:
            raise WAFEncodingInputError(f"pipeline must contain 1..{MAX_PIPELINE} steps")
        collected.append(step)
    bounded = tuple(collected)
    if not 1 <= len(bounded) <= MAX_PIPELINE:
        raise WAFEncodingInputError(f"pipeline must contain 1..{MAX_PIPELINE} steps")
    for step in bounded:
        if not isinstance(step, str) or step not in _TRANSFORMS:
            raise WAFEncodingInputError(f"unknown transform {step!r}")
        current = _bounded_output(_TRANSFORMS[step](current))
    return current


def encoding_catalog(value: str) -> tuple[EncodingCandidate, ...]:
    """Return single- and multi-layer encodings in a stable review order."""

    value = _input(value)
    rows = (
        ("baseline", "raw", value, (), "unencoded control", False),
        ("url", "url_component", urllib.parse.quote(value, safe=""), ("URL decode",), "component percent encoding", False),
        ("url", "url_path_safe", urllib.parse.quote(value, safe="/"), ("URL decode",), "path-aware percent encoding", False),
        ("url", "form_plus", urllib.parse.quote_plus(value), ("form URL decode",), "application/x-www-form-urlencoded spacing", False),
        ("url", "percent_all", _percent_all(value), ("URL decode",), "percent encode every UTF-8 byte", False),
        ("url", "mixed_hex_case", _percent_mixed(value), ("URL decode",), "mixed percent-hex digit case", False),
        ("url", "double_percent", urllib.parse.quote(urllib.parse.quote(value, safe=""), safe=""), ("URL decode", "URL decode"), "two percent-decoding layers", False),
        ("unicode", "unicode_escape", _unicode_escape(value), ("Unicode escape decode",), "language-level Unicode escapes", False),
        ("unicode", "json_escape", _json_escape(value), ("JSON string unescape",), "JSON escape handling", False),
        ("unicode", "fullwidth", _fullwidth(value), ("NFKC normalization",), "compatibility characters", False),
        ("unicode", "nfd", unicodedata.normalize("NFD", value), ("NFC normalization",), "decomposed Unicode form", False),
        ("unicode", "nfkc", unicodedata.normalize("NFKC", value), (), "compatibility-normalized control", True),
        ("html", "html_named", html.escape(value), ("HTML entity decode",), "named entities for HTML metacharacters", False),
        ("html", "html_decimal", _html_decimal(value), ("HTML entity decode",), "decimal character references", False),
        ("html", "html_hex", _html_hex(value), ("HTML entity decode",), "hexadecimal character references", False),
        ("language", "backslash_x", _backslash_x(value), ("byte escape decode",), "backslash hexadecimal byte escapes", False),
        ("language", "css_escape", _css_escape(value), ("CSS escape decode",), "CSS hexadecimal escapes with terminators", False),
        ("legacy", "iis_unicode", _iis_unicode(value), ("legacy %u decode",), "legacy IIS-style Unicode escapes", False),
        ("unicode", "utf16le_percent", _utf16le_percent(value), ("URL decode", "UTF-16LE decode"), "percent-encoded UTF-16LE code units", False),
        ("transport", "base64", _base64(value), ("base64 decode",), "standard base64 transport", False),
        ("transport", "base64url", _base64url(value), ("base64url decode",), "unpadded URL-safe base64 transport", False),
        ("transport", "hex_utf8", value.encode("utf-8").hex(), ("hex decode", "UTF-8 decode"), "hexadecimal UTF-8 bytes", False),
        ("chained", "html_hex_then_url", apply_pipeline(value, ("html_hex", "url_component")), ("URL decode", "HTML entity decode"), "HTML references behind percent encoding", False),
        ("chained", "fullwidth_then_url", apply_pipeline(value, ("fullwidth", "url_component")), ("URL decode", "NFKC normalization"), "compatibility characters behind percent encoding", False),
    )
    return tuple(
        EncodingCandidate(family, name, _bounded_output(encoded), pipeline, purpose, lossy)
        for family, name, encoded, pipeline, purpose, lossy in rows
    )


_PATTERNS: tuple[tuple[str, str, str, str, re.Pattern[str]], ...] = (
    ("normalization", "url_decode", "medium", "A URL-decoding layer changes what later validation sees.", re.compile(r"(?i)\b(?:urldecode|unquote|decodeURIComponent|URLDecoder\.decode)\s*\(")),
    ("normalization", "double_url_decode", "high", "Nested decoding can expose syntax hidden from a single-pass filter.", re.compile(r"(?i)(?:urldecode|unquote|decodeURIComponent)\s*\(\s*(?:urldecode|unquote|decodeURIComponent)\s*\(")),
    ("normalization", "html_entity_decode", "medium", "Entity decoding order matters when HTML syntax is filtered earlier.", re.compile(r"(?i)\b(?:html_entity_decode|html\.unescape|WebUtility\.HtmlDecode)\s*\(")),
    ("normalization", "unicode_normalize", "medium", "Compatibility/canonical normalization can change filtered characters.", re.compile(r"(?i)\b(?:normalize|Normalizer\.normalize|unicodedata\.normalize)\s*\(")),
    ("normalization", "base64_decode", "medium", "Decoded content needs the same validation as direct content.", re.compile(r"(?i)\b(?:base64_decode|b64decode|atob|Base64\.getDecoder)\b")),
    ("filter", "regex_blacklist", "medium", "A denylist is sensitive to alternate representations and normalization order.", re.compile(r"(?i)\b(?:blacklist(?:[_ -]?(?:regex|patterns?))?|blocked_patterns?|denylist|forbidden)\b[^\n]{0,160}(?:regex|re\.|match|replace|contains)")),
    ("filter", "case_normalization", "low", "Case folding may occur before or after a case-sensitive rule.", re.compile(r"(?i)\b(?:lower|lowercase|casefold|toLowerCase)\s*\(")),
    ("product", "modsecurity", "high", "A ModSecurity rule identifier or response marker is present.", re.compile(r"(?i)\b(?:ModSecurity|OWASP_CRS|mod_security)\b")),
    ("product", "cloudflare", "high", "A Cloudflare challenge or response marker is present.", re.compile(r"(?i)\b(?:cf-ray|cloudflare|cf-mitigated)\b")),
    ("product", "aws_waf", "high", "An AWS WAF response or configuration marker is present.", re.compile(r"(?i)\b(?:AWSWAF|x-amzn-waf|aws[-_ ]waf)\b")),
    ("product", "imperva", "high", "An Imperva/Incapsula response marker is present.", re.compile(r"(?i)\b(?:incap_ses|visid_incap|imperva|incapsula)\b")),
)


def analyze_waf_text(supplied_text: str | bytes | bytearray) -> tuple[WAFFinding, ...]:
    """Find normalization/filter/product evidence in supplied source or text."""

    if isinstance(supplied_text, str):
        text = supplied_text
    elif isinstance(supplied_text, (bytes, bytearray)):
        text = bytes(supplied_text).decode("utf-8", "replace")
    else:
        raise WAFEncodingInputError("supplied_text must be text or bytes")
    if len(text) > MAX_TEXT:
        raise WAFEncodingInputError(f"supplied_text exceeds {MAX_TEXT} characters")
    rows: list[WAFFinding] = []
    for category, name, confidence, implication, pattern in _PATTERNS:
        match = pattern.search(text)
        if match:
            rows.append(
                WAFFinding(
                    category,
                    name,
                    text[max(0, match.start() - 48) : min(len(text), match.end() + 96)],
                    match.start(),
                    confidence,
                    implication,
                )
            )
    return tuple(sorted(rows, key=lambda row: (row.offset, row.category, row.name)))


def rows_as_dicts(
    rows: Iterable[EncodingCandidate | WAFFinding],
) -> tuple[dict[str, object], ...]:
    return tuple(row.to_dict() for row in rows)
