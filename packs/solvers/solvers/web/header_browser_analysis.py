#!/usr/bin/env python3
"""Offline CRLF, redirect, host-header, CORS, and CSWSH analysis.

Builders emit inert strings only.  The analyzer consumes bounded saved HTTP
transcripts and source text; it never opens a URL, instantiates a browser, or
deserializes structured challenge input.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Iterable
import urllib.parse


MAX_TEXT = 256_000
MAX_HEADERS = 256
MAX_HEADER_VALUE = 4096


class HeaderAnalysisInputError(ValueError):
    """Raised when an offline input is malformed or exceeds a cap."""


@dataclass(frozen=True, slots=True)
class HeaderCandidate:
    family: str
    name: str
    location: str
    value: str
    purpose: str
    requirements: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"inert": True, "offline": True, "network_requests": 0})
        return row


@dataclass(frozen=True, slots=True)
class BrowserFinding:
    family: str
    name: str
    severity: str
    evidence: str
    recommendation: str
    offset: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_MARKER = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_HOST = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9-]{2,63}$")


def _text(value: str | bytes | bytearray, label: str) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", "replace")
    else:
        raise HeaderAnalysisInputError(f"{label} must be text or bytes")
    if len(text) > MAX_TEXT:
        raise HeaderAnalysisInputError(f"{label} exceeds {MAX_TEXT} characters")
    return text


def _token(value: str, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise HeaderAnalysisInputError(f"{label} must be a conservative HTTP token")
    return value


def _marker(value: str) -> str:
    if not isinstance(value, str) or not _MARKER.fullmatch(value):
        raise HeaderAnalysisInputError("marker must be 1..64 conservative ASCII characters")
    return value


def _reserved_host(value: str) -> str:
    if not isinstance(value, str) or not _HOST.fullmatch(value) or not value.lower().endswith(".invalid"):
        raise HeaderAnalysisInputError("marker_host must be a reserved .invalid hostname")
    return value.lower()


def crlf_payloads(
    marker: str = "R5D_HEADER_MARKER", header_name: str = "X-R5D-Probe"
) -> tuple[HeaderCandidate, ...]:
    """Return line-break encodings for normalization-order analysis."""

    marker = _marker(marker)
    header_name = _token(header_name, "header_name")
    suffix = f"{header_name}: {marker}"
    rows = (
        ("percent_crlf", f"%0d%0a{suffix}", "one URL-decoding layer"),
        ("percent_lf", f"%0a{suffix}", "LF-only header parsing"),
        ("percent_cr", f"%0d{suffix}", "CR-only header parsing"),
        ("double_percent_crlf", f"%250d%250a{suffix}", "two URL-decoding layers"),
        ("mixed_case_hex", f"%0D%0a{suffix}", "case-insensitive percent decoding"),
        ("unicode_escape_text", f"\\u000d\\u000a{suffix}", "Unicode-escape decoding before header construction"),
        ("raw_control", f"\r\n{suffix}", "direct control-character propagation"),
    )
    return tuple(
        HeaderCandidate(
            "crlf", name, "parameter value", value,
            f"compare whether the sink performs {purpose}",
            ("supplied text reaches an HTTP response-header value",),
        )
        for name, value, purpose in rows
    )


def open_redirect_payloads(
    marker_host: str = "redirect.r5d.invalid", marker: str = "R5D"
) -> tuple[HeaderCandidate, ...]:
    """Return absolute, scheme-relative, authority-confusion, and encoded URLs."""

    host = _reserved_host(marker_host)
    marker = _marker(marker)
    path = f"/{marker}"
    rows = (
        ("absolute_https", f"https://{host}{path}", "ordinary absolute URL acceptance"),
        ("scheme_relative", f"//{host}{path}", "scheme-relative URL acceptance"),
        ("triple_slash", f"///{host}{path}", "slash normalization before authority parsing"),
        ("backslash_authority", f"\\\\{host}\\{marker}", "browser backslash-to-slash normalization"),
        ("mixed_slashes", f"/\\{host}/{marker}", "mixed slash normalization"),
        ("encoded_slashes", f"%2f%2f{host}%2f{marker}", "one URL-decoding layer"),
        ("double_encoded_slashes", f"%252f%252f{host}%252f{marker}", "two URL-decoding layers"),
        ("userinfo_decoy", f"https://trusted.invalid@{host}{path}", "userinfo versus hostname validation"),
        ("trusted_fragment_decoy", f"https://{host}{path}#trusted.invalid", "raw suffix checks before fragment parsing"),
        ("scheme_without_slashes", f"https:{host}{path}", "browser base-URL resolution of a scheme-like value"),
    )
    return tuple(
        HeaderCandidate(
            "open_redirect", name, "redirect parameter", value,
            f"compare {purpose}",
            ("the value reaches a redirect sink",),
        )
        for name, value, purpose in rows
    )


def host_header_payloads(
    marker_host: str = "host.r5d.invalid",
) -> tuple[HeaderCandidate, ...]:
    """Return inert host-derived URL and proxy-header variants."""

    host = _reserved_host(marker_host)
    rows = (
        ("host", "Host", host, "direct authority use"),
        ("x_forwarded_host", "X-Forwarded-Host", host, "trusted reverse-proxy host override"),
        ("x_original_host", "X-Original-Host", host, "original-host middleware override"),
        ("x_host", "X-Host", host, "nonstandard host override"),
        ("forwarded", "Forwarded", f"host={host};proto=https", "RFC 7239 host/proto override"),
        ("x_forwarded_proto", "X-Forwarded-Proto", "https", "scheme selection paired with a host override"),
        ("absolute_form", "request-target", f"https://{host}/R5D", "absolute-form authority versus Host"),
    )
    return tuple(
        HeaderCandidate(
            "host_header", name, location, value, f"compare {purpose}",
            ("the application or proxy trusts the supplied field",),
        )
        for name, location, value, purpose in rows
    )


def browser_header_matrix(
    marker_host: str = "probe.r5d.invalid", marker: str = "R5D"
) -> tuple[HeaderCandidate, ...]:
    return (
        *crlf_payloads(marker),
        *open_redirect_payloads(marker_host, marker),
        *host_header_payloads(marker_host),
    )


def _parse_saved_http(text: str) -> tuple[str, tuple[tuple[str, str], ...], str]:
    normalized = text.replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    lines = head.split("\n")
    start = lines[0].strip() if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if len(headers) >= MAX_HEADERS:
            break
        if not line or line[:1] in (" ", "\t") or ":" not in line:
            continue
        name, value = line.split(":", 1)
        clean_name = name.strip().lower()
        clean_value = value.strip()[:MAX_HEADER_VALUE]
        if clean_name and _TOKEN.fullmatch(name.strip()) and "\x00" not in clean_value:
            headers.append((clean_name, clean_value))
    return start, tuple(headers), body if separator else ""


def _values(headers: tuple[tuple[str, str], ...], name: str) -> tuple[str, ...]:
    return tuple(value for key, value in headers if key == name)


def _first(headers: tuple[tuple[str, str], ...], name: str) -> str | None:
    values = _values(headers, name)
    return values[0] if len(values) == 1 else None


def _hostname_from_authority(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urllib.parse.urlsplit("//" + value if "://" not in value else value)
        return parsed.hostname.lower() if parsed.hostname else None
    except ValueError:
        return None


def _origin_host(value: str | None) -> str | None:
    if not value or value == "null":
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
        return parsed.hostname.lower() if parsed.scheme in ("http", "https") and parsed.hostname else None
    except ValueError:
        return None


def _evidence(text: str, needle: str) -> tuple[str, int]:
    offset = text.lower().find(needle.lower())
    if offset < 0:
        return needle[:180], MAX_TEXT
    return text[max(0, offset - 48) : min(len(text), offset + len(needle) + 96)], offset


def _finding(
    family: str,
    name: str,
    severity: str,
    text: str,
    needle: str,
    recommendation: str,
) -> BrowserFinding:
    evidence, offset = _evidence(text, needle)
    return BrowserFinding(family, name, severity, evidence, recommendation, offset)


def analyze_saved_web_exchange(
    request_text: str | bytes | bytearray,
    response_text: str | bytes | bytearray,
    source_text: str | bytes | bytearray = "",
) -> tuple[BrowserFinding, ...]:
    """Analyze one supplied request/response/source bundle without replaying it."""

    request = _text(request_text, "request_text")
    response = _text(response_text, "response_text")
    source = _text(source_text, "source_text")
    request_start, request_headers, _ = _parse_saved_http(request)
    response_start, response_headers, response_body = _parse_saved_http(response)
    combined = request + "\n" + response + "\n" + source
    rows: list[BrowserFinding] = []

    request_host = _hostname_from_authority(_first(request_headers, "host"))
    origin = _first(request_headers, "origin")
    origin_host = _origin_host(origin)
    location = _first(response_headers, "location")
    if location:
        try:
            location_host = urllib.parse.urlsplit(location).hostname
        except ValueError:
            location_host = None
        if location_host and request_host and location_host.lower() != request_host:
            rows.append(_finding(
                "open_redirect", "external_location", "high", response, location,
                "Resolve redirects against a fixed origin and allowlist the parsed destination origin.",
            ))
        if re.search(r"(?i)%0d|%0a|%250d|%250a|\\u000[ad]", location):
            rows.append(_finding(
                "crlf", "encoded_line_break_in_location", "high", response, location,
                "Reject control characters before and after every decoding/normalization layer.",
            ))

    forwarded = {
        name: value
        for name in ("x-forwarded-host", "x-original-host", "x-host")
        if (value := _first(request_headers, name))
    }
    for name, value in forwarded.items():
        if value.lower() in (response + "\n" + response_body).lower():
            rows.append(_finding(
                "host_header", f"reflected_{name.replace('-', '_')}", "high", combined, value,
                "Use a configured canonical public origin and trust proxy headers only from known proxies.",
            ))
    if len(_values(request_headers, "host")) > 1:
        rows.append(_finding(
            "host_header", "duplicate_host", "high", request, "Host:",
            "Reject requests with duplicate or conflicting authority fields.",
        ))

    acao_values = _values(response_headers, "access-control-allow-origin")
    credentials = (_first(response_headers, "access-control-allow-credentials") or "").lower() == "true"
    vary_values = ",".join(_values(response_headers, "vary")).lower()
    if len(acao_values) > 1:
        rows.append(_finding(
            "cors", "duplicate_acao", "high", response, "Access-Control-Allow-Origin",
            "Emit exactly one validated Access-Control-Allow-Origin value.",
        ))
    elif acao_values:
        acao = acao_values[0]
        if acao == "*" and credentials:
            rows.append(_finding(
                "cors", "wildcard_with_credentials", "high", response, acao,
                "Use an explicit allowlist and never combine wildcard origin with credentials.",
            ))
        if acao == "null":
            rows.append(_finding(
                "cors", "null_origin_allowed", "medium", response, acao,
                "Avoid allowing the opaque null origin unless the data is intentionally public.",
            ))
        if origin and acao == origin:
            severity = "high" if credentials else "medium"
            rows.append(_finding(
                "cors", "request_origin_reflected", severity, response, acao,
                "Compare the parsed origin against an exact scheme/host/port allowlist.",
            ))
            if "origin" not in {item.strip() for item in vary_values.split(",") if item.strip()}:
                rows.append(_finding(
                    "cors", "origin_reflection_missing_vary", "medium", response, "Access-Control-Allow-Origin",
                    "Add Vary: Origin whenever the response varies by request Origin.",
                ))

    upgrade_request = (_first(request_headers, "upgrade") or "").lower() == "websocket"
    upgrade_response = (_first(response_headers, "upgrade") or "").lower() == "websocket"
    has_cookie = bool(_values(request_headers, "cookie"))
    accepted = response_start.upper().startswith("HTTP/") and re.search(r"\s101\b", response_start)
    if upgrade_request and upgrade_response and accepted and has_cookie:
        if origin_host and request_host and origin_host != request_host:
            rows.append(_finding(
                "cswsh", "cross_site_cookie_websocket_accepted", "high", request, origin or "Origin:",
                "Validate Origin during the WebSocket handshake and require an unguessable session-bound token.",
            ))
        elif origin is None:
            rows.append(_finding(
                "cswsh", "cookie_websocket_without_origin", "medium", request, "Upgrade: websocket",
                "Require and validate an allowed browser Origin before accepting cookie-authenticated sockets.",
            ))

    static_patterns = (
        ("host_header", "host_derived_absolute_url", "high", r"(?i)(?:req(?:uest)?\.(?:headers?\.)?host|HTTP_HOST)[^\n]{0,160}(?:https?://|reset|absolute|url)", "Build absolute URLs from a configured canonical origin."),
        ("open_redirect", "unvalidated_redirect_parameter", "medium", r"(?i)\b(?:redirect|location|location\.href)\s*\([^\n]{0,160}(?:query|params?|GET\[|request)", "Parse and allowlist redirect destinations by origin."),
        ("crlf", "header_from_request_data", "medium", r"(?i)\b(?:setHeader|addHeader|header)\s*\([^\n]{0,160}(?:query|params?|GET\[|request)", "Reject controls and map user input to fixed header values."),
        ("cors", "origin_reflection_source", "medium", r"(?i)access-control-allow-origin[^\n]{0,160}(?:req(?:uest)?\.headers?\.origin|HTTP_ORIGIN)", "Apply an exact origin allowlist and emit Vary: Origin."),
        ("cswsh", "cookie_authenticated_websocket_source", "medium", r"(?i)\b(?:websocket|upgrade)\b[^\n]{0,200}\b(?:cookie|session)\b", "Validate Origin and a session-bound CSRF token in the handshake."),
    )
    for family, name, severity, pattern, recommendation in static_patterns:
        match = re.search(pattern, source)
        if match:
            rows.append(_finding(family, name, severity, source, match.group(0), recommendation))

    return tuple(sorted(rows, key=lambda row: (row.offset, row.family, row.name, row.severity)))


def rows_as_dicts(
    rows: Iterable[HeaderCandidate | BrowserFinding],
) -> tuple[dict[str, object], ...]:
    return tuple(row.to_dict() for row in rows)


# --- B-236: Vary-disclosed request headers -----------------------------------------------------------
# A response's Vary names the request fields the server keyed it on.  On a trust-boundary denial that is
# a disclosure: the loopback field the gateway reads, then the application's own role/identity field.
# Standard negotiation/caching fields are never a trust header; hop-by-hop, framing and browser-owned
# fields are never set by a reader at all.
VARY_LOOPBACK_HEADERS = frozenset({
    "x-forwarded-for", "x-real-ip", "forwarded", "x-client-ip", "true-client-ip",
    "x-original-forwarded-for", "cf-connecting-ip", "x-cluster-client-ip",
})
VARY_STANDARD_HEADERS = frozenset({
    "accept", "accept-encoding", "accept-language", "accept-charset", "accept-datetime", "origin",
    "cookie", "authorization", "user-agent", "referer", "content-type", "content-encoding",
    "content-language", "if-none-match", "if-modified-since", "if-match", "range", "dnt",
    "x-requested-with", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "x-original-url",
    "x-rewrite-url", "save-data", "viewport-width", "width", "dpr", "device-memory", "rsc",
    "next-router-state-tree", "next-router-prefetch", "next-url", "hx-request", "x-http-method-override",
})
_VARY_NEVER_SET = re.compile(
    r"^(?:host|connection|keep-alive|te|trailer|transfer-encoding|upgrade|content-length|expect|"
    r"proxy-.*|sec-.*|access-control-.*|cache-control|pragma)$"
)


@dataclass(frozen=True, slots=True)
class VaryDisclosure:
    """The field names one response's Vary header(s) disclosed, split by role."""

    tokens: tuple[str, ...]
    loopback: tuple[str, ...]
    custom: tuple[str, ...]
    wildcard: bool
    malformed: bool

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"offline": True, "network_requests": 0})
        return row


def vary_disclosed_headers(header_pairs: Iterable[tuple[str, str]]) -> VaryDisclosure:
    """Classify the request fields named by every ``Vary`` header in ``header_pairs``.

    ``custom`` holds only application-specific fields: never a standard negotiation/cache field, a
    loopback/client-address field, or one a reader must not set (hop-by-hop, framing, ``Sec-*``,
    ``Proxy-*``).  A token that is not a conservative HTTP token marks the disclosure ``malformed`` so a
    caller fails closed instead of guessing what the server meant.  Pure; nothing is sent.
    """
    tokens: list[str] = []
    wildcard = malformed = False
    count = 0
    for row in header_pairs:
        count += 1
        if count > MAX_HEADERS:
            raise HeaderAnalysisInputError(f"more than {MAX_HEADERS} response headers")
        if not isinstance(row, (tuple, list)) or len(row) != 2:
            raise HeaderAnalysisInputError("header pairs must be (name, value)")
        name, value = str(row[0]).strip().lower(), str(row[1])
        if name != "vary":
            continue
        if len(value) > MAX_HEADER_VALUE:
            raise HeaderAnalysisInputError(f"Vary value exceeds {MAX_HEADER_VALUE} characters")
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            if item == "*":
                wildcard = True
                continue
            if not _TOKEN.fullmatch(item):
                malformed = True
                continue
            folded = item.lower()
            if folded not in tokens:
                tokens.append(folded)
    loopback = tuple(token for token in tokens if token in VARY_LOOPBACK_HEADERS)
    custom = tuple(token for token in tokens
                   if token not in VARY_LOOPBACK_HEADERS and token not in VARY_STANDARD_HEADERS
                   and not _VARY_NEVER_SET.fullmatch(token))
    return VaryDisclosure(tuple(tokens), loopback, custom, wildcard, malformed)
