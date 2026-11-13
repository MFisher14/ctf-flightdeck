#!/usr/bin/env python3
"""Offline web-cache poisoning and cache-deception evidence analysis.

Only saved request/response/source text is accepted.  No transport client is
imported and no function can replay traffic.  Findings deliberately distinguish
"interesting evidence" from proof: a cache key and an origin dependency must
disagree before a poisoning hypothesis becomes strong, while deception requires
both a static-looking cache key and evidence of personalised content.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace as _dc_replace
import hashlib
import re
from typing import Iterable, Sequence
from urllib.parse import unquote  # string normalisation only; not a transport client

try:  # Support both namespace-package and direct solver-directory imports.
    from .http_smuggling import SavedHTTPError, SavedRequest, parse_saved_request
except ImportError:  # pragma: no cover - exercised by repository-style direct imports
    from http_smuggling import SavedHTTPError, SavedRequest, parse_saved_request

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt


MAX_SAVED_BYTES = 2 * 1024 * 1024
MAX_SOURCE_CHARS = 2 * 1024 * 1024
MAX_VARIANTS = 32


class CacheAnalysisError(ValueError):
    """Raised when saved cache evidence is malformed or exceeds a bound."""


@dataclass(frozen=True)
class ResponseHeader:
    name: str
    value: str
    line_number: int


@dataclass(frozen=True)
class SavedResponse:
    version: str
    status: int
    reason: str
    headers: tuple[ResponseHeader, ...]
    body: bytes
    anomalies: tuple[str, ...]

    def values(self, name: str) -> tuple[str, ...]:
        wanted = name.casefold()
        return tuple(field.value for field in self.headers
                     if field.name.casefold() == wanted)


@dataclass(frozen=True)
class CacheFinding:
    finding_id: str
    family: str
    title: str
    severity: str
    confidence: str
    evidence: tuple[str, ...]
    remediation: str


@dataclass(frozen=True)
class CacheVariant:
    rank: int
    family: str
    name: str
    value: str
    hypothesis: str
    marker: str
    offline: bool = True
    network_requests: int = 0


@dataclass(frozen=True)
class ResponseComparison:
    marker: str
    marker_only_in_candidate: bool
    status_changed: bool
    body_changed: bool
    cache_headers_changed: bool
    evidence: tuple[str, ...]
    offline: bool = True
    network_requests: int = 0


_HEADER_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_STATIC_SUFFIX = re.compile(
    r"(?i)\.(?:avif|bmp|css|csv|eot|gif|ico|jpe?g|js|json|map|mp3|mp4|pdf|png|svg|txt|webm|webp|woff2?)"
    r"(?:$|[?;#/])"
)
_DECEPTION_SHAPE = re.compile(
    r"(?i)(?:%2f|%252f|%3f|%253f|%23|%2523|%3b|%253b|;|//|/\.\.?/|%2e)"
)
_SENSITIVE_TEXT = re.compile(
    r"(?i)(?:\b(?:account|billing|dashboard|profile|session|csrf|api[-_ ]?key|access[-_ ]?token|"
    r"private|balance|address|email|phone|admin)\b)"
)


def _sensitive_matches(body_text: str) -> tuple[str, ...]:
    """Sensitive words and the active event's flag leads (`PINK{`; R-16: this was a hard-coded
    `CSCTF{`) in a response body, distinct, in body order, at most 12."""
    hits = [(m.start(), m.group(0)) for m in _SENSITIVE_TEXT.finditer(body_text)]
    hits += [(m.start(), m.group(0)) for m in flagfmt.LEAD_TEXT.finditer(body_text)]
    return tuple(dict.fromkeys(text[:80] for _pos, text in sorted(hits)))[:12]
_CACHE_SOURCE_LINE = re.compile(
    r"(?im)^.{0,160}(?:proxy_cache_key|vcl_hash|hash_data|cache[-_ ]?key|cacheKey|cache\.set|"
    r"caches\.open|edge-cache-tag).{0,240}$"
)
_ROUTING_SOURCE_LINE = re.compile(
    r"(?im)^.{0,160}(?:path_info|PATH_INFO|rewrite|try_files|originalUrl|original_uri|"
    r"x-original-url|x-rewrite-url|sendFile|static\().{0,240}$"
)


def _saved_bytes(raw: str | bytes | bytearray | memoryview, label: str) -> bytes:
    if isinstance(raw, str):
        try:
            data = raw.encode("latin-1")
        except UnicodeEncodeError:
            data = raw.encode("utf-8")
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
    else:
        raise CacheAnalysisError(f"{label} must be text or bytes")
    if not data:
        raise CacheAnalysisError(f"{label} is empty")
    if len(data) > MAX_SAVED_BYTES:
        raise CacheAnalysisError(f"{label} exceeds {MAX_SAVED_BYTES} bytes")
    if b"\x00" in data:
        raise CacheAnalysisError(f"{label} contains NUL")
    return data


def parse_saved_response(raw: str | bytes | bytearray | memoryview) -> SavedResponse:
    """Parse one raw saved HTTP response while retaining duplicate fields."""

    data = _saved_bytes(raw, "saved response")
    anomalies: list[str] = []
    separator = b"\r\n\r\n"
    ending = b"\r\n"
    boundary = data.find(separator)
    if boundary < 0:
        separator, ending = b"\n\n", b"\n"
        boundary = data.find(separator)
        anomalies.append("LF-only or missing canonical response framing")
    if boundary < 0:
        head, body = data, b""
        anomalies.append("missing blank line between response headers and body")
    else:
        head, body = data[:boundary], data[boundary + len(separator):]
    if len(head) > 64 * 1024:
        raise CacheAnalysisError("response header block exceeds 65536 bytes")
    has_crlf = b"\r\n" in head
    has_bare_lf = b"\n" in head.replace(b"\r\n", b"")
    if has_crlf and has_bare_lf:
        anomalies.append("mixed CRLF and LF response header line endings")
    normalised_head = head.replace(b"\r\n", b"\n")
    if b"\r" in normalised_head:
        anomalies.append("bare CR in response header block")
    lines = normalised_head.split(b"\n")
    if not lines:
        raise CacheAnalysisError("response status line is missing")
    status_line = lines[0].decode("latin-1")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not re.fullmatch(r"HTTP/[0-9.]+", parts[0], re.I):
        raise CacheAnalysisError("response status line is malformed")
    try:
        status = int(parts[1], 10)
    except ValueError as exc:
        raise CacheAnalysisError("response status code is not decimal") from exc
    if not 100 <= status <= 999:
        raise CacheAnalysisError("response status code is out of range")
    reason = parts[2] if len(parts) == 3 else ""
    headers: list[ResponseHeader] = []
    for number, raw_line in enumerate(lines[1:], 2):
        if len(headers) >= 512:
            raise CacheAnalysisError("response header count exceeds 512")
        if raw_line.startswith((b" ", b"\t")):
            anomalies.append(f"obsolete response header folding at line {number}")
            if headers:
                prior = headers[-1]
                headers[-1] = ResponseHeader(
                    prior.name, prior.value + " " + raw_line.decode("latin-1").strip(),
                    prior.line_number,
                )
            continue
        if b":" not in raw_line:
            anomalies.append(f"response header line {number} has no colon")
            continue
        name_b, value_b = raw_line.split(b":", 1)
        name = name_b.decode("latin-1").strip(" \t")
        value = value_b.decode("latin-1").strip(" \t")
        if not _HEADER_TOKEN.fullmatch(name):
            anomalies.append(f"response header line {number} has a non-token name")
        headers.append(ResponseHeader(name, value, number))
    return SavedResponse(parts[0].upper(), status, reason, tuple(headers), body,
                         tuple(dict.fromkeys(anomalies)))


def _source_text(source: str | bytes | bytearray | memoryview | None) -> str:
    if source is None:
        return ""
    if isinstance(source, str):
        text = source
    elif isinstance(source, (bytes, bytearray, memoryview)):
        text = bytes(source).decode("utf-8", "replace")
    else:
        raise CacheAnalysisError("saved source must be text, bytes, or None")
    if len(text) > MAX_SOURCE_CHARS:
        raise CacheAnalysisError(f"saved source exceeds {MAX_SOURCE_CHARS} characters")
    return text


def _cache_control(response: SavedResponse) -> tuple[str, ...]:
    values = response.values("cache-control")
    return tuple(token.strip().casefold() for value in values for token in value.split(",")
                 if token.strip())


def _cacheability(response: SavedResponse) -> tuple[bool, tuple[str, ...]]:
    evidence: list[str] = []
    policy_headers = ("cache-control", "cdn-cache-control", "surrogate-control")
    directives = tuple(
        token.strip().casefold()
        for name in policy_headers
        for value in response.values(name)
        for token in value.split(",")
        if token.strip()
    )
    if any(item == "no-store" or item == "private" or item.startswith("private=")
           for item in directives):
        return False, (f"saved cache policy blocks shared storage: {directives!r}",)
    explicit = [item for item in directives
                if item == "public" or item.startswith("s-maxage=") or item.startswith("max-age=")]
    if explicit:
        evidence.append(f"shared-cache-compatible Cache-Control: {tuple(explicit)!r}")
    age = response.values("age")
    if any(value.strip().isdigit() and int(value.strip()) >= 0 for value in age):
        evidence.append(f"Age header present: {age!r}")
    for name in ("x-cache", "cf-cache-status", "x-proxy-cache", "cdn-cache-control"):
        values = response.values(name)
        if values:
            evidence.append(f"{name}: {values!r}")
    default_cacheable = response.status in {200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501}
    if default_cacheable:
        evidence.append(f"status {response.status} is commonly cacheable")
    return bool(explicit or age or len(evidence) > (1 if default_cacheable else 0)), tuple(evidence)


def _response_text(response: SavedResponse) -> str:
    header_text = "\n".join(f"{field.name}: {field.value}" for field in response.headers)
    return (header_text + "\n" + response.body.decode("utf-8", "replace"))[:MAX_SAVED_BYTES]


def _vary_tokens(response: SavedResponse) -> set[str]:
    return {token.strip().casefold() for value in response.values("vary")
            for token in value.split(",") if token.strip()}


def _source_lines(pattern: re.Pattern[str], source: str) -> tuple[str, ...]:
    return tuple(match.group(0).strip()[:400] for match in pattern.finditer(source))[:12]


def _request_header_rows(request: SavedRequest, names: set[str]) -> list[tuple[str, str]]:
    return [(field.name.casefold(), field.value) for field in request.headers
            if field.name.casefold() in names]


def _reflection_markers(name: str, value: str) -> tuple[str, ...]:
    """Extract distinctive subvalues an origin might reflect from a proxy field."""

    candidates = [value.strip()]
    if name == "forwarded":
        candidates.extend(
            match.group(1).strip('"')
            for match in re.finditer(
                r"(?i)(?:^|[;,])\s*(?:host|proto)=\s*(\"[^\"]+\"|[^;, ]+)", value
            )
        )
    elif name in {"x-forwarded-host", "x-host", "x-http-host-override"}:
        candidates.extend(part.strip() for part in value.split(","))
    generic = {"http", "https", "80", "443", "true", "false"}
    return tuple(dict.fromkeys(
        item for item in candidates
        if 3 <= len(item) <= 1024 and item.casefold() not in generic
    ))


_UNKEYED_HEADERS = {
    "forwarded", "x-forwarded-host", "x-forwarded-port", "x-forwarded-proto",
    "x-forwarded-scheme", "x-host", "x-http-host-override", "x-original-url",
    "x-rewrite-url", "x-forwarded-prefix",
}


def analyze_cache_poisoning(request_raw: str | bytes | bytearray | memoryview,
                            response_raw: str | bytes | bytearray | memoryview, *,
                            source: str | bytes | bytearray | memoryview | None = None,
                            marker: str | None = None) -> tuple[CacheFinding, ...]:
    """Correlate unkeyed input, reflection, cacheability, and saved key code."""

    try:
        request = parse_saved_request(request_raw)
    except SavedHTTPError as exc:
        raise CacheAnalysisError(str(exc)) from exc
    response = parse_saved_response(response_raw)
    source_text = _source_text(source)
    response_text = _response_text(response)
    response_folded = response_text.casefold()
    cacheable, cache_evidence = _cacheability(response)
    vary = _vary_tokens(response)
    key_lines = _source_lines(_CACHE_SOURCE_LINE, source_text)
    findings: list[CacheFinding] = []

    dependencies = _request_header_rows(request, _UNKEYED_HEADERS)
    for name, value in dependencies:
        clean = value.strip()
        if len(clean) < 3 or len(clean) > 1024:
            continue
        reflected_values = tuple(item for item in _reflection_markers(name, clean)
                                 if item.casefold() in response_folded)
        reflected = bool(reflected_values)
        source_uses = name in source_text.casefold()
        varied = name in vary or "*" in vary
        key_mentions = any(name in line.casefold() for line in key_lines)
        if not reflected and not source_uses:
            continue
        evidence = [f"request field {name!r} supplied {clean!r}"]
        if reflected:
            evidence.append(f"derived field value(s) appear in saved response: {reflected_values!r}")
        if source_uses:
            evidence.append("saved source references the field name")
        if key_lines:
            evidence.append(f"saved cache-key lines: {key_lines!r}")
            evidence.append("field appears in cache key" if key_mentions else "field is absent from shown cache-key lines")
        evidence.extend(cache_evidence)
        if varied:
            evidence.append(f"Vary accounts for {name!r} (or uses Vary: *)")
        strong_gap = cacheable and reflected and not varied and (not key_lines or not key_mentions)
        findings.append(CacheFinding(
            f"unkeyed-{name}", "web-cache-poisoning",
            f"Potential unkeyed {name} dependency",
            "high" if strong_gap else "medium",
            "high" if strong_gap and key_lines else ("medium" if strong_gap else "low"),
            tuple(evidence),
            f"Remove trust in {name}, or include its validated canonical value in the cache key and Vary policy.",
        ))

    marker_value = marker.strip() if isinstance(marker, str) else ""
    if marker_value:
        if len(marker_value) > 512 or any(ch in marker_value for ch in "\r\n\x00"):
            raise CacheAnalysisError("marker must be at most 512 characters without CR/LF/NUL")
        request_surface = "\n".join(
            [request.target, *(f"{field.name}: {field.value}" for field in request.headers),
             request.body.decode("utf-8", "replace")]
        )
        supplied = marker_value.casefold() in request_surface.casefold()
        if supplied and marker_value.casefold() in response_folded:
            evidence = ["explicit marker appears in saved response", *cache_evidence]
            findings.append(CacheFinding(
                "explicit-marker-reflection", "web-cache-poisoning",
                "Explicit inert marker is reflected in a cacheable response",
                "high" if cacheable else "medium", "medium",
                tuple(evidence),
                "Identify the origin input that produced the marker, then key it or stop reflecting it.",
            ))

    host_values = request.values("host")
    absolute = re.match(r"(?i)^https?://([^/]+)", request.target)
    if absolute and host_values and absolute.group(1).casefold() not in {item.casefold() for item in host_values}:
        findings.append(CacheFinding(
            "absolute-host-conflict", "web-cache-poisoning",
            "Absolute-form authority conflicts with Host",
            "high", "high",
            (f"request-target authority: {absolute.group(1)!r}", f"Host values: {host_values!r}", *cache_evidence),
            "Reject authority disagreement and derive routing/cache keys from one canonical authority.",
        ))
    if len(host_values) > 1:
        findings.append(CacheFinding(
            "duplicate-host", "web-cache-poisoning", "Duplicate Host fields reach cache analysis",
            "high", "high", (f"Host values: {host_values!r}", *cache_evidence),
            "Reject requests with anything other than one canonical Host/authority value.",
        ))

    # Stable order independent of input header order.
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def analyze_cache_deception(request_raw: str | bytes | bytearray | memoryview,
                            response_raw: str | bytes | bytearray | memoryview, *,
                            source: str | bytes | bytearray | memoryview | None = None) -> tuple[CacheFinding, ...]:
    """Identify static-looking keys paired with saved personalised responses."""

    try:
        request = parse_saved_request(request_raw)
    except SavedHTTPError as exc:
        raise CacheAnalysisError(str(exc)) from exc
    response = parse_saved_response(response_raw)
    source_text = _source_text(source)
    cacheable, cache_evidence = _cacheability(response)
    target = request.target
    static_looking = bool(_STATIC_SUFFIX.search(target))
    ambiguous_path = bool(_DECEPTION_SHAPE.search(target))
    request_private = bool(request.values("authorization") or request.values("cookie"))
    set_cookie = bool(response.values("set-cookie"))
    body_text = response.body.decode("utf-8", "replace")
    sensitive_matches = _sensitive_matches(body_text)
    routing_lines = _source_lines(_ROUTING_SOURCE_LINE, source_text)
    findings: list[CacheFinding] = []

    response_personalised = set_cookie or bool(sensitive_matches)
    if static_looking and response_personalised:
        evidence = [f"static-looking request target: {target!r}"]
        if ambiguous_path:
            evidence.append("target contains an encoding/normalisation boundary")
        if request_private:
            evidence.append("request carries Cookie and/or Authorization")
        if set_cookie:
            evidence.append("response carries Set-Cookie")
        if sensitive_matches:
            evidence.append(f"sensitive response tokens: {sensitive_matches!r}")
        evidence.extend(cache_evidence)
        if routing_lines:
            evidence.append(f"saved routing/normalisation lines: {routing_lines!r}")
        strong = cacheable and (ambiguous_path or bool(routing_lines))
        findings.append(CacheFinding(
            "static-key-personalised-response", "web-cache-deception",
            "Static-looking cache key returns personalised content",
            "high" if strong else "medium", "high" if strong and routing_lines else "medium",
            tuple(evidence),
            "Never cache authenticated responses; canonicalise the path once and key the route selected by the origin.",
        ))

    content_types = response.values("content-type")
    if static_looking and content_types:
        extension = re.search(r"(?i)\.([a-z0-9]{1,8})(?:$|[?;#/])", target)
        declared = content_types[0].casefold()
        mismatch = bool(extension and (
            (extension.group(1).casefold() == "css" and "text/css" not in declared)
            or (extension.group(1).casefold() == "js" and "javascript" not in declared)
            or (extension.group(1).casefold() in {"png", "jpg", "jpeg", "gif", "webp"}
                and not declared.startswith("image/"))
        ))
        if mismatch:
            findings.append(CacheFinding(
                "suffix-content-type-mismatch", "web-cache-deception",
                "Static suffix disagrees with response Content-Type", "medium",
                "medium" if cacheable else "low",
                (f"target: {target!r}", f"Content-Type: {content_types!r}", *cache_evidence),
                "Use origin route metadata rather than an unnormalised suffix to decide cacheability.",
            ))
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def compare_saved_responses(control_raw: str | bytes | bytearray | memoryview,
                            candidate_raw: str | bytes | bytearray | memoryview, *,
                            marker: str) -> ResponseComparison:
    """Compare two saved responses without treating a difference as exploitation."""

    if not isinstance(marker, str) or not marker or len(marker) > 512:
        raise CacheAnalysisError("marker must be 1..512 characters")
    if any(ch in marker for ch in "\r\n\x00"):
        raise CacheAnalysisError("marker contains CR/LF/NUL")
    control = parse_saved_response(control_raw)
    candidate = parse_saved_response(candidate_raw)
    control_text = _response_text(control)
    candidate_text = _response_text(candidate)
    marker_only = marker.casefold() not in control_text.casefold() and marker.casefold() in candidate_text.casefold()
    body_changed = hashlib.sha256(control.body).digest() != hashlib.sha256(candidate.body).digest()
    cache_names = ("age", "x-cache", "cf-cache-status", "cache-control", "vary")
    changed_names = tuple(name for name in cache_names if control.values(name) != candidate.values(name))
    evidence = [f"control status {control.status}; candidate status {candidate.status}"]
    if marker_only:
        evidence.append("marker occurs only in the candidate response")
    if body_changed:
        evidence.append("response body digests differ")
    if changed_names:
        evidence.append(f"changed cache headers: {changed_names!r}")
    return ResponseComparison(
        marker, marker_only, control.status != candidate.status, body_changed,
        bool(changed_names), tuple(evidence),
    )


def _safe_host(host: str) -> str:
    if (not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9._:\[\]-]{1,253}", host)
            or ".." in host):
        raise CacheAnalysisError("host must be a bounded ASCII authority without delimiters")
    return host


def _safe_path(path: str) -> str:
    if (not isinstance(path, str) or not path.startswith("/") or len(path) > 4096
            or any(ord(ch) < 33 for ch in path)):
        raise CacheAnalysisError("path must be a bounded absolute path without whitespace/control data")
    return path


def build_poisoning_variants(host: str, *, path: str = "/",
                             marker: str = "r5d-cache.invalid") -> tuple[CacheVariant, ...]:
    """Return inert header/key hypotheses as complete saved-request strings."""

    host, path, marker = _safe_host(host), _safe_path(path), _safe_host(marker)
    rows: list[CacheVariant] = []

    def render_request(extra: Sequence[tuple[str, str]], body: str = "") -> str:
        fields = [("Host", host), *extra, ("X-R5D-Cache-Marker", marker)]
        if body:
            fields.append(("Content-Length", str(len(body.encode("ascii")))))
        return (f"GET {path} HTTP/1.1\r\n" +
                "".join(f"{name}: {value}\r\n" for name, value in fields) + "\r\n" + body)

    specs = (
        ("x-forwarded-host", (("X-Forwarded-Host", marker),),
         "origin uses X-Forwarded-Host while the cache key omits it"),
        ("x-host", (("X-Host", marker),),
         "origin uses X-Host while the cache key omits it"),
        ("forwarded", (("Forwarded", f"host={marker};proto=http"),),
         "origin trusts Forwarded authority/scheme while the cache key omits it"),
        ("x-original-url", (("X-Original-URL", "/__r5d_cache_marker__"),),
         "origin routes on X-Original-URL while the cache keys the visible target"),
        ("x-rewrite-url", (("X-Rewrite-URL", "/__r5d_cache_marker__"),),
         "origin routes on X-Rewrite-URL while the cache keys the visible target"),
        ("scheme-port", (("X-Forwarded-Scheme", "http"), ("X-Forwarded-Port", "81")),
         "origin constructs absolute links from unkeyed scheme/port fields"),
    )
    for name, headers, hypothesis in specs:
        rows.append(CacheVariant(len(rows) + 1, "web-cache-poisoning", name,
                                 render_request(headers), hypothesis, marker))
    absolute = (f"GET http://{marker}{path} HTTP/1.1\r\nHost: {host}\r\n"
                f"X-R5D-Cache-Marker: {marker}\r\n\r\n")
    rows.append(CacheVariant(
        len(rows) + 1, "web-cache-poisoning", "absolute-authority", absolute,
        "cache and origin select different authorities from absolute-form and Host", marker,
    ))
    body = f"r5d_cache_marker={marker}"
    rows.append(CacheVariant(
        len(rows) + 1, "web-cache-poisoning", "fat-get-body",
        render_request((("Content-Type", "application/x-www-form-urlencoded"),), body),
        "origin varies on a GET body omitted from the cache key", marker,
    ))
    return tuple(rows)


def build_deception_variants(path: str = "/account") -> tuple[CacheVariant, ...]:
    """Return inert static-looking path normalisation hypotheses."""

    base = _safe_path(path).rstrip("/") or "/"
    marker = "r5d-static.css"
    specs = (
        ("path-info", f"{base}/{marker}", "origin ignores PATH_INFO while cache keys the CSS suffix"),
        ("semicolon", f"{base};{marker}", "origin strips path parameters while cache retains them"),
        ("encoded-question", f"{base}%3f{marker}", "cache and origin decode an encoded question mark at different stages"),
        ("double-encoded-question", f"{base}%253f{marker}", "one hop performs an extra percent-decoding pass"),
        ("encoded-fragment", f"{base}%23{marker}", "cache and origin disagree on encoded fragment delimiters"),
        ("encoded-slash", f"{base}%2f{marker}", "cache and origin disagree on encoded slash normalisation"),
        ("double-slash", f"{base}//{marker}", "origin collapses slashes while cache retains the raw path"),
        ("dot-segment", f"{base}/..%2f{base.strip('/')}/{marker}", "cache and origin canonicalise encoded dot-segments differently"),
        ("suffix-traversal", f"{base}.css%2f..%2f{base.strip('/')}", "static suffix is removed by origin traversal normalisation"),
    )
    rows = tuple(CacheVariant(index, "web-cache-deception", name, value, hypothesis,
                              "R5D-INERT-CACHE")
                 for index, (name, value, hypothesis) in enumerate(specs, 1))
    if len(rows) > MAX_VARIANTS:  # defensive invariant
        raise CacheAnalysisError("variant bound exceeded")
    return rows


def analyze_cache_exchange(request_raw: str | bytes | bytearray | memoryview,
                           response_raw: str | bytes | bytearray | memoryview, *,
                           source: str | bytes | bytearray | memoryview | None = None,
                           marker: str | None = None) -> dict[str, object]:
    """Return one deterministic JSON-ready report across both cache families."""

    poisoning = analyze_cache_poisoning(request_raw, response_raw, source=source, marker=marker)
    deception = analyze_cache_deception(request_raw, response_raw, source=source)
    return {
        "poisoning": [asdict(item) for item in poisoning],
        "deception": [asdict(item) for item in deception],
        "offline": True,
        "network_requests": 0,
        "caution": "saved evidence only; compare a benign control before concluding a cache discrepancy",
    }


# ---------------------------------------------------------------------------
# B-105: front-vs-backend cache-key mapping, poisoning-primitive report, and an
# inert authenticated-bot exfil plan.
#
# The CSCTF "broadsheet-organizer" (Varnish) shape chains an unkeyed param and a
# %2e%2e normalisation collision through an authenticated bot into a second cache
# zone.  Finding the collision is mechanical and is automated here; assembling the
# chain through a live bot and a second zone is multi-insight work that stays human.
# Every primitive and plan says so, and nothing in this section performs or stages a
# real request.
# ---------------------------------------------------------------------------

CHAIN_NOTE = (
    "Flagged primitive only: the collision/anomaly is found automatically, but assembling the "
    "chain — reaching a second cache zone and priming it through an authenticated bot — stays "
    "manual. Confirm with a benign control before concluding anything."
)

MAX_KEY_PATHS = 256


@dataclass(frozen=True)
class KeyComponent:
    """One request component and whether the front cache keys it vs the backend reads it."""

    component: str
    keyed_front: bool
    used_backend: bool
    primitive: str          # "" | "unkeyed-input" | "over-keyed" | "front-key-unknown" | "backend-inputs-unknown"
    note: str


@dataclass(frozen=True)
class NormalizationCollision:
    """Distinct front cache keys (or a cacheable-looking key) that the backend resolves elsewhere."""

    backend_resource: str
    front_keys: tuple[str, ...]
    static_front_keys: tuple[str, ...]
    kind: str               # "multi-key-collision" | "normalization-shift"
    note: str


@dataclass(frozen=True)
class PoisoningPrimitive:
    """A flagged cache-key anomaly, never a proven exploit chain."""

    primitive_id: str
    kind: str               # "unkeyed-input" | "host-confusion" | "reflection" | "normalization-collision"
    severity: str
    confidence: str
    evidence: tuple[str, ...]
    chain_note: str = CHAIN_NOTE
    offline: bool = True
    network_requests: int = 0


@dataclass(frozen=True)
class BotExfilStep:
    order: int
    actor: str              # "attacker" | "authenticated-bot" | "operator"
    action: str
    inert: bool = True


@dataclass(frozen=True)
class BotExfilPlan:
    """An inert, staged step order for an authenticated-bot exfil. It never runs traffic."""

    objective: str
    poison_key: str
    bot_read_path: str
    steps: tuple[BotExfilStep, ...]
    requires_live_bot: bool = True
    human_step: str = (
        "Needs the event's own authenticated bot and a live cache; this helper only stages the "
        "inert step order. Run the chain by hand against the live target."
    )
    offline: bool = True
    network_requests: int = 0


def _collapse_dotseg(path: str, *, strip_trailing_slash: bool = False) -> str:
    """Resolve `.`/`..` segments and collapse repeated slashes, keeping any leading slash.

    A trailing slash is kept (RFC 3986 remove_dot_segments keeps it, and many backends route
    ``/a/`` and ``/a`` differently): ``/a/`` stays ``/a/`` and ``/a/b/..`` becomes ``/a/``.
    ``strip_trailing_slash=True`` models a backend that folds the two together.
    """

    anchored = path.startswith("/")
    segments = path.split("/")
    out: list[str] = []
    for seg in segments:
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    trailing = (len(segments) > 1 and segments[-1] in ("", ".", "..")) and not strip_trailing_slash
    joined = "/".join(out)
    if trailing and joined:
        joined += "/"
    return ("/" + joined) if anchored else joined


def _front_canonical(path: str) -> str:
    """A Varnish-style front key: the raw request target, byte-for-byte (validated)."""

    return _safe_path(path)


def _backend_canonical(path: str, *, decode_passes: int = 1, collapse: bool = True,
                       strip_params: bool = False, strip_trailing_slash: bool = False) -> str:
    """Model one permissive backend's view of a target: percent-decode then canonicalise.

    `decode_passes` is how many percent-decoding layers the backend applies (2 models a
    double-decode bug); `strip_params` drops a `;params` suffix; `collapse` resolves dot-segments
    and repeated slashes; `strip_trailing_slash` folds ``/a/`` onto ``/a``. Only the path is
    normalised; the query is preserved verbatim.
    """

    _safe_path(path)
    if decode_passes < 0 or decode_passes > 4:
        raise CacheAnalysisError("decode_passes must be 0..4")
    head, sep, query = path.partition("?")
    if strip_params:
        head = head.split(";", 1)[0]
    for _ in range(decode_passes):
        head = unquote(head)
    if "\x00" in head or any(ord(ch) < 32 for ch in head):
        raise CacheAnalysisError("decoded path contains control characters")
    if collapse:
        head = _collapse_dotseg(head, strip_trailing_slash=strip_trailing_slash)
    if not head.startswith("/"):
        head = "/" + head
    return head + (sep + query if sep else "")


def _normalize_component(label: str) -> str:
    if not isinstance(label, str):
        raise CacheAnalysisError("cache-key component must be text")
    clean = label.strip().casefold()
    if not clean or len(clean) > 256 or any(ord(ch) < 32 for ch in clean):
        raise CacheAnalysisError("cache-key component must be 1..256 printable characters")
    # The Host header is one input however a source spells it: the front extractor says "host"
    # (req.http.host, $host), a backend read of headers["Host"] says "header:host".
    return _COMPONENT_ALIASES.get(clean, clean)


_COMPONENT_ALIASES = {"header:host": "host", "header:http-host": "host"}


def _parent(component: str) -> str | None:
    """``"query"`` for ``"query:lang"``: the whole input a sub-component is part of."""

    head, sep, tail = component.partition(":")
    return head if sep and head and tail else None


def map_frontend_backend_keys(front_keyed: Iterable[str],
                              backend_used: Iterable[str]) -> tuple[KeyComponent, ...]:
    """Map components the front cache keys against components the backend reads.

    A component the backend reads but the front does not key is an unkeyed-input poisoning
    primitive; one the front keys but the backend ignores is merely over-keyed (cache-busting).
    Components are opaque labels such as ``"path"``, ``"query:lang"`` or ``"header:x-forwarded-host"``.

    A parent component covers its children: a front that keys the whole ``"query"`` keys every
    ``"query:<name>"`` the backend reads, and a backend reading ``"query:lang"`` uses the front's
    ``"query"``. The reverse is not assumed: a front keying only ``"query:lang"`` against a backend
    reading the whole ``"query"`` leaves the other parameters off-key, so ``"query"`` is flagged.

    Both sets must be known: an empty side means "not determined", not "nothing", so this
    raises rather than tagging every input of the other side as an anomaly. Use
    :func:`build_key_map` when either side may be unknown.
    """

    front = {_normalize_component(item) for item in front_keyed}
    back = {_normalize_component(item) for item in backend_used}
    if not front or not back:
        raise CacheAnalysisError(
            "cache-key map needs both the front-keyed and the backend-read component sets; "
            "an empty set means the side is unknown, not empty"
        )
    back_parents = {_parent(item) for item in back}
    rows: list[KeyComponent] = []
    for comp in sorted(front | back):
        parent = _parent(comp)
        kf = comp in front or (parent is not None and parent in front)
        ub = comp in back or (parent is not None and parent in back) or comp in back_parents
        if ub and not kf:
            primitive = "unkeyed-input"
            note = "backend reads this input but the front cache key omits it: poisonable / varies off-key"
        elif kf and not ub:
            primitive = "over-keyed"
            note = "front keys an input the backend ignores: cache fragmentation only, low value"
        else:
            primitive = ""
            if comp not in front:
                note = f"keyed through the front's whole {parent!r} and read by the backend"
            elif comp not in back and parent is not None and parent in back:
                note = f"keyed by the front; the backend reads the whole {parent!r}"
            elif comp not in back:
                note = "keyed by the front; the backend reads parts of it"
            else:
                note = "input is both keyed by the front and read by the backend"
        rows.append(KeyComponent(comp, kf, ub, primitive, note))
    return tuple(rows)


KEY_MAP_COMPLETE = "complete"
KEY_MAP_FRONT_UNKNOWN = "front-key-unknown"
KEY_MAP_BACKEND_UNKNOWN = "backend-inputs-unknown"
KEY_MAP_EMPTY = "no-key-information"


def build_key_map(front_keyed: Iterable[str],
                  backend_used: Iterable[str]) -> tuple[str, tuple[KeyComponent, ...]]:
    """Return ``(status, rows)`` for a key map where either side may be undetermined.

    With both sides known the rows are :func:`map_frontend_backend_keys`. With one side unknown
    the known side's components are listed, each tagged ``front-key-unknown`` or
    ``backend-inputs-unknown`` and never as an anomaly, since there is no evidence for one.
    """

    front = {_normalize_component(item) for item in front_keyed}
    back = {_normalize_component(item) for item in backend_used}
    if front and back:
        return KEY_MAP_COMPLETE, map_frontend_backend_keys(front, back)
    if back:
        return KEY_MAP_FRONT_UNKNOWN, tuple(
            KeyComponent(comp, False, True, KEY_MAP_FRONT_UNKNOWN,
                         "backend reads this input; the front cache key could not be determined, "
                         "so whether it is keyed is unknown (supply --front)")
            for comp in sorted(back)
        )
    if front:
        return KEY_MAP_BACKEND_UNKNOWN, tuple(
            KeyComponent(comp, True, False, KEY_MAP_BACKEND_UNKNOWN,
                         "front keys this input; which inputs the backend reads could not be "
                         "determined (supply --backend)")
            for comp in sorted(front)
        )
    return KEY_MAP_EMPTY, ()


_FRONT_KEY_LINE = re.compile(
    r"(?im)^.{0,200}?(?:hash_data\s*\(|proxy_cache_key\b)[^\n]{0,400}$"
)
_VARNISH_REQ = re.compile(r"(?i)req\.(url|http\.[a-z0-9-]+)")
_NGINX_VAR = re.compile(r"\$(request_uri|uri|host|http_host|arg_[a-z0-9_]+|http_[a-z0-9_]+)")
# A VCL function wrapping req.url inside hash_data(...): regsub/regsuball with its pattern, or a
# vmod-querystring call. VCL strings are literal, so a query-stripping pattern reads `\?.*$`.
_VCL_URL_WRAP = re.compile(
    r'(?i)\b(regsuball|regsub|querystring\.[a-z_]+)\s*\(\s*req\.url\b\s*(?:,\s*"((?:[^"\\]|\\.)*)")?'
)
# vmod-querystring calls that drop the whole query or keep only a filtered part of it. A partly
# keyed query is reported as not keyed: some parameters reach the backend off-key.
_QS_STRIPPING = {"querystring.remove", "querystring.clean", "querystring.filter",
                 "querystring.filter_except", "querystring.regfilter",
                 "querystring.regfilter_except", "querystring.globfilter",
                 "querystring.globfilter_except"}


# A regsub pattern that removes everything from the `?` to the end of the URL: `\?.*$`, `[?].*`,
# `^([^?]*)(\?.*)?$`. A pattern that removes one parameter (`\?utm_source=[^&]*`, `[?&]utm_...`)
# keeps the rest of the query keyed, so it is not a full strip.
_FULL_QUERY_STRIP = re.compile(r"(?:\\\?|\[\?\])\.[*+]\)?\??\$?$")


def _regsub_strips_query(pattern: str | None) -> bool:
    if pattern is None:
        return False
    return _FULL_QUERY_STRIP.search(pattern) is not None


def _url_components(seg: str, url_start: int) -> set[str]:
    """Components keyed by the req.url token at `url_start` in a hash_data line."""

    for wrap in _VCL_URL_WRAP.finditer(seg):
        url_at = seg.casefold().find("req.url", wrap.start(), wrap.end())
        if url_at != url_start:
            continue
        func = wrap.group(1).casefold()
        if func in ("regsub", "regsuball"):
            return {"path"} if _regsub_strips_query(wrap.group(2)) else {"path", "query"}
        if func in _QS_STRIPPING:
            return {"path"}
        return {"path", "query"}
    return {"path", "query"}


def extract_front_keyed(source: str | bytes | bytearray | memoryview | None) -> frozenset[str]:
    """Best-effort front cache-key components from Varnish VCL / nginx cache-key source.

    A hint only: it reads ``hash_data(...)`` / ``proxy_cache_key`` lines. ``req.url`` keys path and
    query, except inside a query-stripping ``regsub``/``regsuball`` (pattern with ``\\?``) or a
    ``querystring.remove``/``filter*`` call, where only the path is keyed. Comments (``#``, ``//``,
    ``/* */``) are dropped first, so a commented-out ``hash_data`` keys nothing. A ``set req.url =
    ...`` rewrite earlier in ``vcl_recv`` is not followed. Prefer the explicit
    :func:`map_frontend_backend_keys` contract when the key is known.
    """

    text = _strip_comments(_source_text(source))
    found: set[str] = set()
    for line in _FRONT_KEY_LINE.finditer(text):
        seg = line.group(0)
        for m in _VARNISH_REQ.finditer(seg):
            token = m.group(1).casefold()
            if token == "url":
                found.update(_url_components(seg, m.start()))
            elif token == "http.host":
                found.add("host")
            elif token.startswith("http."):
                found.add("header:" + token[len("http."):])
        for m in _NGINX_VAR.finditer(seg):
            token = m.group(1).casefold()
            if token == "request_uri":
                found.update({"path", "query"})
            elif token == "uri":
                found.add("path")
            elif token in ("host", "http_host"):
                found.add("host")
            elif token.startswith("arg_"):
                found.add("query:" + token[len("arg_"):])
            elif token.startswith("http_"):
                found.add("header:" + token[len("http_"):].replace("_", "-"))
    return frozenset(found)


_BACKEND_HEADER = re.compile(
    r"(?i)(?:headers?(?:\.get)?\s*[\[(]\s*['\"]|HTTP_|get_?header\s*\(\s*['\"]|\breq\.get\s*\(\s*['\"]|"
    r"\$_SERVER\s*\[\s*['\"]HTTP_)"
    r"([A-Za-z][A-Za-z0-9_-]{1,40})"
)
_BACKEND_PATH = re.compile(
    r"(?i)(?:path_info|originalurl|original_uri|x-original-url|x-rewrite-url|try_files|sendfile|"
    r"req\.path|request\.path|request_uri)"
)
_BACKEND_QUERY = re.compile(
    r"(?i)(?:request\.args|request\.query|req\.query|request\.get\b|url\.searchparams|"
    r"\$_get\b|\$_request\b|querystring|query_string)"
)
_QUOTED = re.compile(r"""(['"])([A-Za-z0-9_-]{1,64})\1""")


def _strip_comments(text: str) -> str:
    """Drop `/* */` blocks and `#` / `//` line comments outside quoted strings (heuristic)."""

    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    out_lines: list[str] = []
    for line in text.splitlines():
        quote = ""
        cut = len(line)
        i = 0
        while i < len(line):
            ch = line[i]
            if quote:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = ""
            elif ch in ("'", '"'):
                quote = ch
            elif ch == "#" or line.startswith("//", i):
                cut = i
                break
            i += 1
        out_lines.append(line[:cut])
    return "\n".join(out_lines)


def extract_backend_inputs(source: str | bytes | bytearray | memoryview | None) -> frozenset[str]:
    """Best-effort set of request inputs the backend reads (headers, path, query). A hint only.

    Comments are stripped first, and a known unkeyed header name counts only as a whole quoted
    string (``"X-Forwarded-Host"``) or in a header-access pattern, never as a substring, so
    ``x-forwarded-host`` does not also imply ``forwarded``.
    """

    text = _strip_comments(_source_text(source))
    found: set[str] = set()
    for m in _QUOTED.finditer(text):
        name = m.group(2).casefold().replace("_", "-")
        if name in _UNKEYED_HEADERS:
            found.add("header:" + name)
    for m in _BACKEND_HEADER.finditer(text):
        raw = m.group(1).replace("_", "-").casefold()
        if raw.startswith("http-"):
            raw = raw[len("http-"):]
        if raw in {"host", "http-host"}:
            found.add("host")
        elif raw.startswith("x-") or raw == "forwarded":
            found.add("header:" + raw)
    if _BACKEND_PATH.search(text):
        found.add("path")
    if _BACKEND_QUERY.search(text):
        found.add("query")
    return frozenset(found)


def seed_candidate_paths(base_path: str) -> tuple[str, ...]:
    """The base path plus parser_differential's normalisation variants of it (B-021 reuse).

    Lets an operator test one base path for collisions without typing every %2e/%2e%2e/;/
    double-slash variant by hand. The variant generator is ``parser_differential``'s; this only
    validates and de-duplicates.
    """

    base = _safe_path(base_path)
    try:
        from . import parser_differential as _pd  # type: ignore[import-not-found]
    except ImportError:
        import parser_differential as _pd  # type: ignore[no-redef]
    out = [base]
    for row in _pd.path_normalization_variants(base):
        payload = _safe_path(row["payload"])
        if payload not in out:
            out.append(payload)
    return tuple(out)


def find_normalization_collisions(paths: Iterable[str], *, decode_passes: int = 1,
                                  collapse: bool = True, strip_params: bool = False,
                                  strip_trailing_slash: bool = False
                                  ) -> tuple[NormalizationCollision, ...]:
    """Group raw request targets by the backend resource they canonicalise to.

    When two distinct front cache keys collapse to one backend resource, that is a cache-key
    collision primitive; a single cacheable-looking key whose backend form shifts is a
    normalisation shift. Neither is a proven exploit — the chain stays human.
    """

    raws: list[str] = []
    for path in paths:
        if not isinstance(path, str):
            raise CacheAnalysisError("each candidate path must be text")
        raws.append(path)
        if len(raws) > MAX_KEY_PATHS:
            raise CacheAnalysisError(f"candidate path count exceeds {MAX_KEY_PATHS}")

    groups: dict[str, list[str]] = {}
    for raw in raws:
        front = _front_canonical(raw)
        canon = _backend_canonical(raw, decode_passes=decode_passes, collapse=collapse,
                                   strip_params=strip_params,
                                   strip_trailing_slash=strip_trailing_slash)
        groups.setdefault(canon, [])
        if front not in groups[canon]:
            groups[canon].append(front)

    collisions: list[NormalizationCollision] = []
    for canon in sorted(groups):
        fronts = tuple(groups[canon])
        static = tuple(fk for fk in fronts if _STATIC_SUFFIX.search(fk))
        if len(fronts) >= 2:
            note = (f"{len(fronts)} distinct front cache keys resolve to one backend resource "
                    f"{canon!r}; a victim and an attacker key can diverge.")
            collisions.append(NormalizationCollision(canon, fronts, static, "multi-key-collision", note))
        elif fronts and fronts[0] != canon and static:
            note = (f"cacheable-looking key {fronts[0]!r} resolves at the backend to {canon!r}; "
                    "the front may cache it while the origin serves a different resource.")
            collisions.append(NormalizationCollision(canon, fronts, static, "normalization-shift", note))
    return tuple(collisions)


def _primitive_from_finding(finding: CacheFinding) -> PoisoningPrimitive:
    kind_map = {
        "absolute-host-conflict": "host-confusion",
        "duplicate-host": "host-confusion",
        "explicit-marker-reflection": "reflection",
    }
    kind = kind_map.get(finding.finding_id,
                        "unkeyed-input" if finding.finding_id.startswith("unkeyed-") else "reflection")
    return PoisoningPrimitive(
        f"poison-{finding.finding_id}", kind, finding.severity, finding.confidence,
        finding.evidence,
    )


def _resolve_key_sets(source: str | bytes | bytearray | memoryview | None,
                      front_keyed: Iterable[str] | None,
                      backend_used: Iterable[str] | None,
                      use_source_hints: bool) -> tuple[set[str], set[str]]:
    """Explicit component sets win; otherwise fill each side from the source hints."""

    front = set(front_keyed) if front_keyed is not None else set()
    back = set(backend_used) if backend_used is not None else set()
    if use_source_hints and source is not None:
        if front_keyed is None:
            front |= set(extract_front_keyed(source))
        if backend_used is None:
            back |= set(extract_backend_inputs(source))
    return front, back


def report_poisoning_primitives(request_raw: str | bytes | bytearray | memoryview,
                                response_raw: str | bytes | bytearray | memoryview, *,
                                source: str | bytes | bytearray | memoryview | None = None,
                                marker: str | None = None,
                                candidate_paths: Sequence[str] = (),
                                front_keyed: Iterable[str] | None = None,
                                backend_used: Iterable[str] | None = None,
                                use_source_hints: bool = True) -> tuple[PoisoningPrimitive, ...]:
    """Aggregate every cache-key anomaly into one deterministic poisoning-primitive report.

    An unkeyed header found both by the saved-exchange analysis (``poison-unkeyed-<name>``) and by
    the key map is reported once: the key-map evidence is appended to the existing primitive.
    Key-map primitives need both sides of the key map; with either side unknown none are emitted.
    """

    response = parse_saved_response(response_raw)
    cacheable, _cache_evidence = _cacheability(response)
    primitives: list[PoisoningPrimitive] = [
        _primitive_from_finding(f)
        for f in analyze_cache_poisoning(request_raw, response_raw, source=source, marker=marker)
    ]
    by_id = {p.primitive_id: i for i, p in enumerate(primitives)}

    front, back = _resolve_key_sets(source, front_keyed, backend_used, use_source_hints)
    status, rows = build_key_map(front, back)
    if status == KEY_MAP_COMPLETE:
        for row in rows:
            if row.primitive != "unkeyed-input":
                continue
            evidence = (f"cache-key map: {row.note}",
                        f"component {row.component!r} keyed_front={row.keyed_front} "
                        f"used_backend={row.used_backend}")
            if row.component.startswith("header:"):
                existing = by_id.get("poison-unkeyed-" + row.component[len("header:"):])
                if existing is not None:
                    prior = primitives[existing]
                    primitives[existing] = _dc_replace(prior, evidence=prior.evidence + evidence)
                    continue
            sev = "medium" if cacheable else "low"
            primitives.append(PoisoningPrimitive(
                f"keymap-{row.component}", "unkeyed-input", sev, "low", evidence,
            ))

    for coll in find_normalization_collisions(candidate_paths):
        anchor = (coll.static_front_keys[0] if coll.static_front_keys else coll.front_keys[0])
        strong = bool(coll.static_front_keys) and cacheable
        primitives.append(PoisoningPrimitive(
            f"collision-{anchor}", "normalization-collision",
            "high" if strong else "medium", "medium" if coll.static_front_keys else "low",
            (coll.note, f"backend resource: {coll.backend_resource!r}",
             f"front keys: {coll.front_keys!r}"),
        ))

    return tuple(sorted(primitives, key=lambda item: item.primitive_id))


def build_bot_exfil_plan(poison_key: str, bot_read_path: str, *,
                         marker: str = "r5d-inert") -> BotExfilPlan:
    """Stage (never run) the inert step order for an authenticated-bot cache-exfil chain."""

    poison_key = _safe_path(poison_key)
    bot_read_path = _safe_path(bot_read_path)
    if (not isinstance(marker, str) or not marker or len(marker) > 512
            or any(ch in marker for ch in "\r\n\x00")):
        raise CacheAnalysisError("marker must be 1..512 characters without CR/LF/NUL")
    steps = (
        BotExfilStep(1, "attacker",
                     f"request the poison key {poison_key!r} so the front cache stores an entry under it "
                     f"(inert marker {marker!r}; no request is sent here)"),
        BotExfilStep(2, "authenticated-bot",
                     f"have the event's own bot visit {bot_read_path!r}; if its authenticated response is "
                     f"keyed to the same front entry, the cache stores privileged content"),
        BotExfilStep(3, "attacker",
                     f"re-request {poison_key!r}; a cached authenticated body is the exfiltrated secret"),
        BotExfilStep(4, "operator",
                     "diff against a benign control before claiming the cache served another identity's body"),
    )
    return BotExfilPlan(
        f"exfil {bot_read_path!r} via a shared cache key {poison_key!r}",
        poison_key, bot_read_path, steps,
    )


def analyze_cache_key_confusion(request_raw: str | bytes | bytearray | memoryview,
                                response_raw: str | bytes | bytearray | memoryview, *,
                                source: str | bytes | bytearray | memoryview | None = None,
                                marker: str | None = None,
                                candidate_paths: Sequence[str] = (),
                                front_keyed: Iterable[str] | None = None,
                                backend_used: Iterable[str] | None = None,
                                exfil_read_path: str | None = None) -> dict[str, object]:
    """One deterministic JSON-ready front/back cache-key-confusion report.

    ``exfil_read_path`` needs a candidate poison key (a ``candidate_paths`` entry); without one
    this raises instead of silently omitting the requested bot plan.
    """

    if exfil_read_path is not None and not candidate_paths:
        raise CacheAnalysisError(
            "exfil-read needs a candidate poison key: give at least one candidate path (--path)"
        )
    primitives = report_poisoning_primitives(
        request_raw, response_raw, source=source, marker=marker,
        candidate_paths=candidate_paths, front_keyed=front_keyed, backend_used=backend_used,
    )
    collisions = find_normalization_collisions(candidate_paths)
    front, back = _resolve_key_sets(source, front_keyed, backend_used, True)
    key_map_status, key_map = build_key_map(front, back)

    bot_plan = None
    if exfil_read_path is not None:
        static = [fk for coll in collisions for fk in coll.static_front_keys]
        poison = static[0] if static else candidate_paths[0]
        bot_plan = asdict(build_bot_exfil_plan(poison, exfil_read_path))

    return {
        "primitives": [asdict(item) for item in primitives],
        "collisions": [asdict(item) for item in collisions],
        "key_map": [asdict(item) for item in key_map],
        "key_map_status": key_map_status,
        "bot_plan": bot_plan,
        "offline": True,
        "network_requests": 0,
        "caution": CHAIN_NOTE,
    }


__all__ = [
    "BotExfilPlan", "BotExfilStep", "CHAIN_NOTE", "CacheAnalysisError", "CacheFinding",
    "CacheVariant", "KEY_MAP_BACKEND_UNKNOWN", "KEY_MAP_COMPLETE", "KEY_MAP_EMPTY",
    "KEY_MAP_FRONT_UNKNOWN", "KeyComponent", "MAX_KEY_PATHS", "MAX_SAVED_BYTES", "NormalizationCollision",
    "PoisoningPrimitive", "ResponseComparison", "ResponseHeader", "SavedResponse",
    "analyze_cache_deception", "analyze_cache_exchange", "analyze_cache_key_confusion",
    "analyze_cache_poisoning", "build_bot_exfil_plan", "build_deception_variants", "build_key_map",
    "build_poisoning_variants", "compare_saved_responses", "extract_backend_inputs",
    "extract_front_keyed", "find_normalization_collisions", "map_frontend_backend_keys",
    "parse_saved_response", "report_poisoning_primitives", "seed_candidate_paths",
]
