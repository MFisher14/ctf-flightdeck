#!/usr/bin/env python3
"""Offline cookie/session/CSP evaluation and non-overlapping cache/upload catalogs.

All functions consume bounded saved text/metadata or emit inert strings.  No
browser, HTTP client, file decoder, archive parser, image parser, process, or
execution facility is imported.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, Sequence


MAX_TEXT = 2_000_000
MAX_HEADERS = 512
MAX_COOKIES = 128
MAX_VARIANTS = 64


class SessionDepthError(ValueError):
    """Raised for malformed or over-limit saved policy evidence."""


@dataclass(frozen=True)
class PolicyFinding:
    finding_id: str
    family: str
    title: str
    severity: str
    confidence: str
    evidence: tuple[str, ...]
    remediation: str


@dataclass(frozen=True)
class HeaderField:
    name: str
    value: str
    line_number: int


@dataclass(frozen=True)
class ExtendedVariant:
    rank: int
    family: str
    name: str
    value: str
    content_type: str
    hypothesis: str
    inert: bool = True
    offline: bool = True
    network_requests: int = 0


def _text(raw: str | bytes | bytearray | memoryview, label: str) -> str:
    if isinstance(raw, str):
        text = raw
        size = len(text.encode("utf-8"))
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        size = len(data)
        text = data.decode("utf-8", "replace")
    else:
        raise SessionDepthError(f"{label} must be text or bytes")
    if size > MAX_TEXT:
        raise SessionDepthError(f"{label} exceeds {MAX_TEXT} bytes")
    if "\x00" in text:
        raise SessionDepthError(f"{label} contains NUL")
    return text


def parse_saved_headers(raw: str | bytes | bytearray | memoryview) -> tuple[HeaderField, ...]:
    """Preserve duplicate saved HTTP header fields without parsing the body."""

    text = _text(raw, "saved HTTP artifact")
    head = re.split(r"\r?\n\r?\n", text, maxsplit=1)[0]
    lines = head.replace("\r\n", "\n").split("\n")
    if lines and not ":" in lines[0]:
        lines = lines[1:]
        offset = 2
    else:
        offset = 1
    rows: list[HeaderField] = []
    for number, line in enumerate(lines, offset):
        if not line:
            continue
        if len(rows) >= MAX_HEADERS:
            raise SessionDepthError(f"header count exceeds {MAX_HEADERS}")
        if line.startswith((" ", "\t")) or ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip().casefold()
        value = value.strip(" \t")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", name):
            continue
        rows.append(HeaderField(name, value[:65_536], number))
    return tuple(rows)


def _header_values(rows: Sequence[HeaderField], name: str) -> tuple[str, ...]:
    wanted = name.casefold()
    return tuple(row.value for row in rows if row.name == wanted)


def _cookie_parts(value: str) -> tuple[str, str, tuple[tuple[str, str], ...]]:
    pieces = [piece.strip() for piece in value.split(";")]
    if not pieces or "=" not in pieces[0]:
        return "", "", ()
    name, cookie_value = pieces[0].split("=", 1)
    attrs: list[tuple[str, str]] = []
    for piece in pieces[1:]:
        attr, separator, attr_value = piece.partition("=")
        attrs.append((attr.strip().casefold(), attr_value.strip() if separator else ""))
    return name.strip(), cookie_value, tuple(attrs)


def _sensitive_cookie_name(name: str) -> bool:
    folded = name.casefold()
    if folded in {"phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid"}:
        return True
    return bool(re.search(
        r"(?:^|[-_])(?:session(?:[-_]?id)?|sess(?:[-_]?id)?|sid|auth(?:[-_]?token)?|"
        r"access[-_]?token|refresh[-_]?token|token|jwt|csrf)(?:$|[-_])|(?:auth|access|refresh)?token$",
        folded,
    ))


def evaluate_cookie_session_csp(response: str | bytes | bytearray | memoryview, *,
                                request: str | bytes | bytearray | memoryview = "",
                                source: str | bytes | bytearray | memoryview = "",
                                html: str | bytes | bytearray | memoryview = "") -> tuple[PolicyFinding, ...]:
    """Evaluate saved Set-Cookie/session cache/CSP evidence without a browser."""

    response_text = _text(response, "saved response")
    request_text = _text(request, "saved request")
    source_text = _text(source, "saved session source")
    html_text = _text(html, "saved HTML")
    headers = parse_saved_headers(response_text)
    request_headers = parse_saved_headers(request_text) if request_text else ()
    findings: list[PolicyFinding] = []

    def add(code: str, family: str, title: str, severity: str, confidence: str,
            evidence: Iterable[str], remediation: str) -> None:
        findings.append(PolicyFinding(code, family, title, severity, confidence,
                                      tuple(evidence), remediation))

    cookie_rows = _header_values(headers, "set-cookie")
    if len(cookie_rows) > MAX_COOKIES:
        raise SessionDepthError(f"Set-Cookie count exceeds {MAX_COOKIES}")
    cookies: list[tuple[str, str, tuple[tuple[str, str], ...]]] = []
    sensitive_cookie_present = False
    for index, value in enumerate(cookie_rows, 1):
        name, cookie_value, attrs = _cookie_parts(value)
        cookies.append((name, cookie_value, attrs))
        if not name:
            add(f"cookie-malformed-{index}", "cookie", "Malformed Set-Cookie field", "medium", "high",
                (f"line value: {value[:256]!r}",), "Reject malformed cookie metadata.")
            continue
        attr_names = tuple(name for name, _value in attrs)
        duplicates = tuple(sorted({name for name in attr_names if attr_names.count(name) > 1}))
        if duplicates:
            add(f"cookie-duplicate-attrs-{index}", "cookie", "Cookie repeats attributes", "high", "high",
                (f"cookie {name!r}", f"attributes {duplicates!r}"),
                "Emit each cookie attribute once with a canonical value.")
        attr_map = {key: value for key, value in attrs}
        sensitive = _sensitive_cookie_name(name)
        sensitive_cookie_present = sensitive_cookie_present or sensitive
        if sensitive and "secure" not in attr_map:
            add(f"cookie-secure-{index}", "cookie", "Sensitive cookie lacks Secure", "high", "high",
                (f"cookie {name!r}",), "Mark authentication/session cookies Secure.")
        if sensitive and "httponly" not in attr_map:
            add(f"cookie-httponly-{index}", "cookie", "Sensitive cookie lacks HttpOnly", "high", "high",
                (f"cookie {name!r}",), "Mark bearer session cookies HttpOnly unless script access is essential.")
        same_site = attr_map.get("samesite", "").casefold()
        if same_site and same_site not in {"strict", "lax", "none"}:
            add(f"cookie-samesite-invalid-{index}", "cookie", "Cookie has an invalid SameSite value", "medium", "high",
                (f"cookie {name!r}", f"SameSite={attr_map.get('samesite', '')!r}"),
                "Use exactly Strict, Lax, or None and test the intended browser flow.")
        if same_site == "none" and "secure" not in attr_map:
            add(f"cookie-samesite-none-{index}", "cookie", "SameSite=None cookie lacks Secure", "high", "high",
                (f"cookie {name!r}",), "Pair SameSite=None with Secure and explicit CSRF protections.")
        if sensitive and not same_site:
            add(f"cookie-samesite-missing-{index}", "cookie", "Sensitive cookie omits SameSite", "medium", "high",
                (f"cookie {name!r}",), "Set an explicit SameSite policy compatible with the authentication flow.")
        if "partitioned" in attr_map and "secure" not in attr_map:
            add(f"cookie-partitioned-{index}", "cookie", "Partitioned cookie lacks Secure", "medium", "high",
                (f"cookie {name!r}",), "Use Secure with Partitioned and validate browser support/fallback.")
        if name.startswith("__Host-") and ("secure" not in attr_map or attr_map.get("path") != "/" or "domain" in attr_map):
            add(f"cookie-host-prefix-{index}", "cookie", "__Host- cookie violates prefix requirements", "high", "high",
                (f"attributes {attrs!r}",), "Use Secure, Path=/, and no Domain for __Host- cookies.")
        if name.startswith("__Secure-") and "secure" not in attr_map:
            add(f"cookie-secure-prefix-{index}", "cookie", "__Secure- cookie lacks Secure", "high", "high",
                (f"cookie {name!r}",), "Honor the __Secure- prefix contract.")
        domain = attr_map.get("domain", "")
        if sensitive and domain:
            add(f"cookie-domain-{index}", "cookie", "Sensitive cookie is scoped to subdomains", "medium", "high",
                (f"Domain={domain}",), "Prefer host-only session cookies.")
    names = [name for name, _value, _attrs in cookies if name]
    duplicate_cookie_names = tuple(sorted({name for name in names if names.count(name) > 1}))
    if duplicate_cookie_names:
        add("cookie-name-collision", "cookie", "Response sets the same cookie name more than once", "medium", "high",
            (f"names: {duplicate_cookie_names!r}",),
            "Avoid overlapping Domain/Path variants and expire old scope variants explicitly.")

    cache_control = ",".join(_header_values(headers, "cache-control")).casefold()
    authenticated_request = bool(_header_values(request_headers, "cookie") or
                                 _header_values(request_headers, "authorization"))
    if (authenticated_request or sensitive_cookie_present) and not re.search(
            r"(?:^|,)\s*(?:private|no-store)\b", cache_control):
        add("session-cache-policy", "session", "Session-bearing response lacks private/no-store cache policy",
            "high", "medium", (f"Cache-Control: {cache_control!r}",
                               f"authenticated request: {authenticated_request}"),
            "Prevent shared storage of personalized/session-establishing responses.")
    start_line = request_text.replace("\r\n", "\n").split("\n", 1)[0] if request_text else ""
    if re.search(r"(?i)[?&](?:sid|session(?:id)?|token|auth)=", start_line):
        add("session-id-url", "session", "Session/token identifier appears in the request URL", "high", "high",
            (start_line[:512],), "Keep session identifiers out of URLs, logs, referrers, and browser history.")
    if (re.search(r"(?i)(?:session_?(?:id)?|sid)\s*=\s*(?:req|request)\.(?:query|body|params)", source_text)
            and not re.search(r"(?i)(?:regenerate|rotate|renew).*session", source_text)):
        add("session-fixation-source", "session", "Source accepts client session identifiers without rotation evidence",
            "high", "medium", ("client-controlled session-id token", "no regeneration token"),
            "Generate/rotate the server session ID at authentication and privilege changes.")

    enforced = _header_values(headers, "content-security-policy")
    report_only = _header_values(headers, "content-security-policy-report-only")
    if report_only and not enforced:
        add("csp-report-only", "CSP", "Only report-only CSP is present", "medium", "high",
            (f"policies: {len(report_only)}",), "Deploy an enforced policy after validating reports.")
    policies: list[dict[str, tuple[str, ...]]] = []
    for policy_index, policy in enumerate(enforced, 1):
        directives: dict[str, tuple[str, ...]] = {}
        duplicates: list[str] = []
        for part in policy.split(";"):
            tokens = part.strip().split()
            if not tokens:
                continue
            name = tokens[0].casefold()
            if name in directives:
                duplicates.append(name)
            else:
                directives[name] = tuple(tokens[1:])
        policies.append(directives)
        if duplicates:
            add(f"csp-duplicate-directive-{policy_index}", "CSP", "One CSP policy repeats directives",
                "medium", "high", (f"directives: {tuple(duplicates)!r}",),
                "Emit each directive once; browsers ignore later duplicates within a policy.")
        script = directives.get("script-src", directives.get("default-src", ()))
        folded_script = {token.casefold() for token in script}
        risky = tuple(token for token in script if token.casefold() in {
            "'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:", "https:",
        })
        if risky:
            add(f"csp-script-risk-{policy_index}", "CSP", "Script policy contains broad execution sources",
                "high", "high", (f"tokens: {risky!r}",),
                "Use nonces/hashes and narrowly trusted origins; remove unsafe-inline/eval and broad schemes.")
        nonces = tuple(token[7:-1] for token in script
                       if token.casefold().startswith("'nonce-") and token.endswith("'"))
        short_nonces = tuple(value for value in nonces if len(value) < 16)
        if short_nonces:
            add(f"csp-short-nonce-{policy_index}", "CSP", "CSP nonce text is unusually short", "medium", "high",
                (f"lengths: {tuple(len(item) for item in short_nonces)!r}",),
                "Generate a fresh unpredictable nonce per response.")
        for required in ("object-src", "base-uri"):
            if required not in directives:
                add(f"csp-missing-{required}-{policy_index}", "CSP", f"CSP omits {required}", "low", "high",
                    (f"policy {policy_index}",), f"Set {required} explicitly, commonly to 'none'.")
        if "trusted-types" not in directives and ("'unsafe-inline'" in folded_script or "'unsafe-eval'" in folded_script):
            add(f"csp-trusted-types-{policy_index}", "CSP", "Risky script policy has no Trusted Types directive",
                "low", "medium", (f"policy {policy_index}",),
                "Consider require-trusted-types-for 'script' alongside a compatible application policy.")
    if enforced and html_text:
        policy_nonces = tuple(re.findall(r"(?i)'nonce-([^']+)'", " ".join(enforced)))
        html_nonces = tuple(re.findall(r"(?i)\bnonce\s*=\s*[\"']([^\"']+)", html_text))
        unauthorized = tuple(sorted(set(html_nonces).difference(policy_nonces)))
        if unauthorized:
            add("csp-html-nonce-mismatch", "CSP", "Saved elements use nonce values absent from the CSP", "medium", "high",
                (f"unmatched nonces: {unauthorized[:16]!r}",),
                "Generate one fresh response nonce and place the same value in policy and intended elements.")
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def build_extended_cache_variants(path: str = "/account", marker: str = "R5D_INERT") -> tuple[ExtendedVariant, ...]:
    """Additional cache-key/deception forms not present in cache_analysis."""

    if (not isinstance(path, str) or not path.startswith("/") or len(path) > 4096
            or any(ord(char) < 33 or ord(char) > 126 for char in path)):
        raise SessionDepthError("path must be a bounded ASCII absolute path")
    if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{3,63}", marker):
        raise SessionDepthError("marker must be a bounded inert token")
    base = path.rstrip("/") or "/"
    specs = (
        ("cache-deception", "encoded-dot-suffix", f"{base}%2eR5D.css", "encoded dot becomes a static suffix at one hop"),
        ("cache-deception", "encoded-backslash", f"{base}.css%5c..%5c{base.strip('/')}", "Windows/origin backslash normalization differs"),
        ("cache-deception", "matrix-session", f"{base};jsessionid={marker}/r5d.css", "path-parameter/session stripping differs"),
        ("cache-deception", "encoded-null-suffix", f"{base}%00.r5d.css", "NUL rejection/truncation differs between layers"),
        ("cache-deception", "fullwidth-dot-suffix", f"{base}\uff0er5d.css", "Unicode compatibility normalization differs"),
        ("cache-deception", "suffix-query-fold", f"{base}.css%3f/r5d/{marker}", "encoded query delimiter changes origin route"),
        ("cache-key", "forwarded-prefix", f"X-Forwarded-Prefix: /{marker}", "origin route/reflection uses an unkeyed prefix"),
        ("cache-key", "forwarded-uri", f"X-Forwarded-Uri: /{marker}", "origin uses an unkeyed forwarded URI"),
        ("cache-key", "original-host", f"X-Original-Host: {marker}.invalid", "origin authority differs from cache authority"),
        ("cache-key", "accel-redirect", f"X-Accel-Redirect: /{marker}", "internal redirect metadata crosses the cache key"),
        ("cache-key", "cookie-marker", f"Cookie: r5d_cache={marker}", "origin varies on a cookie omitted from the shared key"),
    )
    return tuple(ExtendedVariant(index, family, name, value, "text/plain", hypothesis)
                 for index, (family, name, value, hypothesis) in enumerate(specs, 1))


def analyze_extended_cache_source(source: str | bytes | bytearray | memoryview) -> tuple[PolicyFinding, ...]:
    text = _text(source, "saved cache source/config")
    findings: list[PolicyFinding] = []
    patterns = (
        ("cache-query-omission", r"(?i)(?:ignore[_ -]?query|query[_ -]?string\s*=\s*false|cacheEverything)",
         "Cache configuration may omit query data from a route that consumes it"),
        ("cache-cookie-omission", r"(?i)(?:ignore[_ -]?cookie|cookies?\s*=\s*none|cache_key[^\n]{0,200}\$uri)",
         "Cache key may omit cookies"),
        ("cache-normalization-gap", r"(?i)(?:decodeURIComponent|unescape|normalize|realpath|path_info|try_files)",
         "Origin/cache path normalization tokens are present"),
        ("cache-extension-rule", r"(?i)(?:\.css|\.js|\.png|static).{0,100}(?:cache|ttl|max-age)",
         "Static-extension cache rule appears in saved configuration"),
    )
    for code, pattern, title in patterns:
        match = re.search(pattern, text)
        if match:
            findings.append(PolicyFinding(
                code, "cache", title, "medium", "medium",
                (f"matched text: {match.group(0)[:200]!r}",),
                "Canonicalize once and key every request component that changes the origin response.",
            ))
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def build_extended_upload_variants(basename: str = "r5d_probe", marker: str = "R5D_INERT") -> tuple[ExtendedVariant, ...]:
    """Additional inert magic/polyglot/multipart metadata strings."""

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", basename):
        raise SessionDepthError("basename must be a bounded filename token")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{3,63}", marker):
        raise SessionDepthError("marker must be a bounded inert token")
    specs = (
        ("upload-magic", "webp-riff", f"RIFF\\x00\\x00\\x00\\x00WEBP{marker}", "image/webp", "RIFF/WEBP prefix-only validation"),
        ("upload-magic", "mp4-ftyp", f"\\x00\\x00\\x00\\x18ftypisom{marker}", "video/mp4", "ftyp brand prefix-only validation"),
        ("upload-magic", "bmp", f"BM\\x00\\x00\\x00\\x00{marker}", "image/bmp", "BMP signature without decoded dimensions"),
        ("upload-magic", "tiff-little", f"II*\\x00{marker}", "image/tiff", "TIFF byte-order/magic-only validation"),
        ("upload-magic", "ico", f"\\x00\\x00\\x01\\x00{marker}", "image/x-icon", "ICO header-only validation"),
        ("upload-polyglot", "jpeg-zip-tail", f"\\xFF\\xD8\\xFF{marker}PK\\x03\\x04R5D_NO_ARCHIVE", "image/jpeg", "leading-image versus trailing-container classification"),
        ("upload-polyglot", "pdf-zip-tail", f"%PDF-1.7\\n%{marker}\\n%%EOF\\nPK\\x05\\x06R5D_NO_ARCHIVE", "application/pdf", "PDF EOF versus ZIP-tail classification"),
        ("upload-polyglot", "gif-html-comment", f"GIF89a<!--{marker}-->", "image/gif", "image prefix versus text serving/sniffing"),
        ("multipart-metadata", "filename-star-conflict",
         f'Content-Disposition: form-data; name="file"; filename="{basename}.jpg"; filename*=UTF-8\'\'{basename}%2e{marker}.txt',
         "text/plain", "filename versus RFC 5987 filename* selection"),
        ("multipart-metadata", "duplicate-content-type",
         f"Content-Type: image/jpeg\\r\\nContent-Type: application/octet-stream\\r\\nX-R5D-Marker: {marker}",
         "text/plain", "first/last Content-Type selection"),
    )
    if len(specs) > MAX_VARIANTS:
        raise SessionDepthError("variant cap exceeded")
    return tuple(ExtendedVariant(index, family, name, value, content_type, hypothesis)
                 for index, (family, name, value, content_type, hypothesis) in enumerate(specs, 1))


def analyze_upload_metadata(fields: Sequence[tuple[str, str]]) -> tuple[PolicyFinding, ...]:
    """Correlate saved filename/media/magic metadata without opening a file."""

    if not isinstance(fields, Sequence) or isinstance(fields, (str, bytes, bytearray)) or len(fields) > MAX_HEADERS:
        raise SessionDepthError("upload metadata must be a bounded sequence of pairs")
    rows: list[tuple[str, str]] = []
    for item in fields:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise SessionDepthError("upload metadata contains a non-pair")
        name, value = item
        if not isinstance(name, str) or not isinstance(value, str) or len(value) > 65_536:
            raise SessionDepthError("upload metadata field is invalid")
        rows.append((name.casefold(), value))
    findings: list[PolicyFinding] = []
    for name in ("filename", "filename*", "content-type", "magic", "detected-type"):
        values = tuple(value for key, value in rows if key == name)
        if len(values) > 1:
            findings.append(PolicyFinding(
                f"upload-duplicate-{name}", "upload", "Upload metadata field is duplicated",
                "high", "high", (f"{name}: {values!r}",),
                "Reject duplicate multipart/type metadata before validation.",
            ))
    filename = next((value for key, value in rows if key == "filename"), "")
    filename_star = next((value for key, value in rows if key == "filename*"), "")
    if filename and filename_star and filename.casefold() != filename_star.casefold():
        findings.append(PolicyFinding(
            "upload-filename-conflict", "upload", "filename and filename* disagree", "high", "high",
            (f"filename {filename!r}", f"filename* {filename_star!r}"),
            "Choose one decoded filename representation, reject conflicts, and generate a server filename.",
        ))
    declared = next((value for key, value in rows if key == "content-type"), "").casefold()
    detected = next((value for key, value in rows if key == "detected-type"), "").casefold()
    if declared and detected and declared != detected:
        findings.append(PolicyFinding(
            "upload-type-conflict", "upload", "Declared and detected media types disagree", "medium", "high",
            (f"declared {declared!r}", f"detected {detected!r}"),
            "Fully decode/re-encode allowed formats and serve from a non-executable origin.",
        ))
    extension = filename.rsplit(".", 1)[-1].casefold() if "." in filename else ""
    expected = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif",
                "webp": "image/webp", "pdf": "application/pdf"}.get(extension)
    if expected and declared and declared != expected:
        findings.append(PolicyFinding(
            "upload-extension-media-conflict", "upload", "Filename extension and declared media type disagree",
            "medium", "high", (f"extension {extension!r}", f"Content-Type {declared!r}"),
            "Require extension, decoded type, and re-encoded output policy to agree.",
        ))
    return tuple(sorted(findings, key=lambda item: item.finding_id))


__all__ = [
    "ExtendedVariant", "HeaderField", "PolicyFinding", "SessionDepthError",
    "analyze_extended_cache_source", "analyze_upload_metadata", "build_extended_cache_variants",
    "build_extended_upload_variants", "evaluate_cookie_session_csp", "parse_saved_headers",
]
