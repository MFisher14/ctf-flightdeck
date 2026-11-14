#!/usr/bin/env python3
"""Offline REST/OpenAPI authorization and parser-differential analysis.

OpenAPI and source inputs are treated as bounded text.  This module does not
load JSON/YAML objects, resolve references, execute code, or send requests.
The line-oriented schema extractor is intentionally conservative: findings are
evidence leads with explicit confidence, never vulnerability claims.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, Sequence
from urllib.parse import parse_qsl, urlsplit

try:  # Namespace-package and direct solver-directory imports.
    from .api_protocols import APIProtocolError, parse_saved_handshake
except ImportError:  # pragma: no cover - repository tests use direct import
    from api_protocols import APIProtocolError, parse_saved_handshake


MAX_SCHEMA_CHARS = 2_000_000
MAX_SOURCE_CHARS = 2_000_000
MAX_OPERATIONS = 1024
MAX_VARIANTS = 32


class RESTAnalysisError(ValueError):
    """Raised for malformed or over-limit saved REST/schema input."""


@dataclass(frozen=True)
class RESTFinding:
    finding_id: str
    family: str
    title: str
    severity: str
    confidence: str
    evidence: tuple[str, ...]
    remediation: str


@dataclass(frozen=True)
class RouteOperation:
    path: str
    method: str
    line_number: int
    operation_id: str
    security_state: str
    deprecated: bool
    parameter_names: tuple[str, ...]
    content_types: tuple[str, ...]


@dataclass(frozen=True)
class RESTVariant:
    rank: int
    family: str
    name: str
    request: str
    hypothesis: str
    offline: bool = True
    network_requests: int = 0


_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
_OBJECT_PARAM = re.compile(r"(?i)\{(?:id|[A-Za-z0-9_]*(?:id|uuid|key|slug|account|user|tenant)[A-Za-z0-9_]*)\}")
_SENSITIVE_FIELD = re.compile(
    r"(?i)^(?:role|roles|isadmin|admin|permissions?|privileges?|owner(?:id)?|user(?:id)?|account(?:id)?|"
    r"tenant(?:id)?|status|state|balance|credit|verified|approved|internal|price|plan)$"
)
_PAGINATION = re.compile(r"(?i)^(?:limit|pagesize|perpage|take|maxresults|count|offset|page)$")
_PATH_LINE = re.compile(r'^\s*(?:"(?P<json>/[^"\r\n]+)"|(?P<yaml>/[^:\s][^:]*))\s*:\s*(?:\{|$)')
_METHOD_LINE = re.compile(r'^\s*(?:"(?P<json>get|post|put|patch|delete|options|head|trace)"|'
                          r'(?P<yaml>get|post|put|patch|delete|options|head|trace))\s*:\s*(?:\{|$)', re.I)


def _text(raw: str | bytes | bytearray | memoryview, label: str, maximum: int) -> str:
    if isinstance(raw, str):
        value = raw
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        value = bytes(raw).decode("utf-8", "replace")
    else:
        raise RESTAnalysisError(f"{label} must be text or bytes")
    if len(value) > maximum:
        raise RESTAnalysisError(f"{label} exceeds {maximum} characters")
    if "\x00" in value:
        raise RESTAnalysisError(f"{label} contains NUL")
    return value


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _quoted_or_yaml_value(block: str, key: str) -> tuple[str, ...]:
    pattern = re.compile(
        rf'(?im)^\s*(?:"{re.escape(key)}"|{re.escape(key)})\s*:\s*'
        r'(?:"([^"\r\n]+)"|\'([^\'\r\n]+)\'|([^\s,}\]\r\n]+))'
    )
    return tuple(next(value for value in match.groups() if value is not None)
                 for match in pattern.finditer(block))


def _property_names(block: str) -> tuple[str, ...]:
    names: list[str] = []
    for pattern in (
        re.compile(r'(?im)^\s*(?:-\s*)?name\s*:\s*["\']?([A-Za-z_][A-Za-z0-9_.-]{0,127})'),
        re.compile(r'(?im)^\s*"name"\s*:\s*"([A-Za-z_][A-Za-z0-9_.-]{0,127})"'),
    ):
        names.extend(match.group(1) for match in pattern.finditer(block))
    return tuple(dict.fromkeys(names))


def extract_openapi_operations(schema: str | bytes | bytearray | memoryview) -> tuple[RouteOperation, ...]:
    """Lexically extract path/method blocks without deserializing the schema."""

    text = _text(schema, "OpenAPI schema", MAX_SCHEMA_CHARS)
    lines = text.splitlines()
    markers: list[tuple[int, str, str, int]] = []
    current_path = ""
    current_path_indent = -1
    for index, line in enumerate(lines):
        path_match = _PATH_LINE.match(line)
        if path_match:
            current_path = path_match.group("json") or path_match.group("yaml") or ""
            current_path_indent = _indent(line)
            markers.append((index, "path", current_path, current_path_indent))
            continue
        line_indent = _indent(line)
        if current_path and line.strip() and line_indent <= current_path_indent:
            current_path = ""
            current_path_indent = -1
        method_match = _METHOD_LINE.match(line)
        if (method_match and current_path and current_path_indent < line_indent
                <= current_path_indent + 4):
            method = (method_match.group("json") or method_match.group("yaml") or "").casefold()
            markers.append((index, "method", method, line_indent))
    operations: list[RouteOperation] = []
    active_path = ""
    for position, (line_index, kind, value, marker_indent) in enumerate(markers):
        if kind == "path":
            active_path = value
            continue
        if not active_path:
            continue
        if len(operations) >= MAX_OPERATIONS:
            raise RESTAnalysisError(f"operation count exceeds {MAX_OPERATIONS}")
        end = len(lines)
        for next_index, next_kind, _next_value, _next_indent in markers[position + 1:]:
            if next_kind in {"method", "path"}:
                end = next_index
                break
        for candidate in range(line_index + 1, end):
            if lines[candidate].strip() and _indent(lines[candidate]) <= marker_indent:
                end = candidate
                break
        block = "\n".join(lines[line_index:end])
        operation_ids = _quoted_or_yaml_value(block, "operationId")
        security_present = bool(re.search(r'(?im)^\s*(?:"security"|security)\s*:', block))
        security_empty = bool(re.search(
            r'(?im)^\s*(?:"security"|security)\s*:\s*(?:\[\s*\]|\{\s*\}|null)\s*,?$', block
        ))
        state = "explicit-empty" if security_empty else ("operation" if security_present else "inherited-or-unknown")
        deprecated = bool(re.search(r'(?im)^\s*(?:"deprecated"|deprecated)\s*:\s*true\b', block))
        content_types = tuple(dict.fromkeys(re.findall(
            r'(?im)(?:^|["\'\s])((?:application|text)/[A-Za-z0-9.+_-]+)\s*(?::|"\s*:)', block
        )))
        operations.append(RouteOperation(
            active_path, value, line_index + 1, operation_ids[0] if operation_ids else "",
            state, deprecated, _property_names(block), content_types,
        ))
    return tuple(operations)


def _sensitive_schema_fields(schema_text: str) -> tuple[tuple[str, bool, int], ...]:
    lines = schema_text.splitlines()
    results: list[tuple[str, bool, int]] = []
    patterns = (
        re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_-]{0,127})\s*:\s*(?:\{|$)'),
        re.compile(r'^\s*"([A-Za-z_][A-Za-z0-9_-]{0,127})"\s*:\s*\{?'),
    )
    for index, line in enumerate(lines):
        name = ""
        for pattern in patterns:
            match = pattern.match(line)
            if match:
                name = match.group(1)
                break
        if not name or not _SENSITIVE_FIELD.fullmatch(name):
            continue
        field_indent = _indent(line)
        end = len(lines)
        for candidate in range(index + 1, len(lines)):
            if lines[candidate].strip() and _indent(lines[candidate]) <= field_indent:
                end = candidate
                break
        window = "\n".join(lines[index:end])
        read_only = bool(re.search(r'(?i)(?:"readOnly"|readOnly)\s*:\s*true', window))
        results.append((name, read_only, index + 1))
    return tuple(results)


def _schema_paths(operations: Sequence[RouteOperation]) -> set[str]:
    return {operation.path for operation in operations}


def _source_routes(source: str) -> tuple[tuple[str, str], ...]:
    routes = re.findall(
        r'(?i)\b(?:app|router|server)\s*\.\s*(get|post|put|patch|delete|options|head)\s*'
        r'\(\s*["\'](/[^"\'\r\n]{1,500})["\']', source
    )
    return tuple((method.casefold(), path) for method, path in routes[:MAX_OPERATIONS])


def _normalise_version(path: str) -> str:
    return re.sub(r"(?i)(?<=/)v[0-9]+(?=/|$)", "{version}", path)


def _route_shape(path: str) -> str:
    path = re.sub(r"\{[^/{}]+\}", "{param}", path)
    return re.sub(r"(?<=/):[A-Za-z_][A-Za-z0-9_]*(?=/|$)", "{param}", path)


def analyze_openapi_schema(schema: str | bytes | bytearray | memoryview, *,
                           source: str | bytes | bytearray | memoryview = "") -> tuple[RESTFinding, ...]:
    """Return BOLA/BFLA/mass-assignment/parser/version leads from saved text."""

    schema_text = _text(schema, "OpenAPI schema", MAX_SCHEMA_CHARS)
    source_text = _text(source, "saved REST source", MAX_SOURCE_CHARS)
    operations = extract_openapi_operations(schema_text)
    findings: list[RESTFinding] = []
    schema_lines = schema_text.splitlines()
    first_path_line = next((index for index, line in enumerate(schema_lines)
                            if _PATH_LINE.match(line)), len(schema_lines))
    global_region = "\n".join(schema_lines[:first_path_line])
    global_security = bool(re.search(r'(?im)^\s*(?:"security"|security)\s*:', global_region))

    def add(finding_id: str, family: str, title: str, severity: str, confidence: str,
            evidence: Iterable[str], remediation: str) -> None:
        findings.append(RESTFinding(finding_id, family, title, severity, confidence,
                                    tuple(evidence), remediation))

    object_ops = tuple(operation for operation in operations
                       if _OBJECT_PARAM.search(operation.path)
                       and operation.method in {"get", "put", "patch", "delete"})
    if object_ops:
        empty = tuple(f"{item.method.upper()} {item.path}" for item in object_ops
                      if item.security_state == "explicit-empty")
        evidence = [f"object-keyed operations: {tuple(f'{item.method.upper()} {item.path}' for item in object_ops)!r}",
                    f"global security declaration observed: {global_security}"]
        if empty:
            evidence.append(f"operations with explicit empty security: {empty!r}")
        source_auth = bool(re.search(r"(?i)\b(?:owner|tenant|authorize|permission|policy)\b", source_text))
        if source_text:
            evidence.append(f"saved source ownership/authorization token observed: {source_auth}")
        add("openapi-object-routes", "BOLA", "Object-keyed routes require per-object authorization",
            "high" if empty else "medium", "medium" if empty else "low", evidence,
            "Authenticate and authorize subject/action/object for every object lookup; never rely on identifier secrecy.")

    by_path: dict[str, list[RouteOperation]] = {}
    for operation in operations:
        by_path.setdefault(operation.path, []).append(operation)
    method_gaps: list[str] = []
    for path, rows in by_path.items():
        states = {row.security_state for row in rows}
        if "explicit-empty" in states and len(states) > 1:
            method_gaps.append(f"{path}: {tuple((row.method, row.security_state) for row in rows)!r}")
    admin_open = tuple(f"{item.method.upper()} {item.path}" for item in operations
                       if re.search(r"(?i)(?:^|/)(?:admin|manage|internal|ops)(?:/|$)", item.path)
                       and item.security_state == "explicit-empty")
    if method_gaps or admin_open:
        add("openapi-function-security", "BFLA", "Function-level security differs across privileged operations",
            "high", "high" if admin_open else "medium",
            (f"method security gaps: {tuple(method_gaps)!r}", f"open privileged operations: {admin_open!r}"),
            "Apply deny-by-default function authorization consistently to every method and version.")

    sensitive = tuple(item for item in _sensitive_schema_fields(schema_text) if not item[1])
    body_methods = tuple(item for item in operations if item.method in {"post", "put", "patch"})
    unsafe_bind = bool(re.search(
        r"(?i)(?:Object\.assign\s*\([^,]+,\s*(?:req|request)\.body|\.update\s*\(\s*(?:req|request)\.body|"
        r"\.save\s*\(\s*(?:req|request)\.body|\{\s*\.\.\.(?:req|request)\.body)", source_text
    ))
    if sensitive and body_methods:
        add("openapi-mass-assignment", "mass-assignment",
            "Writable sensitive-looking schema fields accompany body-writing operations", "high", "medium",
            (f"fields without nearby readOnly: {sensitive!r}",
             f"body-writing operations: {tuple(f'{item.method.upper()} {item.path}' for item in body_methods)!r}",
             f"saved source whole-body binding signal: {unsafe_bind}"),
            "Allowlist writable DTO fields and derive ownership/role/status server-side.")
    if re.search(r'(?i)(?:"additionalProperties"|additionalProperties)\s*:\s*true', schema_text):
        add("openapi-additional-properties", "mass-assignment", "Schema permits unspecified object properties",
            "medium", "high", ("additionalProperties: true appears in saved schema",),
            "Reject unknown input fields for state-changing request schemas.")

    override_tokens = tuple(dict.fromkeys(re.findall(
        r"(?i)x-http-method-override|x-method-override|\b_method\b|methodOverride", schema_text + "\n" + source_text
    )))
    if override_tokens:
        add("openapi-method-override", "method-override", "Method-override support is advertised or implemented",
            "medium", "high", (f"tokens: {override_tokens!r}",),
            "Disable method override or run authorization/routing on one canonical effective method.")

    risky_content: list[str] = []
    for operation in operations:
        lowered = {value.casefold() for value in operation.content_types}
        risky = lowered.intersection({
            "application/xml", "text/xml", "application/yaml", "text/yaml",
            "application/x-www-form-urlencoded", "multipart/form-data", "text/plain",
        })
        if risky and len(lowered) > 1:
            risky_content.append(f"{operation.method.upper()} {operation.path}: {tuple(sorted(lowered))!r}")
    if risky_content:
        add("openapi-content-type-differential", "content-type",
            "Operation accepts multiple materially different body parsers", "medium", "high",
            (f"operations: {tuple(risky_content)!r}",),
            "Use one canonical media type per input schema and identical validation/authorization after parsing.")

    versions: dict[str, list[RouteOperation]] = {}
    for operation in operations:
        if re.search(r"(?i)(?:^|/)v[0-9]+(?:/|$)", operation.path):
            versions.setdefault(_normalise_version(operation.path) + " " + operation.method,
                                []).append(operation)
    version_gaps = tuple(
        f"{key}: {tuple((item.path, item.security_state, item.deprecated) for item in rows)!r}"
        for key, rows in versions.items()
        if len({item.path for item in rows}) > 1
        and len({item.security_state for item in rows}) > 1
    )
    if version_gaps:
        add("openapi-version-security", "api-versioning", "API versions expose inconsistent security metadata",
            "high", "medium", version_gaps,
            "Retire legacy versions or enforce the current authorization policy at a shared gateway/service layer.")

    pagination_gaps: list[str] = []
    for index, line in enumerate(schema_lines):
        match = re.search(r'(?i)(?:"name"\s*:\s*"|name\s*:\s*["\']?)([A-Za-z0-9_.-]+)', line)
        if not match or not _PAGINATION.fullmatch(match.group(1)):
            continue
        parameter_indent = _indent(line)
        end = len(schema_lines)
        for candidate in range(index + 1, len(schema_lines)):
            candidate_line = schema_lines[candidate]
            if candidate_line.strip() and _indent(candidate_line) <= parameter_indent:
                end = candidate
                break
        window = "\n".join(schema_lines[index:end])
        if not re.search(r'(?i)(?:"maximum"|maximum|maxValue)\s*:', window):
            pagination_gaps.append(f"{match.group(1)} near line {index + 1}")
    if pagination_gaps:
        add("openapi-pagination-bound", "pagination", "Pagination parameters lack a nearby maximum",
            "medium", "medium", (f"parameters: {tuple(pagination_gaps)!r}",),
            "Enforce a server-side maximum page size and bounded cursor/work budget.")

    documented_routes = {(operation.method, _route_shape(operation.path)) for operation in operations}
    hidden_routes = tuple(f"{method.upper()} {path}" for method, path in _source_routes(source_text)
                          if (method, _route_shape(path)) not in documented_routes)
    schema_folded = schema_text.casefold()
    source_fields = tuple(dict.fromkeys(match.group(1) for match in re.finditer(
        r'(?i)(?:body|params|query)\s*(?:\.|\[\s*["\'])([A-Za-z_][A-Za-z0-9_-]{1,127})', source_text
    )))
    hidden_sensitive = tuple(field for field in source_fields
                             if _SENSITIVE_FIELD.fullmatch(field) and field.casefold() not in schema_folded)
    if hidden_routes or hidden_sensitive:
        add("openapi-hidden-surface", "hidden-fields",
            "Saved source exposes routes or sensitive fields absent from the schema", "high", "medium",
            (f"undocumented routes: {hidden_routes!r}", f"undocumented sensitive fields: {hidden_sensitive!r}"),
            "Inventory source/gateway routes and reject undocumented input fields at runtime.")
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def _header_values(handshake, name: str) -> tuple[str, ...]:
    return handshake.values(name)


def _body_keys(body: str) -> tuple[str, ...]:
    return tuple(match.group(1) for match in re.finditer(
        r'["\']([A-Za-z_][A-Za-z0-9_.-]{0,127})["\']\s*:', body
    ))


def analyze_rest_capture(request: str | bytes | bytearray | memoryview, *,
                         response: str | bytes | bytearray | memoryview = "",
                         source: str | bytes | bytearray | memoryview = "") -> tuple[RESTFinding, ...]:
    """Analyze one saved REST request plus optional response/source text."""

    try:
        saved = parse_saved_handshake(request)
    except APIProtocolError as exc:
        raise RESTAnalysisError(str(exc)) from exc
    response_text = _text(response, "saved REST response", MAX_SCHEMA_CHARS)
    source_text = _text(source, "saved REST source", MAX_SOURCE_CHARS)
    parts = saved.start_line.split(" ")
    if len(parts) != 3:
        raise RESTAnalysisError("saved REST request line is malformed")
    method, target, _version = parts
    method = method.upper()
    if (method not in {item.upper() for item in _METHODS}
            or not (target.startswith("/") or re.match(r"(?i)^https?://", target))
            or not re.fullmatch(r"HTTP/[0-9.]+", _version, re.I)):
        raise RESTAnalysisError("saved REST request line is malformed")
    body = saved.body.decode("utf-8", "replace")
    findings: list[RESTFinding] = []

    def add(finding_id: str, family: str, title: str, severity: str, confidence: str,
            evidence: Iterable[str], remediation: str) -> None:
        findings.append(RESTFinding(finding_id, family, title, severity, confidence,
                                    tuple(evidence), remediation))

    content_types = _header_values(saved, "content-type")
    if len(content_types) > 1:
        add("rest-duplicate-content-type", "content-type", "Duplicate Content-Type fields select parsers ambiguously",
            "high", "high", (f"values: {content_types!r}",),
            "Reject duplicate content metadata before routing or parsing.")
    if content_types:
        declared = content_types[0].split(";", 1)[0].strip().casefold()
        stripped = body.lstrip()
        mismatch = ((declared == "application/json" and stripped.startswith(("<", "---")))
                    or (declared in {"application/xml", "text/xml"} and stripped.startswith(("{", "[")))
                    or (declared == "application/x-www-form-urlencoded" and stripped.startswith(("{", "[", "<"))))
        if mismatch:
            add("rest-body-parser-mismatch", "content-type", "Declared media type disagrees with saved body shape",
                "medium", "high", (f"Content-Type: {declared}", f"body prefix: {stripped[:24]!r}"),
                "Reject mismatched bodies and use one parser/validator for the declared media type.")

    override_values = _header_values(saved, "x-http-method-override") + _header_values(saved, "x-method-override")
    try:
        split_target = urlsplit(target)
    except ValueError as exc:
        raise RESTAnalysisError("saved REST request target is malformed") from exc
    if split_target.query.count("&") >= 512:
        raise RESTAnalysisError("query field count exceeds 512")
    try:
        query = tuple(parse_qsl(split_target.query, keep_blank_values=True, strict_parsing=False,
                                max_num_fields=512))
    except ValueError as exc:
        raise RESTAnalysisError("saved REST request target is malformed") from exc
    override_values += tuple(value for name, value in query if name.casefold() == "_method")
    if override_values:
        add("rest-method-override", "method-override", "Saved request supplies an effective-method override",
            "high", "high", (f"wire method: {method}", f"override values: {override_values!r}"),
            "Reject overrides or canonicalize once before routing, CSRF, and authorization checks.")

    path = split_target.path
    path_ids = tuple(segment for segment in path.split("/")
                     if re.fullmatch(r"(?:[0-9]{1,20}|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{32,})", segment))
    keys = _body_keys(body)
    authority_keys = tuple(key for key in keys if _SENSITIVE_FIELD.fullmatch(key))
    if path_ids and method in {"GET", "PUT", "PATCH", "DELETE"}:
        add("rest-object-identifier", "BOLA", "Saved request addresses an object with a client-controlled identifier",
            "medium", "low", (f"method/path: {method} {path}", f"identifier segments: {path_ids!r}"),
            "Authorize the authenticated subject for the resolved object and action.")
    if authority_keys and method in {"POST", "PUT", "PATCH"}:
        duplicates = tuple(sorted({key for key in keys if keys.count(key) > 1}))
        add("rest-sensitive-body-fields", "mass-assignment",
            "Saved state-changing body supplies authority/sensitive fields", "high", "medium",
            (f"fields: {authority_keys!r}", f"duplicate keys: {duplicates!r}"),
            "Use a duplicate-rejecting parser and allowlist writable DTO fields.")

    pagination = []
    for name, value in query:
        if _PAGINATION.fullmatch(name) and value.isdigit() and int(value) > 1000:
            pagination.append((name, value))
    if pagination:
        add("rest-pagination-bound", "pagination", "Saved request asks for an unusually large page/work unit",
            "medium", "high", (f"arguments: {tuple(pagination)!r}",),
            "Apply server-side page-size and total-work maxima.")
    if re.search(r"(?i)(?:^|/)v[0-9]+(?:/|$)", path) and re.search(
            r"(?i)(?:deprecated|legacy|sunset)", response_text + "\n" + source_text):
        add("rest-legacy-version", "api-versioning", "Versioned request intersects legacy/deprecation evidence",
            "medium", "medium", (f"path: {path!r}", "legacy/deprecation token in saved evidence"),
            "Apply current authorization at shared enforcement points and retire legacy versions.")
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def _safe_path(path: str) -> str:
    if (not isinstance(path, str) or not path.startswith("/") or len(path) > 4096
            or any(ord(char) < 33 or ord(char) > 126 for char in path)):
        raise RESTAnalysisError("path must be a bounded ASCII absolute path")
    return path


def build_rest_variants(path: str = "/api/v1/items/{id}", *, method: str = "PATCH",
                        marker: str = "R5D_INERT") -> tuple[RESTVariant, ...]:
    """Build inert saved-request strings for REST parser/authorization review."""

    path = _safe_path(path)
    method = str(method).upper()
    if method not in {item.upper() for item in _METHODS}:
        raise RESTAnalysisError("method is unsupported")
    if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", marker):
        raise RESTAnalysisError("marker must be a bounded inert token")

    def render(wire_method: str, target: str, headers: Sequence[tuple[str, str]], body: str = "") -> str:
        rows = [f"{wire_method} {target} HTTP/1.1", "Host: r5d-probe.invalid", *
                (f"{name}: {value}" for name, value in headers)]
        if body:
            rows.append(f"Content-Length: {len(body.encode('ascii'))}")
        return "\r\n".join(rows) + "\r\n\r\n" + body

    object_path = re.sub(r"\{[^{}]+\}", "R5D_OTHER_OBJECT_ID", path)
    version_path = re.sub(r"(?i)(?<=/)v[0-9]+(?=/|$)", "vR5D", path)
    mass_body = f'{{"r5d_marker":"{marker}","role":"{marker}","ownerId":"{marker}"}}'
    specs = (
        ("BOLA", "object-placeholder", render("GET", object_path, (("X-R5D-Marker", marker),)),
         "object authorization must not depend on identifier secrecy"),
        ("BFLA", "alternate-method", render("DELETE", path, (("X-R5D-Marker", marker),)),
         "function authorization must cover every routed method"),
        ("mass-assignment", "sensitive-fields", render(method, path, (("Content-Type", "application/json"),), mass_body),
         "unknown/sensitive input fields should be rejected or server-derived"),
        ("method-override", "override", render("POST", path, (("X-HTTP-Method-Override", method),
                                                               ("X-R5D-Marker", marker))),
         "wire and effective methods must share routing/authorization policy"),
        ("content-type", "text-json-shape", render(method, path, (("Content-Type", "text/plain"),), mass_body),
         "alternate body parsers must not bypass validation"),
        ("api-versioning", "version-placeholder", render(method, version_path, (("X-R5D-Marker", marker),)),
         "legacy/current versions must share authorization policy"),
        ("pagination", "bounded-placeholder", render("GET", path + ("&" if "?" in path else "?")
                                                       + "limit=R5D_BOUNDARY", (("X-R5D-Marker", marker),)),
         "server-side work limits must ignore untrusted client maxima"),
        ("hidden-fields", "unknown-field", render(method, path, (("Content-Type", "application/json"),),
                                                   f'{{"r5d_hidden":"{marker}"}}'),
         "runtime must reject undocumented request fields"),
    )
    if len(specs) > MAX_VARIANTS:
        raise RESTAnalysisError("variant count exceeds bound")
    return tuple(RESTVariant(index, family, name, request, hypothesis)
                 for index, (family, name, request, hypothesis) in enumerate(specs, 1))


__all__ = [
    "MAX_OPERATIONS", "MAX_SCHEMA_CHARS", "RESTAnalysisError", "RESTFinding", "RESTVariant",
    "RouteOperation", "analyze_openapi_schema", "analyze_rest_capture", "build_rest_variants",
    "extract_openapi_operations",
]
