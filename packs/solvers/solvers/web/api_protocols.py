#!/usr/bin/env python3
"""Offline GraphQL, gRPC-web, and WebSocket capture analysis.

This module has no transport client.  It accepts bounded saved bytes/text,
preserves duplicate metadata fields, and emits inert strings or frames for
manual reasoning.  GraphQL and WebSocket messages are inspected lexically;
gRPC-web message payloads remain opaque and are never passed to a protobuf
runtime.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import re
from typing import Iterable, Sequence


MAX_TEXT = 1_000_000
MAX_CAPTURE = 2_000_000
MAX_HEADERS = 256
MAX_FRAMES = 512
MAX_FRAME_PAYLOAD = 1_000_000
MAX_VARIANTS = 32


class APIProtocolError(ValueError):
    """Raised when an offline input is malformed or exceeds a hard bound."""


@dataclass(frozen=True)
class EvidenceFinding:
    finding_id: str
    protocol: str
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
    raw_name: str


@dataclass(frozen=True)
class SavedHandshake:
    start_line: str
    headers: tuple[HeaderField, ...]
    body: bytes
    anomalies: tuple[str, ...]

    def values(self, name: str) -> tuple[str, ...]:
        wanted = name.casefold()
        return tuple(field.value for field in self.headers
                     if field.name.casefold() == wanted)


@dataclass(frozen=True)
class InertVariant:
    rank: int
    protocol: str
    name: str
    value: str
    hypothesis: str
    offline: bool = True
    network_requests: int = 0


@dataclass(frozen=True)
class GRPCTrailer:
    name: str
    value: str
    line_number: int


@dataclass(frozen=True)
class GRPCWebFrame:
    index: int
    kind: str
    flags: int
    declared_length: int
    payload_length: int
    complete: bool
    payload_sha256: str
    ascii_preview: str
    trailers: tuple[GRPCTrailer, ...]


@dataclass(frozen=True)
class WebSocketFrame:
    index: int
    fin: bool
    rsv_bits: int
    opcode: int
    masked: bool
    declared_length: int
    complete: bool
    payload: bytes
    payload_sha256: str


_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_GRAPHQL_NAME = re.compile(r"^[_A-Za-z][_0-9A-Za-z]{0,127}$")


def _bounded_bytes(raw: str | bytes | bytearray | memoryview, label: str,
                   *, maximum: int = MAX_CAPTURE) -> bytes:
    if isinstance(raw, str):
        data = raw.encode("utf-8")
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
    else:
        raise APIProtocolError(f"{label} must be text or bytes")
    if len(data) > maximum:
        raise APIProtocolError(f"{label} exceeds {maximum} bytes")
    return data


def _bounded_text(raw: str | bytes | bytearray | memoryview, label: str) -> str:
    data = _bounded_bytes(raw, label, maximum=MAX_TEXT)
    if b"\x00" in data:
        raise APIProtocolError(f"{label} contains NUL")
    return data.decode("utf-8", "replace")


def _header_pairs(headers: Sequence[tuple[str, str]] | None) -> tuple[tuple[str, str], ...]:
    if headers is None:
        return ()
    if not isinstance(headers, Sequence) or isinstance(headers, (str, bytes, bytearray)):
        raise APIProtocolError("headers must be a bounded sequence of pairs")
    if len(headers) > MAX_HEADERS:
        raise APIProtocolError(f"header count exceeds {MAX_HEADERS}")
    result: list[tuple[str, str]] = []
    for item in headers:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise APIProtocolError("each header must be a name/value pair")
        name, value = item
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
            raise APIProtocolError("header name is not an HTTP token")
        if not isinstance(value, str) or len(value) > 8192 or any(ch in value for ch in "\r\n\x00"):
            raise APIProtocolError(f"header {name!r} has an unsafe value")
        result.append((name, value))
    return tuple(result)


def parse_saved_handshake(raw: str | bytes | bytearray | memoryview) -> SavedHandshake:
    """Parse a saved HTTP-style handshake without merging duplicate fields."""

    data = _bounded_bytes(raw, "saved handshake")
    if not data:
        raise APIProtocolError("saved handshake is empty")
    if b"\x00" in data:
        raise APIProtocolError("saved handshake contains NUL")
    anomalies: list[str] = []
    boundary = data.find(b"\r\n\r\n")
    separator = b"\r\n\r\n"
    if boundary < 0:
        boundary = data.find(b"\n\n")
        separator = b"\n\n"
        anomalies.append("LF-only or missing canonical handshake framing")
    if boundary < 0:
        head, body = data, b""
        anomalies.append("missing handshake header terminator")
    else:
        head, body = data[:boundary], data[boundary + len(separator):]
    if len(head) > 64 * 1024:
        raise APIProtocolError("handshake header block exceeds 65536 bytes")
    has_crlf = b"\r\n" in head
    has_bare_lf = b"\n" in head.replace(b"\r\n", b"")
    if has_crlf and has_bare_lf:
        anomalies.append("mixed CRLF and LF handshake line endings")
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    if not lines or not lines[0]:
        raise APIProtocolError("handshake start line is missing")
    start_line = lines[0].decode("latin-1")
    fields: list[HeaderField] = []
    for number, raw_line in enumerate(lines[1:], 2):
        if len(fields) >= MAX_HEADERS:
            raise APIProtocolError(f"header count exceeds {MAX_HEADERS}")
        if raw_line.startswith((b" ", b"\t")):
            anomalies.append(f"obsolete folded header at line {number}")
            continue
        if b":" not in raw_line:
            anomalies.append(f"header line {number} has no colon")
            continue
        name_b, value_b = raw_line.split(b":", 1)
        raw_name = name_b.decode("latin-1")
        name = raw_name.strip(" \t")
        value = value_b.decode("latin-1").strip(" \t")
        if not _HEADER_NAME.fullmatch(name):
            anomalies.append(f"header line {number} has a non-token name")
        if raw_name != name:
            anomalies.append(f"header line {number} has name-adjacent whitespace")
        if any(ord(ch) < 32 and ch != "\t" for ch in value):
            anomalies.append(f"header line {number} contains a control character")
        fields.append(HeaderField(name, value, number, raw_name))
    return SavedHandshake(start_line, tuple(fields), body, tuple(dict.fromkeys(anomalies)))


# ---------------------------------------------------------------------------
# GraphQL lexical analysis and inert documents


def _mask_graphql_literals(text: str) -> str:
    """Mask comments and quoted strings while retaining braces/newlines."""

    chars = list(text)
    index = 0
    state = "code"
    while index < len(chars):
        if state == "code":
            if text.startswith('"""', index):
                chars[index:index + 3] = "   "
                index += 3
                state = "block-string"
                continue
            if chars[index] == '"':
                chars[index] = " "
                index += 1
                state = "string"
                continue
            if chars[index] == "#":
                chars[index] = " "
                index += 1
                state = "comment"
                continue
            index += 1
            continue
        if state == "comment":
            if chars[index] in "\r\n":
                state = "code"
            else:
                chars[index] = " "
            index += 1
            continue
        if state == "string":
            if chars[index] == "\\":
                chars[index] = " "
                if index + 1 < len(chars):
                    chars[index + 1] = " "
                index += 2
                continue
            if chars[index] == '"':
                chars[index] = " "
                state = "code"
            elif chars[index] not in "\r\n":
                chars[index] = " "
            index += 1
            continue
        if text.startswith('"""', index):
            chars[index:index + 3] = "   "
            index += 3
            state = "code"
        else:
            if chars[index] not in "\r\n":
                chars[index] = " "
            index += 1
    return "".join(chars)


def _brace_depth(masked: str) -> tuple[int, bool]:
    depth = 0
    maximum = 0
    balanced = True
    for char in masked:
        if char == "{":
            depth += 1
            maximum = max(maximum, depth)
        elif char == "}":
            depth -= 1
            if depth < 0:
                balanced = False
                depth = 0
    return maximum, balanced and depth == 0


def _mask_parenthesized(masked: str) -> str:
    """Mask argument/directive regions for selection-alias counting."""

    chars = list(masked)
    depth = 0
    for index, char in enumerate(masked):
        if char == "(":
            depth += 1
            chars[index] = " "
        elif char == ")":
            chars[index] = " "
            depth = max(0, depth - 1)
        elif depth:
            chars[index] = "\n" if char == "\n" else " "
    return "".join(chars)


def analyze_graphql_document(document: str | bytes | bytearray | memoryview, *,
                             method: str = "POST",
                             headers: Sequence[tuple[str, str]] | None = None) -> tuple[EvidenceFinding, ...]:
    """Return bounded lexical GraphQL abuse leads without parsing a schema."""

    text = _bounded_text(document, "GraphQL document")
    method = str(method).upper()
    if not re.fullmatch(r"[A-Z]{1,16}", method):
        raise APIProtocolError("method must be an ASCII HTTP token")
    pairs = _header_pairs(headers)
    masked = _mask_graphql_literals(text)
    selection_view = _mask_parenthesized(masked)
    folded = masked.casefold()
    depth, balanced = _brace_depth(masked)
    aliases = re.findall(
        r"\b([_A-Za-z][_0-9A-Za-z]*)\s*:\s*([_A-Za-z][_0-9A-Za-z]*)",
        selection_view,
    )
    operations = re.findall(r"(?i)\b(query|mutation|subscription)\b", masked)
    selections = re.findall(r"(?m)(?<![$@])\b[_A-Za-z][_0-9A-Za-z]*\b\s*(?:\([^{}]*\))?\s*(?=[{@\n\r,}])", masked)
    findings: list[EvidenceFinding] = []

    def add(finding_id: str, title: str, severity: str, confidence: str,
            evidence: Iterable[str], remediation: str) -> None:
        findings.append(EvidenceFinding(finding_id, "graphql", title, severity, confidence,
                                        tuple(evidence), remediation))

    if not balanced:
        add("graphql-unbalanced", "GraphQL selection braces are unbalanced", "low", "high",
            (f"maximum observed depth: {depth}",),
            "Verify the saved capture is complete before drawing security conclusions.")
    if "__schema" in masked or "__type" in masked:
        add("graphql-introspection", "Schema introspection fields appear in saved input", "low", "high",
            tuple(name for name in ("__schema", "__type") if name in masked),
            "Gate introspection according to challenge/application policy; do not rely on obscurity for authorization.")
    if len(aliases) >= 8:
        add("graphql-alias-amplification", "Many aliases can multiply resolver work", "medium", "high",
            (f"alias count: {len(aliases)}", f"sample: {tuple(aliases[:8])!r}"),
            "Apply query cost limits after alias and fragment expansion.")
    if depth >= 8:
        add("graphql-depth", "Deep selection nesting can amplify resolver work", "medium", "high",
            (f"maximum selection depth: {depth}",),
            "Enforce depth and cost budgets using the expanded operation tree.")
    if len(selections) >= 100:
        add("graphql-selection-volume", "Large selection set observed", "medium", "medium",
            (f"approximate lexical selections: {len(selections)}",),
            "Use schema-aware field-cost accounting and a hard request budget.")
    if "mutation" in folded and method == "GET":
        add("graphql-get-mutation", "Mutation appears in a GET capture", "high", "high",
            ("HTTP method: GET", "mutation token present outside strings/comments"),
            "Reject mutations over safe/idempotent methods and enforce CSRF defenses.")
    large_page = tuple((name, value) for name, value in re.findall(
        r"(?i)\b(first|last|limit|pageSize|take)\s*:\s*([0-9]{1,20})", masked
    ) if int(value) > 1000)
    if large_page:
        add("graphql-pagination-limit", "Large GraphQL pagination arguments observed", "medium", "high",
            (f"arguments: {large_page!r}",),
            "Apply server-side maxima independent of client pagination arguments.")
    batch_count = len(re.findall(r'(?i)"query"\s*:', text))
    if text.lstrip().startswith("[") and batch_count > 1:
        add("graphql-batching", "Lexical GraphQL batch contains multiple operations", "medium", "medium",
            (f"query members: {batch_count}",),
            "Bound batch members and charge aggregate cost before execution.")
    content_types = tuple(value.casefold() for name, value in pairs if name.casefold() == "content-type")
    if len(content_types) > 1:
        add("graphql-duplicate-content-type", "Duplicate Content-Type fields accompany GraphQL input",
            "medium", "high", (f"values: {content_types!r}",),
            "Reject duplicate content metadata before choosing a body parser.")
    if len(operations) > 1:
        add("graphql-multiple-operations", "Several operation declarations share one document", "low", "high",
            (f"operation declarations: {tuple(operations)!r}",),
            "Require an unambiguous operationName and apply authorization/cost checks to the selected operation.")
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def _graphql_name(value: str, label: str) -> str:
    if not isinstance(value, str) or not _GRAPHQL_NAME.fullmatch(value):
        raise APIProtocolError(f"{label} must be a GraphQL name")
    return value


def build_graphql_variants(*, root_field: str = "node", id_argument: str = "id",
                           marker: str = "R5D_INERT") -> tuple[InertVariant, ...]:
    """Build a small inert GraphQL complexity/normalisation matrix."""

    root_field = _graphql_name(root_field, "root_field")
    id_argument = _graphql_name(id_argument, "id_argument")
    if (not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", marker)):
        raise APIProtocolError("marker must be a bounded inert token")
    leaf = f'{root_field}({id_argument}: "{marker}") {{ __typename }}'
    specs = (
        ("typename-control", "query R5DControl { __typename }",
         "minimal control operation for comparing saved handling"),
        ("alias-fanout", "query R5DAliases { " + " ".join(
            f"r5d{index}: {leaf}" for index in range(1, 5)) + " }",
         "aliases expose whether cost accounting expands repeated resolvers"),
        ("fragment-reuse", f"query R5DFragments {{ a: {root_field}({id_argument}: \"{marker}\") "
         "{ ...R5DFields } } fragment R5DFields on Node { __typename }",
         "fragment expansion may differ from lexical field counting"),
        ("multi-operation", "query R5DOne { __typename } query R5DTwo { __typename }",
         "operationName selection must be unambiguous"),
        ("lexical-batch", '[{"query":"query R5DOne { __typename }"},'
         '{"query":"query R5DTwo { __typename }"}]',
         "batch limits must charge aggregate operation cost"),
    )
    return tuple(InertVariant(index, "graphql", name, value, hypothesis)
                 for index, (name, value, hypothesis) in enumerate(specs, 1))


# ---------------------------------------------------------------------------
# gRPC-web framing (opaque messages; no protobuf runtime)


def _grpc_trailers(payload: bytes) -> tuple[GRPCTrailer, ...]:
    text = payload.decode("latin-1")
    rows: list[GRPCTrailer] = []
    for number, line in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        if not line:
            continue
        if ":" not in line:
            rows.append(GRPCTrailer("<malformed>", line[:4096], number))
            continue
        name, value = line.split(":", 1)
        canonical = name.strip()
        if not _HEADER_NAME.fullmatch(canonical) or canonical != canonical.casefold():
            rows.append(GRPCTrailer("<malformed>", line[:4096], number))
        else:
            rows.append(GRPCTrailer(canonical, value.strip()[:4096], number))
        if len(rows) >= MAX_HEADERS:
            break
    return tuple(rows)


def parse_grpc_web_frames(raw: str | bytes | bytearray | memoryview, *,
                          text_mode: bool = False) -> tuple[GRPCWebFrame, ...]:
    """Parse gRPC-web envelopes while leaving protobuf message bytes opaque."""

    data = _bounded_bytes(raw, "gRPC-web capture")
    if text_mode:
        compact = re.sub(rb"[\t\r\n ]+", b"", data)
        try:
            data = base64.b64decode(compact, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise APIProtocolError("gRPC-web-text capture is not canonical base64") from exc
        if len(data) > MAX_CAPTURE:
            raise APIProtocolError("decoded gRPC-web-text capture exceeds bound")
    frames: list[GRPCWebFrame] = []
    cursor = 0
    while cursor < len(data):
        if len(frames) >= MAX_FRAMES:
            raise APIProtocolError(f"gRPC-web frame count exceeds {MAX_FRAMES}")
        index = len(frames) + 1
        remaining = len(data) - cursor
        if remaining < 5:
            payload = data[cursor:]
            frames.append(GRPCWebFrame(
                index, "malformed", payload[0] if payload else 0, -1, len(payload), False,
                hashlib.sha256(payload).hexdigest(), payload.decode("ascii", "replace")[:80], (),
            ))
            break
        flags = data[cursor]
        declared = int.from_bytes(data[cursor + 1:cursor + 5], "big")
        cursor += 5
        available = len(data) - cursor
        take = min(declared, available, MAX_FRAME_PAYLOAD)
        payload = data[cursor:cursor + take]
        complete = declared <= available and declared <= MAX_FRAME_PAYLOAD
        kind = "trailers" if flags & 0x80 else "data"
        trailers = _grpc_trailers(payload) if kind == "trailers" and complete else ()
        frames.append(GRPCWebFrame(
            index, kind, flags, declared, len(payload), complete,
            hashlib.sha256(payload).hexdigest(), payload.decode("ascii", "replace")[:80], trailers,
        ))
        if not complete:
            break
        cursor += declared
    return tuple(frames)


def analyze_grpc_web_capture(raw: str | bytes | bytearray | memoryview, *,
                             text_mode: bool = False,
                             headers: Sequence[tuple[str, str]] | None = None) -> tuple[EvidenceFinding, ...]:
    """Analyze saved gRPC-web envelope and trailer consistency."""

    frames = parse_grpc_web_frames(raw, text_mode=text_mode)
    pairs = _header_pairs(headers)
    findings: list[EvidenceFinding] = []

    def add(finding_id: str, title: str, severity: str, confidence: str,
            evidence: Iterable[str], remediation: str) -> None:
        findings.append(EvidenceFinding(finding_id, "grpc-web", title, severity, confidence,
                                        tuple(evidence), remediation))

    content_types = tuple(value for name, value in pairs if name.casefold() == "content-type")
    if len(content_types) > 1:
        add("grpc-duplicate-content-type", "Duplicate gRPC-web Content-Type fields", "medium", "high",
            (f"values: {content_types!r}",), "Reject duplicate parser-selection metadata.")
    elif content_types and "grpc-web" not in content_types[0].casefold():
        add("grpc-content-type", "Saved envelope has a non-gRPC-web Content-Type", "low", "high",
            (f"Content-Type: {content_types[0]!r}",),
            "Verify capture boundaries and enforce the expected media type before framing.")
    encodings = tuple(value for name, value in pairs if name.casefold() == "grpc-encoding")
    trailer_seen = False
    statuses: list[str] = []
    for frame in frames:
        if not frame.complete:
            add("grpc-truncated-frame", "gRPC-web frame is truncated or over the payload cap", "medium", "high",
                (f"frame {frame.index}", f"declared {frame.declared_length}",
                 f"captured {frame.payload_length}"),
                "Reject incomplete envelopes before application decoding.")
        if frame.flags & ~0x81:
            add("grpc-reserved-flags", "gRPC-web frame uses reserved flag bits", "medium", "high",
                (f"frame {frame.index} flags: 0x{frame.flags:02x}",),
                "Accept only the data/trailer and compression bits defined by the framing profile.")
        if frame.flags & 0x01 and not encodings:
            add("grpc-compression-without-encoding", "Compressed frame lacks grpc-encoding metadata",
                "medium", "high", (f"frame {frame.index} flags: 0x{frame.flags:02x}",),
                "Require one supported grpc-encoding before decompressing; apply post-decompression limits.")
        if trailer_seen and frame.kind == "data":
            add("grpc-data-after-trailers", "Data frame follows a trailer frame", "high", "high",
                (f"frame {frame.index} is data after trailers",),
                "Treat trailers as terminal and reject subsequent message frames.")
        if frame.kind == "trailers":
            trailer_seen = True
            statuses.extend(item.value for item in frame.trailers if item.name == "grpc-status")
            malformed = tuple(item.value for item in frame.trailers if item.name == "<malformed>")
            if malformed:
                add("grpc-malformed-trailers", "Malformed gRPC-web trailer lines are preserved", "medium", "high",
                    (f"frame {frame.index}: {malformed!r}",),
                    "Reject trailer blocks that are not canonical name/value fields.")
    if frames and trailer_seen and not statuses:
        add("grpc-missing-status", "Trailer block omits grpc-status", "medium", "high",
            ("at least one trailer frame was captured",),
            "Require exactly one valid grpc-status field in terminal metadata.")
    if len(statuses) > 1:
        add("grpc-duplicate-status", "Duplicate grpc-status trailers are ambiguous", "high", "high",
            (f"values: {tuple(statuses)!r}",),
            "Require exactly one decimal grpc-status and reject duplicates.")
    invalid_status = tuple(value for value in statuses if not re.fullmatch(r"[0-9]+", value))
    if invalid_status:
        add("grpc-invalid-status", "Non-decimal grpc-status value", "medium", "high",
            (f"values: {invalid_status!r}",), "Validate terminal status before exposing it to application logic.")
    return tuple(sorted(findings, key=lambda item: (item.finding_id, item.evidence)))


def build_grpc_web_frame(payload: str | bytes | bytearray | memoryview, *,
                         trailers: bool = False, compressed: bool = False) -> bytes:
    """Build one deterministic inert gRPC-web envelope; no protobuf encoding."""

    data = _bounded_bytes(payload, "gRPC-web payload", maximum=MAX_FRAME_PAYLOAD)
    flags = (0x80 if trailers else 0) | (0x01 if compressed else 0)
    return bytes((flags,)) + len(data).to_bytes(4, "big") + data


def build_grpc_web_trailers(fields: Sequence[tuple[str, str]]) -> bytes:
    """Build a trailer envelope while preserving caller-supplied duplicates."""

    pairs = _header_pairs(fields)
    try:
        body = "".join(f"{name.casefold()}: {value}\r\n" for name, value in pairs).encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise APIProtocolError("gRPC-web trailer metadata must be ASCII") from exc
    return build_grpc_web_frame(body, trailers=True)


def build_grpc_web_variants(marker: str = "R5D_INERT") -> tuple[InertVariant, ...]:
    if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", marker):
        raise APIProtocolError("marker must be a bounded inert token")
    data = build_grpc_web_frame(marker.encode("ascii"))
    trailers = build_grpc_web_trailers((
        ("grpc-status", "0"), ("x-r5d-marker", marker),
    ))
    duplicate = build_grpc_web_trailers((("grpc-status", "0"), ("grpc-status", "7")))
    specs = (
        ("binary-control", base64.b64encode(data + trailers).decode("ascii"),
         "base64 is display-only; decoded bytes contain one opaque marker and terminal trailers"),
        ("text-control", base64.b64encode(data + trailers).decode("ascii"),
         "canonical grpc-web-text representation for saved-parser comparison"),
        ("duplicate-status", base64.b64encode(data + duplicate).decode("ascii"),
         "duplicate status fields expose first/last metadata selection"),
    )
    return tuple(InertVariant(index, "grpc-web", name, value, hypothesis)
                 for index, (name, value, hypothesis) in enumerate(specs, 1))


# ---------------------------------------------------------------------------
# WebSocket handshake and saved frame analysis


def analyze_websocket_handshake(raw: str | bytes | bytearray | memoryview, *,
                                expected_origin: str | None = None,
                                source: str | bytes | bytearray | memoryview = "") -> tuple[EvidenceFinding, ...]:
    handshake = parse_saved_handshake(raw)
    source_text = _bounded_text(source, "saved WebSocket source").casefold()
    findings: list[EvidenceFinding] = []

    def add(finding_id: str, title: str, severity: str, confidence: str,
            evidence: Iterable[str], remediation: str) -> None:
        findings.append(EvidenceFinding(finding_id, "websocket", title, severity, confidence,
                                        tuple(evidence), remediation))

    parts = handshake.start_line.split(" ")
    if len(parts) != 3 or parts[0].upper() != "GET":
        add("ws-handshake-method", "Handshake start line is not canonical GET", "medium", "high",
            (f"start line: {handshake.start_line!r}",),
            "Require a canonical HTTP/1.1 GET upgrade request.")
    upgrade = handshake.values("upgrade")
    connection = handshake.values("connection")
    if len(upgrade) != 1 or upgrade[0].casefold() != "websocket":
        add("ws-upgrade-field", "Upgrade metadata is missing, duplicated, or non-canonical", "medium", "high",
            (f"Upgrade values: {upgrade!r}",), "Require exactly one Upgrade: websocket field.")
    if not connection or not any("upgrade" in {token.strip().casefold() for token in value.split(",")}
                                 for value in connection):
        add("ws-connection-field", "Connection metadata does not nominate Upgrade", "medium", "high",
            (f"Connection values: {connection!r}",), "Require an unambiguous Connection: Upgrade token.")
    keys = handshake.values("sec-websocket-key")
    valid_key = False
    if len(keys) == 1:
        try:
            valid_key = len(base64.b64decode(keys[0], validate=True)) == 16
        except (ValueError, base64.binascii.Error):
            valid_key = False
    if len(keys) != 1 or not valid_key:
        add("ws-key", "Sec-WebSocket-Key is missing, duplicated, or malformed", "medium", "high",
            (f"key field count: {len(keys)}",), "Require one canonical base64 value decoding to 16 bytes.")
    versions = handshake.values("sec-websocket-version")
    if versions != ("13",):
        add("ws-version", "WebSocket version metadata is not exactly 13", "low", "high",
            (f"values: {versions!r}",), "Accept exactly one supported version field.")
    origins = handshake.values("origin")
    authenticated = bool(handshake.values("cookie") or handshake.values("authorization"))
    origin_check_in_source = bool(re.search(r"\borigin\b.{0,100}(?:allow|check|valid|equal|match)", source_text))
    if authenticated and (not origins or origins == ("null",)):
        add("ws-cswsh-origin", "Authenticated handshake lacks a concrete Origin", "high", "medium",
            (f"Origin values: {origins!r}", "Cookie/Authorization metadata is present",
             f"saved source origin-check signal: {origin_check_in_source}"),
            "Validate an explicit allowlisted Origin before accepting authenticated upgrades.")
    if len(origins) > 1:
        add("ws-duplicate-origin", "Duplicate Origin fields are ambiguous", "high", "high",
            (f"Origin values: {origins!r}",),
            "Require exactly one canonical Origin and compare it with an allowlist.")
    if expected_origin is not None:
        if (not isinstance(expected_origin, str) or len(expected_origin) > 2048
                or any(ch in expected_origin for ch in "\r\n\x00")):
            raise APIProtocolError("expected_origin is invalid")
        if origins and any(value.casefold() != expected_origin.casefold() for value in origins):
            add("ws-origin-mismatch", "Saved Origin differs from the expected origin", "high", "high",
                (f"expected: {expected_origin!r}", f"observed: {origins!r}"),
                "Compare parsed scheme/host/port against an exact allowlist.")
    protocols = handshake.values("sec-websocket-protocol")
    offered = tuple(token.strip() for value in protocols for token in value.split(",") if token.strip())
    if len(offered) != len(set(item.casefold() for item in offered)):
        add("ws-duplicate-subprotocol", "Duplicate WebSocket subprotocol tokens are ambiguous", "medium", "high",
            (f"tokens: {offered!r}",), "Reject duplicate tokens and authorize the one selected protocol.")
    extensions = ",".join(handshake.values("sec-websocket-extensions")).casefold()
    if "permessage-deflate" in extensions and "server_no_context_takeover" not in extensions:
        add("ws-compression-context", "permessage-deflate may retain server compression context", "low", "high",
            (f"extensions: {extensions!r}",),
            "Disable compression for secrets or require no-context-takeover and strict size limits.")
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def parse_websocket_frames(raw: str | bytes | bytearray | memoryview) -> tuple[WebSocketFrame, ...]:
    """Parse saved RFC 6455 frames and unmask payload bytes locally."""

    data = _bounded_bytes(raw, "WebSocket frame capture")
    frames: list[WebSocketFrame] = []
    cursor = 0
    while cursor < len(data):
        if len(frames) >= MAX_FRAMES:
            raise APIProtocolError(f"WebSocket frame count exceeds {MAX_FRAMES}")
        start = cursor
        if len(data) - cursor < 2:
            payload = data[cursor:]
            frames.append(WebSocketFrame(len(frames) + 1, False, 0, -1, False, -1, False,
                                         payload, hashlib.sha256(payload).hexdigest()))
            break
        first, second = data[cursor], data[cursor + 1]
        cursor += 2
        fin = bool(first & 0x80)
        rsv = (first >> 4) & 0x07
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length_code = second & 0x7F
        ext = 2 if length_code == 126 else (8 if length_code == 127 else 0)
        if len(data) - cursor < ext:
            payload = data[start:]
            frames.append(WebSocketFrame(len(frames) + 1, fin, rsv, opcode, masked, -1, False,
                                         payload, hashlib.sha256(payload).hexdigest()))
            break
        declared = (int.from_bytes(data[cursor:cursor + ext], "big") if ext
                    else length_code)
        cursor += ext
        mask_key = b""
        if masked:
            if len(data) - cursor < 4:
                payload = data[start:]
                frames.append(WebSocketFrame(len(frames) + 1, fin, rsv, opcode, masked, declared, False,
                                             payload, hashlib.sha256(payload).hexdigest()))
                break
            mask_key = data[cursor:cursor + 4]
            cursor += 4
        available = len(data) - cursor
        take = min(declared, available, MAX_FRAME_PAYLOAD)
        payload = data[cursor:cursor + take]
        if masked:
            payload = bytes(value ^ mask_key[index % 4] for index, value in enumerate(payload))
        complete = declared <= available and declared <= MAX_FRAME_PAYLOAD
        frames.append(WebSocketFrame(len(frames) + 1, fin, rsv, opcode, masked, declared, complete,
                                     payload, hashlib.sha256(payload).hexdigest()))
        if not complete:
            break
        cursor += declared
    return tuple(frames)


def _json_like_key_records(text: str) -> tuple[tuple[int, str], ...]:
    """Lexically collect object-scoped JSON-like keys without deserializing."""

    records: list[tuple[int, str]] = []
    object_stack: list[int] = []
    next_scope = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char == "{":
            next_scope += 1
            object_stack.append(next_scope)
            index += 1
            continue
        if char == "}":
            if object_stack:
                object_stack.pop()
            index += 1
            continue
        if char != '"':
            index += 1
            continue
        index += 1
        value: list[str] = []
        valid = True
        while index < len(text):
            if text[index] == "\\":
                if index + 1 >= len(text):
                    valid = False
                    index += 1
                    break
                value.append(text[index:index + 2])
                index += 2
                continue
            if text[index] == '"':
                break
            value.append(text[index])
            index += 1
        if index >= len(text) or text[index] != '"':
            break
        index += 1
        cursor = index
        while cursor < len(text) and text[cursor] in " \t\r\n":
            cursor += 1
        key = "".join(value)
        if (valid and object_stack and cursor < len(text) and text[cursor] == ":"
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", key)):
            records.append((object_stack[-1], key))
    return tuple(records)


def analyze_websocket_frames(raw: str | bytes | bytearray | memoryview, *,
                             direction: str = "client",
                             extensions: Sequence[str] = (),
                             source: str | bytes | bytearray | memoryview = "") -> tuple[EvidenceFinding, ...]:
    """Analyze saved frames and message text; never open a WebSocket."""

    if direction not in {"client", "server"}:
        raise APIProtocolError("direction must be 'client' or 'server'")
    if len(extensions) > 32 or any(not isinstance(item, str) or len(item) > 256 for item in extensions):
        raise APIProtocolError("extensions must be a bounded sequence of text values")
    extension_text = ",".join(extensions).casefold()
    source_text = _bounded_text(source, "saved WebSocket source").casefold()
    frames = parse_websocket_frames(raw)
    findings: list[EvidenceFinding] = []
    fragmented = False
    fragment_opcode: int | None = None
    fragment_payload = bytearray()
    fragment_compressed = False

    def add(finding_id: str, title: str, severity: str, confidence: str,
            evidence: Iterable[str], remediation: str) -> None:
        findings.append(EvidenceFinding(finding_id, "websocket", title, severity, confidence,
                                        tuple(evidence), remediation))

    def inspect_text_message(payload: bytes, prefix: str) -> None:
        try:
            text = payload.decode("utf-8", "strict")
        except UnicodeDecodeError:
            add("ws-invalid-text", "Text message payload is not valid UTF-8", "medium", "high", (prefix,),
                "Validate complete reassembled text messages as UTF-8 before parsing.")
            return
        records = _json_like_key_records(text)
        keys = tuple(key for _scope, key in records)
        counts: dict[tuple[int, str], int] = {}
        for scope, key in records:
            counts[(scope, key)] = counts.get((scope, key), 0) + 1
        duplicates = tuple(sorted({key for (_scope, key), count in counts.items() if count > 1}))
        if duplicates:
            add("ws-duplicate-message-keys", "Duplicate JSON-like message keys are ambiguous", "high", "high",
                (prefix, f"same-object duplicate keys: {duplicates!r}"),
                "Use a duplicate-rejecting parser and one canonical message schema.")
        authority_keys = tuple(dict.fromkeys(key for key in keys if key.casefold() in {
            "role", "userid", "accountid", "ownerid", "isadmin", "permissions", "tenantid",
        }))
        if authority_keys:
            source_signal = any(key.casefold() in source_text for key in authority_keys)
            add("ws-client-authority-fields", "Client message supplies identity/authority fields", "high", "medium",
                (prefix, f"fields: {authority_keys!r}", f"saved source references fields: {source_signal}"),
                "Derive identity and authorization server-side for every message action.")
        if re.search(r'(?i)"(?:action|method|type)"\s*:\s*"[^"\r\n]*(?:delete|transfer|approve|admin|update)', text):
            add("ws-state-changing-message", "Saved message lexically requests a privileged/state-changing action",
                "medium", "medium", (prefix,),
                "Authorize each message action independently of handshake success and client-supplied role fields.")
        if "__schema" in text or re.search(r"(?i)\bmutation\b", text):
            add("ws-graphql-operation", "GraphQL-over-WebSocket message contains mutation/introspection tokens",
                "medium", "medium", (prefix,),
                "Apply the same GraphQL authorization and cost policy to subscription transport messages.")

    for frame in frames:
        prefix = f"frame {frame.index}"
        if not frame.complete:
            add("ws-truncated-frame", "WebSocket frame is truncated or over the payload cap", "medium", "high",
                (prefix, f"declared {frame.declared_length}", f"captured {len(frame.payload)}"),
                "Reject incomplete frames before message dispatch.")
        if direction == "client" and not frame.masked:
            add("ws-client-unmasked", "Saved client frame is not masked", "medium", "high", (prefix,),
                "Reject unmasked client-to-server frames.")
        if direction == "server" and frame.masked:
            add("ws-server-masked", "Saved server frame is unexpectedly masked", "low", "high", (prefix,),
                "Reject masked server-to-client frames or verify capture direction.")
        compression_negotiated = "permessage-deflate" in extension_text
        allowed_rsv = 4 if compression_negotiated and frame.opcode in {1, 2} else 0
        if frame.rsv_bits & ~allowed_rsv:
            add("ws-rsv-without-extension", "RSV bits are set without a negotiated extension", "medium", "high",
                (prefix, f"RSV bits: {frame.rsv_bits:03b}"), "Reject extension bits not negotiated by the handshake.")
        if frame.opcode not in {0, 1, 2, 8, 9, 10}:
            add("ws-reserved-opcode", "Reserved WebSocket opcode observed", "medium", "high",
                (prefix, f"opcode: {frame.opcode}"), "Reject reserved opcodes before application dispatch.")
        if frame.opcode >= 8 and (not frame.fin or frame.declared_length > 125):
            add("ws-control-framing", "Control frame is fragmented or oversized", "medium", "high",
                (prefix, f"FIN: {frame.fin}", f"length: {frame.declared_length}"),
                "Require FIN and payload length <=125 for control frames.")
        if frame.opcode == 8 and frame.declared_length == 1:
            add("ws-close-length", "Close frame has an invalid one-byte payload", "low", "high", (prefix,),
                "Require an empty close body or at least a two-byte status code.")
        if not frame.complete:
            continue
        message_opcode: int | None = None
        message_payload: bytes | None = None
        message_compressed = False
        if frame.opcode == 0:
            if not fragmented:
                add("ws-orphan-continuation", "Continuation frame has no open fragmented message", "medium", "high",
                    (prefix,), "Track fragmentation state and reject orphan continuation frames.")
            elif len(fragment_payload) + len(frame.payload) > MAX_FRAME_PAYLOAD:
                add("ws-reassembled-size", "Fragmented message exceeds the reassembly cap", "medium", "high",
                    (prefix, f"cap: {MAX_FRAME_PAYLOAD}"),
                    "Apply a total message-size limit across all fragments.")
                fragmented = False
                fragment_opcode = None
                fragment_payload.clear()
            else:
                fragment_payload.extend(frame.payload)
                if frame.fin:
                    message_opcode = fragment_opcode
                    message_payload = bytes(fragment_payload)
                    message_compressed = fragment_compressed
                    fragmented = False
                    fragment_opcode = None
                    fragment_payload.clear()
        elif frame.opcode in {1, 2}:
            if fragmented:
                add("ws-interleaved-message", "New data message begins before prior fragments finish", "medium", "high",
                    (prefix,), "Permit only continuation frames until a fragmented message completes.")
                fragment_payload.clear()
            if frame.fin:
                fragmented = False
                fragment_opcode = None
                message_opcode = frame.opcode
                message_payload = frame.payload
                message_compressed = bool(frame.rsv_bits & 4 and compression_negotiated)
            else:
                fragmented = True
                fragment_opcode = frame.opcode
                fragment_payload = bytearray(frame.payload)
                fragment_compressed = bool(frame.rsv_bits & 4 and compression_negotiated)
        if message_opcode == 1 and message_payload is not None and not message_compressed:
            inspect_text_message(message_payload, prefix)
    if fragmented:
        add("ws-incomplete-message", "Capture ends with an unfinished fragmented message", "low", "high",
            (f"captured fragment bytes: {len(fragment_payload)}",),
            "Verify capture completeness and bound fragment count/total size.")
    return tuple(sorted(findings, key=lambda item: (item.finding_id, item.evidence)))


def build_websocket_frame(payload: str | bytes | bytearray | memoryview, *,
                          opcode: int = 1, fin: bool = True, masked: bool = True,
                          mask_key: bytes = b"R5D!") -> bytes:
    """Build one deterministic inert RFC 6455 frame."""

    data = _bounded_bytes(payload, "WebSocket payload", maximum=MAX_FRAME_PAYLOAD)
    if not isinstance(opcode, int) or opcode not in {0, 1, 2, 8, 9, 10}:
        raise APIProtocolError("opcode is unsupported")
    if opcode >= 8 and (not fin or len(data) > 125):
        raise APIProtocolError("control frames must be final and at most 125 bytes")
    if masked and (not isinstance(mask_key, bytes) or len(mask_key) != 4):
        raise APIProtocolError("mask_key must contain exactly four bytes")
    first = (0x80 if fin else 0) | opcode
    marker = 0x80 if masked else 0
    if len(data) < 126:
        head = bytes((first, marker | len(data)))
    elif len(data) <= 0xFFFF:
        head = bytes((first, marker | 126)) + len(data).to_bytes(2, "big")
    else:
        head = bytes((first, marker | 127)) + len(data).to_bytes(8, "big")
    if not masked:
        return head + data
    encoded = bytes(value ^ mask_key[index % 4] for index, value in enumerate(data))
    return head + mask_key + encoded


def build_websocket_variants(marker: str = "R5D_INERT") -> tuple[InertVariant, ...]:
    if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", marker):
        raise APIProtocolError("marker must be a bounded inert token")
    messages = (
        ("control", f'{{"type":"{marker}"}}', "minimal application-message control"),
        ("duplicate-key", f'{{"type":"{marker}","role":"user","role":"{marker}"}}',
         "duplicate rejection versus first/last-key selection"),
        ("authority-field", f'{{"type":"{marker}","userId":"{marker}","action":"read"}}',
         "server must not trust client-supplied object ownership"),
        ("graphql-ws", f'{{"id":"{marker}","type":"subscribe",'
         '"payload":{"query":"query R5D { __typename }"}}',
         "GraphQL-over-WebSocket policy parity"),
    )
    rows: list[InertVariant] = []
    for index, (name, message, hypothesis) in enumerate(messages, 1):
        frame = build_websocket_frame(message, masked=True)
        rows.append(InertVariant(index, "websocket", name, base64.b64encode(frame).decode("ascii"), hypothesis))
    return tuple(rows)


__all__ = [
    "APIProtocolError", "EvidenceFinding", "GRPCTrailer", "GRPCWebFrame", "HeaderField",
    "InertVariant", "MAX_CAPTURE", "MAX_FRAMES", "MAX_FRAME_PAYLOAD", "MAX_HEADERS",
    "SavedHandshake", "WebSocketFrame", "analyze_graphql_document", "analyze_grpc_web_capture",
    "analyze_websocket_frames", "analyze_websocket_handshake", "build_graphql_variants",
    "build_grpc_web_frame", "build_grpc_web_trailers", "build_grpc_web_variants",
    "build_websocket_frame", "build_websocket_variants", "parse_grpc_web_frames",
    "parse_saved_handshake", "parse_websocket_frames",
]
