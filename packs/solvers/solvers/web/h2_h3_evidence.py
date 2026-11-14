#!/usr/bin/env python3
"""Offline HTTP/2 and HTTP/3 structural-evidence analyzer.

The input is a bounded, human-readable trace DSL, never a live connection or
wire decoder.  One record appears per line::

    FRAME type=HEADERS stream=1 protocol=h2
    HEADER stream=1 block=initial name=:method value=POST
    FRAME type=DATA stream=1 length=5 captured=5 flags=END_STREAM
    QPACK stream=0 required_insert_count=4 insert_count=2 blocked_streams=3

Duplicate fields and record order are preserved.  Builders emit only inert DSL
text; this module does not implement HPACK, QPACK, QUIC, TLS, sockets, or replay.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


MAX_TRACE_BYTES = 2_000_000
MAX_RECORDS = 4096
MAX_FIELDS = 64
MAX_VALUE = 8192
MAX_VARIANTS = 32


class ModernHTTPError(ValueError):
    """Raised when saved structural evidence is malformed or over a cap."""


@dataclass(frozen=True)
class TraceRecord:
    index: int
    kind: str
    fields: tuple[tuple[str, str], ...]
    raw: str

    def values(self, name: str) -> tuple[str, ...]:
        wanted = name.casefold()
        return tuple(value for key, value in self.fields if key.casefold() == wanted)

    def one(self, name: str) -> str | None:
        values = self.values(name)
        return values[0] if len(values) == 1 else None


@dataclass(frozen=True)
class ModernHTTPFinding:
    finding_id: str
    protocol: str
    title: str
    severity: str
    confidence: str
    evidence: tuple[str, ...]
    remediation: str


@dataclass(frozen=True)
class TraceVariant:
    rank: int
    protocol: str
    name: str
    trace: str
    hypothesis: str
    inert: bool = True
    offline: bool = True
    network_requests: int = 0


_PAIR = re.compile(r'([A-Za-z0-9_.:-]{1,64})=("(?:[^"\\]|\\.){0,8192}"|[^\s]{1,8192})')
_INT = re.compile(r"[0-9]{1,20}")
_HEADER_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def _text(raw: str | bytes | bytearray | memoryview) -> str:
    if isinstance(raw, str):
        text = raw
        try:
            size = len(raw.encode("utf-8"))
        except UnicodeError as exc:
            raise ModernHTTPError("trace contains non-UTF-8 text") from exc
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        try:
            data = bytes(raw)
        except (ValueError, TypeError) as exc:
            raise ModernHTTPError("trace bytes are unavailable") from exc
        size = len(data)
        text = data.decode("utf-8", "replace")
    else:
        raise ModernHTTPError("trace must be text or bytes")
    if size > MAX_TRACE_BYTES:
        raise ModernHTTPError(f"trace exceeds {MAX_TRACE_BYTES} bytes")
    if "\x00" in text:
        raise ModernHTTPError("trace contains NUL")
    return text


def parse_structural_trace(raw: str | bytes | bytearray | memoryview) -> tuple[TraceRecord, ...]:
    """Parse the inert record DSL while retaining duplicate keys and order."""

    text = _text(raw)
    records: list[TraceRecord] = []
    for line_number, source_line in enumerate(text.splitlines(), 1):
        line = source_line.strip()
        if not line or line.startswith("#"):
            continue
        if len(records) >= MAX_RECORDS:
            raise ModernHTTPError(f"record count exceeds {MAX_RECORDS}")
        first, separator, remainder = line.partition(" ")
        kind = first.upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_-]{0,31}", kind):
            raise ModernHTTPError(f"line {line_number} has an invalid record kind")
        fields: list[tuple[str, str]] = []
        cursor = 0
        for match in _PAIR.finditer(remainder if separator else ""):
            if remainder[cursor:match.start()].strip():
                raise ModernHTTPError(f"line {line_number} has malformed field syntax")
            if len(fields) >= MAX_FIELDS:
                raise ModernHTTPError(f"line {line_number} field count exceeds {MAX_FIELDS}")
            key, value = match.groups()
            if value.startswith('"'):
                value = re.sub(r'\\(["\\])', r'\1', value[1:-1])
            if len(value) > MAX_VALUE:
                raise ModernHTTPError(f"line {line_number} field value exceeds {MAX_VALUE}")
            fields.append((key, value))
            cursor = match.end()
        if separator and remainder[cursor:].strip():
            raise ModernHTTPError(f"line {line_number} has trailing malformed syntax")
        records.append(TraceRecord(len(records) + 1, kind, tuple(fields), line[:16_384]))
    return tuple(records)


def _number(record: TraceRecord, name: str, *, maximum: int = (1 << 63) - 1) -> int | None:
    value = record.one(name)
    if value is None or not _INT.fullmatch(value):
        return None
    parsed = int(value)
    return parsed if parsed <= maximum else None


def _bool(record: TraceRecord, name: str) -> bool | None:
    value = record.one(name)
    if value is None:
        return None
    if value.casefold() in {"1", "true", "yes"}:
        return True
    if value.casefold() in {"0", "false", "no"}:
        return False
    return None


def _headers(records: tuple[TraceRecord, ...], protocol: str) -> dict[tuple[int, str], list[TraceRecord]]:
    blocks: dict[tuple[int, str], list[TraceRecord]] = {}
    for record in records:
        if record.kind not in {"HEADER", "H2_HEADER", "H3_HEADER"}:
            continue
        tagged = (record.one("protocol") or ("h3" if record.kind == "H3_HEADER" else "h2")).casefold()
        if tagged != protocol:
            continue
        stream = _number(record, "stream")
        if stream is None:
            continue
        block = (record.one("block") or "initial").casefold()
        blocks.setdefault((stream, block), []).append(record)
    return blocks


def _header_block_findings(records: tuple[TraceRecord, ...], protocol: str,
                           default_role: str = "request") -> list[ModernHTTPFinding]:
    rows: list[ModernHTTPFinding] = []
    for (stream, block), fields in _headers(records, protocol).items():
        names = tuple(record.one("name") or "" for record in fields)
        values = tuple(record.one("value") or "" for record in fields)
        pseudo_seen: set[str] = set()
        regular_seen = False
        duplicates: set[str] = set()
        for name in names:
            if name.startswith(":"):
                if regular_seen:
                    rows.append(ModernHTTPFinding(
                        f"{protocol}-pseudo-after-regular-s{stream}-{block}", protocol,
                        "Pseudo-header appears after a regular field", "high", "high",
                        (f"stream {stream} block {block}", f"order: {names!r}"),
                        "Require all pseudo-headers before regular fields and reject reordered blocks.",
                    ))
                if name in pseudo_seen:
                    duplicates.add(name)
                pseudo_seen.add(name)
            else:
                regular_seen = True
                if name and (not _HEADER_TOKEN.fullmatch(name) or name != name.casefold()):
                    rows.append(ModernHTTPFinding(
                        f"{protocol}-invalid-header-name-s{stream}-{block}-{len(rows)}", protocol,
                        "Regular header name is uppercase or non-token", "medium", "high",
                        (f"stream {stream}", f"name {name!r}"),
                        "Reject uppercase and non-token field names before application routing.",
                    ))
        if duplicates:
            rows.append(ModernHTTPFinding(
                f"{protocol}-duplicate-pseudo-s{stream}-{block}", protocol,
                "Duplicate pseudo-header fields are ambiguous", "critical", "high",
                (f"stream {stream}", f"duplicates: {tuple(sorted(duplicates))!r}"),
                "Require each permitted pseudo-header exactly once.",
            ))
        mapping: dict[str, list[str]] = {}
        for name, value in zip(names, values):
            mapping.setdefault(name.casefold(), []).append(value)
        role_values = tuple(value.casefold() for record in fields
                            for value in (*record.values("message"), *record.values("role")))
        role_set = tuple(sorted(set(role_values)))
        if any(role not in {"request", "response", "unknown"} for role in role_set) or len(role_set) > 1:
            rows.append(ModernHTTPFinding(
                f"{protocol}-message-role-s{stream}-{block}", protocol,
                "Header block has invalid or conflicting message-role metadata", "medium", "high",
                (f"stream {stream}", f"roles: {role_set!r}"),
                "Record one canonical request/response role for each decoded header block.",
            ))
            role = default_role
        else:
            role = role_set[0] if role_set else default_role
        if block != "initial" and any(name.startswith(":") for name in names):
            rows.append(ModernHTTPFinding(
                f"{protocol}-pseudo-in-trailers-s{stream}-{block}", protocol,
                "Trailer block contains pseudo-headers", "high", "high",
                (f"stream {stream}", f"pseudo fields: {tuple(name for name in names if name.startswith(':'))!r}"),
                "Reject pseudo-headers in trailer blocks.",
            ))
        if block == "initial" and role == "request":
            unexpected = tuple(sorted(name for name in mapping if name.startswith(":") and name not in {
                ":method", ":scheme", ":authority", ":path", ":protocol",
            }))
            if unexpected:
                rows.append(ModernHTTPFinding(
                    f"{protocol}-request-pseudo-set-s{stream}", protocol,
                    "Request block contains response/unknown pseudo-headers", "high", "high",
                    (f"stream {stream}", f"unexpected: {unexpected!r}"),
                    "Reject pseudo-headers outside the request pseudo-header set.",
                ))
            method = mapping.get(":method", [])
            path = mapping.get(":path", [])
            authority = mapping.get(":authority", [])
            if len(method) != 1:
                rows.append(ModernHTTPFinding(
                    f"{protocol}-method-cardinality-s{stream}", protocol,
                    "Initial request block lacks one unambiguous :method", "high", "high",
                    (f"stream {stream}", f":method values: {tuple(method)!r}"),
                    "Require one :method in every initial request header block.",
                ))
            if method != ["CONNECT"] and len(path) != 1:
                rows.append(ModernHTTPFinding(
                    f"{protocol}-path-cardinality-s{stream}", protocol,
                    "Initial request block lacks one unambiguous :path", "high", "high",
                    (f"stream {stream}", f":path values: {tuple(path)!r}"),
                    "Require one :path except for classic CONNECT.",
                ))
            scheme = mapping.get(":scheme", [])
            if method != ["CONNECT"] and len(scheme) != 1:
                rows.append(ModernHTTPFinding(
                    f"{protocol}-scheme-cardinality-s{stream}", protocol,
                    "Initial request block lacks one unambiguous :scheme", "high", "high",
                    (f"stream {stream}", f":scheme values: {tuple(scheme)!r}"),
                    "Require one :scheme in every initial request block except classic CONNECT.",
                ))
            if method == ["CONNECT"] and path and not mapping.get(":protocol"):
                rows.append(ModernHTTPFinding(
                    f"{protocol}-connect-path-s{stream}", protocol,
                    "Classic CONNECT includes :path without extended-CONNECT :protocol", "medium", "high",
                    (f"stream {stream}",),
                    "Apply the correct classic or extended CONNECT pseudo-header set.",
                ))
            hosts = mapping.get("host", [])
            if authority and hosts and {item.casefold() for item in authority} != {
                    item.casefold() for item in hosts}:
                rows.append(ModernHTTPFinding(
                    f"{protocol}-authority-host-s{stream}", protocol,
                    ":authority conflicts with Host", "critical", "high",
                    (f":authority {tuple(authority)!r}", f"Host {tuple(hosts)!r}"),
                    "Reject authority disagreement before routing, caching, or downgrade.",
                ))
        elif block == "initial" and role == "response":
            unexpected = tuple(sorted(name for name in mapping if name.startswith(":") and name != ":status"))
            if unexpected:
                rows.append(ModernHTTPFinding(
                    f"{protocol}-response-pseudo-set-s{stream}", protocol,
                    "Response block contains request/unknown pseudo-headers", "high", "high",
                    (f"stream {stream}", f"unexpected: {unexpected!r}"),
                    "Permit only :status in an initial response pseudo-header set.",
                ))
            statuses = mapping.get(":status", [])
            status = statuses[0] if len(statuses) == 1 else ""
            if not re.fullmatch(r"[1-5][0-9]{2}", status):
                rows.append(ModernHTTPFinding(
                    f"{protocol}-status-cardinality-s{stream}", protocol,
                    "Initial response block lacks one canonical :status", "high", "high",
                    (f"stream {stream}", f":status values: {tuple(statuses)!r}"),
                    "Require exactly one three-digit :status in response headers.",
                ))
        forbidden = {"connection", "keep-alive", "proxy-connection", "upgrade"}
        present_forbidden = tuple(name for name in mapping if name in forbidden)
        te_values = mapping.get("transfer-encoding", [])
        if present_forbidden or any(value.casefold().strip() != "trailers" for value in te_values):
            rows.append(ModernHTTPFinding(
                f"{protocol}-connection-fields-s{stream}-{block}", protocol,
                "Connection-specific fields survive multiplexed HTTP metadata", "high", "high",
                (f"fields: {present_forbidden!r}", f"transfer-encoding: {tuple(te_values)!r}"),
                "Reject connection-specific fields; permit only TE: trailers where the protocol allows it.",
            ))
        content_lengths = mapping.get("content-length", [])
        if len(content_lengths) > 1 or any(not _INT.fullmatch(value) for value in content_lengths):
            rows.append(ModernHTTPFinding(
                f"{protocol}-content-length-ambiguity-s{stream}-{block}", protocol,
                "Content-Length metadata is duplicated or non-decimal", "high", "high",
                (f"values: {tuple(content_lengths)!r}",),
                "Require at most one canonical decimal Content-Length and verify DATA length.",
            ))
    return rows


def analyze_http2_trace(raw: str | bytes | bytearray | memoryview, *,
                        direction: str = "client") -> tuple[ModernHTTPFinding, ...]:
    """Analyze saved HTTP/2 frame/header records without HPACK decoding."""

    if not isinstance(direction, str) or direction not in {"client", "server", "unknown"}:
        raise ModernHTTPError("direction must be client, server, or unknown")
    records = parse_structural_trace(raw)
    default_role = "request" if direction == "client" else ("response" if direction == "server" else "unknown")
    findings = _header_block_findings(records, "h2", default_role)
    data_by_stream: dict[int, int] = {}
    ended: set[int] = set()
    resets: dict[int, int] = {}
    priorities: list[tuple[int, int]] = []
    settings_seen: dict[str, list[str]] = {}
    for record in records:
        protocol = (record.one("protocol") or "h2").casefold()
        if protocol != "h2" and record.kind not in {"H2_FRAME", "H2_HEADER"}:
            continue
        if record.kind not in {"FRAME", "H2_FRAME", "SETTINGS", "PRIORITY", "RST_STREAM"}:
            continue
        frame_type = (record.one("type") or record.kind).upper()
        stream = _number(record, "stream")
        if stream is not None and stream in resets and frame_type in {"HEADERS", "DATA"}:
            findings.append(ModernHTTPFinding(
                f"h2-frame-after-reset-{record.index}", "h2", "Stream carries a frame after RST_STREAM",
                "high", "high", (record.raw,),
                "Stop processing application frames after a stream reset and bound retained stream state.",
            ))
        if frame_type in {"HEADERS", "DATA", "PRIORITY", "RST_STREAM"} and stream == 0:
            findings.append(ModernHTTPFinding(
                f"h2-stream-zero-{record.index}", "h2", "Stream-specific frame uses stream 0",
                "high", "high", (record.raw,), "Reject stream-specific frames on the connection control stream.",
            ))
        if direction == "client" and stream and frame_type in {"HEADERS", "DATA"} and stream % 2 == 0:
            findings.append(ModernHTTPFinding(
                f"h2-client-even-stream-{record.index}", "h2", "Client request uses an even stream ID",
                "medium", "high", (record.raw,), "Enforce peer stream-ID parity and monotonic allocation.",
            ))
        if frame_type == "DATA" and stream is not None:
            length = _number(record, "length")
            captured = _number(record, "captured")
            if length is None:
                findings.append(ModernHTTPFinding(
                    f"h2-data-length-{record.index}", "h2", "DATA record lacks a bounded decimal length",
                    "medium", "high", (record.raw,), "Retain exact frame lengths in the capture and reject invalid framing.",
                ))
            else:
                data_by_stream[stream] = data_by_stream.get(stream, 0) + length
                if captured is not None and captured != length:
                    findings.append(ModernHTTPFinding(
                        f"h2-data-capture-mismatch-{record.index}", "h2",
                        "DATA declared and captured lengths differ", "high", "high",
                        (f"declared {length}", f"captured {captured}"),
                        "Verify capture completeness and reject truncated/overlong frames.",
                    ))
            if "END_STREAM" in (record.one("flags") or "").upper().split(","):
                ended.add(stream)
        elif frame_type == "RST_STREAM" and stream is not None:
            resets[stream] = resets.get(stream, 0) + 1
        elif frame_type == "PRIORITY" and stream is not None:
            dependency = _number(record, "dependency")
            weight = _number(record, "weight")
            if dependency is not None:
                priorities.append((stream, dependency))
            if dependency == stream or weight is None or not 1 <= weight <= 256:
                findings.append(ModernHTTPFinding(
                    f"h2-priority-invalid-{record.index}", "h2", "Invalid/self-dependent priority metadata",
                    "medium", "high", (record.raw,), "Reject self-dependency and weights outside 1..256.",
                ))
        elif frame_type == "SETTINGS":
            setting = (record.one("id") or "").upper()
            value = record.one("value") or ""
            flags = {item.strip().upper() for item in (record.one("flags") or "").split(",") if item.strip()}
            if "ACK" in flags and (setting or value):
                findings.append(ModernHTTPFinding(
                    f"h2-settings-ack-payload-{record.index}", "h2",
                    "SETTINGS acknowledgement carries setting payload metadata", "high", "high",
                    (record.raw,), "Require ACK SETTINGS frames to have an empty payload.",
                ))
            settings_seen.setdefault(setting, []).append(value)
            numeric = int(value) if _INT.fullmatch(value) else None
            invalid = (
                setting == "ENABLE_PUSH" and numeric not in {0, 1}
                or setting == "INITIAL_WINDOW_SIZE" and (numeric is None or numeric > (1 << 31) - 1)
                or setting == "MAX_FRAME_SIZE" and (numeric is None or not 16_384 <= numeric <= 16_777_215)
            )
            if invalid:
                findings.append(ModernHTTPFinding(
                    f"h2-setting-range-{record.index}", "h2", "HTTP/2 setting is outside its legal range",
                    "high", "high", (record.raw,), "Validate every setting identifier and range before applying it.",
                ))
    for (stream, block), header_records in _headers(records, "h2").items():
        if block != "initial" or stream not in ended:
            continue
        lengths = [record.one("value") or "" for record in header_records
                   if (record.one("name") or "").casefold() == "content-length"]
        if len(lengths) == 1 and _INT.fullmatch(lengths[0]) and int(lengths[0]) != data_by_stream.get(stream, 0):
            findings.append(ModernHTTPFinding(
                f"h2-content-length-data-s{stream}", "h2", "Content-Length differs from summed DATA length",
                "critical", "high",
                (f"stream {stream}", f"Content-Length {lengths[0]}", f"DATA {data_by_stream.get(stream, 0)}"),
                "Enforce message length before translating or reusing a downstream HTTP/1 connection.",
            ))
    total_resets = sum(resets.values())
    if total_resets >= 8:
        findings.append(ModernHTTPFinding(
            "h2-reset-volume", "h2", "High reset volume is present in the saved trace", "medium", "medium",
            (f"RST_STREAM records: {total_resets}", f"streams: {tuple(sorted(resets))!r}"),
            "Rate-limit stream creation/reset work and bound per-connection state.",
        ))
    if len(priorities) >= 32:
        findings.append(ModernHTTPFinding(
            "h2-priority-volume", "h2", "High priority-update volume is present", "medium", "medium",
            (f"priority records: {len(priorities)}",),
            "Bound priority tree updates and ignore unsupported priority signals safely.",
        ))
    dependency_by_stream = {stream: dependency for stream, dependency in priorities if dependency != 0}
    cycle: tuple[int, ...] = ()
    for start in sorted(dependency_by_stream):
        path: list[int] = []
        positions: dict[int, int] = {}
        current = start
        while current in dependency_by_stream and current not in positions:
            positions[current] = len(path)
            path.append(current)
            current = dependency_by_stream[current]
        if current in positions:
            cycle = tuple(path[positions[current]:] + [current])
            break
    if cycle:
        findings.append(ModernHTTPFinding(
            "h2-priority-cycle", "h2", "Priority dependencies contain a cycle", "medium", "high",
            (f"cycle: {cycle!r}",), "Reject cyclic dependencies and bound priority-tree update work.",
        ))
    repeated_settings = tuple((key, tuple(values)) for key, values in settings_seen.items()
                              if key and len(values) > 1 and len(set(values)) > 1)
    if repeated_settings:
        findings.append(ModernHTTPFinding(
            "h2-settings-churn", "h2", "Settings values change repeatedly in one saved trace", "medium", "medium",
            (f"changes: {repeated_settings!r}",), "Bound SETTINGS churn and apply state changes atomically.",
        ))
    if re.search(r"(?i)\b(?:downgrade|h2c|http/1\.1 backend|translated_to=h1)\b", _text(raw)):
        findings.append(ModernHTTPFinding(
            "h2-downgrade-evidence", "h2", "Trace explicitly records HTTP/2-to-HTTP/1 translation", "medium", "high",
            ("downgrade/translation token appears in saved trace",),
            "Canonicalize authority, framing, and forbidden fields before one-way translation.",
        ))
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def analyze_http3_trace(raw: str | bytes | bytearray | memoryview, *,
                        direction: str = "client") -> tuple[ModernHTTPFinding, ...]:
    """Analyze saved HTTP/3/QPACK/0-RTT/migration metadata without QUIC."""

    if not isinstance(direction, str) or direction not in {"client", "server", "unknown"}:
        raise ModernHTTPError("direction must be client, server, or unknown")
    records = parse_structural_trace(raw)
    default_role = "request" if direction == "client" else ("response" if direction == "server" else "unknown")
    findings = _header_block_findings(records, "h3", default_role)
    settings_records = 0
    for record in records:
        protocol = (record.one("protocol") or "h3").casefold()
        if protocol != "h3" and record.kind not in {"H3_FRAME", "H3_HEADER", "QPACK", "CONNECTION", "ALT_SVC"}:
            continue
        frame_type = (record.one("type") or record.kind).upper()
        stream_type = (record.one("stream_type") or "").casefold()
        if frame_type == "SETTINGS":
            settings_records += 1
            if stream_type and stream_type != "control":
                findings.append(ModernHTTPFinding(
                    f"h3-settings-stream-{record.index}", "h3", "HTTP/3 SETTINGS appears off the control stream",
                    "high", "high", (record.raw,), "Accept one SETTINGS frame on the peer control stream only.",
                ))
        if frame_type in {"DATA", "HEADERS"} and stream_type == "control":
            findings.append(ModernHTTPFinding(
                f"h3-request-frame-control-{record.index}", "h3", "Request-stream frame appears on a control stream",
                "high", "high", (record.raw,), "Enforce unidirectional stream types before parsing frame payloads.",
            ))
        if record.kind == "QPACK" or frame_type == "QPACK":
            required = _number(record, "required_insert_count")
            inserted = _number(record, "insert_count")
            blocked = _number(record, "blocked_streams")
            advertised_blocked = _number(record, "max_blocked_streams")
            capacity = _number(record, "dynamic_table_capacity")
            advertised_capacity = _number(record, "max_table_capacity")
            if required is not None and inserted is not None and required > inserted:
                findings.append(ModernHTTPFinding(
                    f"h3-qpack-blocked-{record.index}", "h3", "QPACK block references unavailable inserts",
                    "medium", "high", (record.raw,),
                    "Bound blocked streams/time and reject impossible required-insert counts.",
                ))
            if blocked is not None and advertised_blocked is not None and blocked > advertised_blocked:
                findings.append(ModernHTTPFinding(
                    f"h3-qpack-block-limit-{record.index}", "h3", "QPACK blocked-stream count exceeds advertised limit",
                    "high", "high", (record.raw,), "Enforce SETTINGS_QPACK_BLOCKED_STREAMS exactly.",
                ))
            if capacity is not None and advertised_capacity is not None and capacity > advertised_capacity:
                findings.append(ModernHTTPFinding(
                    f"h3-qpack-capacity-{record.index}", "h3", "QPACK dynamic table exceeds advertised capacity",
                    "high", "high", (record.raw,), "Reject encoder capacity updates beyond the configured maximum.",
                ))
        early = _bool(record, "early_data")
        if early:
            method = (record.one("method") or "").upper()
            credentials = _bool(record, "credentials")
            if method in {"POST", "PUT", "PATCH", "DELETE"} or credentials:
                findings.append(ModernHTTPFinding(
                    f"h3-early-data-replay-{record.index}", "h3", "0-RTT carries state-changing or credentialed evidence",
                    "high", "high", (record.raw,),
                    "Reject/replay-protect non-idempotent or credential-bound early data.",
                ))
        if record.kind == "CONNECTION" or frame_type == "MIGRATION":
            event = (record.one("event") or frame_type).casefold()
            if "migration" in event and _bool(record, "validated") is False:
                findings.append(ModernHTTPFinding(
                    f"h3-unvalidated-migration-{record.index}", "h3", "Connection migration lacks saved path validation",
                    "high", "high", (record.raw,),
                    "Require PATH_CHALLENGE/PATH_RESPONSE validation before moving authenticated traffic.",
                ))
        if record.kind == "ALT_SVC":
            origin = record.one("origin") or ""
            authority = record.one("authority") or ""
            max_age = _number(record, "ma")
            if origin and authority and origin.casefold() != authority.casefold():
                findings.append(ModernHTTPFinding(
                    f"h3-alt-svc-authority-{record.index}", "h3", "Alt-Svc authority differs from saved origin",
                    "medium", "high", (record.raw,),
                    "Treat alternative services as origin-authorized routing metadata and validate certificate scope.",
                ))
            if max_age is not None and max_age > 31_536_000:
                findings.append(ModernHTTPFinding(
                    f"h3-alt-svc-lifetime-{record.index}", "h3", "Alt-Svc lifetime exceeds one year",
                    "low", "high", (record.raw,), "Bound alternative-service persistence and honor clear/revocation.",
                ))
    if settings_records > 1:
        findings.append(ModernHTTPFinding(
            "h3-duplicate-settings", "h3", "Multiple HTTP/3 SETTINGS records appear", "high", "high",
            (f"SETTINGS records: {settings_records}",), "Accept exactly one SETTINGS frame per control stream.",
        ))
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def build_modern_http_variants(marker: str = "R5D_INERT") -> tuple[TraceVariant, ...]:
    """Return inert saved-trace examples for H2/H3 parser-policy review."""

    if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{3,63}", marker):
        raise ModernHTTPError("marker must be a bounded inert token")
    specs = (
        ("h2", "pseudo-order", "\n".join((
            "FRAME type=HEADERS stream=1 protocol=h2",
            "HEADER stream=1 block=initial name=x-r5d value=" + marker + " protocol=h2",
            "HEADER stream=1 block=initial name=:method value=GET protocol=h2",
            "HEADER stream=1 block=initial name=:path value=/ protocol=h2",
        )), "pseudo-header ordering must be rejected before routing"),
        ("h2", "content-length-downgrade", "\n".join((
            "HEADER stream=1 block=initial name=:method value=POST protocol=h2",
            "HEADER stream=1 block=initial name=:path value=/r5d protocol=h2",
            "HEADER stream=1 block=initial name=content-length value=0 protocol=h2",
            "FRAME type=DATA stream=1 length=4 captured=4 flags=END_STREAM protocol=h2 translated_to=h1",
        )), "message length must be enforced before HTTP/1 translation"),
        ("h2", "reset-volume", "\n".join(
            f"FRAME type=RST_STREAM stream={index * 2 + 1} error=CANCEL protocol=h2" for index in range(8)
        ), "per-connection reset work must be bounded"),
        ("h3", "qpack-block", "QPACK stream=0 required_insert_count=9 insert_count=2 blocked_streams=5 max_blocked_streams=1 dynamic_table_capacity=4096 max_table_capacity=128",
         "QPACK blocking and table capacity must honor advertised limits"),
        ("h3", "zero-rtt", "H3_FRAME type=HEADERS stream=0 method=POST early_data=true credentials=true marker=" + marker,
         "credentialed state changes must not be replayable as early data"),
        ("h3", "migration-alt-svc", "\n".join((
            "CONNECTION event=MIGRATION old=pathA new=pathB validated=false",
            "ALT_SVC origin=app.example authority=alt.example ma=63072000 value=h3",
        )), "path migration and alternative authority require explicit validation"),
    )
    if len(specs) > MAX_VARIANTS:
        raise ModernHTTPError("variant count exceeds cap")
    return tuple(TraceVariant(index, protocol, name, trace, hypothesis)
                 for index, (protocol, name, trace, hypothesis) in enumerate(specs, 1))


__all__ = [
    "MAX_RECORDS", "MAX_TRACE_BYTES", "ModernHTTPError", "ModernHTTPFinding",
    "TraceRecord", "TraceVariant", "analyze_http2_trace", "analyze_http3_trace",
    "build_modern_http_variants", "parse_structural_trace",
]
