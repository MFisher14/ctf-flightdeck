#!/usr/bin/env python3
"""Offline classifier for modern HTTP desynchronisation state evidence.

This module consumes a bounded JSON evidence bundle.  It never opens a socket,
replays a request, or creates attack traffic.  Every saved request is parsed by
``http_smuggling.parse_saved_request`` so duplicate fields and raw whitespace
retain the same meaning as the existing HTTP toolkit.

The v1 bundle is intentionally explicit about facts that cannot be recovered
from one raw message::

    {
      "schema": "wpgap-desync-evidence-v1",
      "requests": [{
        "id": "edge-1", "sequence": 1, "hop": "edge",
        "connection": "front-a", "protocol": "h1",
        "framing": "zero", "body_bytes_seen": 0,
        "end_stream": true, "raw": "GET / HTTP/1.1..."
      }],
      "responses": [{
        "id": "resp-1", "request_id": "upstream-1",
        "connection": "pool-a", "raw": "HTTP/1.1 200 OK...",
        "before_body_complete": true, "connection_reused": true
      }],
      "links": [{"kind": "rewritten-from", "from": "edge-1",
                  "to": "upstream-1"}],
      "config": {"downstream_protocol": "h1", "upstream_protocol": "h1",
                 "reuse_upstream": true}
    }

Observed framing values are ``zero``, ``content-length``,
``transfer-encoding``, ``stream``, or ``unknown``.  A raw Content-Length
mismatch alone is never promoted to 0.CL: a paired per-hop framing decision is
required.  Likewise, connection reuse and ordered response facts are required
for body-debt escalation.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

from http_smuggling import (
    SavedHTTPError,
    SavedRequest,
    analyze_saved_request,
    parse_saved_request,
)


SCHEMA = "wpgap-desync-evidence-v1"
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_REQUESTS = 64
MAX_RESPONSES = 128
MAX_LINKS = 256
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_HEADER_BYTES = 64 * 1024
MAX_RESPONSE_HEADERS = 512
MAX_ID_LENGTH = 96
MAX_DECLARED_LENGTH = (1 << 63) - 1
MAX_PATH_BYTES = 4096


class DesyncEvidenceError(ValueError):
    """Only public exception raised for malformed or over-limit evidence."""


@dataclass(frozen=True)
class DesyncStateFinding:
    """One evidence-backed state classification, never an exploitability claim."""

    finding_id: str
    family: str
    title: str
    severity: str
    confidence: str
    request_ids: tuple[str, ...]
    evidence: tuple[str, ...]
    state_path: tuple[str, ...]
    remediation: str


@dataclass(frozen=True)
class _RequestEvidence:
    evidence_id: str
    sequence: int
    hop: str
    connection: str
    protocol: str
    framing: str
    body_bytes_seen: int
    end_stream: bool
    raw: str
    parsed: SavedRequest


@dataclass(frozen=True)
class _ParsedResponse:
    version: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def values(self, name: str) -> tuple[str, ...]:
        wanted = name.casefold()
        return tuple(value for key, value in self.headers if key == wanted)


@dataclass(frozen=True)
class _ResponseEvidence:
    evidence_id: str
    request_id: str
    connection: str
    before_body_complete: bool
    connection_reused: bool
    parsed: _ParsedResponse


@dataclass(frozen=True)
class _Link:
    kind: str
    source: str
    target: str
    byte_count: int | None


@dataclass(frozen=True)
class _Config:
    downstream_protocol: str
    upstream_protocol: str
    reuse_upstream: bool
    dechunk_requests: bool
    path_percent_decoded_before_upstream: bool


@dataclass(frozen=True)
class _Bundle:
    requests: tuple[_RequestEvidence, ...]
    responses: tuple[_ResponseEvidence, ...]
    links: tuple[_Link, ...]
    config: _Config


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}")
_DECIMAL = re.compile(r"[0-9]+")
_STATUS = re.compile(r"HTTP/(?:0\.9|1\.0|1\.1|2(?:\.0)?|3(?:\.0)?) ([1-5][0-9]{2})(?:[ \t].*)?", re.I)
_NESTED_REQUEST = re.compile(
    rb"(?:^|\r\n)(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|CONNECT|TRACE) "
    rb"[^\r\n ]+ HTTP/1\.[01]\r\n"
)
_PROTOCOLS = {"unknown", "h1", "h2", "h3"}
_HOPS = {"client", "edge", "upstream", "origin"}
_FRAMING = {"unknown", "zero", "content-length", "transfer-encoding", "stream"}
_LINK_KINDS = {
    "rewritten-from", "consumed-as-body", "prefix-contaminates",
    "response-attributed-to", "overread-into",
}


def _fail(message: str) -> DesyncEvidenceError:
    return DesyncEvidenceError(message)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise _fail(f"{label} keys must be text")
    return value


def _keys(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise _fail(f"{label} has unknown fields: {', '.join(unknown)}")


def _bounded_text(value: Any, label: str, *, maximum: int = MAX_RESPONSE_BYTES) -> str:
    if not isinstance(value, str):
        raise _fail(f"{label} must be text")
    try:
        size = len(value.encode("latin-1", "strict"))
    except UnicodeError as exc:
        raise _fail(f"{label} must be byte-preserving Latin-1 text") from exc
    if not value:
        raise _fail(f"{label} must not be empty")
    if size > maximum:
        raise _fail(f"{label} exceeds {maximum} bytes")
    if "\x00" in value:
        raise _fail(f"{label} contains NUL")
    return value


def _identifier(value: Any, label: str) -> str:
    value = _bounded_text(value, label, maximum=MAX_ID_LENGTH)
    if not _ID.fullmatch(value):
        raise _fail(f"{label} is not a safe identifier")
    return value


def _boolean(value: Any, label: str, *, default: bool | None = None) -> bool:
    if value is None and default is not None:
        return default
    if type(value) is not bool:  # bool-as-int ambiguity is rejected deliberately
        raise _fail(f"{label} must be a boolean")
    return value


def _integer(value: Any, label: str, *, default: int | None = None,
             maximum: int = MAX_INPUT_BYTES) -> int:
    if value is None and default is not None:
        return default
    if type(value) is not int or value < 0 or value > maximum:
        raise _fail(f"{label} must be an integer in 0..{maximum}")
    return value


def _enum(value: Any, allowed: set[str], label: str, *, default: str) -> str:
    if value is None:
        if default not in allowed:
            raise _fail(f"{label} is required")
        return default
    if not isinstance(value, str) or value not in allowed:
        raise _fail(f"{label} must be one of {', '.join(sorted(allowed))}")
    return value


def _decode_source(source: Mapping[str, Any] | str | bytes | bytearray | memoryview) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    if isinstance(source, str):
        try:
            encoded = source.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise _fail("JSON evidence is not valid UTF-8 text") from exc
    elif isinstance(source, (bytes, bytearray, memoryview)):
        encoded = bytes(source)
    else:
        raise _fail("evidence must be a JSON object or JSON text/bytes")
    if len(encoded) > MAX_INPUT_BYTES:
        raise _fail(f"JSON evidence exceeds {MAX_INPUT_BYTES} bytes")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _fail(f"duplicate JSON object key {key!r}")
            result[key] = value
        return result

    try:
        decoded = json.loads(encoded, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise _fail("evidence is not valid JSON") from exc
    return _mapping(decoded, "evidence")


def _parse_response(raw: str, label: str) -> _ParsedResponse:
    data = _bounded_text(raw, label, maximum=MAX_RESPONSE_BYTES).encode("latin-1")
    crlf = data.find(b"\r\n\r\n")
    lf = data.find(b"\n\n")
    if crlf >= 0 and (lf < 0 or crlf <= lf):
        head, body = data[:crlf], data[crlf + 4:]
    elif lf >= 0:
        head, body = data[:lf], data[lf + 2:]
    else:
        raise _fail(f"{label} lacks a complete response header block")
    if len(head) > MAX_RESPONSE_HEADER_BYTES:
        raise _fail(f"{label} header block exceeds {MAX_RESPONSE_HEADER_BYTES} bytes")
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    if not lines or not lines[0]:
        raise _fail(f"{label} lacks a status line")
    status_line = lines[0].decode("latin-1")
    match = _STATUS.fullmatch(status_line)
    if not match:
        raise _fail(f"{label} has an invalid status line")
    headers: list[tuple[str, str]] = []
    for number, line in enumerate(lines[1:], 2):
        if len(headers) >= MAX_RESPONSE_HEADERS:
            raise _fail(f"{label} header count exceeds {MAX_RESPONSE_HEADERS}")
        if not line or line.startswith((b" ", b"\t")) or b":" not in line:
            raise _fail(f"{label} has malformed header line {number}")
        name_b, value_b = line.split(b":", 1)
        name = name_b.decode("latin-1")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise _fail(f"{label} has invalid header name at line {number}")
        value = value_b.decode("latin-1").strip(" \t")
        if any(ord(ch) < 32 and ch != "\t" for ch in value):
            raise _fail(f"{label} has a control character at line {number}")
        headers.append((name.casefold(), value))
    version = status_line.split(" ", 1)[0].upper()
    return _ParsedResponse(version, int(match.group(1)), tuple(headers), body)


def _parse_bundle(source: Mapping[str, Any] | str | bytes | bytearray | memoryview) -> _Bundle:
    root = _decode_source(source)
    _keys(root, {"schema", "requests", "responses", "links", "config"}, "evidence")
    if root.get("schema") != SCHEMA:
        raise _fail(f"schema must be {SCHEMA!r}")

    request_rows = root.get("requests")
    response_rows = root.get("responses", [])
    link_rows = root.get("links", [])
    if not isinstance(request_rows, list) or not request_rows:
        raise _fail("requests must be a non-empty array")
    if not isinstance(response_rows, list):
        raise _fail("responses must be an array")
    if not isinstance(link_rows, list):
        raise _fail("links must be an array")
    if len(request_rows) > MAX_REQUESTS:
        raise _fail(f"request count exceeds {MAX_REQUESTS}")
    if len(response_rows) > MAX_RESPONSES:
        raise _fail(f"response count exceeds {MAX_RESPONSES}")
    if len(link_rows) > MAX_LINKS:
        raise _fail(f"link count exceeds {MAX_LINKS}")

    requests: list[_RequestEvidence] = []
    aggregate_raw_bytes = 0
    all_ids: set[str] = set()
    for index, untrusted in enumerate(request_rows):
        row = _mapping(untrusted, f"requests[{index}]")
        _keys(row, {"id", "sequence", "hop", "connection", "raw", "protocol",
                    "framing", "body_bytes_seen", "end_stream"}, f"requests[{index}]")
        evidence_id = _identifier(row.get("id"), f"requests[{index}].id")
        if evidence_id in all_ids:
            raise _fail(f"duplicate evidence id {evidence_id!r}")
        all_ids.add(evidence_id)
        raw = _bounded_text(row.get("raw"), f"requests[{index}].raw", maximum=MAX_INPUT_BYTES)
        aggregate_raw_bytes += len(raw.encode("latin-1"))
        if aggregate_raw_bytes > MAX_INPUT_BYTES:
            raise _fail(f"aggregate raw evidence exceeds {MAX_INPUT_BYTES} bytes")
        try:
            parsed = parse_saved_request(raw)
        except (SavedHTTPError, UnicodeError, ValueError, TypeError, OverflowError) as exc:
            raise _fail(f"requests[{index}].raw is not a valid saved request: {exc}") from exc
        inferred_protocol = "h2" if parsed.version.startswith("HTTP/2") else (
            "h3" if parsed.version.startswith("HTTP/3") else "h1"
        )
        protocol = _enum(row.get("protocol"), _PROTOCOLS,
                         f"requests[{index}].protocol", default=inferred_protocol)
        requests.append(_RequestEvidence(
            evidence_id=evidence_id,
            sequence=_integer(row.get("sequence"), f"requests[{index}].sequence",
                              default=index, maximum=1_000_000),
            hop=_enum(row.get("hop"), _HOPS, f"requests[{index}].hop", default="client"),
            connection=_identifier(row.get("connection"), f"requests[{index}].connection"),
            protocol=protocol,
            framing=_enum(row.get("framing"), _FRAMING,
                          f"requests[{index}].framing", default="unknown"),
            body_bytes_seen=_integer(row.get("body_bytes_seen"),
                                     f"requests[{index}].body_bytes_seen",
                                     default=len(parsed.body), maximum=MAX_INPUT_BYTES),
            end_stream=_boolean(row.get("end_stream"), f"requests[{index}].end_stream",
                                default=False),
            raw=raw,
            parsed=parsed,
        ))

    request_ids = {item.evidence_id for item in requests}
    request_by_id = {item.evidence_id: item for item in requests}
    responses: list[_ResponseEvidence] = []
    for index, untrusted in enumerate(response_rows):
        row = _mapping(untrusted, f"responses[{index}]")
        _keys(row, {"id", "request_id", "connection", "raw",
                    "before_body_complete", "connection_reused"}, f"responses[{index}]")
        evidence_id = _identifier(row.get("id"), f"responses[{index}].id")
        if evidence_id in all_ids:
            raise _fail(f"duplicate evidence id {evidence_id!r}")
        all_ids.add(evidence_id)
        request_id = _identifier(row.get("request_id"), f"responses[{index}].request_id")
        if request_id not in request_ids:
            raise _fail(f"responses[{index}] references unknown request {request_id!r}")
        raw = _bounded_text(row.get("raw"), f"responses[{index}].raw")
        aggregate_raw_bytes += len(raw.encode("latin-1"))
        if aggregate_raw_bytes > MAX_INPUT_BYTES:
            raise _fail(f"aggregate raw evidence exceeds {MAX_INPUT_BYTES} bytes")
        response_connection = _identifier(
            row.get("connection"), f"responses[{index}].connection"
        )
        if response_connection != request_by_id[request_id].connection:
            raise _fail(
                f"responses[{index}] connection differs from its associated request"
            )
        responses.append(_ResponseEvidence(
            evidence_id=evidence_id,
            request_id=request_id,
            connection=response_connection,
            before_body_complete=_boolean(row.get("before_body_complete"),
                                          f"responses[{index}].before_body_complete",
                                          default=False),
            connection_reused=_boolean(row.get("connection_reused"),
                                       f"responses[{index}].connection_reused", default=False),
            parsed=_parse_response(raw, f"responses[{index}].raw"),
        ))

    response_ids = {item.evidence_id for item in responses}
    links: list[_Link] = []
    for index, untrusted in enumerate(link_rows):
        row = _mapping(untrusted, f"links[{index}]")
        _keys(row, {"kind", "from", "to", "bytes"}, f"links[{index}]")
        kind = _enum(row.get("kind"), _LINK_KINDS, f"links[{index}].kind", default="")
        source_id = _identifier(row.get("from"), f"links[{index}].from")
        target_id = _identifier(row.get("to"), f"links[{index}].to")
        byte_count = None if "bytes" not in row else _integer(
            row.get("bytes"), f"links[{index}].bytes", maximum=MAX_INPUT_BYTES
        )
        if kind in {"rewritten-from", "consumed-as-body", "prefix-contaminates"}:
            if source_id not in request_ids or target_id not in request_ids:
                raise _fail(f"links[{index}] requires request ids")
        elif kind == "response-attributed-to":
            if source_id not in response_ids or target_id not in request_ids:
                raise _fail(f"links[{index}] requires response -> request ids")
        elif kind == "overread-into":
            if source_id not in response_ids or target_id not in response_ids:
                raise _fail(f"links[{index}] requires response ids")
        links.append(_Link(kind, source_id, target_id, byte_count))

    config_row = _mapping(root.get("config", {}), "config")
    _keys(config_row, {"downstream_protocol", "upstream_protocol", "reuse_upstream",
                       "dechunk_requests", "path_percent_decoded_before_upstream"}, "config")
    config = _Config(
        downstream_protocol=_enum(config_row.get("downstream_protocol"), _PROTOCOLS,
                                  "config.downstream_protocol", default="unknown"),
        upstream_protocol=_enum(config_row.get("upstream_protocol"), _PROTOCOLS,
                                "config.upstream_protocol", default="unknown"),
        reuse_upstream=_boolean(config_row.get("reuse_upstream"),
                                "config.reuse_upstream", default=False),
        dechunk_requests=_boolean(config_row.get("dechunk_requests"),
                                  "config.dechunk_requests", default=False),
        path_percent_decoded_before_upstream=_boolean(
            config_row.get("path_percent_decoded_before_upstream"),
            "config.path_percent_decoded_before_upstream", default=False,
        ),
    )
    return _Bundle(tuple(requests), tuple(responses), tuple(links), config)


def _content_length(request: _RequestEvidence) -> int | None:
    values = request.parsed.values("content-length")
    if len(values) != 1:
        return None
    value = values[0].strip(" \t")
    if not _DECIMAL.fullmatch(value):
        return None
    try:
        parsed = int(value, 10)
    except (ValueError, OverflowError):
        return None
    return parsed if parsed <= MAX_DECLARED_LENGTH else None


def _has_transfer_encoding(request: _RequestEvidence) -> bool:
    return bool(request.parsed.values("transfer-encoding"))


def _header_pairs(request: _RequestEvidence) -> set[tuple[str, str]]:
    return {(field.name.casefold(), field.value) for field in request.parsed.headers}


def _encoded_line_break(request: _RequestEvidence) -> bool:
    values = (request.parsed.target,) + tuple(field.value for field in request.parsed.headers)
    return any(re.search(r"(?i)%(?:0d%0a|0a|0d)", value) for value in values)


def _percent_decoded_sources(request: _RequestEvidence) -> tuple[str, ...]:
    """Decode only %HH octets to correlate supplied input with added fields."""

    def decode(value: str) -> str:
        return re.sub(
            r"%([0-9A-Fa-f]{2})",
            lambda match: chr(int(match.group(1), 16)),
            value,
        )

    return (decode(request.parsed.target),) + tuple(
        decode(field.value) for field in request.parsed.headers
    )


def _valid_final_chunked(request: _RequestEvidence) -> bool:
    tokens = tuple(
        token.strip(" \t").casefold()
        for value in request.parsed.values("transfer-encoding")
        for token in value.split(",")
    )
    if not tokens or tokens[-1] != "chunked":
        return False
    finding_ids = {item.finding_id for item in analyze_saved_request(request.raw)}
    return "chunk-framing-residue" not in finding_ids


def _has_outstanding_body(request: _RequestEvidence) -> bool:
    cl = _content_length(request)
    if cl is not None:
        return request.body_bytes_seen < cl
    return request.framing in {"transfer-encoding", "stream"} and not request.end_stream


def _observed_reuse(bundle: _Bundle, request_id: str) -> bool:
    request = next(item for item in bundle.requests if item.evidence_id == request_id)
    response_reuse = any(
        response.request_id == request_id
        and response.connection == request.connection
        and response.connection_reused
        for response in bundle.responses
    )
    later_request = any(
        other.connection == request.connection and other.sequence > request.sequence
        for other in bundle.requests
    )
    return response_reuse or later_request


def _early_final(bundle: _Bundle, request_id: str) -> tuple[_ResponseEvidence, ...]:
    request = next(item for item in bundle.requests if item.evidence_id == request_id)
    if not _has_outstanding_body(request):
        return ()
    return tuple(
        response for response in bundle.responses
        if response.request_id == request_id
        and response.parsed.status >= 200
        and response.before_body_complete
    )


def _analyze(bundle: _Bundle) -> tuple[DesyncStateFinding, ...]:
    requests = {item.evidence_id: item for item in bundle.requests}
    findings: dict[str, DesyncStateFinding] = {}
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    confidence_order = {"low": 0, "medium": 1, "high": 2}

    def add(finding_id: str, family: str, title: str, severity: str, confidence: str,
            request_ids: tuple[str, ...], evidence: tuple[str, ...],
            state_path: tuple[str, ...], remediation: str) -> None:
        prior = findings.get(finding_id)
        row = DesyncStateFinding(
            finding_id, family, title, severity, confidence,
            tuple(dict.fromkeys(request_ids)), tuple(dict.fromkeys(evidence)),
            state_path, remediation,
        )
        if prior is None:
            findings[finding_id] = row
            return
        findings[finding_id] = DesyncStateFinding(
            finding_id, family, title,
            severity if severity_order[severity] > severity_order[prior.severity] else prior.severity,
            confidence if confidence_order[confidence] > confidence_order[prior.confidence]
            else prior.confidence,
            tuple(dict.fromkeys((*prior.request_ids, *row.request_ids))),
            tuple(dict.fromkeys((*prior.evidence, *row.evidence))),
            prior.state_path,
            remediation,
        )

    rewrite_pairs: list[tuple[_RequestEvidence, _RequestEvidence]] = []
    for link in bundle.links:
        if link.kind == "rewritten-from":
            rewrite_pairs.append((requests[link.source], requests[link.target]))

    zero_cl_pairs: list[tuple[_RequestEvidence, _RequestEvidence]] = []
    cl_zero_pairs: list[tuple[_RequestEvidence, _RequestEvidence]] = []
    for front, back in rewrite_pairs:
        back_cl = _content_length(back)
        front_cl = _content_length(front)
        if (front.framing == "zero" and back.framing == "content-length"
                and back_cl is not None and back_cl > back.body_bytes_seen):
            zero_cl_pairs.append((front, back))
            add(
                "zero-cl-body-debt", "0.CL", "Paired hops create Content-Length body debt",
                "critical" if _observed_reuse(bundle, back.evidence_id) else "high", "high",
                (front.evidence_id, back.evidence_id),
                (f"front framing=zero on {front.evidence_id}",
                 f"upstream Content-Length={back_cl}, body bytes seen={back.body_bytes_seen}"),
                ("front completes at headers", "back waits for declared body", "next bytes can pay debt"),
                "Reject the parser differential; reconcile body length before forwarding and close on error.",
            )
        if (front.framing == "content-length" and back.framing == "zero"
                and front_cl is not None and front_cl > 0):
            cl_zero_pairs.append((front, back))

        if (front.framing == "transfer-encoding" and back.framing == "zero"
                and _valid_final_chunked(front) and not _has_transfer_encoding(back)
                and _content_length(back) is None and len(back.parsed.body) > 0
                and bundle.config.dechunk_requests):
            reused = _observed_reuse(bundle, back.evidence_id)
            add(
                "te-zero-after-dechunk", "TE.0", "Dechunked bytes cross an implicit-zero boundary",
                "critical" if reused else "high", "high",
                (front.evidence_id, back.evidence_id),
                ("front hop uses Transfer-Encoding", "upstream has neither TE nor CL",
                 f"unframed upstream residue={len(back.parsed.body)} bytes",
                 f"upstream reuse={reused}"),
                ("front dechunks body", "forwarded H1 request has implicit zero length",
                 "decoded bytes remain at the next request boundary"),
                "Set an exact upstream length after dechunking, reject ambiguity, and close the H1 connection.",
            )

        if _encoded_line_break(front):
            extra_headers = _header_pairs(back) - _header_pairs(front)
            decoded_sources = _percent_decoded_sources(front)
            nested_match = _NESTED_REQUEST.search(back.parsed.body)
            nested = bool(
                nested_match
                and any(nested_match.group(0).decode("latin-1") in source
                        for source in decoded_sources)
            )
            injected_headers = tuple(sorted(
                pair for pair in extra_headers
                if any(re.search(r"(?:\r\n|\n)" + re.escape(pair[0]) + r"[ \t]*:",
                                 source, re.I) for source in decoded_sources)
            ))
            changed = bool(injected_headers) or nested
            if changed:
                add(
                    "crlf-rewrite-injection", "CRLF rewrite",
                    "Encoded line break becomes upstream HTTP structure", "critical", "high",
                    (front.evidence_id, back.evidence_id),
                    (f"downstream target={front.parsed.target!r}",
                     f"upstream target={back.parsed.target!r}",
                     f"encoded-input-correlated upstream fields={injected_headers!r}",
                     f"nested request bytes={nested}"),
                    ("encoded CR/LF enters rewrite", "normalization emits raw delimiter",
                     "upstream parser sees added HTTP structure"),
                    "Never interpolate decoded URI data into an upstream start-line/header; reject CR/LF.",
                )

    # Early final responses are meaningful even without connection reuse (the
    # DiceCTF pyramid state race), but reuse plus debt is a distinct escalation.
    for request in bundle.requests:
        cl = _content_length(request)
        for response in _early_final(bundle, request.evidence_id):
            add(
                "early-final-response", "early response",
                "Final response precedes completion of the declared request body", "high", "high",
                (request.evidence_id,),
                (f"status={response.parsed.status}",
                 f"Content-Length={cl!r}, body bytes seen={request.body_bytes_seen}"),
                ("headers accepted", "application emits final response", "request body remains incomplete"),
                "Do not expose mutable request state before body completion; drain or close on early final response.",
            )
            if (cl is not None and cl > request.body_bytes_seen
                    and _observed_reuse(bundle, request.evidence_id)):
                add(
                    "early-response-reuse", "early response",
                    "Reusable connection retains request body debt after a final response", "critical", "high",
                    (request.evidence_id,),
                    (f"outstanding bytes={cl - request.body_bytes_seen}",
                     f"connection={response.connection}", "final response and reuse are both observed"),
                    ("origin responds early", "H1 connection stays reusable",
                     "next request prefix can satisfy old body debt"),
                    "Close the upstream connection after an early final response with undrained body debt.",
                )

    # Expect is an ordered response state machine.  A normal 100 -> final
    # sequence intentionally produces no finding.
    for request in bundle.requests:
        expect_fields = tuple(
            field for field in request.parsed.headers
            if field.name.casefold() == "expect" and "100-continue" in field.value.casefold()
        )
        if not expect_fields:
            continue
        response_sequence = tuple(
            response for response in bundle.responses if response.request_id == request.evidence_id
        )
        statuses = tuple(response.parsed.status for response in response_sequence)
        final_positions = [index for index, status in enumerate(statuses) if status >= 200]
        late_continue = any(
            status == 100 and any(final_index < index for final_index in final_positions)
            for index, status in enumerate(statuses)
        )
        if late_continue:
            add(
                "expect-state-confusion", "Expect", "100 Continue appears after a final response",
                "high", "high", (request.evidence_id,),
                (f"ordered statuses={statuses!r}",),
                ("final response closes request state", "late interim block re-enters body state"),
                "Keep interim and final response state ordered and discard/close on a late 100 response.",
            )
        if any(field.raw_name != field.name or field.value.strip().casefold() != "100-continue"
               for field in expect_fields):
            add(
                "expect-obfuscated-trigger", "Expect", "Obfuscated 100-continue token reaches parsing",
                "medium", "high", (request.evidence_id,),
                tuple(f"line {field.line_number}: {field.raw_name!r}: {field.value!r}"
                      for field in expect_fields),
                ("non-canonical Expect spelling", "hops may enter different request-body states"),
                "Canonicalize or reject noncanonical Expect values consistently at the first hop.",
            )
        if _early_final(bundle, request.evidence_id) and _observed_reuse(bundle, request.evidence_id):
            add(
                "expect-early-final-reuse", "Expect",
                "Expect request receives an early final response on a reusable connection",
                "critical", "high", (request.evidence_id,),
                (f"ordered statuses={statuses!r}", "body incomplete at final response", "reuse observed"),
                ("Expect splits header/body phases", "backend sends non-100 final",
                 "front/upstream body state can diverge"),
                "Drain or close the connection and keep Expect state identical at every hop.",
            )

    # RFC 9112: HTTP/1.0 plus Transfer-Encoding is faulty and must close.
    for request in bundle.requests:
        if request.parsed.version == "HTTP/1.0" and _has_transfer_encoding(request):
            add(
                "h10-transfer-encoding-fault", "HTTP/1.0 TE",
                "HTTP/1.0 request carries Transfer-Encoding", "high", "high",
                (request.evidence_id,),
                (f"Transfer-Encoding={request.parsed.values('transfer-encoding')!r}",),
                ("HTTP/1.0 message contains TE", "framing is faulty by RFC 9112"),
                "Reject the message and close the connection after the response.",
            )
            if _observed_reuse(bundle, request.evidence_id):
                add(
                    "h10-transfer-encoding-reuse", "HTTP/1.0 TE",
                    "Faulty HTTP/1.0 Transfer-Encoding message is followed by reuse",
                    "critical", "high", (request.evidence_id,),
                    ("connection reuse is observed/configured despite faulty framing",),
                    ("recipient disagrees on H1.0 TE", "connection remains pooled",
                     "body bytes can become a later request"),
                    "Reject HTTP/1.0 Transfer-Encoding and never reuse that connection.",
                )

    # Response-only semantics applied to a request are only promoted when an
    # observed zero-framing decision/body discrepancy accompanies the header.
    for request in bundle.requests:
        content_types = tuple(value.casefold() for value in request.parsed.values("content-type"))
        response_semantics = (
            any("multipart/byteranges" in value for value in content_types)
            or bool(request.parsed.values("content-range"))
        )
        cl = _content_length(request)
        if (response_semantics and request.framing == "zero"
                and cl is not None and cl > request.body_bytes_seen):
            add(
                "shared-response-parser-confusion", "shared parser",
                "Response-only semantics alter request body framing", "critical", "high",
                (request.evidence_id,),
                (f"Content-Type={request.parsed.values('content-type')!r}",
                 f"Content-Range={request.parsed.values('content-range')!r}",
                 f"Content-Length={cl}, body bytes seen={request.body_bytes_seen}"),
                ("request enters shared parser", "response-only rule selects zero body",
                 "declared body becomes request-boundary residue"),
                "Separate request/response parsers and ignore response-only fields for request framing.",
            )
    for front, back in rewrite_pairs:
        content_types = tuple(value.casefold() for value in front.parsed.values("content-type"))
        response_semantics = (any("multipart/byteranges" in value for value in content_types)
                              or bool(front.parsed.values("content-range")))
        if response_semantics and back.framing == "zero" and front.framing in {
                "content-length", "transfer-encoding"}:
            add(
                "shared-response-parser-confusion", "shared parser",
                "Response-only semantics alter request body framing", "critical", "high",
                (front.evidence_id, back.evidence_id),
                (f"front framing={front.framing}", f"back framing={back.framing}",
                 f"Content-Type={front.parsed.values('content-type')!r}"),
                ("request enters shared parser", "response-only rule changes request framing",
                 "hops disagree on the request boundary"),
                "Separate request/response parsers and reject inconsistent framing before reuse.",
            )

    # Request-context response semantics and adjustable HEAD/Range gadgets.
    for request in bundle.requests:
        associated = tuple(response for response in bundle.responses
                           if response.request_id == request.evidence_id)
        finals = tuple(response for response in associated if response.parsed.status >= 200)
        if len(finals) > 1:
            add(
                "response-queue-surplus", "response parser",
                "One recorded request is assigned multiple final responses", "high", "high",
                (request.evidence_id,),
                (f"final statuses={tuple(item.parsed.status for item in finals)!r}",),
                ("one request association", "multiple final response blocks", "queue attribution may shift"),
                "Close on surplus response bytes and verify request/response queue accounting.",
            )
        for response in associated:
            status = response.parsed.status
            # 101 legitimately transitions to a different protocol after the
            # header block, so following tunnel bytes are not HTTP content.
            bodyless_status = (100 <= status < 200 and status != 101) or status in {204, 304}
            if bodyless_status and response.parsed.body:
                add(
                    "bodyless-response-overread", "response parser",
                    "Bodyless status is followed by bytes treated as response content", "high", "high",
                    (request.evidence_id,),
                    (f"status={status}", f"bytes after header block={len(response.parsed.body)}"),
                    ("bodyless response headers end", "additional bytes remain on response stream"),
                    "Use status-aware response framing and close on bytes beyond a bodyless response.",
                )
            if request.parsed.method == "HEAD" and response.parsed.body:
                nested_status = bool(re.search(rb"(?:^|\r\n)HTTP/(?:1\.[01]|2|3) [1-5][0-9]{2}",
                                               response.parsed.body))
                front_context = tuple(
                    front for front, back in rewrite_pairs
                    if back.evidence_id == request.evidence_id and front.parsed.method != "HEAD"
                )
                explicit_overread = any(
                    link.kind == "overread-into" and link.source == response.evidence_id
                    for link in bundle.links
                )
                if nested_status and (front_context or explicit_overread):
                    add(
                        "head-response-overread", "HEAD response",
                        "Later response bytes are consumed under mismatched HEAD context",
                        "critical", "high",
                        (*tuple(item.evidence_id for item in front_context), request.evidence_id),
                        (f"bytes after HEAD response headers={len(response.parsed.body)}",
                         "nested status line=true",
                         f"front-end non-HEAD context={bool(front_context)}",
                         f"explicit overread link={explicit_overread}"),
                        ("backend response is for HEAD", "front end associates a non-HEAD request",
                         "later status bytes fall inside apparent response debt"),
                        "Bind response framing to the originating request method and close on queue mismatch.",
                    )
            response_cl = response.parsed.values("content-length")
            if (request.parsed.method == "HEAD" and request.parsed.values("range")
                    and status == 206 and response.parsed.values("content-range")
                    and len(response_cl) == 1 and _DECIMAL.fullmatch(response_cl[0])):
                add(
                    "range-head-length-gadget", "HEAD/Range gadget",
                    "HEAD plus Range yields an adjustable advertised response length",
                    "medium", "high", (request.evidence_id,),
                    (f"Range={request.parsed.values('range')!r}",
                     f"Content-Range={response.parsed.values('content-range')!r}",
                     f"advertised Content-Length={response_cl[0]}"),
                    ("smuggled HEAD selects a range", "206 advertises chosen length",
                     "wrong-method response parser can over-read by that length"),
                    "Preserve request-method association and never treat HEAD metadata as response content.",
                )

    # Explicit response-attribution evidence is stronger than status anomalies.
    for link in bundle.links:
        if link.kind != "response-attributed-to":
            continue
        response = next(item for item in bundle.responses if item.evidence_id == link.source)
        if response.request_id != link.target:
            add(
                "response-attribution-shift", "response queue",
                "Observed response attribution differs from the front-end request assignment",
                "critical", "high", (response.request_id, link.target),
                (f"response {response.evidence_id} assigned={response.request_id}",
                 f"observed origin request={link.target}"),
                ("front-end response queue advances", "origin response belongs to a different request"),
                "Reset the connection on any queue mismatch and avoid shared HTTP/1 upstream pools.",
            )

    # H3 must reconcile Content-Length with DATA bytes before FIN.  Critical
    # H3->H1 debt additionally requires the Envoy advisory's early-response,
    # reuse, and next-request-consumption evidence.
    for request in bundle.requests:
        cl = _content_length(request)
        if (request.protocol == "h3" and request.end_stream and cl is not None
                and cl != request.body_bytes_seen):
            add(
                "h3-length-mismatch-at-fin", "H3 framing",
                "HTTP/3 stream ends with Content-Length/Data mismatch", "critical", "high",
                (request.evidence_id,),
                (f"Content-Length={cl}", f"DATA bytes={request.body_bytes_seen}", "end_stream=true"),
                ("H3 HEADERS declare length", "stream reaches FIN", "DATA total does not match"),
                "Reject the malformed H3 message before routing or protocol translation.",
            )
    for h3_request, h1_request in rewrite_pairs:
        if h3_request.protocol != "h3" or h1_request.protocol != "h1":
            continue
        h3_cl = _content_length(h3_request)
        h1_cl = _content_length(h1_request)
        debt = (h1_cl - h1_request.body_bytes_seen
                if h1_cl is not None and h1_cl > h1_request.body_bytes_seen else None)
        consumed = tuple(
            link for link in bundle.links
            if link.kind == "consumed-as-body"
            and link.target == h1_request.evidence_id
            and requests[link.source].protocol == "h1"
            and requests[link.source].connection == h1_request.connection
            and requests[link.source].sequence > h1_request.sequence
            and debt is not None
            and link.byte_count == debt
        )
        early = _early_final(bundle, h1_request.evidence_id)
        vulnerable_shape = (
            bundle.config.downstream_protocol == "h3"
            and bundle.config.upstream_protocol == "h1"
            and h3_request.end_stream
            and h3_cl is not None and h3_cl > h3_request.body_bytes_seen
            and h1_cl == h3_cl and h1_request.body_bytes_seen < h1_cl
            and bool(early) and _observed_reuse(bundle, h1_request.evidence_id)
            and bool(consumed)
        )
        if vulnerable_shape:
            add(
                "h3-h1-body-debt", "H3->H1 body debt",
                "Headers-only H3 completion becomes reusable H1 body debt", "critical", "high",
                (h3_request.evidence_id, h1_request.evidence_id,
                 *(link.source for link in consumed)),
                (f"H3 Content-Length={h3_cl}, DATA={h3_request.body_bytes_seen}, FIN=true",
                 f"H1 preserved Content-Length={h1_cl}", "early final response observed",
                 "next-request bytes observed paying the debt"),
                ("H3 HEADERS+FIN bypasses length reconciliation",
                 "translator finalizes H1 with stale nonzero CL", "origin responds early and reuses socket",
                 "next request prefix satisfies prior body debt"),
                "Reject inconsistent H3 lengths before downgrade; never reuse H1 with unresolved body debt.",
            )

    # A double desync is only classified when explicit evidence connects all
    # three stages: 0.CL debt, the resulting CL.0, and a contaminated victim.
    for zero_front, zero_back in zero_cl_pairs:
        if not _early_final(bundle, zero_back.evidence_id) or not _observed_reuse(
                bundle, zero_back.evidence_id):
            continue
        for cl_front, cl_back in cl_zero_pairs:
            if cl_back.connection != zero_back.connection:
                continue
            if cl_back.sequence <= zero_back.sequence:
                continue
            debt_linked = any(
                link.kind == "consumed-as-body"
                and link.source == cl_back.evidence_id
                and link.target == zero_back.evidence_id
                for link in bundle.links
            )
            victims = tuple(
                requests[link.target] for link in bundle.links
                if link.kind == "prefix-contaminates"
                and link.source == cl_back.evidence_id
                and requests[link.target].connection == cl_back.connection
                and requests[link.target].sequence > cl_back.sequence
            )
            if debt_linked and victims:
                add(
                    "double-desync-sequence", "double desync",
                    "0.CL debt converts a later request into CL.0 and contaminates a victim",
                    "critical", "high",
                    (zero_front.evidence_id, zero_back.evidence_id,
                     cl_front.evidence_id, cl_back.evidence_id,
                     *(victim.evidence_id for victim in victims)),
                    ("first pair is 0.CL with early reusable response",
                     "second pair is CL.0 on the same upstream connection",
                     "explicit consumed-as-body link connects both stages",
                     "explicit prefix-contaminates link reaches a later victim request"),
                    ("stage 1: 0.CL poisons connection", "stage 2: debt cuts into next request",
                     "stage 3: resulting CL.0 leaves a new prefix"),
                    "Eliminate the first parser differential and reset pooled H1 state after any early response.",
                )

    return tuple(findings[key] for key in sorted(findings))


def analyze_evidence(
    source: Mapping[str, Any] | str | bytes | bytearray | memoryview,
) -> tuple[DesyncStateFinding, ...]:
    """Classify supplied saved evidence; raise only :class:`DesyncEvidenceError`."""

    try:
        return _analyze(_parse_bundle(source))
    except DesyncEvidenceError:
        raise
    except Exception as exc:  # fail closed across all parser/shape mistakes
        raise DesyncEvidenceError(f"unable to analyze evidence: {exc}") from exc


def report_dict(source: Mapping[str, Any] | str | bytes | bytearray | memoryview) -> dict[str, Any]:
    """Return a deterministic JSON-ready report without reproducing raw bodies."""

    try:
        bundle = _parse_bundle(source)
        findings = _analyze(bundle)
        return {
            "schema": SCHEMA,
            "summary": {
                "request_records": len(bundle.requests),
                "response_records": len(bundle.responses),
                "links": len(bundle.links),
                "finding_count": len(findings),
            },
            "findings": [asdict(item) for item in findings],
            "offline": True,
            "network_requests": 0,
        }
    except DesyncEvidenceError:
        raise
    except Exception as exc:
        raise DesyncEvidenceError(f"unable to build report: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Classify saved HTTP desync request/response/config evidence offline"
    )
    parser.add_argument("evidence", help="v1 JSON evidence file, or - for stdin")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (TypeError, ValueError) as exc:
        print(f"wpgap_desync_state: invalid arguments: {exc}", file=sys.stderr)
        return 2
    try:
        if not isinstance(args.evidence, str):
            raise DesyncEvidenceError("evidence path must be text")
        if args.evidence == "-":
            raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        else:
            if "\x00" in args.evidence:
                raise DesyncEvidenceError("evidence path contains NUL")
            if len(args.evidence.encode("utf-8", "strict")) > MAX_PATH_BYTES:
                raise DesyncEvidenceError(f"evidence path exceeds {MAX_PATH_BYTES} bytes")
            with Path(args.evidence).open("rb") as evidence_file:
                raw = evidence_file.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise DesyncEvidenceError(f"JSON evidence exceeds {MAX_INPUT_BYTES} bytes")
        report = report_dict(raw)
    except (DesyncEvidenceError, OSError, TypeError, ValueError, UnicodeError) as exc:
        print(f"wpgap_desync_state: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0


__all__ = [
    "DesyncEvidenceError", "DesyncStateFinding", "MAX_INPUT_BYTES", "SCHEMA",
    "analyze_evidence", "main", "report_dict",
]


if __name__ == "__main__":
    raise SystemExit(main())
