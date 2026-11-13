#!/usr/bin/env python3
"""Offline HTTP request-boundary analysis and inert variant construction.

The functions in this module consume *saved* request bytes.  They never open a
socket, replay a request, or infer that a target is vulnerable merely because a
request has an unusual shape.  Candidate requests contain an explicit inert
marker and are intended for byte-level reasoning inside an assigned CTF
challenge.

The parser intentionally keeps duplicate fields and records malformed lines.
That is important for desynchronisation work: normalising a capture through a
dictionary would discard exactly the evidence under review.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Iterable, Sequence


MAX_CAPTURE_BYTES = 2 * 1024 * 1024
MAX_HEADERS = 512
MAX_HEADER_BYTES = 64 * 1024
MAX_VARIANTS = 32


class SavedHTTPError(ValueError):
    """Raised when saved traffic is missing, malformed, or exceeds a bound."""


@dataclass(frozen=True)
class HeaderField:
    """One saved header field, preserving duplicates and original spelling."""

    name: str
    value: str
    line_number: int
    raw_name: str
    obs_folded: bool = False
    raw_value: str = ""


@dataclass(frozen=True)
class SavedRequest:
    """A bounded, non-normalising representation of one saved HTTP request."""

    method: str
    target: str
    version: str
    headers: tuple[HeaderField, ...]
    body: bytes
    line_ending: str
    anomalies: tuple[str, ...]

    def values(self, name: str) -> tuple[str, ...]:
        wanted = name.casefold()
        return tuple(field.value for field in self.headers
                     if field.name.casefold() == wanted)


@dataclass(frozen=True)
class SmugglingFinding:
    """Evidence from a saved request; never a claim of exploitability."""

    finding_id: str
    family: str
    title: str
    severity: str
    confidence: str
    evidence: tuple[str, ...]
    related_variants: tuple[str, ...]
    remediation: str


@dataclass(frozen=True)
class SmugglingVariant:
    """An inert parser-disagreement shape represented as text, not sent."""

    rank: int
    family: str
    name: str
    protocol: str
    request: str
    front_end_view: str
    back_end_view: str
    prerequisite: str
    marker: str = "R5D-INERT-BOUNDARY"
    offline: bool = True
    network_requests: int = 0


_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_METHOD = re.compile(r"^[A-Z!#$%&'*+.^_`|~-]{1,32}$")
_VERSION = re.compile(r"^HTTP/(?:0\.9|1\.0|1\.1|2(?:\.0)?|3(?:\.0)?)$", re.I)


def _capture_bytes(raw: str | bytes | bytearray | memoryview) -> bytes:
    if isinstance(raw, str):
        try:
            data = raw.encode("latin-1", "strict")
        except UnicodeError as exc:
            raise SavedHTTPError("saved request contains non-Latin-1 text") from exc
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        try:
            data = bytes(raw)
        except (ValueError, TypeError) as exc:
            raise SavedHTTPError("saved request bytes are unavailable") from exc
    else:
        raise SavedHTTPError("saved request must be text or bytes")
    if not data:
        raise SavedHTTPError("saved request is empty")
    if len(data) > MAX_CAPTURE_BYTES:
        raise SavedHTTPError(f"saved request exceeds {MAX_CAPTURE_BYTES} bytes")
    if b"\x00" in data:
        raise SavedHTTPError("saved request contains NUL")
    return data


def _split_head(data: bytes) -> tuple[bytes, bytes, bytes, list[str]]:
    anomalies: list[str] = []
    crlf = data.find(b"\r\n\r\n")
    lf = data.find(b"\n\n")
    if crlf >= 0 and (lf < 0 or crlf <= lf):
        head, body, ending = data[:crlf], data[crlf + 4:], b"\r\n"
    elif lf >= 0:
        head, body, ending = data[:lf], data[lf + 2:], b"\n"
        anomalies.append("LF-only header framing")
    else:
        head, body, ending = data, b"", b"\r\n"
        anomalies.append("missing blank line between headers and body")
    if len(head) > MAX_HEADER_BYTES:
        raise SavedHTTPError(f"header block exceeds {MAX_HEADER_BYTES} bytes")
    return head, body, ending, anomalies


def parse_saved_request(raw: str | bytes | bytearray | memoryview) -> SavedRequest:
    """Parse one raw saved HTTP request without merging duplicate headers."""

    data = _capture_bytes(raw)
    head, body, ending, anomalies = _split_head(data)
    has_crlf = b"\r\n" in head
    without_crlf = head.replace(b"\r\n", b"")
    has_bare_lf = b"\n" in without_crlf
    if has_crlf and has_bare_lf:
        anomalies.append("mixed CRLF and LF header line endings")
        line_style = "MIXED"
    else:
        line_style = "CRLF" if ending == b"\r\n" else "LF"
    normalised_head = head.replace(b"\r\n", b"\n")
    if b"\r" in normalised_head:
        anomalies.append("bare CR in header block")
    lines = normalised_head.split(b"\n")
    if not lines or not lines[0]:
        raise SavedHTTPError("request line is missing")

    # Text exports from H2 tooling commonly contain pseudo-headers rather than
    # a synthetic request line.  Parse that representation explicitly so an
    # H2 downgrade hypothesis can be derived from the supplied capture without
    # decoding HPACK or executing a protocol stack.
    if lines[0].startswith(b":"):
        fields: list[HeaderField] = []
        pseudo: dict[str, list[str]] = {}
        regular_seen = False
        for number, raw_line in enumerate(lines, 1):
            if len(fields) >= MAX_HEADERS:
                raise SavedHTTPError(f"header count exceeds {MAX_HEADERS}")
            line = raw_line.decode("latin-1")
            if line.startswith(":"):
                match = re.fullmatch(r":([a-z0-9-]+)(?::[ \t]*|[ \t]+)(.*)", line)
                if not match:
                    anomalies.append(f"malformed HTTP/2 pseudo-header at line {number}")
                    continue
                name = ":" + match.group(1)
                value = match.group(2)
                if regular_seen:
                    anomalies.append(f"HTTP/2 pseudo-header {name} follows a regular field")
                if any(ord(ch) < 32 and ch != "\t" for ch in value):
                    anomalies.append(f"HTTP/2 pseudo-header {name} contains a control character")
                fields.append(HeaderField(name, value, number, name, raw_value=value))
                pseudo.setdefault(name, []).append(value)
                continue
            regular_seen = True
            if line.startswith((" ", "\t")):
                anomalies.append(f"obsolete folded HTTP/2 field at line {number}")
                continue
            if ":" not in line:
                anomalies.append(f"header line {number} has no colon")
                continue
            raw_name, value_text = line.split(":", 1)
            name = raw_name.strip(" \t")
            raw_value = value_text
            value = raw_value.strip(" \t")
            if not name:
                anomalies.append(f"header line {number} has an empty name")
                continue
            if not _TOKEN.fullmatch(name):
                anomalies.append(f"header {number} has a non-token name")
            if raw_name != name:
                anomalies.append(f"header {number} has whitespace adjacent to its name")
            fields.append(HeaderField(name, value, number, raw_name, raw_value=raw_value))

        for name, values in pseudo.items():
            if len(values) > 1:
                anomalies.append(f"duplicate HTTP/2 pseudo-header {name}")
        methods = pseudo.get(":method", [])
        paths = pseudo.get(":path", [])
        if not methods:
            raise SavedHTTPError("HTTP/2 pseudo-header capture lacks :method")
        method = methods[0]
        if not _METHOD.fullmatch(method):
            anomalies.append("non-canonical HTTP/2 :method token")
        if paths:
            target = paths[0]
        elif method.upper() == "CONNECT":
            target = pseudo.get(":authority", ["/"])[0]
            anomalies.append("CONNECT capture has no :path")
        else:
            raise SavedHTTPError("HTTP/2 pseudo-header capture lacks :path")
        if any(ch in target for ch in "\r\n\x00"):
            raise SavedHTTPError("HTTP/2 :path contains a control delimiter")
        return SavedRequest(
            method=method,
            target=target,
            version="HTTP/2",
            headers=tuple(fields),
            body=body,
            line_ending=line_style,
            anomalies=tuple(dict.fromkeys(anomalies)),
        )

    try:
        request_line = lines[0].decode("latin-1")
    except UnicodeError as exc:  # latin-1 is total, retained for defensive clarity
        raise SavedHTTPError("request line is not decodable") from exc
    parts = request_line.split(" ")
    if len(parts) != 3 or not all(parts):
        raise SavedHTTPError("request line must contain method, target, and version")
    method, target, version = parts
    if not _METHOD.fullmatch(method):
        anomalies.append("non-canonical request method token")
    if not _VERSION.fullmatch(version):
        anomalies.append("unrecognised HTTP version token")
    if any(ch in target for ch in "\r\n\x00"):
        raise SavedHTTPError("request target contains a control delimiter")

    fields: list[HeaderField] = []
    for number, raw_line in enumerate(lines[1:], 2):
        if len(fields) >= MAX_HEADERS:
            raise SavedHTTPError(f"header count exceeds {MAX_HEADERS}")
        line = raw_line.decode("latin-1")
        if line.startswith((" ", "\t")):
            if not fields:
                anomalies.append(f"orphan folded line at {number}")
                continue
            prior = fields[-1]
            fields[-1] = HeaderField(
                prior.name,
                prior.value + " " + line.lstrip(" \t"),
                prior.line_number,
                prior.raw_name,
                True,
                prior.raw_value + "\r\n" + line,
            )
            anomalies.append(f"obsolete folded header beginning at {prior.line_number}")
            continue
        if b":" not in raw_line:
            anomalies.append(f"header line {number} has no colon")
            continue
        name_b, value_b = raw_line.split(b":", 1)
        raw_name = name_b.decode("latin-1")
        raw_value = value_b.decode("latin-1")
        value = raw_value.strip(" \t")
        name = raw_name.strip(" \t")
        if not name:
            anomalies.append(f"header line {number} has an empty name")
            continue
        if not _TOKEN.fullmatch(name):
            anomalies.append(f"header {number} has a non-token name")
        if raw_name != name:
            anomalies.append(f"header {number} has whitespace adjacent to its name")
        if any(ord(ch) < 32 and ch != "\t" for ch in value):
            anomalies.append(f"header {number} contains a control character")
        fields.append(HeaderField(name, value, number, raw_name, raw_value=raw_value))
    return SavedRequest(
        method=method,
        target=target,
        version=version.upper(),
        headers=tuple(fields),
        body=body,
        line_ending=line_style,
        anomalies=tuple(dict.fromkeys(anomalies)),
    )


def _parse_decimal_lengths(values: Sequence[str]) -> tuple[list[int], list[str]]:
    parsed: list[int] = []
    errors: list[str] = []
    for value in values:
        stripped = value.strip(" \t")
        if not re.fullmatch(r"[0-9]+", stripped):
            errors.append(repr(value))
            continue
        parsed.append(int(stripped, 10))
    return parsed, errors


def _transfer_tokens(values: Sequence[str]) -> tuple[str, ...]:
    tokens: list[str] = []
    for value in values:
        tokens.extend(piece.strip(" \t").casefold() for piece in value.split(","))
    return tuple(tokens)


def _chunked_shape(body: bytes) -> tuple[bool, int, str]:
    """Boundedly parse chunk framing and report bytes left after the terminator."""

    cursor = 0
    chunks = 0
    while cursor < len(body) and chunks < 4096:
        end = body.find(b"\r\n", cursor, min(len(body), cursor + 8194))
        if end < 0:
            return False, len(body) - cursor, "chunk-size line has no CRLF"
        size_token = body[cursor:end].split(b";", 1)[0].strip()
        if not size_token or not re.fullmatch(rb"[0-9A-Fa-f]+", size_token):
            return False, len(body) - cursor, "invalid chunk-size token"
        size = int(size_token, 16)
        cursor = end + 2
        if size == 0:
            # Accept a normal empty trailer block.  Non-empty trailers are
            # consumed until CRLFCRLF and any remaining bytes are residue.
            if body[cursor:cursor + 2] == b"\r\n":
                cursor += 2
            else:
                trailer_end = body.find(b"\r\n\r\n", cursor)
                if trailer_end < 0:
                    return False, len(body) - cursor, "zero chunk lacks trailer terminator"
                cursor = trailer_end + 4
            return True, len(body) - cursor, "complete chunk framing"
        data_end = cursor + size
        if data_end + 2 > len(body) or body[data_end:data_end + 2] != b"\r\n":
            return False, max(0, len(body) - cursor), "chunk data is truncated or lacks CRLF"
        cursor = data_end + 2
        chunks += 1
    return False, max(0, len(body) - cursor), "chunk count/length bound reached"


def analyze_saved_request(raw: str | bytes | bytearray | memoryview) -> tuple[SmugglingFinding, ...]:
    """Return stable request-boundary findings from one saved request."""

    request = parse_saved_request(raw)
    cl = request.values("content-length")
    te = request.values("transfer-encoding")
    findings: list[SmugglingFinding] = []

    def add(finding_id: str, family: str, title: str, severity: str,
            confidence: str, evidence: Iterable[str], variants: Sequence[str],
            remediation: str) -> None:
        findings.append(SmugglingFinding(
            finding_id, family, title, severity, confidence,
            tuple(evidence), tuple(variants), remediation,
        ))

    parsed_cl, invalid_cl = _parse_decimal_lengths(cl)
    if ((request.line_ending == "MIXED"
         or (request.line_ending == "LF" and not request.version.startswith(("HTTP/2", "HTTP/3")))
         or any("bare CR" in item for item in request.anomalies))):
        add(
            "ambiguous-line-endings", "HTTP-line-framing", "Non-canonical HTTP header line framing",
            "high", "high", tuple(item for item in request.anomalies
                                    if "line ending" in item or "LF-only" in item or "bare CR" in item),
            ("TE.TE/obs-fold",),
            "Reject mixed CRLF/LF or bare-CR framing at the first HTTP hop.",
        )
    if invalid_cl:
        add(
            "invalid-content-length", "CL", "Non-decimal Content-Length spelling",
            "high", "high", (f"unparseable values: {', '.join(invalid_cl)}",),
            ("CL.TE/canonical", "TE.CL/canonical"),
            "Reject non-canonical Content-Length fields at the first hop.",
        )
    if len(cl) > 1:
        conflict = len(set(parsed_cl)) > 1 or bool(invalid_cl)
        add(
            "duplicate-content-length", "CL", "Duplicate Content-Length fields",
            "high" if conflict else "medium", "high",
            (f"{len(cl)} fields preserved", f"values: {cl!r}",
             "values conflict" if conflict else "values are textually/semantically compatible"),
            ("CL.TE/duplicate-cl-first", "TE.CL/duplicate-cl-last"),
            "Accept exactly one canonical Content-Length or reject the request.",
        )
    if cl and te:
        add(
            "cl-te-coexist", "CL.TE/TE.CL", "Content-Length and Transfer-Encoding coexist",
            "critical", "high", (f"Content-Length: {cl!r}", f"Transfer-Encoding: {te!r}"),
            ("CL.TE/canonical", "TE.CL/canonical", "TE.TE/duplicate-order"),
            "Reject requests containing both framing mechanisms; normalise once before routing.",
        )

    te_tokens = _transfer_tokens(te)
    if len(te) > 1:
        add(
            "duplicate-transfer-encoding", "TE.TE", "Duplicate Transfer-Encoding fields",
            "high", "high", (f"{len(te)} fields preserved", f"tokens: {te_tokens!r}"),
            ("TE.TE/duplicate-order", "TE.TE/duplicate-identity"),
            "Reject duplicate Transfer-Encoding fields at the edge.",
        )
    if te:
        raw_te_fields = [field for field in request.headers
                         if field.name.casefold() == "transfer-encoding"]
        def unusual_ows(field: HeaderField) -> bool:
            leading_length = len(field.raw_value) - len(field.raw_value.lstrip(" \t"))
            leading = field.raw_value[:leading_length]
            return leading not in {"", " "} or field.raw_value.endswith((" ", "\t"))

        obfuscated = [field for field in raw_te_fields
                      if field.raw_name != field.name or field.obs_folded
                      or unusual_ows(field)]
        suspicious_tokens = tuple(token for token in te_tokens
                                  if "chunked" in token and token != "chunked")
        if (obfuscated or suspicious_tokens or "" in te_tokens
                or ("chunked" in te_tokens and te_tokens[-1] != "chunked")):
            details = [f"tokens: {te_tokens!r}"]
            if suspicious_tokens:
                details.append(f"non-canonical chunked-like tokens: {suspicious_tokens!r}")
            details.extend(f"line {field.line_number}: {field.raw_name!r}: {field.value!r}"
                           for field in obfuscated)
            add(
                "obfuscated-transfer-encoding", "TE.TE", "Ambiguous Transfer-Encoding normalisation",
                "high", "high", details,
                ("TE.TE/name-ows", "TE.TE/value-tab", "TE.TE/comma-order"),
                "Reject whitespace-obfuscated, folded, empty, or non-final chunked codings.",
            )
        if "chunked" in te_tokens:
            complete, residue, note = _chunked_shape(request.body)
            if not complete or residue:
                add(
                    "chunk-framing-residue", "TE", "Chunk framing is invalid or leaves request-like residue",
                    "high", "high" if residue else "medium",
                    (note, f"body bytes: {len(request.body)}", f"bytes after terminator: {residue}"),
                    ("CL.TE/canonical", "TE.TE/duplicate-order"),
                    "Require a single strict chunk parser and close the connection on any residue/error.",
                )

    if parsed_cl and len(request.body) not in set(parsed_cl):
        add(
            "content-length-mismatch", "CL", "Captured body length differs from Content-Length",
            "high", "high", (f"declared values: {tuple(parsed_cl)!r}",
                              f"captured: {len(request.body)}"),
            ("CL.TE/canonical", "TE.CL/canonical"),
            "Verify the capture is complete, then reject truncated or overlong bodies.",
        )

    if request.version.startswith(("HTTP/2", "HTTP/3")):
        pseudo_anomalies = tuple(item for item in request.anomalies if "pseudo-header" in item)
        if pseudo_anomalies:
            add(
                "h2-pseudo-header-ambiguity", "HTTP2-downgrade",
                "HTTP/2 pseudo-header ordering or duplication is ambiguous", "high", "high",
                pseudo_anomalies,
                ("HTTP2-downgrade/connection-field",),
                "Require each mandatory pseudo-header exactly once and before all regular fields.",
            )
        authorities = request.values(":authority")
        hosts = request.values("host")
        if authorities and hosts and {item.casefold() for item in authorities} != {
                item.casefold() for item in hosts}:
            add(
                "h2-authority-host-conflict", "HTTP2-downgrade",
                "HTTP/2 :authority conflicts with a Host field", "critical", "high",
                (f":authority values: {authorities!r}", f"Host values: {hosts!r}"),
                ("HTTP2-downgrade/H2.CL", "HTTP2-downgrade/H2.TE"),
                "Reject Host/:authority disagreement before translating to HTTP/1.",
            )
        forbidden = tuple(field.name for field in request.headers
                          if field.name.casefold() in {"connection", "keep-alive", "proxy-connection",
                                                       "transfer-encoding", "upgrade"})
        if forbidden:
            add(
                "h2-connection-specific-fields", "HTTP2-downgrade",
                "HTTP/2+ capture contains connection-specific framing fields", "critical", "high",
                (f"version: {request.version}", f"forbidden fields: {forbidden!r}"),
                ("HTTP2-downgrade/H2.TE", "HTTP2-downgrade/connection-field"),
                "Strip/reject connection-specific fields before any HTTP/1 downgrade.",
            )
        if parsed_cl and parsed_cl[0] != len(request.body):
            add(
                "h2-content-length-downgrade", "HTTP2-downgrade",
                "HTTP/2 DATA length conflicts with Content-Length", "critical", "high",
                (f"declared: {parsed_cl[0]}", f"captured DATA bytes: {len(request.body)}"),
                ("HTTP2-downgrade/H2.CL",),
                "Enforce HTTP/2 message length before translating to HTTP/1.",
            )

    return tuple(findings)


def _safe_component(value: str, label: str, *, limit: int) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise SavedHTTPError(f"{label} must be 1..{limit} characters")
    if any(ord(ch) < 33 or ord(ch) > 126 or ch in "\r\n\x00" for ch in value):
        raise SavedHTTPError(f"{label} contains non-ASCII whitespace/control data")
    return value


def _host_from(request: SavedRequest) -> str:
    values = request.values("host")
    authorities = request.values(":authority")
    if authorities:
        coherent = (len(authorities) == 1 and
                    (not values or {item.casefold() for item in values} ==
                     {authorities[0].casefold()}))
        if coherent:
            candidate = authorities[0]
            if re.fullmatch(r"[A-Za-z0-9._:\[\]-]{1,253}", candidate):
                return candidate
        return "r5d-probe.invalid"
    if len(values) == 1:
        candidate = values[0]
        if re.fullmatch(r"[A-Za-z0-9._:\[\]-]{1,253}", candidate):
            return candidate
    return "r5d-probe.invalid"


def _h1(method: str, target: str, host: str,
        headers: Sequence[tuple[str, str]], body: bytes) -> str:
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    return "\r\n".join(lines) + "\r\n\r\n" + body.decode("latin-1")


def build_variant_matrix(raw: str | bytes | bytearray | memoryview, *,
                         marker_path: str = "/__r5d_inert_boundary__") -> tuple[SmugglingVariant, ...]:
    """Build a deterministic CL.TE/TE.CL/TE.TE/H2 matrix from saved traffic.

    The result is inert text.  It deliberately exposes parser assumptions and
    has no replay helper.  The host falls back to the reserved ``.invalid`` TLD
    when the capture has no single safe Host field.
    """

    saved = parse_saved_request(raw)
    marker_path = _safe_component(marker_path, "marker_path", limit=1024)
    if not marker_path.startswith("/"):
        raise SavedHTTPError("marker_path must start with /")
    try:
        checked_target = _safe_component(saved.target, "saved target", limit=4096)
    except SavedHTTPError:
        checked_target = "/"
    target = checked_target if checked_target.startswith("/") else "/"
    host = _host_from(saved)
    method = saved.method if _METHOD.fullmatch(saved.method) else "POST"
    if method in {"GET", "HEAD", "TRACE", "OPTIONS"}:
        method = "POST"
    inner = _h1("OPTIONS", marker_path, "r5d-probe.invalid",
                (("X-R5D-Marker", "R5D-INERT-BOUNDARY"), ("Connection", "close")), b"").encode("latin-1")
    zero_then_inner = b"0\r\n\r\n" + inner
    chunk_prefix = f"{len(inner):x}\r\n".encode("ascii")
    chunked_inner = chunk_prefix + inner + b"\r\n0\r\n\r\n"
    rows: list[SmugglingVariant] = []

    def add(family: str, name: str, protocol: str, request_text: str,
            front: str, back: str, prerequisite: str) -> None:
        rows.append(SmugglingVariant(len(rows) + 1, family, name, protocol,
                                     request_text, front, back, prerequisite))

    add(
        "CL.TE", "canonical", "HTTP/1.1",
        _h1(method, target, host,
            (("Content-Length", str(len(zero_then_inner))), ("Transfer-Encoding", "chunked"),
             ("Connection", "keep-alive")), zero_then_inner),
        "uses Content-Length and consumes the complete body",
        "uses chunked framing and stops at the zero chunk",
        "front and back select different framing fields",
    )
    add(
        "CL.TE", "te-name-ows", "HTTP/1.1",
        _h1(method, target, host,
            (("Content-Length", str(len(zero_then_inner))), ("Transfer-Encoding ", "chunked")),
            zero_then_inner),
        "ignores the whitespace-suffixed header name and uses Content-Length",
        "trims the name and uses chunked framing",
        "hops normalise whitespace adjacent to header names differently",
    )
    add(
        "CL.TE", "duplicate-cl-first", "HTTP/1.1",
        _h1(method, target, host,
            (("Content-Length", str(len(zero_then_inner))), ("Content-Length", "5"),
             ("Transfer-Encoding", "chunked")), zero_then_inner),
        "selects the first Content-Length",
        "selects Transfer-Encoding after duplicate-field normalisation",
        "hops handle duplicate Content-Length and TE precedence differently",
    )

    prefix_length = len(chunk_prefix)
    add(
        "TE.CL", "canonical", "HTTP/1.1",
        _h1(method, target, host,
            (("Content-Length", str(prefix_length)), ("Transfer-Encoding", "chunked")), chunked_inner),
        "uses chunked framing and consumes the chunk plus terminator",
        "uses Content-Length and consumes only the chunk-size line",
        "front and back select different framing fields",
    )
    add(
        "TE.CL", "value-tab", "HTTP/1.1",
        _h1(method, target, host,
            (("Content-Length", str(prefix_length)), ("Transfer-Encoding", "\tchunked")), chunked_inner),
        "trims optional whitespace and uses chunked framing",
        "does not recognise the tab-prefixed coding and uses Content-Length",
        "hops normalise leading transfer-coding whitespace differently",
    )
    add(
        "TE.CL", "duplicate-cl-last", "HTTP/1.1",
        _h1(method, target, host,
            (("Transfer-Encoding", "chunked"), ("Content-Length", "0"),
             ("Content-Length", str(prefix_length))), chunked_inner),
        "uses Transfer-Encoding after rejecting/merging duplicate lengths",
        "selects the final Content-Length",
        "hops apply duplicate-field selection and TE precedence differently",
    )

    add(
        "TE.TE", "duplicate-order", "HTTP/1.1",
        _h1(method, target, host,
            (("Content-Length", str(len(zero_then_inner))), ("Transfer-Encoding", "identity"),
             ("Transfer-Encoding", "chunked")), zero_then_inner),
        "selects the first/combined coding and falls back to Content-Length",
        "selects the final chunked field",
        "hops choose different duplicate Transfer-Encoding occurrences",
    )
    add(
        "TE.TE", "duplicate-identity", "HTTP/1.1",
        _h1(method, target, host,
            (("Content-Length", str(len(zero_then_inner))), ("Transfer-Encoding", "chunked"),
             ("Transfer-Encoding", "identity")), zero_then_inner),
        "selects the first chunked field",
        "selects identity/falls back to Content-Length",
        "hops choose different duplicate Transfer-Encoding occurrences",
    )
    add(
        "TE.TE", "comma-order", "HTTP/1.1",
        _h1(method, target, host,
            (("Content-Length", str(len(zero_then_inner))),
             ("Transfer-Encoding", "chunked, identity")), zero_then_inner),
        "recognises chunked anywhere in a coding list",
        "requires chunked to be final and falls back to Content-Length",
        "hops validate transfer-coding order differently",
    )
    add(
        "TE.TE", "obs-fold", "HTTP/1.1",
        _h1(method, target, host,
            (("Content-Length", str(len(zero_then_inner))),
             ("Transfer-Encoding", "chunked\r\n\tidentity")), zero_then_inner),
        "unfolds the field into a coding list",
        "parses the first physical line as chunked",
        "hops disagree on obsolete line folding",
    )

    h2_cl = (f":method: {method}\n:path: {target}\n:scheme: https\n:authority: {host}\n"
             "content-length: 0\n\n" + inner.decode("latin-1"))
    add(
        "HTTP2-downgrade", "H2.CL", "HTTP/2 textual capture",
        h2_cl,
        "accepts DATA bytes independently of the declared length",
        "downgrades to HTTP/1 with Content-Length: 0 and reuses the remainder",
        "the H2 endpoint fails to enforce Content-Length before downgrade",
    )
    h2_te = (f":method: {method}\n:path: {target}\n:scheme: https\n:authority: {host}\n"
             "transfer-encoding: chunked\n\n" + zero_then_inner.decode("latin-1"))
    add(
        "HTTP2-downgrade", "H2.TE", "HTTP/2 textual capture",
        h2_te,
        "accepts or hides a forbidden Transfer-Encoding field",
        "forwards the field into HTTP/1 and applies chunk framing",
        "a forbidden HTTP/2 connection-specific field survives downgrade",
    )
    h2_connection = (f":method: {method}\n:path: {target}\n:scheme: https\n:authority: {host}\n"
                     "connection: transfer-encoding\ntransfer-encoding: chunked\n\n"
                     + zero_then_inner.decode("latin-1"))
    add(
        "HTTP2-downgrade", "connection-field", "HTTP/2 textual capture",
        h2_connection,
        "uses Connection to suppress a hop-by-hop field",
        "downgrades both fields and enables HTTP/1 chunk framing",
        "connection-specific HTTP/2 fields are not rejected before translation",
    )

    if len(rows) > MAX_VARIANTS:  # defensive invariant
        raise SavedHTTPError("variant bound exceeded")
    return tuple(rows)


def report_dict(raw: str | bytes | bytearray | memoryview) -> dict[str, object]:
    """Return a JSON-ready, deterministic offline report."""

    request = parse_saved_request(raw)
    return {
        "request": {
            "method": request.method,
            "target": request.target,
            "version": request.version,
            "headers": [asdict(field) for field in request.headers],
            "body_length": len(request.body),
            "line_ending": request.line_ending,
            "anomalies": list(request.anomalies),
        },
        "findings": [asdict(item) for item in analyze_saved_request(raw)],
        "variants": [asdict(item) for item in build_variant_matrix(raw)],
        "offline": True,
        "network_requests": 0,
    }


__all__ = [
    "HeaderField", "MAX_CAPTURE_BYTES", "MAX_HEADERS", "MAX_VARIANTS",
    "SavedHTTPError", "SavedRequest", "SmugglingFinding", "SmugglingVariant",
    "analyze_saved_request", "build_variant_matrix", "parse_saved_request", "report_dict",
]
