"""Deterministic tests for the offline R5D request-boundary engine."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import http_smuggling as smuggle  # noqa: E402


def test_parser_preserves_duplicates_folding_and_raw_name_evidence():
    raw = (
        b"POST /submit HTTP/1.1\r\n"
        b"Host: app.test\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 8\r\n"
        b"Transfer-Encoding : chunked\r\n"
        b"\tidentity\r\n\r\n"
        b"0\r\n\r\nGET /next HTTP/1.1\r\n\r\n"
    )
    parsed = smuggle.parse_saved_request(raw)
    assert parsed.method == "POST" and parsed.target == "/submit"
    assert parsed.values("content-length") == ("5", "8")
    assert parsed.values("transfer-encoding") == ("chunked identity",)
    te = next(field for field in parsed.headers if field.name.casefold() == "transfer-encoding")
    assert te.raw_name == "Transfer-Encoding " and te.obs_folded is True
    assert any("whitespace adjacent" in item for item in parsed.anomalies)
    assert any("folded header" in item for item in parsed.anomalies)


def test_analysis_correlates_conflicting_framing_and_chunk_residue():
    body = b"0\r\n\r\nOPTIONS /inert HTTP/1.1\r\nHost: r5d.invalid\r\n\r\n"
    raw = (
        b"POST / HTTP/1.1\r\nHost: app.test\r\n"
        b"Content-Length: 5\r\nContent-Length: 57\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n" + body
    )
    findings = smuggle.analyze_saved_request(raw)
    by_id = {item.finding_id: item for item in findings}
    assert {
        "duplicate-content-length", "cl-te-coexist", "chunk-framing-residue",
        "content-length-mismatch",
    } <= set(by_id)
    assert by_id["cl-te-coexist"].severity == "critical"
    assert by_id["duplicate-content-length"].confidence == "high"
    assert "CL.TE/canonical" in by_id["cl-te-coexist"].related_variants
    assert any("bytes after terminator" in evidence
               for evidence in by_id["chunk-framing-residue"].evidence)


def test_analysis_flags_noncanonical_lengths_and_te_order():
    raw = (
        b"POST /x HTTP/1.1\r\nHost: app.test\r\n"
        b"Content-Length: +4\r\n"
        b"Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n"
    )
    by_id = {item.finding_id: item for item in smuggle.analyze_saved_request(raw)}
    assert "invalid-content-length" in by_id
    assert "obfuscated-transfer-encoding" in by_id
    assert "cl-te-coexist" in by_id


@pytest.mark.parametrize("te_value", [b" \tchunked", b" xchunked", b" chunked;bad=1"])
def test_transfer_encoding_ows_and_chunked_like_tokens_are_preserved_as_evidence(te_value):
    raw = (b"POST / HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding:" + te_value
           + b"\r\n\r\n0\r\n\r\n")
    parsed = smuggle.parse_saved_request(raw)
    field = next(item for item in parsed.headers if item.name.casefold() == "transfer-encoding")
    assert field.raw_value == te_value.decode("latin-1")
    ids = {item.finding_id for item in smuggle.analyze_saved_request(raw)}
    assert "obfuscated-transfer-encoding" in ids


def test_complete_chunked_body_with_trailer_has_no_residue_finding():
    body = b"3\r\nabc\r\n0\r\nX-Audit: inert\r\n\r\n"
    raw = (b"POST / HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n"
           + body)
    ids = {item.finding_id for item in smuggle.analyze_saved_request(raw)}
    assert "chunk-framing-residue" not in ids


def test_http2_downgrade_evidence_requires_saved_protocol_clues():
    raw = (
        b"POST /rpc HTTP/2\r\nHost: app.test\r\n"
        b"Connection: keep-alive\r\nTransfer-Encoding: chunked\r\n"
        b"Content-Length: 0\r\n\r\nabc"
    )
    findings = smuggle.analyze_saved_request(raw)
    by_id = {item.finding_id: item for item in findings}
    assert "h2-connection-specific-fields" in by_id
    assert "h2-content-length-downgrade" in by_id
    assert by_id["h2-connection-specific-fields"].family == "HTTP2-downgrade"
    assert by_id["h2-content-length-downgrade"].severity == "critical"


def test_textual_http2_pseudo_headers_parse_and_surface_authority_conflict():
    raw = (
        b":method: POST\n:path: /rpc\n:scheme: https\n:authority: edge.test\n"
        b"host: origin.test\nconnection: keep-alive\ncontent-length: 0\n\nabc"
    )
    parsed = smuggle.parse_saved_request(raw)
    assert parsed.version == "HTTP/2" and parsed.method == "POST" and parsed.target == "/rpc"
    assert parsed.values(":authority") == ("edge.test",)
    by_id = {item.finding_id: item for item in smuggle.analyze_saved_request(raw)}
    assert "h2-authority-host-conflict" in by_id
    assert "h2-connection-specific-fields" in by_id
    assert "h2-content-length-downgrade" in by_id


def test_http2_pseudo_header_order_and_duplicates_remain_evidence():
    raw = (
        b":method: POST\n:path: /one\nhost: edge.test\n:path: /two\n"
        b":authority: edge.test\n\n"
    )
    parsed = smuggle.parse_saved_request(raw)
    assert parsed.target == "/one"
    assert any("duplicate HTTP/2 pseudo-header :path" in item for item in parsed.anomalies)
    assert any("follows a regular field" in item for item in parsed.anomalies)
    ids = {item.finding_id for item in smuggle.analyze_saved_request(raw)}
    assert "h2-pseudo-header-ambiguity" in ids


def test_mixed_line_endings_are_parsed_but_never_silently_normalised():
    raw = (
        b"POST / HTTP/1.1\r\nHost: app.test\nContent-Length: 0\r\n\r\n"
    )
    parsed = smuggle.parse_saved_request(raw)
    assert parsed.line_ending == "MIXED"
    assert parsed.values("host") == ("app.test",)
    assert parsed.values("content-length") == ("0",)
    ids = {item.finding_id for item in smuggle.analyze_saved_request(raw)}
    assert "ambiguous-line-endings" in ids

    lf_only = b"POST / HTTP/1.1\nHost: app.test\nContent-Length: 0\n\n"
    lf_finding = next(item for item in smuggle.analyze_saved_request(lf_only)
                      if item.finding_id == "ambiguous-line-endings")
    assert any("LF-only" in evidence for evidence in lf_finding.evidence)


def test_variant_matrix_is_stable_inert_and_covers_all_requested_families():
    saved = b"GET /account HTTP/1.1\r\nHost: app.test\r\n\r\n"
    first = smuggle.build_variant_matrix(saved)
    second = smuggle.build_variant_matrix(saved)
    assert first == second
    assert [item.rank for item in first] == list(range(1, len(first) + 1))
    assert {item.family for item in first} == {
        "CL.TE", "TE.CL", "TE.TE", "HTTP2-downgrade",
    }
    assert {(item.family, item.name) for item in first} >= {
        ("CL.TE", "canonical"),
        ("TE.CL", "canonical"),
        ("TE.TE", "duplicate-order"),
        ("HTTP2-downgrade", "H2.CL"),
        ("HTTP2-downgrade", "H2.TE"),
    }
    assert len(first) <= smuggle.MAX_VARIANTS
    assert all(item.offline and item.network_requests == 0 for item in first)
    assert all("R5D-INERT-BOUNDARY" in item.request for item in first)
    assert all(item.prerequisite and item.front_end_view and item.back_end_view for item in first)

    # H2 variants are textual saved-capture forms and must parse back through
    # the offline analyzer rather than requiring an HTTP/2 implementation.
    for row in first:
        if row.protocol.startswith("HTTP/2"):
            parsed = smuggle.parse_saved_request(row.request)
            assert parsed.version == "HTTP/2"


def test_matrix_falls_back_to_reserved_host_for_ambiguous_capture():
    saved = (
        b"POST / HTTP/1.1\r\nHost: one.test\r\nHost: two.test\r\n\r\n"
    )
    rows = smuggle.build_variant_matrix(saved)
    assert all("Host: r5d-probe.invalid" in row.request or row.protocol.startswith("HTTP/2")
               for row in rows)
    assert all("one.test" not in row.request and "two.test" not in row.request for row in rows)

    h2_conflict = (
        b":method: POST\n:path: /\n:authority: edge.test\nhost: origin.test\n\n"
    )
    assert all("edge.test" not in row.request and "origin.test" not in row.request
               for row in smuggle.build_variant_matrix(h2_conflict))


def test_matrix_replaces_non_ascii_saved_target_instead_of_reemitting_it():
    saved = "POST /café HTTP/1.1\r\nHost: app.test\r\n\r\n"
    rows = smuggle.build_variant_matrix(saved)
    assert all("café" not in row.request for row in rows)


def test_parser_and_builder_fail_closed_on_bounds_and_controls():
    with pytest.raises(smuggle.SavedHTTPError, match="empty"):
        smuggle.parse_saved_request(b"")
    with pytest.raises(smuggle.SavedHTTPError, match="NUL"):
        smuggle.parse_saved_request(b"GET / HTTP/1.1\r\nX: a\x00b\r\n\r\n")
    with pytest.raises(smuggle.SavedHTTPError, match="request line"):
        smuggle.parse_saved_request(b"GET /missing-version\r\n\r\n")
    with pytest.raises(smuggle.SavedHTTPError, match="lacks :method"):
        smuggle.parse_saved_request(b":path: /\n\n")
    with pytest.raises(smuggle.SavedHTTPError, match="lacks :path"):
        smuggle.parse_saved_request(b":method: POST\n:authority: app.test\n\n")
    with pytest.raises(smuggle.SavedHTTPError, match="marker_path"):
        smuggle.build_variant_matrix(
            b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", marker_path="relative"
        )
    too_many = b"GET / HTTP/1.1\r\n" + b"X-A: x\r\n" * (smuggle.MAX_HEADERS + 1) + b"\r\n"
    with pytest.raises(smuggle.SavedHTTPError, match="header count"):
        smuggle.parse_saved_request(too_many)


def test_report_is_json_ready_and_retains_no_raw_body():
    raw = b"POST /x HTTP/1.1\r\nHost: app.test\r\nContent-Length: 3\r\n\r\nabc"
    report = smuggle.report_dict(raw)
    assert report["offline"] is True and report["network_requests"] == 0
    assert report["request"]["body_length"] == 3
    assert "body" not in report["request"]
    assert report == smuggle.report_dict(raw)


def test_module_has_no_transport_execution_or_deserialisation_surface():
    tree = ast.parse((WEB / "http_smuggling.py").read_text(encoding="utf-8"))
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    assert not imports.intersection({
        "socket", "requests", "http.client", "urllib.request", "subprocess", "pickle", "marshal",
    })
    assert not calls.intersection({
        "connect", "request", "send", "sendall", "urlopen", "loads", "load", "eval", "exec",
    })
