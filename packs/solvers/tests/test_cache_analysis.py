"""Deterministic tests for saved-traffic R5D cache analysis."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import cache_analysis as cache  # noqa: E402


def test_response_parser_preserves_duplicate_headers_and_body():
    raw = (
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\n"
        b"Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nprofile"
    )
    response = cache.parse_saved_response(raw)
    assert response.status == 200 and response.reason == "OK"
    assert response.values("set-cookie") == ("a=1", "b=2")
    assert response.body == b"profile"


def test_response_parser_records_mixed_line_endings_without_losing_fields():
    raw = (
        b"HTTP/1.1 200 OK\r\nCache-Control: public\nAge: 2\r\n\r\nbody"
    )
    response = cache.parse_saved_response(raw)
    assert response.values("cache-control") == ("public",)
    assert response.values("age") == ("2",)
    assert any("mixed CRLF and LF" in item for item in response.anomalies)


def test_poisoning_correlates_reflection_cache_key_and_cacheability():
    request = (
        b"GET /reset HTTP/1.1\r\nHost: app.test\r\n"
        b"X-Forwarded-Host: r5d-cache.invalid\r\n\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nCache-Control: public, s-maxage=120\r\n"
        b"Age: 8\r\nContent-Type: text/html\r\n\r\n"
        b"<a href='https://r5d-cache.invalid/reset'>reset</a>"
    )
    source = (
        'proxy_cache_key "$scheme$host$request_uri";\n'
        'absolute = request.headers["x-forwarded-host"] + request.path\n'
    )
    findings = cache.analyze_cache_poisoning(request, response, source=source)
    item = next(entry for entry in findings if entry.finding_id == "unkeyed-x-forwarded-host")
    assert item.family == "web-cache-poisoning"
    assert item.severity == "high" and item.confidence == "high"
    assert any("derived field value" in evidence for evidence in item.evidence)
    assert any("absent from shown cache-key" in evidence for evidence in item.evidence)
    assert any("Age header" in evidence for evidence in item.evidence)


def test_vary_accounting_keeps_evidence_but_reduces_claim_strength():
    request = (
        b"GET / HTTP/1.1\r\nHost: app.test\r\nX-Host: marker.invalid\r\n\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\n"
        b"Vary: X-Host\r\n\r\nhttps://marker.invalid/"
    )
    item = next(entry for entry in cache.analyze_cache_poisoning(request, response)
                if entry.finding_id == "unkeyed-x-host")
    assert item.severity == "medium" and item.confidence == "low"
    assert any("Vary accounts" in evidence for evidence in item.evidence)


def test_forwarded_subvalue_reflection_is_detected_without_matching_whole_field():
    request = (
        b"GET / HTTP/1.1\r\nHost: app.test\r\n"
        b"Forwarded: for=192.0.2.1;host=marker.invalid;proto=https\r\n\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\n\r\n"
        b"canonical=https://marker.invalid/"
    )
    item = next(entry for entry in cache.analyze_cache_poisoning(request, response)
                if entry.finding_id == "unkeyed-forwarded")
    assert any("marker.invalid" in evidence for evidence in item.evidence)


def test_absolute_authority_and_duplicate_host_are_explicit_findings():
    request = (
        b"GET http://marker.invalid/path HTTP/1.1\r\n"
        b"Host: app.test\r\nHost: other.test\r\n\r\n"
    )
    response = b"HTTP/1.1 301 Moved\r\nCache-Control: public\r\n\r\n"
    ids = {item.finding_id for item in cache.analyze_cache_poisoning(request, response)}
    assert {"absolute-host-conflict", "duplicate-host"} <= ids


def test_deception_requires_static_shape_and_personalisation_evidence():
    request = (
        b"GET /account%2favatar/r5d.css HTTP/1.1\r\nHost: app.test\r\n"
        b"Cookie: sid=opaque\r\n\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nCache-Control: public, s-maxage=90\r\nAge: 3\r\n"
        b"Set-Cookie: csrf=opaque\r\nContent-Type: text/html\r\n\r\n"
        b"<h1>Account profile</h1><span>email</span>"
    )
    source = "route = request.path_info; rewrite(route);"
    findings = cache.analyze_cache_deception(request, response, source=source)
    by_id = {item.finding_id: item for item in findings}
    primary = by_id["static-key-personalised-response"]
    assert primary.severity == "high" and primary.confidence == "high"
    assert any("normalisation boundary" in item for item in primary.evidence)
    assert any("Cookie" in item for item in primary.evidence)
    assert "suffix-content-type-mismatch" in by_id


def test_plain_public_asset_does_not_produce_deception_finding():
    request = b"GET /assets/site.css HTTP/1.1\r\nHost: app.test\r\n\r\n"
    response = (
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=600\r\n"
        b"Content-Type: text/css\r\n\r\nbody{}"
    )
    assert cache.analyze_cache_deception(request, response) == ()


def test_request_cookie_alone_does_not_claim_personalised_response():
    request = (
        b"GET /assets/app.css HTTP/1.1\r\nHost: app.test\r\nCookie: analytics=x\r\n\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=600\r\n"
        b"Content-Type: text/css\r\n\r\nbody{}"
    )
    assert cache.analyze_cache_deception(request, response) == ()


def test_response_only_marker_does_not_create_reflection_finding():
    request = b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n"
    response = (
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\n\r\n"
        b"R5D-INERT-MARKER"
    )
    findings = cache.analyze_cache_poisoning(request, response, marker="R5D-INERT-MARKER")
    assert "explicit-marker-reflection" not in {item.finding_id for item in findings}


def test_no_store_blocks_cacheability_confidence_for_reflection():
    request = (
        b"GET / HTTP/1.1\r\nHost: app.test\r\nX-Host: marker.invalid\r\n\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nAge: 3\r\n\r\nmarker.invalid"
    )
    item = next(entry for entry in cache.analyze_cache_poisoning(request, response)
                if entry.finding_id == "unkeyed-x-host")
    assert item.severity == "medium" and item.confidence == "low"
    assert any("blocks shared storage" in evidence for evidence in item.evidence)

    cdn_response = (
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=600\r\n"
        b"CDN-Cache-Control: no-store\r\nAge: 3\r\n\r\nmarker.invalid"
    )
    cdn_item = next(entry for entry in cache.analyze_cache_poisoning(request, cdn_response)
                    if entry.finding_id == "unkeyed-x-host")
    assert cdn_item.severity == "medium" and cdn_item.confidence == "low"


def test_response_comparison_reports_only_saved_differences():
    control = (
        b"HTTP/1.1 200 OK\r\nX-Cache: MISS\r\nContent-Type: text/plain\r\n\r\ncontrol"
    )
    candidate = (
        b"HTTP/1.1 200 OK\r\nX-Cache: HIT\r\nContent-Type: text/plain\r\n\r\n"
        b"R5D-INERT-MARKER"
    )
    result = cache.compare_saved_responses(control, candidate, marker="R5D-INERT-MARKER")
    assert result.marker_only_in_candidate is True
    assert result.status_changed is False
    assert result.body_changed is True and result.cache_headers_changed is True
    assert result.offline and result.network_requests == 0


def test_variant_catalogs_are_stable_bounded_and_inert():
    poison = cache.build_poisoning_variants("app.test", path="/account")
    deceive = cache.build_deception_variants("/account")
    assert poison == cache.build_poisoning_variants("app.test", path="/account")
    assert deceive == cache.build_deception_variants("/account")
    assert [row.rank for row in poison] == list(range(1, len(poison) + 1))
    assert [row.rank for row in deceive] == list(range(1, len(deceive) + 1))
    assert {row.name for row in poison} >= {
        "x-forwarded-host", "forwarded", "x-original-url", "absolute-authority", "fat-get-body",
    }
    assert {row.name for row in deceive} >= {
        "path-info", "encoded-question", "double-encoded-question", "dot-segment",
    }
    assert all(row.offline and row.network_requests == 0 and row.hypothesis for row in (*poison, *deceive))
    assert all("r5d-cache.invalid" in row.value for row in poison)
    assert len(poison) <= cache.MAX_VARIANTS and len(deceive) <= cache.MAX_VARIANTS


def test_combined_report_is_json_ready_stably_ordered():
    request = (
        b"GET /profile/r5d.css HTTP/1.1\r\nHost: app.test\r\n"
        b"Cookie: sid=x\r\nX-Host: r5d-cache.invalid\r\n\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=30\r\n"
        b"Content-Type: text/html\r\n\r\nprofile r5d-cache.invalid"
    )
    report = cache.analyze_cache_exchange(request, response, marker="r5d-cache.invalid")
    assert report == cache.analyze_cache_exchange(request, response, marker="r5d-cache.invalid")
    assert report["offline"] is True and report["network_requests"] == 0
    assert report["poisoning"] and report["deception"]
    assert [item["finding_id"] for item in report["poisoning"]] == sorted(
        item["finding_id"] for item in report["poisoning"]
    )


def test_inputs_fail_closed_without_decoding_or_transport():
    with pytest.raises(cache.CacheAnalysisError, match="status line"):
        cache.parse_saved_response(b"not-http\r\n\r\n")
    with pytest.raises(cache.CacheAnalysisError, match="marker"):
        cache.compare_saved_responses(
            b"HTTP/1.1 200 OK\r\n\r\na", b"HTTP/1.1 200 OK\r\n\r\nb", marker="bad\r\nvalue"
        )
    with pytest.raises(cache.CacheAnalysisError, match="host"):
        cache.build_poisoning_variants("bad host")
    with pytest.raises(cache.CacheAnalysisError, match="path"):
        cache.build_deception_variants("relative")
    with pytest.raises(cache.CacheAnalysisError, match="saved source"):
        cache.analyze_cache_poisoning(
            b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\n",
            source="x" * (cache.MAX_SOURCE_CHARS + 1),
        )


def test_module_has_no_network_execution_or_unsafe_deserialisation_surface():
    tree = ast.parse((WEB / "cache_analysis.py").read_text(encoding="utf-8"))
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
