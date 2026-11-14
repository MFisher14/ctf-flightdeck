"""Tests for offline CRLF/redirect/host/CORS/CSWSH helpers."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import header_browser_analysis as browser  # noqa: E402


def test_candidate_matrix_is_stable_reserved_and_inert():
    crlf = browser.crlf_payloads("ROUND5", "X-R5D-Test")
    redirect = browser.open_redirect_payloads("redirect.r5d.invalid", "ROUND5")
    host = browser.host_header_payloads("host.r5d.invalid")
    assert [row.name for row in crlf] == [
        "percent_crlf",
        "percent_lf",
        "percent_cr",
        "double_percent_crlf",
        "mixed_case_hex",
        "unicode_escape_text",
        "raw_control",
    ]
    assert crlf[0].value == "%0d%0aX-R5D-Test: ROUND5"
    assert crlf[-1].value == "\r\nX-R5D-Test: ROUND5"
    assert [row.name for row in redirect] == [
        "absolute_https",
        "scheme_relative",
        "triple_slash",
        "backslash_authority",
        "mixed_slashes",
        "encoded_slashes",
        "double_encoded_slashes",
        "userinfo_decoy",
        "trusted_fragment_decoy",
        "scheme_without_slashes",
    ]
    assert redirect[0].value == "https://redirect.r5d.invalid/ROUND5"
    assert redirect[7].value == "https://trusted.invalid@redirect.r5d.invalid/ROUND5"
    assert [row.location for row in host[:3]] == ["Host", "X-Forwarded-Host", "X-Original-Host"]
    assert host[-1].value == "https://host.r5d.invalid/R5D"
    matrix = browser.browser_header_matrix("probe.r5d.invalid", "ROUND5")
    assert len(matrix) == 24
    assert all(row.to_dict()["inert"] and row.to_dict()["network_requests"] == 0 for row in matrix)


def test_builders_reject_nonreserved_hosts_and_header_breakout():
    with pytest.raises(browser.HeaderAnalysisInputError, match=r"reserved \.invalid"):
        browser.open_redirect_payloads("attacker.example")
    with pytest.raises(browser.HeaderAnalysisInputError, match="HTTP token"):
        browser.crlf_payloads(header_name="X-Test\r\nInjected")
    with pytest.raises(browser.HeaderAnalysisInputError, match="conservative ASCII"):
        browser.crlf_payloads("bad marker")


def test_exchange_analysis_correlates_host_cors_and_cswsh_evidence():
    request = (
        "GET /socket HTTP/1.1\r\n"
        "Host: app.local\r\n"
        "Origin: https://evil.r5d.invalid\r\n"
        "Cookie: session=opaque\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "X-Forwarded-Host: poison.r5d.invalid\r\n\r\n"
    )
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Access-Control-Allow-Origin: https://evil.r5d.invalid\r\n"
        "Access-Control-Allow-Credentials: true\r\n"
        "Location: https://poison.r5d.invalid/reset\r\n\r\n"
    )
    source = """
reset_url = req.headers.host + '/reset absolute url'
res.redirect(req.query.next)
setHeader('X-Trace', request.query.trace)
setHeader('Access-Control-Allow-Origin', request.headers.origin)
websocket upgrade uses session cookie
"""
    rows = browser.analyze_saved_web_exchange(request, response, source)
    names = {row.name for row in rows}
    assert {
        "external_location",
        "reflected_x_forwarded_host",
        "request_origin_reflected",
        "origin_reflection_missing_vary",
        "cross_site_cookie_websocket_accepted",
        "host_derived_absolute_url",
        "unvalidated_redirect_parameter",
        "header_from_request_data",
        "origin_reflection_source",
        "cookie_authenticated_websocket_source",
    } <= names
    assert all(row.severity in {"medium", "high"} for row in rows)
    assert all(row.recommendation.endswith(".") for row in rows)


def test_cors_duplicate_wildcard_null_and_crlf_cases_are_explicit():
    request = "GET /data HTTP/1.1\r\nHost: app.local\r\nOrigin: null\r\n\r\n"
    wildcard = (
        "HTTP/1.1 302 Found\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Credentials: true\r\n"
        "Location: https://app.local/%0d%0aX-R5D:yes\r\n\r\n"
    )
    names = {row.name for row in browser.analyze_saved_web_exchange(request, wildcard)}
    assert {"wildcard_with_credentials", "encoded_line_break_in_location"} <= names

    duplicate = (
        "HTTP/1.1 200 OK\r\n"
        "Access-Control-Allow-Origin: null\r\n"
        "Access-Control-Allow-Origin: https://other.invalid\r\n\r\n"
    )
    names = {row.name for row in browser.analyze_saved_web_exchange(request, duplicate)}
    assert "duplicate_acao" in names

    null_only = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: null\r\n\r\n"
    names = {row.name for row in browser.analyze_saved_web_exchange(request, null_only)}
    assert "null_origin_allowed" in names


def test_duplicate_host_and_bounds_fail_closed():
    request = "GET / HTTP/1.1\r\nHost: one.local\r\nHost: two.local\r\n\r\n"
    rows = browser.analyze_saved_web_exchange(request, "HTTP/1.1 200 OK\r\n\r\n")
    assert [row.name for row in rows] == ["duplicate_host"]
    with pytest.raises(browser.HeaderAnalysisInputError, match="exceeds"):
        browser.analyze_saved_web_exchange("x" * (browser.MAX_TEXT + 1), "")


def test_module_has_no_network_browser_or_dynamic_execution_surface():
    tree = ast.parse((WEB / "header_browser_analysis.py").read_text(encoding="utf-8"))
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
    assert not imports.intersection(
        {"socket", "requests", "http.client", "urllib.request", "selenium", "playwright", "pickle", "marshal"}
    )
    assert not calls.intersection(
        {"connect", "send", "sendall", "urlopen", "request", "get", "post", "loads", "eval", "exec"}
    )
