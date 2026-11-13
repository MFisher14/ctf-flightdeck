"""Deterministic tests for session/CSP and extended cache/upload depth."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import session_cache_upload_depth as policy  # noqa: E402


def _ids(rows):
    return {row.finding_id for row in rows}


def test_saved_header_parser_preserves_duplicate_fields_and_order():
    rows = policy.parse_saved_headers(
        "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-Test: one\r\n\r\nbody"
    )
    assert [(row.name, row.value) for row in rows] == [
        ("set-cookie", "a=1"), ("set-cookie", "b=2"), ("x-test", "one"),
    ]


def test_cookie_prefix_attributes_scope_and_session_cache_findings():
    response = """HTTP/1.1 200 OK\r
Set-Cookie: __Host-session=abc; Domain=.example.test; SameSite=None; Partitioned; Path=/app; Path=/\r
Cache-Control: public, max-age=60\r
\r
private profile
"""
    request = "GET /account HTTP/1.1\r\nHost: app.test\r\nCookie: old=1\r\n\r\n"
    ids = _ids(policy.evaluate_cookie_session_csp(response, request=request))
    assert {
        "cookie-duplicate-attrs-1", "cookie-secure-1", "cookie-httponly-1",
        "cookie-samesite-none-1", "cookie-partitioned-1", "cookie-host-prefix-1",
        "cookie-domain-1", "session-cache-policy",
    } <= ids


def test_cookie_name_collision_url_session_and_fixation_source():
    response = """HTTP/1.1 302 Found
Set-Cookie: sid=one; Secure; HttpOnly; SameSite=Lax
Set-Cookie: sid=two; Secure; HttpOnly; SameSite=Lax; Path=/admin
Cache-Control: no-store

"""
    request = "GET /cb?sessionid=leaked HTTP/1.1\r\nHost: app.test\r\n\r\n"
    source = "session_id = request.query.sid; session.save(session_id)"
    ids = _ids(policy.evaluate_cookie_session_csp(response, request=request, source=source))
    assert {"cookie-name-collision", "session-id-url", "session-fixation-source"} <= ids


def test_csp_risky_duplicate_report_only_and_missing_defenses():
    response = """HTTP/1.1 200 OK
Content-Security-Policy: default-src *; script-src 'unsafe-inline' 'unsafe-eval' data:; script-src 'none'
Content-Security-Policy-Report-Only: default-src 'none'

"""
    ids = _ids(policy.evaluate_cookie_session_csp(response))
    assert {"csp-duplicate-directive-1", "csp-script-risk-1", "csp-missing-object-src-1",
            "csp-missing-base-uri-1", "csp-trusted-types-1"} <= ids
    report_only = "HTTP/1.1 200 OK\r\nContent-Security-Policy-Report-Only: default-src 'none'\r\n\r\n"
    assert "csp-report-only" in _ids(policy.evaluate_cookie_session_csp(report_only))


def test_clean_cookie_session_and_csp_control():
    response = """HTTP/1.1 200 OK\r
Set-Cookie: __Host-session=abc; Secure; HttpOnly; SameSite=Lax; Path=/\r
Cache-Control: private, no-store\r
Content-Security-Policy: default-src 'none'; script-src 'nonce-abcdefghijklmnop'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r
\r
"""
    request = "GET / HTTP/1.1\r\nHost: app.test\r\nCookie: __Host-session=abc\r\n\r\n"
    assert policy.evaluate_cookie_session_csp(response, request=request) == ()


def test_csp_short_nonce_allows_same_response_reuse_and_flags_mismatch():
    response = "HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src 'nonce-short'; object-src 'none'; base-uri 'none'\r\n\r\n"
    html = "".join('<script nonce="short"></script>' for _ in range(9))
    ids = _ids(policy.evaluate_cookie_session_csp(response, html=html))
    assert "csp-short-nonce-1" in ids
    assert "csp-nonce-reuse-page" not in ids
    mismatch = policy.evaluate_cookie_session_csp(response, html='<script nonce="other"></script>')
    assert "csp-html-nonce-mismatch" in _ids(mismatch)


def test_analytics_cookie_does_not_imply_session_cache_and_invalid_samesite_is_evidence():
    analytics = "HTTP/1.1 200 OK\r\nSet-Cookie: analytics=1; Secure; SameSite=Lax\r\nCache-Control: public\r\n\r\n"
    assert policy.evaluate_cookie_session_csp(analytics) == ()
    invalid = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=1; Secure; HttpOnly; SameSite=Maybe\r\nCache-Control: no-store\r\n\r\n"
    assert "cookie-samesite-invalid-1" in _ids(policy.evaluate_cookie_session_csp(invalid))


def test_extended_cache_variants_are_new_stable_and_inert():
    rows = policy.build_extended_cache_variants("/account")
    assert rows == policy.build_extended_cache_variants("/account")
    assert [row.rank for row in rows] == list(range(1, len(rows) + 1))
    names = {row.name for row in rows}
    assert {"encoded-dot-suffix", "encoded-backslash", "matrix-session", "fullwidth-dot-suffix",
            "forwarded-prefix", "forwarded-uri", "original-host", "accel-redirect", "cookie-marker"} <= names
    assert not names.intersection({"path-info", "semicolon", "encoded-question", "dot-segment",
                                   "suffix-traversal", "x-forwarded-host", "x-original-url"})
    assert all(row.inert and row.offline and row.network_requests == 0 for row in rows)


def test_extended_cache_source_analyzer_positive_and_negative():
    source = "cache_key = $scheme$host$uri; ignore_query = true; cookies = none; route = normalize(path_info); .css ttl=1h"
    ids = _ids(policy.analyze_extended_cache_source(source))
    assert {"cache-query-omission", "cache-cookie-omission", "cache-normalization-gap",
            "cache-extension-rule"} <= ids
    assert policy.analyze_extended_cache_source("cache disabled for authenticated routes") == ()


def test_extended_upload_catalog_is_nonoverlapping_and_inert():
    rows = policy.build_extended_upload_variants()
    names = {row.name for row in rows}
    assert {"webp-riff", "mp4-ftyp", "bmp", "tiff-little", "ico", "jpeg-zip-tail",
            "pdf-zip-tail", "gif-html-comment", "filename-star-conflict",
            "duplicate-content-type"} == names
    assert not names.intersection({"gif89a-marker", "jpeg-marker", "png-marker",
                                   "pdf-comment-marker", "zip-local-header-marker", "svg-text-marker"})
    assert all(row.inert and row.offline and row.network_requests == 0 and "R5D" in row.value for row in rows)


def test_upload_metadata_duplicates_filename_and_type_conflicts():
    fields = (
        ("filename", "image.jpg"), ("filename", "other.jpg"),
        ("filename*", "image.php"),
        ("content-type", "application/octet-stream"), ("content-type", "image/jpeg"),
        ("detected-type", "image/png"),
    )
    ids = _ids(policy.analyze_upload_metadata(fields))
    assert {"upload-duplicate-filename", "upload-duplicate-content-type", "upload-filename-conflict",
            "upload-type-conflict", "upload-extension-media-conflict"} <= ids
    clean = (("filename", "image.jpg"), ("content-type", "image/jpeg"),
             ("detected-type", "image/jpeg"))
    assert policy.analyze_upload_metadata(clean) == ()


def test_policy_catalog_caps_and_malformed_inputs():
    too_many = "HTTP/1.1 200 OK\r\n" + "".join(f"X-{i}: y\r\n" for i in range(policy.MAX_HEADERS + 1)) + "\r\n"
    with pytest.raises(policy.SessionDepthError, match="header count"):
        policy.parse_saved_headers(too_many)
    with pytest.raises(policy.SessionDepthError, match="path"):
        policy.build_extended_cache_variants("relative")
    with pytest.raises(policy.SessionDepthError, match="bounded"):
        policy.build_extended_upload_variants("bad.name")
    with pytest.raises(policy.SessionDepthError, match="sequence"):
        policy.analyze_upload_metadata("not pairs")


def test_policy_module_has_no_client_browser_file_parser_process_or_deserializer():
    tree = ast.parse((WEB / "session_cache_upload_depth.py").read_text(encoding="utf-8"))
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
    assert not imports.intersection({"socket", "requests", "http.client", "urllib.request", "subprocess",
                                     "pickle", "marshal", "json", "yaml", "zipfile", "tarfile", "PIL",
                                     "selenium", "playwright"})
    assert not calls.intersection({"connect", "request", "send", "sendall", "urlopen", "Popen", "run",
                                   "loads", "load", "extract", "extractall", "eval", "exec"})
