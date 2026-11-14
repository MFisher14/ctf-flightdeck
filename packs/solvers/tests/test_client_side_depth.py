"""Deterministic tests for offline client-side depth analysis."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import client_side_depth as client  # noqa: E402


def test_dom_catalogs_cover_browser_inputs_and_contextual_sinks():
    sources = client.dom_source_catalog()
    sinks = client.dom_sink_catalog()
    assert [row.name for row in sources] == [
        "location_search",
        "location_hash",
        "document_url",
        "document_referrer",
        "window_name",
        "message_data",
        "storage",
        "cookie",
        "url_search_params",
        "websocket_data",
    ]
    assert {row.name for row in sinks} >= {
        "innerHTML",
        "insertAdjacentHTML",
        "eval",
        "location_navigation",
        "script_src",
        "react_html",
    }
    assert {row.context for row in sinks} == {"html", "script", "url"}


def test_dom_taint_tracks_aliases_transforms_sanitizers_and_url_context():
    source = """
const raw = location.hash;
const decoded = decodeURIComponent(raw);
panel.innerHTML = decoded;
const safe = DOMPurify.sanitize(raw);
safePanel.innerHTML = safe;
const next = document.referrer;
window.location.href = next;
"""
    rows = client.analyze_dom_flows(source)
    assert [(row.source, row.sink) for row in rows] == [
        ("location_hash", "innerHTML"),
        ("location_hash", "innerHTML"),
        ("document_referrer", "location_navigation"),
    ]
    first, second, third = rows
    assert first.variables == ("raw", "decoded")
    assert first.transforms == ("decodeURIComponent",)
    assert first.sanitizers == () and first.confidence == "high" and not first.mitigated
    assert second.sanitizers == ("DOMPurify",) and second.mitigated and second.confidence == "low"
    assert third.sink_context == "url" and third.confidence == "medium"
    assert [row.line for row in rows] == [4, 6, 8]


def test_dom_analysis_ignores_comments_and_string_decoys_but_finds_direct_message_data():
    decoys = '''
const text = "location.hash; node.innerHTML = raw";
// const raw = document.URL; node.innerHTML = raw;
const fixed = "safe";
node.textContent = fixed;
'''
    assert client.analyze_dom_flows(decoys) == ()
    direct = "window.onmessage = event => { panel.innerHTML = event.data; };"
    rows = client.analyze_dom_flows(direct)
    assert len(rows) == 1
    assert (rows[0].source, rows[0].sink, rows[0].variables) == (
        "message_data",
        "innerHTML",
        (),
    )

    sanitized = "panel.innerHTML = DOMPurify.sanitize(location.hash);"
    row = client.analyze_dom_flows(sanitized)[0]
    assert row.sanitizers == ("DOMPurify",) and row.mitigated


def test_prototype_gadget_database_matches_signatures_without_claiming_exploitability():
    source = """
__webpack_require__.p = options.publicPath;
const clean = DOMPurify.sanitize(input, {ALLOWED_TAGS: config.ALLOWED_TAGS});
"""
    manifest = '{"dependencies":{"webpack":"5.91.0","dompurify":"3.1.5"}}'
    rows = client.match_prototype_gadgets(source, manifest)
    assert [row.gadget for row in rows] == ["webpack_public_path", "dompurify_config"]
    assert rows[0].package_hints == ("webpack@5.91.0",)
    assert rows[1].package_hints == ("dompurify@3.1.5",)
    assert all(row.confidence == "medium" and row.requirements for row in rows)

    catalog = client.prototype_gadget_catalog()
    assert len(catalog) >= 10
    assert len({row.name for row in catalog}) == len(catalog)


def test_prototype_candidates_are_inert_marker_strings():
    rows = client.prototype_marker_candidates("publicPath", "ROUND5")
    assert [row.name for row in rows] == ["query_proto", "query_constructor", "json_text"]
    assert rows[0].value == "__proto__[publicPath]=ROUND5"
    assert rows[1].value == "constructor[prototype][publicPath]=ROUND5"
    assert rows[2].value == '{"__proto__":{"publicPath":"ROUND5"}}'
    assert all(row.to_dict()["inert"] and row.to_dict()["network_requests"] == 0 for row in rows)
    assert not any("script" in row.value.lower() or "onerror" in row.value.lower() for row in rows)


def test_postmessage_analysis_finds_wildcard_untrusted_receiver_and_unvalidated_shape():
    source = """
window.addEventListener("message", (event) => {
  const parsed = JSON.parse(event.data);
  panel.innerHTML = parsed.html;
});
peer.postMessage(marker, "*");
"""
    rows = client.analyze_postmessage(source)
    assert [row.name for row in rows] == [
        "receiver_without_exact_origin",
        "unvalidated_message_shape",
        "wildcard_target_origin",
    ]
    assert rows[0].severity == "high"
    assert all(row.precondition for row in rows)

    checked = '''
window.addEventListener("message", (event) => {
  if (event.origin === "https://trusted.invalid") panel.textContent = event.data;
});
'''
    assert client.analyze_postmessage(checked) == ()

    guarded = '''
window.addEventListener("message", (event) => {
  if (event.origin !== "https://trusted.invalid") return;
  panel.innerHTML = event.data;
});
'''
    assert client.analyze_postmessage(guarded) == ()

    harmless = 'window.addEventListener("message", event => panel.textContent = event.data);'
    assert client.analyze_postmessage(harmless) == ()


def test_postmessage_candidates_require_reserved_https_origin():
    rows = client.postmessage_marker_candidates("https://message.r5d.invalid", "ROUND5")
    assert [row.value for row in rows] == [
        "ROUND5",
        '{"type":"r5d-marker","value":"ROUND5"}',
        "https://message.r5d.invalid",
    ]
    assert all(row.to_dict()["browser_started"] is False for row in rows)
    with pytest.raises(client.ClientDepthInputError, match=r"reserved HTTPS \.invalid"):
        client.postmessage_marker_candidates("https://real.example")


def test_postmessage_suffix_origin_checks_remain_only_leads():
    source = '''
window.addEventListener("message", event => {
  if (event.origin.endsWith("trusted.invalid")) panel.innerHTML = event.data;
});
'''
    assert [row.name for row in client.analyze_postmessage(source)] == [
        "receiver_without_exact_origin",
        "weak_origin_substring_check",
    ]


def test_clickjacking_correlates_headers_meta_script_and_session_cookie():
    headers = "HTTP/1.1 200 OK\r\nSet-Cookie: session=opaque; Secure; HttpOnly\r\n\r\n"
    document = '''
<meta http-equiv="X-Frame-Options" content="DENY">
<script>if (top !== self) top.location = self.location;</script>
'''
    rows = client.analyze_clickjacking(headers, document)
    assert {row.name for row in rows} == {
        "missing_frame_protection",
        "meta_x_frame_options_ineffective",
        "script_only_framebuster",
        "ambient_session_cookie",
    }
    assert all(row.family == "clickjacking" for row in rows)

    protected = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n\r\n"
    )
    assert client.analyze_clickjacking(protected) == ()

    conflict = (
        "HTTP/1.1 200 OK\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-Frame-Options: SAMEORIGIN\r\n\r\n"
    )
    assert [row.name for row in client.analyze_clickjacking(conflict)] == [
        "conflicting_x_frame_options"
    ]

    permissive = (
        "HTTP/1.1 200 OK\r\n"
        "X-Frame-Options: ALLOW-FROM https://legacy.invalid\r\n"
        "Content-Security-Policy: frame-ancestors *\r\n\r\n"
    )
    assert {row.name for row in client.analyze_clickjacking(permissive)} == {
        "obsolete_allow_from",
        "permissive_frame_ancestors",
    }


def test_combined_report_is_offline_and_does_not_start_browser():
    report = client.analyze_client_side(
        "const raw=location.search; node.innerHTML=raw;",
        "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n",
    )
    assert report["offline"] is True
    assert report["browser_started"] is False
    assert report["network_requests"] == 0
    assert len(report["dom_flows"]) == 1


def test_bounds_and_identifiers_fail_closed():
    with pytest.raises(client.ClientDepthInputError, match="exceeds"):
        client.analyze_dom_flows("x" * (client.MAX_SOURCE + 1))
    with pytest.raises(client.ClientDepthInputError, match="identifier"):
        client.prototype_marker_candidates("x\r\nInjected")
    many = "\n".join(f"const v{index}=location.hash;" for index in range(client.MAX_ASSIGNMENTS + 1))
    with pytest.raises(client.ClientDepthInputError, match="assignment count"):
        client.analyze_dom_flows(many)


def test_module_has_no_browser_network_process_or_deserializer_surface():
    tree = ast.parse((WEB / "client_side_depth.py").read_text(encoding="utf-8"))
    imports: set[str] = set()
    direct_calls: set[str] = set()
    attribute_calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                direct_calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                attribute_calls.add(node.func.attr)
    assert not imports.intersection(
        {"socket", "requests", "urllib.request", "http.client", "subprocess", "selenium", "playwright", "pickle", "marshal", "json"}
    )
    assert not direct_calls.intersection({"eval", "exec", "compile", "open", "__import__"})
    assert not attribute_calls.intersection(
        {"connect", "send", "sendall", "urlopen", "request", "get", "post", "loads", "load", "system", "popen", "run"}
    )
