"""Deterministic tests for the offline WAF encoding catalog."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import waf_encoding_catalog as waf  # noqa: E402


def test_encoding_catalog_has_stable_families_pipelines_and_strings():
    rows = waf.encoding_catalog("A /<")
    assert [row.name for row in rows] == [
        "raw",
        "url_component",
        "url_path_safe",
        "form_plus",
        "percent_all",
        "mixed_hex_case",
        "double_percent",
        "unicode_escape",
        "json_escape",
        "fullwidth",
        "nfd",
        "nfkc",
        "html_named",
        "html_decimal",
        "html_hex",
        "backslash_x",
        "css_escape",
        "iis_unicode",
        "utf16le_percent",
        "base64",
        "base64url",
        "hex_utf8",
        "html_hex_then_url",
        "fullwidth_then_url",
    ]
    values = {row.name: row for row in rows}
    assert values["raw"].value == "A /<"
    assert values["url_component"].value == "A%20%2F%3C"
    assert values["url_path_safe"].value == "A%20/%3C"
    assert values["form_plus"].value == "A+%2F%3C"
    assert values["percent_all"].value == "%41%20%2F%3C"
    assert values["double_percent"].decode_pipeline == ("URL decode", "URL decode")
    assert values["unicode_escape"].value == r"\u0041\u0020\u002f\u003c"
    assert values["html_hex"].value == "&#x41;&#x20;&#x2f;&#x3c;"
    assert values["utf16le_percent"].value.startswith("%41%00%20%00")
    assert values["base64url"].value == "QSAvPA"
    assert all(isinstance(row.value, str) and row.to_dict()["inert"] for row in rows)
    assert all(row.to_dict()["network_requests"] == 0 for row in rows)


def test_named_pipeline_is_bounded_explicit_and_deterministic():
    assert waf.apply_pipeline("/<", ("html_hex", "url_component")) == "%26%23x2f%3B%26%23x3c%3B"
    assert waf.apply_pipeline("Ａ", ("nfkc", "percent_all")) == "%41"
    with pytest.raises(waf.WAFEncodingInputError, match="sequence"):
        waf.apply_pipeline("x", "url_component")
    with pytest.raises(waf.WAFEncodingInputError, match="unknown transform"):
        waf.apply_pipeline("x", ("__import__",))
    with pytest.raises(waf.WAFEncodingInputError, match="1..4"):
        waf.apply_pipeline("x", ())
    with pytest.raises(waf.WAFEncodingInputError, match="1..4"):
        waf.apply_pipeline("x", ("url_component" for _ in range(1000)))
    with pytest.raises(waf.WAFEncodingInputError, match="encoded output exceeds"):
        waf.apply_pipeline("x" * waf.MAX_INPUT, ("html_decimal", "html_decimal", "html_decimal"))


def test_inputs_fail_closed_on_type_nul_and_size():
    with pytest.raises(waf.WAFEncodingInputError, match="must be text"):
        waf.encoding_catalog(b"bytes")  # type: ignore[arg-type]
    with pytest.raises(waf.WAFEncodingInputError, match="must not contain NUL"):
        waf.encoding_catalog("a\x00b")
    with pytest.raises(waf.WAFEncodingInputError, match="1..4096"):
        waf.encoding_catalog("x" * (waf.MAX_INPUT + 1))


def test_static_analysis_finds_normalization_filter_and_product_evidence():
    supplied = """
decoded = unquote(unquote(raw))
markup = html.unescape(decoded)
canon = unicodedata.normalize('NFKC', markup)
blob = b64decode(canon)
if blacklist_regex.contains(blob): reject()
folded = blob.casefold()
HTTP/1.1 403 Forbidden
Server: cloudflare
CF-Ray: abc
ModSecurity: Access denied with code 403
X-Debug: AWSWAF and visid_incap
"""
    rows = waf.analyze_waf_text(supplied)
    names = {row.name for row in rows}
    assert {
        "url_decode",
        "double_url_decode",
        "html_entity_decode",
        "unicode_normalize",
        "base64_decode",
        "regex_blacklist",
        "case_normalization",
        "cloudflare",
        "modsecurity",
        "aws_waf",
        "imperva",
    } <= names
    assert [row.offset for row in rows] == sorted(row.offset for row in rows)
    assert all(row.implication.endswith(".") for row in rows)
    with pytest.raises(waf.WAFEncodingInputError, match="exceeds"):
        waf.analyze_waf_text("x" * (waf.MAX_TEXT + 1))


def test_module_has_no_transport_process_or_dynamic_execution_surface():
    tree = ast.parse((WEB / "waf_encoding_catalog.py").read_text(encoding="utf-8"))
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
        {"socket", "requests", "http.client", "urllib.request", "subprocess", "pickle", "marshal"}
    )
    assert not calls.intersection(
        {"connect", "send", "sendall", "urlopen", "request", "system", "popen", "loads", "eval", "exec"}
    )
