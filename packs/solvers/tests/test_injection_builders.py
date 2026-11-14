"""Deterministic tests for the offline r5d injection builder lane."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import injection_builders as inj  # noqa: E402


def test_family_matrix_is_stable_inert_and_offline():
    rows = inj.injection_matrix(field="account", attribute="mail", marker="ROUND5")
    assert [row.family for row in rows] == [
        *("nosql" for _ in range(6)),
        *("ldap" for _ in range(5)),
        *("xpath" for _ in range(6)),
    ]
    assert len({(row.family, row.name) for row in rows}) == len(rows)
    assert all(isinstance(row.value, str) and row.value for row in rows)
    assert all(row.to_dict()["inert"] and row.to_dict()["network_requests"] == 0 for row in rows)
    assert inj.nosql_payloads("account", "ROUND5")[0].value == (
        '{"account":{"$ne":null}}'
    )
    assert inj.ldap_payloads("mail", "ROUND5")[1].value == "*)(mail=*"
    assert inj.xpath_payloads("ROUND5")[-1].value == (
        "' or contains(string(.),'ROUND5') or 'a'='b"
    )


def test_payload_builders_reject_grammar_breaking_or_unbounded_inputs():
    with pytest.raises(inj.InjectionInputError, match="field must match"):
        inj.nosql_payloads("user\r\nX-Evil")
    with pytest.raises(inj.InjectionInputError, match="attribute must match"):
        inj.ldap_payloads("uid)(objectClass")
    with pytest.raises(inj.InjectionInputError, match="marker must contain"):
        inj.xpath_payloads("quote'")
    with pytest.raises(inj.InjectionInputError, match="exceeds"):
        inj.analyze_injection_text("x" * (inj.MAX_TEXT + 1))


def test_saved_text_signature_analysis_is_ordered_and_bounded():
    text = (
        "HTTP/1.1 500 Error\r\n\r\n"
        "InvalidSearchFilterException: malformed request; "
        "then XPathEvalError: Invalid predicate; finally MongoServerError"
    )
    findings = inj.analyze_injection_text(text)
    assert [(row.family, row.signature) for row in findings] == [
        ("ldap", "ldap_exception"),
        ("xpath", "xpath_exception"),
        ("xpath", "predicate_error"),
        ("nosql", "mongodb_error"),
    ]
    assert [row.offset for row in findings] == sorted(row.offset for row in findings)
    assert all(len(row.evidence) < 180 and row.confidence == "high" for row in findings)


def test_response_comparison_uses_saved_bytes_only():
    baseline = b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\ndenied\n"
    candidate = (
        b"HTTP/1.1 500 Error\r\nContent-Type: text/plain\r\n\r\n"
        b"ROUND5\nMongoServerError: unknown query operator\nnew detail\n"
    )
    result = inj.compare_saved_responses(baseline, candidate, marker="ROUND5")
    assert result["baseline_status"] == 401
    assert result["candidate_status"] == 500
    assert result["status_changed"] is True
    assert result["marker_reflected"] is True
    assert result["new_error_families"] == ("nosql",)
    assert result["new_lines"] == (
        "ROUND5",
        "MongoServerError: unknown query operator",
        "new detail",
    )
    assert result["offline"] is True and result["network_requests"] == 0


def test_module_has_no_transport_or_execution_surface():
    path = WEB / "injection_builders.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
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
        {"socket", "requests", "http.client", "urllib.request", "pickle", "marshal"}
    )
    assert not calls.intersection(
        {"connect", "send", "sendall", "urlopen", "request", "loads", "eval", "exec"}
    )
