"""Real-vector tests for the offline request-Cookie differential analyzer."""

from __future__ import annotations

import ast
from http.cookies import SimpleCookie
import json
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import research_wp_cookie_diff as cookie_diff  # noqa: E402


def _views(report: cookie_diff.CookieDifferentialReport):
    return {view.name: view for view in report.views}


def _codes(report: cookie_diff.CookieDifferentialReport) -> set[str]:
    return {finding.code for finding in report.findings}


def _last(view: cookie_diff.CookieParserView) -> dict[str, str]:
    return {item.name: item.value for item in view.last_wins}


def _first(view: cookie_diff.CookieParserView) -> dict[str, str]:
    return {item.name: item.value for item in view.first_wins}


def test_portswigger_cookie_sandwich_has_distinct_modern_and_legacy_views():
    # PortSwigger Research, "Stealing HttpOnly cookies with the cookie sandwich
    # technique" (2025), lines 62-70 of the published example.
    raw = (
        'GET / HTTP/1.1\r\n'
        'Host: example.test\r\n'
        'Cookie: $Version=1; param1="start; sessionId=secret; param2=end"\r\n'
        '\r\n'
    )
    report = cookie_diff.analyze_cookie_headers(raw)
    views = _views(report)
    modern = views["modern-semicolon-join"]
    legacy = views["legacy-versioned"]

    assert legacy.active is True
    assert _last(modern)["sessionId"] == "secret"
    assert "sessionId" not in _last(legacy)
    assert _last(legacy)["param1"] == "start; sessionId=secret; param2=end"
    assert {
        "legacy-parser-view-difference",
        "legacy-quoted-span-absorbs-cookie",
    } <= _codes(report)
    assert report.vulnerability_confirmed is False
    assert report.runtime_confirmation_required is True
    assert all(finding.vulnerability_confirmed is False for finding in report.findings)


def test_simplecookie_octal_view_matches_independent_stdlib_oracle():
    # The octal-encoded eval string is the published PortSwigger phantom
    # $Version-cookie vector.  The implementation under test does not import
    # http.cookies; SimpleCookie is used here only as a non-circular oracle.
    value = r'$Version=1; foo="\145\166\141\154\050\047\164\145\163\164\047\051"; $Path=/'
    report = cookie_diff.analyze_cookie_headers("Cookie: " + value)
    modeled = _last(_views(report)["python-simplecookie-style"])["foo"]

    oracle = SimpleCookie()
    oracle.load(value)
    assert modeled == oracle["foo"].value == "eval('test')"
    assert "simplecookie-octal-decoding" in _codes(report)

    source = Path(cookie_diff.__file__).read_text(encoding="utf-8")
    assert "http.cookies" not in source


def test_portswigger_multiple_cookie_fields_show_join_policy_difference():
    # This field shape is from the duplicate-Cookie example in PortSwigger's
    # 2024 phantom $Version-cookie research.
    raw = (
        "GET / HTTP/1.1\r\n"
        "Host: example.test\r\n"
        "Cookie: param1=value1;\r\n"
        "Cookie: param2=value2;\r\n"
        "\r\n"
    )
    report = cookie_diff.analyze_cookie_headers(raw)
    views = _views(report)

    assert len(report.fields) == 2
    assert report.fields[0].raw_value == " param1=value1;"
    assert [(item.name, item.value) for item in views["modern-separate"].observations] == [
        ("param1", "value1"), ("param2", "value2"),
    ]
    assert [(item.name, item.value) for item in views["modern-semicolon-join"].observations] == [
        ("param1", "value1"), ("param2", "value2"),
    ]
    assert [(item.name, item.value) for item in views["modern-comma-join"].observations] == [
        ("param1", "value1"), (", param2", "value2"),
    ]
    assert {"duplicate-cookie-fields", "header-join-policy-difference"} <= _codes(report)


def test_versioned_comma_separator_matches_published_rfc2109_shape():
    report = cookie_diff.analyze_cookie_headers(
        "Cookie: $Version=1; foo=bar, abc = qux"
    )
    legacy = _views(report)["legacy-versioned"]
    assert legacy.active is True
    assert [(item.name, item.value) for item in legacy.observations] == [
        ("foo", "bar"), ("abc", "qux"),
    ]


def test_portswigger_unicode_prefix_vector_collides_after_trim_and_nfkc():
    # U+2000 + __Host-name is the minimal vector published in PortSwigger's
    # 2025 Cookie Chaos research.
    raw = "Cookie: __Host-name=Carlos; \u2000__Host-name=injected"
    report = cookie_diff.analyze_cookie_headers(raw)
    views = _views(report)

    modern_names = [item.name for item in views["modern-semicolon-join"].observations]
    assert modern_names == ["__Host-name", "\u2000__Host-name"]
    unicode_view = views["unicode-trim-nfkc"]
    assert [item.name for item in unicode_view.observations] == ["__Host-name", "__Host-name"]
    assert _first(unicode_view)["__Host-name"] == "Carlos"
    assert _last(unicode_view)["__Host-name"] == "injected"
    assert {
        "unicode-cookie-name-normalization",
        "protected-prefix-emerges-after-normalization",
        "unicode-normalized-name-collision",
    } <= _codes(report)


def test_first_and_last_duplicate_consequences_are_explicit():
    report = cookie_diff.analyze_cookie_headers(
        "Cookie: session=first; theme=dark; session=last"
    )
    view = _views(report)["modern-separate"]
    assert _first(view)["session"] == "first"
    assert _last(view)["session"] == "last"
    finding = next(item for item in report.findings
                   if item.code == "duplicate-cookie-order-consequence")
    assert "first-wins" in " ".join(finding.evidence)
    assert "last-wins" in " ".join(finding.evidence)


@pytest.mark.parametrize("bad", [
    b"",
    object(),
    "Cookie a=1",
    " Cookie: a=1",
    "Cookie: a=one\x00two",
    "GET / HTTP/1.1\rCookie: a=1",
])
def test_public_boundary_converts_malformed_inputs_to_declared_exception(bad):
    with pytest.raises(cookie_diff.ResearchWPCookieError):
        cookie_diff.analyze_cookie_headers(bad)


def test_bounds_and_json_ready_report(monkeypatch):
    monkeypatch.setattr(cookie_diff, "MAX_INPUT_BYTES", 16)
    with pytest.raises(cookie_diff.ResearchWPCookieError, match="exceed"):
        cookie_diff.analyze_cookie_headers("Cookie: a=" + "x" * 20)

    monkeypatch.setattr(cookie_diff, "MAX_INPUT_BYTES", 256 * 1024)
    report = cookie_diff.analyze_cookie_headers(b"Cookie: a=1; a=2")
    encoded = json.dumps(report.as_dict(), sort_keys=True)
    assert '"offline": true' in encoded
    assert '"network_requests": 0' in encoded


def test_guarded_argparse_cli_returns_codes_without_traceback(capsys):
    assert cookie_diff.main([]) == 2
    missing = capsys.readouterr()
    assert "usage:" in missing.err
    assert "Traceback" not in missing.err

    assert cookie_diff.main(["Cookie: a=1; a=2"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["offline"] is True
    assert result["network_requests"] == 0
    assert result["vulnerability_confirmed"] is False

    assert cookie_diff.main(["--not-an-option"]) == 2
    invalid = capsys.readouterr()
    assert "Traceback" not in invalid.err


def test_module_has_no_transport_execution_or_simplecookie_dependency():
    tree = ast.parse(Path(cookie_diff.__file__).read_text(encoding="utf-8"))
    imports: set[str] = set()
    calls: set[str] = set()
    caught_system_exit = False
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
        elif isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name):
            caught_system_exit |= node.type.id == "SystemExit"

    forbidden_imports = {
        "socket", "requests", "http.client", "urllib.request", "subprocess",
        "http.cookies", "pickle", "marshal",
    }
    assert not imports.intersection(forbidden_imports)
    assert not calls.intersection({
        "connect", "request", "send", "sendall", "urlopen", "system", "popen",
        "eval", "exec", "loads", "load",
    })
    assert caught_system_exit is True

