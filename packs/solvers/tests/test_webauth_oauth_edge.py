"""RFC and independent-structure tests for OAuth/OIDC edge correlation."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import webauth_oauth_edge as oauth


RFC7636_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC7636_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def _codes(report):
    return {row["code"] for row in report["findings"]}


def _flow(**changes):
    value = {
        "id": "clean",
        "authorization": {
            "response_type": "code",
            "client_id": "client-1",
            "redirect_uri": "https://app.example/callback",
            "code_challenge": RFC7636_CHALLENGE,
            "code_challenge_method": "S256",
            "nonce": "nonce-1",
        },
        "callback": {"code": "CODE-1", "iss": "https://idp.example"},
        "token_request": {"code": "CODE-1", "code_verifier": RFC7636_VERIFIER},
        "registered_redirect_uris": ["https://app.example/callback"],
        "id_token_claims": {
            "iss": "https://idp.example",
            "sub": "user-1",
            "nonce": "nonce-1",
            "aud": "client-1",
        },
        "userinfo_claims": {"sub": "user-1"},
        "metadata": {"issuer": "https://idp.example"},
        "expected_issuer": "https://idp.example",
        "callback_location": "query",
    }
    value.update(changes)
    return value


def test_rfc7636_appendix_b_s256_vector():
    assert oauth.pkce_s256(RFC7636_VERIFIER) == RFC7636_CHALLENGE
    with pytest.raises(oauth.WebauthOAuthError, match="43..128"):
        oauth.pkce_s256("short")


def test_contextual_csrf_finding_recognizes_bound_pkce_or_oidc_nonce():
    report = oauth.analyze_flows([_flow()])
    assert "state_absent_with_alternate_binding" in _codes(report)
    assert "csrf_binding_absent" not in _codes(report)
    assert report["flows"][0]["pkce_bound"] is True
    assert report["flows"][0]["nonce_bound"] is True
    assert report["offline"] and report["network_requests"] == 0


def test_rfc9700_pkce_downgrade_shape_is_explicit():
    flow = _flow(
        authorization={
            "response_type": "code",
            "client_id": "client-1",
            "redirect_uri": "https://app.example/callback",
        },
        id_token_claims={},
    )
    report = oauth.analyze_flows([flow])
    assert {
        "pkce_downgrade_verifier_without_challenge",
        "csrf_binding_absent",
    } <= _codes(report)


def test_exact_redirect_policy_and_native_loopback_port_exception():
    loopback = _flow(
        authorization={
            "response_type": "code",
            "client_id": "native",
            "redirect_uri": "http://127.0.0.1:54321/callback",
            "state": "unique-state",
        },
        callback={"code": "C", "state": "unique-state"},
        token_request={},
        id_token_claims={},
        metadata={},
        expected_issuer=None,
        registered_redirect_uris=["http://127.0.0.1/callback"],
    )
    report = oauth.analyze_flows([loopback])
    assert "redirect_not_exactly_registered" not in _codes(report)

    hostile = _flow(
        authorization={
            "response_type": "code",
            "client_id": "c",
            "redirect_uri": "https://app.example/cb%2f..%2fevil",
            "state": "s",
        },
        callback={"code": "C", "state": "s"},
        token_request={},
        registered_redirect_uris=["https://*.example/cb"],
        id_token_claims={},
        metadata={},
        expected_issuer=None,
    )
    assert {
        "registered_redirect_pattern",
        "redirect_parser_boundary",
        "redirect_not_exactly_registered",
    } <= _codes(oauth.analyze_flows([hostile]))

    private_use = _flow(
        authorization={
            "response_type": "code",
            "client_id": "native",
            "redirect_uri": "com.example.app:/oauth2redirect/provider",
            "state": "native-state",
        },
        callback={"code": "C", "state": "native-state"},
        token_request={},
        id_token_claims={},
        metadata={},
        expected_issuer=None,
        registered_redirect_uris=["com.example.app:/oauth2redirect/provider"],
    )
    assert "redirect_not_exactly_registered" not in _codes(oauth.analyze_flows([private_use]))


def test_jar_par_jarm_subject_and_mixup_correlations():
    flow = _flow(
        request_object_claims={"redirect_uri": "https://other.example/cb", "client_id": "client-1"},
        jarm_claims={"code": "OTHER", "iss": "https://other-idp.example"},
        par={"client_id": "other-client"},
        userinfo_claims={"sub": "other-user"},
    )
    assert {
        "jar_parameter_conflict",
        "jarm_parameter_conflict",
        "par_client_binding_mismatch",
        "userinfo_subject_mismatch",
        "authorization_server_mixup",
    } <= _codes(oauth.analyze_flows([flow]))


def test_oidc_core_nonce_and_array_audience_semantics():
    flow = _flow(
        authorization={
            "response_type": "code",
            "client_id": "client-1",
            "redirect_uri": "https://app.example/callback",
            "state": "S",
            "nonce": "expected-nonce",
        },
        callback={"code": "C", "state": "S", "iss": "https://idp.example"},
        token_request={},
        id_token_claims={
            "iss": "https://idp.example",
            "sub": "user-1",
            "nonce": "other-nonce",
            "aud": ["client-1", "resource-server"],
            "azp": "different-client",
        },
    )
    report = oauth.analyze_flows([flow])
    assert {"oidc_nonce_mismatch", "authorized_party_mismatch"} <= _codes(report)
    assert report["flows"][0]["nonce_bound"] is False

    single_audience = _flow(
        id_token_claims={
            "iss": "https://idp.example",
            "sub": "user-1",
            "nonce": "nonce-1",
            "aud": "client-1",
            "azp": "different-client",
            "amr": ["pwd", "otp"],
        },
        userinfo_claims={"sub": "user-1", "address": {"country": "RO"}},
    )
    assert "authorized_party_mismatch" in _codes(oauth.analyze_flows([single_audience]))

    multi_without_azp = _flow(
        id_token_claims={
            "iss": "https://idp.example",
            "sub": "user-1",
            "nonce": "nonce-1",
            "aud": ["client-1", "resource-server"],
        }
    )
    assert "authorized_party_missing" in _codes(oauth.analyze_flows([multi_without_azp]))


def test_query_token_and_deprecated_implicit_response_are_flagged():
    flow = _flow(
        authorization={
            "response_type": "token id_token",
            "client_id": "client-1",
            "redirect_uri": "https://app.example/callback",
            "state": "S",
        },
        callback={"access_token": "opaque", "id_token": "opaque", "state": "S"},
        token_request={},
        id_token_claims={},
        metadata={},
        expected_issuer=None,
    )
    assert {"implicit_access_token_flow", "token_in_query"} <= _codes(oauth.analyze_flows([flow]))


def test_multi_flow_reuse_detects_codes_state_nonce_pkce_and_request_uri():
    first = _flow()
    second = _flow(id="second")
    report = oauth.analyze_flows([first, second])
    assert {
        "reused_authorization_code",
        "reused_nonce",
        "reused_code_challenge",
        "reused_code_verifier",
    } <= _codes(report)
    code = next(row for row in report["findings"] if row["code"] == "reused_authorization_code")
    assert code["flow_ids"] == ["clean", "second"]


def test_strict_json_duplicate_and_public_type_fail_closed():
    with pytest.raises(oauth.WebauthOAuthError, match="duplicate JSON member"):
        oauth.load_flows('{"authorization":{},"authorization":{}}')
    for value in ([], ["not-an-object"], [{"authorization": []}]):
        with pytest.raises(oauth.WebauthOAuthError):
            oauth.analyze_flows(value)
    with pytest.raises(oauth.WebauthOAuthError):
        oauth.analyze_flows([{"id_token_claims": {"aud": [{"nested": "object"}]}}])


def test_guarded_cli_and_offline_import_surface(tmp_path, capsys):
    assert oauth.main(["analyze"]) == 2
    assert oauth.main(["--bad"]) == 2
    assert oauth.main(["pkce", RFC7636_VERIFIER]) == 0
    assert RFC7636_CHALLENGE in capsys.readouterr().out

    fixture = tmp_path / "flow.json"
    fixture.write_text(json.dumps(_flow()), encoding="utf-8")
    assert oauth.main(["analyze", str(fixture)]) == 0

    tree = ast.parse(Path(oauth.__file__).read_text("utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert not imports.intersection({"socket", "requests", "urllib.request", "http.client", "subprocess"})

