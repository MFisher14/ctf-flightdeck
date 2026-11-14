"""Deterministic tests for WebAuthn, identity trust, and API auth depth."""

from __future__ import annotations

import ast
import base64
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import identity_api_depth as depth  # noqa: E402


def b64u(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _ids(rows):
    return {row.finding_id for row in rows}


def test_clean_webauthn_registration_and_assertion_metadata():
    rp_hash = b"R" * 32
    registration = (
        ("clientDataJSON", b64u('{"type":"webauthn.create","challenge":"C1","origin":"https://app.test","crossOrigin":false}')),
        ("authenticatorData", b64u(rp_hash + bytes((0x45,)) + (1).to_bytes(4, "big"))),
        ("attestationObject", b64u(b"opaque-cbor-not-parsed")),
        ("fmt", "packed"),
    )
    assert depth.analyze_webauthn_ceremony(
        registration, ceremony="registration", expected_challenge="C1",
        expected_origin="https://app.test", expected_rp_id_hash=rp_hash,
    ) == ()
    assertion = (
        ("clientDataJSON", b64u('{"type":"webauthn.get","challenge":"C2","origin":"https://app.test"}')),
        ("authenticatorData", b64u(rp_hash + bytes((0x05,)) + (2).to_bytes(4, "big"))),
        ("signature", b64u(b"opaque-signature")),
        ("userHandle", "user-1"),
    )
    assert depth.analyze_webauthn_ceremony(
        assertion, ceremony="assertion", expected_challenge="C2", expected_origin="https://app.test",
        expected_rp_id_hash=rp_hash.hex(), previous_sign_count=1, expected_user_handle="user-1",
    ) == ()


def test_webauthn_binding_flags_counter_and_assertion_failures():
    rp_hash = b"A" * 32
    fields = (
        ("clientDataJSON", b64u('{"type":"webauthn.create","challenge":"wrong","origin":"https://evil.test","crossOrigin":true}')),
        ("authenticatorData", b64u(rp_hash + bytes((0x10,)) + (2).to_bytes(4, "big"))),
        ("signature", b64u(b"")),
        ("userHandle", "other"),
    )
    ids = _ids(depth.analyze_webauthn_ceremony(
        fields, ceremony="assertion", expected_challenge="right", expected_origin="https://app.test",
        expected_rp_id_hash=(b"B" * 32), previous_sign_count=3, expected_user_handle="user-1",
    ))
    assert {
        "webauthn-type-mismatch", "webauthn-challenge-mismatch", "webauthn-origin-mismatch",
        "webauthn-cross-origin", "webauthn-rp-id-hash", "webauthn-user-presence",
        "webauthn-user-verification", "webauthn-backup-flags", "webauthn-sign-count-rollback",
        "webauthn-signature-missing", "webauthn-user-handle",
    } <= ids


def test_webauthn_duplicate_client_fields_short_data_and_attestation_assurance():
    client = b64u('{"type":"webauthn.create","type":"webauthn.get","challenge":"x","origin":"https://app.test"}')
    fields = (("clientDataJSON", client), ("authenticatorData", b64u(b"short")),
              ("attestationObject", b64u(b"opaque")), ("fmt", "none"))
    ids = _ids(depth.analyze_webauthn_ceremony(fields, ceremony="registration"))
    assert {"webauthn-client-duplicate-type", "webauthn-type-mismatch",
            "webauthn-authenticator-data-short", "webauthn-attestation-assurance"} <= ids


def test_jwks_trust_boundary_clean_and_hostile_key_selection():
    clean = depth.analyze_jwks_trust_boundary(
        (("kid", "key-1"),), configured_issuer="https://idp.test/",
        configured_jwks_uri="https://idp.test/.well-known/jwks.json",
        saved_keys=(("key-1", "RSA", "RS256", "sig"),),
    )
    assert clean == ()
    hostile = depth.analyze_jwks_trust_boundary(
        (("kid", "../keys?id=*"), ("jku", "https://evil.test/jwks"),
         ("x5u", "http://127.0.0.1/cert"), ("jwk", "opaque")),
        configured_issuer="https://idp.test/",
        configured_jwks_uri="https://idp.test/jwks",
        saved_keys=(("other", "RSA", "RS256", "sig"),),
    )
    ids = _ids(hostile)
    assert {"jwks-structured-kid", "jwks-kid-cardinality", "jwks-jku-boundary",
            "jwks-x5u-url", "jwks-embedded-key", "jwks-multiple-key-sources"} <= ids


def test_jwks_duplicate_headers_and_cross_host_configuration_are_evidence():
    findings = depth.analyze_jwks_trust_boundary(
        (("kid", "a"), ("kid", "b")), configured_issuer="https://issuer.test/",
        configured_jwks_uri="https://keys.test/jwks",
    )
    assert {"jwks-duplicate-kid", "jwks-cross-host-configuration"} <= _ids(findings)


def test_jwks_exact_query_and_selected_key_algorithm_policy():
    findings = depth.analyze_jwks_trust_boundary(
        (("kid", "key-1"), ("alg", "HS256"), ("jku", "https://idp.test/jwks?set=other")),
        configured_issuer="https://idp.test/", configured_jwks_uri="https://idp.test/jwks?set=main",
        saved_keys=(("key-1", "RSA", "RS256", "enc"),),
    )
    assert {"jwks-jku-path", "jwks-alg-key-mismatch", "jwks-key-use"} <= _ids(findings)


def test_sso_oidc_saml_correlation_and_clean_control():
    bad = (
        ("oidc.discovery.issuer", "https://a.test"),
        ("oidc.callback.iss", "https://b.test"),
        ("oidc.request.state", "state-a"), ("oidc.callback.state", "state-b"),
        ("oidc.request.response_mode", "form_post"), ("session.cookie.samesite", "Strict"),
        ("saml.request.id", "REQ1"), ("saml.response.in_response_to", "REQ2"),
        ("saml.request.relay_state", "R1"), ("saml.response.relay_state", "R2"),
        ("saml.sp.acs", "https://sp.test/acs"), ("saml.response.destination", "https://evil.test/acs"),
    )
    assert {
        "sso-oidc-issuer-mixup", "sso-state-correlation", "sso-form-post-cookie",
        "sso-saml-request-correlation", "sso-saml-relay-state", "sso-saml-destination",
    } <= _ids(depth.correlate_sso_metadata(bad))
    clean = (
        ("oidc.discovery.issuer", "https://idp.test"), ("oidc.callback.iss", "https://idp.test"),
        ("oidc.request.state", "S"), ("oidc.callback.state", "S"),
        ("saml.request.id", "R"), ("saml.response.in_response_to", "R"),
        ("saml.request.relay_state", "X"), ("saml.response.relay_state", "X"),
        ("saml.sp.acs", "https://sp.test/acs"), ("saml.response.destination", "https://sp.test/acs"),
    )
    assert depth.correlate_sso_metadata(clean) == ()


def test_sso_nonce_client_redirect_and_saml_assertion_bindings():
    fields = (
        ("oidc.request.nonce", "N1"), ("oidc.id_token.nonce", "N2"),
        ("oidc.request.client_id", "client-a"), ("oidc.id_token.aud", "client-b"),
        ("oidc.request.redirect_uri", "https://sp.test/cb"),
        ("oidc.token.redirect_uri", "https://sp.test/other"),
        ("saml.sp.acs", "https://sp.test/acs"),
        ("saml.assertion.recipient", "https://evil.test/acs"),
        ("saml.sp.entity_id", "urn:sp"), ("saml.assertion.audience", "urn:other"),
        ("saml.idp.entity_id", "urn:idp"), ("saml.response.issuer", "urn:other-idp"),
    )
    assert {"sso-nonce-correlation", "sso-audience-correlation", "sso-redirect-uri-correlation",
            "sso-saml-recipient", "sso-saml-audience", "sso-saml-issuer"} <= _ids(
                depth.correlate_sso_metadata(fields)
            )


def test_graphql_field_auth_cost_and_resolver_idor_correlation():
    schema = """
type Query {
  public: String
  adminSecret: String
  billingEmail: String @auth
}
type Mutation {
  updateRole(id: ID!, role: String!): User
  updateName(id: ID!, name: String!): User @auth
}
"""
    query = "query Q { adminSecret " + " ".join(
        f"a{i}: users(first: 2000) {{ id }}" for i in range(16)
    ) + " } mutation M { updateRole(id: \"1\", role: \"x\") { id } }"
    source = "return db.findById(args.id)"
    ids = _ids(depth.analyze_graphql_field_policy(schema, query, source=source))
    assert {"graphql-field-authz", "graphql-mutation-authz", "graphql-cost-evidence",
            "graphql-resolver-idor"} <= ids
    clean = depth.analyze_graphql_field_policy(
        "type Query { adminSecret: String @auth }", "query Q { adminSecret }",
        source="authorize(context.user); return db.findById(args.id)",
    )
    assert clean == ()


def test_graphql_argument_labels_are_not_aliases_and_batch_shape_is_evidence():
    argument_heavy = "query Q { users(status: ACTIVE, order: DESC, first: 2) { id } }"
    assert depth.analyze_graphql_field_policy("type Query { users: [User] @auth }", argument_heavy) == ()
    batch = '[{"query":"{ viewer { id } }"},{"query":"{ viewer { id } }"}]'
    assert "graphql-batch-evidence" in _ids(depth.analyze_graphql_field_policy("", batch))


def test_hpp_mass_assignment_and_idor_source_analysis():
    request = (
        "PATCH /users/12345?id=one&id=two&Role=user HTTP/1.1\r\n"
        "Host: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
        "role=admin&role=user&userId=7&filter[x]=1"
    )
    source = "user = db.findById(request.params.id); Object.assign(user, request.body)"
    ids = _ids(depth.analyze_parameter_authorization(request, source=source))
    assert {"hpp-conflicting-values", "hpp-normalization", "parameter-mass-assignment",
            "parameter-idor-source", "parameter-whole-body-binding"} <= ids
    clean = "GET /public?q=one HTTP/1.1\r\nHost: app.test\r\n\r\n"
    assert depth.analyze_parameter_authorization(clean) == ()


def test_parameter_body_parser_selection_json_and_conflicting_content_type():
    misleading = "POST / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\nrole=admin&userId=7"
    assert depth.analyze_parameter_authorization(misleading) == ()
    json_request = 'PATCH /users/7 HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"role":"admin","userId":7}'
    assert "parameter-mass-assignment" in _ids(depth.analyze_parameter_authorization(json_request))
    ambiguous = ("POST / HTTP/1.1\r\nContent-Type: application/json\r\n"
                 "Content-Type: application/x-www-form-urlencoded\r\n\r\nrole=admin")
    assert "parameter-content-type-ambiguity" in _ids(depth.analyze_parameter_authorization(ambiguous))


def test_identity_api_plans_caps_and_malformed_inputs():
    plans = depth.build_identity_api_plans()
    assert [row.rank for row in plans] == list(range(1, len(plans) + 1))
    assert all(row.inert and row.offline and row.network_requests == 0 for row in plans)
    with pytest.raises(depth.IdentityAPIDepthError, match="ceremony"):
        depth.analyze_webauthn_ceremony((), ceremony="bad")
    with pytest.raises(depth.IdentityAPIDepthError, match="field count"):
        depth.analyze_webauthn_ceremony((("x", "y"),) * (depth.MAX_FIELDS + 1), ceremony="assertion")
    with pytest.raises(depth.IdentityAPIDepthError, match="malformed"):
        depth.analyze_parameter_authorization("not http")
    with pytest.raises(depth.IdentityAPIDepthError, match="32 bytes"):
        depth.analyze_webauthn_ceremony((), ceremony="assertion", expected_rp_id_hash="aa" * 1_000_000)
    with pytest.raises(depth.IdentityAPIDepthError, match="over cap"):
        depth.analyze_jwks_trust_boundary(
            (), configured_issuer="https://idp.test/", configured_jwks_uri="https://idp.test/jwks",
            saved_keys=(("K" * 4097, "RSA", "RS256", "sig"),),
        )


def test_identity_api_module_has_no_fetch_crypto_signing_or_deserialisation_surface():
    tree = ast.parse((WEB / "identity_api_depth.py").read_text(encoding="utf-8"))
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
                                     "pickle", "marshal", "json", "yaml", "cryptography", "Crypto"})
    assert not calls.intersection({"connect", "request", "send", "sendall", "urlopen", "Popen", "run",
                                   "loads", "load", "sign", "verify", "decrypt", "eval", "exec"})
