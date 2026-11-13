"""Deterministic tests for static JOSE, SAML, and OAuth/OIDC analysis."""

import ast
import base64
import hashlib
import json
from pathlib import Path

import pytest

import identity_flows as identity


def b64u(raw: bytes | str) -> str:
    if isinstance(raw, str):
        raw = raw.encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwt(header: str, payload: str, signature: bytes = b"") -> str:
    return f"{b64u(header)}.{b64u(payload)}.{b64u(signature)}"


def codes(report):
    return [item.code for item in report.findings]


def test_duplicate_jwt_fields_none_and_claim_bindings_are_evidence():
    token = jwt(
        '{"alg":"RS256","alg":"none","typ":"JWT"}',
        '{"iss":"wrong","aud":"other","nonce":"stale","exp":10}',
    )
    report = identity.analyze_jose(
        token,
        now=20,
        expected_issuer="https://issuer.example",
        expected_audience="client-1",
        expected_nonce="fresh",
    )
    assert report.artifact_type == "jwt_compact"
    assert report.duplicates == ("header.alg",)
    assert {
        "duplicate_field", "unsecured_algorithm", "expired", "issuer_mismatch",
        "audience_mismatch", "nonce_mismatch",
    }.issubset(codes(report))
    assert report.verified is report.replayed is False
    assert report.requests_sent == 0


@pytest.mark.parametrize(
    ("alg", "length", "expected_code"),
    [
        ("HS256", 31, "signature_length_mismatch"),
        ("ES256", 63, "signature_length_mismatch"),
        ("EdDSA", 65, "signature_length_mismatch"),
        ("RS256", 128, "rsa_signature_length_suspicious"),
    ],
)
def test_jws_cryptographic_signature_lengths(alg, length, expected_code):
    report = identity.analyze_jose(jwt(json.dumps({"alg": alg}), '{"sub":"u"}', b"x" * length))
    assert expected_code in codes(report)


def test_compact_jwe_checks_algorithm_iv_tag_and_key_shape():
    header = b64u('{"alg":"dir","enc":"A256GCM"}')
    token = f"{header}.{b64u(b'not-empty')}.{b64u(b'i' * 8)}.{b64u(b'cipher')}.{b64u(b't' * 12)}"
    report = identity.analyze_jose(token)
    assert report.artifact_type == "jwe_compact"
    assert {"direct_with_encrypted_key", "iv_length_mismatch", "tag_length_mismatch"}.issubset(codes(report))
    assert report.metadata["ciphertext_bytes"] == 6


def test_jwe_direct_ecdh_and_wrapped_cek_length_rules():
    direct_header = b64u('{"alg":"ECDH-ES","enc":"A128GCM","epk":{}}')
    direct = f"{direct_header}..{b64u(b'i' * 12)}.{b64u(b'c')}.{b64u(b't' * 16)}"
    direct_report = identity.analyze_jose(direct)
    assert "missing_encrypted_key" not in codes(direct_report)
    assert "invalid_ephemeral_key" in codes(direct_report)

    wrap_header = b64u('{"alg":"A128KW","enc":"A256GCM"}')
    wrapped = f"{wrap_header}.{b64u(b'k' * 24)}.{b64u(b'i' * 12)}.{b64u(b'c')}.{b64u(b't' * 16)}"
    wrapped_report = identity.analyze_jose(wrapped)
    assert "encrypted_key_length_mismatch" in codes(wrapped_report)


def test_pbes2_salt_and_unencoded_payload_critical_policy():
    header = b64u('{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2c":100,"p2s":"AQ"}')
    token = f"{header}.{b64u(b'k' * 24)}.{b64u(b'i' * 12)}.{b64u(b'c')}.{b64u(b't' * 16)}"
    assert "invalid_p2s" in codes(identity.analyze_jose(token))

    uncritical = jwt('{"alg":"none","b64":false}', '{}')
    assert "b64_not_critical" in codes(identity.analyze_jose(uncritical))


def test_jwe_json_detects_header_collisions_and_missing_encrypted_key():
    protected = b64u('{"alg":"A128KW","enc":"A128GCM"}')
    artifact = json.dumps({
        "protected": protected,
        "unprotected": {"alg": "dir"},
        "iv": b64u(b"i" * 12),
        "ciphertext": b64u(b"c"),
        "tag": b64u(b"t" * 16),
        "encrypted_key": "",
    })
    report = identity.analyze_jose(artifact)
    assert report.artifact_type == "jwe_json"
    assert "duplicate_header_parameter" in codes(report)
    assert "missing_encrypted_key" in codes(report)


def test_jws_json_checks_protected_header_and_claims():
    artifact = json.dumps({
        "payload": b64u('{"iss":"issuer","aud":"client"}'),
        "protected": b64u('{"alg":"ES256"}'),
        "signature": b64u(b"s" * 63),
    })
    report = identity.analyze_jose(artifact, expected_issuer="issuer", expected_audience="client")
    assert report.artifact_type == "jws_json"
    assert "signature_length_mismatch" in codes(report)
    assert report.metadata["claims"]["iss"] == "issuer"


def test_jwks_duplicate_kid_key_material_and_crypto_lengths():
    tiny_n = b64u((2**511 + 1).to_bytes(64, "big"))
    exponent = b64u((65537).to_bytes(3, "big"))
    key = {"kty": "RSA", "alg": "ES256", "kid": "same", "n": tiny_n, "e": exponent}
    report = identity.analyze_jose(json.dumps({"keys": [key, dict(key)]}))
    assert report.artifact_type == "jwks"
    assert {"alg_kty_mismatch", "weak_rsa_modulus", "duplicate_kid", "duplicate_key_material"}.issubset(codes(report))
    assert report.metadata["keys"][0]["bits"] == 512


def test_jwk_octet_length_private_material_and_key_ops():
    report = identity.analyze_jose(json.dumps({
        "kty": "oct",
        "alg": "HS512",
        "k": b64u(b"short"),
        "d": "unexpected",
        "use": "sig",
        "key_ops": ["sign", "encrypt", "sign"],
    }))
    assert {"short_symmetric_key", "private_key_material", "symmetric_key_material", "duplicate_key_ops", "use_key_ops_mismatch"}.issubset(codes(report))


def test_jwk_use_and_algorithm_are_checked_independently_of_key_ops():
    report = identity.analyze_jose(json.dumps({
        "kty": "RSA", "alg": "RSA-OAEP", "use": "sig",
        "n": b64u((2**2047 + 1).to_bytes(256, "big")), "e": b64u(b"\x01\x00\x01"),
    }))
    assert "use_alg_mismatch" in codes(report)


def test_jwk_algorithm_and_key_ops_conflict_is_separate_evidence():
    report = identity.analyze_jose(json.dumps({
        "kty": "oct", "alg": "HS256", "k": b64u(b"k" * 32),
        "key_ops": ["encrypt"],
    }))
    assert "alg_key_ops_mismatch" in codes(report)


def test_saml_xsw_duplicate_ids_reference_and_unsigned_assertion_evidence():
    xml = """<samlp:Response ID="R" Destination="https://sp.example/acs">
      <ds:Signature><ds:SignedInfo><ds:Reference URI="#A"/></ds:SignedInfo></ds:Signature>
      <saml:Issuer>https://idp.example</saml:Issuer>
      <saml:Assertion ID="A"><saml:Issuer>https://idp.example</saml:Issuer></saml:Assertion>
      <saml:Assertion Id="A"><saml:Audience>other</saml:Audience></saml:Assertion>
    </samlp:Response>"""
    report = identity.analyze_saml(
        xml,
        expected_issuer="https://idp.example",
        expected_destination="https://sp.example/acs",
        expected_audience="sp-entity",
    )
    assert report.metadata["parser"] == "none-regex-only"
    assert {"duplicate_id", "ambiguous_reference_target", "multiple_assertions", "unsigned_assertion_with_signature_elsewhere", "audience_mismatch"}.issubset(codes(report))
    assert "ID:A" in report.duplicates


def test_saml_reference_missing_target_and_correlation_checks():
    xml = '<samlp:Response ID="R"><ds:Signature><ds:Reference URI="#missing"/></ds:Signature></samlp:Response>'
    report = identity.analyze_saml(
        xml,
        expected_issuer="issuer",
        expected_destination="acs",
        expected_in_response_to="REQ-1",
    )
    assert {"missing_reference_target", "issuer_mismatch", "destination_mismatch", "in_response_to_mismatch"}.issubset(codes(report))


def test_saml_doctype_is_only_a_parser_precondition_lead():
    report = identity.analyze_saml('<!DOCTYPE x [<!ENTITY y "z">]><Response/>')
    finding = next(item for item in report.findings if item.code == "xml_declaration_surface")
    assert "parser" in finding.precondition
    assert report.verified is False


def test_complete_saved_oauth_oidc_flow_with_s256_is_clean_of_binding_errors():
    verifier = "A" * 43
    challenge = b64u(hashlib.sha256(verifier.encode()).digest())
    id_token = jwt(
        '{"alg":"ES256"}',
        '{"iss":"https://idp.example","aud":"client-1","nonce":"nonce-1234567890","exp":200}',
        b"s" * 64,
    )
    report = identity.analyze_oauth_flow(
        authorization_request=(
            "https://idp.example/auth?response_type=code&client_id=client-1"
            "&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid"
            "&state=state-1234567890&nonce=nonce-1234567890"
            f"&code_challenge={challenge}&code_challenge_method=S256"
        ),
        callback="https://app.example/cb?code=CODE1&state=state-1234567890&iss=https%3A%2F%2Fidp.example",
        token_request=(
            "grant_type=authorization_code&code=CODE1&client_id=client-1"
            "&redirect_uri=https%3A%2F%2Fapp.example%2Fcb"
            f"&code_verifier={verifier}"
        ),
        token_response=json.dumps({"access_token": "saved", "token_type": "Bearer", "id_token": id_token}),
        expected_state="state-1234567890",
        expected_nonce="nonce-1234567890",
        expected_redirect_uri="https://app.example/cb",
        expected_issuer="https://idp.example",
        expected_client_id="client-1",
        now=100,
    )
    binding_codes = {
        "callback_state_mismatch", "pkce_mismatch", "redirect_mismatch", "issuer_mismatch",
        "id_token.nonce_mismatch", "id_token.audience_mismatch", "id_token.issuer_mismatch",
    }
    assert not binding_codes.intersection(codes(report))
    assert report.metadata["pkce_method"] == "S256"
    assert report.requests_sent == 0


def test_oauth_duplicate_state_redirect_pkce_nonce_and_issuer_failures():
    report = identity.analyze_oauth_flow(
        authorization_request=(
            "response_type=code&client_id=wrong&redirect_uri=https%3A%2F%2Fevil.example%2Fcb"
            "&scope=openid&state=a&state=b&code_challenge=abc&code_challenge_method=plain"
        ),
        callback="code=C&state=wrong&iss=https%3A%2F%2Fevil-idp.example",
        token_request="grant_type=authorization_code&code=C&redirect_uri=https%3A%2F%2Fother.example%2Fcb",
        expected_state="expected-state-value",
        expected_nonce="expected-nonce",
        expected_redirect_uri="https://app.example/cb",
        expected_issuer="https://idp.example",
        expected_client_id="client-1",
    )
    assert {
        "duplicate_parameter", "missing_nonce", "weak_pkce_method", "redirect_mismatch",
        "client_id_mismatch", "callback_state_mismatch", "authorization_issuer_mismatch",
        "token_redirect_mismatch", "missing_pkce_verifier",
    }.issubset(codes(report))
    assert "authorization.state" in report.duplicates


def test_http_saved_request_lines_and_form_bodies_are_parsed_offline():
    report = identity.analyze_oauth_flow(
        authorization_request="GET /authorize?response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fa%2Fcb&state=1234567890123456 HTTP/1.1\r\nHost: idp\r\n\r\n",
        callback="GET /cb?code=X&state=1234567890123456 HTTP/1.1\r\nHost: a\r\n\r\n",
        token_request="POST /token HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ngrant_type=authorization_code&code=X&redirect_uri=https%3A%2F%2Fa%2Fcb",
    )
    assert report.metadata["authorization_fields"][:3] == ["response_type", "client_id", "redirect_uri"]
    assert "authorization_code_mismatch" not in codes(report)


def test_saved_http_json_response_body_and_pkce_challenge_syntax():
    report = identity.analyze_oauth_flow(
        authorization_request=(
            "response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fa%2Fcb"
            "&state=1234567890123456&code_challenge=short&code_challenge_method=S256"
        ),
        token_response=(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            '{"access_token":"saved","token_type":"DPoP"}'
        ),
    )
    assert "invalid_pkce_challenge" in codes(report)
    assert "unexpected_token_type" in codes(report)
    assert "access_token" in report.metadata["token_response_fields"]


@pytest.mark.parametrize("domain", ("jose", "saml", "oauth"))
def test_mutation_catalogs_are_stable_inert_non_wire_plans(domain):
    first = identity.build_mutation_skeletons(domain, marker="R5D_SAFE")
    second = identity.build_mutation_skeletons(domain, marker="R5D_SAFE")
    assert first == second
    assert first
    for plan in first:
        assert plan.skeleton.startswith("R5D_INERT_MUTATION|")
        assert plan.inert is plan.offline is True
        assert plan.wire_artifact is plan.signed is plan.replayable is False
        assert plan.preconditions
        assert all(character not in plan.skeleton for character in "{}<>")
        assert "http://" not in plan.skeleton and "https://" not in plan.skeleton


def test_bounds_duplicate_json_and_strict_input_types(monkeypatch):
    duplicate = identity.analyze_jose('{"kty":"oct","kty":"RSA","n":"AQ","e":"Aw"}')
    assert "json.kty" in duplicate.duplicates
    assert "duplicate_field" in codes(duplicate)
    monkeypatch.setattr(identity, "MAX_TOKEN_CHARS", 8)
    with pytest.raises(identity.IdentityInputError, match="exceeds"):
        identity.analyze_jose("x" * 9)
    with pytest.raises(identity.IdentityInputError, match="text or bytes"):
        identity.analyze_saml({"xml": "not implicitly stringified"})
    with pytest.raises(identity.IdentityInputError, match="expected_issuer"):
        identity.analyze_jose(jwt('{"alg":"none"}', '{}'), expected_issuer={"bad": "type"})


def test_safe_json_rejects_nonstandard_numbers_and_overdeep_data():
    with pytest.raises(identity.IdentityInputError, match="non-standard"):
        identity.analyze_jose('{"kty":"oct","k":NaN}')
    nested = '{"x":' * 40 + "0" + "}" * 40
    with pytest.raises(identity.IdentityInputError, match="nesting"):
        identity.analyze_jose(nested)


def test_module_has_no_network_xml_signing_or_replay_runtime():
    tree = ast.parse(Path(identity.__file__).read_text(encoding="utf-8"))
    forbidden_roots = {
        "requests", "httpx", "socket", "urllib.request", "lxml", "xml", "subprocess",
        "jwt", "jose", "saml", "pickle", "yaml",
    }
    imports: set[str] = set()
    direct_calls: set[str] = set()
    attribute_calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            direct_calls.add(node.func.id)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attribute_calls.add(node.func.attr)
    assert not {name.split(".")[0] for name in imports}.intersection(forbidden_roots)
    assert not direct_calls.intersection({"eval", "exec", "compile", "__import__"})
    assert not attribute_calls.intersection({"sign", "request", "send", "post"})

