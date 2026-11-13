"""Independent JOSE/auth vectors and fail-closed fuzz for the existing engines.

Oracles are PyJWT 2.15.1, jwcrypto 1.6.1, cryptography 50.0.2, and the
published RFC 7636/7638/7797 vectors.  No engine output is used to construct
an expected value, and all artifacts remain local.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import socket

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwe, jwk, jws

import auth_trust as auth
import identity_api_depth as api
import identity_flows as flows
import token_depth as token


HMAC_KEY = b"0123456789abcdef0123456789abcdef"
OCT_K = base64.urlsafe_b64encode(HMAC_KEY).rstrip(b"=").decode("ascii")
ATTACK_HEADERS = {
    "kid": "../../keys/current",
    "jku": "https://attacker.invalid/jwks.json",
    "x5u": "https://attacker.invalid/cert.pem",
    "jwk": {"kty": "oct", "k": OCT_K, "alg": "HS256"},
}
CLAIMS = {"sub": "alice", "role": "user", "scope": "read"}

# RFC 7638 section 3.1, including optional members intentionally omitted from
# the thumbprint input by the standard.
RFC7638_RSA = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
        "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64"
        "tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD"
        "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
        "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH"
        "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    ),
    "e": "AQAB",
    "alg": "RS256",
    "kid": "2011-04-29",
}
RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

# Fixed jwcrypto-produced artifacts. Tests also deserialize and verify them
# with jwcrypto before comparing the existing engines.
JWCRYPTO_JWE = (
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZml4ZWQifQ.."
    "wnZSK1w3LAzRt9-4.B6eVbx6mYiZINh-NFAQ3_u0dHGZ6zcyVpZ0XoXu4TjUVSco."
    "xCcjx5XjaqWvtnkWHOcWmw"
)
JWCRYPTO_JWE_CTY_NUMBER = (
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZml4ZWQiLCJjdHkiOjEyM30.."
    "xj9jMSdpNu59RqkV.QpfHJo7Er6wgA0d-45BxVMNWRacLO7SIAprmgY0Tzmem3ZQ."
    "TEBdaTmNYBfHQcNY7lgw3g"
)
JWCRYPTO_JWS_JSON = (
    '{"payload":"eyJzdWIiOiJhbGljZSIsImFkbWluIjpmYWxzZX0",'
    '"protected":"eyJhbGciOiJIUzI1NiIsImprdSI6Imh0dHBzOi8va2V5cy5leGFtcGxlL2p3a3MuanNvbiIsImtpZCI6ImZpeGVkIn0",'
    '"signature":"bxxvbb139w0Nn0OHQV61AkZuF18rucwt_rpHfGqpd6o"}'
)
JWCRYPTO_OCT = jwk.JWK(kty="oct", k=base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode())


def _pyjwt() -> str:
    return jwt.encode(CLAIMS, HMAC_KEY, algorithm="HS256", headers=ATTACK_HEADERS)


def _codes(report) -> list[str]:
    return [finding.code for finding in report.findings]


def _api_ids(rows) -> set[str]:
    return {row.finding_id for row in rows}


def _assert_declared_or_clean(call, declared) -> None:
    try:
        call()
    except declared:
        return


@pytest.fixture(autouse=True)
def _forbid_network(monkeypatch):
    def blocked(*_args, **_kwargs):
        raise AssertionError("test attempted a network request")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


# ---------------------------------------------------------------------------
# auth_trust.py: every public function has an independent vector.


def test_auth_inspect_and_hmac_confirmation_match_pyjwt():
    compact = _pyjwt()
    oracle_header = jwt.get_unverified_header(compact)
    oracle_claims = jwt.decode(compact, HMAC_KEY, algorithms=["HS256"])
    result = auth.inspect_jwt(compact)
    assert result["header"] == oracle_header
    assert result["payload"] == oracle_claims
    assert result["alg"] == oracle_header["alg"]
    assert result["kid"] == oracle_header["kid"]
    assert result["signature_present"] is True
    assert result["verified"] is False
    confirmed = auth.confirm_hmac_keys(compact, [b"wrong" * 8, HMAC_KEY])
    assert confirmed["confirmed"] is True
    assert confirmed["matches"] == [{"index": 1, "key": HMAC_KEY.decode()}]
    assert confirmed["tested"] == 2


def test_auth_forgers_are_verified_by_pyjwt_and_manual_hmac():
    hs384_key = HMAC_KEY * 2
    built = auth.forge_jwt(CLAIMS, key=hs384_key, alg="HS384", header={"kid": "local"})
    assert jwt.decode(built, hs384_key, algorithms=["HS384"]) == CLAIMS
    assert jwt.get_unverified_header(built) == {"alg": "HS384", "kid": "local", "typ": "JWT"}

    overridden = auth.apply_claim_overrides(
        {"sub": "alice", "roles": ["user"], "is_admin": False},
        {"scope": "flag:read"}, role="admin",
    )
    assert overridden == {
        "sub": "alice", "roles": ["admin", "user"], "is_admin": True,
        "scope": "flag:read",
    }

    captured = _pyjwt()
    forged = auth.forge_from_token(
        captured, key=HMAC_KEY, overrides={"scope": "flag:read"}, role="admin",
    )
    assert jwt.decode(forged["token"], HMAC_KEY, algorithms=["HS256"]) == {
        "sub": "alice", "role": "admin", "scope": "flag:read",
    }
    unsigned = auth.forge_alg_none(captured, role="admin")
    assert jwt.get_unverified_header(unsigned["token"])["alg"] == "none"
    assert jwt.decode(unsigned["token"], options={"verify_signature": False})["role"] == "admin"

    kids = auth.forge_kid_candidates(captured, key=HMAC_KEY, kids=["../../a", "key-b"])
    assert [jwt.get_unverified_header(row["token"])["kid"] for row in kids] == ["../../a", "key-b"]
    assert all(jwt.decode(row["token"], HMAC_KEY, algorithms=["HS256"])["role"] == "admin"
               for row in kids)


def test_auth_rsa_jwk_pem_matches_cryptography_and_confusion_mac():
    modulus = int.from_bytes(base64.urlsafe_b64decode(RFC7638_RSA["n"] + "=="), "big")
    exponent = int.from_bytes(base64.urlsafe_b64decode(RFC7638_RSA["e"] + "=="), "big")
    oracle_pem = rsa.RSAPublicNumbers(exponent, modulus).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert auth.rsa_jwk_to_pem(RFC7638_RSA) == oracle_pem
    assert auth.public_key_hmac_secret(RFC7638_RSA) == (oracle_pem, "jwks_canonical_spki_pem")
    assert auth.public_key_hmac_secret(oracle_pem) == (oracle_pem, "caller_supplied_pem_exact_bytes")

    captured = jwt.encode(CLAIMS, HMAC_KEY, algorithm="HS256", headers={"kid": "2011-04-29"})
    # The builder requires an RSA/PS declaration, but does not verify the captured signature.
    head, body, sig = captured.split(".")
    rsa_header = base64.urlsafe_b64encode(
        b'{"alg":"RS256","kid":"2011-04-29","typ":"JWT"}'
    ).rstrip(b"=").decode()
    declared_rsa = ".".join((rsa_header, body, sig))
    row = auth.forge_rs_hs_confusion(declared_rsa, RFC7638_RSA, role="admin")
    fhead, fpayload, fsig = row["token"].split(".")
    expected = hmac.new(oracle_pem, f"{fhead}.{fpayload}".encode(), hashlib.sha256).digest()
    assert base64.urlsafe_b64decode(fsig + "==") == expected
    assert jwt.get_unverified_header(row["token"])["alg"] == "HS256"
    assert jwt.decode(row["token"], options={"verify_signature": False})["role"] == "admin"


def test_auth_header_injection_and_client_role_vectors():
    captured = _pyjwt()
    for kind, extra in (
        ("jwk", {}),
        ("jku", {"url": "https://keys.example/jwks.json"}),
        ("x5u", {"url": "https://keys.example/cert.pem"}),
    ):
        row = auth.forge_header_key_injection(captured, kind=kind, key=HMAC_KEY, **extra)
        header = jwt.get_unverified_header(row["token"])
        assert kind in header
        assert jwt.decode(row["token"], HMAC_KEY, algorithms=["HS256"])["role"] == "admin"
        assert row["network_requests"] == 0

    rows = auth.forge_client_role(
        '{"role":"user","admin":false}', role="admin",
        storage_key="profile", cookie_name="profile",
    )
    assert json.loads(rows[0]["value"]) == {"admin": True, "role": "admin"}
    assert rows[0]["browser_operation"]["operation"] == "localStorage.setItem"
    assert rows[1]["request_header"] == {"Cookie": "profile=" + rows[1]["value"]}
    assert all(row["network_requests"] == 0 for row in rows)


def test_auth_valid_cli_uses_pyjwt_token(capsys):
    assert auth.main(["inspect", _pyjwt()]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["header"] == jwt.get_unverified_header(_pyjwt())
    assert result["payload"] == CLAIMS
    assert result["network_requests"] == 0


@pytest.mark.parametrize("algorithm", ["none", "None", "NONE", "hs256"])
def test_auth_forge_jwt_keeps_alg_confusion_variants(algorithm):
    compact = auth.forge_jwt(CLAIMS, key=HMAC_KEY, alg=algorithm)
    protected, payload, signature = compact.split(".")
    header = json.loads(base64.urlsafe_b64decode(protected + "=" * (-len(protected) % 4)))
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert header["alg"] == algorithm
    assert claims == CLAIMS
    if algorithm.lower() == "none":
        assert signature == ""
    else:
        expected = hmac.new(HMAC_KEY, f"{protected}.{payload}".encode("ascii"), hashlib.sha256).digest()
        assert base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)) == expected


@pytest.mark.parametrize("argv,expected", [(["--help"], 0), ([], 2)])
def test_auth_cli_never_leaks_systemexit(argv, expected):
    assert auth.main(argv) == expected


# ---------------------------------------------------------------------------
# identity_flows.py public entrypoints.


def test_identity_jwt_header_and_claims_match_pyjwt():
    compact = _pyjwt()
    report = flows.analyze_jose(compact)
    assert report.artifact_type == "jwt_compact"
    assert report.metadata["header"] == jwt.get_unverified_header(compact)
    assert report.metadata["claims"] == jwt.decode(compact, HMAC_KEY, algorithms=["HS256"])
    assert report.metadata["signature_bytes"] == 32
    assert _codes(report).count("remote_key_locator") == 2
    assert {"embedded_jwk", "structured_kid"} <= set(_codes(report))
    assert report.requests_sent == 0 and report.verified is False


def test_identity_jwcrypto_jwe_jws_json_and_rfc_jwk_vectors():
    oracle_jwe = jwe.JWE()
    oracle_jwe.deserialize(JWCRYPTO_JWE, key=JWCRYPTO_OCT)
    assert oracle_jwe.payload == b'{"sub":"alice","scope":"flag:read"}'
    jwe_report = flows.analyze_jose(JWCRYPTO_JWE)
    assert jwe_report.artifact_type == "jwe_compact"
    assert jwe_report.metadata == {
        "protected": {"alg": "dir", "enc": "A256GCM", "kid": "fixed"},
        "encrypted_key_bytes": 0, "iv_bytes": 12, "ciphertext_bytes": 35,
        "tag_bytes": 16, "segments": 5,
    }
    assert jwe_report.findings == ()

    oracle_jws = jws.JWS()
    oracle_jws.deserialize(JWCRYPTO_JWS_JSON)
    oracle_jws.verify(JWCRYPTO_OCT)
    assert oracle_jws.payload == b'{"sub":"alice","admin":false}'
    jws_report = flows.analyze_jose(JWCRYPTO_JWS_JSON)
    assert jws_report.artifact_type == "jws_json"
    assert jws_report.metadata["claims"] == {"sub": "alice", "admin": False}
    assert jws_report.metadata["signatures"] == [{
        "index": 0,
        "header": {"alg": "HS256", "jku": "https://keys.example/jwks.json", "kid": "fixed"},
        "signature_bytes": 32,
    }]
    assert _codes(jws_report) == ["remote_key_locator"]

    jwk_report = flows.analyze_jose(json.dumps(RFC7638_RSA))
    assert jwk_report.artifact_type == "jwk"
    assert jwk_report.metadata == {
        "keys": [{"index": 0, "kty": "RSA", "alg": "RS256", "kid": "2011-04-29",
                  "use": None, "bits": 2048, "exponent": 65537}],
        "key_count": 1,
    }
    assert jwk_report.findings == ()


def test_identity_saml_oauth_and_inert_plan_documented_semantics():
    saml = (
        '<samlp:Response ID="R" Destination="https://sp.example/acs">'
        '<ds:Signature><ds:SignedInfo><ds:Reference URI="#A"/></ds:SignedInfo></ds:Signature>'
        '<saml:Issuer>https://idp.example</saml:Issuer>'
        '<saml:Assertion ID="A"><saml:Audience>wrong-sp</saml:Audience></saml:Assertion>'
        '</samlp:Response>'
    )
    saml_report = flows.analyze_saml(
        saml, expected_issuer="https://idp.example",
        expected_destination="https://sp.example/acs", expected_audience="sp-entity",
    )
    assert "audience_mismatch" in _codes(saml_report)
    assert saml_report.metadata["parser"] == "none-regex-only"
    assert saml_report.requests_sent == 0

    # RFC 7636 appendix B verifier/challenge pair.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    oauth = flows.analyze_oauth_flow(
        authorization_request=(
            "response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fapp.example%2Fcb"
            f"&state=0123456789abcdef&code_challenge={challenge}&code_challenge_method=S256"
        ),
        callback="code=CODE&state=0123456789abcdef",
        token_request=(
            "grant_type=authorization_code&code=CODE&client_id=client"
            "&redirect_uri=https%3A%2F%2Fapp.example%2Fcb"
            f"&code_verifier={verifier}"
        ),
        expected_state="0123456789abcdef", expected_redirect_uri="https://app.example/cb",
        expected_client_id="client",
    )
    assert not {"pkce_mismatch", "callback_state_mismatch", "redirect_mismatch"}.intersection(_codes(oauth))
    assert oauth.metadata["pkce_method"] == "S256"
    assert oauth.requests_sent == 0

    plans = flows.mutation_catalog(marker="R5D_SAFE")
    assert plans == tuple(
        plan for domain in ("jose", "saml", "oauth")
        for plan in flows.build_mutation_skeletons(domain, marker="R5D_SAFE")
    )
    assert plans and all(plan.inert and not plan.wire_artifact and not plan.replayable for plan in plans)


@pytest.mark.parametrize("entry", ["jose", "saml", "oauth"])
def test_identity_text_entrypoints_reject_unencodable_unicode(entry):
    calls = {
        "jose": lambda: flows.analyze_jose("\ud800"),
        "saml": lambda: flows.analyze_saml("\ud800"),
        "oauth": lambda: flows.analyze_oauth_flow(authorization_request="\ud800"),
    }
    with pytest.raises(flows.IdentityInputError):
        calls[entry]()


# ---------------------------------------------------------------------------
# identity_api_depth.py: documented field and trust-boundary semantics.


def test_identity_api_webauthn_jwks_and_sso_vectors():
    rp_hash = hashlib.sha256(b"example.com").digest()
    client = base64.urlsafe_b64encode(
        b'{"type":"webauthn.get","challenge":"challenge-1","origin":"https://example.com"}'
    ).rstrip(b"=").decode()
    authenticator = base64.urlsafe_b64encode(
        rp_hash + bytes((0x05,)) + (2).to_bytes(4, "big")
    ).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(b"opaque signature").rstrip(b"=").decode()
    assert api.analyze_webauthn_ceremony(
        (("clientDataJSON", client), ("authenticatorData", authenticator),
         ("signature", signature), ("userHandle", "alice")),
        ceremony="assertion", expected_challenge="challenge-1",
        expected_origin="https://example.com", expected_rp_id_hash=rp_hash,
        previous_sign_count=1, expected_user_handle="alice",
    ) == ()

    header = jwt.get_unverified_header(_pyjwt())
    fields = tuple((name, json.dumps(value) if isinstance(value, dict) else value)
                   for name, value in header.items() if name in {"alg", "kid", "jku", "x5u", "jwk"})
    boundary = api.analyze_jwks_trust_boundary(
        fields, configured_issuer="https://idp.example/",
        configured_jwks_uri="https://idp.example/.well-known/jwks.json",
        saved_keys=((header["kid"], "RSA", "RS256", "enc"),),
    )
    assert {
        "jwks-structured-kid", "jwks-jku-boundary", "jwks-x5u-boundary",
        "jwks-embedded-key", "jwks-multiple-key-sources",
        "jwks-alg-key-mismatch", "jwks-key-use",
    } <= _api_ids(boundary)

    correlation = api.correlate_sso_metadata((
        ("oidc.request.state", "one"), ("oidc.callback.state", "two"),
        ("oidc.request.nonce", "n1"), ("oidc.id_token.nonce", "n2"),
        ("saml.request.id", "REQ1"), ("saml.response.in_response_to", "REQ2"),
    ))
    assert {"sso-state-correlation", "sso-nonce-correlation", "sso-saml-request-correlation"} <= _api_ids(correlation)


def test_identity_api_graphql_http_and_plan_vectors():
    graph = api.analyze_graphql_field_policy(
        "type Query {\n  adminSecret: String\n}\ntype Mutation {\n  updateRole(id: ID!): User\n}",
        'query { adminSecret } mutation { updateRole(id:"7") { id } }',
        source="return db.findById(args.id)",
    )
    assert {"graphql-field-authz", "graphql-mutation-authz", "graphql-resolver-idor"} <= _api_ids(graph)
    request = (
        "PATCH /users/7?id=one&id=two HTTP/1.1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        "role=admin&role=user&userId=7"
    )
    parameters = api.analyze_parameter_authorization(
        request, source="user = db.findById(request.params.id); Object.assign(user, request.body)",
    )
    assert {"hpp-conflicting-values", "parameter-mass-assignment", "parameter-idor-source",
            "parameter-whole-body-binding"} <= _api_ids(parameters)
    plans = api.build_identity_api_plans("R5D_SAFE")
    assert [plan.rank for plan in plans] == list(range(1, len(plans) + 1))
    assert all(plan.inert and plan.offline and plan.network_requests == 0 for plan in plans)


@pytest.mark.parametrize("entry", ["webauthn", "jwks", "sso", "graphql", "parameter"])
def test_identity_api_text_entrypoints_reject_unencodable_unicode(entry):
    calls = {
        "webauthn": lambda: api.analyze_webauthn_ceremony((("x", "\ud800"),), ceremony="assertion"),
        "jwks": lambda: api.analyze_jwks_trust_boundary(
            (("kid", "\ud800"),), configured_issuer="https://idp.example",
            configured_jwks_uri="https://idp.example/jwks",
        ),
        "sso": lambda: api.correlate_sso_metadata((("oidc.request.state", "\ud800"),)),
        "graphql": lambda: api.analyze_graphql_field_policy("\ud800", "{}"),
        "parameter": lambda: api.analyze_parameter_authorization("\ud800"),
    }
    with pytest.raises(api.IdentityAPIDepthError):
        calls[entry]()


def test_identity_api_saved_keys_type_is_fail_closed():
    with pytest.raises(api.IdentityAPIDepthError):
        api.analyze_jwks_trust_boundary(
            (), configured_issuer="https://idp.example",
            configured_jwks_uri="https://idp.example/jwks", saved_keys=None,
        )


# ---------------------------------------------------------------------------
# token_depth.py vectors from PyJWT, jwcrypto, and RFC 7638.


def test_token_base64_and_compact_jws_match_pyjwt():
    raw = b"\x00binary\xff"
    encoded = token.b64u_encode(raw)
    assert encoded == base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    assert token.b64u_decode(encoded) == raw

    compact = _pyjwt()
    oracle = jwt.api_jws.decode_complete(compact, key=HMAC_KEY, algorithms=["HS256"])
    result = token.parse_compact(compact)
    assert result["kind"] == "jws"
    assert result["protected"] == oracle["header"]
    assert result["payload"] == oracle["payload"]
    assert result["signature"] == oracle["signature"]
    assert result["protected"]["kid"] == ATTACK_HEADERS["kid"]
    assert result["protected"]["jku"] == ATTACK_HEADERS["jku"]
    assert result["protected"]["x5u"] == ATTACK_HEADERS["x5u"]


def test_token_jwcrypto_jwe_parse_and_decrypt():
    oracle = jwe.JWE()
    oracle.deserialize(JWCRYPTO_JWE, key=JWCRYPTO_OCT)
    parsed = token.parse_compact(JWCRYPTO_JWE)
    assert parsed["kind"] == "jwe"
    assert parsed["protected"] == oracle.jose_header
    assert len(parsed["iv"]) == 12 and len(parsed["tag"]) == 16
    result = token.decrypt_jwe(JWCRYPTO_JWE, bytes(range(32)))
    assert result["verified"] is True
    assert result["plaintext"] == oracle.payload == b'{"sub":"alice","scope":"flag:read"}'
    assert result["nested"] == {"sub": "alice", "scope": "flag:read"}
    assert result["requests_sent"] == 0


def test_token_rfc7638_thumbprint_and_jwcrypto_jws_verification():
    assert token.jwk_thumbprint(RFC7638_RSA) == RFC7638_THUMBPRINT
    assert jwk.JWK(**RFC7638_RSA).thumbprint() == RFC7638_THUMBPRINT

    compact = _pyjwt()
    oct_jwk = {"kty": "oct", "k": OCT_K, "alg": "HS256", "kid": ATTACK_HEADERS["kid"]}
    result = token.verify_jws(compact, oct_jwk)
    assert result["verified"] is True
    assert result["protected"] == jwt.get_unverified_header(compact)
    assert result["payload_json"] == jwt.decode(compact, HMAC_KEY, algorithms=["HS256"])
    assert result["thumbprint"] == jwk.JWK(**oct_jwk).thumbprint()
    assert result["requests_sent"] == 0


def test_token_assess_jwks_and_valid_cli(tmp_path, capsys):
    jwks = {"keys": [RFC7638_RSA, {"kty": "oct", "kid": "shared", "alg": "HS256", "k": OCT_K}]}
    report = token.assess_jwks(jwks)
    assert report["keys"][0]["thumbprint"] == RFC7638_THUMBPRINT
    assert report["keys"][1]["thumbprint"] == jwk.JWK(**jwks["keys"][1]).thumbprint()
    assert report["keys"][0]["bits"] == 2048
    assert report["urls_fetched"] == 0
    assert token.main(["inspect", _pyjwt(), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["protected"] == jwt.get_unverified_header(_pyjwt())


@pytest.mark.parametrize("crit", [None, []])
def test_token_verifies_rfc7797_b64_false_with_empty_crit(crit):
    header = {"alg": "HS256", "b64": False, "crit": crit}
    protected = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode("ascii")
    ).rstrip(b"=").decode()
    payload = "hello"
    signature = hmac.new(HMAC_KEY, f"{protected}.{payload}".encode(), hashlib.sha256).digest()
    compact = f"{protected}.{payload}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"
    result = token.verify_jws(compact, {"kty": "oct", "k": OCT_K, "alg": "HS256"})
    assert result["verified"] is True
    assert result["payload"] == b"hello"
    assert result["protected"]["b64"] is False
    assert result["protected"]["crit"] == crit


def test_token_flags_oct_symmetric_secret_as_private_material():
    report = token.assess_jwks({"keys": [{"kty": "oct", "kid": "secret", "k": OCT_K}]})
    assert "private_key_material" in {row["kind"] for row in report["findings"]}


def test_token_unencoded_nonascii_payload_is_fail_closed():
    protected = base64.urlsafe_b64encode(
        b'{"alg":"HS256","b64":false,"crit":["b64"]}'
    ).rstrip(b"=").decode()
    with pytest.raises(token.TokenError):
        token.parse_compact(f"{protected}.\u00e9.")


def test_token_authenticated_bad_cty_type_is_fail_closed():
    oracle = jwe.JWE()
    oracle.deserialize(JWCRYPTO_JWE_CTY_NUMBER, key=JWCRYPTO_OCT)
    assert oracle.jose_header["cty"] == 123
    with pytest.raises(token.TokenError):
        token.decrypt_jwe(JWCRYPTO_JWE_CTY_NUMBER, bytes(range(32)))


def test_token_b64u_encode_wrong_type_is_fail_closed():
    with pytest.raises(token.TokenError):
        token.b64u_encode(None)


def test_token_thumbprint_hash_type_is_fail_closed():
    with pytest.raises(token.TokenError):
        token.jwk_thumbprint({"kty": "oct", "k": OCT_K}, None)


def test_token_assess_jwks_host_type_is_fail_closed():
    with pytest.raises(token.TokenError):
        token.assess_jwks(b'{"keys":[]}')


def test_token_cli_help_returns_cleanly():
    assert token.main(["--help"]) == 0


# ---------------------------------------------------------------------------
# Deterministic malformed-input corpus. Accepting a structurally valid mutation
# is permitted; the boundary being locked is clean return or declared error.


def _compact_corpus(valid: str) -> list[object]:
    rng = random.Random(0x5745424155544832)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.%="
    rows: list[object] = ["", ".", "..", "...", "\xff" * 64, b"\xff" * 64, None, 17]
    rows.extend(valid[:index] for index in range(min(len(valid), 80)))
    for index in range(0, len(valid), max(1, len(valid) // 32)):
        replacement = alphabet[(index * 17) % len(alphabet)]
        rows.append(valid[:index] + replacement + valid[index + 1:])
    rows.extend("".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 200))) for _ in range(128))
    return rows


def test_auth_token_entrypoints_fail_closed_fuzz(monkeypatch):
    valid = _pyjwt()
    cap = len(valid) + 8
    monkeypatch.setattr(auth, "MAX_TOKEN_CHARS", cap)
    corpus = _compact_corpus(valid) + ["A" * (cap + 1)]
    token_calls = (
        lambda value: auth.inspect_jwt(value),
        lambda value: auth.confirm_hmac_keys(value, [HMAC_KEY]),
        lambda value: auth.forge_from_token(value, key=HMAC_KEY),
        lambda value: auth.forge_alg_none(value),
        lambda value: auth.forge_kid_candidates(value, key=HMAC_KEY, kids=["key"]),
        lambda value: auth.forge_rs_hs_confusion(value, RFC7638_RSA),
        lambda value: auth.forge_header_key_injection(
            value, kind="jku", key=HMAC_KEY, url="https://keys.example/jwks",
        ),
    )
    for value in corpus:
        for call in token_calls:
            _assert_declared_or_clean(lambda call=call, value=value: call(value), auth.AuthInputError)


def test_auth_other_public_entrypoints_fail_closed_fuzz():
    calls = (
        lambda: auth.forge_jwt(None),
        lambda: auth.apply_claim_overrides(None),
        lambda: auth.rsa_jwk_to_pem({}),
        lambda: auth.public_key_hmac_secret(object()),
        lambda: auth.forge_client_role("\xff" * (auth.MAX_CONTAINER_CHARS + 1)),
    )
    for call in calls:
        with pytest.raises(auth.AuthInputError):
            call()


def test_identity_public_entrypoints_fail_closed_fuzz(monkeypatch):
    valid = _pyjwt()
    cap = len(valid) + 8
    monkeypatch.setattr(flows, "MAX_TOKEN_CHARS", cap)
    for value in _compact_corpus(valid) + ["A" * (cap + 1)]:
        _assert_declared_or_clean(lambda value=value: flows.analyze_jose(value), flows.IdentityInputError)
    for value in ("", b"", b"\xff" * 64, "<Response", "x" * 1024, 17, None):
        _assert_declared_or_clean(lambda value=value: flows.analyze_saml(value), flows.IdentityInputError)
        _assert_declared_or_clean(
            lambda value=value: flows.analyze_oauth_flow(authorization_request=value),
            flows.IdentityInputError,
        )
    for call in (
        lambda: flows.build_mutation_skeletons("bad"),
        lambda: flows.build_mutation_skeletons("jose", marker="x"),
        lambda: flows.mutation_catalog(marker="x"),
    ):
        with pytest.raises(flows.IdentityInputError):
            call()


def test_identity_api_public_entrypoints_fail_closed_fuzz(monkeypatch):
    monkeypatch.setattr(api, "MAX_TEXT_BYTES", 128)
    text_corpus = ("", b"", b"\xff" * 64, "{" * 64, "A" * 129, None, 17)
    for value in text_corpus:
        _assert_declared_or_clean(
            lambda value=value: api.analyze_graphql_field_policy(value, value),
            api.IdentityAPIDepthError,
        )
        _assert_declared_or_clean(
            lambda value=value: api.analyze_parameter_authorization(value),
            api.IdentityAPIDepthError,
        )
    bad_fields = ((), (("kid", "%" * 10),), (("x", "\xff" * 64),), None, "kid=x", (("x",),))
    for fields in bad_fields:
        _assert_declared_or_clean(
            lambda fields=fields: api.analyze_webauthn_ceremony(fields, ceremony="assertion"),
            api.IdentityAPIDepthError,
        )
        _assert_declared_or_clean(
            lambda fields=fields: api.correlate_sso_metadata(fields), api.IdentityAPIDepthError,
        )
        _assert_declared_or_clean(
            lambda fields=fields: api.analyze_jwks_trust_boundary(
                fields, configured_issuer="https://idp.example",
                configured_jwks_uri="https://idp.example/jwks",
            ), api.IdentityAPIDepthError,
        )
    with pytest.raises(api.IdentityAPIDepthError):
        api.build_identity_api_plans("x")


def test_token_compact_entrypoints_fail_closed_fuzz(monkeypatch):
    valid = _pyjwt()
    oct_jwk = {"kty": "oct", "k": OCT_K, "alg": "HS256"}
    cap = len(valid) + 8
    monkeypatch.setattr(token, "MAX_TOKEN", cap)
    for value in _compact_corpus(valid) + ["A" * (cap + 1)]:
        _assert_declared_or_clean(lambda value=value: token.b64u_decode(value), token.TokenError)
        _assert_declared_or_clean(lambda value=value: token.parse_compact(value), token.TokenError)
        _assert_declared_or_clean(
            lambda value=value: token.verify_jws(value, oct_jwk), token.TokenError,
        )
        _assert_declared_or_clean(
            lambda value=value: token.decrypt_jwe(value, bytes(range(32))), token.TokenError,
        )
    assert token.b64u_encode(b"") == ""
    assert token.b64u_encode(b"\xff" * 4096) == base64.urlsafe_b64encode(b"\xff" * 4096).rstrip(b"=").decode()


def test_token_jwk_entrypoints_fail_closed_fuzz():
    for value in ({}, {"kty": "oct"}, {"kty": "RSA", "n": "!", "e": "AQAB"}, None, [], "x", 17):
        _assert_declared_or_clean(lambda value=value: token.jwk_thumbprint(value), token.TokenError)
    for value in ({}, {"keys": []}, {"keys": [None]}, {"keys": [{}]}, {"keys": [1] * (token.MAX_KEYS + 1)}):
        _assert_declared_or_clean(lambda value=value: token.assess_jwks(value), token.TokenError)
    assert token.main([]) == 2
    assert token.main(["inspect", "truncated"]) == 2
