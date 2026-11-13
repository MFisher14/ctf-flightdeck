"""Independent vector locks and deterministic fail-closed fuzz for webauth engines."""

from __future__ import annotations

import base64
import hashlib
import json
import random
import urllib.parse
import zlib

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from lxml import etree
import jwt
import pytest

import webauth_browser_catalog as browser
import webauth_jose_edge as jose
import webauth_oauth_edge as oauth
import webauth_saml_xsw as saml
import webauth_webauthn as webauthn


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _codes(report: object) -> set[str]:
    findings = report.findings if hasattr(report, "findings") else report["findings"]
    return {
        row.code if hasattr(row, "code") else row["code"]
        for row in findings
    }


def _only_declared(call, error: type[Exception]) -> None:
    try:
        call()
    except error:
        return
    except Exception as exc:  # pragma: no cover - this is the leak detector
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


def _random_bytes(seed: int, count: int = 48) -> list[bytes]:
    rng = random.Random(seed)
    return [rng.randbytes(rng.randrange(1, 160)) for _ in range(count)]


# ---------------------------------------------------------------------------
# SAML: bindings and XML signature structure


SAML_XML = (
    b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="R">'
    b'<saml:Assertion ID="A"><saml:Subject><saml:NameID>alice</saml:NameID>'
    b'</saml:Subject></saml:Assertion></samlp:Response>'
)


def _raw_deflate(value: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-15)
    return compressor.compress(value) + compressor.flush()


def test_saml_raw_and_redirect_vector_lock_uses_stdlib_and_no_entity_lxml_oracles():
    # lxml is oracle-only and is explicitly configured never to load a DTD,
    # resolve an entity, or access a network resource.
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    oracle_root = etree.fromstring(SAML_XML, parser=parser)
    assert oracle_root.tag.endswith("Response")

    redirect = base64.b64encode(_raw_deflate(SAML_XML)).decode("ascii")
    query = "SAMLResponse=" + urllib.parse.quote_plus(redirect)

    raw_result = saml.decode_saml_artifact(SAML_XML, binding="xml")
    redirect_result = saml.decode_saml_artifact(query, binding="redirect")
    assert raw_result["xml"] == redirect_result["xml"] == SAML_XML
    assert (raw_result["binding"], redirect_result["binding"]) == (
        "xml", "http-redirect"
    )

    report = saml.analyze_saml_artifact(SAML_XML)
    assert report["counts"] == {
        "elements": 4, "responses": 1, "assertions": 1,
        "signatures": 0, "references": 0,
    }
    assert report["assertions"][0]["name_ids"] == ["alice"]
    assert report["offline_only"] is True and report["network_requests"] == 0


def test_saml_bare_post_base64_preserves_standard_base64_plus_vector():
    # The stdlib base64 decoder is the independent binding oracle.  This
    # fixture intentionally contains '+' in its standard-base64 spelling.
    post = base64.b64encode(SAML_XML).decode("ascii")
    assert "+" in post
    assert base64.b64decode(post, validate=True) == SAML_XML
    result = saml.decode_saml_artifact(post, binding="post")
    assert result["xml"] == SAML_XML


def test_saml_external_entity_fixture_is_never_resolved():
    xxe = (
        b'<!DOCTYPE r [<!ENTITY external SYSTEM "file:///definitely-not-read">]>'
        b'<r>&external;</r>'
    )
    safe_parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    parsed = etree.fromstring(xxe, parser=safe_parser)
    assert parsed.text is None
    with pytest.raises(saml.WebauthSamlError, match="DTD|ENTITY"):
        saml.analyze_saml_artifact(xxe)


def test_saml_decode_and_analyze_fail_closed_fuzz_all_mutation_classes():
    flipped = bytearray(SAML_XML)
    flipped[len(flipped) // 2] ^= 0x80
    corpus: list[object] = [
        b"", None, 0, SAML_XML[:1], SAML_XML[: len(SAML_XML) // 2], SAML_XML[:-1],
        bytes(flipped), b"A" * (saml.MAX_ARTIFACT_BYTES + 1),
        *_random_bytes(0x5A4D4C),
    ]
    for value in corpus:
        _only_declared(lambda value=value: saml.decode_saml_artifact(value), saml.WebauthSamlError)
        _only_declared(lambda value=value: saml.analyze_saml_artifact(value), saml.WebauthSamlError)
    assert saml.main(["--definitely-invalid"]) == 2


# ---------------------------------------------------------------------------
# WebAuthn: W3C authenticator-data layout with cbor2 as the encoder oracle


RP_ID = "login.example"
ORIGIN = "https://login.example"
CHALLENGE = b"independent-webauthn-challenge"
CREDENTIAL_ID = b"cred-id-oracle"


def _registration_artifact() -> dict[str, object]:
    client = json.dumps({
        "type": "webauthn.create",
        "challenge": _b64u(CHALLENGE),
        "origin": ORIGIN,
        "crossOrigin": False,
    }, separators=(",", ":"), sort_keys=True).encode()
    cose_key = {1: 2, 3: -7, -1: 1, -2: b"X" * 32, -3: b"Y" * 32}
    auth_data = (
        hashlib.sha256(RP_ID.encode()).digest()
        + b"\x45"  # UP + UV + AT
        + (23).to_bytes(4, "big")
        + bytes.fromhex("00112233445566778899aabbccddeeff")
        + len(CREDENTIAL_ID).to_bytes(2, "big")
        + CREDENTIAL_ID
        + cbor2.dumps(cose_key, canonical=True)
    )
    attestation = cbor2.dumps(
        {"fmt": "none", "authData": auth_data, "attStmt": {}}, canonical=True
    )
    return {
        "id": _b64u(CREDENTIAL_ID),
        "rawId": _b64u(CREDENTIAL_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64u(client),
            "attestationObject": _b64u(attestation),
        },
    }


def test_webauthn_w3c_layout_vector_lock_with_cbor2_oracle():
    artifact = _registration_artifact()
    # Independent cbor2 round-trip establishes the bytes represented by the fixture.
    decoded = cbor2.loads(base64.urlsafe_b64decode(
        artifact["response"]["attestationObject"] + "=="  # type: ignore[index]
    ))
    assert decoded["fmt"] == "none"
    assert decoded["authData"][:32] == hashlib.sha256(RP_ID.encode()).digest()

    report = webauthn.analyze_webauthn(
        artifact,
        ceremony="registration",
        expected_challenge=CHALLENGE,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        require_uv=True,
        expected_credential_id=CREDENTIAL_ID,
    )
    assert report.findings == ()
    auth = report.metadata["authenticator_data"]
    assert auth["sign_count"] == 23
    assert auth["flag_names"] == ["UP", "UV", "AT"]
    assert auth["credential_id"] == _b64u(CREDENTIAL_ID)
    assert auth["cose_key"]["alg"] == -7
    assert report.offline and report.network_requests == 0


def test_webauthn_public_entrypoint_fail_closed_fuzz_all_mutation_classes():
    valid = json.dumps(_registration_artifact(), separators=(",", ":")).encode()
    flipped = bytearray(valid)
    flipped[len(flipped) // 2] ^= 0x40
    corpus: list[object] = [
        b"", None, [], {}, valid[:1], valid[: len(valid) // 2], valid[:-1], bytes(flipped),
        b"{" + b"A" * (webauthn.MAX_JSON_BYTES + 1),
        *_random_bytes(0x57414241),
    ]
    for value in corpus:
        _only_declared(
            lambda value=value: webauthn.analyze_webauthn(value),
            webauthn.WebauthnArtifactError,
        )
    assert webauthn.main(["--definitely-invalid"]) == 2


# ---------------------------------------------------------------------------
# Browser semantics: WHATWG named access, CSP fallback, documented CVEs


def test_browser_documented_semantics_vector_lock():
    dom = browser.analyze_dom_clobbering(
        '<form id="profile"><input name="next" value="https://evil.invalid"></form>',
        "location.assign(window.profile.next.value);",
    )
    chains = {row["chain"]: row for row in dom["chains"]}
    assert chains["profile.next"]["mechanism"] == "form named-property access"
    assert ("profile.next", "navigation") in {
        (row["chain"], row["sink"]) for row in dom["findings"]
    }

    # CSP uses the first duplicate directive and multiple policies intersect.
    parsed = browser.parse_csp_policies(
        "default-src 'none'; script-src https://clients1.google.com; script-src 'none'"
    )[0]
    scripts = [row for row in parsed.directives if row.name == "script-src"]
    assert [row.occurrence for row in scripts] == [1, 2]
    allowed = browser.analyze_csp(parsed.raw)
    assert "google_complete_jsonp" in {row["name"] for row in allowed["catalog_matches"]}
    blocked = browser.analyze_csp([parsed.raw, "default-src 'none'; script-src 'none'"])
    assert blocked["catalog_matches"] == []

    proto = browser.match_prototype_gadgets(
        "$.extend(true, {}, attackerInput);",
        '{"dependencies":{"jquery":"3.3.1"}}',
    )
    jquery = next(row for row in proto if row["name"] == "jquery_deep_extend")
    assert jquery["cve"] == "CVE-2019-11358"
    assert jquery["version_status"] == "affected-version"
    assert browser.analyze_prototype_catalog("", "")["offline"] is True

    assert {row.cve for row in browser.current_script_catalog()} >= {"CVE-2024-43788"}
    assert {row.name for row in browser.csp_gadget_catalog()} >= {"google_complete_jsonp"}
    assert {row.cve for row in browser.prototype_gadget_catalog()} >= {"CVE-2019-11358"}


def test_browser_untrusted_entrypoints_fail_closed_fuzz_all_mutation_classes():
    valid_html = b'<form id="x"><input name="y"></form>'
    valid_js = b"location.assign(window.x.y.value);"
    flipped = bytearray(valid_html)
    flipped[len(flipped) // 2] ^= 0x80
    text_corpus: list[object] = [
        b"", None, 7, valid_html[:1], valid_html[:-1], bytes(flipped),
        b"A" * (browser.MAX_HTML_BYTES + 1), *_random_bytes(0x42524F57),
    ]
    for value in text_corpus:
        _only_declared(
            lambda value=value: browser.analyze_dom_clobbering(value, valid_js),
            browser.WebauthBrowserError,
        )

    policy_corpus: list[object] = [
        "", None, b"script-src 'none'", [], ["script-src 'none'", 7],
        "script-src " + "a" * (browser.MAX_CSP_BYTES + 1),
        "script-src https://x.invalid\x00", "script-src https://[bad",
    ]
    policy_corpus.extend(
        raw.decode("latin1") for raw in _random_bytes(0x43535033, count=24)
    )
    for value in policy_corpus:
        _only_declared(
            lambda value=value: browser.parse_csp_policies(value),
            browser.WebauthBrowserError,
        )
        _only_declared(
            lambda value=value: browser.analyze_csp(value),
            browser.WebauthBrowserError,
        )

    js_corpus: list[object] = [
        b"", None, 3, valid_js[:1], valid_js[:-1],
        bytes(bytearray(valid_js[:-1]) + b"\xff"),
        b"J" * (browser.MAX_JS_BYTES + 1), *_random_bytes(0x50524F54),
    ]
    for value in js_corpus:
        _only_declared(
            lambda value=value: browser.match_prototype_gadgets(value),
            browser.WebauthBrowserError,
        )
        _only_declared(
            lambda value=value: browser.analyze_prototype_catalog(value),
            browser.WebauthBrowserError,
        )
    assert browser.build_parser().prog
    assert browser.main(["--definitely-invalid"]) == 2


# ---------------------------------------------------------------------------
# JOSE: real PyJWT/cryptography ES256 token plus hostile compact inputs


def test_jose_real_pyjwt_es256_vector_lock():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    token = jwt.encode(
        {"sub": "alice", "admin": False},
        private_key,
        algorithm="ES256",
        headers={"kid": "oracle-key"},
    )
    # The independent library verifies signature and claims before the static
    # engine is asked to describe the same compact artifact.
    assert jwt.decode(token, public_key, algorithms=["ES256"])["sub"] == "alice"
    report = jose.analyze_jws(token)
    assert report["header"]["alg"] == "ES256"
    assert report["payload_json"] == {"sub": "alice", "admin": False}
    assert report["signature"] == {
        "bytes": 64,
        "encoding": "IEEE-P1363",
        "component_bytes": 32,
        "curve": "P-256",
        "r_zero": False,
        "s_zero": False,
    }
    assert not {
        "ecdsa_signature_length", "ecdsa_component_zero",
        "ecdsa_component_out_of_range", "psychic_signature_all_zero",
    }.intersection(_codes(report))
    assert report["verified"] is False and report["network_requests"] == 0


def test_jose_catalog_documented_version_boundaries_and_copy_semantics():
    assert [row["id"] for row in jose.implementation_risks(
        "node-jsonwebtoken", "4.2.1"
    )] == ["CVE-2015-9235"]
    assert jose.implementation_risks("node-jsonwebtoken", "4.2.2") == ()
    catalog = jose.cve_catalog()
    assert {row["id"] for row in catalog} >= {"CVE-2022-21449", "CVE-2015-9235"}
    mutated = catalog[0]
    mutated["id"] = "changed"
    assert jose.cve_catalog()[0]["id"] == "CVE-2022-21449"


def test_jose_public_entrypoints_fail_closed_fuzz_all_mutation_classes():
    key = ec.generate_private_key(ec.SECP256R1())
    valid = jwt.encode({"sub": "fuzz"}, key, algorithm="ES256")
    flipped = list(valid)
    flipped[len(flipped) // 2] = "A" if flipped[len(flipped) // 2] != "A" else "B"
    corpus: list[object] = [
        "", None, b"a.b.c", 7, valid[:1], valid[: len(valid) // 2], valid[:-1],
        "".join(flipped), "A" * (jose.MAX_TOKEN_BYTES + 1),
    ]
    corpus.extend(raw.decode("latin1") for raw in _random_bytes(0x4A4F5345))
    for value in corpus:
        _only_declared(lambda value=value: jose.analyze_jws(value), jose.WebauthJoseError)

    for implementation, version in [
        (None, "1.0"), ("pyjwt", None), ("unknown", "1.0"),
        ("pyjwt", ""), ("pyjwt", "1."), (7, "1.0"),
        ("x" * 300, "1.0"), ("pyjwt", "9" * 300),
    ]:
        _only_declared(
            lambda implementation=implementation, version=version: jose.implementation_risks(
                implementation, version
            ),
            jose.WebauthJoseError,
        )
    assert jose.main(["--definitely-invalid"]) == 2


# ---------------------------------------------------------------------------
# OAuth: RFC 7636 Appendix B and normalized multi-flow evidence


RFC7636_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC7636_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def _oauth_flow() -> dict[str, object]:
    return {
        "id": "oracle-flow",
        "authorization": {
            "response_type": "code",
            "client_id": "client",
            "redirect_uri": "https://client.example/callback",
            "code_challenge": RFC7636_CHALLENGE,
            "code_challenge_method": "S256",
            "state": "state-value",
            "nonce": "nonce-value",
        },
        "callback": {
            "code": "code-value", "state": "state-value",
            "iss": "https://issuer.example",
        },
        "token_request": {"code_verifier": RFC7636_VERIFIER},
        "registered_redirect_uris": ["https://client.example/callback"],
        "id_token_claims": {
            "iss": "https://issuer.example", "sub": "alice",
            "aud": "client", "nonce": "nonce-value",
        },
        "metadata": {"issuer": "https://issuer.example"},
        "expected_issuer": "https://issuer.example",
        "callback_location": "query",
    }


def test_oauth_rfc7636_and_saved_flow_vector_lock():
    oracle = _b64u(hashlib.sha256(RFC7636_VERIFIER.encode("ascii")).digest())
    assert oracle == RFC7636_CHALLENGE
    assert oauth.pkce_s256(RFC7636_VERIFIER) == oracle

    serialized = json.dumps({"flows": [_oauth_flow()]}, separators=(",", ":"))
    loaded = oauth.load_flows(serialized)
    assert loaded == [_oauth_flow()]
    report = oauth.analyze_flows(loaded)
    assert report["flows"] == [{
        "id": "oracle-flow", "pkce_method": "S256", "pkce_bound": True,
        "nonce_bound": True, "response_types": ["code"],
        "callback_location": "query",
    }]
    assert report["offline"] is True and report["network_requests"] == 0


def test_oauth_public_entrypoints_fail_closed_fuzz_all_mutation_classes():
    valid_json = json.dumps({"flows": [_oauth_flow()]}, separators=(",", ":")).encode()
    flipped = bytearray(valid_json)
    flipped[len(flipped) // 2] ^= 0x80
    raw_corpus: list[object] = [
        b"", None, {}, valid_json[:1], valid_json[: len(valid_json) // 2],
        valid_json[:-1], bytes(flipped), b"[" + b"A" * (oauth.MAX_INPUT_BYTES + 1),
        *_random_bytes(0x4F415554),
    ]
    for value in raw_corpus:
        _only_declared(lambda value=value: oauth.load_flows(value), oauth.WebauthOAuthError)

    flow_corpus: list[object] = [
        [], None, {}, [None], ["bad"], [{"authorization": []}],
        [_oauth_flow()] * (oauth.MAX_FLOWS + 1),
    ]
    rng = random.Random(0x464C4F57)
    flow_corpus.extend([
        [{"id": f"random-{index}", "authorization": {
            "field": rng.randbytes(rng.randrange(1, 32)).hex(),
        }}]
        for index in range(24)
    ])
    for value in flow_corpus:
        _only_declared(lambda value=value: oauth.analyze_flows(value), oauth.WebauthOAuthError)

    verifier_corpus: list[object] = [
        "", None, 7, RFC7636_VERIFIER[:1], RFC7636_VERIFIER[:-1],
        RFC7636_VERIFIER + "!", "A" * 129,
    ]
    verifier_corpus.extend(
        _b64u(raw) for raw in _random_bytes(0x504B4345, count=24)
    )
    for value in verifier_corpus:
        _only_declared(lambda value=value: oauth.pkce_s256(value), oauth.WebauthOAuthError)
    assert oauth.main(["--definitely-invalid"]) == 2
