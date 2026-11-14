"""Published-vector tests for the offline JOSE edge analyzer."""

from __future__ import annotations

import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
import pytest

import webauth_jose_edge as jose


RFC7515_ES256 = (
    "eyJhbGciOiJFUzI1NiJ9."
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
    "pmWQxfKTUJqPP3-Kg6NU1Q"
)


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _token(header: dict[str, object], signature: bytes, payload: bytes = b"{}") -> str:
    return f"{_b64u(json.dumps(header, separators=(',', ':')).encode())}.{_b64u(payload)}.{_b64u(signature)}"


def _codes(report: dict[str, object]) -> set[str]:
    return {row["code"] for row in report["findings"]}


def test_rfc7515_appendix_a3_es256_vector_has_in_range_p1363_components():
    report = jose.analyze_jws(RFC7515_ES256)
    assert report["header"] == {"alg": "ES256"}
    assert report["signature"] == {
        "bytes": 64,
        "encoding": "IEEE-P1363",
        "component_bytes": 32,
        "curve": "P-256",
        "r_zero": False,
        "s_zero": False,
    }
    assert not {
        "psychic_signature_all_zero",
        "ecdsa_component_zero",
        "ecdsa_component_out_of_range",
        "ecdsa_signature_length",
    }.intersection(_codes(report))
    assert report["payload_json"]["iss"] == "joe"
    assert report["verified"] is False
    assert report["offline"] is True and report["network_requests"] == 0


def test_cve_2022_21449_documented_zero_signature_and_runtime_bounds():
    token = _token({"alg": "ES256"}, bytes(64))
    report = jose.analyze_jws(token, implementation="java-sunec", version="17.0.2")
    assert {"psychic_signature_all_zero", "ecdsa_component_zero"} <= _codes(report)
    assert report["signature"]["r_zero"] is report["signature"]["s_zero"] is True
    assert [row["id"] for row in report["implementation_matches"]] == ["CVE-2022-21449"]
    assert jose.implementation_risks("java-sunec", "17.0.3") == ()
    assert jose.implementation_risks("java-sunec", "18.0.0")[0]["id"] == "CVE-2022-21449"


def test_ecdsa_component_must_be_strictly_below_curve_order():
    # Published NIST P-256 subgroup order (SEC 2 / RFC 7518), independent of the engine table.
    order = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    signature = order.to_bytes(32, "big") + (1).to_bytes(32, "big")
    report = jose.analyze_jws(_token({"alg": "ES256"}, signature))
    assert "ecdsa_component_out_of_range" in _codes(report)
    assert "psychic_signature_all_zero" not in _codes(report)

    partial_zero = jose.analyze_jws(
        _token({"alg": "ES256"}, bytes(32) + (1).to_bytes(32, "big"))
    )
    assert "ecdsa_component_zero" in _codes(partial_zero)
    assert "psychic_signature_all_zero" not in _codes(partial_zero)


def test_token_to_jwks_binding_and_non_path_kid_injection_catalog():
    kid = "' OR (uid=*) -- café"
    token = _token({"alg": "HS256", "kid": kid}, b"x" * 32)
    jwks = {"keys": [{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig"}]}
    report = jose.analyze_jws(token, jwks=jwks)
    assert {
        "kid_sql_syntax",
        "kid_ldap_filter_syntax",
        "kid_unicode_normalization",
        "token_alg_key_family_mismatch",
        "token_alg_key_policy_mismatch",
    } <= _codes(report)
    assert report["selected_keys"] == [
        {"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig"}
    ]


def test_versioned_library_catalog_boundaries_are_explicit_not_guessed():
    assert [row["id"] for row in jose.implementation_risks("node-jsonwebtoken", "4.2.1")] == [
        "CVE-2015-9235"
    ]
    assert jose.implementation_risks("node-jsonwebtoken", "4.2.2") == ()
    assert {row["id"] for row in jose.implementation_risks("pyjwt", "1.5.0")} == {
        "CVE-2017-11424",
        "CVE-2022-29217",
    }
    assert {row["id"] for row in jose.implementation_risks("pyjwt", "1.4.0")} == {
        "CVE-2017-11424"
    }
    assert jose.implementation_risks("pyjwt", "2.4.0") == ()
    with pytest.raises(jose.WebauthJoseError, match="final release"):
        jose.implementation_risks("pyjwt", "2.4.0rc1")
    with pytest.raises(jose.WebauthJoseError, match="unknown implementation"):
        jose.implementation_risks("mystery-jwt", "1.0")


@pytest.mark.parametrize(
    "value",
    [
        "not-a-token",
        "@@@@.e30.",
        "eyJhbGciOiJFUzI1NiIsImFsZyI6IkhTMjU2In0.e30.",
        _token({"alg": "ES256", "x5c": ["not base64!"]}, b"x" * 64),
    ],
)
def test_malformed_public_inputs_raise_only_declared_error(value):
    with pytest.raises(jose.WebauthJoseError):
        jose.analyze_jws(value)

    valid = _token({"alg": "ES256"}, b"x" * 64)
    with pytest.raises(jose.WebauthJoseError):
        jose.analyze_jws(valid, expected_x5c_sha256=123)  # type: ignore[arg-type]


def test_real_x509_leaf_and_hmac_confusion_shape_use_independent_crypto_oracle():
    private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "offline.example")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2034, 1, 1))
        .sign(private, algorithm=None)
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(der).hexdigest()
    token = _token({"alg": "HS256", "x5c": [base64.b64encode(der).decode("ascii")]}, b"S" * 32)
    report = jose.analyze_jws(token, expected_x5c_sha256=fingerprint)
    assert report["certificates"][0]["sha256"] == fingerprint
    assert "CN=offline.example" in report["certificates"][0]["subject"]
    assert "x5c_leaf_fingerprint_mismatch" not in _codes(report)
    assert "x5c_hmac_key_confusion_shape" in _codes(report)


def test_guarded_cli_and_module_surface(capsys):
    assert jose.main(["analyze"]) == 2
    assert jose.main(["--not-an-option"]) == 2
    assert jose.main(["catalog"]) == 0
    output = capsys.readouterr().out
    assert "CVE-2022-21449" in output

    surrogate = _token({"alg": "HS256", "kid": "\ud800"}, b"S" * 32)
    assert jose.main(["analyze", surrogate]) == 2

    path = Path(jose.__file__)
    tree = ast.parse(path.read_text("utf-8"))
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

