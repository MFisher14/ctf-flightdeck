"""Deterministic tests for the strict offline WebAuthn artifact decoder.

The binary fixtures follow the authenticator-data and attested-credential-data
layouts in W3C WebAuthn.  CBOR is produced by the independent ``cbor2`` library,
not by code from the engine under test.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path

import cbor2
import pytest

import webauth_webauthn as webauthn


RP_ID = "app.example"
ORIGIN = "https://app.example"
CHALLENGE = b"published-layout-challenge"
CREDENTIAL_ID = b"credential-id-0001"
AAGUID = bytes.fromhex("00112233445566778899aabbccddeeff")


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def client_data(kind: str, challenge: bytes = CHALLENGE, origin: str = ORIGIN,
                **extra: object) -> bytes:
    value: dict[str, object] = {
        "type": kind,
        "challenge": b64u(challenge),
        "origin": origin,
        "crossOrigin": False,
    }
    value.update(extra)
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def public_ec2_key() -> dict[int, object]:
    return {1: 2, 3: -7, -1: 1, -2: b"X" * 32, -3: b"Y" * 32}


def registration(*, cose: dict[int, object] | None = None,
                 credential_id: bytes = CREDENTIAL_ID,
                 extensions: dict[object, object] | None = None) -> dict[str, object]:
    flags = 0x45 | (0x80 if extensions is not None else 0)
    auth_data = (
        hashlib.sha256(RP_ID.encode()).digest()
        + bytes((flags,))
        + (7).to_bytes(4, "big")
        + AAGUID
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + cbor2.dumps(cose or public_ec2_key(), canonical=True)
    )
    if extensions is not None:
        auth_data += cbor2.dumps(extensions, canonical=True)
    attestation = cbor2.dumps(
        {
            "fmt": "packed",
            "authData": auth_data,
            "attStmt": {"alg": -7, "sig": b"\x30\x00", "x5c": [b"\x30\x01"]},
        },
        canonical=True,
    )
    return {
        "id": b64u(credential_id),
        "rawId": b64u(credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(client_data("webauthn.create")),
            "attestationObject": b64u(attestation),
        },
    }


def assertion(*, credential_id: bytes = CREDENTIAL_ID, user_handle: bytes | None = b"alice") -> dict[str, object]:
    auth_data = (
        hashlib.sha256(RP_ID.encode()).digest()
        + b"\x05"  # UP + UV
        + (8).to_bytes(4, "big")
    )
    response: dict[str, object] = {
        "clientDataJSON": b64u(client_data("webauthn.get")),
        "authenticatorData": b64u(auth_data),
        "signature": b64u(b"opaque-assertion-signature"),
    }
    if user_handle is not None:
        response["userHandle"] = b64u(user_handle)
    return {
        "id": b64u(credential_id),
        "rawId": b64u(credential_id),
        "type": "public-key",
        "response": response,
    }


def codes(report: webauthn.WebauthnReport) -> set[str]:
    return {row.code for row in report.findings}


def test_registration_decodes_w3c_layout_cbor_cose_attestation_and_extensions():
    artifact = registration(extensions={"credProps": {"rk": True}})
    report = webauthn.analyze_webauthn(
        json.dumps(artifact),
        ceremony="registration",
        expected_challenge=CHALLENGE,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        require_uv=True,
        expected_credential_id=CREDENTIAL_ID,
        registered_credentials={b64u(CREDENTIAL_ID): "alice"},
        expected_owner="alice",
    )
    assert report.findings == ()
    assert report.offline is True and report.network_requests == 0
    assert report.cryptographically_verified is False
    auth = report.metadata["authenticator_data"]
    assert auth["rp_id_hash"] == hashlib.sha256(RP_ID.encode()).hexdigest()
    assert auth["aaguid"] == AAGUID.hex()
    assert auth["credential_id"] == b64u(CREDENTIAL_ID)
    assert auth["flag_names"] == ["UP", "UV", "AT", "ED"]
    assert auth["extensions"] == ["credProps"]
    assert auth["cose_key"] == {
        "kty": 2, "kty_name": "EC2", "alg": -7,
        "labels": ["-1", "-2", "-3", "1", "3"],
        "curve": 1, "x_bytes": 32, "y_bytes": 32,
    }
    assert report.metadata["attestation"]["format"] == "packed"
    assert report.metadata["attestation"]["certificate_count"] == 1


def test_assertion_binds_account_by_registered_credential_not_unsigned_user_handle():
    report = webauthn.analyze_webauthn(
        assertion(user_handle=b"mallory"),
        expected_challenge=b64u(CHALLENGE),
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        require_uv=True,
        registered_credentials={CREDENTIAL_ID: "alice"},
        expected_owner="alice",
    )
    assert codes(report) == {"user_handle_unsigned_hint"}
    finding = report.findings[0]
    assert "not covered" in finding.consequence
    assert report.metadata["registered_owner"] == "alice"
    assert report.metadata["authenticator_data"]["user_handle"] == b64u(b"mallory")


def test_account_substitution_is_detected_even_when_user_handle_names_victim():
    attacker_id = b"attacker-credential"
    report = webauthn.analyze_webauthn(
        assertion(credential_id=attacker_id, user_handle=b"alice"),
        expected_challenge=CHALLENGE,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        registered_credentials={attacker_id: "mallory", CREDENTIAL_ID: "alice"},
        expected_owner="alice",
    )
    assert {"user_handle_unsigned_hint", "credential_owner_mismatch"} <= codes(report)


def test_cose_algorithm_family_and_private_material_findings():
    rsa_claiming_es256 = {
        1: 3,
        3: -7,
        -1: b"\x80" + b"N" * 255,
        -2: b"\x01\x00\x01",
        -3: b"private-d",
    }
    report = webauthn.analyze_webauthn(
        registration(cose=rsa_claiming_es256),
        expected_challenge=CHALLENGE,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )
    assert {"cose_alg_kty_mismatch", "cose_private_key_material"} <= codes(report)
    assert report.metadata["authenticator_data"]["cose_key"]["modulus_bits"] == 2048

    unknown_alg = public_ec2_key()
    unknown_alg[3] = -999
    assert "unsupported_cose_alg" in codes(webauthn.analyze_webauthn(registration(cose=unknown_alg)))


@pytest.mark.parametrize(
    "origin",
    [
        "ftp://app.example",
        "https://app.example:bad",
        "https://user@app.example",
        "https://app.example/",
        "https://app.example?query",
        "http://app.example",
    ],
)
def test_web_origin_shape_rejects_non_serialized_or_untrustworthy_origins(origin):
    artifact = registration()
    artifact["response"]["clientDataJSON"] = b64u(client_data("webauthn.create", origin=origin))
    assert "origin_shape" in codes(webauthn.analyze_webauthn(artifact))


def test_loopback_origin_top_origin_and_user_handle_bounds():
    artifact = registration()
    artifact["response"]["clientDataJSON"] = b64u(
        client_data(
            "webauthn.create",
            origin="http://127.0.0.1:49152",
            crossOrigin=True,
            topOrigin="https://top.example/path",
        )
    )
    report = webauthn.analyze_webauthn(
        artifact, expected_origin="http://127.0.0.1:49152"
    )
    assert "origin_shape" not in codes(report)
    assert {"top_origin_shape", "cross_origin_ceremony"} <= codes(report)

    with pytest.raises(webauthn.WebauthnArtifactError, match="userHandle"):
        webauthn.analyze_webauthn(assertion(user_handle=b"A" * 65))

    with pytest.raises(webauthn.WebauthnArtifactError, match="expected_origin"):
        webauthn.analyze_webauthn(registration(), expected_origin="https://app.example:bad")


def test_duplicate_json_members_are_rejected_in_outer_and_exact_client_data():
    with pytest.raises(webauthn.WebauthnArtifactError, match="duplicate key 'id'"):
        webauthn.analyze_webauthn('{"id":"YQ","id":"Yg"}')

    artifact = registration()
    duplicate_client = (
        b'{"type":"webauthn.create","challenge":"YQ","challenge":"Yg",'
        b'"origin":"https://app.example"}'
    )
    artifact["response"]["clientDataJSON"] = b64u(duplicate_client)
    with pytest.raises(webauthn.WebauthnArtifactError, match="duplicate key 'challenge'"):
        webauthn.analyze_webauthn(artifact)


def test_trailing_and_duplicate_cbor_are_rejected_fail_closed():
    trailing = registration()
    raw = base64.urlsafe_b64decode(trailing["response"]["attestationObject"] + "==")
    trailing["response"]["attestationObject"] = b64u(raw + b"\x00")
    with pytest.raises(webauthn.WebauthnArtifactError, match="trailing"):
        webauthn.analyze_webauthn(trailing)

    base = registration()
    attestation = cbor2.loads(base64.urlsafe_b64decode(
        base["response"]["attestationObject"] + "=="
    ))
    # Independently encode a four-entry map containing duplicate text key "fmt".
    duplicate_map = (
        b"\xa4"
        + cbor2.dumps("fmt") + cbor2.dumps("packed")
        + cbor2.dumps("fmt") + cbor2.dumps("none")
        + cbor2.dumps("authData") + cbor2.dumps(attestation["authData"])
        + cbor2.dumps("attStmt") + cbor2.dumps({})
    )
    base["response"]["attestationObject"] = b64u(duplicate_map)
    with pytest.raises(webauthn.WebauthnArtifactError, match="duplicate map key"):
        webauthn.analyze_webauthn(base)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.update({"rawId": value["rawId"] + "="}),
        lambda value: value["response"].update({"clientDataJSON": b64u(b"\xff")}),
        lambda value: value["response"].update({"attestationObject": b64u(b"\xa1")}),
    ],
)
def test_malformed_public_inputs_raise_only_declared_error(mutator):
    artifact = registration()
    mutator(artifact)
    with pytest.raises(webauthn.WebauthnArtifactError):
        webauthn.analyze_webauthn(artifact)


def test_policy_mismatches_and_configurable_uv_are_findings_not_parser_crashes():
    artifact = assertion(user_handle=None)
    raw = base64.urlsafe_b64decode(artifact["response"]["authenticatorData"] + "==")
    artifact["response"]["authenticatorData"] = b64u(raw[:32] + b"\x01" + raw[33:])
    relaxed = webauthn.analyze_webauthn(
        artifact, expected_challenge=b"wrong", expected_origin="https://wrong.example",
        expected_rp_id="wrong.example", require_uv=False,
    )
    assert "user_verification_required" not in codes(relaxed)
    assert {"challenge_mismatch", "origin_mismatch", "rp_id_hash_mismatch"} <= codes(relaxed)
    strict = webauthn.analyze_webauthn(artifact, require_uv=True)
    assert "user_verification_required" in codes(strict)


def test_cli_outputs_json_and_guarded_argparse(tmp_path, capsys):
    artifact_path = tmp_path / "credential.json"
    artifact_path.write_text(json.dumps(registration()), encoding="utf-8")
    code = webauthn.main([
        str(artifact_path),
        "--ceremony", "registration",
        "--expected-challenge", b64u(CHALLENGE),
        "--expected-origin", ORIGIN,
        "--rp-id", RP_ID,
        "--require-uv",
    ])
    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ceremony"] == "registration"
    assert output["network_requests"] == 0
    assert webauthn.main(["--definitely-not-an-option"]) == 2

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (webauthn.MAX_JSON_BYTES + 1))
    assert webauthn.main([str(oversized)]) == 2


def test_module_is_offline_and_does_not_execute_or_deserialize_unsafely():
    path = Path(webauthn.__file__)
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
    assert not {name.split(".")[0] for name in imports}.intersection(
        {"socket", "requests", "httpx", "subprocess", "pickle", "yaml", "marshal"}
    )
    assert not calls.intersection({"eval", "exec", "urlopen", "request", "connect", "send"})

