"""Authenticated offline JWE/JWS/JWK round trips and parser hardening."""
from __future__ import annotations

import hashlib
import hmac
import json
import random
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))

import token_depth as token  # noqa: E402


def _segment(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return token.b64u_encode(raw)


def _direct_jwe(plaintext, key, header=None):
    protected = _segment(header or {"alg": "dir", "enc": "A256GCM", "cty": "JWT"})
    iv = bytes.fromhex("00112233445566778899aabb")
    encrypted = AESGCM(key).encrypt(iv, plaintext, protected.encode())
    return ".".join((protected, "", token.b64u_encode(iv),
                     token.b64u_encode(encrypted[:-16]), token.b64u_encode(encrypted[-16:])))


def _cbc_kw_jwe(plaintext, kek, cek):
    protected = _segment({"alg": "A128KW", "enc": "A128CBC-HS256"})
    iv = bytes.fromhex("00112233445566778899aabbccddeeff")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(cek[16:]), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    aad = protected.encode()
    tag = hmac.new(cek[:16], aad + iv + ciphertext + (len(aad) * 8).to_bytes(8, "big"),
                   hashlib.sha256).digest()[:16]
    wrapped = aes_key_wrap(kek, cek)
    return ".".join((protected, token.b64u_encode(wrapped), token.b64u_encode(iv),
                     token.b64u_encode(ciphertext), token.b64u_encode(tag)))


def test_direct_a256gcm_nested_jwt_authenticates_before_return():
    key = bytes.fromhex("00" * 32)
    nested = _segment({"alg": "none", "typ": "JWT"}) + "." + _segment(
        {"sub": "fixture", "flag": "CSCTF{jwe_verified}"}) + "."
    compact = _direct_jwe(nested.encode(), key)
    result = token.decrypt_jwe(compact, key)
    assert result["verified"] and result["plaintext"] == nested.encode()
    assert result["nested"]["protected"]["alg"] == "none"
    damaged = compact[:-1] + ("A" if compact[-1] != "A" else "B")
    with pytest.raises(token.TokenError, match="authentication"):
        token.decrypt_jwe(damaged, key)


def test_aes_key_wrap_cbc_hmac_roundtrip_and_tamper():
    kek = bytes.fromhex("11" * 16)
    cek = bytes.fromhex("22" * 32)
    compact = _cbc_kw_jwe(b"CSCTF{cbc_hmac_jwe}", kek, cek)
    assert token.decrypt_jwe(compact, kek)["plaintext"] == b"CSCTF{cbc_hmac_jwe}"
    parts = compact.split(".")
    tag = bytearray(token.b64u_decode(parts[-1])); tag[0] ^= 1
    parts[-1] = token.b64u_encode(bytes(tag))
    with pytest.raises(token.TokenError, match="authentication"):
        token.decrypt_jwe(".".join(parts), kek)


def test_rfc7638_jwks_confusion_and_private_material_findings():
    material = token.b64u_encode(b"tiny-shared-key")
    jwks = {"keys": [
        {"kty": "oct", "kid": "dup", "alg": "HS256", "k": material},
        {"kty": "oct", "kid": "dup", "alg": "RS256", "k": token.b64u_encode(b"different")},
        {"kty": "oct", "kid": "other", "alg": "HS256", "k": material, "d": "leak"},
    ]}
    report = token.assess_jwks(jwks)
    kinds = {row["kind"] for row in report["findings"]}
    assert {"duplicate_kid", "same_key_multiple_kids", "alg_key_type_mismatch",
            "private_key_material", "short_symmetric_key"} <= kinds
    expected = token.b64u_encode(hashlib.sha256(
        json.dumps({"k": material, "kty": "oct"}, sort_keys=True,
                   separators=(",", ":")).encode()).digest())
    assert token.jwk_thumbprint(jwks["keys"][0]) == expected
    assert report["urls_fetched"] == 0


def test_hmac_jws_is_verified_with_exact_jwk_only():
    key = b"known-offline-key-material-32bytes"
    protected, payload = _segment({"alg": "HS256", "kid": "local"}), _segment(
        {"flag": "CSCTF{jws_verified}"})
    signed = (protected + "." + payload).encode()
    compact = protected + "." + payload + "." + token.b64u_encode(hmac.new(key, signed, hashlib.sha256).digest())
    jwk = {"kty": "oct", "kid": "local", "alg": "HS256", "k": token.b64u_encode(key)}
    result = token.verify_jws(compact, jwk)
    assert result["verified"] and result["payload_json"]["flag"] == "CSCTF{jws_verified}"
    wrong = {**jwk, "k": token.b64u_encode(b"x" * 32)}
    assert token.verify_jws(compact, wrong)["verified"] is False


def test_guarded_cli_and_strict_duplicate_json(tmp_path, capsys):
    compact = _direct_jwe(b"marker", bytes(32), {"alg": "dir", "enc": "A256GCM"})
    assert token.main(["inspect", compact, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "jwe"
    assert token.main([]) == 2
    assert "Traceback" not in capsys.readouterr().err
    bad_header = token.b64u_encode(b'{"alg":"none","alg":"HS256"}')
    with pytest.raises(token.TokenError, match="duplicate"):
        token.parse_compact(bad_header + ".e30.")


def test_seeded_compact_mutation_has_one_error_boundary():
    rng = random.Random(0x705E)
    seed = _direct_jwe(b"CSCTF{mutate}", bytes(32))
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.=%"
    for _ in range(1000):
        chars = list(seed)
        for _ in range(rng.randrange(1, 8)):
            action = rng.randrange(3)
            if action == 0 and chars:
                chars[rng.randrange(len(chars))] = rng.choice(alphabet)
            elif action == 1 and chars:
                del chars[rng.randrange(len(chars))]
            else:
                chars.insert(rng.randrange(len(chars) + 1), rng.choice(alphabet))
        try:
            parsed = token.parse_compact("".join(chars))
            assert parsed["kind"] in {"jws", "jwe"}
        except token.TokenError:
            pass
