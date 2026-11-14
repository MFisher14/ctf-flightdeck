"""Round-5 crypto depth: ECDH-ES, signature faults, MAC misuse, and lattice guards."""
from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "web"))

import crypto_faults as faults  # noqa: E402
import lattice_backends as backends  # noqa: E402
import lattice_tools as lattices  # noqa: E402
import modern_crypto  # noqa: E402
import shamir_totp as shamir  # noqa: E402
import token_depth as token  # noqa: E402
from ctf import triage  # noqa: E402


def test_shamir_prime_field_declines_composite_ring_even_when_shares_interpolate():
    # These four points lie on 4 + 2*x modulo every listed composite and previously produced a
    # supposedly verified secret because the selected denominators happened to be invertible.
    for modulus in (9, 15, 21, 25, 35, 49, 77):
        points = [(x, (4 + 2 * x) % modulus) for x in range(1, 5)]
        assert shamir.recover_prime(points, modulus, threshold=2) is None
        assert shamir.recover_prime(points, modulus) is None
    assert shamir.recover_prime([(True, 6), (2, 8), (3, 10)], 7919, threshold=2) is None
    assert shamir.recover_prime([(1, 6), (2, 8), (3, 10)], 7919, threshold=2.0) is None

    # The share cap is a refusal boundary, not permission to verify a valid prefix while silently
    # ignoring a contradictory 257th share.
    capped = [(x, (4 + 2 * x) % 7919) for x in range(1, shamir.MAX_SHARES + 1)]
    capped.append((shamir.MAX_SHARES + 1, 0))
    assert shamir.recover_prime(capped, 7919, threshold=2) is None


def _segment(value):
    return token.b64u_encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _other_info(algorithm: str, apu: bytes, apv: bytes, bits: int) -> bytes:
    field = lambda value: len(value).to_bytes(4, "big") + value
    return field(algorithm.encode()) + field(apu) + field(apv) + bits.to_bytes(4, "big")


def _gcm_compact(header, encrypted_key: bytes, cek: bytes, plaintext: bytes) -> str:
    protected = _segment(header)
    iv = bytes.fromhex("00112233445566778899aabb")
    sealed = AESGCM(cek).encrypt(iv, plaintext, protected.encode())
    return ".".join((protected, token.b64u_encode(encrypted_key), token.b64u_encode(iv),
                     token.b64u_encode(sealed[:-16]), token.b64u_encode(sealed[-16:])))


def test_p256_direct_ecdh_es_crosschecks_cryptography_concat_kdf():
    recipient = ec.derive_private_key(0x123456789ABCDEF, ec.SECP256R1())
    ephemeral = ec.derive_private_key(0xFEDCBA987654321, ec.SECP256R1())
    numbers = ephemeral.public_key().public_numbers()
    apu, apv = b"Alice", b"Bob"
    header = {"alg": "ECDH-ES", "enc": "A256GCM", "apu": token.b64u_encode(apu),
              "apv": token.b64u_encode(apv), "epk": {
                  "kty": "EC", "crv": "P-256",
                  "x": token.b64u_encode(numbers.x.to_bytes(32, "big")),
                  "y": token.b64u_encode(numbers.y.to_bytes(32, "big")),
              }}
    shared = ephemeral.exchange(ec.ECDH(), recipient.public_key())
    independent = ConcatKDFHash(
        algorithm=hashes.SHA256(), length=32,
        otherinfo=_other_info("A256GCM", apu, apv, 256),
    ).derive(shared)
    assert token._ecdh_derived_key(header, recipient, "A256GCM", 32) == independent
    compact = _gcm_compact(header, b"", independent, b"CSCTF{p256_ecdh_es_verified}")
    assert token.decrypt_jwe(compact, recipient)["plaintext"] == b"CSCTF{p256_ecdh_es_verified}"

    wrong = ec.derive_private_key(7, ec.SECP256R1())
    with pytest.raises(token.TokenError, match="authentication"):
        token.decrypt_jwe(compact, wrong)
    poisoned = json.loads(json.dumps(header))
    poisoned["epk"]["d"] = token.b64u_encode(b"x" * 32)
    with pytest.raises(token.TokenError, match="private"):
        token._ecdh_derived_key(poisoned, recipient, "A256GCM", 32)


def test_x25519_ecdh_es_a256kw_and_private_jwk_round_trip():
    recipient = x25519.X25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    ephemeral = x25519.X25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
    public_raw = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    header = {"alg": "ECDH-ES+A256KW", "enc": "A128GCM", "epk": {
        "kty": "OKP", "crv": "X25519", "x": token.b64u_encode(public_raw)}}
    shared = ephemeral.exchange(recipient.public_key())
    kek = ConcatKDFHash(algorithm=hashes.SHA256(), length=32,
                        otherinfo=_other_info("ECDH-ES+A256KW", b"", b"", 256)).derive(shared)
    cek = bytes.fromhex("a5" * 16)
    compact = _gcm_compact(header, aes_key_wrap(kek, cek), cek, b"CSCTF{x25519_kw_verified}")
    private_raw = recipient.private_bytes(serialization.Encoding.Raw,
                                          serialization.PrivateFormat.Raw,
                                          serialization.NoEncryption())
    recipient_public = recipient.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    jwk = json.dumps({"kty": "OKP", "crv": "X25519", "d": token.b64u_encode(private_raw),
                      "x": token.b64u_encode(recipient_public)}).encode()
    assert token.decrypt_jwe(compact, jwk)["plaintext"] == b"CSCTF{x25519_kw_verified}"

    inconsistent = json.loads(jwk)
    inconsistent["x"] = token.b64u_encode(b"\0" * 32)
    with pytest.raises(token.TokenError, match="does not match"):
        token.decrypt_jwe(compact, json.dumps(inconsistent).encode())


def test_ecdh_jwk_parser_5000_seeded_mutations_have_one_boundary():
    base = bytearray(json.dumps({"kty": "OKP", "crv": "X25519",
                                 "d": token.b64u_encode(bytes(range(32)))}).encode())
    rng = random.Random(0xECD5)
    alphabet = b'{}[],:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'
    for _ in range(5000):
        data = bytearray(base)
        for _ in range(rng.randrange(1, 7)):
            action = rng.randrange(3)
            if action == 0 and data:
                data[rng.randrange(len(data))] = rng.choice(alphabet)
            elif action == 1 and data:
                del data[rng.randrange(len(data))]
            elif len(data) < token.MAX_JSON:
                data.insert(rng.randrange(len(data) + 1), rng.choice(alphabet))
        try:
            parsed = token._jwk_document(bytes(data))
            assert parsed is None or isinstance(parsed, dict)
        except token.TokenError:
            pass


def test_ecdsa_fault_and_ed25519_reuse_decline_wrong_values():
    cv = modern_crypto.CURVES["secp256k1"]
    private, nonce, z1, z2 = 0x123456789, 0x987654321, 111, 222
    public = modern_crypto.ec_mul(private, cv)
    r = modern_crypto.ec_mul(nonce, cv)[0] % cv["n"]
    s1 = pow(nonce, -1, cv["n"]) * (z1 + r * private) % cv["n"]
    s2 = pow(nonce, -1, cv["n"]) * (z2 + r * private) % cv["n"]
    result = faults.ecdsa_fault_pair_recover("secp256k1", public, (r, s1, z1), (r, s2, z2))
    assert result and result.private_scalar == private and result.nonce == nonce and result.verified
    wrong_public = modern_crypto.ec_mul(private + 1, cv)
    assert faults.ecdsa_fault_pair_recover(
        "secp256k1", wrong_public, (r, s1, z1), (r, s2, z2)) is None
    assert faults.ecdsa_fault_pair_recover(
        "secp256k1", public, (r, s1, z1), (r + 1, s2, z2)) is None

    secret, ed_nonce = 123456789012345678901234567890, 998877665544332211
    ed_public = faults._ed_encode(faults._ed_mul(secret))
    ed_r = faults._ed_encode(faults._ed_mul(ed_nonce))

    def sign(message):
        challenge = int.from_bytes(hashlib.sha512(ed_r + ed_public + message).digest(), "little") % faults._ED_L
        return ed_r + ((ed_nonce + challenge * secret) % faults._ED_L).to_bytes(32, "little")

    sig1, sig2 = sign(b"correct"), sign(b"faulted-message")
    recovered = faults.ed25519_nonce_reuse_recover(
        ed_public, b"correct", sig1, b"faulted-message", sig2)
    assert recovered and recovered.secret_scalar == secret and recovered.nonce_scalar == ed_nonce
    damaged = sig2[:-1] + bytes([sig2[-1] ^ 1])
    assert faults.ed25519_nonce_reuse_recover(
        ed_public, b"correct", sig1, b"faulted-message", damaged) is None


def _raw_aes_cbc_mac(key: bytes, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    return (encryptor.update(data) + encryptor.finalize())[-16:]


def test_cbc_mac_plan_aead_audit_and_whitebox_table_are_exact():
    key = bytes.fromhex("42" * 16)
    first = b"first-block-0001" + b"first-block-0002"
    second = b"other-block-0001" + b"other-block-0002"
    tag1, tag2 = _raw_aes_cbc_mac(key, first), _raw_aes_cbc_mac(key, second)
    plan = faults.cbc_mac_length_extension(first, tag1, second, tag2)
    assert faults.verify_cbc_mac_plan(plan, lambda message: _raw_aes_cbc_mac(key, message))
    assert not faults.verify_cbc_mac_plan(plan, lambda _message: bytes(16))
    report = faults.audit_aead_misuse([
        {"algorithm": "AES-256-GCM", "key_id": "local", "nonce": "00" * 12,
         "ciphertext": "11", "tag": "22" * 16},
        {"algorithm": "AES-256-GCM", "key_id": "local", "nonce": "00" * 12,
         "ciphertext": "33", "tag": "44" * 8},
    ])
    assert {row["kind"] for row in report["findings"]} == {"nonce_reuse", "truncated_tag"}
    assert report["requests_sent"] == 0
    masked = bytes(faults._AES_SBOX[value ^ 37] ^ 91 for value in range(256))
    assert faults.recover_masked_aes_sbox(masked) == [{"input_xor": 37, "output_xor": 91}]
    damaged = bytearray(masked); damaged[99] ^= 1
    assert faults.recover_masked_aes_sbox(bytes(damaged)) == []


def test_crypto_fault_json_parser_5000_seeded_mutations_and_guarded_cli(tmp_path, capsys):
    seed = bytearray(b'{"observations":[],"mode":"offline"}')
    rng = random.Random(0xFA017)
    for _ in range(5000):
        data = bytearray(seed)
        for _ in range(rng.randrange(1, 8)):
            action = rng.randrange(3)
            if action == 0 and data:
                data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
            elif action == 1 and data:
                del data[rng.randrange(len(data))]
            elif len(data) < faults.MAX_JSON:
                data.insert(rng.randrange(len(data) + 1), rng.randrange(256))
        try:
            assert isinstance(faults.parse_json_document(bytes(data)), dict)
        except ValueError:
            pass
    bad = tmp_path / "duplicate.json"
    bad.write_text('{"observations":[],"observations":[]}', encoding="utf-8")
    assert faults.main(["aead-audit", str(bad), "--json"]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_lattice_backend_json_parser_5000_seeded_mutations():
    seed = bytearray(b'{"basis":[[1,2],[3,5]],"method":"lll"}')
    rng = random.Random(0xB42)
    for _ in range(5000):
        data = bytearray(seed)
        for _ in range(rng.randrange(1, 7)):
            action = rng.randrange(3)
            if action == 0 and data:
                data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
            elif action == 1 and data:
                del data[rng.randrange(len(data))]
            elif len(data) < backends.MAX_JSON:
                data.insert(rng.randrange(len(data) + 1), rng.randrange(256))
        try:
            assert isinstance(backends.parse_json_document(bytes(data)), dict)
        except ValueError:
            pass


def test_lattice_backend_exact_hnf_and_twelve_variable_small_root():
    reduced = backends.reduce_lattice([[105, 821, 37], [12, 93, 41]], method="lll")
    assert reduced and reduced.lattice_verified and reduced.method == "lll"
    assert backends.backend_status()["lll"] is True

    variables = 12
    powers = [1] + [0] * (variables - 1)
    roots = lattices.small_roots(
        [{"powers": powers, "coefficient": 1}], 101, [[0, 0]] * variables,
        m=1, t=0, max_enumeration=1,
    )
    assert roots == [(0,) * variables]
    with pytest.raises(ValueError, match="monomial shifts exceed"):
        lattices._monomial_shifts(16, 2, lattices.MAX_HG_DIMENSION)


def test_round5_crypto_triage_routes_depth_engine_first():
    route = triage.suggest("crypto", "Ed25519 fault signatures reuse nonce and white-box AES S-box")
    assert route["engines"][0] == "solvers/common/crypto_faults.py"
    route = triage.suggest("web", "JWE ECDH-ES epk X25519 compact token")
    assert route["engines"][0] == "solvers/web/token_depth.py"
