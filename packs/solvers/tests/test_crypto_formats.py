"""Offline bounded structure tests for r5c crypto formats."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest


COMMON = Path(__file__).resolve().parents[1] / "solvers" / "common"
sys.path.insert(0, str(COMMON))
import crypto_formats as fmt  # noqa: E402


def _packet(tag, body):
    return bytes([0xC0 | tag, len(body)]) + body


def _mpi(value):
    bits = value.bit_length()
    raw = value.to_bytes((bits + 7) // 8, "big")
    return bits.to_bytes(2, "big") + raw


def _armor(blob):
    crc = fmt._crc24(blob).to_bytes(3, "big")
    return ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
            + base64.b64encode(blob).decode() + "\n=" + base64.b64encode(crc).decode()
            + "\n-----END PGP PUBLIC KEY BLOCK-----\n")


def _openssh_blob(pem):
    match = re.search(br"-----BEGIN OPENSSH PRIVATE KEY-----\s*(.*?)\s*-----END OPENSSH PRIVATE KEY-----", pem, re.S)
    assert match
    return base64.b64decode(re.sub(br"\s", b"", match.group(1)), validate=True)


def _openssh_pem(blob):
    encoded = base64.b64encode(blob)
    lines = b"\n".join(encoded[index:index + 70] for index in range(0, len(encoded), 70))
    return b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + lines + b"\n-----END OPENSSH PRIVATE KEY-----\n"


def test_pgp_armor_packets_s2k_public_metadata_and_malformed_decline():
    public = bytes([4]) + (1_700_000_000).to_bytes(4, "big") + bytes([1]) + _mpi(3233) + _mpi(17)
    userid = b"ctf@example.test"
    s2k = bytes([4, 9, 3, 8]) + b"12345678" + bytes([96])
    blob = _packet(6, public) + _packet(13, userid) + _packet(3, s2k)
    report = fmt.analyze_pgp(_armor(blob))
    assert report and report.armored and report.crc24_valid is True
    assert report.user_ids == ("ctf@example.test",) and len(report.public_fingerprints) == 1
    assert report.packets[-1].s2k_type == 3 and report.packets[-1].s2k_count == (16 << 12)
    with pytest.raises(FrozenInstanceError):
        report.armored = False
    assert fmt.analyze_pgp(blob[:-1]) is None
    assert fmt.analyze_pgp(_packet(6, public[:-1])) is None
    assert fmt.analyze_pgp(_packet(6, b"\x02" + public[1:])) is None
    assert fmt.analyze_pgp(_packet(6, bytes([4]) + (1_700_000_000).to_bytes(4, "big") + bytes([22]))) is None
    assert fmt.analyze_pgp(_packet(3, b"\x04\x09\x03\x08short")) is None
    assert fmt.analyze_pgp(_packet(3, b"\x05\x09\x00\x08")) is None
    assert fmt.analyze_pgp(_packet(0, b"x")) is None
    assert fmt.analyze_pgp(_armor(b"")) is None
    bad_armor = re.sub(r"(?m)^=[A-Za-z0-9+/]{4}$", "=AAAA", _armor(blob))
    assert "armor_crc24_mismatch" in fmt.analyze_pgp(bad_armor).warnings
    duplicate_crc = _armor(blob).replace("\n-----END", "\n=AAAA\n-----END")
    assert fmt.analyze_pgp(duplicate_crc) is None


def test_ssh_authorized_and_private_structure_crosschecked_by_cryptography():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    key = ed25519.Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    report = fmt.analyze_ssh(public + b" unit@test")
    assert report and report.format == "authorized_key" and report.key_type == "ssh-ed25519" and report.bits == 256
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption())
    private_report = fmt.analyze_ssh(private)
    assert private_report and private_report.format == "private_key" and private_report.bits == 256
    encrypted = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                  serialization.BestAvailableEncryption(b"local-pass"))
    locked = fmt.analyze_ssh(encrypted)
    assert locked and locked.encrypted and "private_key_not_loaded" in locked.warnings
    unlocked = fmt.analyze_ssh(encrypted, password=b"local-pass")
    assert unlocked and unlocked.bits == 256
    encrypted_blob = _openssh_blob(encrypted)
    assert b"aes256-ctr" in encrypted_blob and b"bcrypt" in encrypted_blob
    assert fmt.analyze_ssh(_openssh_pem(encrypted_blob.replace(b"aes256-ctr", b"evil00-ctr", 1))) is None
    assert fmt.analyze_ssh(_openssh_pem(encrypted_blob.replace(b"bcrypt", b"evil!!", 1))) is None
    options_at = len(b"openssh-key-v1\0")
    for _ in range(2):
        size = int.from_bytes(encrypted_blob[options_at:options_at + 4], "big")
        options_at += 4 + size
    options_size = int.from_bytes(encrypted_blob[options_at:options_at + 4], "big")
    options_start = options_at + 4
    bad_rounds = bytearray(encrypted_blob)
    bad_rounds[options_start + options_size - 4:options_start + options_size] = b"\0" * 4
    assert fmt.analyze_ssh(_openssh_pem(bytes(bad_rounds))) is None
    assert fmt.analyze_ssh(_openssh_pem(encrypted_blob[:-1])) is None

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    for private_format in (serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.TraditionalOpenSSL):
        encrypted_pem = rsa_key.private_bytes(
            serialization.Encoding.PEM, private_format, serialization.BestAvailableEncryption(b"pem-pass")
        )
        pem_locked = fmt.analyze_ssh(encrypted_pem)
        assert pem_locked and pem_locked.encrypted and "private_key_not_loaded" in pem_locked.warnings
        assert fmt.analyze_ssh(encrypted_pem, password=b"pem-pass").bits == 1024
    assert fmt.analyze_ssh(b"ssh-ed25519 !!!!") is None
    key_type = b"ssh-ed25519"
    malformed = (len(key_type).to_bytes(4, "big") + key_type
                 + (31).to_bytes(4, "big") + b"x" * 31)
    assert fmt.analyze_ssh(b"ssh-ed25519 " + base64.b64encode(malformed)) is None
    assert fmt.analyze_ssh(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n") is None
    assert fmt.analyze_ssh(
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
    ) is None
    assert fmt.analyze_ssh(
        b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nAAAA\n-----END RSA PRIVATE KEY-----\n"
    ) is None


def _client_hello(ciphers=b"\x13\x01\x00\x2f\x13\x03", compressions=b"\x00", extensions=None):
    groups = b"\x00\x0a\x00\x06\x00\x04\x00\x1d\x00\x17"
    versions = b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"
    extensions = groups + versions if extensions is None else extensions
    body = (b"\x03\x03" + b"\0" * 32 + b"\0" + len(ciphers).to_bytes(2, "big") + ciphers
            + bytes([len(compressions)]) + compressions + len(extensions).to_bytes(2, "big") + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def _server_hello(selected=b"\x13\x03", extension=b"\x00\x2b\x00\x02\x03\x04"):
    body = (b"\x03\x03" + b"\1" * 32 + b"\0" + selected + b"\x00"
            + len(extension).to_bytes(2, "big") + extension)
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def _tls_record(fragment, content_type=22, version=b"\x03\x03"):
    return bytes([content_type]) + version + len(fragment).to_bytes(2, "big") + fragment


def test_tls_record_dict_and_hello_structure_no_network():
    report = fmt.analyze_tls(_client_hello())
    assert report and report.handshake_types == (1,)
    assert "TLS_AES_128_GCM_SHA256" in report.cipher_suites
    assert report.supported_versions == ("TLS1.3", "TLS1.2")
    assert report.groups == ("x25519", "secp256r1")
    joined = fmt.analyze_tls(_client_hello() + _server_hello())
    assert joined and joined.selected_cipher == "TLS_CHACHA20_POLY1305_SHA256"
    hello_bytes = _client_hello()[5:]
    fragmented = _tls_record(hello_bytes[:2]) + _tls_record(hello_bytes[2:19]) + _tls_record(hello_bytes[19:])
    fragmented_report = fmt.analyze_tls(fragmented)
    assert fragmented_report and fragmented_report.handshake_types == (1,) \
        and fragmented_report.cipher_suites == report.cipher_suites
    dictionary = fmt.analyze_tls({"version": "TLS1.3", "cipher": "TLS_AES_128_GCM_SHA256",
                                  "groups": ["x25519"], "certificates": []})
    assert dictionary and dictionary.selected_cipher == "TLS_AES_128_GCM_SHA256"
    numeric = fmt.analyze_tls({"versions": [0x0304], "cipher": 0x1301, "groups": [29]})
    assert numeric and numeric.selected_cipher == "TLS_AES_128_GCM_SHA256" and numeric.groups == ("x25519",)
    assert fmt.analyze_tls(_client_hello()[:-1]) is None
    assert fmt.analyze_tls({"versions": ["TLS1.3"] * 257}) is None
    assert fmt.analyze_tls({"versions": [object()]}) is None
    assert fmt.analyze_tls({"versions": [0x0300]}) is None
    assert fmt.analyze_tls({}) is None
    assert fmt.analyze_tls({"cipher": 0x1301, "cipher_suites": [0x1302]}) is None
    assert fmt.analyze_tls({"cipher": 0x1301, "cipher_suites": []}) is None
    assert fmt.analyze_tls({"versions": ["\ud800"]}) is None
    assert fmt.analyze_tls({"certificates": [b"not-a-certificate"]}) is None
    assert fmt.analyze_tls(_client_hello(ciphers=b"")) is None
    assert fmt.analyze_tls(_client_hello(compressions=b"")) is None
    assert fmt.analyze_tls(_client_hello() + _server_hello(selected=b"\x13\x02")) is None
    assert fmt.analyze_tls(_client_hello(extensions=b"\x00\x2b\x00\x02\x03\x04")) is None
    assert fmt.analyze_tls(_client_hello(extensions=b"\x00\x2b\x00\x03\x02\x03\x00")) is None
    assert fmt.analyze_tls(_client_hello(extensions=b"\x00\x0a\x00\x02\x00\x00")) is None
    group_extension = b"\x00\x0a\x00\x04\x00\x02\x00\x1d"
    assert fmt.analyze_tls(_client_hello(extensions=group_extension * 2)) is None
    many = b"\x00\x00\x00\x00" * (fmt.MAX_ITEMS + 1)
    assert fmt.analyze_tls(b"\x16\x03\x03" + len(many).to_bytes(2, "big") + many) is None
    short_cert = b"\x0b\x00\x00\x02xx"
    assert fmt.analyze_tls(b"\x16\x03\x03" + len(short_cert).to_bytes(2, "big") + short_cert) is None
    empty_cert = b"\x0b\x00\x00\x03\x00\x00\x00"
    assert fmt.analyze_tls(_tls_record(empty_cert)) is None
    assert fmt.analyze_tls(_tls_record(b"x", content_type=25)) is None
    assert fmt.analyze_tls(_tls_record(b"", version=b"\x03\x00")) is None
    app_record = fmt.analyze_tls(_tls_record(b"ciphertext", content_type=23))
    assert app_record and app_record.record_versions == ("TLS1.2",) and not app_record.handshake_types
    malformed_group = _client_hello().replace(
        b"\x00\x0a\x00\x06\x00\x04\x00\x1d\x00\x17",
        b"\x00\x0a\x00\x06\x00\x03\x00\x1d\x00\x17",
    )
    assert fmt.analyze_tls(malformed_group) is None
    cert_body = b"\x00\x00\x05\x00\x00\x0a\xaa\xbb"
    cert_hs = b"\x0b" + len(cert_body).to_bytes(3, "big") + cert_body
    cert_record = b"\x16\x03\x03" + len(cert_hs).to_bytes(2, "big") + cert_hs
    assert fmt.analyze_tls(cert_record) is None


def test_age_and_sops_json_yaml_structures_only():
    age_mac = base64.b64encode(b"M" * 32).decode().rstrip("=")
    age = f"age-encryption.org/v1\n-> X25519 age1example\nAAAA\n-> scrypt salt 18\nBBBB\n--- {age_mac}\nbody"
    age_report = fmt.analyze_age_sops(age)
    assert age_report and age_report.kind == "age" and age_report.recipients == ("age1example",)
    assert any(value.startswith("scrypt") for value in age_report.kdfs)

    document = {"secret": "ENC[AES256_GCM,data:x,iv:nonce123,tag:t,type:str]",
                "sops": {"age": [{"recipient": "age1local"}], "mac": "ENC[AES256_GCM,data:m]",
                         "shamir_threshold": 2}}
    report = fmt.analyze_age_sops(json.dumps(document))
    assert report and report.kind == "sops" and report.recipients == ("age1local",)
    assert report.nonces == ("nonce123",) and report.mac_present
    yaml = "value: ENC[AES256_GCM,data:x,iv:ivv,tag:t,type:str]\nsops:\n  age:\n  - recipient: age1yaml\n  mac: ENC[x]"
    yreport = fmt.analyze_age_sops(yaml)
    assert yreport and yreport.recipients == ("age1yaml",) and yreport.nonces == ("ivv",)
    assert fmt.analyze_age_sops("ordinary text") is None
    assert fmt.analyze_age_sops("age-encryption.org/v2\n-> X25519 age1x\nAAAA\n--- MAC\nbody") is None
    assert fmt.analyze_age_sops("age-encryption.org/v1\n") is None
    assert fmt.analyze_age_sops(f"age-encryption.org/v1\n-> X25519 age1x\nAAAA\n--- {age_mac}\n") is None
    assert fmt.analyze_age_sops(f"age-encryption.org/v1\n-> X25519 age1x\n!!!\n--- {age_mac}\nbody") is None
    assert fmt.analyze_age_sops("age-encryption.org/v1\n-> X25519 age1x\nAAAA\n--- A\nbody") is None
    assert fmt.analyze_age_sops(f"age-encryption.org/v1\n-> X25519 age1x\nAAAA\n--- {age_mac}\n!!!") is None
    assert fmt.analyze_age_sops('{"sops":{"mac":"a"},"sops":{"mac":"b"}}') is None
    assert fmt.analyze_age_sops('{"sops":{"mac":""}}') is None
    assert fmt.analyze_age_sops('{"sops":{"mac":"plain"}}') is None
    assert fmt.analyze_age_sops("sops:\n  mac: ENC[") is None
    too_many = "age-encryption.org/v1\n" + "".join(f"-> X25519 age1{i}\n" for i in range(fmt.MAX_ITEMS + 1))
    assert fmt.analyze_age_sops(too_many) is None


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt(secret, header=None, payload=None):
    header = header or {"alg": "HS256", "typ": "JWT", "kid": "local"}
    payload = payload or {"sub": "7", "role": "user"}
    first, second = _b64u(json.dumps(header, separators=(",", ":")).encode()), _b64u(json.dumps(payload, separators=(",", ":")).encode())
    signature = hmac.new(secret, (first + "." + second).encode(), hashlib.sha256).digest()
    return first + "." + second + "." + _b64u(signature)


def test_jwt_structure_hmac_unique_reverification_and_ambiguity_decline():
    secret, token = b"local-secret", _jwt(b"local-secret")
    report = fmt.analyze_jwt(token)
    assert report and report.algorithm == "HS256" and report.key_id == "local" and report.signature_bytes == 32
    assert fmt.recover_jwt_hmac_secret(token, [b"wrong", secret]) == secret
    assert fmt.recover_jwt_hmac_secret(token, [b"wrong"]) is None
    assert fmt.recover_jwt_hmac_secret(token, itertools_repeat(secret)) is None
    assert fmt.recover_jwt_hmac_secret(token, [secret], max_candidates=fmt.MAX_CANDIDATES + 1) is None
    assert fmt.recover_jwt_hmac_secret(token, [b"x" * 4096] * 513) is None
    assert fmt.recover_jwt_hmac_secret(token, [secret, "bad"]) is None
    class BytesSubclass(bytes):
        def __hash__(self):
            raise RuntimeError("must not be hashed")
    assert fmt.recover_jwt_hmac_secret(token, [BytesSubclass(secret)]) is None
    duplicate = _b64u(b'{"alg":"HS256","alg":"none"}') + "." + token.split(".")[1] + "."
    assert fmt.analyze_jwt(duplicate) is None
    nested = {"leaf": True}
    for _ in range(fmt.MAX_JSON_DEPTH + 1):
        nested = {"next": nested}
    assert fmt.analyze_jwt(_jwt(secret, payload=nested)) is None

    class StrSubclass(str):
        pass
    assert fmt.analyze_jwt(StrSubclass(token)) is None


def itertools_repeat(value):
    while True:
        yield value


def test_jwk_structure_thumbprint_private_presence_and_single_key_ambiguity():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    numbers = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_numbers()
    n = _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))
    e = _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
    report = fmt.analyze_jwk({"kty": "RSA", "n": n, "e": e, "kid": "one", "alg": "RS256"})
    assert report and report.key_bits == 1024 and report.thumbprint_sha256 and not report.has_private
    private_shape = fmt.analyze_jwk({"kty": "oct", "k": _b64u(b"secret"), "kid": "s"})
    assert private_shape and private_shape.has_private and "symmetric_key_material_present" in private_shape.warnings
    ec_numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    ec_report = fmt.analyze_jwk({"kty": "EC", "crv": "P-256",
                                 "x": _b64u(ec_numbers.x.to_bytes(32, "big")),
                                 "y": _b64u(ec_numbers.y.to_bytes(32, "big"))})
    assert ec_report and ec_report.key_bits == 256
    ed_raw = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert fmt.analyze_jwk({"kty": "OKP", "crv": "Ed25519", "x": _b64u(ed_raw)}).key_bits == 256
    assert fmt.analyze_jwk({"keys": [{"kty": "oct", "k": "YQ"}, {"kty": "oct", "k": "Yg"}]}) is None
    assert fmt.analyze_jwk({"kty": "RSA", "n": "AQ", "e": "AQ"}) is None
    assert fmt.analyze_jwk({"kty": "RSA", "n": n, "e": e, "d": "!!!"}) is None
    assert fmt.analyze_jwk({"kty": "EC", "crv": "P-256", "x": _b64u(b"x" * 32),
                            "y": _b64u(b"y" * 32)}) is None
    assert fmt.analyze_jwk({"kty": "OKP", "crv": "Ed25519", "x": _b64u(b"x" * 31)}) is None
    assert fmt.analyze_jwk({"kty": "oct", "k": "YR"}) is None
    assert fmt.analyze_jwk(json.dumps({"kty": "oct", "k": "YQ", **{f"x{i}": i for i in range(65)}})) is None

    class DictSubclass(dict):
        pass
    assert fmt.analyze_jwk(DictSubclass(kty="oct", k="YQ")) is None


def test_package_import_caps_and_malformed_iterators():
    from solvers.common import crypto_formats as package
    assert package.analyze_jwt(_jwt(b"x")).algorithm == "HS256"

    def failing():
        yield b"x"
        raise RuntimeError("broken source")

    assert fmt.recover_jwt_hmac_secret(_jwt(b"x"), failing()) is None
    assert fmt.analyze_pgp(b"x" * (fmt.MAX_BYTES + 1)) is None
