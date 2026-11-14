"""Official-vector locks for the existing modern-crypto primitives.

Sources:
* RFC 5297 Appendix A.2 (nonce-based AES-SIV with two ordered AD components)
* RFC 8439 section 2.5.2 (Poly1305)
* NIST SP 800-38D, AES-GCM test case 2 (zero AES-128 key/IV)
"""
from __future__ import annotations

import importlib.util
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


modern = _load("cryptodepth_hardened_modern_crypto", REPO / "solvers/common/modern_crypto.py")
depth = _load("cryptodepth_hardened_crypto_depth", REPO / "solvers/common/crypto_depth.py")
H = bytes.fromhex


def test_rfc5297_appendix_a2_ordered_aad_and_nonce():
    key = H(
        "7f7e7d7c7b7a79787776757473727170"
        "404142434445464748494a4b4c4d4e4f"
    )
    ad1 = H(
        "00112233445566778899aabbccddeeff"
        "deaddadadeaddadaffeeddccbbaa9988"
        "7766554433221100"
    )
    ad2 = H("102030405060708090a0")
    nonce = H("09f911029d74e35bd84156c5635688c0")
    plaintext = H(
        "7468697320697320736f6d6520706c61"
        "696e7465787420746f20656e63727970"
        "74207573696e67205349562d414553"
    )
    output = H(
        "7bdb6e3b432667eb06f4d14bff2fbd0f"
        "cb900f2fddbe404326601965c889bf17"
        "dba77ceb094fa663b7a3f748ba8af829"
        "ea64ad544a272e9c485b62a3fd5c0d"
    )
    tag, ciphertext = output[:16], output[16:]

    assert modern.aes_siv_open(key, ciphertext, tag, [ad1, ad2], nonce) == plaintext
    assert modern.aes_siv_open(key, ciphertext, tag, (memoryview(ad1), bytearray(ad2)), nonce) == plaintext

    assert modern.aes_siv_open(key, ciphertext, tag, [ad2, ad1], nonce) is None
    assert modern.aes_siv_open(key, ciphertext, tag, [ad1[:-1] + bytes([ad1[-1] ^ 1]), ad2], nonce) is None
    assert modern.aes_siv_open(key, ciphertext, tag, [ad1, ad2], nonce[:-1] + bytes([nonce[-1] ^ 1])) is None
    assert modern.aes_siv_open(key, ciphertext, tag[:-1] + bytes([tag[-1] ^ 1]), [ad1, ad2], nonce) is None


def test_aes_siv_aad_type_and_resource_guards(monkeypatch):
    key = bytes(32)
    tag = bytes(16)
    nonce = b"nonce"

    assert modern.aes_siv_open(key, b"", tag, "implicit text", nonce) is None
    assert modern.aes_siv_open(key, b"", tag, [b"ok", "not bytes"], nonce) is None
    assert modern.aes_siv_open(key, b"", tag, (part for part in [b"not-a-sequence"]), nonce) is None
    assert modern.aes_siv_open(1, b"", tag, [], nonce) is None
    assert modern.aes_siv_open(key, object(), tag, [], nonce) is None
    assert modern.aes_siv_open(key, b"", None, [], nonce) is None
    assert modern.aes_siv_open(key, b"", tag, [b""] * modern.MAX_SIV_AAD_COMPONENTS, nonce) is None
    assert modern.aes_siv_open(key, b"", tag, [b""] * (modern.MAX_SIV_AAD_COMPONENTS + 1)) is None
    assert modern.aes_siv_open(key, b"", tag, [], b"") is None

    monkeypatch.setattr(modern, "MAX_SIV_AAD_BYTES", 3)
    assert modern.aes_siv_open(key, b"", tag, b"1234") is None
    assert modern.aes_siv_open(key, b"", tag, [b"12", b"34"]) is None
    assert modern.aes_siv_open(key, b"", tag, [], b"1234") is None


def test_rfc8439_poly1305_vector_and_malformed_inputs():
    one_time_key = H(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    message = b"Cryptographic Forum Research Group"
    expected = H("a8061dc1305136c6c22b8baf0c0127a9")

    assert modern.poly1305_mac(one_time_key, message) == expected
    assert modern.poly1305_mac(bytearray(one_time_key), memoryview(message)) == expected
    for bad_key in (b"", one_time_key[:-1], one_time_key + b"\x00", "not bytes", [0] * 32):
        assert modern.poly1305_mac(bad_key, message) is None
    assert modern.poly1305_mac(one_time_key, "not bytes") is None


def test_nist_sp800_38d_zero_key_gcm_vectors():
    # AES_K(0^128), and E_K(J0) for K=0^128, IV=0^96.
    authentication_key = int.from_bytes(H("66e94bd4ef8a2c3b884cfa59ca342b2e"), "big")
    counter_mask = int.from_bytes(H("58e2fccefa7e3061367f1d57a4e7455a"), "big")

    assert depth.ghash(authentication_key, b"", b"") == 0
    assert depth.gcm_tag(authentication_key, counter_mask, b"", b"") == H(
        "58e2fccefa7e3061367f1d57a4e7455a"
    )

    ciphertext = H("0388dace60b6a392f328c2b971b2fe78")
    expected_ghash = H("f38cbb1ad69223dcc3457ae5b6b0f885")
    expected_tag = H("ab6e47d42cec13bdf53a67b21257bddf")
    assert depth.ghash(authentication_key, b"", ciphertext) == int.from_bytes(expected_ghash, "big")
    assert depth.gcm_tag(authentication_key, counter_mask, b"", ciphertext) == expected_tag
