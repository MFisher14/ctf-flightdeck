"""Deterministic success and ambiguity-decline tests for r5c oracle/AEAD helpers."""

from __future__ import annotations

import hashlib
import itertools
import sys
from pathlib import Path

from Crypto.Cipher import AES, ChaCha20_Poly1305


COMMON = Path(__file__).resolve().parents[1] / "solvers" / "common"
sys.path.insert(0, str(COMMON))

import crypto_oracles as base_oracles  # noqa: E402
import crypto_depth as base_depth  # noqa: E402
import oracle_aead as attack  # noqa: E402


# Fixed RSA fixtures avoid random key generation and keep adaptive tests stable.
RSA_P = 246_402_745_979_669
RSA_Q = 177_951_351_149_821
RSA_N = RSA_P * RSA_Q
RSA_E = 65_537
RSA_D = pow(RSA_E, -1, (RSA_P - 1) * (RSA_Q - 1))
RSA_K = (RSA_N.bit_length() + 7) // 8


def _rsa_decrypt(candidate: bytes, *, d=RSA_D, n=RSA_N) -> int:
    return pow(int.from_bytes(candidate, "big"), d, n)


def test_rsa_parity_oracle_public_round_trip_and_decline_gate():
    message = 12_345_678_901_234_567_890
    ciphertext = pow(message, RSA_E, RSA_N)
    oracle = lambda candidate: bool(_rsa_decrypt(candidate) & 1)
    assert attack.recover_rsa_parity_plaintext(
        ciphertext, RSA_N, RSA_E, oracle, verify=lambda value: value == message
    ) == message
    assert attack.recover_rsa_parity_plaintext(
        ciphertext, RSA_N, RSA_E, oracle, verify=lambda _value: False
    ) is None


def test_bleichenbacher_structure_reencrypts_and_rejected_evidence_declines():
    encoded = b"\x00\x02" + b"A" * 8 + b"\x00X"
    ciphertext = pow(int.from_bytes(encoded, "big"), RSA_E, RSA_N)
    bound = 1 << (8 * (RSA_K - 2))
    oracle = lambda candidate: 2 * bound <= _rsa_decrypt(candidate) < 3 * bound
    assert attack.recover_bleichenbacher_plaintext(
        ciphertext, RSA_N, RSA_E, oracle, max_queries=100_000,
        verify=lambda plaintext: plaintext == b"X",
    ) == b"X"
    assert attack.recover_bleichenbacher_plaintext(
        ciphertext, RSA_N, RSA_E, oracle, max_queries=100_000,
        verify=lambda _plaintext: False,
    ) is None


def test_manger_encoded_structure_round_trip_and_ambiguous_decoder_declines():
    bound = 1 << (8 * (RSA_K - 1))
    value = bound // 3 + 12_345
    ciphertext = pow(value, RSA_E, RSA_N)
    oracle = lambda candidate: _rsa_decrypt(candidate) < bound
    expected = value.to_bytes(RSA_K, "big")
    decoder = lambda block: block if block.startswith(b"\x00") else None
    assert attack.recover_manger_plaintext(
        ciphertext, RSA_N, RSA_E, oracle, decoder=decoder,
        verify=lambda block: block == expected,
    ) == expected
    assert attack.recover_manger_plaintext(
        ciphertext, RSA_N, RSA_E, oracle, decoder=lambda _block: None
    ) is None


OAEP_P = 4624866114560513231975851877517956957736949679738194530373
OAEP_Q = 4478546467182512245191508434411878393013332441048894433827
OAEP_N = OAEP_P * OAEP_Q
OAEP_E = 65_537
OAEP_D = pow(OAEP_E, -1, (OAEP_P - 1) * (OAEP_Q - 1))
OAEP_K = (OAEP_N.bit_length() + 7) // 8


def _oaep_encode(message: bytes, size: int, seed: bytes, label: bytes) -> bytes:
    hlen = hashlib.sha1().digest_size
    db = (hashlib.sha1(label).digest()
          + b"\x00" * (size - len(message) - 2 * hlen - 2)
          + b"\x01" + message)
    db_mask = base_oracles.mgf1(seed, size - hlen - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = base_oracles.mgf1(masked_db, hlen)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db


def test_manger_oaep_label_hash_and_reencryption_are_both_required():
    label, plaintext = b"r5c", b"OK"
    encoded = _oaep_encode(plaintext, OAEP_K, bytes(range(20)), label)
    ciphertext = pow(int.from_bytes(encoded, "big"), OAEP_E, OAEP_N)
    bound = 1 << (8 * (OAEP_K - 1))

    def decrypt(candidate: bytes) -> int:
        return pow(int.from_bytes(candidate, "big"), OAEP_D, OAEP_N)

    oracle = lambda candidate: decrypt(candidate) < bound
    assert attack.recover_manger_oaep_plaintext(
        ciphertext, OAEP_N, OAEP_E, oracle, label=label,
        verify=lambda value: value == plaintext,
    ) == plaintext
    assert attack.recover_manger_oaep_plaintext(
        ciphertext, OAEP_N, OAEP_E, oracle, label=b"wrong"
    ) is None


def _xor_block(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _toy_cbc_encrypt(plaintext: bytes, iv: bytes, key: bytes) -> bytes:
    previous = iv
    out = bytearray(iv)
    for offset in range(0, len(plaintext), len(key)):
        previous = _xor_block(_xor_block(plaintext[offset:offset + len(key)], previous), key)
        out.extend(previous)
    return bytes(out)


def _toy_cbc_decrypt(combined: bytes, key: bytes) -> bytes:
    size, previous, out = len(key), combined[:len(key)], bytearray()
    for offset in range(size, len(combined), size):
        block = combined[offset:offset + size]
        out.extend(_xor_block(_xor_block(block, key), previous))
        previous = block
    return bytes(out)


def test_cbc_padding_oracle_needs_independent_plaintext_confirmation():
    key, iv, message = b"toy-key!", b"initial!", b"verified CBC recovery"
    combined = _toy_cbc_encrypt(base_oracles.pkcs7_pad(message, 8), iv, key)

    def oracle(candidate: bytes) -> bool:
        try:
            base_oracles.pkcs7_unpad(_toy_cbc_decrypt(candidate, key), 8)
            return True
        except ValueError:
            return False

    assert attack.recover_cbc_padding_plaintext(
        combined, oracle, lambda value: value == message, block_size=8
    ) == message
    assert attack.recover_cbc_padding_plaintext(
        combined, oracle, lambda _value: False, block_size=8
    ) is None


def test_prefix_mac_length_extension_returns_only_unique_oracle_acceptance():
    secret, message, extra = b"hidden-prefix", b"user=guest", b"&admin=1"
    digest = hashlib.sha256(secret + message).digest()

    def verify(candidate: bytes, tag: bytes) -> bool:
        return hashlib.sha256(secret + candidate).digest() == tag

    result = attack.forge_prefix_mac_length_extension(
        "sha256", digest, message, extra, range(4, 20), verify
    )
    assert result is not None
    forged, tag, recovered_length = result
    assert recovered_length == len(secret) and forged.endswith(extra) and verify(forged, tag)
    assert attack.forge_prefix_mac_length_extension(
        "sha256", digest, message, extra, [1, 2], lambda _m, _t: True
    ) is None


def _cbc_mac(key: bytes, message: bytes, iv: bytes | None = None) -> bytes:
    iv = bytes(16) if iv is None else iv
    state, cipher = iv, AES.new(key, AES.MODE_ECB)
    assert message and len(message) % 16 == 0
    for offset in range(0, len(message), 16):
        state = cipher.encrypt(_xor_block(state, message[offset:offset + 16]))
    return state


def test_cbc_mac_variable_iv_forgery_is_verified_or_declines():
    key = bytes(range(16))
    original = b"from=alice......" + b"amount=000001000"
    target = b"from=admin......" + original[16:]
    iv = bytes(range(16, 32))
    tag = _cbc_mac(key, original, iv)
    verify = lambda message, candidate_iv, candidate_tag: _cbc_mac(key, message, candidate_iv) == candidate_tag
    result = attack.forge_cbc_mac_variable_iv(original, iv, tag, target, verify)
    assert result is not None and verify(target, result[0], result[1])
    assert attack.forge_cbc_mac_variable_iv(
        original, iv, tag, target, lambda *_args: False
    ) is None


def test_cbc_mac_length_extension_forgery_is_verified_or_declines():
    key = bytes(reversed(range(16)))
    original = b"transfer-block!!" + b"second-block!!!!"
    extension = b"admin-extension!" + b"final-extension!"
    tag, extension_tag = _cbc_mac(key, original), _cbc_mac(key, extension)
    verify = lambda message, candidate_tag: _cbc_mac(key, message) == candidate_tag
    result = attack.forge_cbc_mac_length_extension(
        original, tag, extension, extension_tag, verify
    )
    assert result is not None and verify(*result)
    assert attack.forge_cbc_mac_length_extension(
        original, tag, extension, extension_tag, lambda *_args: False
    ) is None


def test_nonce_reuse_inventory_keeps_algorithms_and_keys_separate():
    records = [
        {"algorithm": "AES-GCM", "key_id": "key-a", "nonce": b"nonce-1"},
        {"algorithm": "aes-gcm", "key_id": "key-a", "nonce": b"nonce-1"},
        {"algorithm": "aes-gcm", "key_id": "key-b", "nonce": b"nonce-1"},
        {"algorithm": "chacha20-poly1305", "key_id": "key-a", "nonce": b"nonce-1"},
    ]
    findings = attack.detect_nonce_reuse(records)
    assert findings is not None and len(findings) == 1
    assert findings[0].record_indices == (0, 1)
    # Without key identity, equal nonce bytes do not prove misuse.
    assert attack.detect_nonce_reuse([
        {"algorithm": "aes-gcm", "nonce": b"same"},
        {"algorithm": "aes-gcm", "nonce": b"same"},
    ]) is None


def _aes_gcm(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)


def test_gcm_nonce_reuse_key_and_forgery_cross_check_pycryptodome():
    key, nonce, aad = bytes(range(16)), bytes(range(12)), b"r5c-gcm-aad"
    observations = [_aes_gcm(key, nonce, aad, byte * 16)
                    for byte in (b"A", b"B", b"C")]
    triples = [(aad, ciphertext, tag) for ciphertext, tag in observations]
    recovered = attack.recover_gcm_nonce_reuse_key(triples)
    expected_h = int.from_bytes(AES.new(key, AES.MODE_ECB).encrypt(bytes(16)), "big")
    expected_mask = int.from_bytes(AES.new(key, AES.MODE_ECB).encrypt(nonce + b"\0\0\0\1"), "big")
    assert recovered == (expected_h, expected_mask)

    target_ciphertext, trusted_tag = _aes_gcm(key, nonce, aad, b"forged target!!!")

    def verify(candidate_aad: bytes, ciphertext: bytes, tag: bytes) -> bool:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(candidate_aad)
        try:
            cipher.decrypt_and_verify(ciphertext, tag)
            return True
        except ValueError:
            return False

    assert attack.forge_gcm_nonce_reuse_tag(
        triples, aad, target_ciphertext, verify
    ) == trusted_tag
    assert attack.forge_gcm_nonce_reuse_tag(
        triples, aad, target_ciphertext, lambda *_args: False
    ) is None
    assert attack.recover_gcm_nonce_reuse_key(triples[:1]) is None


def _chacha(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)


def test_chacha_nonce_reuse_key_and_forgery_cross_check_pycryptodome():
    key, nonce, aad = bytes(range(32)), bytes(range(12)), b"r5c-chacha-aad"
    observations = [_chacha(key, nonce, aad, byte * 16)
                    for byte in (b"X", b"Y", b"Z")]
    triples = [(aad, ciphertext, tag) for ciphertext, tag in observations]
    recovered = attack.recover_chacha20_poly1305_one_time_key(triples)
    assert recovered is not None

    target_ciphertext, trusted_tag = _chacha(key, nonce, aad, b"chosen target body")

    def verify(candidate_aad: bytes, ciphertext: bytes, tag: bytes) -> bool:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(candidate_aad)
        try:
            cipher.decrypt_and_verify(ciphertext, tag)
            return True
        except ValueError:
            return False

    assert attack.forge_chacha20_poly1305_nonce_reuse_tag(
        triples, aad, target_ciphertext, verify
    ) == trusted_tag
    assert attack.forge_chacha20_poly1305_nonce_reuse_tag(
        triples, aad, target_ciphertext, lambda *_args: False
    ) is None
    assert attack.recover_chacha20_poly1305_one_time_key(triples[:1]) is None


def test_whitebox_xor_sbox_recovers_exact_transform_and_declines_symmetry():
    assert attack.aes_sbox(0x00) == 0x63
    assert attack.aes_sbox(0x53) == 0xED
    key, mask = 0x3A, 0xC7
    table = [attack.aes_sbox(value ^ key) ^ mask for value in range(256)]
    assert attack.recover_whitebox_xor_sbox(
        table, known_pairs=[(0, table[0]), (255, table[255])]
    ) == (key, mask)
    assert attack.recover_whitebox_xor_sbox(
        table, known_pairs=[(0, table[0] ^ 1)]
    ) is None
    # Identity has 256 equivalent (key, mask=key) explanations.
    assert attack.recover_whitebox_xor_sbox(
        list(range(256)), sbox=list(range(256))
    ) is None


def test_whitebox_trace_key_requires_one_exact_candidate():
    key = 0x91
    model = lambda value, candidate: attack.aes_sbox(value ^ candidate)
    traces = [(value, model(value, key)) for value in range(32)]
    assert attack.recover_whitebox_trace_key(traces, model) == key
    assert attack.recover_whitebox_trace_key(
        [(1, 0), (2, 0)], lambda _value, _candidate: 0
    ) is None


# -- second-pass adversarial protocol and cap audit -------------------------

def _raises(*_args):
    raise RuntimeError("synthetic callback failure")


def test_rsa_oracle_protocol_budget_and_contradictory_structure_decline():
    message = 12_345_678_901_234_567_890
    ciphertext = pow(message, RSA_E, RSA_N)
    correct = lambda candidate: bool(_rsa_decrypt(candidate) & 1)
    assert attack.recover_rsa_parity_plaintext(
        ciphertext, RSA_N, RSA_E, lambda _candidate: "odd"
    ) is None
    assert attack.recover_rsa_parity_plaintext(
        ciphertext, RSA_N, RSA_E, correct, max_queries=1
    ) is None
    assert attack.recover_rsa_parity_plaintext(
        ciphertext, RSA_N, RSA_E, _raises
    ) is None

    # An overaccepting PKCS oracle may drive the interval math, but the final
    # block is not structurally valid and therefore cannot escape the wrapper.
    raw_ciphertext = pow(42, RSA_E, RSA_N)
    assert attack.recover_bleichenbacher_plaintext(
        raw_ciphertext, RSA_N, RSA_E, lambda _candidate: True,
        max_queries=1000,
    ) is None
    encoded = b"\x00\x02" + b"A" * 8 + b"\x00X"
    encoded_ciphertext = pow(int.from_bytes(encoded, "big"), RSA_E, RSA_N)
    bound = 1 << (8 * (RSA_K - 2))
    pkcs_oracle = lambda candidate: 2 * bound <= _rsa_decrypt(candidate) < 3 * bound
    assert attack.recover_bleichenbacher_plaintext(
        encoded_ciphertext, RSA_N, RSA_E, pkcs_oracle, max_queries=1
    ) is None
    assert attack.recover_bleichenbacher_plaintext(
        encoded_ciphertext, RSA_N, RSA_E, _raises, max_queries=10
    ) is None

    manger_bound = 1 << (8 * (RSA_K - 1))
    manger_value = manger_bound // 3 + 7
    manger_ciphertext = pow(manger_value, RSA_E, RSA_N)
    assert attack.recover_manger_plaintext(
        manger_ciphertext, RSA_N, RSA_E, lambda _candidate: "yes",
        decoder=lambda block: block,
    ) is None
    assert attack.recover_manger_plaintext(
        manger_ciphertext, RSA_N, RSA_E, _raises,
        decoder=lambda block: block,
    ) is None


def test_padding_oracle_ambiguity_budget_and_callback_failures_decline():
    ciphertext = b"A" * 16
    assert attack.recover_cbc_padding_plaintext(
        ciphertext, lambda _candidate: True, lambda _value: True,
        block_size=8, max_queries=10_000,
    ) is None
    assert attack.recover_cbc_padding_plaintext(
        ciphertext, _raises, lambda _value: True,
        block_size=8, max_queries=10,
    ) is None
    assert attack.recover_cbc_padding_plaintext(
        ciphertext, lambda _candidate: False, lambda _value: True,
        block_size=8, max_queries=1,
    ) is None


def test_mac_duplicate_lengths_negative_controls_and_callback_failures():
    secret, message, extra = b"hidden-prefix", b"user=guest", b"&admin=1"
    digest = hashlib.sha256(secret + message).digest()
    verify = lambda candidate, tag: hashlib.sha256(secret + candidate).digest() == tag
    duplicate = attack.forge_prefix_mac_length_extension(
        "sha256", digest, message, extra,
        [len(secret), len(secret), len(secret)], verify,
    )
    assert duplicate is not None and duplicate[2] == len(secret)
    # A verifier accepting the one-bit negative control is not evidence.
    assert attack.forge_prefix_mac_length_extension(
        "sha256", digest, message, extra, [len(secret)], lambda *_args: True
    ) is None
    assert attack.forge_prefix_mac_length_extension(
        "sha256", digest, message, extra, [len(secret)], _raises
    ) is None

    key = bytes(range(16))
    original = b"from=alice......" + b"amount=000001000"
    target = b"from=admin......" + original[16:]
    iv, tag = bytes(range(16, 32)), _cbc_mac(key, original, bytes(range(16, 32)))
    assert attack.forge_cbc_mac_variable_iv(
        original, iv, tag, target, lambda *_args: True
    ) is None
    assert attack.forge_cbc_mac_variable_iv(
        original, iv, tag, target, _raises
    ) is None

    extension = b"admin-extension!" + b"final-extension!"
    extension_tag = _cbc_mac(key, extension)
    assert attack.forge_cbc_mac_length_extension(
        original, _cbc_mac(key, original), extension, extension_tag,
        lambda *_args: True,
    ) is None
    assert attack.forge_cbc_mac_length_extension(
        original, _cbc_mac(key, original), extension, extension_tag, _raises
    ) is None


def test_aead_two_record_ambiguity_tampering_and_verifier_controls():
    key, nonce, aad = bytes(range(16)), bytes(range(12)), b"aad"
    p1 = bytes.fromhex("0104070a0d101316191c1f2225282b2e31")
    p2 = bytes.fromhex("01080f161d242b323940474e555c636a71")
    two = [(aad, *_aes_gcm(key, nonce, aad, plaintext)) for plaintext in (p1, p2)]
    assert len(base_depth.gcm_recover_subkey(two)) == 3
    assert attack.recover_gcm_nonce_reuse_key(two) is None

    good = [(aad, *_aes_gcm(key, nonce, aad, byte * 16))
            for byte in (b"A", b"B", b"C")]
    tampered = list(good)
    bad_tag = bytearray(tampered[-1][2])
    bad_tag[0] ^= 1
    tampered[-1] = (tampered[-1][0], tampered[-1][1], bytes(bad_tag))
    assert attack.recover_gcm_nonce_reuse_key(tampered) is None
    target_ciphertext, _ = _aes_gcm(key, nonce, aad, b"target body")
    assert attack.forge_gcm_nonce_reuse_tag(
        good, aad, target_ciphertext, lambda *_args: True
    ) is None
    assert attack.forge_gcm_nonce_reuse_tag(
        good, aad, target_ciphertext, _raises
    ) is None

    ckey, cnonce, caad = bytes(range(32)), bytes(range(12)), b"chacha-aad"
    cgood = [(caad, *_chacha(ckey, cnonce, caad, byte * 16))
             for byte in (b"X", b"Y", b"Z")]
    ctampered = list(cgood)
    bad_tag = bytearray(ctampered[-1][2])
    bad_tag[-1] ^= 0x80
    ctampered[-1] = (ctampered[-1][0], ctampered[-1][1], bytes(bad_tag))
    assert attack.recover_chacha20_poly1305_one_time_key(ctampered) is None
    target_ciphertext, _ = _chacha(ckey, cnonce, caad, b"target body")
    assert attack.forge_chacha20_poly1305_nonce_reuse_tag(
        cgood, caad, target_ciphertext, lambda *_args: True
    ) is None
    assert attack.forge_chacha20_poly1305_nonce_reuse_tag(
        cgood, caad, target_ciphertext, _raises
    ) is None


def test_generators_are_bounded_and_aead_forgers_do_not_double_consume():
    key, nonce, aad = bytes(range(16)), bytes(range(12)), b"generator-aad"
    triples = [(aad, *_aes_gcm(key, nonce, aad, byte * 16))
               for byte in (b"A", b"B", b"C")]
    target_ciphertext, trusted_tag = _aes_gcm(key, nonce, aad, b"target body")

    def verify(candidate_aad, ciphertext, tag):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(candidate_aad)
        try:
            cipher.decrypt_and_verify(ciphertext, tag)
            return True
        except ValueError:
            return False

    assert attack.forge_gcm_nonce_reuse_tag(
        (item for item in triples), aad, target_ciphertext, verify
    ) == trusted_tag
    assert attack.forge_prefix_mac_length_extension(
        "sha256", b"\0" * 32, b"m", b"x", itertools.count(), lambda *_args: False
    ) is None
    assert attack.detect_nonce_reuse((
        {"algorithm": "gcm", "key_id": "k", "nonce": b"n"}
        for _ in range(attack.MAX_RECORDS + 1)
    )) is None
    assert attack.recover_gcm_nonce_reuse_key(
        itertools.repeat((b"", b"c", b"t" * 16), attack.MAX_RECORDS + 1)
    ) is None


def test_byte_and_whitebox_caps_malformed_models_and_exceptions():
    oversized = memoryview(bytearray(attack.MAX_TOTAL_BYTES + 1))
    assert attack.detect_nonce_reuse([
        {"algorithm": "gcm", "key_id": "k", "nonce": oversized}
    ]) is None
    assert attack.recover_whitebox_xor_sbox([False] * 256) is None
    assert attack.recover_whitebox_xor_sbox([0.5] * 256) is None
    assert attack.recover_whitebox_xor_sbox(
        list(range(256)), sbox=list(range(257))
    ) is None
    assert attack.recover_whitebox_xor_sbox(
        list(range(256)), known_pairs=[("not", "integers")]
    ) is None
    assert attack.recover_whitebox_trace_key(
        [(1, 2)], _raises
    ) is None
    assert attack.recover_whitebox_trace_key(
        ((index, 0) for index in range(attack.MAX_WHITEBOX_TRACES + 1)),
        lambda _value, _key: 0,
    ) is None
    assert attack.recover_whitebox_trace_key(
        [(1, 0)], lambda _value, _key: 0,
        key_candidates=range(attack.MAX_WHITEBOX_KEYS + 1),
    ) is None
