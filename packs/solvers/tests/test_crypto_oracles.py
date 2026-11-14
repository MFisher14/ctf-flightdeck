"""Synthetic, transport-free coverage for the callback oracle engines."""
from __future__ import annotations

import hashlib
import math
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
import crypto_oracles as oracle  # noqa: E402


def _xor_block(block: bytes, key: bytes) -> bytes:
    """A tiny permutation used as a synthetic block cipher (not cryptography)."""
    return bytes(a ^ b for a, b in zip(block, key))


def _cbc_encrypt(plaintext: bytes, iv: bytes, key: bytes) -> bytes:
    size = len(key)
    previous = iv
    out = bytearray(iv)
    for offset in range(0, len(plaintext), size):
        mixed = bytes(a ^ b for a, b in zip(plaintext[offset:offset + size], previous))
        previous = _xor_block(mixed, key)
        out.extend(previous)
    return bytes(out)


def _cbc_decrypt(combined: bytes, key: bytes) -> bytes:
    size = len(key)
    previous = combined[:size]
    out = bytearray()
    for offset in range(size, len(combined), size):
        block = combined[offset:offset + size]
        out.extend(a ^ b for a, b in zip(_xor_block(block, key), previous))
        previous = block
    return bytes(out)


def _padding_oracle(key: bytes):
    size = len(key)

    def check(combined: bytes) -> bool:
        if not isinstance(combined, bytes) or len(combined) < 2 * size or len(combined) % size:
            return False
        try:
            oracle.pkcs7_unpad(_cbc_decrypt(combined, key), size)
            return True
        except ValueError:
            return False

    return check


def test_cbc_padding_oracle_decrypt_and_encrypt_round_trip():
    key = b"toy-key!"  # 8-byte XOR permutation
    iv = b"initial!"
    message = b"chosen CBC plaintext spans blocks"
    combined = _cbc_encrypt(oracle.pkcs7_pad(message, 8), iv, key)
    check = _padding_oracle(key)

    assert oracle.cbc_padding_oracle_decrypt(combined, check, block_size=8) == message

    built = oracle.cbc_padding_oracle_encrypt(
        message, check, block_size=8, final_block=b"finalblk"
    )
    assert oracle.pkcs7_unpad(_cbc_decrypt(built, key), 8) == message


def test_cbc_query_budget_and_oracle_protocol_are_explicit():
    with pytest.raises(oracle.OracleLimitError):
        oracle.cbc_padding_oracle_decrypt(b"A" * 16, lambda _c: False,
                                          block_size=8, max_queries=1)
    with pytest.raises(oracle.OracleProtocolError):
        oracle.cbc_padding_oracle_decrypt(b"A" * 16, lambda _c: "yes",
                                          block_size=8, max_queries=10)


# Fixed 48-bit primes keep the adaptive RSA tests deterministic and quick.
P = 246_402_745_979_669
Q = 177_951_351_149_821
N = P * Q
E = 65_537
D = pow(E, -1, (P - 1) * (Q - 1))
K = (N.bit_length() + 7) // 8


def _decrypt(ciphertext: bytes) -> int:
    return pow(int.from_bytes(ciphertext, "big"), D, N)


def test_rsa_parity_oracle_exact_interval_and_public_proof():
    message = 12_345_678_901_234_567_890
    ciphertext = pow(message, E, N)
    got = oracle.rsa_parity_oracle_recover(
        ciphertext, N, E, lambda candidate: bool(_decrypt(candidate) & 1)
    )
    assert got == message
    assert pow(got, E, N) == ciphertext


def test_bleichenbacher_recovers_full_encoded_block_and_decodes():
    # k=12: the minimum eight-byte PS plus a one-byte message.
    encoded = b"\x00\x02" + b"A" * 8 + b"\x00X"
    message = int.from_bytes(encoded, "big")
    ciphertext = pow(message, E, N)
    B = 1 << (8 * (K - 2))

    # This is the canonical interval oracle leaked by the 00 02 prefix check.
    check = lambda candidate: 2 * B <= _decrypt(candidate) < 3 * B
    recovered = oracle.bleichenbacher_pkcs1_v1_5_recover(
        ciphertext, N, E, check, max_queries=100_000
    )
    assert recovered == encoded
    assert oracle.decode_pkcs1_v1_5(recovered) == b"X"


def test_manger_leading_zero_recovers_and_reencrypts():
    B = 1 << (8 * (K - 1))
    message = B // 3 + 12_345
    ciphertext = pow(message, E, N)
    recovered = oracle.manger_leading_zero_recover(
        ciphertext, N, E, lambda candidate: _decrypt(candidate) < B
    )
    assert recovered == message
    assert pow(recovered, E, N) == ciphertext


def _oaep_encode(message: bytes, size: int, seed: bytes, label: bytes = b"") -> bytes:
    hlen = hashlib.sha1().digest_size
    assert len(seed) == hlen and len(message) <= size - 2 * hlen - 2
    db = hashlib.sha1(label).digest() + b"\x00" * (size - len(message) - 2 * hlen - 2) + b"\x01" + message
    db_mask = oracle.mgf1(seed, size - hlen - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = oracle.mgf1(masked_db, hlen)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db


def test_oaep_decode_integrity_and_cli_guard(capsys):
    encoded = _oaep_encode(b"OAEP fixture", 64, bytes(range(20)), b"label")
    assert oracle.oaep_decode(encoded, label=b"label") == b"OAEP fixture"
    corrupted = bytearray(encoded)
    corrupted[-1] ^= 1
    assert oracle.oaep_decode(bytes(corrupted), label=b"label") is None

    assert oracle.main(["pkcs7-unpad", "not-hex"]) == 2
    assert "crypto_oracles:" in capsys.readouterr().err
    assert oracle.main(["pkcs7-unpad", "00", "--block-size", "0"]) == 2
    assert "crypto_oracles:" in capsys.readouterr().err
    assert oracle.main(["describe", "--json"]) == 0
    assert '"transport"' in capsys.readouterr().out


def test_rsa_input_and_query_caps():
    assert math.gcd(E, (P - 1) * (Q - 1)) == 1
    with pytest.raises(ValueError):
        oracle.rsa_parity_oracle_recover(N, N, E, lambda _c: False)
    with pytest.raises(ValueError):
        oracle.OracleBudget(lambda _c: False, oracle.MAX_QUERIES + 1)
