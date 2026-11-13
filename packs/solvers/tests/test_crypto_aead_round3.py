"""Synthetic round trips for the round-3 offline AEAD depth primitives."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from Crypto.Cipher import AES, ChaCha20_Poly1305


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))

import crypto_depth as cd  # noqa: E402


def _aes_gcm(key, nonce, aad, plaintext):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)


def _chacha(key, nonce, aad, plaintext):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)


def test_gcm_forge_from_recovered_h_round_trips_non_aligned_lengths():
    key = bytes(range(16))
    nonce = bytes(range(16, 28))
    aad = b"non-block-aligned aad!"
    plaintext = b"a chosen body whose size is deliberately not aligned"
    ciphertext, trusted_tag = _aes_gcm(key, nonce, aad, plaintext)

    h = int.from_bytes(AES.new(key, AES.MODE_ECB).encrypt(bytes(16)), "big")
    counter_mask = int.from_bytes(
        AES.new(key, AES.MODE_ECB).encrypt(nonce + b"\x00\x00\x00\x01"), "big"
    )
    forged = cd.gcm_forge_tag(h, counter_mask, aad, ciphertext)
    assert forged == trusted_tag
    assert cd.gcm_forge_tag(h.to_bytes(16, "big"), counter_mask.to_bytes(16, "big"),
                            aad, ciphertext, 12) == trusted_tag[:12]

    verifier = AES.new(key, AES.MODE_GCM, nonce=nonce)
    verifier.update(aad)
    assert verifier.decrypt_and_verify(ciphertext, forged) == plaintext
    assert cd.verify_ghash_key_commitment(h, counter_mask, [(aad, ciphertext, trusted_tag)])


def test_chacha20_poly1305_nonce_reuse_recovery_and_forgery_round_trip():
    key = bytes(range(32))
    nonce = bytes(range(12))
    aad = b"header-19-byte-value"
    observations = []
    for plaintext in (b"A" * 16, b"B" * 16, b"C" * 16):
        ciphertext, tag = _chacha(key, nonce, aad, plaintext)
        observations.append((aad, ciphertext, tag))

    candidates = cd.recover_chacha20_poly1305_nonce_reuse(observations)
    assert len(candidates) == 1
    r, s = candidates[0]
    assert r & ~cd.POLY1305_R_MASK == 0
    assert all(cd.chacha20_poly1305_forge_tag(r, s, a, c) == t
               for a, c, t in observations)

    target_plaintext = b"a non-aligned forged target ciphertext!"
    target_ciphertext, trusted_tag = _chacha(key, nonce, aad, target_plaintext)
    forged = cd.chacha20_poly1305_nonce_reuse_forge(
        observations, aad, target_ciphertext
    )
    assert [candidate["tag"] for candidate in forged] == [trusted_tag]

    verifier = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    verifier.update(aad)
    assert verifier.decrypt_and_verify(target_ciphertext, forged[0]["tag"]) == target_plaintext


def test_chacha_recovery_rejects_unsupported_degree_and_inconsistent_capture():
    key = bytes(reversed(range(32)))
    nonce = bytes(range(12, 24))
    aad = b"same-aad"
    # Both ciphertext blocks differ, leaving a cubic equation.  The bounded
    # engine explicitly returns no candidate instead of claiming a heuristic.
    high_degree = []
    for plaintext in (b"A" * 32, b"B" * 32):
        ciphertext, tag = _chacha(key, nonce, aad, plaintext)
        high_degree.append((aad, ciphertext, tag))
    assert cd.recover_chacha20_poly1305_nonce_reuse(high_degree) == []

    supported = []
    for plaintext in (b"X" * 16, b"Y" * 16, b"Z" * 16):
        ciphertext, tag = _chacha(key, nonce, aad, plaintext)
        supported.append((aad, ciphertext, tag))
    broken = bytearray(supported[-1][2])
    broken[0] ^= 0x80
    supported[-1] = (supported[-1][0], supported[-1][1], bytes(broken))
    assert cd.recover_chacha20_poly1305_nonce_reuse(supported) == []


def test_ghash_commitment_candidate_and_observation_partitions():
    key = bytes(range(80, 96))
    h = int.from_bytes(AES.new(key, AES.MODE_ECB).encrypt(bytes(16)), "big")
    nonce_a = bytes(range(12))
    nonce_b = bytes(range(20, 32))
    records = []
    for nonce, messages in ((nonce_a, (b"first", b"second message")),
                            (nonce_b, (b"third", b"fourth message!"))):
        for index, plaintext in enumerate(messages):
            aad = b"aad" + bytes([index])
            ciphertext, tag = _aes_gcm(key, nonce, aad, plaintext)
            records.append((aad, ciphertext, tag))

    reports = cd.ghash_partition_observations([h, h ^ 1], records)
    true_report = reports[0]
    assert true_report["group_count"] == 2
    assert {tuple(group["observation_indices"]) for group in true_report["groups"]} == {
        (0, 1), (2, 3)
    }
    assert true_report["verified"]
    assert reports[1]["group_count"] == 4

    mask_a = cd.ghash(h, records[0][0], records[0][1]) ^ int.from_bytes(records[0][2], "big")
    mask_b = cd.ghash(h, records[2][0], records[2][1]) ^ int.from_bytes(records[2][2], "big")
    partitions = cd.ghash_partition_candidates(
        [(h, mask_a), (h, mask_a), (h, mask_b)], records[0][0], records[0][1], records[0][2]
    )
    matching = [group for group in partitions if group["matches_observed"]]
    assert len(matching) == 1
    assert matching[0]["candidate_indices"] == [0, 1]


def test_crypto_depth_guarded_cli(tmp_path, capsys):
    key = bytes(range(16))
    nonce = bytes(range(12))
    aad = b"cli aad"
    ciphertext, tag = _aes_gcm(key, nonce, aad, b"cli body")
    h = AES.new(key, AES.MODE_ECB).encrypt(bytes(16))
    mask = AES.new(key, AES.MODE_ECB).encrypt(nonce + b"\x00\x00\x00\x01")
    fixture = tmp_path / "gcm.json"
    fixture.write_text(json.dumps({
        "h": h.hex(),
        "counter_mask": mask.hex(),
        "aad": aad.hex(),
        "ciphertext": ciphertext.hex(),
    }))
    assert cd.main(["gcm-forge", str(fixture), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["tag"] == tag.hex()

    garbage = tmp_path / "garbage.json"
    garbage.write_bytes(b"not json")
    assert cd.main(["chacha-recover", str(garbage), "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("crypto_depth: ")
    assert "Traceback" not in captured.err


def test_aead_public_bounds_and_type_guards():
    with pytest.raises(ValueError):
        cd.gcm_forge_tag(0, 0, b"", b"", tag_length=3)
    with pytest.raises(ValueError):
        cd.recover_chacha20_poly1305_nonce_reuse([], max_carry=5)
    with pytest.raises(TypeError):
        cd.gcm_forge_tag(0, 0, "text is not bytes", b"")
