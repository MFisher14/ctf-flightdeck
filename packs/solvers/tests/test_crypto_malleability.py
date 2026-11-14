"""Trusted local round trips for the offline CBC/CTR malleability builders."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers/common"))
import crypto_malleability as cli  # noqa: E402
import modern_crypto as M  # noqa: E402

AES = pytest.importorskip("Crypto.Cipher.AES")

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
IV = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")


def _cbc_encrypt(plaintext: bytes) -> bytes:
    assert len(plaintext) % 16 == 0
    return AES.new(KEY, AES.MODE_CBC, IV).encrypt(plaintext)


def _cbc_decrypt(iv: bytes, ciphertext: bytes) -> bytes:
    return AES.new(KEY, AES.MODE_CBC, iv).decrypt(ciphertext)


def test_cbc_first_block_edit_changes_iv_without_collateral():
    plaintext = b"uid=10;role=user" + b";expires=never!!"  # 32 bytes
    assert len(plaintext) == 32
    ciphertext = _cbc_encrypt(plaintext)
    offset = plaintext.index(b"user")
    result = M.cbc_bitflip(IV, ciphertext, offset, b"user", b"root")
    expected = plaintext[:offset] + b"root" + plaintext[offset + 4:]
    assert _cbc_decrypt(result["iv"], result["ciphertext"]) == expected
    assert result["collateral_plaintext_blocks"] == []
    assert result["modified_ciphertext_ranges"] == []
    assert result["changed_byte_count"] == 4


def test_cbc_later_block_edit_reports_exact_collateral():
    plaintext = b"A" * 16 + b"role=user;pad!!!" + b"C" * 16
    assert len(plaintext) == 48
    ciphertext = _cbc_encrypt(plaintext)
    result = M.cbc_bitflip(IV, ciphertext, 21, b"user", b"root")
    decrypted = _cbc_decrypt(result["iv"], result["ciphertext"])
    assert decrypted[21:25] == b"root"
    assert decrypted[16:32] == plaintext[16:21] + b"root" + plaintext[25:32]
    assert decrypted[:16] != plaintext[:16]
    assert result["collateral_plaintext_blocks"] == [0]
    assert result["target_plaintext_blocks"] == [1]


def test_cbc_nonadjacent_multiblock_edits_and_adjacent_refusal():
    plaintext = b"0" * 16 + b"block-one-USER!!" + b"2" * 16 + b"block-three-NO!!"
    assert len(plaintext) == 64
    ciphertext = _cbc_encrypt(plaintext)
    edits = [(26, b"USER", b"ROOT"), (60, b"NO", b"OK")]
    result = M.cbc_bitflip_forge(IV, ciphertext, edits)
    decrypted = _cbc_decrypt(result["iv"], result["ciphertext"])
    assert decrypted[26:30] == b"ROOT" and decrypted[60:62] == b"OK"
    assert result["target_plaintext_blocks"] == [1, 3]
    assert result["collateral_plaintext_blocks"] == [0, 2]

    with pytest.raises(M.MalleabilityError, match="also collateral"):
        M.cbc_bitflip_forge(IV, ciphertext, [(20, b"k", b"K"), (36, b"2", b"X")])


def test_ctr_multiple_edits_have_no_collateral():
    nonce = b"fixture!"
    plaintext = b"uid=1000&role=user&enabled=false"
    ciphertext = AES.new(KEY, AES.MODE_CTR, nonce=nonce).encrypt(plaintext)
    role = plaintext.index(b"user")
    enabled = plaintext.index(b"false")
    result = M.ctr_edit_forge(ciphertext, [
        (role, b"user", b"root"),
        {"offset": enabled, "known": b"false", "desired": b"true!"},
    ])
    decrypted = AES.new(KEY, AES.MODE_CTR, nonce=nonce).decrypt(result["ciphertext"])
    assert decrypted == plaintext[:role] + b"root" + plaintext[role + 4:enabled] + b"true!"
    assert result["collateral_plaintext_blocks"] == []
    assert result["changed_byte_count"] > 0


def test_overlap_bounds_and_types_fail_closed():
    ciphertext = b"X" * 32
    with pytest.raises(M.MalleabilityError, match="contradictory"):
        M.ctr_edit_forge(ciphertext, [(0, b"AB", b"CD"), (1, b"Z", b"Y")])
    with pytest.raises(M.MalleabilityError, match="past"):
        M.ctr_edit_forge(ciphertext, [(31, b"AB", b"CD")])
    with pytest.raises(M.MalleabilityError, match="bytes"):
        M.ctr_edit_forge(ciphertext, [(0, "A", "B")])
    with pytest.raises(M.MalleabilityError, match="block aligned"):
        M.cbc_bitflip_forge(IV, b"short", [(0, b"a", b"b")])


def test_guarded_cli_json_and_error(capsys):
    plaintext = b"uid=10;role=user" + b";expires=never!!"
    ciphertext = _cbc_encrypt(plaintext)
    assert cli.main(["cbc", "--iv", IV.hex(), "--ciphertext", ciphertext.hex(),
                     "--edit", "12:75736572:726f6f74", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert bytes.fromhex(result["iv"]) != IV
    assert result["mode"] == "cbc-bitflip"

    assert cli.main(["ctr", "--ciphertext", "not-hex", "--edit", "0:00:01"]) == 2
    captured = capsys.readouterr()
    assert "crypto_malleability:" in captured.err and "Traceback" not in captured.err

