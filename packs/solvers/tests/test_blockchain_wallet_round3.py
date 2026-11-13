"""Synthetic BIP39/BIP32, keystore-v3, storage-slot, WIF, and brainwallet fixtures."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from Crypto.Cipher import AES


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import blockchain as chain  # noqa: E402


MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_bip39_vector_and_optional_checksum_validation():
    seed = chain.bip39_seed(MNEMONIC, "TREZOR")
    assert seed.hex() == (
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    )

    words = [f"word{i:04d}" for i in range(2048)]
    valid = " ".join([words[0]] * 11 + [words[3]])  # 128 zero entropy + SHA256 checksum 0011
    assert chain.bip39_seed(valid, wordlist=words) is not None
    assert chain.bip39_seed(" ".join([words[0]] * 12), wordlist=words) is None


def test_bip32_bip44_ethereum_bitcoin_and_extended_keys():
    wallet = chain.derive_wallet(MNEMONIC, paths=["m/44'/60'/0'/0/0", "m/44'/0'/0'/0/0"])
    assert wallet["derived"][0]["ethereum"] == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    assert wallet["master_xprv"].startswith("xprv")
    assert wallet["master_xpub"].startswith("xpub")
    assert wallet["derived"][1]["bitcoin_p2pkh"].startswith("1")
    for item in wallet["derived"]:
        assert chain.wif_decode(item["wif"])["private"] == int.from_bytes(item["private"], "big")

    assert chain.parse_bip32_path("m/44'/60'/0'/0/0") == [
        44 | 0x80000000, 60 | 0x80000000, 0x80000000, 0, 0
    ]
    assert chain.parse_bip32_path("m//0") is None


def _keystore(private: bytes, password: str):
    salt = bytes.fromhex("11" * 32)
    iv = bytes.fromhex("22" * 16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000, 32)
    cipher = AES.new(derived[:16], AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
    ciphertext = cipher.encrypt(private)
    address = chain.private_to_eth_address(int.from_bytes(private, "big"))
    return {
        "version": 3,
        "address": address.removeprefix("0x").lower(),
        "crypto": {
            "cipher": "aes-128-ctr", "ciphertext": ciphertext.hex(),
            "cipherparams": {"iv": iv.hex()},
            "kdf": "pbkdf2",
            "kdfparams": {"dklen": 32, "c": 1000, "prf": "hmac-sha256", "salt": salt.hex()},
            "mac": chain.keccak(derived[16:32] + ciphertext).hex(),
        },
    }


def test_keystore_v3_decrypt_requires_mac_and_address_roundtrip():
    private = (123456789).to_bytes(32, "big")
    document = _keystore(private, "correct password")
    result = chain.decrypt_keystore_v3(document, "correct password")
    assert result["private"] == private
    assert result["verified_mac"] is True
    assert result["ethereum"] == chain.private_to_eth_address(123456789)
    assert chain.decrypt_keystore_v3(document, "wrong password") is None

    tampered = json.loads(json.dumps(document))
    tampered["crypto"]["ciphertext"] = "00" + tampered["crypto"]["ciphertext"][2:]
    assert chain.decrypt_keystore_v3(tampered, "correct password") is None


def test_storage_slots_wif_and_brainwallet_are_exact():
    slot = chain.storage_slot(4, 1)
    assert slot == chain.keccak((4).to_bytes(32, "big") + (1).to_bytes(32, "big"))
    nested = chain.nested_storage_slot([{"value": 4, "type": "uint256"},
                                        {"value": "0x" + "12" * 20, "type": "address"}], 1)
    assert len(nested) == 32

    wif = chain.wif_encode(1)
    assert wif == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    assert chain.wif_decode(wif) == {"private": 1, "compressed": True, "network": "mainnet"}
    brain = chain.brainwallet("correct horse battery staple")
    assert brain["private"] == int.from_bytes(hashlib.sha256(b"correct horse battery staple").digest(), "big")
    assert chain.wif_decode(brain["wif"])["private"] == brain["private"]


def test_guarded_wallet_cli(tmp_path, capsys):
    fixture = tmp_path / "wallet.json"
    fixture.write_text(json.dumps({"mnemonic": MNEMONIC, "paths": ["m/44'/60'/0'/0/0"]}),
                       encoding="utf-8")
    assert chain.main(["wallet", str(fixture), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["verified"] is True
    assert output["sensitive"] is True
    assert output["candidate"]["derived"][0]["ethereum"] == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

    bad = tmp_path / "bad.json"
    bad.write_bytes(b"{\xff")
    assert chain.main(["keystore", str(bad)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("blockchain: ")
    assert "Traceback" not in captured.err

