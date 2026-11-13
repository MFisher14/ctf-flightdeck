import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import chain_formats as chain


def word(number):
    return int(number).to_bytes(32, "big")


def test_known_calldata_dynamic_values_revert_and_panics():
    recipient = bytes.fromhex("11" * 20)
    data = chain.selector("transfer(address,uint256)") + b"\0" * 12 + recipient + word(123)
    decoded = chain.decode_calldata(data)
    assert decoded["signature"] == "transfer(address,uint256)"
    assert decoded["arguments"] == ["0x" + recipient.hex(), 123]
    assert chain.decode_calldata(bytes.fromhex("deadbeef") + word(7))["signature"] is None

    reason = b"bad call"
    error = bytes.fromhex("08c379a0") + word(32) + word(len(reason)) + reason + b"\0" * (32 - len(reason))
    assert chain.decode_revert(error)["reason"] == "bad call"
    panic = bytes.fromhex("4e487b71") + word(0x11)
    assert "overflow" in chain.decode_revert(panic)["reason"]
    custom = chain.selector("Nope(uint256)") + word(9)
    assert chain.decode_revert(custom, {custom[:4].hex(): "Nope(uint256)"})["arguments"] == [9]


def test_standard_event_decode():
    signature = "Transfer(address,address,uint256)"
    topic0 = chain.keccak256(signature.encode())
    sender = bytes.fromhex("22" * 20)
    receiver = bytes.fromhex("33" * 20)
    report = chain.decode_event([topic0, b"\0" * 12 + sender, b"\0" * 12 + receiver], word(55))
    assert report["name"] == "Transfer"
    assert report["indexed"] == ["0x" + sender.hex(), "0x" + receiver.hex()]
    assert report["data_values"] == [55]
    unknown = chain.decode_event([b"\xff" * 32], b"")
    assert unknown["signature"] is None


def test_wallet_formats_are_public_only():
    keypair = list(range(64))
    report = chain.classify_wallet(keypair)
    assert report["format"] == "solana-keypair-array"
    assert report["public_key"] == chain.base58_encode(bytes(range(32, 64)))
    assert "0, 1, 2" not in json.dumps(report)

    eth = {"version": 3, "address": "abcd", "crypto": {"cipher": "aes-128-ctr", "ciphertext": "SECRET", "kdf": "scrypt"}}
    report = chain.classify_wallet(eth)
    assert report == {"format": "ethereum-keystore-v3", "address": "abcd", "cipher": "aes-128-ctr",
                      "kdf": "scrypt", "encrypted_private_material": True}
    assert "SECRET" not in json.dumps(report)
    electrum = {"wallet_type": "standard", "seed_version": 17,
                "keystore": {"type": "bip32", "xpub": "public", "seed": "never emit"}}
    report = chain.classify_wallet(electrum)
    assert report["format"] == "electrum-wallet" and report["private_material_present"] is True
    assert "never emit" not in json.dumps(report)


def test_descriptor_extended_key_and_walletconnect():
    report = chain.classify_descriptor("raw(deadbeef)#89f8spxm")
    assert report and report["checksum_valid"] is True
    assert chain.classify_descriptor("raw(deadbeef)#aaaaaaaa")["checksum_valid"] is False

    payload = bytes.fromhex("0488b21e") + bytes([3]) + b"\x11" * 4 + (7).to_bytes(4, "big") + b"\x22" * 32 + b"\x02" + b"\x33" * 32
    encoded = chain.base58_encode(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4])
    extended = chain.classify_extended_key(encoded)
    assert extended and extended["prefix"] == "xpub" and extended["depth"] == 3 and extended["child_number"] == 7
    assert chain.classify_extended_key(encoded[:-1] + "1") is None

    wc = chain.parse_walletconnect_uri("wc:topic@2?relay-protocol=irn&symKey=deadbeef")
    assert wc == {"format": "walletconnect-uri", "topic": "topic", "version": 2,
                  "relay_protocol": "irn", "symmetric_key_present": True}
    assert "deadbeef" not in json.dumps(wc)


def compact(number):
    assert number < 0xFD
    return bytes([number])


def test_psbt_v0_parser():
    unsigned = (struct.pack("<I", 2) + compact(1) + b"\0" * 32 + struct.pack("<I", 0) + compact(0)
                + struct.pack("<I", 0xFFFFFFFF) + compact(1) + struct.pack("<Q", 5000) + compact(0)
                + struct.pack("<I", 0))
    psbt = b"psbt\xff" + b"\x01\x00" + compact(len(unsigned)) + unsigned + b"\x00\x00\x00"
    report = chain.parse_psbt(psbt)
    assert report["version"] == 0 and report["inputs"] == 1 and report["outputs"] == 1
    assert chain.parse_psbt(base64.b64encode(psbt).decode()) == report
    with pytest.raises(ValueError):
        chain.parse_psbt(psbt + b"trailing")


def test_psbt_v2_compact_counts():
    # Global version=2, input count=1 and output count=1; empty per-input/output maps.
    psbt = (b"psbt\xff" + b"\x01\xfb\x04\x02\x00\x00\x00"
            + b"\x01\x04\x01\x01" + b"\x01\x05\x01\x01" + b"\x00\x00\x00")
    report = chain.parse_psbt(psbt)
    assert report["version"] == 2 and report["inputs"] == report["outputs"] == 1
    malformed = psbt.replace(b"\x01\x04\x01\x01", b"\x01\x04\x02\x01\x00")
    with pytest.raises(ValueError):
        chain.parse_psbt(malformed)


def test_psbt_unsigned_transaction_must_be_structurally_complete():
    # Declares one output but omits its script length and locktime.
    tx = (struct.pack("<I", 2) + b"\x01" + b"\0" * 32 + struct.pack("<I", 0)
          + b"\x00" + struct.pack("<I", 0xFFFFFFFF) + b"\x01" + struct.pack("<Q", 1))
    psbt = b"psbt\xff" + b"\x01\x00" + compact(len(tx)) + tx + b"\x00"
    with pytest.raises(ValueError):
        chain.parse_psbt(psbt)


def test_solana_legacy_transaction_parser():
    raw = (b"\x01" + b"\0" * 64 + b"\x01\x00\x00" + b"\x01" + b"\x01" * 32
           + b"\x02" * 32 + b"\x01" + b"\x00" + b"\x00" + b"\x02hi")
    report = chain.parse_solana_transaction(base64.b64encode(raw).decode())
    assert report["version"] == "legacy" and report["signature_count"] == 1
    assert report["accounts"] == [chain.base58_encode(b"\x01" * 32)]
    assert report["instructions"][0]["data_base58"] == chain.base58_encode(b"hi")
    with pytest.raises(ValueError):
        chain.parse_solana_transaction(raw[:-1])


def test_ethereum_json_artifact_and_strict_abi():
    calldata = "0x" + (chain.selector("balanceOf(address)") + b"\0" * 12 + b"\x44" * 20).hex()
    artifact = json.dumps({"from": "0x1", "to": "0x2", "chainId": "0x1", "input": calldata,
                           "accessList": [{"address": "0x2"}], "blobVersionedHashes": ["0xabc"]}).encode()
    report = chain.analyze_chain_artifact(artifact, "tx.json")
    assert report["format"] == "ethereum-transaction-json"
    assert report["calldata"]["name"] == "balanceOf" and report["access_list_entries"] == 1
    with pytest.raises(ValueError):
        chain.abi_decode(["bool"], word(2))
    with pytest.raises(ValueError):
        chain.decode_calldata("0x01")
    creation = chain.analyze_chain_artifact(json.dumps({"to": None, "input": "0x"}).encode(), "tx.json")
    assert creation["calldata"]["selector"] is None


def test_direct_decoder_bounds(monkeypatch):
    monkeypatch.setattr(chain, "MAX_INPUT", 8)
    with pytest.raises(ValueError, match="cap"):
        chain.decode_calldata("00" * 100)
    with pytest.raises(ValueError, match="cap"):
        chain.parse_psbt("A" * 100)
    with pytest.raises(ValueError, match="cap"):
        chain.parse_solana_transaction("A" * 100)
    with pytest.raises(ValueError, match="cap"):
        chain.base58_decode("1" * 300)
