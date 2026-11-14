"""Saved-capture-only BLE, HCI, Zigbee and AES-CCM verification."""
from __future__ import annotations

import json
import random
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import radio_capture as radio  # noqa: E402


def _ble_adv():
    addr = bytes.fromhex("665544332211")
    ad = (b"\x02\x01\x06" + b"\x0f\x09CSCTF{ble_adv}" +
          b"\x06\xff\x4c\x00XYZ")
    return b"\x00" + bytes([len(addr + ad)]) + addr + ad


def _h4_att():
    att = b"\x1b\x25\x00CSCTF{gatt}"
    l2 = len(att).to_bytes(2, "little") + b"\x04\x00" + att
    acl = b"\x01\x20" + len(l2).to_bytes(2, "little") + l2
    return b"\x02" + acl


def _mac(payload, *, src_ext=bytes.fromhex("0807060504030201")):
    fcf = 1 | 0x40 | (2 << 10) | (3 << 14)  # data, PAN-compressed, short dest, ext src
    return (fcf.to_bytes(2, "little") + b"\x33" + b"\x34\x12" + b"\xff\xff" +
            src_ext + payload)


def _aps(flag=b"CSCTF{zigbee_zcl}"):
    zcl = b"\x18\x42\x0a" + flag
    return b"\x00\x01\x06\x00\x04\x01\x01\x99" + zcl


def _zigbee_unencrypted():
    nwk = b"\x08\x00" + b"\xff\xff\x44\x33\x1e\x07" + _aps()
    return _mac(nwk)


def _zigbee_encrypted(key):
    source = bytes.fromhex("0807060504030201")
    fcf = 0x0008 | 0x0200 | 0x1000  # v2, security, source IEEE present
    header = fcf.to_bytes(2, "little") + b"\xff\xff\x44\x33\x1e\x08" + source
    control, counter = 0x2D, 0x10203040  # level 5, key sequence, extended nonce
    aux = bytes([control]) + counter.to_bytes(4, "little") + source + b"\x01"
    nonce = source + counter.to_bytes(4, "little") + bytes([control])
    plaintext = _aps(b"CSCTF{zigbee_ccm}")
    encrypted = AESCCM(key, tag_length=4).encrypt(nonce, plaintext, header + aux)
    return _mac(header + aux + encrypted, src_ext=source)


def _pcap(linktype, frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for index, frame in enumerate(frames):
        out += struct.pack("<IIII", index, 0, len(frame), len(frame)) + frame
    return out


def test_ble_advertising_and_ad_structures():
    report = radio.parse_ble_advertising(_ble_adv())
    assert report["advertiser"] == "11:22:33:44:55:66"
    fields = {row["name"]: row for row in report["advertising_data"]}
    assert fields["complete_name"]["text"] == "CSCTF{ble_adv}"
    assert fields["manufacturer_data"]["company_id"] == 0x004C
    assert radio.parse_ble_advertising(_ble_adv()[:-1]) is None


def test_hci_h4_acl_l2cap_att_and_btsnoop():
    rows = radio.parse_h4_stream(_h4_att())
    att = rows[0]["l2cap"]["att"]
    assert att["operation"] == "HandleValueNotification"
    assert att["handle"] == 0x25 and att["value"] == b"CSCTF{gatt}"
    record = struct.pack(">IIIIQ", len(_h4_att()), len(_h4_att()), 0, 0, 1) + _h4_att()
    snoop = b"btsnoop\x00" + struct.pack(">II", 1, 1002) + record
    assert radio.parse_btsnoop(snoop)[0]["packets"][0]["l2cap"]["att"]["handle"] == 0x25


def test_zigbee_mac_nwk_aps_zcl_stack():
    result = radio.parse_ieee802154(_zigbee_unencrypted())
    assert result["destination_pan"] == "0x1234"
    assert result["source"] == "01:02:03:04:05:06:07:08"
    aps = result["zigbee"]["aps"]
    assert aps["cluster"] == 6 and aps["profile"] == 0x0104
    assert aps["zcl"]["command_name"] == "ReportAttributes"
    assert aps["zcl"]["payload"] == b"CSCTF{zigbee_zcl}"


def test_zigbee_authenticated_decryption_and_tamper_decline():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    frame = _zigbee_encrypted(key)
    result = radio.parse_ieee802154(frame, network_key=key)
    nwk = result["zigbee"]
    assert nwk["decryption"] == {"verified": True, "mic_length": 4}
    assert nwk["aps"]["zcl"]["payload"] == b"CSCTF{zigbee_ccm}"
    damaged = bytearray(frame)
    damaged[-1] ^= 1
    bad = radio.parse_ieee802154(bytes(damaged), network_key=key)["zigbee"]
    assert bad["decryption"]["verified"] is False and "aps" not in bad


def test_radio_pcap_and_guarded_cli(tmp_path, capsys):
    capture = _pcap(230, [_zigbee_unencrypted()])
    report = radio.analyze(capture, kind="pcap")
    assert report["linktype"] == 230 and report["records"][0]["zigbee"]["aps"]["cluster"] == 6
    path = tmp_path / "radio.pcap"
    path.write_bytes(capture)
    assert radio.main([str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["offline"] is True
    assert radio.main([]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_seeded_mutation_never_leaks_parser_exceptions():
    rng = random.Random(0xB1E5BEE)
    seeds = [_ble_adv(), _zigbee_unencrypted(), _h4_att()]
    for _ in range(1000):
        blob = bytearray(rng.choice(seeds))
        for _ in range(rng.randrange(1, 10)):
            if not blob or (len(blob) < 512 and rng.randrange(3) == 0):
                blob.insert(rng.randrange(len(blob) + 1), rng.randrange(256))
            elif rng.randrange(2):
                blob[rng.randrange(len(blob))] ^= 1 << rng.randrange(8)
            else:
                del blob[rng.randrange(len(blob))]
        raw = bytes(blob)
        radio.parse_ble_advertising(raw)
        radio.parse_ieee802154(raw)
        try:
            radio.parse_h4_stream(raw)
        except radio.RadioError:
            pass
