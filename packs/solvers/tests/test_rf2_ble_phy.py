"""Published and independent vectors for the offline BLE PHY extension."""
from __future__ import annotations

import json
import random

import pytest
from scapy.layers.bluetooth import EIR_CompleteLocalName, EIR_Hdr
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_IND

import rf2_ble_phy as ble


# Bluetooth Core sample-data packet, channel 38, in transmitted-byte packing.
SIG_PDU = bytes.fromhex("4209a6a5a4a3a2c1010203")
SIG_CRC = bytes.fromhex("adb4eb")
SIG_WHITENED = bytes.fromhex("94cce285fd7d434e1aa7acefcfa5")
SIG_PACKET = bytes.fromhex("aad6be898e94cce285fd7d434e1aa7acefcfa5")


def ref_whiten(data: bytes, channel: int) -> bytes:
    """Direct test-side transcription of Core Vol 6 Part B's LFSR."""
    state = channel | 0x40
    out = bytearray()
    for octet in data:
        value = 0
        for bit in range(8):
            whitening = state & 1
            value |= (((octet >> bit) & 1) ^ whitening) << bit
            state = (state >> 1) ^ (0x44 if whitening else 0)
        out.append(value)
    return bytes(out)


def clean(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except ble.RF2BLEError:
        return None
    except BaseException as exc:
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


def test_bluetooth_sig_complete_packet_crc_and_whitening_vector():
    assert ble.ble_crc24(SIG_PDU) == SIG_CRC
    assert ble.ble_whiten(SIG_PDU + SIG_CRC, 38) == SIG_WHITENED
    report = ble.decode_advertising_phy(SIG_PACKET, 38)
    assert report["preamble"] == 0xAA
    assert report["access_address"] == "0x8e89bed6"
    assert report["pdu"] == SIG_PDU and report["crc"] == SIG_CRC
    assert report["crc_ok"] is True
    # The SIG PHY sample uses arbitrary AdvData rather than complete AD records.
    assert report["advertising"] is None


def test_scapy_pdu_oracle_and_independent_wire_synthesis():
    packet = (BTLE() / BTLE_ADV() /
              BTLE_ADV_IND(AdvA="11:22:33:44:55:66") /
              EIR_Hdr() / EIR_CompleteLocalName(local_name=b"CSCTF{rf2_ble}"))
    raw = bytes(packet)
    assert raw[:4] == bytes.fromhex("d6be898e")
    pdu, oracle_crc = raw[4:-3], raw[-3:]
    assert ble.ble_crc24(pdu) == oracle_crc
    wire = b"\xaa" + raw[:4] + ref_whiten(raw[4:], 37)
    report = ble.decode_advertising_phy(wire, 37)
    decoded = report["advertising"]
    assert decoded["pdu_name"] == "ADV_IND"
    assert decoded["advertiser"] == "11:22:33:44:55:66"
    assert decoded["advertising_data"][0]["text"] == "CSCTF{rf2_ble}"


def test_official_whitening_sequence_prefix_for_channel_37():
    # Core sample data gives transmitted bits
    # 10110001 01001011 ...; packed LSB-first these are 8d d2 ...
    assert ble.ble_whiten(bytes(8), 37) == bytes.fromhex("8dd257a13da766b0")
    assert ble.ble_whiten(ref_whiten(b"round-trip", 39), 39) == b"round-trip"


def test_corruption_and_malformed_frames_fail_closed():
    damaged = bytearray(SIG_PACKET)
    damaged[-1] ^= 1
    with pytest.raises(ble.RF2BLEError, match="CRC"):
        ble.decode_advertising_phy(bytes(damaged), 38)
    cases = [
        b"", SIG_PACKET[:4], b"\x55" + SIG_PACKET[1:],
        SIG_PACKET[:1] + b"\x00\x00\x00\x00" + SIG_PACKET[5:],
        SIG_PACKET + b"x", b"x" * (ble.MAX_FRAME + 1),
    ]
    for raw in cases:
        clean(ble.decode_advertising_phy, raw, 38)
    for bad_channel in (-1, 0, 36, 40, True, None, "37"):
        clean(ble.decode_advertising_phy, SIG_PACKET, bad_channel)
    for bad in (None, bytearray(b"x"), {}, [], object()):
        clean(ble.ble_crc24, bad)
        clean(ble.ble_whiten, bad, 37)


def test_seeded_random_never_leaks_and_cli_is_guarded(tmp_path, capsys):
    rng = random.Random(0xB1E2)
    for size in range(96):
        clean(ble.decode_advertising_phy, rng.randbytes(size), 37)
    path = tmp_path / "adv.bin"
    path.write_bytes(SIG_PACKET)
    assert ble.main([str(path), "--channel", "38"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["crc_ok"] is True and report["pdu"]["hex"] == SIG_PDU.hex()
    assert ble.main(["--help"]) == 0
    capsys.readouterr()
    assert ble.main([]) == 2

