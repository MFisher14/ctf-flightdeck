"""Independent waveform/packet locks and fail-closed fuzz for the RF2 PHYs."""
from __future__ import annotations

import json
import random

import numpy as np
import pytest
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_IND
from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4FCS
from scapy.packet import Raw

import rf2_ble_phy as ble
import rf2_ieee802154_phy as ieee


def _ble_numpy_whiten(data: bytes, channel: int) -> bytes:
    """Bluetooth Vol 6 Part B LFSR written independently with NumPy bits."""
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8), bitorder="little")
    state = channel | 0x40
    output = np.empty(bits.size, dtype=np.uint8)
    for index, bit in enumerate(bits):
        whitening = state & 1
        output[index] = int(bit) ^ whitening
        state = (state >> 1) ^ (0x44 if whitening else 0)
    return np.packbits(output, bitorder="little").tobytes()


def _ble_vector() -> tuple[bytes, bytes, bytes]:
    # Scapy independently supplies LL length and the advertising CRC.  Raw AD
    # structures avoid Scapy nesting one EIR length over all following EIRs.
    ad = b"\x02\x01\x06\x0e\x09CSCTF{np_ble}"
    packet = (BTLE() / BTLE_ADV() /
              BTLE_ADV_IND(AdvA="02:11:22:33:44:55") / Raw(ad))
    raw = bytes(packet)
    assert raw.hex() == (
        "d6be898e00185544332211020201060e0943534354467b6e705f626c657d3930b6"
    )
    wire = b"\xaa" + raw[:4] + _ble_numpy_whiten(raw[4:], 37)
    return wire, raw[4:-3], raw[-3:]


def _fcs_reference(data: bytes) -> bytes:
    """Bit-at-a-time CRC-16/KERMIT from IEEE 802.15.4's polynomial."""
    crc = 0
    for octet in data:
        for bit in range(8):
            feedback = (crc ^ (octet >> bit)) & 1
            crc >>= 1
            if feedback:
                crc ^= 0x8408
    return crc.to_bytes(2, "little")


def _ieee_vector() -> tuple[bytes, bytes]:
    packet = (Dot15d4FCS(
        fcf_frametype=1, fcf_panidcompress=1,
        fcf_destaddrmode=2, fcf_srcaddrmode=2, seqnum=0x5A,
    ) / Dot15d4Data(
        dest_panid=0x1AAA, dest_addr=0x3344, src_addr=0x5566,
    ) / Raw(b"CSCTF{np_154}"))
    psdu = bytes(packet)
    assert psdu.hex() == "41885aaa1a4433665543534354467b6e705f3135347d8355"
    fields = np.concatenate((
        np.zeros(4, dtype=np.uint8),
        np.array((0xA7, len(psdu)), dtype=np.uint8),
        np.frombuffer(psdu, dtype=np.uint8),
    ))
    # Explicit bit unpack/pack models the LSB-first PHY octet transmission.
    ppdu = np.packbits(
        np.unpackbits(fields, bitorder="little"), bitorder="little"
    ).tobytes()
    return ppdu, psdu


def _accept_or_declared(function, error, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except error as exc:
        assert type(exc) is error
        return None
    except BaseException as exc:  # pragma: no cover - contract assertion
        pytest.fail(f"{function.__name__} leaked {type(exc).__name__}: {exc}")


def test_ble_numpy_waveform_matches_scapy_and_recovers_exact_advertisement():
    wire, pdu, oracle_crc = _ble_vector()
    assert _ble_numpy_whiten(_ble_numpy_whiten(pdu + oracle_crc, 37), 37) == pdu + oracle_crc
    assert ble.ble_whiten(pdu + oracle_crc, 37) == wire[5:]
    assert ble.ble_crc24(pdu) == oracle_crc

    report = ble.decode_advertising_phy(wire, 37)
    assert report["pdu"] == pdu
    assert report["crc"] == oracle_crc
    assert report["access_address"] == "0x8e89bed6"
    decoded = report["advertising"]
    assert decoded["pdu_name"] == "ADV_IND"
    assert decoded["advertiser"] == "02:11:22:33:44:55"
    assert decoded["advertising_data"] == [
        {"type": 1, "name": "flags", "raw": b"\x06", "flags": 6},
        {"type": 9, "name": "complete_name", "raw": b"CSCTF{np_ble}",
         "text": "CSCTF{np_ble}"},
    ]


def test_ieee_numpy_ppdu_matches_scapy_fcs_and_recovers_exact_mac():
    ppdu, psdu = _ieee_vector()
    assert _fcs_reference(psdu[:-2]) == psdu[-2:]
    assert ieee.ieee802154_fcs(psdu[:-2]) == psdu[-2:]
    psdu_report = ieee.decode_psdu(psdu)
    ppdu_report = ieee.decode_ppdu(ppdu)
    assert psdu_report == ppdu_report["psdu"]
    assert ppdu_report["psdu_length"] == len(psdu)
    decoded = psdu_report["decoded"]
    assert decoded["sequence"] == 0x5A
    assert decoded["destination_pan"] == "0x1aaa"
    assert decoded["destination"] == "0x3344"
    assert decoded["source"] == "0x5566"
    assert decoded["mac_payload"] == b"CSCTF{np_154}"


def test_ble_every_public_parser_fail_closed_fuzz_and_oversize(tmp_path, capsys):
    wire, pdu, _ = _ble_vector()
    rng = random.Random(0xB1E154)
    bit_flips = []
    for position in (0, 1, 5, len(wire) // 2, len(wire) - 1):
        changed = bytearray(wire)
        changed[position] ^= 1
        bit_flips.append(bytes(changed))
    corpus = [b"", b"\xff" * 32, rng.randbytes(97), wire[:4], wire[:-1],
              wire + b"x", b"x" * (ble.MAX_FRAME + 1), *bit_flips]
    for value in corpus:
        _accept_or_declared(ble.decode_advertising_phy, ble.RF2BLEError, value, 37)
        _accept_or_declared(ble.ble_crc24, ble.RF2BLEError, value)
        _accept_or_declared(ble.ble_whiten, ble.RF2BLEError, value, 37)
    for value in (None, bytearray(pdu), memoryview(pdu), {}, 1):
        _accept_or_declared(ble.ble_crc24, ble.RF2BLEError, value)
        _accept_or_declared(ble.ble_whiten, ble.RF2BLEError, value, 37)
        _accept_or_declared(ble.decode_advertising_phy, ble.RF2BLEError, value, 37)
    for channel in (-1, 0, 36, 40, True, None, "37"):
        _accept_or_declared(ble.ble_whiten, ble.RF2BLEError, pdu, channel)
        _accept_or_declared(ble.decode_advertising_phy, ble.RF2BLEError, wire, channel)

    path = tmp_path / "adv.bin"
    path.write_bytes(wire)
    assert ble.main([str(path), "--channel", "37"]) == 0
    assert json.loads(capsys.readouterr().out)["crc_ok"] is True
    oversized = tmp_path / "adv-big.bin"
    oversized.write_bytes(b"x" * (ble.MAX_FRAME + 1))
    assert ble.main([str(oversized), "--channel", "37"]) == 2
    capsys.readouterr()
    assert ble.main(["--help"]) == 0
    capsys.readouterr()
    assert ble.main([]) == 2
    capsys.readouterr()


def test_ieee_every_public_parser_fail_closed_fuzz_and_oversize(tmp_path, capsys):
    ppdu, psdu = _ieee_vector()
    rng = random.Random(0x154B1E)
    bit_flips = []
    for position in (0, 4, 5, 6, len(ppdu) // 2, len(ppdu) - 1):
        changed = bytearray(ppdu)
        changed[position] ^= 1
        bit_flips.append(bytes(changed))
    corpus = [b"", b"\xff" * 16, rng.randbytes(113), ppdu[:6], ppdu[:-1],
              ppdu + b"x", b"x" * (ieee.MAX_PPDU + 1), *bit_flips]
    for value in corpus:
        _accept_or_declared(ieee.decode_ppdu, ieee.RF2IEEE802154Error, value)
        _accept_or_declared(ieee.decode_psdu, ieee.RF2IEEE802154Error, value)
        _accept_or_declared(ieee.ieee802154_fcs, ieee.RF2IEEE802154Error, value)
    for value in (None, bytearray(psdu), memoryview(psdu), {}, 1):
        _accept_or_declared(ieee.decode_ppdu, ieee.RF2IEEE802154Error, value)
        _accept_or_declared(ieee.decode_psdu, ieee.RF2IEEE802154Error, value)
        _accept_or_declared(ieee.ieee802154_fcs, ieee.RF2IEEE802154Error, value)

    path = tmp_path / "frame.ppdu"
    path.write_bytes(ppdu)
    assert ieee.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["psdu"]["fcs_ok"] is True
    oversized = tmp_path / "frame-big.ppdu"
    oversized.write_bytes(b"x" * (ieee.MAX_PPDU + 1))
    assert ieee.main([str(oversized)]) == 2
    capsys.readouterr()
    assert ieee.main(["--help"]) == 0
    capsys.readouterr()
    assert ieee.main([]) == 2
    capsys.readouterr()
