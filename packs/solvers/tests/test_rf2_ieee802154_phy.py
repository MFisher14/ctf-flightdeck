"""Published PPDU/FCS vectors and synthetic Zigbee framing tests."""
from __future__ import annotations

import json
import random

import pytest

import rf2_ieee802154_phy as phy


IEEE_ACK_MAC = bytes.fromhex("02006a")
IEEE_ACK_FCS = bytes.fromhex("e479")
IEEE_ACK_PPDU = bytes.fromhex("00000000a70502006ae479")


def ref_fcs(data: bytes) -> bytes:
    """Independent bitwise reflected x^16+x^12+x^5+1 reference."""
    crc = 0
    for octet in data:
        for bit in range(8):
            feedback = (crc ^ (octet >> bit)) & 1
            crc >>= 1
            if feedback:
                crc ^= 0x8408
    return crc.to_bytes(2, "little")


def clean(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except phy.RF2IEEE802154Error:
        return None
    except BaseException as exc:
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


def synthetic_zigbee_mac() -> bytes:
    # IEEE 802.15.4-2006 data, PAN compression, short destination/source.
    mac_fcf = 0x9841
    nwk = (bytes.fromhex("4800") + bytes.fromhex("34127856") +
           bytes((0x1E, 0x2A)) + b"CSCTF{rf2_zigbee}")
    return (mac_fcf.to_bytes(2, "little") + b"\x5a" +
            bytes.fromhex("aa1a44336655") + nwk)


def test_ieee_published_ack_ppdu_and_crc_vector():
    assert ref_fcs(IEEE_ACK_MAC) == IEEE_ACK_FCS
    assert phy.ieee802154_fcs(IEEE_ACK_MAC) == IEEE_ACK_FCS
    report = phy.decode_ppdu(IEEE_ACK_PPDU)
    assert report["preamble"] == bytes(4) and report["sfd"] == 0xA7
    assert report["psdu_length"] == 5
    assert report["psdu"]["fcs_ok"] is True
    decoded = report["psdu"]["decoded"]
    assert decoded["frame_type"] == "ack" and decoded["sequence"] == 0x6A


def test_crc_kermit_check_value_and_synthetic_zigbee_stack():
    assert ref_fcs(b"123456789") == bytes.fromhex("8921")
    assert phy.ieee802154_fcs(b"123456789") == bytes.fromhex("8921")
    mac = synthetic_zigbee_mac()
    psdu = mac + ref_fcs(mac)
    ppdu = bytes(4) + b"\xa7" + bytes((len(psdu),)) + psdu
    report = phy.decode_ppdu(ppdu)
    decoded = report["psdu"]["decoded"]
    assert decoded["destination_pan"] == "0x1aaa"
    assert decoded["destination"] == "0x3344"
    assert decoded["source"] == "0x5566"
    nwk = decoded["zigbee"]
    assert nwk["destination"] == "0x1234" and nwk["source"] == "0x5678"
    assert nwk["radius"] == 0x1E and nwk["sequence"] == 0x2A
    assert nwk["nwk_payload"] == b"CSCTF{rf2_zigbee}"


def test_fcs_length_sync_and_reserved_bits_fail_closed():
    variants = [
        b"", IEEE_ACK_PPDU[:-1], b"\x01" + IEEE_ACK_PPDU[1:],
        IEEE_ACK_PPDU[:4] + b"\x00" + IEEE_ACK_PPDU[5:],
        IEEE_ACK_PPDU[:5] + b"\x85" + IEEE_ACK_PPDU[6:],
        IEEE_ACK_PPDU[:5] + b"\x06" + IEEE_ACK_PPDU[6:],
        IEEE_ACK_PPDU + b"x", b"x" * (phy.MAX_PPDU + 1),
    ]
    for raw in variants:
        clean(phy.decode_ppdu, raw)
    damaged = bytearray(IEEE_ACK_PPDU)
    damaged[-1] ^= 0x80
    with pytest.raises(phy.RF2IEEE802154Error, match="FCS"):
        phy.decode_ppdu(bytes(damaged))
    for bad in (None, bytearray(b"x"), {}, [], object()):
        clean(phy.decode_ppdu, bad)
        clean(phy.decode_psdu, bad)
        clean(phy.ieee802154_fcs, bad)


def test_random_fuzz_bounds_and_guarded_cli(tmp_path, capsys):
    rng = random.Random(0x154F)
    for size in range(140):
        raw = rng.randbytes(size)
        clean(phy.decode_ppdu, raw)
        clean(phy.decode_psdu, raw)
    path = tmp_path / "ack.ppdu"
    path.write_bytes(IEEE_ACK_PPDU)
    assert phy.main([str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["psdu"]["fcs_ok"] is True
    assert phy.main(["--help"]) == 0
    capsys.readouterr()
    assert phy.main([]) == 2

