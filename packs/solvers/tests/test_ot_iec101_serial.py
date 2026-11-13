"""Independent FT1.2 vectors and malformed-input coverage.

Published byte vectors: Beckhoff, IEC 60870-5-101 telegram structure,
https://infosys.beckhoff.com/content/1033/ts650x_tcplc_iec60870-5-10x/11700014987.html
Control oracle: ABB REC523, 1MRS 750956-MUM, tables 1.2.3.1-2/1.2.3.2-2;
balanced DIR/FCB/FCV: lib60870-C src/iec60870/link_layer/link_layer.c.
Additional width/SQ cases use the small independent wire builder below, never
an engine encoder or generated expected output.
"""

import argparse
import random

import pytest

import ot_iec101_serial as iec


BECKHOFF_CONFIG = dict(address_size=2, cot_size=1, common_address_size=2, ioa_size=2)
FIXED_REQUEST = bytes.fromhex("10 49 0C 00 55 16")
FIXED_RESPONSE = bytes.fromhex("10 0B 0C 00 17 16")
COUNTER_REQUEST = bytes.fromhex("68 0B 0B 68 08 0C 00 65 01 0A 0C 00 00 00 05 95 16")
COUNTER_VALUE = bytes.fromhex("68 0F 0F 68 08 0C 00 0F 01 03 0C 00 81 30 DA 16 00 00 07 DB 16")
SCALED_PUBLISHED = bytes.fromhex(
    "68 2B 2B 68 08 0C 00 0B 07 03 0C 00 10 30 BE 09 00 11 30 90 09 00 "
    "0E 30 75 00 00 28 30 25 09 00 29 30 75 00 00 0F 30 0F 0A 00 2E 30 AE 05 00 85 16"
)
# Published erratum: the displayed 43 body bytes sum to 1414 (0x586), so the
# checksum must be 0x86, not the printed 0x85. Preserve both fixtures explicitly.
SCALED_VALUES = SCALED_PUBLISHED[:-2] + b"\x86\x16"


def wire_variable(asdu, address, width, control=0x08):
    """Reference wire layout from the vendor's table; not an engine round trip."""
    body = bytes([control]) + address.to_bytes(width, "little") + asdu
    checksum = 0
    for octet in body:
        checksum = (checksum + octet) % 256
    return b"\x68" + bytes([len(body), len(body)]) + b"\x68" + body + bytes([checksum, 0x16])


@pytest.mark.parametrize("raw,function,primary,checksum", [
    (FIXED_REQUEST, "request_link_status", True, 0x55),
    (FIXED_RESPONSE, "link_status", False, 0x17),
])
def test_published_fixed_frames(raw, function, primary, checksum):
    result = iec.parse_frame(raw, **BECKHOFF_CONFIG)
    assert result["format"] == "fixed"
    assert result["link_address"] == 12
    assert result["checksum"] == checksum
    assert result["checksum_valid"] is True
    assert result["control"]["function"] == function
    assert result["control"]["primary"] is primary


def test_published_counter_request():
    result = iec.parse_frame(COUNTER_REQUEST, **BECKHOFF_CONFIG)
    assert result["checksum"] == 0x95
    asdu = result["asdu"]
    assert asdu["type_id"] == 101
    assert asdu["common_address"] == 12
    assert asdu["originator_address"] is None
    assert asdu["cause"] == 10
    # The vendor example's prose calls 10 confirmation; IEC assigns 7 to
    # confirmation and 10 to termination. Its literal octet is unambiguous.
    assert asdu["cause_name"] == "activation termination"
    assert asdu["information_objects"] == [{"ioa": 0, "raw_hex": "05", "qcc": 5}]


def test_published_integrated_total():
    result = iec.parse_frame(COUNTER_VALUE, **BECKHOFF_CONFIG)
    assert result["checksum"] == 0xdb
    assert result["control"]["function"] == "user_data"
    asdu = result["asdu"]
    assert asdu["type_id"] == 15
    assert asdu["cause"] == 3
    assert asdu["information_objects"] == [
        {"ioa": 12417, "raw_hex": "da16000007", "counter": 5850, "sequence_notation": 7}
    ]


def test_published_seven_scaled_values():
    assert sum(SCALED_PUBLISHED[4:-2]) == 1414
    with pytest.raises(iec.IEC101Error, match="checksum"):
        iec.parse_frame(SCALED_PUBLISHED, **BECKHOFF_CONFIG)
    result = iec.parse_frame(SCALED_VALUES, **BECKHOFF_CONFIG)
    assert result["checksum"] == 0x86
    asdu = result["asdu"]
    assert asdu["num_objects"] == 7
    assert asdu["type_id"] == 11
    assert [(o["ioa"], o["scaled"], o["quality"]) for o in asdu["information_objects"]] == [
        (12304, 2494, 0), (12305, 2448, 0), (12302, 117, 0), (12328, 2341, 0),
        (12329, 117, 0), (12303, 2575, 0), (12334, 1454, 0),
    ]


@pytest.mark.parametrize("address_size,mode", [(0, "balanced"), (1, "balanced"),
                                               (2, "balanced"), (1, "unbalanced"), (2, "unbalanced")])
@pytest.mark.parametrize("cot_size", [1, 2])
@pytest.mark.parametrize("common_address_size", [1, 2])
@pytest.mark.parametrize("ioa_size", [1, 2, 3])
@pytest.mark.parametrize("sequential", [False, True])
def test_configured_widths_and_sequential_addresses(address_size, mode, cot_size,
                                                  common_address_size, ioa_size, sequential):
    # Two signed scaled values, an explicit 0x80 quality, and two known IOAs.
    asdu = bytes([11, 0x82 if sequential else 2, 3])
    if cot_size == 2:
        asdu += b"\x07"
    asdu += (23).to_bytes(common_address_size, "little")
    asdu += (0x21).to_bytes(ioa_size, "little") + b"\x2e\xfb\x80"
    if not sequential:
        asdu += (0x22).to_bytes(ioa_size, "little")
    asdu += b"\xff\x7f\x00"
    config = dict(cot_size=cot_size, common_address_size=common_address_size, ioa_size=ioa_size)
    direct = iec.decode_asdu(asdu, **config)
    framed = iec.parse_frame(wire_variable(asdu, 19 if address_size else 0, address_size, 0xf3),
                             address_size=address_size, mode=mode, **config)["asdu"]
    for result in (direct, framed):
        assert result["raw_hex"] == asdu.hex()
        assert result["common_address"] == 23
        assert result["originator_address"] == (7 if cot_size == 2 else None)
        assert result["sq"] == int(sequential)
        assert [(o["ioa"], o["scaled"], o["quality"]) for o in result["information_objects"]] == [
            (33, -1234, 128), (34, 32767, 0)
        ]


def test_control_modes_from_published_bit_layout():
    balanced = iec.decode_control(0xf3, mode="balanced")
    assert balanced["function"] == "user_data_confirmed"
    assert balanced["dir"] is True
    assert balanced["primary"] is True
    assert balanced["fcb"] is True and balanced["fcv"] is True
    assert balanced["acd"] is None and balanced["dfc"] is None
    assert balanced["reserved_bits"] == 0
    secondary = iec.decode_control(0x3b)
    assert secondary["primary"] is False
    assert secondary["acd"] is True and secondary["dfc"] is True
    assert secondary["fcb"] is None and secondary["fcv"] is None
    assert iec.decode_control(0xa0, mode="balanced")["reserved_bits"] == 0x20
    assert iec.decode_control(0xc9)["reserved_bits"] == 0x80
    assert iec.decode_control(0x42, mode="balanced")["function"] == "test_link"
    assert iec.decode_control(0x42)["function"] == "reserved"
    assert iec.decode_control(0x5a)["function"] == "request_class_1"
    assert iec.decode_control(0x5b)["function"] == "request_class_2"
    assert iec.decode_control(0x0e)["function"] == "link_service_not_functioning"


def test_published_single_characters_and_complete_stream_offsets():
    raw = FIXED_REQUEST + b"\xe5\xa2" + COUNTER_VALUE + FIXED_RESPONSE
    results = iec.parse_stream(raw, **BECKHOFF_CONFIG)
    assert [r["offset"] for r in results] == [0, 6, 7, 8, 29]
    assert [r["length"] for r in results] == [6, 1, 1, 21, 6]
    assert results[1]["acknowledgement"] == "positive"
    assert results[2]["acknowledgement"] == "negative"
    assert iec.parse_frame(b"\xe5")["acknowledgement"] == "positive"
    assert iec.parse_stream(b"") == []


def test_zero_width_fixed_and_broadcast_addresses():
    # Control 0xc9 contributes the entire checksum in an addressless frame.
    result = iec.parse_frame(bytes.fromhex("10 c9 c9 16"), address_size=0, mode="balanced")
    assert result["link_address"] is None and result["broadcast"] is False
    assert result["control"]["dir"] is True
    result = iec.parse_frame(bytes.fromhex("10 44 ff 43 16"))
    assert result["link_address"] == 255 and result["broadcast"] is True


def test_unknown_asdu_is_preserved_without_invented_objects():
    asdu = bytes.fromhex("fa 01 03 01 00 43 53 43 54 46 7b 78 7d")
    result = iec.decode_asdu(asdu, cot_size=1, common_address_size=2, ioa_size=2)
    assert result["layout_decoded"] is False
    assert result["information_raw_hex"] == "43534354467b787d"
    assert "information_objects" not in result


@pytest.mark.parametrize("raw", [FIXED_REQUEST, FIXED_RESPONSE, COUNTER_REQUEST, COUNTER_VALUE, SCALED_VALUES])
def test_every_truncation_checksum_corruption_and_trailing_data_rejected(raw):
    for length in range(len(raw)):
        with pytest.raises(iec.IEC101Error):
            iec.parse_frame(raw[:length], **BECKHOFF_CONFIG)
    body_start = 4 if raw[0] == 0x68 else 1
    for position in range(body_start, len(raw) - 2):
        damaged = bytearray(raw)
        damaged[position] ^= 1
        with pytest.raises(iec.IEC101Error, match="checksum"):
            iec.parse_frame(damaged, **BECKHOFF_CONFIG)
    for position in (len(raw) - 2, len(raw) - 1):
        damaged = bytearray(raw)
        damaged[position] ^= 1
        with pytest.raises(iec.IEC101Error):
            iec.parse_frame(damaged, **BECKHOFF_CONFIG)
    with pytest.raises(iec.IEC101Error):
        iec.parse_frame(raw + b"\xe5", **BECKHOFF_CONFIG)
    with pytest.raises(iec.IEC101Error):
        iec.parse_stream(raw + b"\x10", **BECKHOFF_CONFIG)


def test_repeated_length_start_and_malformed_asdu_rejected():
    for position in (1, 2, 3):
        damaged = bytearray(COUNTER_VALUE)
        damaged[position] ^= 1
        with pytest.raises(iec.IEC101Error):
            iec.parse_frame(damaged, **BECKHOFF_CONFIG)
    with pytest.raises(iec.IEC101Error, match="ASDU"):
        iec.parse_frame(bytes.fromhex("68 02 02 68 08 01 09 16"))
    # Correct frame checksum cannot conceal missing/excess object bytes.
    for asdu in (bytes.fromhex("01 01 03 00 01 00 01 00 00"),
                 bytes.fromhex("01 01 03 00 01 00 01 00 00 01 99")):
        with pytest.raises(iec.IEC101Error, match="object count"):
            iec.parse_frame(wire_variable(asdu, 1, 1))
    with pytest.raises(iec.IEC101Error, match="sequential IOA"):
        iec.decode_asdu(bytes.fromhex("01 82 03 01 ff 01 00"), cot_size=1,
                        common_address_size=1, ioa_size=1)


def test_bounds_and_invalid_configuration():
    for kwargs in ({"address_size": 0}, {"address_size": 3}, {"address_size": True},
                   {"mode": []}, {"cot_size": None}, {"common_address_size": "2"},
                   {"ioa_size": 4}):
        with pytest.raises(iec.IEC101Error):
            iec.parse_frame(b"\xe5", **kwargs)
    for limit in (None, 0, -1, True, iec.MAX_FRAMES + 1, "1"):
        with pytest.raises(iec.IEC101Error):
            iec.parse_stream(b"", max_frames=limit)
    with pytest.raises(iec.IEC101Error, match="count limit"):
        iec.parse_stream(b"\xe5\xe5", max_frames=1)
    with pytest.raises(iec.IEC101Error, match="exceeds"):
        iec.parse_stream(b"\xe5" * (iec.MAX_INPUT + 1))
    with pytest.raises(iec.IEC101Error, match="exceeds"):
        iec.decode_asdu(b"\0" * 255)


def test_deterministic_fail_closed_inputs():
    rng = random.Random(60870101)
    inputs = [None, "", "\ud800\x00☃" * 1000, 3, True, {}, [], set(), b"", b"\0" * 65536]
    inputs.extend(bytes(rng.randrange(256) for _ in range(n)) for n in range(0, 270))
    released = memoryview(b"x")
    released.release()
    inputs.append(released)
    for function in (iec.parse_frame, iec.parse_stream, iec.decode_asdu, iec.decode_control):
        for value in inputs:
            try:
                function(value)
            except iec.IEC101Error:
                pass
    assert iec.parse_frame(memoryview(FIXED_REQUEST), **BECKHOFF_CONFIG)["link_address"] == 12


def test_cli_raw_hex_errors_and_guard(tmp_path, capsys, monkeypatch):
    path = tmp_path / "serial.bin"
    path.write_bytes(FIXED_REQUEST)
    assert iec.main([str(path), "--address-size", "2"]) == 0
    assert '"link_address": 12' in capsys.readouterr().out
    path.write_text(COUNTER_REQUEST.hex(), encoding="ascii")
    assert iec.main([str(path), "--hex", "--address-size", "2", "--cot-size", "1", "--ioa-size", "2"]) == 0
    assert '"qcc": 5' in capsys.readouterr().out
    path.write_text("not hex", encoding="ascii")
    assert iec.main([str(path), "--hex"]) == 2
    assert iec.main([str(path / "missing")]) == 2
    assert iec.main([]) == 2
    assert iec.main(["--help"]) == 0
    assert iec.main([None]) == 2
    assert iec.main(["--address-size", "3"]) == 2

    def noninteger_exit(*args, **kwargs):
        raise SystemExit("message")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", noninteger_exit)
    assert iec.main([]) == 2
