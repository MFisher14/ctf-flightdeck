"""Transport semantic tests; expected values do not use engine encoders/tables.

Sources:
* CSS Electronics J1939 tutorial: 0CF00401 / FFFFFF6813FFFFFF = 621 rpm.
* CyberBoat 2024 CAN/J1939/N2K lesson: FF7D7D701200FFFF = 590 rpm.
* CANboat PGN documentation: 129025, 129029, 127250, 126992 layouts.
* Kvaser J1587: byte lengths, extended PIDs, two's-complement checksum.
* Yacht Devices YDES-04 manual: Volvo D12 8054005B005C00BE0000B7.
"""
import random
import struct

import cantools
import pytest

import transport_j1939 as j
import transport_nmea2000 as n


def test_published_eec1_vectors():
    assert j.decode_frame(0x0CF00401, "FFFFFF6813FFFFFF")["spns"]["190"]["value"] == 621
    row = j.decode_frame(0x0CF00400, "FF7D7D701200FFFF")
    assert row["spns"]["190"]["value"] == 590
    assert row["spns"]["512"]["value"] == 0
    assert row["source"] == 0


def test_real_cantools_dbc_oracle():
    # DBC manually transcribed from published EEC1 SPN positions, independent
    # from the engine's table. cantools supplies endian extraction/scaling.
    dbc = '''VERSION ""
NS_ :
BS_:
BU_: Engine
BO_ 256 EEC1: 8 Engine
 SG_ Speed : 24|16@1+ (0.125,0) [0|8031.875] "rpm" Engine
 SG_ Demand : 8|8@1+ (1,-125) [-125|125] "%" Engine
 SG_ Torque : 16|8@1+ (1,-125) [-125|125] "%" Engine
'''
    oracle = cantools.database.load_string(dbc, database_format="dbc")
    for raw in (bytes.fromhex("FF7D7D701200FFFF"), bytes.fromhex("FF1299882200FFFF")):
        truth = oracle.decode_message(256, raw)
        result = j.decode_pgn(61444, raw)["spns"]
        assert result["190"]["value"] == truth["Speed"]
        assert result["512"]["value"] == truth["Demand"]
        assert result["513"]["value"] == truth["Torque"]


def test_j1939_values_and_sentinels():
    assert j.decode_pgn(65265, bytes.fromhex("FF8050FFFFFFFFFF"))["spns"]["84"]["value"] == 80.5
    assert j.decode_pgn(65262, bytes([100]) + bytes(7))["spns"]["110"]["value"] == 60
    assert j.decode_pgn(65253, struct.pack("<II", 100, 3))["spns"]["247"]["value"] == 5
    assert j.decode_pgn(65257, struct.pack("<II", 100, 300))["spns"]["250"]["value"] == 150
    for high, status in [(0xFF, "not_available"), (0xFE, "error"), (0xFB, "reserved")]:
        field = j.decode_pgn(61444, bytes([0, 0, 0, 0, high, 0, 0, 0]))["spns"]["190"]
        assert field["value"] is None
        assert field["status"] == status


def test_name_request_vin():
    # NAME assembled by hand from J1939-81 bit positions.
    value = 12345 | (204 << 21) | (3 << 32) | (17 << 35) | (42 << 40) | (12 << 49) | (2 << 56) | (4 << 60) | (1 << 63)
    result = j.decode_pgn(60928, value.to_bytes(8, "little"))
    assert result["manufacturer_code"] == 204
    assert result["identity_number"] == 12345
    assert result["function"] == 42
    assert result["industry_group"] == 4
    assert result["arbitrary_address_capable"] is True
    assert j.decode_pgn(59904, bytes.fromhex("04f000"))["requested_pgn"] == 61444
    assert j.decode_pgn(65260, b"CSCTF{vin}*")["vehicle_identification"] == "CSCTF{vin}"


def test_saved_tp_vin_reuses_existing_assembler():
    text = "\n".join([
        "can0 18ECFF80#200A0002FFECFE00",
        "can0 18EBFF80#0143534354467B76",
        "can0 18EBFF80#02696E7DFFFFFFFF",
    ])
    result = j.analyze_candump(text)
    assert result["messages"][0]["vehicle_identification"] == "CSCTF{vin}"
    assert result["tp_issues"] == []


def packet(*octets):
    """Independent J1708 additive checksum encoder."""
    return bytes(octets) + bytes([(-sum(octets)) % 256])


def test_j1587_published_volvo_d12():
    result = j.decode_j1587("8054005B005C00BE0000B7")
    assert result["mid"] == 128
    assert [r["pid"] for r in result["parameters"]] == [84, 91, 92, 190]
    assert all(r["unsigned"] == 0 for r in result["parameters"])


def test_j1587_extended_variable_text_signed():
    result = j.decode_j1587(packet(128, 21, 254, 255, 1, 5, 226, 3, 65, 66, 67))
    assert result["parameters"][0]["value"] == -5
    assert result["parameters"][1]["pid"] == 257
    assert result["parameters"][1]["unsigned"] == 5
    assert result["parameters"][2]["text_latin1"] == "ABC"


@pytest.mark.parametrize("raw", [b"", b"\x80", b"\x80\xff\x81", packet(128, 190, 0),
                                    packet(128, 226, 9, 65), packet(128, 254, 0), b"x"*22])
def test_j1587_malformed(raw):
    with pytest.raises(j.TransportJ1939Error):
        j.decode_j1587(raw)


def test_nmea_position_cantools_oracle():
    dbc = '''VERSION ""
NS_ :
BS_:
BU_: GPS
BO_ 257 Position: 8 GPS
 SG_ Latitude : 0|32@1- (0.0000001,0) [-90|90] "deg" GPS
 SG_ Longitude : 32|32@1- (0.0000001,0) [-180|180] "deg" GPS
'''
    oracle = cantools.database.load_string(dbc, database_format="dbc")
    raw = struct.pack("<ii", 481173000, -115166667)
    expected = oracle.decode_message(257, raw)
    result = n.decode_pgn(129025, raw)
    assert result["latitude"] == expected["Latitude"]
    assert result["longitude"] == expected["Longitude"]
    assert n.decode_pgn(129025, struct.pack("<ii", 0x7fffffff, 0x7ffffffe))["latitude"] is None


def gnss_payload():
    # Independent byte encoder transcribed from CANboat's 129029 field widths.
    return struct.pack("<BHIqqqBBBhh i B HH", 4, 20000, 123456789,
                       481173000000000000, -115166666666666666, 545400000,
                       0x10, 0xfc, 8, 90, 120, -3400, 1, (123 << 4) | 1, 250)


def test_nmea_gnss_full_position_and_reference():
    result = n.decode_pgn(129029, gnss_payload())
    assert result["latitude"] == pytest.approx(48.1173)
    assert result["longitude"] == pytest.approx(-11.516666666666666)
    assert result["altitude_m"] == pytest.approx(545.4)
    assert result["unix_time"] == pytest.approx(20000*86400 + 12345.6789)
    assert result["hdop"] == .9
    assert result["method"] == 1
    assert result["reference_stations"] == [{"type": 1, "id": 123, "age_seconds": 2.5}]


def test_nmea_fast_packet_reuses_existing_assembler():
    raw = gnss_payload()
    # Hand-encode documented N2K fast-packet headers, independent of assembler.
    frames = [bytes([0x60, len(raw)]) + raw[:6]]
    for index, pos in enumerate(range(6, len(raw), 7), 1):
        frames.append((bytes([0x60 | index]) + raw[pos:pos+7]).ljust(8, b"\xff"))
    text = "\n".join("can0 0DF80523#" + frame.hex() for frame in frames)
    result = n.analyze_candump(text)
    assert result["messages"][0]["latitude"] == pytest.approx(48.1173)
    assert result["messages"][0]["source"] == 0x23
    assert result["fast_packet_issues"] == []
    incomplete = n.analyze_candump("\n".join(text.splitlines()[:-1]))
    assert incomplete["messages"] == []
    assert incomplete["fast_packet_issues"][0]["kind"] == "incomplete-fast-packet"


def test_other_nmea_pgns():
    result = n.decode_pgn(127250, struct.pack("<BHhhB", 9, 10000, -200, 500, 0xfd))
    assert result["heading_rad"] == 1
    assert result["deviation_rad"] == -.02
    assert result["variation_rad"] == .05
    assert result["reference"] == 1
    result = n.decode_pgn(129026, struct.pack("<BBHHH", 9, 0xfc, 30000, 625, 0xffff))
    assert result["course_rad"] == 3
    assert result["speed_m_s"] == 6.25
    result = n.decode_pgn(126992, struct.pack("<BBHI", 9, 0xf0, 20000, 123456789))
    assert result["unix_time"] == pytest.approx(20000*86400+12345.6789)
    result = n.decode_pgn(127488, struct.pack("<BHHbH", 1, 2400, 1000, -5, 0xffff))
    assert result["engine_speed_rpm"] == 600
    assert result["boost_pressure_pa"] == 100000
    assert result["tilt_trim_percent"] == -5


@pytest.mark.parametrize("pgn,raw", [(129025, b""), (129025, struct.pack("<ii", 910000000, 0)),
                                       (129029, gnss_payload()[:-1]), (129029, gnss_payload()+b"\x00"),
                                       (126992, struct.pack("<BBHI", 1, 0, 1, 900000000)),
                                       (127250, struct.pack("<BHhhB", 1, 64000, 0, 0, 0))])
def test_nmea_malformed(pgn, raw):
    with pytest.raises(n.TransportNMEA2000Error):
        n.decode_pgn(pgn, raw)


@pytest.mark.parametrize("bad", [None, {}, [], object(), -1, True, "zz", "\ud800"])
def test_public_contract(bad):
    for function, args in [(j.decode_pgn, (61444, bad)), (j.decode_name, (bad,)),
                           (j.decode_j1587, (bad,)), (j.analyze_candump, (bad,)),
                           (n.decode_pgn, (129025, bad)), (n.analyze_candump, (bad,))]:
        with pytest.raises((j.TransportJ1939Error, n.TransportNMEA2000Error)):
            function(*args)


def test_deterministic_malformed_bytes_never_leak():
    rng = random.Random(1939)
    for _ in range(150):
        raw = rng.randbytes(rng.randrange(0, 60))
        for function, args, error in [(j.decode_pgn, (61444, raw), j.TransportJ1939Error),
                                       (j.decode_j1587, (raw,), j.TransportJ1939Error),
                                       (n.decode_pgn, (129029, raw), n.TransportNMEA2000Error)]:
            try:
                function(*args)
            except error:
                pass


def test_cli_guard_and_missing(tmp_path):
    for module in (j, n):
        assert module.main([]) == 2
        assert module.main(["--help"]) == 0
        assert module.main([str(tmp_path / "absent")]) == 2
        assert module.main(["bad\x00path"]) == 2
    source = tmp_path / "can.log"
    source.write_text("can0 0CF00401#FFFFFF6813FFFFFF\n")
    assert j.main([str(source)]) == 0
    source.write_text("can0 09F80101#0000000000000000\n")
    assert n.main([str(source)]) == 0
