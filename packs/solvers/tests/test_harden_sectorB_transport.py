"""Independent vectors and fail-closed fuzz for the sector-B transport parsers.

The expected values below come from published wire/layout semantics, never from
an encoder in the engine under test.  Mutation cases may either return a value
or raise exactly the engine's declared exception, but may not leak a stdlib or
dependency exception.
"""
from __future__ import annotations

import copy
import io
import random
import struct
import zipfile

import pytest

import transport_ais as ais
import transport_cargo as cargo
import transport_edifact as edifact
import transport_gtfs as gtfs
import transport_j1939 as j1939
import transport_nmea0183 as nmea0183
import transport_nmea2000 as nmea2000


def _fail_closed(function, declared_error, cases):
    """Accept a clean return or exactly the parser's documented exception."""

    for label, args in cases:
        try:
            function(*args)
        except declared_error as exc:
            assert type(exc) is declared_error, (
                f"{function.__module__}.{function.__name__} {label} raised "
                f"subclass {type(exc).__name__}"
            )
        except Exception as exc:  # pragma: no cover - this is the failure under test
            pytest.fail(
                f"{function.__module__}.{function.__name__} {label} leaked "
                f"{type(exc).__name__}: {exc}"
            )


def _flip_bytes(value: bytes, index: int = 0) -> bytes:
    changed = bytearray(value)
    changed[index] ^= 0x01
    return bytes(changed)


def _flip_text(value: str, index: int = 0) -> str:
    replacement = "X" if value[index] != "X" else "Y"
    return value[:index] + replacement + value[index + 1:]


def _random_bytes() -> list[bytes]:
    rng = random.Random(0x5EC70B)
    return [rng.randbytes(length) for length in (1, 2, 7, 16, 63)]


def _random_text() -> list[str]:
    rng = random.Random(0x5EC70B ^ 0xA15)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,!$*+#:'? "
    return ["".join(rng.choice(alphabet) for _ in range(length))
            for length in (1, 2, 9, 31, 127)]


def _gtfs_zip() -> bytes:
    """Standard-library ZIP/CSV writer independent of the GTFS reader."""

    tables = {
        "routes.txt": "route_id,route_short_name,route_type\nR1,Blue,3\n",
        "trips.txt": "route_id,service_id,trip_id\nR1,WK,T1\n",
        "stops.txt": "stop_id,stop_name\nS1,Central\nS2,Harbour\n",
        "stop_times.txt": (
            "trip_id,arrival_time,departure_time,stop_id,stop_sequence\n"
            "T1,25:15:00,25:16:00,S2,20\n"
            "T1,24:50:00,24:50:30,S1,10\n"
        ),
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, text in tables.items():
            archive.writestr(name, text)
    return output.getvalue()


GTFS_ZIP = _gtfs_zip()
# Hand-written proto2 wire: FeedMessage.header (field 1), whose FeedHeader
# contains required gtfs_realtime_version (field 1) = UTF-8 string "2.0".
GTFS_RT = bytes.fromhex("0a050a03322e30")


def test_gtfs_documented_schedule_and_protobuf_vectors():
    """GTFS Schedule clock/joins and GTFS-Realtime proto field numbers."""

    feed = gtfs.parse_gtfs_zip(GTFS_ZIP)
    assert feed["tables"]["routes.txt"][0] == {
        "route_id": "R1", "route_short_name": "Blue", "route_type": "3"
    }
    itinerary = gtfs.trip_itinerary(feed, "T1")
    assert [row["stop"]["stop_id"] for row in itinerary["stops"]] == ["S1", "S2"]
    assert itinerary["stops"][1]["arrival_time_seconds"] == 25 * 3600 + 15 * 60
    assert gtfs.service_seconds("123:59:59") == 123 * 3600 + 59 * 60 + 59
    assert gtfs.decode_gtfs_rt(GTFS_RT) == {
        "header": {"gtfs_realtime_version": "2.0"}
    }


def test_gtfs_all_public_entrypoints_fail_closed_under_mutations():
    _fail_closed(gtfs.parse_gtfs_zip, gtfs.TransportGTFSError, [
        ("empty", (b"",)),
        *(("random", (raw,)) for raw in _random_bytes()),
        ("truncated-valid", (GTFS_ZIP[:-7],)),
        ("bit-flipped", (_flip_bytes(GTFS_ZIP),)),
        ("oversized", (b"Z" * (gtfs.MAX_INPUT + 1),)),
        ("wrong-type", (None,)),
    ])
    _fail_closed(gtfs.decode_gtfs_rt, gtfs.TransportGTFSError, [
        ("empty", (b"",)),
        *(("random", (raw,)) for raw in _random_bytes()),
        ("truncated-valid", (GTFS_RT[:-1],)),
        ("bit-flipped", (_flip_bytes(GTFS_RT),)),
        ("oversized", (b"Z" * (gtfs.MAX_INPUT + 1),)),
        ("wrong-type", (None,)),
    ])
    _fail_closed(gtfs.service_seconds, gtfs.TransportGTFSError, [
        ("empty", ("",)),
        *(("random", (text,)) for text in _random_text()),
        ("truncated-valid", ("25:15:0",)),
        ("bit-flipped", ("25:X5:00",)),
        ("oversized", ("1" * 4096,)),
        ("wrong-type", (None,)),
    ])

    feed = gtfs.parse_gtfs_zip(GTFS_ZIP)
    missing_table = copy.deepcopy(feed)
    del missing_table["tables"]["stops.txt"]
    random_feed = {"tables": {"trips.txt": [{"trip_id": object()}]}}
    _fail_closed(gtfs.trip_itinerary, gtfs.TransportGTFSError, [
        ("empty", ({}, "T1")),
        ("random", (random_feed, "T1")),
        ("truncated-valid", (missing_table, "T1")),
        ("bit-flipped", (feed, "U1")),
        ("oversized", (feed, "T" * 100_000)),
        ("wrong-type", (None, "T1")),
    ])


# Published pyais README capture. Expected MMSI and positions are independently
# extracted from ITU-R M.1371 fields: MMSI bits 8..37; lon/lat scale 1/600000.
AIS_CAPTURE = "!AIVDM,1,1,,B,15NG6V0P01G?cFhE`R2IU?wn28R>,0*05"


def test_ais_published_aivdm_vector():
    decoded = ais.parse_ais(AIS_CAPTURE)[0]
    assert decoded["message_type"] == 1
    assert decoded["bit_length"] == 168
    assert decoded["decoded"]["mmsi"] == 367380120
    # pyais exposes six decimal places, still within one 1/600000-degree AIS LSB.
    assert decoded["decoded"]["lat"] == pytest.approx(37.80694833333333, abs=5e-7)
    assert decoded["decoded"]["lon"] == pytest.approx(-122.40433333333333, abs=5e-7)


def test_ais_parse_entrypoint_fail_closed_under_mutations():
    _fail_closed(ais.parse_ais, ais.TransportAISError, [
        ("empty", ("",)),
        *(("random", (text,)) for text in _random_text()),
        ("truncated-valid", (AIS_CAPTURE[:-1],)),
        ("bit-flipped", (AIS_CAPTURE[:-2] + "00",)),
        ("oversized", ("A" * ((16 << 20) + 1),)),
        ("wrong-type", (None,)),
    ])


# Trimble Alloy GLL example with published checksum. Coordinate expectation is
# the NMEA degrees + minutes/60 rule, independent of the parser.
NMEA_GLL = "$GPGLL,3953.88008971,N,10506.75318910,W,034138.00,A,D*7A"


def test_nmea0183_published_trimble_gll_vector():
    out = nmea0183.parse_sentence(NMEA_GLL)
    assert out is not None
    assert out["latitude"] == pytest.approx(39 + 53.88008971 / 60)
    assert out["longitude"] == pytest.approx(-(105 + 6.75318910 / 60))
    assert out["time_utc"] == "03:41:38.00"
    assert out["valid"] is True and out["mode"] == "D"


def test_nmea0183_all_parse_entrypoints_fail_closed_under_mutations():
    single_cases = [
        ("empty", ("",)),
        *(("random", (text,)) for text in _random_text()),
        ("truncated-valid", (NMEA_GLL[:-1],)),
        ("bit-flipped", (NMEA_GLL[:-2] + "00",)),
        ("oversized", ("A" * 1025,)),
        ("wrong-type", (None,)),
    ]
    _fail_closed(nmea0183.parse_sentence, nmea0183.TransportNMEAError, single_cases)
    text_cases = [
        ("empty", ("",)),
        *(("random", (text,)) for text in _random_text()),
        ("truncated-valid", (NMEA_GLL[:-1],)),
        ("bit-flipped", (NMEA_GLL[:-2] + "00",)),
        ("oversized", ("A" * ((16 << 20) + 1),)),
        ("wrong-type", (None,)),
    ]
    _fail_closed(nmea0183.parse_text, nmea0183.TransportNMEAError, text_cases)


N2K_POSITION = struct.pack("<ii", 481_173_000, -115_166_667)
N2K_CANDUMP = "can0 09F80123#" + N2K_POSITION.hex()


def test_nmea2000_canboat_129025_vector():
    """CANboat PGN 129025: signed LE int32 coordinates at 1e-7 degree."""

    out = nmea2000.decode_pgn(129025, N2K_POSITION)
    assert out["latitude"] == pytest.approx(48.1173)
    assert out["longitude"] == pytest.approx(-11.5166667)
    dump = nmea2000.analyze_candump(N2K_CANDUMP)
    assert dump["messages"][0]["source"] == 0x23
    assert dump["messages"][0]["latitude"] == pytest.approx(48.1173)


def test_nmea2000_all_parse_entrypoints_fail_closed_under_mutations():
    _fail_closed(nmea2000.decode_pgn, nmea2000.TransportNMEA2000Error, [
        ("empty", (129025, b"")),
        *(("random", (129025, raw)) for raw in _random_bytes()),
        ("truncated-valid", (129025, N2K_POSITION[:-1])),
        ("bit-flipped", (129025, _flip_bytes(N2K_POSITION))),
        ("oversized", (129025, b"Z" * 224)),
        ("wrong-type", (129025, None)),
    ])
    _fail_closed(nmea2000.analyze_candump, nmea2000.TransportNMEA2000Error, [
        ("empty", ("",)),
        *(("random", (text,)) for text in _random_text()),
        ("truncated-valid", (N2K_CANDUMP[:-1],)),
        ("bit-flipped", (_flip_text(N2K_CANDUMP, N2K_CANDUMP.index("0")),)),
        ("oversized", ("A" * (nmea2000.MAX_FILE + 1),)),
        ("wrong-type", (None,)),
    ])


J1939_EEC1 = bytes.fromhex("FFFFFF6813FFFFFF")
J1939_CAN_ID = 0x0CF00401
J1939_CANDUMP = "can0 0CF00401#FFFFFF6813FFFFFF"
J1587_VOLVO = bytes.fromhex("8054005B005C00BE0000B7")


def test_j1939_published_css_eec1_and_j1587_vectors():
    """CSS EEC1 example: SPN190 raw 0x1368 * 0.125 = 621 rpm."""

    out = j1939.decode_frame(J1939_CAN_ID, J1939_EEC1)
    assert out["pgn"] == 61444 and out["source"] == 1
    assert out["spns"]["190"] == {
        "label": "engine_speed", "raw": 0x1368, "value": 621.0,
        "unit": "rpm", "status": "available",
    }
    assert j1939.decode_pgn(61444, J1939_EEC1)["spns"]["190"]["value"] == 621
    assert j1939.analyze_candump(J1939_CANDUMP)["messages"][0]["spns"]["190"]["value"] == 621

    # Published Yacht Devices Volvo D12 J1587 packet: fixed one-byte PIDs
    # 84, 91, 92 and two-byte PID 190, with two's-complement checksum 0xB7.
    j1587 = j1939.decode_j1587(J1587_VOLVO)
    assert j1587["mid"] == 128
    assert [row["pid"] for row in j1587["parameters"]] == [84, 91, 92, 190]
    assert j1587["checksum_valid"] is True

    # J1939-81 NAME is an explicitly little-endian 64-bit bitfield.
    value = (12345 | (204 << 21) | (42 << 40) | (4 << 60) | (1 << 63))
    name = j1939.decode_name(value.to_bytes(8, "little"))
    assert name["identity_number"] == 12345
    assert name["manufacturer_code"] == 204
    assert name["function"] == 42
    assert name["industry_group"] == 4
    assert name["arbitrary_address_capable"] is True


def test_j1939_all_parse_entrypoints_fail_closed_under_mutations():
    name_seed = (12345 | (204 << 21) | (42 << 40)).to_bytes(8, "little")
    _fail_closed(j1939.decode_name, j1939.TransportJ1939Error, [
        ("empty", (b"",)),
        *(("random", (raw,)) for raw in _random_bytes()),
        ("truncated-valid", (name_seed[:-1],)),
        ("bit-flipped", (_flip_bytes(name_seed),)),
        ("oversized", (b"Z" * 9,)),
        ("wrong-type", (None,)),
    ])
    _fail_closed(j1939.decode_pgn, j1939.TransportJ1939Error, [
        ("empty", (61444, b"")),
        *(("random", (61444, raw)) for raw in _random_bytes()),
        ("truncated-valid", (61444, J1939_EEC1[:-1])),
        ("bit-flipped", (61444, _flip_bytes(J1939_EEC1))),
        ("oversized", (61444, b"Z" * 1786)),
        ("wrong-type", (61444, None)),
    ])
    _fail_closed(j1939.decode_frame, j1939.TransportJ1939Error, [
        ("empty", (J1939_CAN_ID, b"")),
        *(("random", (J1939_CAN_ID, raw)) for raw in _random_bytes()),
        ("truncated-valid", (J1939_CAN_ID, J1939_EEC1[:-1])),
        ("bit-flipped", (J1939_CAN_ID, _flip_bytes(J1939_EEC1))),
        ("oversized", (J1939_CAN_ID, b"Z" * 9)),
        ("wrong-type", (J1939_CAN_ID, None)),
    ])
    _fail_closed(j1939.decode_j1587, j1939.TransportJ1939Error, [
        ("empty", (b"",)),
        *(("random", (raw,)) for raw in _random_bytes()),
        ("truncated-valid", (J1587_VOLVO[:-1],)),
        ("bit-flipped", (_flip_bytes(J1587_VOLVO),)),
        ("oversized", (b"Z" * 22,)),
        ("wrong-type", (None,)),
    ])
    _fail_closed(j1939.analyze_candump, j1939.TransportJ1939Error, [
        ("empty", ("",)),
        *(("random", (text,)) for text in _random_text()),
        ("truncated-valid", (J1939_CANDUMP[:-1],)),
        ("bit-flipped", (_flip_text(J1939_CANDUMP, J1939_CANDUMP.index("F")),)),
        ("oversized", ("A" * (j1939.MAX_FILE + 1),)),
        ("wrong-type", (None,)),
    ])


# GS1 EANCOM 2002 S3 IFTMIN example. The expected control counts and values are
# literal published message semantics, not produced by another local engine.
GS1_IFTMIN = """UNH+ME000001+IFTMIN:D:01B:UN:EAN004'
BGM+610+569952+9'
DTM+137:20020301:102'
DTM+2:200203081100:203'
CNT+11:1'
RFF+CU:TI1284'
TDT+20++30+31'
DTM+133:20020305 1100:203'
LOC+9+5412345678908::9'
NAD+CZ+5412345123453::9'
NAD+CA+5411234512309::9'
NAD+CN+5411234444402::9'
NAD+DP+5412345145660::9'
GID+1+1:09::9+14:PK'
HAN+EAT::9'
TMP+2+000:CEL'
RNG+5+CEL:-5:5'
MOA+44:45000:EUR'
PIA+5+5410738377117:SRV'
MEA+AAE+X7E+KGM:250'
PCI+33E'
GIN+BJ+354123450000000014'
UNT+23+ME000001'"""


def test_edifact_published_gs1_iftmin_vector():
    segments = edifact.parse_segments(GS1_IFTMIN)
    assert len(segments) == 23
    assert segments[0]["tag"] == "UNH" and segments[-1]["tag"] == "UNT"
    out = edifact.analyze(GS1_IFTMIN)
    message = out["messages"][0]
    assert message["type"] == "IFTMIN"
    assert message["reference"] == "ME000001"
    assert message["summary"]["documents"][0]["number"] == "569952"
    assert message["summary"]["transport"][0]["mode"] == "30"
    assert message["summary"]["measurements"][0]["unit"] == "KGM"
    assert message["summary"]["measurements"][0]["value"] == "250"


def test_edifact_all_parse_entrypoints_fail_closed_under_mutations():
    random_blobs = _random_bytes()
    cases = [
        ("empty", (b"",)),
        *(("random", (raw,)) for raw in random_blobs),
        ("truncated-valid", (GS1_IFTMIN[:-1],)),
        ("bit-flipped", (_flip_text(GS1_IFTMIN, GS1_IFTMIN.index("U")),)),
        ("oversized", ("A" * (edifact.MAX_INPUT + 1),)),
        ("wrong-type", (None,)),
    ]
    _fail_closed(edifact.parse_segments, edifact.TransportEdifactError, cases)
    _fail_closed(edifact.analyze, edifact.TransportEdifactError, cases)


def test_cargo_published_awb_modulus_and_iata_uld_vectors():
    """ABF's 1234567 mod-7 vector and IATA 3+5+2 ULD composition."""

    awb = cargo.parse_awb("020-12345675")
    assert awb["serial"] == "1234567"
    assert awb["check_digit"] == 5
    assert awb["checksum_valid"] is True
    assert awb["canonical"] == "020-12345675"
    uld = cargo.parse_uld("AKE12345LH")
    assert (uld["type_code"], uld["serial"], uld["owner_code"]) == (
        "AKE", "12345", "LH"
    )
    assert uld["registry_verified"] is False


def test_cargo_all_parse_entrypoints_fail_closed_under_mutations():
    _fail_closed(cargo.parse_awb, cargo.TransportCargoError, [
        ("empty", ("",)),
        *(("random", (text,)) for text in _random_text()),
        ("truncated-valid", ("020-1234567",)),
        ("bit-flipped", ("020-12345674",)),
        ("oversized", ("A" * 65,)),
        ("wrong-type", (None,)),
    ])
    _fail_closed(cargo.parse_uld, cargo.TransportCargoError, [
        ("empty", ("",)),
        *(("random", (text,)) for text in _random_text()),
        ("truncated-valid", ("AKE12345L",)),
        ("bit-flipped", ("BKE12345LH",)),
        ("oversized", ("A" * 65,)),
        ("wrong-type", (None,)),
    ])

