"""Independent vectors and fail-closed checks for sec_airsurv_modes."""

from __future__ import annotations

import json
import random

import pyModeS
import pytest

from sec_airsurv_modes import (
    AirSurvModesError,
    MAX_SWIM_BYTES,
    decode_adsb_me,
    decode_arinc429,
    decode_bds_register,
    decode_modes_frame,
    main,
    parse_swim_artifact,
)


def _pymodes_payload(payload_hex: str, df: int = 20) -> dict:
    """Real-library oracle, with an explicit ICAO to avoid AP ambiguity."""
    return dict(pyModeS.decode(payload=payload_hex, df=df, icao="ABCDEF"))


@pytest.mark.parametrize(
    ("register", "payload_hex", "mapping"),
    [
        (
            "1,0",
            "10010080F50000",
            {
                "config": "config",
                "acas_operational": "acas_operational",
                "mode_s_specific_services": "mode_s_specific_services",
                "acas_rtca_version": "acas_rtca_version",
                "dte_status": "dte_status",
            },
        ),
        (
            "4,0",
            "BE860D30A801C6",
            {
                "selected_altitude_mcp_ft": "selected_altitude_mcp",
                "selected_altitude_fms_ft": "selected_altitude_fms",
                "barometric_pressure_mbar": "baro_pressure_setting",
                "vnav_mode": "vnav_mode",
                "altitude_hold_mode": "altitude_hold_mode",
                "approach_mode": "approach_mode",
                "target_altitude_source": "target_altitude_source",
            },
        ),
        (
            "5,0",
            "F81C01387E04E6",
            {
                "roll_deg": "roll",
                "true_track_deg": "true_track",
                "ground_speed_kt": "groundspeed",
                "track_angle_rate_deg_s": "track_rate",
                "true_airspeed_kt": "true_airspeed",
            },
        ),
        (
            "6,0",
            "F00A032DBFFC00",
            {
                "magnetic_heading_deg": "magnetic_heading",
                "indicated_airspeed_kt": "indicated_airspeed",
                "mach": "mach",
                "barometric_vertical_rate_ft_min": "baro_vertical_rate",
                "inertial_vertical_rate_ft_min": "inertial_vertical_rate",
            },
        ),
    ],
)
def test_bds_vectors_match_pymodes(register, payload_hex, mapping):
    decoded = decode_bds_register(bytes.fromhex(payload_hex), register)
    oracle = _pymodes_payload(payload_hex)
    assert oracle["bds"] == register
    for ours, theirs in mapping.items():
        assert decoded[ours] == pytest.approx(oracle[theirs])


def test_comm_b_full_frames_address_parity_and_payload_match_pymodes():
    # Public pyModeS/Mode-S sample: self-identifying BDS 1,0 in DF20.
    bds10_hex = "A000178D10010080F50000D5893C"
    ours10 = decode_modes_frame(bytes.fromhex(bds10_hex))
    oracle10 = dict(pyModeS.decode(bds10_hex))
    assert ours10["df"] == oracle10["df"] == 20
    assert ours10["icao_candidate_if_address_parity"] == oracle10["icao"] == "8BDCDB"
    assert ours10["icao_verified"] is False
    assert ours10["bds"] == oracle10["bds"] == "1,0"
    assert ours10["mb"]["acas_operational"] == oracle10["acas_operational"]

    # Published DF21 Comm-B sample; selector is supplied because it is uplink-only.
    bds60_hex = "A8000D9FA55A032DBFFC000D8123"
    ours60 = decode_modes_frame(bytes.fromhex(bds60_hex), "6,0")
    oracle60 = dict(pyModeS.decode(bds60_hex))
    assert ours60["icao_candidate_if_address_parity"] == oracle60["icao"] == "406674"
    assert ours60["squawk"] == oracle60["squawk"] == "5667"
    assert ours60["mb"]["magnetic_heading_deg"] == pytest.approx(
        oracle60["magnetic_heading"]
    )
    assert ours60["mb"]["mach"] == pytest.approx(oracle60["mach"])


@pytest.mark.parametrize(
    ("register", "frame_hex", "icao", "field", "expected"),
    [
        ("4,0", "A8001EBCAEE57730A80106DE1344", "48548E",
         "selected_altitude_mcp_ft", 24000),
        ("5,0", "A80006ACF9363D3BBF9CE98F1E1D", "4008B4",
         "true_track_deg", 140.2734375),
        ("6,0", "A80004AAA74A072BFDEFC1D5CB4F", "4CA53F",
         "barometric_vertical_rate_ft_min", -2144),
    ],
)
def test_1090mhz_riddle_published_ehs_frames(register, frame_hex, icao, field, expected):
    """Examples published with the BDS 4,0/5,0/6,0 field tables."""
    ours = decode_modes_frame(bytes.fromhex(frame_hex), register)
    oracle = dict(pyModeS.decode(frame_hex))
    assert ours["icao_candidate_if_address_parity"] == oracle["icao"] == icao
    assert ours["bds"] == oracle["bds"] == register
    assert ours["mb"][field] == pytest.approx(expected)


def test_comm_b_does_not_guess_non_identifying_bds():
    frame = bytes.fromhex("A8000D9FA55A032DBFFC000D8123")
    decoded = decode_modes_frame(frame)
    assert decoded["bds"] is None
    assert "interrogation" in decoded["bds_note"]


@pytest.mark.parametrize(
    "frame_hex",
    [
        "8D4840D6202CC371C32CE0576098",  # callsign KLM1023
        "8D485020994409940838175B284F",  # airborne velocity
        "8D40621D58C382D690C8AC2863A7",  # even CPR position
        "8D40621D58C386435CC412692AD6",  # odd CPR position
    ],
)
def test_published_adsb_frames_match_pymodes(frame_hex):
    ours = decode_modes_frame(bytes.fromhex(frame_hex))
    oracle = dict(pyModeS.decode(frame_hex))
    assert ours["df"] == oracle["df"] == 17
    assert ours["icao"] == oracle["icao"]
    assert ours["crc_ok"] is True
    assert ours["type_code"] == oracle["typecode"]
    if "callsign" in oracle:
        assert ours["callsign"] == oracle["callsign"]
    if oracle.get("typecode") == 19:
        assert ours["me"]["ground_speed_kt"] == oracle["groundspeed"]
        assert ours["me"]["track_deg"] == pytest.approx(oracle["track"])
        assert ours["me"]["vertical_rate_ft_min"] == oracle["vertical_rate"]
        assert ours["me"]["gnss_minus_baro_ft"] == oracle["geo_minus_baro"]


def test_df18_uses_control_field_not_df17_capability_name():
    # Spec-packed DF18/CF2 identification frame; literal parity was calculated
    # with generator 0x1FFF409 and is independently accepted by pyModeS.
    frame_hex = "92A1B2C3202CC371C32CE01464BF"
    oracle = dict(pyModeS.decode(frame_hex))
    ours = decode_modes_frame(bytes.fromhex(frame_hex))
    assert oracle["df"] == ours["df"] == 18
    assert oracle["crc_valid"] is ours["crc_ok"] is True
    assert ours["control_field"] == 2
    assert "capability" not in ours
    assert ours["callsign"] == oracle["callsign"] == "KLM1023"


def _pack_me(fields: list[tuple[int, int, int]]) -> bytes:
    """Reference packer from published one-based ME bit positions."""
    value = 0
    for start, end, field in fields:
        assert 1 <= start <= end <= 56
        assert 0 <= field < (1 << (end - start + 1))
        value |= field << (56 - end)
    return value.to_bytes(7, "big")


@pytest.mark.parametrize(
    ("payload", "expected_hex", "checks"),
    [
        (
            _pack_me([(1, 5, 28), (6, 8, 1), (9, 11, 3), (12, 24, 0x808)]),
            "E1680800000000",
            {"emergency_state": 3, "squawk": "1200"},
        ),
        (
            _pack_me(
                [
                    (1, 5, 29), (6, 7, 1), (8, 8, 1), (9, 9, 1),
                    (10, 20, 1001), (21, 29, 267), (30, 30, 1), (31, 39, 128),
                    (40, 43, 9), (44, 44, 1), (45, 46, 2), (47, 47, 1),
                    (48, 48, 1), (49, 49, 1), (52, 52, 1), (53, 53, 1), (54, 54, 1),
                ]
            ),
            "EBBE985D013B9C",
            {"selected_altitude": 32000, "selected_heading": 90.0, "nac_p": 9},
        ),
        (
            _pack_me(
                [
                    (1, 5, 31), (6, 8, 0), (9, 24, 0x1234), (25, 40, 0x5678),
                    (41, 43, 2), (44, 44, 1), (45, 48, 9), (49, 50, 2),
                    (51, 52, 3), (53, 53, 1), (54, 54, 1), (55, 55, 1),
                ]
            ),
            "F81234567859BE",
            {"version": 2, "capability_class": 0x1234, "sil_supplement": 1},
        ),
    ],
)
def test_adsb_v2_me_reference_layout_matches_pymodes(payload, expected_hex, checks):
    assert payload.hex().upper() == expected_hex
    ours = decode_adsb_me(payload)
    oracle = dict(pyModeS.decode(payload=payload.hex(), df=17, icao="ABCDEF"))
    for oracle_name, expected in checks.items():
        assert oracle[oracle_name] == pytest.approx(expected)
    if ours["type_code"] == 28:
        assert ours["emergency_state"] == oracle["emergency_state"]
        assert ours["squawk"] == oracle["squawk"]
    elif ours["type_code"] == 29:
        assert ours["selected_altitude_ft"] == oracle["selected_altitude"]
        assert ours["selected_heading_deg"] == pytest.approx(oracle["selected_heading"])
        assert ours["nac_p"] == oracle["nac_p"]
    else:
        assert ours["adsb_version"] == oracle["version"]
        assert ours["capability_class"] == oracle["capability_class"]
        assert ours["sil_supplement"] == oracle["sil_supplement"]


def test_crc_valid_published_adsb_v2_operational_status_subfields():
    frame = bytes.fromhex("8DABCDEFF83320220059BA77D4D4")
    ours = decode_modes_frame(frame)
    oracle = dict(pyModeS.decode(frame.hex()))
    assert ours["crc_ok"] is True
    assert ours["me"]["adsb_version"] == oracle["version"] == 2
    assert ours["me"]["capability_class"] == oracle["capability_class"] == 0x3320
    assert ours["me"]["operational_mode"] == oracle["operational_mode"] == 0x2200
    assert ours["me"]["tcas_operational"] is True
    assert ours["me"]["es1090_in"] is True
    assert ours["me"]["air_referenced_velocity_report"] is True
    assert ours["me"]["target_state_report"] is True
    assert ours["me"]["resolution_advisory_active"] is True
    assert ours["me"]["system_design_assurance"] == 2
    assert ours["me"]["sil_supplement"] == 1


@pytest.mark.parametrize(
    ("frame_hex", "typecode", "checks"),
    [
        (
            "8DABCDEFE1A80800000000B0DF0D",
            28,
            {"emergency_state": 5, "squawk": "1200"},
        ),
        (
            "8DABCDEFEBBE985F013B9C489AB7",
            29,
            {"selected_altitude_ft": 32000, "selected_heading_deg": 270.0, "nac_p": 9},
        ),
    ],
)
def test_crc_valid_adsb_v2_status_frames(frame_hex, typecode, checks):
    ours = decode_modes_frame(bytes.fromhex(frame_hex))
    oracle = dict(pyModeS.decode(frame_hex))
    assert ours["crc_ok"] is oracle["crc_valid"] is True
    assert ours["me"]["type_code"] == oracle["typecode"] == typecode
    for key, expected in checks.items():
        if isinstance(expected, str):
            assert ours["me"][key] == expected
        else:
            assert ours["me"][key] == pytest.approx(expected)


def test_arinc429_published_layout_label_and_odd_parity():
    # Hand-packed ARINC bits: wire label reverse8(0o203)=0xC1, SDI=2,
    # data=32000, BNR SSM=3, odd parity.  The manufacturer table names 203.
    decoded = decode_arinc429(bytes.fromhex("c102f4e1"), byteorder="little")
    assert decoded == {
        "protocol": "arinc-429",
        "word_hex": "E1F402C1",
        "byteorder": "little",
        "label_packing": "wire",
        "label_raw_hex": "C1",
        "label": 0o203,
        "label_octal": "203",
        "label_description": "pressure_altitude",
        "sdi": 2,
        "data_raw": 32000,
        "ssm": 3,
        "ssm_bnr": "normal_operation",
        "ssm_bcd": "minus_south_west_left_from_below",
        "parity_bit": 1,
        "parity": "odd",
        "parity_ok": True,
    }
    assert decode_arinc429(0xE1F40283, label_packing="normalized")["label_octal"] == "203"
    with pytest.raises(AirSurvModesError):
        decode_arinc429(0xE1F402C0)
    assert decode_arinc429(0xE1F402C0, strict_parity=False)["parity_ok"] is False


def test_bounded_swim_fixm_xml_and_iwxxm_json_artifacts():
    xml = b"""<?xml version='1.0'?>
    <fixm:Flight xmlns:fixm='http://www.fixm.aero/flight/4.3'>
      <fixm:SWIMDataPublishedTS>2026-11-05T12:00:00Z</fixm:SWIMDataPublishedTS>
      <fixm:aircraftIdentification>CSCTF01</fixm:aircraftIdentification>
    </fixm:Flight>"""
    decoded_xml = parse_swim_artifact(xml)
    assert decoded_xml["format"] == "xml"
    assert decoded_xml["root"] == "Flight"
    assert decoded_xml["models"] == ["FIXM"]
    assert decoded_xml["metadata_present"] == ["SWIMDataPublishedTS"]

    artifact = {
        "SWIMProducerInstanceID": "offline-fixture",
        "SWIMProducerInstanceMsgSeqNum": 7,
        "payload": {"model": "IWXXM", "METAR": "LROP"},
    }
    decoded_json = parse_swim_artifact(json.dumps(artifact).encode())
    assert decoded_json["format"] == "json"
    assert decoded_json["models"] == ["IWXXM"]
    assert decoded_json["metadata_present"] == [
        "SWIMProducerInstanceID",
        "SWIMProducerInstanceMsgSeqNum",
    ]


def _only_declared(call):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 - this is the contract under test
        assert type(exc) is AirSurvModesError


def test_fail_closed_fuzz_never_leaks_stdlib_exceptions():
    rng = random.Random(0xA12_2026)
    malformed = [None, "", b"", b"\x00", b"\xff" * 6, b"\xff" * 8, object()]
    for value in malformed:
        _only_declared(lambda value=value: decode_bds_register(value, "4,0"))
        _only_declared(lambda value=value: decode_adsb_me(value))
        _only_declared(lambda value=value: decode_modes_frame(value))
        _only_declared(lambda value=value: decode_arinc429(value))
        _only_declared(lambda value=value: parse_swim_artifact(value))

    for _ in range(200):
        payload = rng.randbytes(7)
        frame = rng.randbytes(14)
        word = rng.randbytes(4)
        for register in ("1,0", "4,0", "5,0", "6,0"):
            _only_declared(
                lambda payload=payload, register=register: decode_bds_register(payload, register)
            )
        _only_declared(lambda payload=payload: decode_adsb_me(payload))
        _only_declared(lambda frame=frame: decode_modes_frame(frame))
        _only_declared(lambda word=word: decode_arinc429(word))
        _only_declared(lambda payload=payload: parse_swim_artifact(payload))

    with pytest.raises(AirSurvModesError):
        parse_swim_artifact(b"x" * (MAX_SWIM_BYTES + 1))
    with pytest.raises(AirSurvModesError):
        parse_swim_artifact(b"<!DOCTYPE x [<!ENTITY e 'boom'>]><x>&e;</x>")
    with pytest.raises(AirSurvModesError):
        decode_bds_register(bytes.fromhex("00000000000001"), "4,0")


def test_cli_is_guarded(capsys):
    assert main([]) == 2
    assert main(["bds", "6,0", "F00A032DBFFC00"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["magnetic_heading_deg"] == 315.0
    assert main(["arinc", "00000000"]) == 2

