"""Independent ETSI/osmo-tetra fixtures for the passive TETRA analyzer."""
from __future__ import annotations

import json
import random

import pytest

import sec_lmr_tetra as tetra


NORMAL_1 = "1101000011101001110100"
NORMAL_2 = "0111101001000011011110"
NORMAL_3 = "1011011100000110101101"
SYNC = "11000001100111001110100111000001100111"
EXTENDED = "100111010000111010011101000011"
FREQ = "1" * 8 + "0" * 64 + "1" * 8


def packed(bits: str) -> bytes:
    """Test-local ETSI MSB-first bit container; never calls an engine encoder."""
    assert bits and set(bits) <= {"0", "1"}
    padded = bits + "0" * (-len(bits) % 8)
    return int(padded, 2).to_bytes(len(padded) // 8, "big")


def put(target: list[str], offset: int, value: str) -> None:
    target[offset:offset + len(value)] = value


def field(value: int, width: int) -> str:
    assert 0 <= value < (1 << width)
    return f"{value:0{width}b}"


def llc_fcs(bits: str) -> int:
    """Direct transcription of EN 300 392-2's MSB-first LLC CRC recurrence."""
    crc = 0xFFFFFFFF
    if len(bits) < 32:
        crc = (crc << (32 - len(bits))) & 0xFFFFFFFF
    for char in bits:
        feedback = int(char) ^ ((crc >> 31) & 1)
        crc = (crc << 1) & 0xFFFFFFFF
        if feedback:
            crc ^= 0x04C11DB7
    return (~crc) & 0xFFFFFFFF


def clean(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except tetra.SecLmrTetraError:
        return None
    except BaseException as exc:  # pragma: no cover - assertion diagnostic
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


def sync_burst() -> str:
    bits = ["0"] * 510
    put(bits, 0, NORMAL_3[10:])
    put(bits, 14, FREQ)
    put(bits, 214, SYNC)
    put(bits, 500, NORMAL_3[:10])
    return "".join(bits)


def normal_burst() -> str:
    bits = ["0"] * 510
    put(bits, 0, NORMAL_3[10:])
    put(bits, 244, NORMAL_1)
    put(bits, 500, NORMAL_3[:10])
    return "".join(bits)


def test_published_sync_and_normal_burst_layouts():
    sync_bits = sync_burst()
    report = tetra.parse_air_burst(packed(sync_bits), 510)
    assert report["burst_type"] == "sb-cont"
    assert report["modulation"] == "pi/4"
    assert report["bit_length"] == 510
    checks = {item["field"]: item for item in report["sequence_checks"]}
    assert checks["sync_training"]["valid"] is True
    assert checks["frequency_correction"]["valid"] is True
    assert report["fields"]["sync_training"]["offset_bits"] == 214
    assert report["fields"]["sync_training"]["length_bits"] == 38

    normal_bits = normal_burst()
    normal = tetra.parse_air_burst(packed(normal_bits), 510)
    assert normal["burst_type"] == "ndb-cont"
    normal_check = next(item for item in normal["sequence_checks"]
                        if item["field"] == "normal_training")
    assert normal_check["variant"] == "normal-1"
    assert normal["fields"]["block_1"]["length_bits"] == 216
    assert normal["fields"]["block_2"]["offset_bits"] == 282


@pytest.mark.parametrize(
    ("kind", "modulation", "length", "training_offset", "training"),
    [
        ("cb", "pi/4", 206, 88, EXTENDED),
        ("nub", "pi/4", 462, 220, NORMAL_2),
        ("cb", "pi/8", 309, 132, "0" * 45),
        ("nub", "pi/8", 693, 330, "0" * 33),
    ],
)
def test_uplink_layout_matrix_is_from_etsi_tables(kind, modulation, length,
                                                   training_offset, training):
    bits = ["0"] * length
    if modulation == "pi/4":
        put(bits, 0, "1100")
        put(bits, length - 4, "1100")
    put(bits, training_offset, training)
    report = tetra.parse_air_burst(
        packed("".join(bits)), length, burst_type=kind, modulation=modulation
    )
    assert report["bit_length"] == length
    assert any(item["offset_bits"] == training_offset for item in report["fields"].values())


@pytest.mark.parametrize(
    ("kind", "modulation", "length", "middle_offset", "middle_name"),
    [
        ("ndb-cont", "pi/8", 739, 353, "normal_training"),
        ("ndb-disc", "pi/4", 492, 234, "normal_training"),
        ("ndb-disc", "pi/8", 721, 343, "normal_training"),
        ("sb-disc", "pi/4", 492, 204, "sync_training"),
    ],
)
def test_remaining_downlink_etsi_layouts(kind, modulation, length,
                                         middle_offset, middle_name):
    bits = ["0"] * length
    continuous = kind.endswith("cont")
    put(bits, 0, NORMAL_3[10:] if continuous else NORMAL_3[20:])
    put(bits, length - (10 if continuous else 2),
        NORMAL_3[:10] if continuous else NORMAL_3[:2])
    if kind.startswith("sb"):
        put(bits, 4, FREQ)
        put(bits, middle_offset, SYNC)
    elif modulation == "pi/4":
        put(bits, middle_offset, NORMAL_1)
    # pi/8 training is a separate 33-bit published sequence; zeros are useful
    # here because the test is for the normative offsets, not classification.
    report = tetra.parse_air_burst(
        packed("".join(bits)), length, burst_type=kind, modulation=modulation
    )
    assert report["fields"][middle_name]["offset_bits"] == middle_offset
    assert report["fields"][middle_name]["length_bits"] == (38 if kind.startswith("sb") else (33 if modulation == "pi/8" else 22))
    assert report["fields"]["block_2"]["length_bits"] in (216, 324)


def test_hand_built_mac_sysinfo_and_resource_headers():
    # TS 100 392-2 table 21.65, pi/4 SYSINFO, exactly 124 decoded bits.
    bits = "".join((
        "10", "00", field(0x321, 12), field(5, 4), field(2, 2), field(3, 3),
        "1", field(2, 2), field(5, 3), field(9, 4), field(6, 4), field(10, 4),
        "1", field(0x1234, 16), field(2, 2), field(0xABCDE, 20),
        field(0x1234, 14), field(0xBEEF, 16), field(0xABC, 12),
    ))
    assert len(bits) == 124
    report = tetra.parse_mac_pdu(packed(bits), 124, direction="downlink", modulation="pi/4")
    assert report["pdu_name"] == "BROADCAST"
    assert report["broadcast_name"] == "SYSINFO"
    system = report["system_information"]
    assert system["main_carrier"] == 0x321
    assert system["mle_system_information"]["location_area"] == 0x1234
    assert system["mle_system_information"]["subscriber_class"] == 0xBEEF
    assert system["mle_system_information"]["base_station_service_details"] == 0xABC

    # MAC-RESOURCE with SSI, clear mode, power control and an eight-bit slot grant.
    resource = "".join((
        "00", "0", "1", "00", "1", field(12, 6), "001", field(0x654321, 24),
        "1", field(9, 4), "1", field(0xA5, 8), "0", "10101",
    ))
    parsed = tetra.parse_mac_pdu(packed(resource), len(resource), direction="downlink")
    assert parsed["pdu_name"] == "MAC-RESOURCE"
    body = parsed["resource"]
    assert body["encryption_mode"] == 0
    assert body["address"]["name"] == "SSI"
    assert body["address"]["ssi"] == 0x654321
    assert body["power_control"] == 9
    assert body["slot_granting"] == {"number_of_slots_code": 10, "delay": 5}


def test_llc_fcs_and_cmce_setup_from_hand_reference():
    payload = "10100110" * 5
    crc = llc_fcs(payload)
    bits = "0100" + "1" + "0" + payload + field(crc, 32)
    report = tetra.parse_llc_pdu(packed(bits), len(bits))
    assert report["pdu_name"] == "BL-ADATA-FCS"
    assert report["receive_sequence"] == 1 and report["send_sequence"] == 0
    assert report["tl_sdu_bits"] == payload
    assert report["fcs_valid"] is True

    setup = "".join((
        "010", field(7, 5), field(0x123, 14), field(7, 4), "1", "0",
        field(0xA5, 8), field(2, 2), "1", field(10, 4), "101",
    ))
    mle = tetra.parse_mle_pdu(packed(setup), len(setup), direction="downlink")
    assert mle["protocol_name"] == "CMCE"
    assert mle["cmce"]["pdu_name"] == "D-SETUP"
    assert mle["cmce"]["setup"]["call_identifier"] == 0x123
    assert mle["cmce"]["setup"]["call_priority"] == 10
    assert mle["cmce"]["optional_or_payload_bits"] == "101"


def test_tea_and_evolution_context_are_non_decrypting():
    expected = {"TEA1": 32, "TEA2": 80, "TEA3": 80, "TEA4": 56}
    for name, strength in expected.items():
        report = tetra.tea_context(name)
        assert report["nominal_cipher_key_bits"] == 80
        assert report["initialization_vector_bits"] == 29
        assert report["effective_key_bits"] == strength
        assert report["iv_components_lsb_indexed"]["direction"]["bit"] == 28
        assert report["iv_components_lsb_indexed"]["frame"]["bits"] == [2, 6]
        assert "key" not in report or report["key"] is None
    evolution = tetra.evolution_context()
    rendered = json.dumps(evolution).upper()
    assert all(term in rendered for term in ("TEDS", "MCX", "25", "150", "5G"))


def test_fail_closed_random_and_guarded_cli(tmp_path, capsys):
    rng = random.Random(0x7E7A)
    public = (
        tetra.parse_air_burst, tetra.parse_mac_pdu,
        tetra.parse_llc_pdu, tetra.parse_mle_pdu,
    )
    for size in range(64):
        blob = rng.randbytes(size)
        for parser in public:
            clean(parser, blob, size * 8 if size else 0)
    for malformed in (None, bytearray(b"x"), memoryview(b"x"), {}, [], "01"):
        for parser in public:
            clean(parser, malformed, 8)
    clean(tetra.tea_context, "TEA9")

    path = tmp_path / "sync.bin"
    path.write_bytes(packed(sync_burst()))
    assert tetra.main(["burst", str(path), "--bits", "510"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["bit_length"] == 510
    assert tetra.main(["--help"]) == 0
    capsys.readouterr()
    assert tetra.main([]) == 2

