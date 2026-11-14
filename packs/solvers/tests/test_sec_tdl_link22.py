"""Independent public-layout vectors and fail-closed tests for sec_tdl_link22."""
from __future__ import annotations

import json
import random

import pytest

import sec_tdl_link22 as engine


# MIL-STD-2045-47001D w/Change 1, Appendix B, Table B-I, octets 0..24.
# This is copied from the published standard, not produced by the engine.
VMF_D_TABLE_B_I = bytes.fromhex(
    "e3 67 00 80 55 67 92 1a fc 77 00 00 00 80 f8 63 "
    "44 48 10 fe b6 9b 01 00 00"
)


# Public JREAP application/J-series diagrams, laid out independently in network
# bit order: HT=3, MT=1; TTR=1, spare=0, AP=1; block length=27;
# sender=0x1234; accuracy=4, DVT=0x0123456; then the fig. 9.9 envelope.
JREAP_MT1_VECTOR = bytes.fromhex(
    "31 81 00 1b 12 34 40 12 34 56 "
    "23 45 00 07 80 05 00 01 00 01 02 03 04 05 06 07 08"
)


def _assert_closed(call, *args, **kwargs):
    """A fuzz case may decode or reject, but must never leak another exception."""
    try:
        call(*args, **kwargs)
    except engine.SecTdlLink22Error:
        return
    except Exception as exc:  # pragma: no cover - assertion reports a regression
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


def test_link22_public_series_indicator_tree_in_both_container_packings():
    # NILE's public decision tree is SI=0 unique F; SI=1,PMI=0 packed J;
    # SI=1,PMI=1 reserved.  These fixtures place logical bit zero explicitly.
    msb = bytes.fromhex("00" + "00" * 8 + "80" + "00" * 8 + "c0" + "00" * 8)
    result = engine.parse_link22_words(msb, "msb0")
    assert [word["kind"] for word in result["words"]] == [
        "unique_f_series", "packed_j_series", "reserved"
    ]
    assert [word["series_indicator"] for word in result["words"]] == [0, 1, 1]
    assert result["words"][0]["opaque_payload_bit_count"] == 71
    assert result["words"][1]["opaque_payload_bit_count"] == 70

    lsb = bytes.fromhex("00" + "00" * 8 + "01" + "00" * 8 + "03" + "00" * 8)
    result = engine.parse_link22_words(lsb, "lsb0")
    assert [word["kind"] for word in result["words"]] == [
        "unique_f_series", "packed_j_series", "reserved"
    ]
    assert result["words"][1]["opaque_payload_bits"] == "0" * 70


def test_link22_packed_j_common_header_has_locked_nonzero_orientation():
    # Logical J word value 0xEC4 is independently assembled from WF=0,
    # label=17, sublabel=5, MLI=3.  In an msb0 TMW, SI/PMI plus its LSB-first
    # logical payload produce the literal first octets 88 dc.
    word = bytes.fromhex("88 dc 00 00 00 00 00 00 00")
    decoded = engine.parse_link22_words(word, "msb0")["words"][0]
    assert decoded["kind"] == "packed_j_series"
    assert decoded["j_series_common_header"] == {
        "value_hex": "000000000000000ec4",
        "word_format": 0,
        "word_kind": "initial",
        "label": 17,
        "sublabel": 5,
        "message": "J17.5",
        "message_length_indicator": 3,
    }


def test_link22_public_message_word_count_is_one_through_eight():
    assert engine.parse_link22_words(b"\0" * 9)["word_count"] == 1
    assert engine.parse_link22_words(b"\0" * 72)["word_count"] == 8
    for bad in (b"", b"\0" * 8, b"\0" * 73, b"\0" * 81):
        with pytest.raises(engine.SecTdlLink22Error):
            engine.parse_link22_words(bad)


def test_observed_network_cycle_is_normalized_not_claimed_as_wire_decode():
    observations = [
        {"timestamp": 10.0, "unit": "A"},
        {"timestamp": 15.0, "unit": "A"},
        {"timestamp": 20.0, "unit": "A"},
        {"timestamp": 12.5, "unit": "B"},
        {"timestamp": 17.5, "unit": "B"},
        {"timestamp": 22.5, "unit": "B"},
    ]
    result = engine.analyze_network_cycle(observations)
    assert result["time_origin"] == 10.0
    assert result["inferred_cycle_seconds"] == 5.0
    assert result["maximum_absolute_jitter_seconds"] == 0.0
    assert result["units"][1]["normalized_timestamps"] == [2.5, 7.5, 12.5]
    assert result["wire_layout_decoded"] is False


def test_vmf_official_appendix_b_vector_and_dfi_dui_identity():
    result = engine.parse_vmf_header_prefix(VMF_D_TABLE_B_I)
    assert result["header_version"] == 3
    assert result["originators"] == [{"urn": 207, "unit_name": "UNITA"}]
    assert result["recipients"] == [{"urn": 3}]
    assert result["information_addressees"] == []
    assert result["user_data_message_format"] == 2
    assert result["vmf_identification"] == {
        "fad": 15,
        "functional_area": "undefined",
        "message_number": 99,
        "message": "K15.99",
        "message_subtype": None,
    }
    keyed = {field["name"]: field for field in result["dfi_dui_fields"]}
    assert (keyed["HEADER VERSION"]["dfi"], keyed["HEADER VERSION"]["dui"]) == (6001, 6)
    assert (keyed["USER DATA MESSAGE FORMAT"]["dfi"],
            keyed["USER DATA MESSAGE FORMAT"]["dui"]) == (6001, 12)
    assert (keyed["FUNCTIONAL AREA DESIGNATOR"]["dfi"],
            keyed["FUNCTIONAL AREA DESIGNATOR"]["dui"]) == (4081, 1)
    assert (keyed["MESSAGE NUMBER"]["dfi"], keyed["MESSAGE NUMBER"]["dui"]) == (4085, 19)
    assert result["prefix_bits_consumed"] == 128
    assert result["mil_std_6017_body_decoded"] is False
    by_name = {field["name"]: field for field in result["dfi_dui_fields"]}
    assert (by_name["Originator Address GPI"]["dfi"],
            by_name["Originator Address GPI"]["dui"]) == (4014, 1)
    assert (by_name["Originator URN"]["dfi"],
            by_name["Originator URN"]["dui"]) == (4004, 12)
    assert by_name["Originator Unit Name"]["value"] == "UNITA"
    assert (by_name["Originator Unit Name"]["dfi"],
            by_name["Originator Unit Name"]["dui"]) == (6010, 13)
    assert (by_name["HEADER SIZE FPI"]["dfi"],
            by_name["HEADER SIZE FPI"]["dui"]) == (4014, 2)
    assert (by_name["User Data Message Handling GRI"]["dfi"],
            by_name["User Data Message Handling GRI"]["dui"]) == (4045, 1)


def test_jreap_public_10_byte_header_and_mt1_envelope_vector():
    result = engine.parse_jreap_c_block(JREAP_MT1_VECTOR)
    assert result["header_type"] == 3
    assert result["message_type"] == 1
    assert result["transmission_time_reference"] is True
    assert result["application_protocol_version"] == 1
    assert result["application_block_length"] == 27
    assert result["sender_id"] == 0x1234
    assert result["time_accuracy_code"] == 4
    assert result["time_accuracy_milliseconds"] == 8
    assert result["data_valid_time_seconds"] == 0x0123456
    assert result["j_series"] == {
        "source_track_number": 0x2345,
        "message_sequence_number": 7,
        "r_flag": True,
        "a_flag": False,
        "data_age": 5,
        "word_count": 1,
        "words_hex": ["000102030405060708"],
    }


def test_jreap_tcp_stream_uses_declared_block_lengths():
    result = engine.parse_jreap_c_stream(JREAP_MT1_VECTOR * 2)
    assert result["block_count"] == 2
    assert [block["stream_offset"] for block in result["blocks"]] == [0, 27]
    with pytest.raises(engine.SecTdlLink22Error):
        engine.parse_jreap_c_stream(JREAP_MT1_VECTOR + JREAP_MT1_VECTOR[:-1])


def test_jreap_one_application_block_can_hold_multiple_same_type_messages():
    first = JREAP_MT1_VECTOR[10:]
    second = bytes.fromhex(
        "34 56 00 08 80 06 00 01 09 0a 0b 0c 0d 0e 0f 10 11"
    )
    block = bytearray(JREAP_MT1_VECTOR[:10] + first + second)
    block[2:4] = len(block).to_bytes(2, "big")
    result = engine.parse_jreap_c_block(block)
    assert result["application_block_length"] == 44
    assert result["j_series_message_count"] == 2
    assert [message["payload_offset"] for message in result["j_series_messages"]] == [0, 17]
    assert [message["source_track_number"] for message in result["j_series_messages"]] == [
        0x2345, 0x3456
    ]
    assert result["j_series_messages"][1]["words_hex"] == ["090a0b0c0d0e0f1011"]


def test_resource_bounds_cover_multidimensional_views_and_nonfinite_cycles():
    oversized = memoryview(bytearray(engine.MAX_INPUT + 1)).cast(
        "B", shape=[1, engine.MAX_INPUT + 1]
    )
    assert len(oversized) == 1 and oversized.nbytes == engine.MAX_INPUT + 1
    with pytest.raises(engine.SecTdlLink22Error, match="exceeds"):
        engine.parse_vmf_header_prefix(oversized)

    with pytest.raises(engine.SecTdlLink22Error, match="not finite"):
        engine.analyze_network_cycle([
            {"timestamp": 0.0, "unit": "A"},
            {"timestamp": 1e308, "unit": "A"},
            {"timestamp": 0.0, "unit": "B"},
            {"timestamp": 1e308, "unit": "B"},
        ])


def test_every_parser_fails_closed_under_truncation_flip_random_and_oversize():
    rng = random.Random(0x55223011)

    link_cases = [b"", *(bytes(rng.getrandbits(8) for _ in range(n)) for n in range(1, 82))]
    for value in link_cases:
        _assert_closed(engine.parse_link22_words, value, rng.choice(("msb0", "lsb0")))

    for end in range(len(VMF_D_TABLE_B_I) + 1):
        _assert_closed(engine.parse_vmf_header_prefix, VMF_D_TABLE_B_I[:end])
    for bit in range(8):
        changed = bytearray(VMF_D_TABLE_B_I)
        changed[0] ^= 1 << bit
        _assert_closed(engine.parse_vmf_header_prefix, changed)
    _assert_closed(engine.parse_vmf_header_prefix, b"\0" * (engine.MAX_INPUT + 1))

    for end in range(len(JREAP_MT1_VECTOR) + 1):
        _assert_closed(engine.parse_jreap_c_block, JREAP_MT1_VECTOR[:end])
        _assert_closed(engine.parse_jreap_c_stream, JREAP_MT1_VECTOR[:end])
    for index in range(len(JREAP_MT1_VECTOR)):
        changed = bytearray(JREAP_MT1_VECTOR)
        changed[index] ^= 1 << (index % 8)
        _assert_closed(engine.parse_jreap_c_block, changed)
    _assert_closed(engine.parse_jreap_c_block, b"\0" * 65536)

    bad_cycles = [None, {}, [], [None, None], [{"timestamp": 0, "unit": "A"}]]
    for value in bad_cycles:
        _assert_closed(engine.analyze_network_cycle, value)


def test_guarded_cli_contract_and_offline_modes(tmp_path, capsys):
    assert engine.main(["--help"]) == 0
    assert engine.main([]) == 2
    assert engine.main(["not-a-mode"]) == 2
    assert engine.main(["link22", "\0"]) == 2
    assert engine.main(["link22", str(tmp_path / "missing.bin")]) == 2
    capsys.readouterr()

    word_file = tmp_path / "word.bin"
    word_file.write_bytes(b"\x80" + b"\0" * 8)
    assert engine.main(["link22", str(word_file), "--packing", "msb0"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["words"][0]["kind"] == "packed_j_series"

    jreap_file = tmp_path / "jreap.bin"
    jreap_file.write_bytes(JREAP_MT1_VECTOR)
    assert engine.main(["jreap", str(jreap_file)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["j_series"]["source_track_number"] == 0x2345

    vmf_file = tmp_path / "header.vmf"
    vmf_file.write_bytes(VMF_D_TABLE_B_I)
    assert engine.main(["vmf", str(vmf_file)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["vmf_identification"]["message"] == "K15.99"

    cycle_file = tmp_path / "cycle.json"
    cycle_file.write_text(json.dumps({"observations": [
        {"timestamp": 1, "unit": "A"},
        {"timestamp": 6, "unit": "A"},
    ]}), encoding="utf-8")
    assert engine.main(["cycle", str(cycle_file)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["inferred_cycle_seconds"] == 5.0


def test_documented_controlled_boundary_and_unresolved_slcp():
    assert "SLCP" in engine.__doc__
    link = engine.parse_link22_words(b"\0" * 9)
    assert link["current_message_body_standard_controlled"] is True
    jreap = engine.parse_jreap_c_block(JREAP_MT1_VECTOR)
    assert jreap["current_mil_std_3011e_controlled"] is True
