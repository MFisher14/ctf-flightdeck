"""EUROCONTROL/libasterix vector locks for sec_airsurv_asterix."""

from __future__ import annotations

import json
import random

from asterix.base import Bits, RawDatablock
import asterix.generated as generated
import pytest

from sec_airsurv_asterix import (
    AirSurvAsterixError,
    CATEGORY_PROFILES,
    MAX_STREAM,
    decode_block,
    decode_record,
    decode_stream,
    main,
    parse_fspec,
)


ORACLE_CLASSES = {
    4: generated.Cat_004_1_13,
    10: generated.Cat_010_1_1,
    21: generated.Cat_021_2_7,
    23: generated.Cat_023_1_3,
    34: generated.Cat_034_1_29,
    48: generated.Cat_048_1_32,
    62: generated.Cat_062_1_21,
    240: generated.Cat_240_1_3,
}

# Hand-built directly from the cited edition UAPs: CAT/LEN, literal FSPEC,
# and independently scaled field bytes.  libasterix validates every fixture.
SPEC_FIXTURES = {
    4: "04000AD0010207004000",
    10: "0A0012D801020100400020000000C0000000",
    21: "1500138D100102004000200000C00000A1B2C3",
    23: "17000BD801020100400004",
    34: "22000AE0010201004000",
    48: "30000DD0010200400001004000",
    62: "3E001198010200400000800000FF000000",
    240: "F0000DD0010201055241444152",
}


def _oracle_record_count(block: bytes) -> int:
    """Decode with libasterix 0.36.3, not with the engine under test."""
    raw_blocks = RawDatablock.parse(Bits.from_bytes(block))
    assert not isinstance(raw_blocks, ValueError)
    assert len(raw_blocks) == 1
    raw = raw_blocks[0]
    oracle = ORACLE_CLASSES[raw.get_category()].cv_uap.parse(raw.get_raw_records())
    assert not isinstance(oracle, ValueError)
    return len(oracle)


def _item(block: dict, item_name: str) -> dict:
    return next(item for item in block["records"][0]["items"] if item["item"] == item_name)


@pytest.mark.parametrize("category", sorted(SPEC_FIXTURES))
def test_each_requested_category_is_accepted_by_independent_libasterix(category):
    block = bytes.fromhex(SPEC_FIXTURES[category])
    assert _oracle_record_count(block) == 1
    decoded = decode_block(block)
    assert decoded["category"] == category
    assert decoded["record_count"] == 1
    assert decoded["edition"] == CATEGORY_PROFILES[category].edition


def test_category_semantics_from_documented_layouts():
    cat004 = decode_block(bytes.fromhex(SPEC_FIXTURES[4]))
    assert _item(cat004, "I004/000")["message_type_name"] == "short_term_conflict_alert"
    assert _item(cat004, "I004/020")["time_seconds"] == 128.0

    cat010 = decode_block(bytes.fromhex(SPEC_FIXTURES[10]))
    assert _item(cat010, "I010/041")["latitude_deg"] == 45.0
    assert _item(cat010, "I010/041")["longitude_deg"] == -90.0

    cat021 = decode_block(bytes.fromhex(SPEC_FIXTURES[21]))
    assert _item(cat021, "I021/130")["latitude_deg"] == 45.0
    assert _item(cat021, "I021/130")["longitude_deg"] == -90.0
    assert _item(cat021, "I021/080")["aircraft_address"] == "A1B2C3"

    cat023 = decode_block(bytes.fromhex(SPEC_FIXTURES[23]))
    assert _item(cat023, "I023/000")["message_type_name"] == "ground_station_status"
    assert _item(cat023, "I023/100")["spo"] is True
    assert _item(cat023, "I023/100")["nogo"] is False

    cat034 = decode_block(bytes.fromhex(SPEC_FIXTURES[34]))
    assert _item(cat034, "I034/000")["message_type_name"] == "north_marker"
    assert _item(cat034, "I034/030")["time_seconds"] == 128.0

    cat048 = decode_block(bytes.fromhex(SPEC_FIXTURES[48]))
    assert _item(cat048, "I048/040")["range_nm"] == 1.0
    assert _item(cat048, "I048/040")["azimuth_deg"] == 90.0

    cat062 = decode_block(bytes.fromhex(SPEC_FIXTURES[62]))
    assert _item(cat062, "I062/105")["latitude_deg"] == 45.0
    assert _item(cat062, "I062/105")["longitude_deg"] == -90.0

    cat240 = decode_block(bytes.fromhex(SPEC_FIXTURES[240]))
    assert _item(cat240, "I240/030")["summary"] == "RADAR"
    assert _item(cat240, "I240/030")["repetitions"] == 5


def test_published_libasterix_cat048_vector_exact_values():
    # libasterix README's published CAT048 1.32 sample block.
    block = bytes.fromhex("30000C9801020A0020000FFF")
    assert _oracle_record_count(block) == 1
    decoded = decode_block(block)
    assert _item(decoded, "I048/040")["range_nm"] == 10.0
    assert _item(decoded, "I048/040")["azimuth_deg"] == 45.0
    assert _item(decoded, "I048/070")["mode_3a"] == "7777"
    assert _item(decoded, "I048/070")["validated"] is True


def test_published_libasterix_stream_and_blocking_semantics():
    # Four exact blocks from the libasterix README.
    stream = bytes.fromhex(
        "220007C0010201"
        "220008D001020200"
        "30000C9801020A0020000FFF"
        "220008D001020220"
    )
    decoded = decode_stream(stream)
    assert [block["category"] for block in decoded] == [34, 34, 48, 34]
    assert _item(decoded[1], "I034/020")["sector_angle_deg"] == 0.0
    assert _item(decoded[3], "I034/020")["sector_angle_deg"] == 45.0

    # Same two CAT034 records placed into one legal blocking data block.
    blocked = bytes.fromhex("22000CC0010201D001020220")
    assert _oracle_record_count(blocked) == 2
    result = decode_block(blocked)
    assert result["record_count"] == 2
    assert result["records"][0]["items"][1]["message_type_name"] == "north_marker"
    assert result["records"][1]["items"][2]["sector_angle_deg"] == 45.0


def test_fspec_bit_model_and_record_entrypoint():
    # First extent: FRN1 + FX; second extent: FRN8, then terminate.
    assert parse_fspec(b"\x81\x80trailing") == {
        "frns": [1, 8],
        "raw_hex": "8180",
        "length": 2,
        "next_offset": 2,
    }
    record = bytes.fromhex("E0010201004000")
    decoded = decode_record(34, record)
    assert decoded["frns"] == [1, 2, 3]
    assert decoded["next_offset"] == len(record)
    assert decoded["items"][2]["time_seconds"] == 128.0


def _only_declared(call):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 - verifies the public exception contract
        assert type(exc) is AirSurvAsterixError


def test_fail_closed_malformed_and_seeded_fuzz():
    malformed = [None, "", b"", bytearray(b"x"), object(), 1, True]
    for value in malformed:
        _only_declared(lambda value=value: parse_fspec(value))
        _only_declared(lambda value=value: decode_record(48, value))
        _only_declared(lambda value=value: decode_block(value))
        _only_declared(lambda value=value: decode_stream(value))

    for data in (
        b"\x30\x00",                         # partial header
        b"\x30\x00\x04",                    # no record
        b"\x30\x00\x05\x00\x00",           # empty FSPEC
        b"\x30\x00\x06\x20\x01\x01",       # unterminated FX item
        b"\x3e\x00\x04\x40",                # spare CAT062 FRN2
        b"\x30\x00\x04\x02",                # unsupported CAT048 compound FRN7
        b"\x30\x00\x05\x80\x01",            # truncated fixed DSI
        b"\xf0\x00\x05\x10\x00",            # invalid zero repetition is valid record, trailing split
    ):
        _only_declared(lambda data=data: decode_block(data))

    with pytest.raises(AirSurvAsterixError):
        parse_fspec(b"\x01" * 9)
    with pytest.raises(AirSurvAsterixError):
        decode_stream(b"x" * (MAX_STREAM + 1))
    with pytest.raises(AirSurvAsterixError):
        decode_block(b"x" * 65_536)

    rng = random.Random(0xA57E_2026)
    for _ in range(400):
        data = rng.randbytes(rng.randrange(1, 96))
        offset = rng.randrange(len(data))
        _only_declared(lambda data=data, offset=offset: parse_fspec(data, offset))
        for category in ORACLE_CLASSES:
            _only_declared(
                lambda data=data, offset=offset, category=category:
                decode_record(category, data, offset)
            )
        _only_declared(lambda data=data: decode_block(data))
        _only_declared(lambda data=data: decode_stream(data))


def test_cli_guard_and_offline_file_decode(tmp_path, capsys):
    assert main([]) == 2
    capture = tmp_path / "radar.ast"
    capture.write_bytes(bytes.fromhex(SPEC_FIXTURES[240]))
    assert main([str(capture), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result[0]["category"] == 240
    assert result[0]["records"][0]["items"][2]["summary"] == "RADAR"

