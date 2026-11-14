"""Deterministic tests for the offline RFID/NFC depth engine."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import rfid_nfc_depth as rfid  # noqa: E402


def access_bytes(conditions: list[int]) -> bytes:
    assert len(conditions) == 4
    b6 = b7 = b8 = 0
    for block, condition in enumerate(conditions):
        c1, c2, c3 = (condition >> 2) & 1, (condition >> 1) & 1, condition & 1
        b6 |= (c1 ^ 1) << block
        b6 |= (c2 ^ 1) << (4 + block)
        b7 |= c1 << (4 + block)
        b7 |= (c3 ^ 1) << block
        b8 |= c2 << block
        b8 |= c3 << (4 + block)
    return bytes((b6, b7, b8))


def value_block(value: int, address: int) -> bytes:
    encoded = value.to_bytes(4, "little", signed=True)
    return encoded + bytes(byte ^ 0xFF for byte in encoded) + encoded + bytes((address, address ^ 0xFF, address, address ^ 0xFF))


def test_mifare_access_redundancy_default_and_mixed_conditions() -> None:
    default = rfid.decode_mifare_access_bits(bytes.fromhex("ff0780"))
    assert default["valid"]
    assert [row["condition"] for row in default["blocks"]] == ["000", "000", "000", "001"]
    mixed = rfid.decode_mifare_access_bits(access_bytes([0, 2, 6, 3]))
    assert mixed["valid"]
    assert mixed["blocks"][1]["rights"]["write"] == "never"
    assert mixed["blocks"][2]["rights"]["increment"] == "B"
    assert mixed["blocks"][3]["rights"]["access_write"] == "B"
    damaged = bytearray(access_bytes([0, 0, 0, 1])); damaged[0] ^= 1
    assert not rfid.decode_mifare_access_bits(damaged)["valid"]


def test_mifare_value_and_complete_1k_sector_geometry() -> None:
    block = value_block(-123456, 9)
    parsed = rfid.parse_mifare_value_block(block)
    assert parsed == {
        "value": -123456, "value_unsigned": (1 << 32) - 123456, "address": 9,
        "value_redundancy_valid": True, "address_redundancy_valid": True,
        "valid": True, "raw": block.hex(),
    }
    corrupt = bytearray(block); corrupt[7] ^= 1
    assert not rfid.parse_mifare_value_block(corrupt)["valid"]

    dump = bytearray(1024)
    uid = bytes.fromhex("deadbeef")
    dump[:5] = uid + bytes([uid[0] ^ uid[1] ^ uid[2] ^ uid[3]])
    dump[16:32] = value_block(1337, 1)
    for sector in range(16):
        trailer = bytearray.fromhex("ffffffffffff00000069ffffffffffff")
        trailer[6:9] = bytes.fromhex("ff0780")
        dump[(sector * 4 + 3) * 16:(sector * 4 + 4) * 16] = trailer
    report = rfid.parse_mifare_classic_dump(bytes(dump))
    assert report["uid"] == "DEADBEEF" and report["bcc_valid"]
    assert report["sector_count"] == 16 and report["block_count"] == 64
    assert report["sectors"][0]["data_blocks"][1]["value_block"]["value"] == 1337
    assert all(sector["access"]["valid"] for sector in report["sectors"])


def test_mifare_4k_large_sector_layout_and_geometry_rejection() -> None:
    dump = bytearray(4096)
    for sector in range(32):
        dump[(sector * 4 + 3) * 16 + 6:(sector * 4 + 3) * 16 + 9] = bytes.fromhex("ff0780")
    for sector in range(32, 40):
        trailer = 128 + (sector - 32) * 16 + 15
        dump[trailer * 16 + 6:trailer * 16 + 9] = bytes.fromhex("ff0780")
    report = rfid.parse_mifare_classic_dump(dump)
    assert report["sector_count"] == 40
    assert report["sectors"][31]["block_count"] == 4
    assert report["sectors"][32]["block_count"] == 16
    with pytest.raises(rfid.RFIDParseError, match="geometry"):
        rfid.parse_mifare_classic_dump(b"\0" * (129 * 16))


def test_desfire_file_settings_commands_responses_and_trace() -> None:
    standard = bytes((0, 3, 0x12, 0x34)) + (0x1234).to_bytes(3, "little")
    settings = rfid.parse_desfire_file_settings(standard)
    assert settings["file_size"] == 0x1234
    assert settings["access_rights"] == {"read_write": 1, "change": 2, "read": 3, "write": 4}
    record = bytes((3, 0, 0xEE, 0xEE)) + (8).to_bytes(3, "little") + (20).to_bytes(3, "little") + (4).to_bytes(3, "little")
    assert rfid.parse_desfire_file_settings(record)["current_records"] == 4
    value = bytes((2, 1, 0, 0)) + struct.pack("<iiiB", -5, 500, 10, 1)
    assert rfid.parse_desfire_file_settings(value)["lower_limit"] == -5

    select = bytes.fromhex("905a00000333221100")
    write_body = bytes((7,)) + (2).to_bytes(3, "little") + (3).to_bytes(3, "little") + b"ABC"
    write = bytes((0x90, 0x3D, 0, 0, len(write_body))) + write_body + b"\0"
    trace = rfid.analyze_desfire_trace([select, bytes.fromhex("9100"), write, bytes.fromhex("91af")])
    assert trace["selected_application"] == "112233"
    assert trace["operations"][0] == {"index": 2, "application": "112233", "operation": "WRITE_DATA", "file_id": 7, "payload": "414243"}
    assert trace["records"][3]["status_name"] == "additional-frame"
    bad_write = bytearray(write)
    bad_write[9:12] = (4).to_bytes(3, "little")
    with pytest.raises(rfid.RFIDParseError, match="length mismatch"):
        rfid.parse_desfire_apdu(bad_write)
    # Auto direction must prefer a structurally valid command even when its last data octet is
    # 0x91 immediately before Le.
    ending_91 = bytes.fromhex("903d000008010000000100009100")
    assert rfid.parse_desfire_apdu(ending_91)["direction"] == "command"
    read_with_trailing = bytes.fromhex("90bd00000801000001000000aa00")
    with pytest.raises(rfid.RFIDParseError, match="trailing"):
        rfid.parse_desfire_apdu(read_with_trailing)


def test_desfire_neutral_dump_records_preserve_apps_files_and_flags() -> None:
    def tlv(tag: int, value: bytes) -> bytes:
        return bytes((tag,)) + len(value).to_bytes(2, "little") + value
    settings = bytes((4, 0, 0xEE, 0xEE)) + (4).to_bytes(3, "little") + (8).to_bytes(3, "little") + (2).to_bytes(3, "little")
    artifact = tlv(0xA0, bytes.fromhex("030201")) + tlv(0xF0, b"\x05" + settings) + tlv(0xF2, b"\x05\x01\0\0CSCTF{record}")
    report = rfid.parse_desfire_dump_records(artifact)
    assert report["applications"] == ["010203"]
    assert report["records"][1]["settings"]["max_records"] == 8
    assert report["records"][2]["offset"] == 1
    assert report["records"][2]["flags"] == ["CSCTF{record}"]


def uri_ndef(uri: str) -> bytes:
    payload = b"\x04" + uri.encode()
    return bytes((0xD1, 1, len(payload))) + b"U" + payload


def test_ndef_short_long_text_uri_nested_and_strict_end() -> None:
    uri = uri_ndef("example.test/x")
    assert rfid.parse_ndef_message(uri)[0]["uri"] == "https://example.test/x"
    text_payload = b"\x02enCSCTF{text}"
    text = bytes((0xD1, 1, len(text_payload))) + b"T" + text_payload
    parsed = rfid.parse_ndef_message(text)[0]
    assert parsed["language"] == "en" and parsed["text"] == "CSCTF{text}"
    assert parsed["flags"] == ["CSCTF{text}"]
    smart = bytes((0xD1, 2, len(uri))) + b"Sp" + uri
    assert rfid.parse_ndef_message(smart)[0]["nested_records"][0]["uri"].endswith("example.test/x")
    long_payload = b"x" * 300
    long_record = bytes((0xC2, 10)) + len(long_payload).to_bytes(4, "big") + b"text/plain" + long_payload
    assert len(rfid.parse_ndef_message(long_record)[0]["payload"]) == 600
    full_uri = b"\x04chunked.example/CSCTF{chunk}"
    first_payload, last_payload = full_uri[:10], full_uri[10:]
    first_chunk = bytes((0xB1, 1, len(first_payload))) + b"U" + first_payload
    final_chunk = bytes((0x56, 0, len(last_payload))) + last_payload
    chunks = rfid.parse_ndef_message(first_chunk + final_chunk)
    assert chunks[0]["reassembled_record"]["uri"] == "https://chunked.example/CSCTF{chunk}"
    assert chunks[1]["completes_chunk_of"] == 0
    with pytest.raises(rfid.RFIDParseError, match="orphan"):
        rfid.parse_ndef_message(bytes((0xD6, 0, 1)) + b"X")
    with pytest.raises(rfid.RFIDParseError, match="trailing"):
        rfid.parse_ndef_message(uri + b"X")


def test_ntag_tlv_extended_lengths_config_locks_and_dump() -> None:
    pages = bytearray(45 * 4)
    pages[0:4] = bytes.fromhex("041122bf")
    pages[4:8] = bytes.fromhex("33445566")
    pages[8:12] = bytes.fromhex("44880000")
    pages[12:16] = bytes.fromhex("e1101200")
    message = uri_ndef("ctf.local/CSCTF{ntag}")
    user = b"\0" + bytes((3, len(message))) + message + b"\xfe"
    pages[16:16 + len(user)] = user
    pages[40 * 4:40 * 4 + 4] = bytes.fromhex("56341200")
    pages[41 * 4:45 * 4] = bytes.fromhex("90001004 82000000 01020304 aabb0000")
    report = rfid.parse_ntag_dump(pages)
    assert report["model"] == "NTAG213"
    assert report["bcc0_valid"] and report["bcc1_valid"]
    assert report["dynamic_lock_bits"] == 0x123456
    assert report["configuration"]["auth0"] == 4
    assert report["configuration"]["protect_reads"]
    ndef = next(row for row in report["tlvs"] if row["kind"] == "ndef")
    assert ndef["ndef"][0]["uri"].endswith("CSCTF{ntag}")
    assert ndef["flags"] == ["CSCTF{ntag}"]
    extended = b"\x03\xff\x01\x00" + bytes((0xC2, 1)) + (249).to_bytes(4, "big") + b"x" + b"A" * 249 + b"\xfe"
    assert rfid.parse_ntag_tlvs(extended)[0]["length"] == 256
    with pytest.raises(rfid.RFIDParseError, match="magic"):
        rfid.parse_ntag_dump(bytes(45 * 4))


def em4100(identifier: int) -> str:
    body = f"{identifier:040b}"
    nibbles = [body[index:index + 4] for index in range(0, 40, 4)]
    rows = "".join(nibble + str(nibble.count("1") & 1) for nibble in nibbles)
    columns = "".join(str(sum(int(nibble[col]) for nibble in nibbles) & 1) for col in range(4))
    return "1" * 9 + rows + columns + "0"


def wiegand(facility: int, card: int, width: int = 26) -> str:
    if width == 26:
        body = f"{facility:08b}{card:016b}"
    else:
        body = f"{facility:016b}{card:016b}"
    half = len(body) // 2
    return str(body[:half].count("1") & 1) + body + str(1 ^ (body[half:].count("1") & 1))


def test_em4100_parity_search_inversion_and_hid_formats() -> None:
    frame = em4100(0x123456789A)
    parsed = rfid.parse_em4100_frame(frame)
    assert parsed["valid"] and parsed["identifier_hex"] == "123456789A"
    damaged = frame[:20] + ("0" if frame[20] == "1" else "1") + frame[21:]
    assert not rfid.parse_em4100_frame(damaged)["parity_valid"]
    inverted = "".join("1" if bit == "0" else "0" for bit in frame)
    found = rfid.find_em4100_frames("000" + inverted)
    assert found[0]["offset"] == 3 and found[0]["inverted"]

    h26 = rfid.parse_hid_wiegand(wiegand(0x42, 0x1234))
    assert h26["valid"] and (h26["facility_code"], h26["card_number"]) == (0x42, 0x1234)
    h34 = rfid.parse_hid_wiegand(wiegand(0xBEEF, 0xCAFE, 34))
    assert h34["valid"] and h34["format"] == "H10306-34" and h34["facility_code"] == 0xBEEF
    scanned = rfid.find_hid_wiegand_frames("10101" + wiegand(0x42, 0x1234) + "001", widths=(26,))
    assert any(row["offset"] == 5 and row["facility_code"] == 0x42 for row in scanned)


def test_bounded_malformed_inputs_and_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    parsers = [rfid.parse_mifare_value_block, rfid.parse_desfire_file_settings,
               rfid.parse_desfire_apdu, rfid.parse_ndef_message]
    for parser_index, parser in enumerate(parsers):
        for length in range(33):
            value = bytes(((index * 31 + length + parser_index) & 0xFF for index in range(length)))
            try:
                parser(value)
            except (rfid.RFIDParseError, ValueError, TypeError):
                pass
    artifact = tmp_path / "tag.bits"
    artifact.write_text(wiegand(7, 99), encoding="ascii")
    assert rfid.main(["hid", str(artifact)]) == 0
    assert json.loads(capsys.readouterr().out)["card_number"] == 99
    with pytest.raises(rfid.RFIDParseError):
        rfid.parse_hid_wiegand("2" * 26)
