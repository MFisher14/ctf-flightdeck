"""Independent fixtures for ffgame_cartridge_artifacts.

The N64 layouts are transcribed from tool64, the GBA header/logo and checksum
from GBATEK/devkitPro, and the PICO-8 PNG low-bit mapping from the published
cart format.  No fixture is produced by the engine under test.
"""

from __future__ import annotations

import hashlib
import io
import json
import random

from PIL import Image
import pytest

import ffgame_cartridge_artifacts as engine


GBA_LOGO = bytes.fromhex(
    "24ffae51699aa2213d84820a84e409ad11248b98c0817f21a352be199309ce20"
    "10464a4af82731ec58c7e83382e3cebf85f4df94ce4b09c194568ac01372a7fc"
    "9f844d73a3ca9a615897a327fc039876231dc7610304ae56bf38840040a70efd"
    "ff52fe036f9530f197fbc08560d68025a963be03014e38e2f9a234ffbb3e0344"
    "780090cb88113a9465c07c6387f03cafd625e48b380aac7221d4f807"
)

GB_LOGO = bytes.fromhex(
    "ceed6666cc0d000b03730083000c000d0008111f8889000edccc6ee6dddd"
    "d999bbbb67636e0eecccdddc999fbbb9333e"
)


def n64_z64_fixture() -> bytes:
    data = bytearray(0x1100)
    data[0:4] = bytes.fromhex("80371240")
    data[4:8] = (0x0000000F).to_bytes(4, "big")
    data[8:12] = (0x80000400).to_bytes(4, "big")
    data[12:16] = (0x20261105).to_bytes(4, "big")
    data[0x10:0x14] = bytes.fromhex("12345678")
    data[0x14:0x18] = bytes.fromhex("9abcdef0")
    data[0x20:0x34] = b"TOTAL WARFARE".ljust(20, b" ")
    data[0x38:0x3C] = (ord("N")).to_bytes(4, "big")
    data[0x3C:0x3E] = b"TW"
    data[0x3E] = ord("E")
    data[0x3F] = 2
    data[0x40:0x40 + len(b"IPL3 TEST VECTOR")] = b"IPL3 TEST VECTOR"
    flag = b"CSCTF{n64_byte_order}"
    data[0x1020:0x1020 + len(flag)] = flag
    return bytes(data)


def pair_swap(data: bytes) -> bytes:
    assert len(data) % 2 == 0
    return b"".join(data[index:index + 2][::-1] for index in range(0, len(data), 2))


def dword_reverse(data: bytes) -> bytes:
    assert len(data) % 4 == 0
    return b"".join(data[index:index + 4][::-1] for index in range(0, len(data), 4))


def gba_fixture() -> bytes:
    data = bytearray(0x300)
    data[0:4] = bytes.fromhex("000000ea")  # ARM B instruction, stored little-endian.
    data[4:0xA0] = GBA_LOGO
    data[0xA0:0xAC] = b"TOTALWAR2026"
    data[0xAC:0xB0] = b"ATWE"
    data[0xB0:0xB2] = b"01"
    data[0xB2] = 0x96
    data[0xB3] = 0
    data[0xB4] = 0
    data[0xBC] = 3
    data[0xBD] = (-0x19 - sum(data[0xA0:0xBD])) & 0xFF
    data[0x100:0x100 + len(b"EEPROM_V124")] = b"EEPROM_V124"
    flag = b"CSCTF{gba_header_lock}"
    data[0x140:0x140 + len(flag)] = flag
    return bytes(data)


def gb_rom_fixture(*, mbc2: bool = False) -> bytes:
    data = bytearray(32768)
    data[0x104:0x134] = GB_LOGO
    data[0x134:0x144] = b"SAVE LINK".ljust(16, b"\0")
    data[0x147] = 6 if mbc2 else 3
    data[0x148] = 0
    data[0x149] = 0 if mbc2 else 2
    data[0x14D] = (-sum(data[0x134:0x14D]) - 25) & 0xFF
    checksum = sum(data) & 0xFFFF
    data[0x14E:0x150] = checksum.to_bytes(2, "big")
    return bytes(data)


def pico_png_fixture() -> tuple[bytes, dict[str, bytes]]:
    payload = bytearray(160 * 205)
    map_flag = b"CSCTF{pico_map_asset}"
    payload[0x2200:0x2200 + len(map_flag)] = map_flag
    lua = (
        b"-- mission CSCTF{pico_comment}\n"
        b"#include secret/cart.p8\n"
        b"local clue=\"CSCTF{pico_literal}\"\n"
        b"print(clue)\n"
    )
    payload[0x4300:0x4300 + len(lua)] = lua
    consumed = len(lua) + 1  # zero terminator is already present in the bytearray.
    slack_flag = b"CSCTF{pico_lua_slack}"
    slack_at = 0x4300 + consumed + 7
    payload[slack_at:slack_at + len(slack_flag)] = slack_flag
    payload[0x8000] = 42
    extra_flag = b"CSCTF{pico_extra}"
    payload[0x8001:0x8001 + len(extra_flag)] = extra_flag

    # Independent inverse of PICO-8's AARRGGBB low-two-bit packing.
    pixels = [
        (
            0xA0 | ((value >> 4) & 3),
            0x50 | ((value >> 2) & 3),
            0x08 | (value & 3),
            0xF0 | ((value >> 6) & 3),
        )
        for value in payload
    ]
    image = Image.new("RGBA", (160, 205))
    image.putdata(pixels)
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    trailer = b"CSCTF{pico_png_tail}"
    return stream.getvalue() + trailer, {
        "map": map_flag,
        "lua": lua,
        "slack": slack_flag,
        "extra": extra_flag,
        "trailer": trailer,
    }


def named(rows, name):
    return next(row for row in rows if row["name"] == name)


@pytest.mark.parametrize(
    ("physical", "fixture"),
    [
        ("z64-big-endian", n64_z64_fixture),
        ("v64-byte-swapped", lambda: pair_swap(n64_z64_fixture())),
        ("n64-little-endian-words", lambda: dword_reverse(n64_z64_fixture())),
    ],
)
def test_n64_header_byte_orders_normalize_to_one_published_layout(physical, fixture):
    canonical = n64_z64_fixture()
    result = engine.parse_n64(fixture())
    assert result["physical_format"] == physical
    assert result["normalized_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert result["header"] == {
        "pi_domain_word": "80371240",
        "clock_rate": 0xF,
        "entry_point": 0x80000400,
        "release": 0x20261105,
        "crc1": "12345678",
        "crc2": "9abcdef0",
        "title": "TOTAL WARFARE",
        "title_raw_hex": canonical[0x20:0x34].hex(),
        "manufacturer_id": ord("N"),
        "manufacturer_ascii": "N",
        "cartridge_id": "TW",
        "region_code": ord("E"),
        "region_ascii": "E",
        "region": "North America",
        "version": 2,
    }
    assert result["flags"] == ["CSCTF{n64_byte_order}"]
    assert result["flag_hits"] == [
        {"offset": 0x1020, "value": "CSCTF{n64_byte_order}", "section": "program_and_data"}
    ]
    assert result["findings"] == []


def test_n64_exact_structure_and_digests():
    data = n64_z64_fixture()
    result = engine.parse_n64(data)
    assert result["sections"] == [
        {"name": "header", "offset": 0, "declared_bytes": 0x40,
         "available_bytes": 0x40, "missing_bytes": 0},
        {"name": "ipl3_boot_code", "offset": 0x40, "declared_bytes": 0xFC0,
         "available_bytes": 0xFC0, "missing_bytes": 0},
        {"name": "program_and_data", "offset": 0x1000, "declared_bytes": None,
         "available_bytes": 0x100, "missing_bytes": None},
    ]
    assert result["digests"]["header_sha256"] == hashlib.sha256(data[:0x40]).hexdigest()
    assert result["digests"]["ipl3_sha256"] == hashlib.sha256(data[0x40:0x1000]).hexdigest()
    assert result["digests"]["program_and_data_sha256"] == hashlib.sha256(data[0x1000:]).hexdigest()
    assert "CIC-dependent verification is not claimed" in result["notes"][0]


def test_n64_header_only_reports_truncated_ipl3_without_index_error():
    result = engine.parse_n64(n64_z64_fixture()[:0x40])
    assert named(result["sections"], "ipl3_boot_code")["missing_bytes"] == 0xFC0
    assert named(result["sections"], "program_and_data")["available_bytes"] == 0
    assert result["findings"] == ["IPL3 boot-code area is truncated."]


def test_gba_published_header_logo_checksum_fields_and_body_artifacts():
    data = gba_fixture()
    result = engine.parse_gba(data)
    header = result["header"]
    assert len(GBA_LOGO) == 156
    assert header["entry_instruction_hex"] == "000000ea"
    assert header["entry_instruction_little_endian"] == 0xEA000000
    assert header["title"] == "TOTALWAR2026"
    assert header["game_code"] == "ATWE"
    assert header["maker_code"] == "01"
    assert header["fixed_0x96"] == 0x96
    assert header["software_version"] == 3
    assert header["logo_matches"] is True
    expected = (-0x19 - sum(data[0xA0:0xBD])) & 0xFF
    assert header["complement"] == {"stored": expected, "calculated": expected, "matches": True}
    assert result["save_medium_signatures"] == [
        {"offset": 0x100, "marker": "EEPROM_V124", "medium_hint": "eeprom"}
    ]
    assert result["flags"] == ["CSCTF{gba_header_lock}"]
    assert result["flag_hits"][0]["offset"] == 0x140
    assert result["sections"][0]["declared_bytes"] == 192
    assert result["sections"][1]["available_bytes"] == len(data) - 192
    assert result["findings"] == []


def test_gba_tampering_is_reported_but_remains_inspectable():
    data = bytearray(gba_fixture())
    data[4] ^= 1
    data[0xB2] = 0
    data[0xB5] = 1
    data[0xBE] = 2
    data[0xBD] ^= 1
    result = engine.parse_gba(data)
    assert result["header"]["logo_matches"] is False
    assert result["header"]["complement"]["matches"] is False
    assert result["flags"] == ["CSCTF{gba_header_lock}"]
    assert result["findings"] == [
        "Nintendo logo bytes differ from the published retail logo.",
        "Fixed header byte 0xb2 is not 0x96.",
        "GBA header complement checksum mismatch.",
        "Reserved header bytes 0xb5..0xbb are nonzero.",
        "Reserved header bytes 0xbe..0xbf are nonzero.",
    ]


def test_gb_battery_save_raw_inventory_and_rom_correlation():
    save = bytearray(8192)
    save[100:100 + len(b"CSCTF{battery_ram}")] = b"CSCTF{battery_ram}"
    save[500:500 + len(b"PLAYER=ALPHA")] = b"PLAYER=ALPHA"
    result = engine.inspect_gb_sav(save, gb_rom_fixture())
    assert result["sections"] == [
        {"name": "raw_battery_ram", "offset": 0, "available_bytes": 8192}
    ]
    assert result["possible_layouts"] == ["one 8 KiB external-RAM bank"]
    assert result["flags"] == ["CSCTF{battery_ram}"]
    assert any(row["text"] == "PLAYER=ALPHA" for row in result["strings"])
    assert result["rom_correlation"] == {
        "rom_title": "SAVE LINK",
        "cartridge_type": "MBC1+RAM+BATTERY",
        "expected_raw_bytes": 8192,
        "basis": "cartridge header RAM-size code",
        "matches_exactly": True,
        "size_delta": 0,
        "note": "Emulator-specific RTC/footer data is not interpreted.",
    }
    assert result["findings"] == []


def test_gb_mbc2_and_unknown_size_stay_semantics_light():
    mbc2 = engine.inspect_gb_sav(b"\xff" * 512, gb_rom_fixture(mbc2=True))
    assert "MBC2" in mbc2["possible_layouts"][0]
    assert mbc2["rom_correlation"]["expected_raw_bytes"] == 512
    assert mbc2["byte_summary"]["all_ff"] is True
    odd = engine.inspect_gb_sav(b"x" * 123)
    assert odd["possible_layouts"] == []
    assert odd["rom_correlation"] is None
    assert odd["findings"] == ["Size is not one of the common raw Game Boy RAM extents."]


def test_gb_save_walks_known_8k_banks_with_exact_flag_offsets():
    save = bytearray(32768)
    flag = b"CSCTF{bank_two}"
    absolute = 2 * 8192 + 123
    save[absolute:absolute + len(flag)] = flag
    result = engine.inspect_gb_sav(save)
    assert [(row["index"], row["offset"], row["byte_size"])
            for row in result["banks"]] == [
        (0, 0, 8192), (1, 8192, 8192), (2, 16384, 8192), (3, 24576, 8192)
    ]
    assert result["banks"][2]["flag_hits"] == [{
        "offset": 123, "absolute_offset": absolute, "value": flag.decode()
    }]
    assert result["banks"][0]["flag_hits"] == []
    assert result["banks"][2]["sha256"] == hashlib.sha256(
        bytes(save[16384:24576])
    ).hexdigest()


def test_pico_png_reuses_decoder_and_adds_section_lua_and_slack_inventory():
    data, fixture = pico_png_fixture()
    result = engine.inspect_pico8(data)
    assert result["format"] == "p8.png" and result["version"] == 42
    map_row = named(result["sections"], "map")
    assert map_row["location"] == {
        "kind": "decoded-cart-memory", "offset": 0x2000, "capacity_bytes": 0x1000
    }
    assert fixture["map"].decode() in map_row["flags"]
    lua_row = named(result["sections"], "lua")
    assert lua_row["location"] == {
        "kind": "decoded-cart-memory", "offset": 0x4300, "capacity_bytes": 0x3D00
    }
    assert lua_row["compression"] == "uncompressed"
    static = result["lua_static_artifacts"]
    assert static["comments"] == [
        {"offset": 0, "text": "-- mission CSCTF{pico_comment}"}
    ]
    assert static["include_targets"] == [
        {"offset": len(b"-- mission CSCTF{pico_comment}\n"), "target": "secret/cart.p8"}
    ]
    assert any(row["raw_content"] == "CSCTF{pico_literal}" for row in static["quoted_literals"])
    unused = named(result["slack"], "unused_lua_storage")
    assert fixture["slack"].decode() in unused["flags"]
    extra = named(result["slack"], "payload_after_version_byte")
    assert extra["location"]["offset"] == 0x8001
    assert fixture["extra"].decode() in extra["flags"]
    trailer = named(result["slack"], "bytes_after_png_iend")
    assert trailer["location"]["offset"] == len(data) - len(fixture["trailer"])
    assert trailer["flags"] == [fixture["trailer"].decode()]
    assert set(result["flags"]) == {
        fixture["map"].decode(),
        "CSCTF{pico_comment}",
        "CSCTF{pico_literal}",
        fixture["slack"].decode(),
        fixture["extra"].decode(),
        fixture["trailer"].decode(),
    }
    assert "never opened or resolved" in result["notes"][2]


def test_dispatch_is_conservative_for_headerless_saves():
    assert engine.inspect_cartridge(n64_z64_fixture())["format"] == "n64-rom"
    assert engine.inspect_cartridge(gba_fixture())["format"] == "gba-rom"
    assert engine.inspect_cartridge(b"\0" * 8192, "gb-sav")["format"] == "game-boy-battery-save"
    with pytest.raises(engine.FFGameCartridgeError, match="raw Game Boy saves"):
        engine.inspect_cartridge(b"\0" * 8192)


@pytest.mark.parametrize(
    "parser",
    [engine.parse_n64, engine.parse_gba, engine.inspect_gb_sav,
     engine.inspect_pico8, engine.inspect_cartridge],
)
def test_public_parsers_fail_closed_for_deterministic_malformed_inputs(parser):
    rng = random.Random(0xFF2606)
    n64 = n64_z64_fixture()
    gba = gba_fixture()
    pico, _ = pico_png_fixture()
    samples = [
        None,
        "not bytes",
        7,
        object(),
        b"",
        b"\xff" * 257,
        b"\0" * 257,
        rng.randbytes(257),
        n64[:3],
        n64[:63],
        gba[:191],
        pico[:8],
        pico[:100],
    ]
    for original in (n64, gba, pico):
        changed = bytearray(original)
        changed[min(len(changed) - 1, 10)] ^= 0x80
        samples.append(bytes(changed))
    for sample in samples:
        try:
            result = parser(sample)
        except engine.FFGameCartridgeError:
            continue
        assert isinstance(result, dict)


def test_released_memoryviews_and_runtime_limits_use_only_declared_error(monkeypatch):
    view = memoryview(b"data")
    view.release()
    for parser in (engine.parse_n64, engine.parse_gba, engine.inspect_gb_sav,
                   engine.inspect_pico8, engine.inspect_cartridge):
        with pytest.raises(engine.FFGameCartridgeError):
            parser(view)

    monkeypatch.setattr(engine, "MAX_INPUT", 32)
    with pytest.raises(engine.FFGameCartridgeError, match="limit"):
        engine.parse_n64(n64_z64_fixture())
    with pytest.raises(engine.FFGameCartridgeError, match="limit"):
        engine.inspect_cartridge(n64_z64_fixture())
    monkeypatch.setattr(engine, "MAX_GBA_INPUT", 32)
    with pytest.raises(engine.FFGameCartridgeError, match="limit"):
        engine.parse_gba(gba_fixture())
    monkeypatch.setattr(engine, "MAX_SAVE_INPUT", 32)
    with pytest.raises(engine.FFGameCartridgeError, match="limit"):
        engine.inspect_gb_sav(b"x" * 33)
    monkeypatch.setattr(engine, "MAX_PICO_INPUT", 32)
    with pytest.raises(engine.FFGameCartridgeError, match="limit"):
        engine.inspect_pico8(b"x" * 33)


def test_file_boundary_and_guarded_cli(tmp_path, capsys, monkeypatch):
    artifact = tmp_path / "fixture.z64"
    artifact.write_bytes(n64_z64_fixture())
    assert engine.inspect_file(artifact)["header"]["title"] == "TOTAL WARFARE"
    assert engine.main([str(artifact)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["flags"] == ["CSCTF{n64_byte_order}"]
    assert engine.main(["--help"]) == 0
    capsys.readouterr()
    assert engine.main([]) == 2
    capsys.readouterr()
    assert engine.main([str(tmp_path / "missing")]) == 2
    capsys.readouterr()
    with pytest.raises(engine.FFGameCartridgeError):
        engine.inspect_file(tmp_path / "missing")

    def non_integer_exit(*args, **kwargs):
        raise SystemExit("bad")

    monkeypatch.setattr(engine.argparse.ArgumentParser, "parse_args", non_integer_exit)
    assert engine.main([]) == 2
