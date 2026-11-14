"""Spec-derived cartridge vectors and fail-closed game-artifact checks."""

from __future__ import annotations

import hashlib
import json
import random

import pytest

import ffgame_cartridge_artifacts as engine


# Published Nintendo logo data from GBATEK/Pan Docs, copied here so the engine
# cannot serve as its own fixture oracle.
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


def _n64_z64() -> bytes:
    data = bytearray(0x1040)
    data[0:4] = bytes.fromhex("80371240")
    data[4:8] = (15).to_bytes(4, "big")
    data[8:12] = (0x80001234).to_bytes(4, "big")
    data[12:16] = (0xDEADBEEF).to_bytes(4, "big")
    data[0x10:0x14] = bytes.fromhex("a1b2c3d4")
    data[0x14:0x18] = bytes.fromhex("10203040")
    data[0x20:0x34] = b"R3 CARTRIDGE LOCK".ljust(20, b" ")
    data[0x38:0x3C] = ord("N").to_bytes(4, "big")
    data[0x3C:0x3E] = b"R3"
    data[0x3E] = ord("J")
    data[0x3F] = 5
    flag = b"CSCTF{n64_vector}"
    data[0x1008:0x1008 + len(flag)] = flag
    return bytes(data)


def _swap_pairs(data: bytes) -> bytes:
    assert len(data) % 2 == 0
    return b"".join(data[offset:offset + 2][::-1]
                    for offset in range(0, len(data), 2))


def _reverse_words(data: bytes) -> bytes:
    assert len(data) % 4 == 0
    return b"".join(data[offset:offset + 4][::-1]
                    for offset in range(0, len(data), 4))


def _gba_rom() -> bytes:
    data = bytearray(0x180)
    data[0:4] = bytes.fromhex("000000ea")
    data[4:0xA0] = GBA_LOGO
    data[0xA0:0xAC] = b"WARFARE2026!"
    data[0xAC:0xB0] = b"R3GE"
    data[0xB0:0xB2] = b"01"
    data[0xB2] = 0x96
    data[0xBC] = 7
    data[0xBD] = (-0x19 - sum(data[0xA0:0xBD])) & 0xFF
    data[0xC0:0xC0 + len(b"SRAM_V113")] = b"SRAM_V113"
    flag = b"CSCTF{gba_vector}"
    data[0x100:0x100 + len(flag)] = flag
    return bytes(data)


def _gb_rom() -> bytes:
    data = bytearray(32768)
    data[0x104:0x134] = GB_LOGO
    data[0x134:0x144] = b"R3 SAVE VECTOR".ljust(16, b"\0")
    data[0x147] = 0x1B  # MBC5+RAM+BATTERY
    data[0x148] = 0x00  # 32 KiB ROM
    data[0x149] = 0x03  # 32 KiB RAM
    data[0x14A] = 0x01
    data[0x14C] = 0x04
    data[0x14D] = (-sum(data[0x134:0x14D]) - 25) & 0xFF
    checksum = sum(data[:0x14E]) + sum(data[0x150:])
    data[0x14E:0x150] = (checksum & 0xFFFF).to_bytes(2, "big")
    return bytes(data)


def _gb_save() -> tuple[bytes, int]:
    data = bytearray(b"\xff" * 32768)
    data[17:17 + len(b"PLAYER=R3")] = b"PLAYER=R3"
    absolute = 2 * 8192 + 321
    flag = b"CSCTF{gb_bank_vector}"
    data[absolute:absolute + len(flag)] = flag
    return bytes(data), absolute


def _p8_text() -> bytes:
    return (
        b"pico-8 cartridge // http://www.pico-8.com\n"
        b"version 42\n"
        b"__lua__\n"
        b"-- note CSCTF{pico_text}\n"
        b"local x=\"LOCKED\"\n"
    )


def _returns_or_declared(call, *args, **kwargs) -> None:
    try:
        result = call(*args, **kwargs)
    except Exception as exc:  # Deliberately catches leaked implementation errors.
        assert type(exc) is engine.FFGameCartridgeError
    else:
        assert isinstance(result, dict)


@pytest.mark.parametrize(("physical", "fixture"), [
    ("z64-big-endian", _n64_z64),
    ("v64-byte-swapped", lambda: _swap_pairs(_n64_z64())),
    ("n64-little-endian-words", lambda: _reverse_words(_n64_z64())),
])
def test_n64_documented_header_and_physical_byte_orders(physical, fixture) -> None:
    canonical = _n64_z64()
    report = engine.parse_n64(fixture())
    assert report["physical_format"] == physical
    assert report["normalized_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert report["header"] == {
        "pi_domain_word": "80371240", "clock_rate": 15,
        "entry_point": 0x80001234, "release": 0xDEADBEEF,
        "crc1": "a1b2c3d4", "crc2": "10203040",
        "title": "R3 CARTRIDGE LOCK",
        "title_raw_hex": canonical[0x20:0x34].hex(),
        "manufacturer_id": ord("N"), "manufacturer_ascii": "N",
        "cartridge_id": "R3", "region_code": ord("J"),
        "region_ascii": "J", "region": "Japan", "version": 5,
    }
    assert report["flags"] == ["CSCTF{n64_vector}"]
    assert report["flag_hits"] == [{
        "offset": 0x1008, "value": "CSCTF{n64_vector}",
        "section": "program_and_data",
    }]
    assert report["findings"] == []


def test_gba_published_logo_complement_and_save_marker_vector() -> None:
    data = _gba_rom()
    report = engine.parse_gba(data)
    assert len(GBA_LOGO) == 156
    assert report["sha256"] == hashlib.sha256(data).hexdigest()
    assert report["header"]["logo_sha256"] == hashlib.sha256(GBA_LOGO).hexdigest()
    assert report["header"]["title"] == "WARFARE2026!"
    assert report["header"]["game_code"] == "R3GE"
    assert report["header"]["maker_code"] == "01"
    assert report["header"]["software_version"] == 7
    assert report["header"]["logo_matches"] is True
    expected = (-0x19 - sum(data[0xA0:0xBD])) & 0xFF
    assert report["header"]["complement"] == {
        "stored": expected, "calculated": expected, "matches": True,
    }
    assert report["save_medium_signatures"] == [{
        "offset": 0xC0, "marker": "SRAM_V113", "medium_hint": "sram",
    }]
    assert report["flags"] == ["CSCTF{gba_vector}"]
    assert report["findings"] == []


def test_game_boy_pan_docs_header_checksum_and_banked_save_vector() -> None:
    rom = _gb_rom()
    save, absolute = _gb_save()
    assert len(GB_LOGO) == 48
    assert rom[0x14D] == ((-sum(rom[0x134:0x14D]) - 25) & 0xFF)
    assert int.from_bytes(rom[0x14E:0x150], "big") == (
        sum(rom[:0x14E]) + sum(rom[0x150:])
    ) & 0xFFFF

    report = engine.inspect_gb_sav(save, rom)
    assert report["sha256"] == hashlib.sha256(save).hexdigest()
    assert report["possible_layouts"] == ["four 8 KiB external-RAM banks"]
    assert [(row["index"], row["offset"], row["byte_size"])
            for row in report["banks"]] == [
        (0, 0, 8192), (1, 8192, 8192),
        (2, 16384, 8192), (3, 24576, 8192),
    ]
    assert report["banks"][2]["flag_hits"] == [{
        "offset": 321, "absolute_offset": absolute,
        "value": "CSCTF{gb_bank_vector}",
    }]
    assert report["rom_correlation"] == {
        "rom_title": "R3 SAVE VECTOR",
        "cartridge_type": "MBC5+RAM+BATTERY",
        "expected_raw_bytes": 32768,
        "basis": "cartridge header RAM-size code",
        "matches_exactly": True,
        "size_delta": 0,
        "note": "Emulator-specific RTC/footer data is not interpreted.",
    }
    assert report["findings"] == []


def test_text_pico8_static_inventory_is_non_executing() -> None:
    data = _p8_text()
    report = engine.inspect_pico8(data, "p8")
    lua = next(row for row in report["sections"] if row["name"] == "lua")
    lua_bytes = b"-- note CSCTF{pico_text}\nlocal x=\"LOCKED\"\n"
    assert report["format"] == "p8" and report["version"] == 42
    assert report["sha256"] == hashlib.sha256(data).hexdigest()
    assert lua["sha256"] == hashlib.sha256(lua_bytes).hexdigest()
    assert report["flags"] == ["CSCTF{pico_text}"]
    assert report["lua_static_artifacts"]["comments"] == [{
        "offset": 0, "text": "-- note CSCTF{pico_text}",
    }]
    assert report["lua_static_artifacts"]["quoted_literals"] == [{
        "offset": 33, "quote": '"', "raw_content": "LOCKED",
    }]
    assert "never executed" in report["notes"][2]


def test_text_pico8_has_no_png_iend_slack() -> None:
    assert engine.inspect_pico8(_p8_text(), "p8")["slack"] == []


@pytest.mark.parametrize(("entrypoint", "valid", "cap_name", "truncated"), [
    (engine.parse_n64, _n64_z64(), "MAX_INPUT", _n64_z64()[:4]),
    (engine.parse_gba, _gba_rom(), "MAX_GBA_INPUT", _gba_rom()[:0xBF]),
    (engine.inspect_gb_sav, _gb_save()[0], "MAX_SAVE_INPUT", _gb_save()[0][:-1]),
    (engine.inspect_pico8, _p8_text(), "MAX_PICO_INPUT", _p8_text()[:43]),
    (engine.inspect_cartridge, _n64_z64(), "MAX_INPUT", _n64_z64()[:4]),
])
def test_every_public_bytes_entrypoint_fails_closed(
    monkeypatch: pytest.MonkeyPatch, entrypoint, valid: bytes,
    cap_name: str, truncated: bytes,
) -> None:
    changed = bytearray(valid)
    changed[0] ^= 0x80
    for sample in (
        None, "not bytes", b"", random.Random(0x43415254).randbytes(257),
        b"\xff" * 257, truncated, valid[:-1], bytes(changed),
    ):
        _returns_or_declared(entrypoint, sample)
    monkeypatch.setattr(engine, cap_name, 32)
    _returns_or_declared(entrypoint, b"X" * 33)


def test_format_specific_truncations_and_bad_correlation_fail_closed() -> None:
    for sample in (
        bytes.fromhex("80371240"),
        bytes.fromhex("37804012") + b"\0" * 61,
        bytes.fromhex("40123780") + b"\0" * 62,
    ):
        _returns_or_declared(engine.parse_n64, sample)
    for sample in (_gba_rom()[:4], _gba_rom()[:0x9F], _gba_rom()[:0xBF]):
        _returns_or_declared(engine.parse_gba, sample)
    for sample in (
        b"pico-8 cartridge // http://www.pico-8.com", _p8_text()[:-1],
    ):
        _returns_or_declared(engine.inspect_pico8, sample)
    _returns_or_declared(engine.inspect_gb_sav, _gb_save()[0], b"short-rom")
    _returns_or_declared(engine.inspect_cartridge, b"bytes", "unknown")
    _returns_or_declared(engine.inspect_pico8, _p8_text(), "unknown")


def test_released_memoryviews_raise_only_declared_error() -> None:
    view = memoryview(b"inert")
    view.release()
    for entrypoint in (
        engine.parse_n64, engine.parse_gba, engine.inspect_gb_sav,
        engine.inspect_pico8, engine.inspect_cartridge,
    ):
        with pytest.raises(engine.FFGameCartridgeError) as caught:
            entrypoint(view)
        assert type(caught.value) is engine.FFGameCartridgeError


def test_file_entrypoint_and_cli_are_fail_closed(tmp_path, capsys, monkeypatch) -> None:
    artifact = tmp_path / "oracle.z64"
    artifact.write_bytes(_n64_z64())
    assert engine.inspect_file(artifact)["header"]["title"] == "R3 CARTRIDGE LOCK"
    assert engine.main([str(artifact)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["flags"] == ["CSCTF{n64_vector}"]
    assert engine.main(["--help"]) == 0
    capsys.readouterr()
    assert engine.main([]) == 2
    capsys.readouterr()
    assert engine.main([str(tmp_path / "missing")]) == 2
    capsys.readouterr()

    _returns_or_declared(engine.inspect_file, tmp_path / "missing")
    _returns_or_declared(engine.inspect_file, tmp_path)
    monkeypatch.setattr(engine, "MAX_INPUT", 32)
    _returns_or_declared(engine.inspect_file, artifact)

    def non_integer_system_exit(*_args, **_kwargs):
        raise SystemExit("not-an-integer")

    monkeypatch.setattr(engine.argparse.ArgumentParser, "parse_args", non_integer_system_exit)
    assert engine.main([]) == 2
