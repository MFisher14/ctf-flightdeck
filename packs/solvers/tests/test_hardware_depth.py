"""Synthetic static hardware/firmware depth fixtures."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import hardware_depth as hw  # noqa: E402


def test_spi_nor_transactions_reconstruct_reads_and_programs():
    rows = [
        {"mosi": "9f000000", "miso": "00ef4018", "complete": True},
        {"mosi": "0300001000000000", "miso": "0000000043544621", "complete": True},
        {"mosi": "02000014464c4147", "miso": "0000000000000000", "complete": True},
    ]
    result = hw.decode_spi_flash(rows)
    assert result["jedec_ids"] == [bytes.fromhex("ef4018")]
    assert result["base"] == 0x10
    assert result["image"] == b"CTF!FLAG"
    assert result["known"] == 8
    assert [item["name"] for item in result["operations"]] == [
        "read-jedec-id", "read", "page-program"
    ]


def test_sampled_spi_is_split_on_chip_select():
    # Two one-byte transactions, mode 0.  Each bit contributes a low then rising sample.
    clk, mosi, cs = [0], [0], [1]
    for byte in (0x9F, 0x05):
        clk.append(0); mosi.append(0); cs.append(0)
        for bit in range(7, -1, -1):
            value = (byte >> bit) & 1
            clk.extend((0, 1)); mosi.extend((value, value)); cs.extend((0, 0))
        clk.append(0); mosi.append(0); cs.append(1)
    rows = hw.rf.spi_transactions(clk, mosi=mosi, cs=cs)
    assert [row["mosi"] for row in rows] == [b"\x9f", b"\x05"]
    assert all(row["complete"] for row in rows)


def test_i2c_eeprom_pointer_write_and_following_read():
    rows = [
        {"address": 0x50, "rw": "w", "data": b"\x00\x10AB"},
        {"address": 0x50, "rw": "w", "data": b"\x00\x20"},
        {"address": 0x50, "rw": "r", "data": b"FLAG"},
    ]
    result = hw.reconstruct_i2c_eeprom(rows)
    assert result["base"] == 0x10
    assert result["image"][:2] == b"AB"
    assert result["image"][0x10:0x14] == b"FLAG"
    assert result["holes"] == 14


def test_dbc_little_big_signed_and_candump_integration():
    dbc = """
BO_ 291 Engine: 8 ECU
 SG_ Speed : 0|16@1+ (0.1,0) [0|6553.5] "km/h" Vector__XXX
 SG_ Mode M : 16|8@1+ (1,0) [0|255] "" Vector__XXX
 SG_ Torque m2 : 24|8@1- (1,0) [-128|127] "Nm" Vector__XXX
 SG_ Big : 39|8@0+ (1,0) [0|255] "raw" Vector__XXX
"""
    database = hw.parse_dbc(dbc)
    payload = bytes([0xD2, 0x04, 0x02, 0xFB, 0xA5, 0, 0, 0])
    decoded = hw.decode_dbc_frame(database, 291, payload)
    values = {item["name"]: item for item in decoded["signals"]}
    assert values["Speed"]["value"] == 123.4
    assert values["Mode"]["raw"] == 2
    assert values["Torque"]["raw"] == -5
    assert values["Big"]["raw"] == 0xA5

    log = "\n".join(f"({i}.0) can0 123#{payload.hex()}" for i in range(3))
    frames = hw.decode_can_log_with_dbc(log, dbc)
    assert len(frames) == 3
    assert frames[0]["message"] == "Engine"


def test_uart_bootloader_and_debug_identifier_notes():
    report = hw.classify_uart_bootloader(
        b"U-Boot 2024.01\nHit any key to stop autoboot\nbootargs=console=ttyS0 root=/dev/mtdblock3\n=> "
    )
    assert report["candidates"][0]["family"] == "u-boot"
    assert report["bootargs"].startswith("console=ttyS0")

    jtag = hw.boundary_scan_notes("jtag", 0x4BA00477)
    assert jtag["identifier"]["idcode_lsb_valid"] is True
    assert jtag["identifier"]["part"] == 0xBA00
    assert "SAMPLE/PRELOAD" in jtag["candidates"][1]["note"]


def test_embedded_crc_valid_uboot_environment_is_carved():
    body = b"bootcmd=run rescue\x00flag=synthetic\x00\x00"
    body += b"\xff" * (0x1000 - 4 - len(body))
    region = struct.pack("<I", hw.firmware.crc32_std(body)) + body
    blob = b"\xff" * 0x1000 + region + b"\xff" * 0x1000
    candidates = hw.carve_firmware(blob)
    env = next(item for item in candidates if item["kind"] == "uboot_env")
    assert env["offset"] == 0x1000
    assert env["report"]["vars"]["bootcmd"] == "run rescue"
    assert env["verified"] is True


def test_guarded_cli_and_malformed_input(tmp_path, capsys):
    fixture = tmp_path / "spi.json"
    fixture.write_text(json.dumps({"transactions": [{"mosi": "9f000000", "miso": "00ef4018"}]}),
                       encoding="utf-8")
    assert hw.main(["spi-flash", str(fixture), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["jedec_ids"] == ["ef4018"]

    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    assert hw.main(["spi-flash", str(bad)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("hardware_depth: ")
    assert "Traceback" not in captured.err

