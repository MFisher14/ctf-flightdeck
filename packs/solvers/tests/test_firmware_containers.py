"""Synthetic structural tests for firmware_containers.py."""
from __future__ import annotations

import json
import hashlib
import struct
import sys
import zlib
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import firmware_containers as fw  # noqa: E402


def _squash() -> bytes:
    sentinel = 0xFFFFFFFFFFFFFFFF
    header = struct.pack("<IIIIIHHHHHHQQQQQQQQ", fw.CRAMFS_MAGIC * 0 + 0x73717368,
                         3, 1234, 4096, 0, 1, 12, 0, 1, 4, 0,
                         0, 128, 120, sentinel, 96, 104, 112, sentinel)
    return header + b"\x00" * (128 - len(header))


def test_squashfs_superblock_bounds_and_fields():
    report = fw.parse_squashfs(_squash())
    assert report["kind"] == "squashfs" and report["version"] == "4.0"
    assert report["compression"] == "gzip" and report["extent"] == 128
    with pytest.raises(fw.FirmwareError):
        fw.parse_squashfs(_squash()[:100])
    bad_log = bytearray(_squash()); struct.pack_into("<H", bad_log, 22, 13)
    with pytest.raises(fw.FirmwareError, match="geometry"):
        fw.parse_squashfs(bytes(bad_log))


def test_jffs2_node_crc_and_truncation_guard():
    prefix = struct.pack("<HHI", 0x1985, 0x2003, 12)
    node = prefix + struct.pack("<I", fw._jffs2_crc(prefix))
    report = fw.parse_jffs2(node)
    assert report["node_count"] == 1 and report["nodes"][0]["header_crc_ok"]
    broken = struct.pack("<HHII", 0x1985, 0x2003, 100, 0)
    with pytest.raises(fw.FirmwareError):
        fw.parse_jffs2(broken)
    damaged = bytearray(node); damaged[-1] ^= 1
    assert fw.parse_jffs2(bytes(damaged))["invalid_header_crcs"] == 1


def _ubi_peb(sequence: int, peb_size: int = 256) -> bytes:
    peb = bytearray(b"\xff" * peb_size)
    peb[:4] = b"UBI#"; peb[4] = 1
    struct.pack_into(">QIII", peb, 8, sequence, 64, 128, 0x11223344)
    struct.pack_into(">I", peb, 60, fw._ubi_crc(bytes(peb[:60])))
    peb[64:68] = b"UBI!"; peb[68:72] = bytes([1, 1, 0, 0])
    struct.pack_into(">II", peb, 72, 7, sequence)
    struct.pack_into(">IIII", peb, 84, 4, 2, 0, 0)
    struct.pack_into(">Q", peb, 104, sequence + 100)
    struct.pack_into(">I", peb, 124, fw._ubi_crc(bytes(peb[64:124])))
    return bytes(peb)


def test_ubi_headers_peb_geometry_and_vid():
    image = _ubi_peb(0) + _ubi_peb(1)
    report = fw.parse_ubi(image)
    assert report["eraseblock_size"] == 256 and report["peb_count"] == 2
    assert all(row["header_crc_ok"] and row["vid"]["header_crc_ok"] for row in report["headers"])
    assert report["headers"][1]["vid"]["logical_eraseblock"] == 1
    assert [row["kind"] for row in fw.carve_firmware(image)] == ["ubi"]
    damaged = bytearray(image); damaged[60] ^= 1
    assert fw.parse_ubi(bytes(damaged))["headers"][0]["header_crc_ok"] is False


def _cramfs() -> bytes:
    image = bytearray(92)
    struct.pack_into("<IIII", image, 0, fw.CRAMFS_MAGIC, len(image), 1, 0)
    image[16:32] = b"Compressed ROMFS"
    struct.pack_into("<IIII", image, 32, 0, 2, 3, 4)
    image[48:55] = b"fixture"
    checksum = zlib.crc32(image) & 0xFFFFFFFF
    struct.pack_into("<I", image, 32, checksum)
    return bytes(image)


def test_cramfs_checksum_and_metadata():
    report = fw.parse_cramfs(_cramfs())
    assert report["checksum_ok"] and report["name"] == "fixture"
    assert report["file_count"] == 4 and report["edition"] == 2
    damaged = bytearray(_cramfs()); damaged[-1] ^= 1
    assert fw.parse_cramfs(bytes(damaged))["checksum_ok"] is False


def _uimage(payload: bytes = b"CSCTF-fixture") -> bytes:
    header = bytearray(struct.pack(">7I4B32s", 0x27051956, 0, 123, len(payload),
                                   0x8000, 0x8010, zlib.crc32(payload) & 0xFFFFFFFF,
                                   5, 22, 5, 0, b"offline-test\x00"))  # arch 22 = IH_ARCH_ARM64
    struct.pack_into(">I", header, 4, zlib.crc32(header) & 0xFFFFFFFF)
    return bytes(header) + payload


def test_uboot_uimage_crcs_and_architecture():
    report = fw.parse_uimage(_uimage())
    assert report["header_crc_ok"] and report["data_crc_ok"]
    assert report["arch"] == "arm64" and report["type"] == "firmware"
    corrupt = bytearray(_uimage()); corrupt[-1] ^= 1
    assert not fw.parse_uimage(bytes(corrupt))["data_crc_ok"]
    corrupt = bytearray(_uimage()); corrupt[8] ^= 1
    assert not fw.parse_uimage(bytes(corrupt))["header_crc_ok"]


def _fdt_name(name: bytes) -> bytes:
    raw = name + b"\x00"
    return raw + b"\x00" * ((-len(raw)) & 3)


def _fit() -> bytes:
    strings = b"type\x00data\x00algo\x00value\x00"
    body = bytearray()
    body += struct.pack(">I", fw.FDT_BEGIN_NODE) + _fdt_name(b"")
    body += struct.pack(">I", fw.FDT_BEGIN_NODE) + _fdt_name(b"images")
    body += struct.pack(">I", fw.FDT_BEGIN_NODE) + _fdt_name(b"kernel")
    value = b"kernel\x00"
    body += struct.pack(">III", fw.FDT_PROP, len(value), 0) + value + b"\x00" * ((-len(value)) & 3)
    value = b"ABCD"
    body += struct.pack(">III", fw.FDT_PROP, len(value), 5) + value
    body += struct.pack(">I", fw.FDT_BEGIN_NODE) + _fdt_name(b"hash-1")
    algorithm = b"sha256\x00"
    body += struct.pack(">III", fw.FDT_PROP, len(algorithm), 10) + algorithm + b"\x00" * ((-len(algorithm)) & 3)
    digest = hashlib.sha256(value).digest()
    body += struct.pack(">III", fw.FDT_PROP, len(digest), 15) + digest
    body += struct.pack(">I", fw.FDT_END_NODE) * 4 + struct.pack(">I", fw.FDT_END)
    struct_off, strings_off = 40, 40 + len(body)
    total = strings_off + len(strings)
    header = struct.pack(">10I", fw.FDT_MAGIC, total, struct_off, strings_off, 40,
                         17, 16, 0, len(strings), len(body))
    return header + body + strings


def test_fit_fdt_image_nodes_and_embedded_data():
    report = fw.parse_fit(_fit())
    assert report["kind"] == "fit" and report["node_count"] == 4
    image = report["images"][0]
    assert image["name"] == "kernel" and image["type"] == "kernel" and image["embedded_data_size"] == 4
    assert image["hashes"][0]["algorithm"] == "sha256" and image["hashes"][0]["valid"]
    with pytest.raises(fw.FirmwareError):
        fw.parse_fit(_fit()[:-3])


def _ihex(address: int, kind: int, payload: bytes) -> str:
    record = bytes([len(payload)]) + address.to_bytes(2, "big") + bytes([kind]) + payload
    return ":" + (record + bytes([-sum(record) & 0xFF])).hex().upper()


def test_intel_hex_extended_address_entry_segments_and_conflict():
    text = "\n".join([_ihex(0, 4, b"\x00\x01"), _ihex(0x10, 0, b"ABCD"),
                       _ihex(0, 5, b"\x00\x01\x00\x10"), _ihex(0, 1, b"")])
    report = fw.parse_intel_hex(text)
    assert report["base_address"] == 0x10010 and report["entry_address"] == 0x10010
    assert report["segments"][0]["data"] == b"ABCD"
    conflict = "\n".join([_ihex(0, 0, b"A"), _ihex(0, 0, b"B"), _ihex(0, 1, b"")])
    with pytest.raises(fw.FirmwareError, match="conflicting"):
        fw.parse_intel_hex(conflict)
    with pytest.raises(fw.FirmwareError, match="checksum"):
        fw.parse_intel_hex(_ihex(0, 1, b"")[:-2] + "00")


def _srec(kind: int, address: int, payload: bytes = b"") -> str:
    sizes = {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 6: 3, 7: 4, 8: 3, 9: 2}
    addr = address.to_bytes(sizes[kind], "big")
    count = len(addr) + len(payload) + 1
    body = bytes([count]) + addr + payload
    return f"S{kind}" + (body + bytes([~sum(body) & 0xFF])).hex().upper()


def test_srecord_all_structural_checks_and_carver_cli(tmp_path, capsys):
    text = "\n".join([_srec(0, 0, b"HDR"), _srec(1, 0x1000, b"DATA"),
                       _srec(5, 1), _srec(9, 0x1000)])
    report = fw.parse_srec(text)
    assert report["count_matches"] and report["entry_address"] == 0x1000
    assert report["segments"][0]["data"] == b"DATA"
    with pytest.raises(fw.FirmwareError, match="checksum"):
        fw.parse_srec(_srec(9, 0x1000)[:-2] + "00")
    assert fw.carve_firmware(text.encode())[0]["kind"] == "srec"

    blob = b"padding" + _uimage() + b"tail" + _squash()
    kinds = [(row["offset"], row["kind"]) for row in fw.carve_firmware(blob)]
    assert kinds == [(7, "uimage"), (7 + len(_uimage()) + 4, "squashfs")]
    fixture = tmp_path / "firmware.bin"
    fixture.write_bytes(blob)
    assert fw.main([str(fixture)]) == 0
    assert {row["kind"] for row in json.loads(capsys.readouterr().out)} == {"uimage", "squashfs"}
    assert fw.carve_firmware(b"hsqs" + b"\x00" * 200 + b"UBI#") == []
