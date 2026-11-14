"""Structural embedded firmware and architecture tests."""
from __future__ import annotations

import ast
import struct
import sys
import zlib
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import embedded_firmware as firmware  # noqa: E402


def _elf(machine: int, flags: int = 0, endian: str = "little") -> bytes:
    order = "<" if endian == "little" else ">"
    data = bytearray(96)
    data[:7] = b"\x7fELF\x02" + (b"\x01" if endian == "little" else b"\x02") + b"\x01"
    struct.pack_into(order + "H", data, 18, machine)
    struct.pack_into(order + "I", data, 20, 1)
    struct.pack_into(order + "I", data, 48, flags)
    struct.pack_into(order + "H", data, 52, 64)
    return bytes(data)


def _uimage(payload: bytes, arch: int = 2) -> bytes:
    name = b"r5d-kernel".ljust(32, b"\0")
    values = [0x27051956, 0, 1234, len(payload), 0x8000, 0x8001,
              zlib.crc32(payload) & 0xFFFFFFFF, 5, arch, 2, 0, name]
    header = bytearray(struct.pack(">7I4B32s", *values))
    struct.pack_into(">I", header, 4, zlib.crc32(header) & 0xFFFFFFFF)
    return bytes(header) + payload


def _dtb() -> bytes:
    total = 64
    header = struct.pack(">10I", 0xD00DFEED, total, 56, 60, 40, 17, 16, 0, 4, 4)
    return header + b"\0" * 16 + b"\x00\x00\x00\x09" + b"x\0\0\0"


def _squashfs() -> bytes:
    data = bytearray(128)
    data[:4] = b"hsqs"
    struct.pack_into("<4I", data, 4, 10, 1234, 131072, 1)
    struct.pack_into("<6H", data, 20, 1, 17, 0, 1, 4, 0)
    struct.pack_into("<Q", data, 40, 128)
    return bytes(data)


def test_validated_embedded_elf_architectures_and_flags():
    arm = firmware.analyze_firmware(_elf(40, 5 << 24))
    arm_lead = next(row for row in arm.leads if row.name == "arm")
    assert arm_lead.confidence == 100
    assert "ARM EABI version 5" in arm_lead.evidence

    mips = firmware.analyze_firmware(_elf(8, endian="big"))
    assert any(row.name == "mips" and "big" in row.evidence[0] for row in mips.leads)
    riscv = firmware.analyze_firmware(_elf(243, flags=1))
    assert any(row.name == "riscv" and "RVC enabled" in row.evidence for row in riscv.leads)


def test_uimage_crc_architecture_and_truncation():
    image = _uimage(b"KERNEL", arch=26)
    component = firmware.parse_uimage(image)
    assert component.verified is True
    details = dict(component.details)
    assert details["architecture"] == "riscv"
    assert details["header_crc"] == details["data_crc"] == "valid"
    report = firmware.analyze_firmware(b"PADDING" + image)
    assert any(row.kind == "uimage" and row.offset == 7 for row in report.components)
    assert any(row.category == "architecture" and row.name == "riscv" for row in report.leads)

    corrupt = bytearray(image)
    corrupt[-1] ^= 1
    assert firmware.parse_uimage(bytes(corrupt)).verified is False
    with pytest.raises(firmware.FirmwareInputError, match="truncated"):
        firmware.parse_uimage(image[:-1])


def test_dtb_and_squashfs_structural_bounds():
    dtb = firmware.parse_dtb(_dtb())
    assert dtb.verified and dict(dtb.details)["version"] == "17"
    squash = firmware.parse_squashfs(_squashfs())
    assert squash.verified and squash.declared_size == 128
    report = firmware.analyze_firmware(_dtb() + _squashfs())
    assert [row.kind for row in report.components] == ["dtb", "squashfs"]

    bad_dtb = bytearray(_dtb())
    struct.pack_into(">I", bad_dtb, 4, 9999)
    with pytest.raises(firmware.FirmwareInputError, match="truncated"):
        firmware.parse_dtb(bytes(bad_dtb))
    no_reserve_end = bytearray(_dtb())
    struct.pack_into(">QQ", no_reserve_end, 40, 1, 1)
    with pytest.raises(firmware.FirmwareInputError, match="terminator"):
        firmware.parse_dtb(bytes(no_reserve_end))
    overlap = bytearray(_dtb())
    struct.pack_into(">I", overlap, 12, 58)
    with pytest.raises(firmware.FirmwareInputError, match="overlap"):
        firmware.parse_dtb(bytes(overlap))
    reserve_overlap = bytearray(_dtb())
    struct.pack_into(">I", reserve_overlap, 8, 40)
    with pytest.raises(firmware.FirmwareInputError, match="reservation map overlaps"):
        firmware.parse_dtb(bytes(reserve_overlap))
    no_end_token = bytearray(_dtb())
    no_end_token[56:60] = b"\0\0\0\x01"
    with pytest.raises(firmware.FirmwareInputError, match="FDT_END"):
        firmware.parse_dtb(bytes(no_end_token))
    bad_squash = bytearray(_squashfs())
    struct.pack_into("<H", bad_squash, 28, 3)
    with pytest.raises(firmware.FirmwareInputError, match="superblock"):
        firmware.parse_squashfs(bytes(bad_squash))
    bad_log = bytearray(_squashfs())
    struct.pack_into("<H", bad_log, 22, 16)
    with pytest.raises(firmware.FirmwareInputError, match="superblock"):
        firmware.parse_squashfs(bytes(bad_log))
    huge_declared = bytearray(_squashfs())
    struct.pack_into("<Q", huge_declared, 40, firmware.MAX_FIRMWARE + 1)
    with pytest.raises(firmware.FirmwareInputError, match="superblock"):
        firmware.parse_squashfs(bytes(huge_declared))
    bad_compression = bytearray(_squashfs())
    struct.pack_into("<H", bad_compression, 20, 0)
    with pytest.raises(firmware.FirmwareInputError, match="superblock"):
        firmware.parse_squashfs(bytes(bad_compression))


def test_cortex_vector_and_raw_instruction_leads_require_correlated_evidence():
    cortex = struct.pack("<II", 0x20001000, 0x08000101) + b"\0" * 64
    report = firmware.analyze_firmware(cortex)
    assert any(row.name == "arm-cortex-m" and row.confidence == 96 for row in report.leads)

    riscv = b"\x13\x01\x01\xff" + b"X" * 8 + b"\x67\x80\x00\x00"
    assert any(row.name == "riscv" for row in firmware.analyze_firmware(riscv).leads)
    assert not any(row.category == "architecture" for row in firmware.analyze_firmware(b"only \x13\x01\x01\xff").leads)

    # SRAM-looking data plus an odd but implausible reset value is not enough.
    accidental = struct.pack("<II", 0x20001000, 3) + b"\0" * 64
    assert not any(row.name == "arm-cortex-m" for row in firmware.analyze_firmware(accidental).leads)
    weak_arm_fragments = b"\x2d\xe9" + b"X" * 16 + b"\x10\xb5"
    assert not any(row.name == "arm" for row in firmware.analyze_firmware(weak_arm_fragments).leads)
    far_riscv = b"\x13\x01\x01\xff" + b"X" * 0x10001 + b"\x67\x80\x00\x00"
    assert not any(row.name == "riscv" for row in firmware.analyze_firmware(far_riscv).leads)


def test_invalid_magic_hits_are_rejected_as_warnings_not_components():
    report = firmware.analyze_firmware(b"prefix" + b"hsqs" + b"\0" * 100)
    assert report.components == ()
    assert any("rejected SquashFS marker" in warning for warning in report.warnings)
    assert not any(row.category == "architecture" for row in firmware.analyze_firmware(_elf(62)).leads)


def test_caps_types_and_ast_safety(monkeypatch):
    with pytest.raises(TypeError, match="bytes"):
        firmware.analyze_firmware(bytearray(b"x"))  # type: ignore[arg-type]
    monkeypatch.setattr(firmware, "MAX_FIRMWARE", 3)
    with pytest.raises(firmware.FirmwareInputError, match="cap"):
        firmware.analyze_firmware(b"1234")
    tree = ast.parse((REPO / "solvers" / "binary" / "embedded_firmware.py").read_text())
    imports = {alias.name.split(".")[0] for node in ast.walk(tree)
               if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
    calls = {node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not imports & {"subprocess", "socket", "requests", "marshal", "pickle", "importlib"}
    assert not calls & {"open", "exec", "eval", "compile", "__import__"}
