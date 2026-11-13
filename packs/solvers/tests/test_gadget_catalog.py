"""Deterministic tests for the r5b static ELF gadget catalog."""
from pathlib import Path
import struct
import sys

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import gadget_catalog as catalog  # noqa: E402


def _elf64_segment(code: bytes, *, machine: int = 62, endian: str = "little") -> tuple[bytes, int]:
    ec = "<" if endian == "little" else ">"
    data_encoding = 1 if endian == "little" else 2
    ident = b"\x7fELF" + bytes((2, data_encoding, 1, 0)) + b"\x00" * 8
    code_offset = 64 + 56
    virtual = 0x400000 + code_offset
    header = ident + struct.pack(
        ec + "HHIQQQIHHHHHH",
        2, machine, 1, virtual, 64, 0, 0, 64, 56, 1, 0, 0, 0,
    )
    program = struct.pack(
        ec + "IIQQQQQQ", 1, 5, code_offset, virtual, virtual, len(code), len(code), 0x1000
    )
    return header + program + code, virtual


def _elf32_segment(code: bytes, *, machine: int = 3) -> tuple[bytes, int]:
    ident = b"\x7fELF" + bytes((1, 1, 1, 0)) + b"\x00" * 8
    code_offset = 52 + 32
    virtual = 0x8048000 + code_offset
    header = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        2, machine, 1, virtual, 52, 0, 0, 52, 32, 1, 0, 0, 0,
    )
    program = struct.pack(
        "<IIIIIIII", 1, code_offset, virtual, virtual, len(code), len(code), 5, 0x1000
    )
    return header + program + code, virtual


def test_amd64_catalog_finds_rop_jop_and_csu_signatures_without_execution():
    csu_pop = bytes.fromhex("5b5d415c415d415e415fc3")
    code = b"\x90\x5f\xc3\x0f\x05\xc3\xff\xe0" + csu_pop
    elf, base = _elf64_segment(code)
    result = catalog.catalog_elf(elf)
    assert result.architecture == "amd64"
    assert result.bits == 64
    assert result.require("pop rdi ; ret").address == base + 1
    assert result.require("syscall ; ret").raw == b"\x0f\x05\xc3"
    assert result.require("jmp rax").file_offset == 120 + 6
    assert result.require("csu pop rbx rbp r12 r13 r14 r15 ; ret").address == base + 8
    # x86 permits entry in the middle of ``41 5f c3``: both the explicit pop
    # rdi and the suffix of pop r15 are valid decodings at their own addresses.
    assert result.by_semantic()["pop rdi ; ret"] == (base + 1, base + 17)


def test_catalog_rebases_only_by_explicit_caller_bias_and_is_tuple_stable(tmp_path):
    elf, base = _elf64_segment(b"\x58\xc3\x5f\xc3")
    path = tmp_path / "fixture.elf"
    path.write_bytes(elf)
    result = catalog.catalog_elf(path, load_bias=0x55550000)
    assert result.require("pop rax ; ret").address == base + 0x55550000
    assert tuple(sorted(result.gadgets)) == result.gadgets
    picked = catalog.select_addresses(result, ["pop rdi ; ret", "ret"])
    assert picked["pop rdi ; ret"] == base + 2 + 0x55550000


def test_i386_and_aarch64_exact_encodings_are_arch_specific():
    elf32, base32 = _elf32_segment(b"\x58\xc3\xcd\x80\xc3")
    x86 = catalog.catalog_elf(elf32)
    assert x86.require("pop eax ; ret").address == base32
    assert x86.require("int 0x80 ; ret").address == base32 + 2
    assert not x86.find("syscall")

    arm_code = bytes.fromhex("c0035fd6010000d400021fd6")
    elf_arm, base_arm = _elf64_segment(arm_code, machine=183)
    arm = catalog.catalog_elf(elf_arm)
    assert arm.architecture == "aarch64"
    assert arm.require("ret").address == base_arm
    assert arm.require("svc #0").address == base_arm + 4
    assert arm.require("br x16").address == base_arm + 8

    unaligned, _ = _elf64_segment(b"\x90" + bytes.fromhex("c0035fd6"), machine=183)
    assert not catalog.catalog_elf(unaligned).find("ret")


def test_catalog_rejects_malformed_unbounded_and_ambiguous_requests():
    with pytest.raises(catalog.ELFParseError, match="not an ELF"):
        catalog.catalog_elf(b"not an elf")
    elf, _base = _elf64_segment(b"\x90" * 32)
    assert catalog.catalog_elf(elf).gadgets == ()
    elf_many, _ = _elf64_segment(b"\xc3" * 20)
    with pytest.raises(catalog.ELFParseError, match="gadget count"):
        catalog.catalog_elf(elf_many, max_gadgets=2)
    one, _ = _elf64_segment(b"\xc3")
    with pytest.raises(LookupError, match="required gadget absent"):
        catalog.catalog_elf(one).require("pop rdi ; ret")

