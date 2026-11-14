from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import multiarch as multi  # noqa: E402
from contract import BuildError  # noqa: E402


ARCHES = tuple(multi.ARCHITECTURES)


@pytest.mark.parametrize("arch", ARCHES)
def test_marker_shellcode_embeds_exact_marker_and_has_uniform_contract(arch: str) -> None:
    marker = f"R5B_{arch}_OK\n".encode()
    build = multi.build_marker_shellcode(arch, marker)
    payload, placements = build
    assert payload[placements["marker"]:] == marker
    assert build.slice("marker") == marker
    assert build.strategy == "write-marker-exit"
    assert build.metadata["side_effect"] == "write stdout then exit"
    assert placements["write_syscall"] < placements["marker"]
    assert placements["exit_syscall"] < placements["marker"]
    assert multi.ARCHITECTURES[build.architecture].emulator in build.metadata["emulator"]


@pytest.mark.parametrize("arch", ARCHES)
def test_execve_shellcode_embeds_only_requested_nul_terminated_path(arch: str) -> None:
    build = multi.build_execve_shellcode(arch, "/r5b/fixture")
    offset = build.placements["path"]
    assert build.payload[offset:] == b"/r5b/fixture\x00"
    assert build.slice("path") == b"/r5b/fixture\x00"
    assert build.placements["execve_syscall"] < offset
    assert build.metadata["delivery"] == "none"


def test_arm_and_mips_endianness_are_real_instruction_endianness() -> None:
    arm_le = multi.build_marker_shellcode("arm", b"X").payload[:4]
    arm_be = multi.build_marker_shellcode("armbe", b"X").payload[:4]
    assert arm_le == arm_be[::-1]
    mips_be = multi.build_marker_shellcode("mips", b"X").payload[:4]
    mips_le = multi.build_marker_shellcode("mipsel", b"X").payload[:4]
    assert mips_be == mips_le[::-1]
    assert struct.unpack(">I", mips_be)[0] == 0x04110001


@pytest.mark.parametrize("arch", ARCHES)
def test_function_call_rop_maps_every_caller_value(arch: str) -> None:
    bits = multi.ARCHITECTURES[arch].bits
    word = bits // 8
    build = multi.build_call_rop(
        arch,
        loader_gadget=0x1000,
        function=0x2000,
        arguments=(0x11, 0x22),
        continuation=0x3000,
        scratch=0x44,
        stack_base=0x8000,
    )
    assert build.payload[:word] == (0x1000).to_bytes(word, multi.ARCHITECTURES[arch].endian)
    assert build.slice("loader_gadget") == build.payload[:word]
    assert build.slice(next(name for name in build.placements if name in {"r0", "x0", "a0"})) \
        == (0x11).to_bytes(word, multi.ARCHITECTURES[arch].endian)
    absolute = build.absolute_placements()
    assert absolute["loader_gadget"] == 0x8000
    assert "gadget_contract" in build.metadata
    function_label = "pc" if arch.startswith("arm") else {"aarch64": "x16", "mips": "t9", "mipsel": "t9", "riscv64": "t0"}[arch]
    assert int.from_bytes(build.slice(function_label), multi.ARCHITECTURES[arch].endian) == 0x2000


@pytest.mark.parametrize("arch", ARCHES)
def test_syscall_rop_maps_number_gadget_and_continuation(arch: str) -> None:
    build = multi.build_syscall_rop(
        arch,
        loader_gadget=0x1110,
        syscall_gadget=0x2220,
        syscall_number=multi.ARCHITECTURES[arch].write_syscall,
        arguments=(1, 0x404000, 12),
        continuation=0x3330,
    )
    number_label = {"arm": "r7", "armbe": "r7", "aarch64": "x8", "mips": "v0", "mipsel": "v0", "riscv64": "a7"}[arch]
    gadget_label = "pc" if arch.startswith("arm") else {"aarch64": "x16", "mips": "t9", "mipsel": "t9", "riscv64": "t0"}[arch]
    byteorder = multi.ARCHITECTURES[arch].endian
    assert int.from_bytes(build.slice(number_label), byteorder) == multi.ARCHITECTURES[arch].write_syscall
    assert int.from_bytes(build.slice(gadget_label), byteorder) == 0x2220
    assert build.strategy == "multiarch-syscall-rop"


def test_constraints_refuse_instead_of_returning_malformed_payloads() -> None:
    with pytest.raises(BuildError, match="unsupported"):
        multi.build_marker_shellcode("sparc", b"x")
    with pytest.raises(BuildError, match="1..255"):
        multi.build_marker_shellcode("arm", b"")
    with pytest.raises(BuildError, match="embedded NUL"):
        multi.build_execve_shellcode("aarch64", b"/bin\x00/sh")
    with pytest.raises(BuildError, match="forbidden"):
        multi.build_marker_shellcode("riscv64", b"X", bad_bytes={ord("X")})
    with pytest.raises(BuildError, match="at most"):
        multi.build_call_rop("mipsel", loader_gadget=1, function=2, arguments=range(5))
    with pytest.raises(BuildError, match="fit"):
        multi.build_syscall_rop(
            "arm", loader_gadget=1 << 32, syscall_gadget=2,
            syscall_number=4, arguments=(),
        )


def test_coverage_inventory_is_deterministic_and_complete() -> None:
    inventory = multi.available_builders()
    assert tuple(inventory) == ARCHES
    assert all(names == ("marker_shellcode", "execve_shellcode", "call_rop", "syscall_rop")
               for names in inventory.values())
