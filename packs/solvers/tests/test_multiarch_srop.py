"""Exact field-map tests for non-x86 Linux sigreturn builders."""
from pathlib import Path
import sys

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import multiarch_srop as srop  # noqa: E402
from contract import BuildError  # noqa: E402


def _value(build, label):
    return int.from_bytes(build.slice(label), "big" if build.architecture == "mips" else "little")


def _pwntools_frame(architecture, endian, bits, values):
    """Build a reference without inheriting process-global pwntools context."""

    from pwnlib.context import context
    from pwnlib.rop.srop import SigreturnFrame

    with context.local(
        arch=architecture,
        bits=bits,
        endian=endian,
        os="linux",
        kernel=None,
    ):
        reference = SigreturnFrame()
        for name, value in values.items():
            setattr(reference, name, value)
        return bytes(reference)


def test_arm_frame_is_byte_identical_to_pwntools_linux_layout():
    pytest.importorskip("pwnlib")

    values = {"r0": 11, "r1": 0x601000, "r2": 0, "r7": 11,
              "sp": 0x602000, "pc": 0x10400}
    build = srop.build_sigreturn_frame("arm", values)
    assert len(build.payload) == 240
    assert build.payload == _pwntools_frame("arm", "little", 32, values)
    assert _value(build, "frame.vfpu_magic") == 0x56465001


def test_aarch64_frame_is_byte_identical_to_pwntools_and_exposes_pstate():
    pytest.importorskip("pwnlib")

    values = {"x0": 0x4000, "x1": 0, "x2": 0, "x8": 221,
              "sp": 0x800000, "pc": 0x401000}
    build = srop.build_sigreturn_frame("aarch64", values)
    assert len(build.payload) == 600
    assert build.payload == _pwntools_frame("aarch64", "little", 64, values)
    with_pstate = srop.build_sigreturn_frame("aarch64", {**values, "pstate": 0x20000000})
    assert _value(with_pstate, "frame.pstate") == 0x20000000


@pytest.mark.parametrize("architecture,endian,length", [("mips", "big", 296), ("mipsel", "little", 292)])
def test_mips_big_and_little_frames_match_pwntools(architecture, endian, length):
    pytest.importorskip("pwnlib")

    values = {"v0": 4011, "a0": 0x601000, "a1": 0, "a2": 0,
              "sp": 0x602000, "pc": 0x401000}
    expected = _pwntools_frame("mips", endian, 32, values)
    build = srop.build_sigreturn_frame(architecture, values)
    assert len(build.payload) == length
    assert build.payload == expected
    assert _value(build, "frame.v0") == 4011


def test_riscv64_complete_rt_frame_uses_linux_uapi_offsets_and_end_header():
    values = {"a0": 0x601000, "a1": 0, "a2": 0, "a7": 221,
              "sp": 0x800000, "pc": 0x401000, "ra": 0x401100}
    build = srop.build_sigreturn_frame("riscv64", values, frame_address=0x900000)
    assert len(build.payload) == 1088
    assert build.placements["frame.pc"] == 304
    assert build.placements["frame.a0"] == 384
    assert build.placements["frame.a7"] == 440
    assert _value(build, "frame.pc") == 0x401000
    assert _value(build, "frame.sp") == 0x800000
    assert build.payload[1080:1088] == b"\x00" * 8
    assert build.absolute_placements()["frame.pc"] == 0x900000 + 304


@pytest.mark.parametrize("architecture", ["arm", "aarch64", "mips", "mipsel", "riscv64"])
def test_execve_srop_sets_per_abi_syscall_and_argument_registers(architecture):
    spec = srop.sigreturn_abi(architecture)
    setup = (0x41414141, spec.sigreturn_syscall)
    if spec.bits == 64:
        setup = (0x4141414141414141, spec.sigreturn_syscall)
    overflow_offset = 20 if spec.bits == 32 else 8
    build = srop.build_srop_execve(
        architecture,
        command_address=0x601000,
        stack_address=0x800000,
        syscall_gadget=0x401000,
        setup_words=setup,
        sigreturn_number_index=1,
        overflow_offset=overflow_offset,
        payload_address=0x700000,
    )
    assert _value(build, f"frame.{spec.syscall_register}") == spec.execve_syscall
    assert _value(build, f"frame.{spec.argument_registers[0]}") == 0x601000
    assert _value(build, f"frame.{spec.pc_register}") == 0x401000
    assert build.slice("sigreturn_frame") == build.payload[build.placements["sigreturn_frame"]:]


def test_generic_trigger_validates_sigreturn_number_and_stack_alignment():
    with pytest.raises(BuildError, match="must equal 139"):
        srop.build_srop_trigger(
            "aarch64", {"sp": 0x800000, "pc": 0x401000},
            setup_words=(1, 2), sigreturn_number_index=1, syscall_gadget=0x401000,
        )
    with pytest.raises(BuildError, match="16-byte aligned"):
        srop.build_sigreturn_frame("riscv64", {"sp": 0x800008})
    with pytest.raises(BuildError, match="unknown arm"):
        srop.build_sigreturn_frame("arm", {"x0": 1})


@pytest.mark.parametrize(
    "architecture,frame_address,bits",
    [("arm", (1 << 32) - 1, 32), ("aarch64", (1 << 64) - 16, 64)],
)
def test_sigreturn_frame_rejects_address_space_wrap(architecture, frame_address, bits):
    with pytest.raises(BuildError, match=rf"exceeds the {bits}-bit address space"):
        srop.build_sigreturn_frame(architecture, {}, frame_address=frame_address)


@pytest.mark.parametrize(
    "architecture,frame_address,alignment",
    [("arm", 4, 8), ("aarch64", 1, 16), ("mips", 4, 8), ("riscv64", 8, 16)],
)
def test_sigreturn_frame_enforces_abi_frame_alignment(
    architecture, frame_address, alignment
):
    with pytest.raises(BuildError, match=rf"must be {alignment}-byte aligned"):
        srop.build_sigreturn_frame(architecture, {}, frame_address=frame_address)


def test_srop_trigger_rejects_full_payload_address_space_wrap():
    with pytest.raises(BuildError, match="SROP payload exceeds the 32-bit address space"):
        srop.build_srop_trigger(
            "arm", {}, setup_words=(119,), sigreturn_number_index=0,
            syscall_gadget=0x1000, payload_address=(1 << 32) - 9,
        )


def test_srop_setup_word_cap_accepts_boundary_and_rejects_invalid_shapes():
    setup = (119,) + (0,) * (srop.MAX_SETUP_WORDS - 1)
    boundary = srop.build_srop_trigger(
        "arm", {}, setup_words=setup, sigreturn_number_index=0,
        syscall_gadget=0x1000, overflow_offset=4,
    )
    assert len([name for name in boundary.placements if name.startswith("setup[")]) == 256

    invalid = ((), b"\x77", "119", [119] * (srop.MAX_SETUP_WORDS + 1))
    for value in invalid:
        with pytest.raises(BuildError, match="setup_words"):
            srop.build_srop_trigger(
                "arm", {}, setup_words=value, sigreturn_number_index=0,
                syscall_gadget=0x1000,
            )

