"""Independent Capstone and packing oracles for pwnkern multiarch gadgets."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest
from capstone import (
    CS_ARCH_ARM64,
    CS_ARCH_MIPS,
    CS_ARCH_RISCV,
    CS_MODE_BIG_ENDIAN,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MIPS32,
    CS_MODE_RISCVC,
    CS_MODE_RISCV32,
    CS_MODE_RISCV64,
    Cs,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import pwnkern_multiarch_gadgets as G  # noqa: E402


def _oracle(arch: int, mode: int, raw: bytes, address: int = 0x1000):
    """Instantiate Capstone independently of the engine under test."""

    return [
        (instruction.mnemonic, instruction.op_str, instruction.size)
        for instruction in Cs(arch, mode).disasm(raw, address)
    ]


@pytest.mark.parametrize(
    "raw,expected,primitive,transfer,delta",
    [
        (bytes.fromhex("c0035fd6"), [("ret", "", 4)],
         "aarch64-return", "x30", 0),
        (bytes.fromhex("010000d4"), [("svc", "#0", 4)],
         "aarch64-syscall", "kernel", 0),
        (bytes.fromhex("00021fd6"), [("br", "x16", 4)],
         "aarch64-indirect-branch", "x16", 0),
        (bytes.fromhex("00023fd6"), [("blr", "x16", 4)],
         "aarch64-indirect-call", "x16", 0),
        (bytes.fromhex("1f000091"), [("mov", "sp, x0", 4)],
         "aarch64-stack-pivot", "fallthrough", 0),
        (bytes.fromhex("fd7bc1a8c0035fd6"),
         [("ldp", "x29, x30, [sp], #0x10", 4), ("ret", "", 4)],
         "aarch64-frame-return", "x30", 16),
    ],
)
def test_aarch64_canonical_bytes_are_capstone_verified(
    raw, expected, primitive, transfer, delta
):
    assert _oracle(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, raw) == expected
    plan = G.analyze_gadget("aarch64", raw, address=0x1000)
    assert [(item.mnemonic, item.operands, item.size) for item in plan.instructions] == expected
    assert plan.primitive == primitive
    assert plan.transfer == transfer
    assert plan.stack_delta == delta
    assert plan.instruction_alignment == 4


@pytest.mark.parametrize(
    "architecture,mode,jr,jalr,syscall",
    [
        (
            "mips32le", CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN,
            bytes.fromhex("0800e00300000000"),
            bytes.fromhex("09f8200300000000"),
            bytes.fromhex("0c000000"),
        ),
        (
            "mips32be", CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN,
            bytes.fromhex("03e0000800000000"),
            bytes.fromhex("0320f80900000000"),
            bytes.fromhex("0000000c"),
        ),
    ],
)
def test_mips32_endianness_and_delay_slots_use_capstone_oracle(
    architecture, mode, jr, jalr, syscall
):
    assert _oracle(CS_ARCH_MIPS, mode, jr) == [("jr", "$ra", 4), ("nop", "", 4)]
    returned = G.analyze_gadget(architecture, jr, address=0x1000)
    assert returned.primitive == "mips32-return"
    assert returned.transfer == "ra"
    assert returned.has_delay_slot is True
    assert returned.delay_slot_instruction == "nop"

    assert _oracle(CS_ARCH_MIPS, mode, jalr) == [
        ("jalr", "$t9", 4), ("nop", "", 4)
    ]
    called = G.analyze_gadget(architecture, jalr, address=0x2000)
    assert called.primitive == "mips32-indirect-call"
    assert called.required_registers == ("t9",)
    assert called.clobbers == ("ra",)
    assert called.has_delay_slot is True

    assert _oracle(CS_ARCH_MIPS, mode, syscall) == [("syscall", "", 4)]
    trapped = G.analyze_gadget(architecture, syscall, address=0x3000)
    assert trapped.primitive == "mips32-syscall"
    assert trapped.has_delay_slot is False  # syscall is a trap, not a branch
    assert trapped.required_registers == ("v0", "a0", "a1", "a2", "a3")


def test_mips_delay_slot_stack_adjustment_has_explicit_effects():
    # jr $ra ; addiu $sp,$sp,0x20 (little endian words 0x03e00008,
    # 0x27bd0020).  The second instruction executes before the transfer.
    raw = bytes.fromhex("0800e0032000bd27")
    mode = CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN
    assert _oracle(CS_ARCH_MIPS, mode, raw) == [
        ("jr", "$ra", 4), ("addiu", "$sp, $sp, 0x20", 4)
    ]
    plan = G.analyze_gadget("mips32le", raw, address=0x1000)
    assert plan.primitive == "mips32-return"
    assert plan.stack_delta == 0x20
    assert plan.clobbers == ("sp",)
    assert plan.delay_slot_instruction == "addiu $sp, $sp, 0x20"


def test_mips_unknown_delay_slot_side_effect_is_rejected():
    # jr $ra ; move $v0,$zero has a real side effect that the focused model
    # deliberately refuses instead of reporting an incorrect empty clobber set.
    raw = bytes.fromhex("0800e00325100000")
    assert _oracle(
        CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN, raw
    ) == [("jr", "$ra", 4), ("move", "$v0, $zero", 4)]
    with pytest.raises(G.PwnkernGadgetError, match="delay-slot side effect"):
        G.analyze_gadget("mips32le", raw)


@pytest.mark.parametrize(
    "architecture,mode",
    [("rv32", CS_MODE_RISCV32), ("rv64", CS_MODE_RISCV64)],
)
def test_riscv_base_and_compressed_transfers_use_capstone_oracle(architecture, mode):
    ret = bytes.fromhex("67800000")
    ecall = bytes.fromhex("73000000")
    assert _oracle(CS_ARCH_RISCV, mode, ret) == [("ret", "", 4)]
    assert G.analyze_gadget(architecture, ret).primitive == "riscv-return"
    assert _oracle(CS_ARCH_RISCV, mode, ecall) == [("ecall", "", 4)]
    assert G.analyze_gadget(architecture, ecall).primitive == "riscv-syscall"

    compressed_mode = mode | CS_MODE_RISCVC
    compressed_jump = bytes.fromhex("0281")
    compressed_call = bytes.fromhex("0291")
    assert _oracle(CS_ARCH_RISCV, compressed_mode, compressed_jump) == [
        ("c.jr", "sp", 2)
    ]
    jump = G.analyze_gadget(architecture, compressed_jump, rvc=True, address=0x1002)
    assert jump.primitive == "riscv-compressed-stack-jump"
    assert jump.transfer == "sp"
    assert jump.instruction_alignment == 2

    assert _oracle(CS_ARCH_RISCV, compressed_mode, compressed_call) == [
        ("c.jalr", "sp", 2)
    ]
    call = G.analyze_gadget(architecture, compressed_call, rvc=True, address=0x1002)
    assert call.primitive == "riscv-compressed-stack-call"
    assert call.clobbers == ("ra",)


def test_aarch64_epilogue_frame_matches_manual_struct_pack_oracle():
    gadget = bytes.fromhex("fd7bc1a8c0035fd6")
    built = G.build_aarch64_epilogue_frame(
        gadget,
        gadget_address=0x401000,
        frame_address=0x404000,
        next_frame_pointer=0x405000,
        continuation=0x402000,
    )
    assert built.payload == struct.pack("<QQ", 0x405000, 0x402000)
    assert built.placements() == {"next_frame_pointer": 0, "continuation": 8}
    assert built.absolute_placements() == {
        "next_frame_pointer": 0x404000,
        "continuation": 0x404008,
    }
    assert built.gadget.primitive == "aarch64-frame-return"
    assert built.gadget.required_registers == ("sp",)
    assert built.gadget.clobbers == ("x29", "x30", "sp")
    assert built.gadget.stack_delta == 16


def test_incomplete_mips_transfer_and_trailing_undecoded_bytes_fail_closed():
    with pytest.raises(G.PwnkernGadgetError, match="delay-slot"):
        G.analyze_gadget("mips32le", bytes.fromhex("0800e003"))

    # Capstone decodes RET and stops before the invalid all-ones instruction.
    raw = bytes.fromhex("c0035fd6ffffffff")
    assert _oracle(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, raw) == [("ret", "", 4)]
    with pytest.raises(G.PwnkernGadgetError, match="trailing"):
        G.analyze_gadget("aarch64", raw)


@pytest.mark.parametrize(
    "call",
    [
        lambda: G.analyze_gadget("aarch64", "c0035fd6"),
        lambda: G.analyze_gadget("aarch64", b""),
        lambda: G.analyze_gadget("sparc", b"\x00\x00\x00\x00"),
        lambda: G.analyze_gadget("aarch64", b"\x00" * (G.MAX_GADGET_BYTES + 1)),
        lambda: G.analyze_gadget("aarch64", bytes.fromhex("c0035fd6"), address=True),
        lambda: G.analyze_gadget("aarch64", bytes.fromhex("c0035fd6"), address=2),
        lambda: G.analyze_gadget("aarch64", bytes.fromhex("c0035fd6"), rvc=True),
        lambda: G.analyze_gadget("rv64", bytes.fromhex("0281"), rvc=False),
        lambda: G.analyze_gadget("rv32", bytes.fromhex("67800000"), address=(1 << 32) - 2),
    ],
)
def test_malformed_analyzer_inputs_raise_only_declared_error(call):
    with pytest.raises(G.PwnkernGadgetError):
        call()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"gadget_address": 1, "frame_address": 0x404000,
         "next_frame_pointer": 0x405000, "continuation": 0x402000},
        {"gadget_address": 0x401000, "frame_address": 0x404008,
         "next_frame_pointer": 0x405000, "continuation": 0x402000},
        {"gadget_address": 0x401000, "frame_address": 0x404000,
         "next_frame_pointer": 0x405008, "continuation": 0x402000},
        {"gadget_address": 0x401000, "frame_address": 0x404000,
         "next_frame_pointer": 0x405000, "continuation": 0x402002},
    ],
)
def test_aarch64_frame_rejects_misaligned_addresses(kwargs):
    with pytest.raises(G.PwnkernGadgetError):
        G.build_aarch64_epilogue_frame(bytes.fromhex("fd7bc1a8c0035fd6"), **kwargs)


def test_aarch64_frame_refuses_a_different_valid_gadget():
    with pytest.raises(G.PwnkernGadgetError, match="not ldp"):
        G.build_aarch64_epilogue_frame(
            bytes.fromhex("c0035fd6"),
            gadget_address=0x401000,
            frame_address=0x404000,
            next_frame_pointer=0,
            continuation=0x402000,
        )


def test_guarded_argparse_cli_returns_codes_and_json(capsys):
    assert G.main([
        "analyze", "aarch64", "fd7bc1a8c0035fd6",
        "--address", "0x401000", "--json",
    ]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["primitive"] == "aarch64-frame-return"
    assert report["stack_delta"] == 16

    assert G.main(["--help"]) == 0
    help_output = capsys.readouterr().out
    assert "a64-frame" in help_output

    assert G.main(["analyze", "not-an-arch", "00"]) == 2
    parse_error = capsys.readouterr().err
    assert "invalid choice" in parse_error
    assert "Traceback" not in parse_error

    assert G.main(["analyze", "aarch64", "not-hex"]) == 2
    engine_error = capsys.readouterr().err
    assert engine_error.startswith("pwnkern_multiarch_gadgets.py:")
    assert "Traceback" not in engine_error


def test_aarch64_frame_cli_uses_the_same_manual_wire_layout(capsys):
    assert G.main([
        "a64-frame", "fd7bc1a8c0035fd6",
        "--gadget-address", "0x401000",
        "--frame-address", "0x404000",
        "--next-fp", "0x405000",
        "--continuation", "0x402000",
        "--json",
    ]) == 0
    report = json.loads(capsys.readouterr().out)
    assert bytes.fromhex(report["payload_hex"]) == struct.pack(
        "<QQ", 0x405000, 0x402000
    )
    assert report["consumed_bytes"] == 16


def test_cli_rejects_non_sequence_argv_without_leaking_typeerror(capsys):
    assert G.main(42) == 2
    captured = capsys.readouterr()
    assert "malformed argv" in captured.err
    assert "Traceback" not in captured.err
