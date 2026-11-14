#!/usr/bin/env python3
"""Offline Capstone validation for focused non-x86 pwn primitives.

The existing :mod:`gadget_catalog` efficiently finds a small set of exact byte
signatures in ELF executable regions.  This module complements it: callers
provide the candidate bytes and address, and Capstone must decode *all* bytes
before a bounded semantic plan is returned.  It does not parse ELF files,
execute input, open sockets, or infer addresses.

Supported profiles are AArch64 little-endian, MIPS32 little/big-endian, and
RV32/RV64 with optional compressed instructions.  MIPS indirect transfers are
accepted only when their final delay-slot instruction is present.

CLI examples::

    ./.venv/bin/python solvers/toolkits/pwnkern_multiarch_gadgets.py \
        analyze aarch64 fd7bc1a8c0035fd6 --address 0x401000 --json
    ./.venv/bin/python solvers/toolkits/pwnkern_multiarch_gadgets.py \
        a64-frame fd7bc1a8c0035fd6 --gadget-address 0x401000 \
        --frame-address 0x404000 --next-fp 0x405000 \
        --continuation 0x402000 --json
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass
from typing import Sequence

try:
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
        CsError,
    )
except ImportError as exc:  # pragma: no cover - dependency is installed in the solver image
    CS_ARCH_ARM64 = CS_ARCH_MIPS = CS_ARCH_RISCV = 0
    CS_MODE_BIG_ENDIAN = CS_MODE_LITTLE_ENDIAN = CS_MODE_MIPS32 = 0
    CS_MODE_RISCVC = CS_MODE_RISCV32 = CS_MODE_RISCV64 = 0
    Cs = None  # type: ignore[assignment]
    CsError = Exception  # type: ignore[assignment,misc]
    _CAPSTONE_IMPORT_ERROR: ImportError | None = exc
else:
    _CAPSTONE_IMPORT_ERROR = None


MAX_GADGET_BYTES = 256
MAX_INSTRUCTIONS = 64


class PwnkernGadgetError(ValueError):
    """Malformed, unsupported, or incompletely decoded gadget input."""


@dataclass(frozen=True)
class DecodedInstruction:
    """One instruction from a complete Capstone decode."""

    address: int
    size: int
    mnemonic: str
    operands: str
    raw: bytes

    def as_dict(self) -> dict[str, object]:
        return {
            "address": self.address,
            "size": self.size,
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "bytes": self.raw.hex(),
        }


@dataclass(frozen=True)
class GadgetPlan:
    """Auditable semantics for caller-supplied candidate bytes."""

    architecture: str
    bits: int
    endian: str
    address: int
    raw: bytes
    instructions: tuple[DecodedInstruction, ...]
    primitive: str
    transfer: str
    required_registers: tuple[str, ...]
    clobbers: tuple[str, ...]
    stack_delta: int
    has_delay_slot: bool
    delay_slot_instruction: str | None
    instruction_alignment: int

    def as_dict(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "bits": self.bits,
            "endian": self.endian,
            "address": self.address,
            "bytes": self.raw.hex(),
            "instructions": [instruction.as_dict() for instruction in self.instructions],
            "primitive": self.primitive,
            "transfer": self.transfer,
            "required_registers": list(self.required_registers),
            "clobbers": list(self.clobbers),
            "stack_delta": self.stack_delta,
            "has_delay_slot": self.has_delay_slot,
            "delay_slot_instruction": self.delay_slot_instruction,
            "instruction_alignment": self.instruction_alignment,
        }


@dataclass(frozen=True)
class AArch64EpilogueFrame:
    """The two stack words consumed by ``ldp x29,x30,[sp],#16; ret``."""

    gadget_address: int
    frame_address: int
    next_frame_pointer: int
    continuation: int
    payload: bytes
    gadget: GadgetPlan

    def placements(self) -> dict[str, int]:
        return {"next_frame_pointer": 0, "continuation": 8}

    def absolute_placements(self) -> dict[str, int]:
        return {
            name: self.frame_address + offset
            for name, offset in self.placements().items()
        }

    def as_dict(self) -> dict[str, object]:
        return {
            "gadget_address": self.gadget_address,
            "frame_address": self.frame_address,
            "next_frame_pointer": self.next_frame_pointer,
            "continuation": self.continuation,
            "payload_hex": self.payload.hex(),
            "placements": self.placements(),
            "absolute_placements": self.absolute_placements(),
            "consumed_bytes": len(self.payload),
            "gadget": self.gadget.as_dict(),
        }


@dataclass(frozen=True)
class _Architecture:
    name: str
    bits: int
    endian: str
    capstone_arch: int
    capstone_mode: int
    base_alignment: int


_ARCHITECTURES = {
    "aarch64": _Architecture(
        "aarch64", 64, "little", CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, 4
    ),
    "mips32le": _Architecture(
        "mips32le", 32, "little", CS_ARCH_MIPS,
        CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN, 4,
    ),
    "mips32be": _Architecture(
        "mips32be", 32, "big", CS_ARCH_MIPS,
        CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN, 4,
    ),
    "rv32": _Architecture(
        "rv32", 32, "little", CS_ARCH_RISCV, CS_MODE_RISCV32, 4
    ),
    "rv64": _Architecture(
        "rv64", 64, "little", CS_ARCH_RISCV, CS_MODE_RISCV64, 4
    ),
}

_ALIASES = {
    "arm64": "aarch64",
    "mips": "mips32be",
    "mipsbe": "mips32be",
    "mips32": "mips32be",
    "mipsel": "mips32le",
    "mipsle": "mips32le",
    "riscv32": "rv32",
    "riscv64": "rv64",
}


def _architecture(value: object, rvc: object) -> tuple[_Architecture, bool]:
    if not isinstance(value, str):
        raise PwnkernGadgetError("architecture must be text")
    if not isinstance(rvc, bool):
        raise PwnkernGadgetError("rvc must be a boolean")
    key = value.lower().replace("-", "").replace("_", "")
    key = _ALIASES.get(key, key)
    try:
        spec = _ARCHITECTURES[key]
    except KeyError as exc:
        choices = ", ".join(_ARCHITECTURES)
        raise PwnkernGadgetError(
            f"unsupported architecture {value!r}; choose {choices}"
        ) from exc
    if rvc and spec.name not in {"rv32", "rv64"}:
        raise PwnkernGadgetError("rvc is valid only for rv32 or rv64")
    return spec, rvc


def _uint(value: object, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PwnkernGadgetError(f"{name} must be an integer")
    if not 0 <= value < (1 << bits):
        raise PwnkernGadgetError(f"{name} does not fit in {bits} bits")
    return value


def _bounded_bytes(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise PwnkernGadgetError("gadget bytes must be bytes-like")
    try:
        raw = bytes(value)
    except (TypeError, ValueError, BufferError) as exc:
        raise PwnkernGadgetError("gadget bytes cannot be materialized") from exc
    if not raw:
        raise PwnkernGadgetError("gadget bytes must not be empty")
    if len(raw) > MAX_GADGET_BYTES:
        raise PwnkernGadgetError(
            f"gadget exceeds the {MAX_GADGET_BYTES}-byte analysis limit"
        )
    return raw


def _normalized(instruction: DecodedInstruction) -> tuple[str, str]:
    mnemonic = instruction.mnemonic.lower().strip()
    operands = instruction.operands.lower().replace("$", "").replace(" ", "")
    return mnemonic, operands


def _format_instruction(instruction: DecodedInstruction) -> str:
    return (
        f"{instruction.mnemonic} {instruction.operands}".strip()
    )


def _decode(
    spec: _Architecture, raw: bytes, address: int, rvc: bool
) -> tuple[DecodedInstruction, ...]:
    if _CAPSTONE_IMPORT_ERROR is not None or Cs is None:
        raise PwnkernGadgetError("Capstone is unavailable") from _CAPSTONE_IMPORT_ERROR
    alignment = 2 if rvc else spec.base_alignment
    if address % alignment:
        raise PwnkernGadgetError(
            f"address must be {alignment}-byte aligned for {spec.name}"
        )
    if len(raw) % alignment:
        raise PwnkernGadgetError(
            f"gadget length must be a multiple of {alignment} bytes"
        )
    if len(raw) > (1 << spec.bits) - address:
        raise PwnkernGadgetError("gadget address range wraps the target address space")
    mode = spec.capstone_mode | (CS_MODE_RISCVC if rvc else 0)
    try:
        engine = Cs(spec.capstone_arch, mode)
        decoded = tuple(
            DecodedInstruction(
                int(item.address), int(item.size), str(item.mnemonic),
                str(item.op_str), bytes(item.bytes),
            )
            for item in engine.disasm(raw, address)
        )
    except (CsError, TypeError, ValueError, OverflowError) as exc:
        raise PwnkernGadgetError(f"Capstone failed to decode gadget: {exc}") from exc
    if not decoded:
        raise PwnkernGadgetError("Capstone decoded no instructions")
    if len(decoded) > MAX_INSTRUCTIONS:
        raise PwnkernGadgetError(
            f"gadget exceeds the {MAX_INSTRUCTIONS}-instruction limit"
        )
    expected = address
    consumed = 0
    for instruction in decoded:
        if instruction.address != expected or instruction.size <= 0:
            raise PwnkernGadgetError("Capstone returned a discontinuous decode")
        expected += instruction.size
        consumed += instruction.size
    if consumed != len(raw):
        raise PwnkernGadgetError(
            f"Capstone left {len(raw) - consumed} trailing byte(s) undecoded"
        )
    return decoded


def _aarch64_semantics(
    instructions: tuple[DecodedInstruction, ...]
) -> tuple[str, str, tuple[str, ...], tuple[str, ...], int, bool, str | None]:
    ops = tuple(_normalized(item) for item in instructions)
    if ops == (("ret", ""),) or ops == (("ret", "x30"),):
        return "aarch64-return", "x30", ("x30",), (), 0, False, None
    if ops == (("svc", "#0"),):
        required = ("x8", "x0", "x1", "x2", "x3", "x4", "x5")
        return "aarch64-syscall", "kernel", required, ("x0",), 0, False, None
    if ops == (("br", "x16"),):
        return "aarch64-indirect-branch", "x16", ("x16",), (), 0, False, None
    if ops == (("blr", "x16"),):
        return "aarch64-indirect-call", "x16", ("x16",), ("x30",), 0, False, None
    if ops == (("mov", "sp,x0"),):
        return "aarch64-stack-pivot", "fallthrough", ("x0",), ("sp",), 0, False, None
    epilogue = (
        ("ldp", "x29,x30,[sp],#0x10"),
        ("ret", ""),
    )
    epilogue_explicit = (
        ("ldp", "x29,x30,[sp],#0x10"),
        ("ret", "x30"),
    )
    if ops in (epilogue, epilogue_explicit):
        return (
            "aarch64-frame-return", "x30", ("sp",),
            ("x29", "x30", "sp"), 16, False, None,
        )
    return "instruction-sequence", "fallthrough", (), (), 0, False, None


def _mips_semantics(
    instructions: tuple[DecodedInstruction, ...]
) -> tuple[str, str, tuple[str, ...], tuple[str, ...], int, bool, str | None]:
    ops = tuple(_normalized(item) for item in instructions)
    transfers = [
        index for index, (mnemonic, _operands) in enumerate(ops)
        if mnemonic in {"jr", "jalr"}
    ]
    if transfers:
        if len(transfers) != 1:
            raise PwnkernGadgetError("focused MIPS gadgets may contain one indirect transfer")
        transfer_index = transfers[0]
        if transfer_index == len(instructions) - 1:
            raise PwnkernGadgetError("MIPS transfer is missing its delay-slot instruction")
        if transfer_index != len(instructions) - 2:
            raise PwnkernGadgetError(
                "MIPS transfer and its delay slot must end the supplied gadget"
            )
        mnemonic, operands = ops[transfer_index]
        slot = _format_instruction(instructions[-1])
        slot_mnemonic, slot_operands = ops[-1]
        if (slot_mnemonic, slot_operands) == ("nop", ""):
            slot_delta = 0
            slot_clobbers: tuple[str, ...] = ()
        elif slot_mnemonic == "addiu":
            parts = slot_operands.split(",")
            if len(parts) != 3 or parts[:2] != ["sp", "sp"]:
                raise PwnkernGadgetError(
                    "unsupported MIPS delay-slot side effect"
                )
            try:
                slot_delta = int(parts[2], 0)
            except ValueError as exc:
                raise PwnkernGadgetError(
                    "invalid MIPS stack adjustment in delay slot"
                ) from exc
            slot_clobbers = ("sp",)
        else:
            raise PwnkernGadgetError(
                "unsupported MIPS delay-slot side effect"
            )
        if mnemonic == "jr" and operands == "ra":
            return (
                "mips32-return", "ra", ("ra",), slot_clobbers,
                slot_delta, True, slot,
            )
        if mnemonic == "jalr" and operands in {"t9", "ra,t9"}:
            return (
                "mips32-indirect-call", "t9", ("t9",),
                ("ra",) + slot_clobbers, slot_delta, True, slot,
            )
        return (
            "mips32-indirect-transfer", operands or "register",
            tuple(filter(None, (operands,))), slot_clobbers,
            slot_delta, True, slot,
        )
    if ops == (("syscall", ""),):
        required = ("v0", "a0", "a1", "a2", "a3")
        return "mips32-syscall", "kernel", required, ("v0", "a3"), 0, False, None
    return "instruction-sequence", "fallthrough", (), (), 0, False, None


def _riscv_semantics(
    instructions: tuple[DecodedInstruction, ...]
) -> tuple[str, str, tuple[str, ...], tuple[str, ...], int, bool, str | None]:
    ops = tuple(_normalized(item) for item in instructions)
    if ops == (("ret", ""),) or ops == (("c.jr", "ra"),):
        return "riscv-return", "ra", ("ra",), (), 0, False, None
    if ops == (("ecall", ""),):
        required = ("a7", "a0", "a1", "a2", "a3", "a4", "a5")
        return "riscv-syscall", "kernel", required, ("a0",), 0, False, None
    if ops == (("c.jr", "sp"),):
        return "riscv-compressed-stack-jump", "sp", ("sp",), (), 0, False, None
    if ops == (("c.jalr", "sp"),):
        return "riscv-compressed-stack-call", "sp", ("sp",), ("ra",), 0, False, None
    if ops == (("jr", "t0"),):
        return "riscv-indirect-jump", "t0", ("t0",), (), 0, False, None
    return "instruction-sequence", "fallthrough", (), (), 0, False, None


def analyze_gadget(
    architecture: str,
    code: bytes | bytearray | memoryview,
    *,
    address: int = 0,
    rvc: bool = False,
) -> GadgetPlan:
    """Decode every supplied byte and return a focused primitive plan.

    Valid but unrecognized sequences are returned as ``instruction-sequence``;
    incomplete decoding and incomplete MIPS delay-slot sequences are rejected.
    """

    try:
        spec, use_rvc = _architecture(architecture, rvc)
        raw = _bounded_bytes(code)
        checked_address = _uint(address, spec.bits, "address")
        instructions = _decode(spec, raw, checked_address, use_rvc)
        if spec.name == "aarch64":
            semantics = _aarch64_semantics(instructions)
        elif spec.name.startswith("mips"):
            semantics = _mips_semantics(instructions)
        else:
            semantics = _riscv_semantics(instructions)
        primitive, transfer, required, clobbers, delta, delay, slot = semantics
        return GadgetPlan(
            spec.name, spec.bits, spec.endian, checked_address, raw, instructions,
            primitive, transfer, required, clobbers, delta, delay, slot,
            2 if use_rvc else spec.base_alignment,
        )
    except PwnkernGadgetError:
        raise
    except (TypeError, ValueError, OverflowError, BufferError, struct.error) as exc:
        raise PwnkernGadgetError(f"invalid gadget input: {exc}") from exc


def build_aarch64_epilogue_frame(
    gadget_bytes: bytes | bytearray | memoryview,
    *,
    gadget_address: int,
    frame_address: int,
    next_frame_pointer: int,
    continuation: int,
) -> AArch64EpilogueFrame:
    """Build the exact frame consumed by a validated AArch64 epilogue.

    ``gadget_bytes`` must decode completely as
    ``ldp x29, x30, [sp], #0x10; ret`` at ``gadget_address``.  The returned
    payload is placed at ``frame_address``; entering the gadget with
    ``sp == frame_address`` restores the supplied values, advances SP by 16,
    and transfers to ``continuation``.  The gadget address is deliberately
    metadata rather than an assumed preceding stack word.
    """

    try:
        checked_gadget = _uint(gadget_address, 64, "gadget_address")
        checked_frame = _uint(frame_address, 64, "frame_address")
        checked_fp = _uint(next_frame_pointer, 64, "next_frame_pointer")
        checked_continuation = _uint(continuation, 64, "continuation")
        if checked_frame % 16:
            raise PwnkernGadgetError("frame_address must be 16-byte aligned")
        if checked_fp and checked_fp % 16:
            raise PwnkernGadgetError("next_frame_pointer must be zero or 16-byte aligned")
        if checked_continuation % 4:
            raise PwnkernGadgetError("continuation must be 4-byte aligned")
        gadget = analyze_gadget(
            "aarch64", gadget_bytes, address=checked_gadget, rvc=False
        )
        if gadget.primitive != "aarch64-frame-return":
            raise PwnkernGadgetError(
                "gadget is not ldp x29, x30, [sp], #0x10; ret"
            )
        payload = struct.pack("<QQ", checked_fp, checked_continuation)
        return AArch64EpilogueFrame(
            checked_gadget, checked_frame, checked_fp,
            checked_continuation, payload, gadget,
        )
    except PwnkernGadgetError:
        raise
    except (TypeError, ValueError, OverflowError, BufferError, struct.error) as exc:
        raise PwnkernGadgetError(f"invalid AArch64 frame input: {exc}") from exc


def _parse_integer(value: str) -> int:
    try:
        return int(value, 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc


def _parse_hex(value: object) -> bytes:
    if not isinstance(value, str):
        raise PwnkernGadgetError("hex bytes must be text")
    compact = "".join(value.split())
    if not compact:
        raise PwnkernGadgetError("hex bytes must not be empty")
    if len(compact) > MAX_GADGET_BYTES * 2:
        raise PwnkernGadgetError(
            f"hex gadget exceeds the {MAX_GADGET_BYTES}-byte limit"
        )
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise PwnkernGadgetError(f"invalid gadget hex: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnkern_multiarch_gadgets.py",
        description="offline Capstone validation for focused non-x86 pwn gadgets",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="decode and classify supplied bytes")
    analyze.add_argument("architecture", choices=tuple(_ARCHITECTURES))
    analyze.add_argument("hex_bytes", help="candidate bytes as hexadecimal")
    analyze.add_argument("--address", type=_parse_integer, default=0)
    analyze.add_argument("--rvc", action="store_true", help="enable compressed RISC-V")
    analyze.add_argument("--json", action="store_true")

    frame = subparsers.add_parser(
        "a64-frame", help="build a frame for ldp x29,x30,[sp],#16; ret"
    )
    frame.add_argument("hex_bytes", help="epilogue bytes as hexadecimal")
    frame.add_argument("--gadget-address", type=_parse_integer, required=True)
    frame.add_argument("--frame-address", type=_parse_integer, required=True)
    frame.add_argument("--next-fp", type=_parse_integer, required=True)
    frame.add_argument("--continuation", type=_parse_integer, required=True)
    frame.add_argument("--json", action="store_true")
    return parser


def _print_plan(plan: GadgetPlan, as_json: bool) -> None:
    if as_json:
        print(json.dumps(plan.as_dict(), indent=2, sort_keys=True))
        return
    print(
        f"{plan.architecture} @ {plan.address:#x}: {plan.primitive}; "
        f"transfer={plan.transfer}; stack_delta={plan.stack_delta}; "
        f"delay_slot={plan.has_delay_slot}"
    )
    for instruction in plan.instructions:
        print(
            f"  {instruction.address:#x}: {instruction.raw.hex():<16} "
            f"{_format_instruction(instruction)}"
        )


def main(argv: Sequence[str] | None = None) -> int:
    """Guarded CLI entry point; argparse exits are converted to return codes."""

    try:
        try:
            raw_argv = list(sys.argv[1:] if argv is None else argv)
        except Exception as exc:
            raise PwnkernGadgetError("malformed argv") from exc
        try:
            args = _parser().parse_args(raw_argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        if args.command == "analyze":
            plan = analyze_gadget(
                args.architecture,
                _parse_hex(args.hex_bytes),
                address=args.address,
                rvc=args.rvc,
            )
            _print_plan(plan, args.json)
        elif args.command == "a64-frame":
            frame = build_aarch64_epilogue_frame(
                _parse_hex(args.hex_bytes),
                gadget_address=args.gadget_address,
                frame_address=args.frame_address,
                next_frame_pointer=args.next_fp,
                continuation=args.continuation,
            )
            if args.json:
                print(json.dumps(frame.as_dict(), indent=2, sort_keys=True))
            else:
                print(
                    f"AArch64 epilogue frame @ {frame.frame_address:#x}: "
                    f"{frame.payload.hex()} -> {frame.continuation:#x}"
                )
        else:  # pragma: no cover - argparse enforces the command set
            raise PwnkernGadgetError("unsupported command")
        return 0
    except PwnkernGadgetError as exc:
        print(f"pwnkern_multiarch_gadgets.py: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
