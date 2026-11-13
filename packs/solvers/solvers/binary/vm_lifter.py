"""Custom-VM lifter scaffold (B-165): decode / lift / interpret a one-off bytecode VM.

Many rev challenges ship a hand-rolled bytecode interpreter (a dispatch loop over a custom opcode
table). There is no generic semantic solve for one -- the agent still reverses the opcode meanings --
but every racer rebuilt the same harness: a decoder, a listing, and a reference interpreter to check
the opcode semantics against observed behaviour. This module is that harness.

The agent fills in a ``VMSpec`` (the opcode table, operand encodings, and -- for the optional
interpreter -- a handler per op). Then:

  disassemble(bytecode, spec)  -> list[VMInsn]   sequential decode; unknown/truncated raises, loud
  lift(insns, spec)            -> list[Lifted]    normalised, human-readable listing (IR templates)
  interpret(insns, spec, ...)  -> VMState         a stack+register reference machine, step-capped

Nothing here runs the challenge binary: ``interpret`` runs *the agent's own* handlers over the
decoded bytecode, so the agent can prove a hypothesised semantics against the challenge's I/O
without ever executing the sample. This module is import-only (manifest class ``library``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Sequence

__all__ = [
    "VMError",
    "VMDecodeError",
    "VMLiftError",
    "VMRuntimeError",
    "Operand",
    "VMOp",
    "VMSpec",
    "VMInsn",
    "Lifted",
    "VMState",
    "disassemble",
    "lift",
    "interpret",
]


class VMError(ValueError):
    """Base for custom-VM scaffold errors."""


class VMDecodeError(VMError):
    """The bytecode could not be decoded against the spec (unknown opcode, truncation)."""


class VMLiftError(VMError):
    """An IR template did not match its instruction's operands."""


class VMRuntimeError(VMError):
    """The reference interpreter could not continue (no handler, bad pc, step cap)."""


_ENDIANS = ("little", "big")


@dataclass(frozen=True)
class Operand:
    """One operand field that follows an opcode in the bytecode stream.

    size: width in bytes. kind is informational (imm | reg | rel | addr); decode is identical.
    endian "" inherits the spec default. signed uses two's-complement.
    """

    name: str = "op"
    size: int = 1
    kind: str = "imm"
    signed: bool = False
    endian: str = ""

    def __post_init__(self) -> None:
        if self.size <= 0:
            raise VMError(f"operand {self.name!r}: size must be > 0")
        if self.endian and self.endian not in _ENDIANS:
            raise VMError(f"operand {self.name!r}: endian must be little|big or empty")


@dataclass(frozen=True)
class VMOp:
    """One opcode's definition: its mnemonic, operand layout, and optional lift template.

    ``ir`` is a ``str.format`` template fed the decoded operand values, e.g. ``"r{0} = r{1} + {2}"``
    or ``"push {0}"``. When absent, ``lift`` renders ``name op0, op1, ...``.
    """

    name: str
    operands: tuple[Operand, ...] = ()
    ir: str | None = None


@dataclass
class VMSpec:
    """The custom VM the agent reverse-engineered.

    opcodes: opcode value -> VMOp. opcode_size: bytes of the opcode field. endian: default operand
    endianness. handlers: for the optional interpreter, ``name -> fn(state, operands)``; a handler
    mutates ``state`` (push/pop, set regs, append output), may set ``state.pc`` to jump, and sets
    ``state.halted`` to stop. max_steps caps the interpreter.
    """

    opcodes: Mapping[int, VMOp]
    opcode_size: int = 1
    endian: str = "little"
    handlers: Mapping[str, Callable[["VMState", tuple[int, ...]], None]] = field(default_factory=dict)
    max_steps: int = 1_000_000

    def __post_init__(self) -> None:
        if self.opcode_size <= 0:
            raise VMError("opcode_size must be > 0")
        if self.endian not in _ENDIANS:
            raise VMError("spec endian must be little|big")
        if not self.opcodes:
            raise VMError("spec has no opcodes")


@dataclass(frozen=True)
class VMInsn:
    offset: int
    opcode: int
    name: str
    operands: tuple[int, ...]
    size: int
    raw: bytes


@dataclass(frozen=True)
class Lifted:
    offset: int
    text: str


def disassemble(bytecode: bytes, spec: VMSpec, start: int = 0, count: int = 0) -> list[VMInsn]:
    """Linear-sweep decode ``bytecode`` against ``spec`` from ``start`` (``count`` caps the number).

    An opcode not in the table, or an operand that runs off the end, raises VMDecodeError naming the
    byte offset -- the decoder never guesses or skips.
    """
    data = bytes(bytecode)
    if start < 0:
        raise VMDecodeError(f"start offset {start} is negative (offsets count from the bytecode's first byte)")
    if count < 0:
        raise VMDecodeError(f"count {count} is negative (0 means no cap)")
    cur = start
    out: list[VMInsn] = []
    while cur < len(data):
        op_off = cur
        if cur + spec.opcode_size > len(data):
            raise VMDecodeError(f"truncated opcode at offset {op_off}")
        opcode = int.from_bytes(data[cur:cur + spec.opcode_size], spec.endian)
        cur += spec.opcode_size
        op = spec.opcodes.get(opcode)
        if op is None:
            raise VMDecodeError(f"unknown opcode 0x{opcode:0{spec.opcode_size * 2}x} at offset {op_off}")
        values: list[int] = []
        for od in op.operands:
            if cur + od.size > len(data):
                raise VMDecodeError(
                    f"truncated operand {od.name!r} of {op.name} at offset {op_off}"
                )
            values.append(
                int.from_bytes(data[cur:cur + od.size], od.endian or spec.endian, signed=od.signed)
            )
            cur += od.size
        out.append(VMInsn(op_off, opcode, op.name, tuple(values), cur - op_off, data[op_off:cur]))
        if count and len(out) >= count:
            break
    return out


def lift(insns: Sequence[VMInsn], spec: VMSpec) -> list[Lifted]:
    """Render each instruction to a normalised, human-readable line (IR template or ``name ops``)."""
    out: list[Lifted] = []
    for ins in insns:
        op = spec.opcodes.get(ins.opcode)
        if op is not None and op.ir:
            try:
                text = op.ir.format(*ins.operands)
            except (IndexError, KeyError) as exc:
                raise VMLiftError(
                    f"ir template {op.ir!r} of {ins.name} does not fit operands {ins.operands}: {exc}"
                ) from None
        elif ins.operands:
            text = f"{ins.name} " + ", ".join(str(v) for v in ins.operands)
        else:
            text = ins.name
        out.append(Lifted(ins.offset, text))
    return out


@dataclass
class VMState:
    pc: int = 0
    stack: list = field(default_factory=list)
    regs: dict = field(default_factory=dict)
    memory: dict = field(default_factory=dict)
    input: bytes = b""
    input_pos: int = 0
    output: bytearray = field(default_factory=bytearray)
    halted: bool = False
    steps: int = 0


def interpret(
    insns: Sequence[VMInsn],
    spec: VMSpec,
    *,
    input: bytes | None = None,
    max_steps: int | None = None,
    state: VMState | None = None,
    reset: bool = False,
) -> VMState:
    """Run the agent's handlers over the decoded instructions until a handler halts the machine.

    Execution is pc-driven: ``state.pc`` holds the byte offset of the next instruction, so handlers
    jump by assigning it. A pc that is not at a decoded instruction boundary, a missing handler, or
    running more than ``max_steps`` (default ``spec.max_steps``) instructions in this call each raise
    VMRuntimeError -- a runaway loop fails loudly instead of hanging the host.

    Fresh run (no ``state``): pc starts at the first instruction, input is ``input`` (or b"").
    Resume (``state`` given): execution continues from ``state.pc`` with ``state.input`` and
    ``state.input_pos`` kept, unless ``input`` is passed (replaces the input, rewinds input_pos) or
    ``reset=True`` (pc back to the first instruction). A handler that paused the machine by setting
    ``halted`` is resumed by clearing ``state.halted`` before the call. ``state.steps`` keeps the
    running total across calls.
    """
    if not insns:
        raise VMRuntimeError("no instructions to interpret")
    by_off = {ins.offset: ins for ins in insns}
    if state is None:
        st = VMState(pc=insns[0].offset, input=bytes(input or b""))
    else:
        st = state
        if input is not None:
            st.input = bytes(input)
            st.input_pos = 0
        if reset:
            st.pc = insns[0].offset
    limit = spec.max_steps if max_steps is None else max_steps
    ran = 0
    while not st.halted:
        if ran >= limit:
            raise VMRuntimeError(f"exceeded {limit} steps at pc {st.pc} (infinite loop?)")
        ran += 1
        st.steps += 1
        ins = by_off.get(st.pc)
        if ins is None:
            raise VMRuntimeError(f"pc {st.pc} is not at an instruction boundary")
        handler = spec.handlers.get(ins.name)
        if handler is None:
            raise VMRuntimeError(f"no handler for opcode {ins.name!r}")
        st.pc = st.pc + ins.size   # default fall-through; a handler may overwrite it
        handler(st, ins.operands)
    return st
