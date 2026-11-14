"""Lift supplied VM-handler disassembly/metadata into typed, readable IR.

Unlike handler clustering, this module models stack effects, register roles,
code-stream fetches, arithmetic, comparisons, and branch/dispatch semantics.
It parses saved text only and never invokes a disassembler or executes a VM.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Mapping, Sequence


MAX_DISASSEMBLY = 4 << 20
MAX_HANDLERS = 512
MAX_INSTRUCTIONS = 4096
MAX_SOURCE_LINES = 16_384
MAX_SUCCESSORS = 128


class VMLiftInputError(ValueError):
    pass


@dataclass(frozen=True)
class TypedOperand:
    kind: str
    text: str
    bits: int
    role: str | None = None
    value: int | None = None
    base: str | None = None
    displacement: int = 0

    def render(self) -> str:
        suffix = f":{self.bits}"
        if self.role:
            return f"{self.role}<{self.text}>{suffix}"
        return f"{self.text}{suffix}"


@dataclass(frozen=True)
class VMIRInstruction:
    index: int
    address: int | None
    operation: str
    outputs: tuple[TypedOperand, ...]
    inputs: tuple[TypedOperand, ...]
    branch_targets: tuple[int, ...]
    stack_delta: int
    evidence: str

    def render(self) -> str:
        left = ", ".join(item.render() for item in self.outputs)
        right = ", ".join(item.render() for item in self.inputs)
        assignment = f"{left} = " if left else ""
        targets = "" if not self.branch_targets else " -> " + ", ".join(f"0x{x:x}" for x in self.branch_targets)
        stack = "" if not self.stack_delta else f" [stack {self.stack_delta:+d}]"
        return f"  {self.index:03d}: {assignment}{self.operation}({right}){targets}{stack}"


@dataclass(frozen=True)
class VMHandlerIR:
    name: str
    opcode: int
    address: int | None
    word_bits: int
    instructions: tuple[VMIRInstruction, ...]
    stack_delta: int
    required_stack: int
    register_reads: tuple[str, ...]
    register_writes: tuple[str, ...]
    successors: tuple[str, ...]
    terminal: bool
    confidence: int
    evidence: tuple[str, ...]
    warnings: tuple[str, ...]

    def render(self) -> str:
        head = f"handler {self.name} opcode=0x{self.opcode:x} stack={self.stack_delta:+d} requires={self.required_stack}"
        return "\n".join((head, *(row.render() for row in self.instructions))) + "\n"


@dataclass(frozen=True)
class VMProgramIR:
    handlers: tuple[VMHandlerIR, ...]
    dispatch_table: tuple[tuple[int, str], ...]
    edges: tuple[tuple[str, str], ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)

    def render(self) -> str:
        dispatch = "\n".join(f"dispatch 0x{opcode:x} -> {name}" for opcode, name in self.dispatch_table)
        bodies = "\n".join(handler.render() for handler in self.handlers)
        return dispatch + ("\n" if dispatch else "") + bodies


_LINE = re.compile(
    r"^\s*(?:(?:0x([0-9A-Fa-f]{3,16})|([0-9][0-9A-Fa-f]{2,15}))\s*:?)?\s*"
    r"(?:(?:[0-9A-Fa-f]{2}\s+){0,16})"
    r"([A-Za-z][A-Za-z0-9_.]{0,31})(?:\s+(.*?))?\s*$"
)
_REGISTER_NAME = re.compile(r"[%$]?[A-Za-z][A-Za-z0-9_.]{0,31}\Z")
_KNOWN_REGISTER = re.compile(
    r"(?:"
    r"r(?:ax|bx|cx|dx|si|di|sp|bp|ip|[0-9]|1[0-5])(?:[bwd])?|"
    r"e(?:ax|bx|cx|dx|si|di|sp|bp|ip)|"
    r"(?:ax|bx|cx|dx|si|di|sp|bp|ip)|(?:al|ah|bl|bh|cl|ch|dl|dh)|"
    r"[xw]\d+|r\d+|xzr|wzr|sp|lr|pc|cpsr|nzcv|"
    r"zero|at|v[01]|a[0-7]|t[0-9]|s(?:[0-9]|1[01])|k[01]|gp|fp|ra|lo|hi|tp|"
    r"[xyz]mm\d+|[re]?flags"
    r")\Z",
    re.IGNORECASE,
)
_MEMORY_INTEL = re.compile(
    r"\[\s*([%$]?[A-Za-z][A-Za-z0-9_.]*)\s*(?:([+-])\s*(0[xX][0-9A-Fa-f]+|\d+))?\s*\]\Z"
)
_MEMORY_ATT = re.compile(r"(?:(-?(?:0[xX][0-9A-Fa-f]+|\d+)))?\(\s*([%$]?[A-Za-z][A-Za-z0-9_.]*)\s*\)\Z")
_MEMORY_ARM = re.compile(
    r"\[\s*([%$]?[A-Za-z][A-Za-z0-9_.]*)\s*,\s*#?(-?(?:0[xX][0-9A-Fa-f]+|\d+))\s*\]\Z"
)
_NAME = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$-]{0,127}\Z")
_ROLES = {"vip", "vsp", "context", "accumulator", "flags", "temporary", "opcode"}


def _integer(value: str) -> int | None:
    text = value.strip().rstrip(",")
    if text.startswith(("$", "#")):
        text = text[1:]
    if not re.fullmatch(r"-?(?:0[xX][0-9A-Fa-f]+|\d+)", text):
        return None
    sign = -1 if text.startswith("-") else 1
    unsigned = text[1:] if sign < 0 else text
    result = sign * int(unsigned, 16 if unsigned.lower().startswith("0x") else 10)
    if not -(1 << 127) <= result < (1 << 128):
        raise VMLiftInputError("integer operand exceeds the 128-bit cap")
    return result


def _split_operands(text: str) -> tuple[str, ...]:
    if not text:
        return ()
    rows = []
    start = 0
    brackets: list[str] = []
    pairs = {"]": "[", ")": "("}
    for index, char in enumerate(text):
        if char in "[(":
            brackets.append(char)
        elif char in ")]":
            if not brackets or brackets.pop() != pairs[char]:
                raise VMLiftInputError("unbalanced operand brackets")
        elif char == "," and not brackets:
            rows.append(text[start:index].strip())
            start = index + 1
    if brackets:
        raise VMLiftInputError("unbalanced operand brackets")
    rows.append(text[start:].strip())
    if any(not row or len(row) > 256 for row in rows):
        raise VMLiftInputError("invalid operand text")
    return tuple(rows)


def _register_bits(name: str, default: int) -> int:
    value = name.lstrip("%$").lower()
    if re.fullmatch(r"r(?:ax|bx|cx|dx|si|di|sp|bp|ip|[8-9]|1[0-5])", value) or re.fullmatch(r"x\d+", value):
        return 64
    if re.fullmatch(r"e(?:ax|bx|cx|dx|si|di|sp|bp|ip)", value) or re.fullmatch(r"w\d+", value):
        return 32
    if re.fullmatch(r"(?:ax|bx|cx|dx|si|di|sp|bp|ip)", value):
        return 16
    if re.fullmatch(r"(?:al|ah|bl|bh|cl|ch|dl|dh)", value):
        return 8
    return default


def _operand(text: str, roles: Mapping[str, str], word_bits: int) -> TypedOperand:
    stripped = text.strip()
    immediate = _integer(stripped)
    if immediate is not None:
        return TypedOperand("immediate", stripped, word_bits, value=immediate)
    intel = _MEMORY_INTEL.fullmatch(stripped)
    att = _MEMORY_ATT.fullmatch(stripped)
    arm = _MEMORY_ARM.fullmatch(stripped)
    if intel or att or arm:
        if intel:
            base = intel.group(1).lstrip("%$").lower()
            displacement = int(intel.group(3), 0) if intel.group(3) else 0
            if intel.group(2) == "-":
                displacement = -displacement
        elif att:
            base = att.group(2).lstrip("%$").lower()
            displacement = int(att.group(1), 0) if att.group(1) else 0
        else:
            base = arm.group(1).lstrip("%$").lower()
            displacement = int(arm.group(2), 0)
        return TypedOperand("memory", stripped, word_bits, roles.get(base), base=base, displacement=displacement)
    normalized = stripped.lstrip("%$").lower()
    if normalized in roles or _KNOWN_REGISTER.fullmatch(normalized):
        return TypedOperand("register", stripped, _register_bits(stripped, word_bits), roles.get(normalized))
    return TypedOperand("symbol", stripped, word_bits)


def _target(operand: TypedOperand) -> tuple[int, ...]:
    return (operand.value,) if operand.kind == "immediate" and operand.value is not None and operand.value >= 0 else ()


def _handler_input(raw: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(raw, Mapping):
        raise TypeError("handler must be a mapping")
    allowed = {
        "name", "opcode", "address", "disassembly", "register_roles", "word_bits",
        "stack_growth", "successors", "terminal",
    }
    if any(key not in allowed for key in raw):
        raise VMLiftInputError("handler contains an unknown field")
    name, opcode, address, disassembly = raw.get("name"), raw.get("opcode"), raw.get("address"), raw.get("disassembly")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise VMLiftInputError("handler name is invalid")
    if not isinstance(opcode, int) or isinstance(opcode, bool) or not 0 <= opcode <= 0xFFFF:
        raise VMLiftInputError("handler opcode must be in 0..65535")
    if address is not None and (not isinstance(address, int) or isinstance(address, bool) or not 0 <= address < (1 << 64)):
        raise VMLiftInputError("handler address is invalid")
    if not isinstance(disassembly, str) or len(disassembly.encode("utf-8", "replace")) > MAX_DISASSEMBLY:
        raise VMLiftInputError("handler disassembly is invalid or over cap")
    word_bits = raw.get("word_bits", 64)
    if not isinstance(word_bits, int) or isinstance(word_bits, bool) or word_bits not in {8, 16, 32, 64, 128}:
        raise VMLiftInputError("word_bits is unsupported")
    growth = raw.get("stack_growth", "down")
    if not isinstance(growth, str) or growth not in {"down", "up"}:
        raise VMLiftInputError("stack_growth must be down or up")
    roles_raw = raw.get("register_roles", {})
    if not isinstance(roles_raw, Mapping) or len(roles_raw) > 128:
        raise VMLiftInputError("register_roles must be a bounded mapping")
    roles = {}
    for register, role in roles_raw.items():
        if (not isinstance(register, str) or not _REGISTER_NAME.fullmatch(register)
                or not isinstance(role, str) or role not in _ROLES):
            raise VMLiftInputError("register role entry is invalid")
        roles[register.lstrip("%$").lower()] = role
    successors = raw.get("successors", ())
    if (not isinstance(successors, (list, tuple)) or len(successors) > MAX_SUCCESSORS
            or any(not isinstance(item, str) or not _NAME.fullmatch(item) for item in successors)):
        raise VMLiftInputError("successors are invalid")
    terminal = raw.get("terminal", False)
    if not isinstance(terminal, bool):
        raise VMLiftInputError("terminal must be boolean")
    return {
        "name": name, "opcode": opcode, "address": address, "disassembly": disassembly,
        "roles": roles, "word_bits": word_bits, "growth": growth,
        "successors": tuple(sorted(set(successors))), "terminal": terminal,
    }


def _read_write(operand: TypedOperand, reads: set[str], writes: set[str], *, write: bool = False) -> None:
    if operand.kind == "register":
        (writes if write else reads).add(operand.role or operand.text.lstrip("%$").lower())
    elif operand.kind == "virtual" and operand.role:
        (writes if write else reads).add(operand.role)
    elif operand.kind == "memory" and operand.base:
        reads.add(operand.role or operand.base)


def lift_vm_handler(raw: Mapping[str, object]) -> VMHandlerIR:
    value = _handler_input(raw)
    roles = value["roles"]
    word_bits = value["word_bits"]
    word_bytes = word_bits // 8
    operations = []
    warnings = []
    reads: set[str] = set()
    writes: set[str] = set()
    stack_delta = 0
    minimum_stack = 0
    required_stack = 0
    terminal = bool(value["terminal"])
    recognized = 0
    skipped = 0
    source_lines = value["disassembly"].splitlines()
    if len(source_lines) > MAX_SOURCE_LINES:
        raise VMLiftInputError("handler source-line cap exceeded")
    for line in source_lines:
        stripped_line = line.strip()
        if (not stripped_line or stripped_line.startswith(("#", ";", "//"))
                or stripped_line.endswith(":")
                or stripped_line.lower().startswith(("disassembly of ", "file format "))):
            continue
        match = _LINE.match(line)
        if not match:
            skipped += 1
            if len(warnings) < 128:
                warnings.append(f"unparsed disassembly line: {stripped_line[:200]}")
            continue
        if len(operations) >= MAX_INSTRUCTIONS:
            raise VMLiftInputError("handler instruction cap exceeded")
        address_text = match.group(1) or match.group(2)
        address = int(address_text, 16) if address_text else None
        mnemonic = match.group(3).lower()
        operand_text = match.group(4) or ""
        aliases = {
            "addi": "add", "addiu": "add", "addu": "add", "adds": "add",
            "subi": "sub", "subu": "sub", "subs": "sub", "eor": "xor",
            "xori": "xor", "orr": "or", "ori": "or", "andi": "and",
            "lsl": "shl", "lsr": "shr", "sll": "shl", "slli": "shl",
            "srl": "shr", "srli": "shr", "sra": "shr", "srai": "shr",
        }
        mnemonic = aliases.get(mnemonic, mnemonic)
        suffixed = {
            "mov", "add", "sub", "xor", "and", "or", "cmp", "test", "push", "pop",
            "call", "ret", "shl", "shr", "rol", "ror", "mul", "imul",
        }
        if len(mnemonic) > 1 and mnemonic[-1] in "qwlb" and mnemonic[:-1] in suffixed:
            mnemonic = mnemonic[:-1]
        raw_operands = _split_operands(operand_text)
        operands = tuple(_operand(item, roles, word_bits) for item in raw_operands)
        # AT&T syntax marks registers with %, and orders source before
        # destination.  MIPS also uses $, so that marker is intentionally not
        # used to infer syntax.
        if (len(operands) == 2 and any(item.lstrip().startswith("%") for item in raw_operands)
                and mnemonic in {"mov", "add", "sub", "xor", "and", "or", "mul", "imul",
                                 "shl", "shr", "rol", "ror", "cmp", "test"}):
            operands = (operands[1], operands[0])
        op = "native_unknown"
        outputs: tuple[TypedOperand, ...] = ()
        inputs = operands
        targets: tuple[int, ...] = ()
        delta = 0
        if mnemonic in {"vpop", "vm_pop"} and len(operands) == 1:
            op, outputs, inputs, delta = "stack_pop", (operands[0],), (), -1
        elif mnemonic in {"vpush", "vm_push"} and len(operands) == 1:
            op, inputs, delta = "stack_push", operands, 1
        elif mnemonic in {"vdup", "vm_dup"} and not operands:
            op, delta = "stack_dup", 1
        elif mnemonic in {"vswap", "vm_swap"} and not operands:
            op = "stack_swap"
        elif mnemonic in {"vfetch", "vm_fetch"} and operands:
            op, outputs, inputs = "code_fetch", (operands[0],), operands[1:]
        elif mnemonic in {"vbranch", "vm_branch"} and len(operands) == 1:
            op, targets, terminal = "vm_branch", _target(operands[0]), True
        elif mnemonic in {"vbranch_if", "vm_branch_if"} and len(operands) == 2:
            op, inputs, targets = "vm_branch_if", (operands[0],), _target(operands[1])
        elif mnemonic in {"vret", "vm_ret"} and not operands:
            op, inputs, terminal = "vm_return", (), True
        elif mnemonic in {"mov", "ldr", "ldur", "ldrb", "ldrh", "ldrsw", "ld", "lw", "lh", "lb", "lhu", "lbu"} and len(operands) == 2:
            destination, source = operands
            if destination.kind == "memory" and destination.role == "vsp":
                op, outputs, inputs = "stack_store", (destination,), (source,)
            elif source.kind == "memory" and source.role == "vsp":
                op, outputs, inputs = "stack_load", (destination,), (source,)
            elif source.kind == "memory" and source.role == "vip":
                op, outputs, inputs = "code_load", (destination,), (source,)
            else:
                op, outputs, inputs = "assign", (destination,), (source,)
        elif mnemonic in {"str", "stur", "strb", "strh", "sd", "sw", "sh", "sb"} and len(operands) == 2:
            source, destination = operands
            op, outputs, inputs = ("stack_store" if destination.kind == "memory" and destination.role == "vsp" else "store"), (destination,), (source,)
        elif mnemonic in {"add", "sub", "xor", "and", "or", "mul", "imul", "shl", "shr", "rol", "ror"} and len(operands) in {2, 3}:
            destination = operands[0]
            left, source = (destination, operands[1]) if len(operands) == 2 else (operands[1], operands[2])
            signed = source.value if source.kind == "immediate" and (left.text == destination.text or left.role == destination.role) else None
            if mnemonic == "sub" and signed is not None:
                signed = -signed
            if destination.role == "vsp" and signed is not None and signed % word_bytes == 0:
                delta = (-signed if value["growth"] == "down" else signed) // word_bytes
                op, outputs, inputs = "stack_adjust", (destination,), (left, source)
            elif destination.role == "vip" and signed is not None:
                op, outputs, inputs = "advance_ip", (destination,), (left, source)
            else:
                op, outputs, inputs = f"binary_{mnemonic}", (destination,), (left, source)
        elif mnemonic in {"cmp", "test"} and len(operands) == 2:
            flag = TypedOperand("virtual", "condition", 1, "flags")
            op, outputs, inputs = f"compare_{mnemonic}", (flag,), operands
        elif ((mnemonic.startswith("j") and mnemonic not in {"jal", "jalr"}) or mnemonic.startswith("b.")
              or mnemonic in {"b", "br", "jr", "cbz", "cbnz", "beq", "beqz", "bne", "bnez", "bgt", "bge", "blt", "ble", "bhi", "bls"}) and operands:
            target_operand = operands[-1] if operands else None
            targets = _target(target_operand) if target_operand else ()
            if mnemonic in {"jmp", "j", "b", "br", "jr"}:
                op = "dispatch" if target_operand and target_operand.role in {"vip", "opcode"} else "branch"
                terminal = terminal or op == "dispatch"
                inputs = (target_operand,) if target_operand else ()
            else:
                op = "branch_if"
                flag = TypedOperand("virtual", "condition", 1, "flags")
                inputs = operands[:-1] if len(operands) > 1 else (flag,)
        elif mnemonic in {"call", "bl", "blr", "jal", "jalr"} and operands:
            op, targets = "call", _target(operands[-1]) if operands else ()
        elif mnemonic in {"ret", "return"}:
            op, inputs, terminal = "return_dispatch", (), True
        elif mnemonic == "push" and len(operands) == 1:
            op = "host_stack_push"
        elif mnemonic == "pop" and len(operands) == 1:
            op, outputs, inputs = "host_stack_pop", operands, ()
        if op == "native_unknown":
            warnings.append(f"unmodeled instruction: {line.strip()[:200]}")
        else:
            recognized += 1
        for operand in inputs:
            _read_write(operand, reads, writes)
        for operand in outputs:
            _read_write(operand, reads, writes, write=True)
        access = 0
        if op in {"stack_pop", "stack_dup", "stack_load"}:
            access = 1
        elif op == "stack_swap":
            access = 2
        if op == "stack_load" and inputs and inputs[0].kind == "memory":
            displacement = inputs[0].displacement
            logical_displacement = displacement if value["growth"] == "down" else -displacement
            if logical_displacement >= 0 and logical_displacement % word_bytes == 0:
                access = max(access, logical_displacement // word_bytes + 1)
        required_stack = max(required_stack, access - stack_delta)
        stack_delta += delta
        minimum_stack = min(minimum_stack, stack_delta)
        operations.append(VMIRInstruction(len(operations), address, op, outputs, inputs, targets, delta, line.strip()[:512]))
    if not operations:
        raise VMLiftInputError("handler contains no parseable instructions")
    modeled_total = len(operations) + skipped
    confidence = min(100, 50 + int(50 * recognized / modeled_total))
    evidence = (
        f"modeled {recognized}/{modeled_total} supplied instruction-like lines",
        f"register roles: {', '.join(f'{key}={roles[key]}' for key in sorted(roles)) or 'none'}",
    )
    return VMHandlerIR(
        value["name"], value["opcode"], value["address"], word_bits, tuple(operations),
        stack_delta, max(required_stack, -minimum_stack), tuple(sorted(reads)), tuple(sorted(writes)),
        value["successors"], terminal, confidence, evidence, tuple(warnings[:128]),
    )


def lift_vm_program(
    handlers: Sequence[Mapping[str, object]],
    *,
    dispatch_table: Mapping[int, str] | None = None,
) -> VMProgramIR:
    if not isinstance(handlers, Sequence) or isinstance(handlers, (str, bytes)) or not 1 <= len(handlers) <= MAX_HANDLERS:
        raise VMLiftInputError("handlers must contain 1..512 mappings")
    lifted = [lift_vm_handler(handler) for handler in handlers]
    names = [handler.name for handler in lifted]
    opcodes = [handler.opcode for handler in lifted]
    if len(set(names)) != len(names) or len(set(opcodes)) != len(opcodes):
        raise VMLiftInputError("handler names and opcodes must be unique")
    name_set = set(names)
    edges = []
    warnings = []
    for handler in lifted:
        for successor in handler.successors:
            if successor not in name_set:
                raise VMLiftInputError(f"unknown successor {successor!r}")
            edges.append((handler.name, successor))
        if not handler.successors and not handler.terminal:
            warnings.append(f"handler {handler.name} has no declared successor and is not terminal")
    if dispatch_table is None:
        dispatch = {handler.opcode: handler.name for handler in lifted}
    else:
        if not isinstance(dispatch_table, Mapping) or len(dispatch_table) > MAX_HANDLERS:
            raise VMLiftInputError("dispatch_table must be a bounded mapping")
        dispatch = {}
        for opcode, name in dispatch_table.items():
            if (not isinstance(opcode, int) or isinstance(opcode, bool) or not 0 <= opcode <= 0xFFFF
                    or not isinstance(name, str) or name not in name_set):
                raise VMLiftInputError("dispatch table entry is invalid")
            dispatch[opcode] = name
    ordered_handlers = tuple(sorted(lifted, key=lambda row: (row.opcode, row.address is None,
                                                              row.address if row.address is not None else 0, row.name)))
    return VMProgramIR(ordered_handlers, tuple(sorted(dispatch.items())), tuple(sorted(set(edges))), tuple(warnings))


__all__ = [
    "VMLiftInputError", "TypedOperand", "VMIRInstruction", "VMHandlerIR", "VMProgramIR",
    "lift_vm_handler", "lift_vm_program",
]
