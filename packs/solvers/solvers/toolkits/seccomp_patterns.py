"""Offline seccomp classic-BPF pattern analysis and inert operation-plan builders.

This module layers exploitation-oriented *review* on the repository's existing
bounded classic-BPF parser/interpreter.  It accepts packed ``sock_filter`` bytes
or decoded instructions, but never installs a filter, performs a syscall, opens
a target, or delivers a payload.  Reachability is reported honestly as a
finite, deterministic argument corpus plus structural control-flow facts.

Every public ``build_*`` function returns :class:`contract.PayloadBuild`.
Those payloads are canonical JSON-lines documents describing candidate
operations and constraints; they are deliberately not shellcode or drivers.
"""
from __future__ import annotations

import functools
import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence

try:  # package and direct toolkit-path imports
    from .contract import BuildError, PayloadBuild, ensure_uint
    from . import pwn_seccomp as seccomp
except ImportError:  # pragma: no cover - repository tests use direct imports
    from contract import BuildError, PayloadBuild, ensure_uint
    import pwn_seccomp as seccomp


class SeccompPatternError(BuildError):
    """The filter or requested review plan is unsupported or inconsistent."""


def _wrap_pattern_errors(func):
    """Convert base contract validation errors to the declared pattern type.

    The plan builders validate caller-supplied numeric options through the
    shared contract's ``ensure_uint``, which raises a base ``BuildError``.  A
    caller of these entrypoints should only observe :class:`SeccompPatternError`,
    so any such error that is not already one is re-raised as one.  Valid inputs
    never reach this handler.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SeccompPatternError:
            raise
        except BuildError as exc:
            raise SeccompPatternError(str(exc)) from exc

    return wrapper


X32_SYSCALL_BIT = 0x40000000
MAX_PLAN_OPERATIONS = 32
MAX_ARGUMENT_PROBES = 32
MAX_PLAN_BYTES = 256 * 1024
MAX_PLAN_LINE_BYTES = 64 * 1024
MAX_TEXT_BYTES = 512
SECCOMP_DATA_SIZE = 64
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_KERNEL_VERSION_RE = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?$")
_SYSCALL_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")

# x32 assigns 512+ numbers to calls whose pointer-sized structures differ from
# the native x86-64 ABI.  Other calls use the native number with the x32 bit.
_X32_SPECIAL_NUMBERS: Mapping[str, int] = {
    "rt_sigaction": 512, "rt_sigreturn": 513, "ioctl": 514,
    "readv": 515, "writev": 516,
    "recvfrom": 517, "execve": 520, "vmsplice": 532,
    "process_vm_readv": 539, "process_vm_writev": 540,
    "setsockopt": 541, "getsockopt": 542, "execveat": 545,
}


# ``seccomp_check_filter()`` accepts an intentionally smaller instruction set
# than the general classic-BPF verifier.  Keep this exact-code allowlist in
# sync with Linux kernel/seccomp.c rather than accepting socket-only byte/half,
# indirect, MSH, or modulo operations that the kernel rejects for seccomp.
_SECCOMP_ALLOWED_CODES = frozenset({
    seccomp.BPF_LD | seccomp.BPF_W | seccomp.BPF_ABS,
    seccomp.BPF_LD | seccomp.BPF_W | seccomp.BPF_LEN,
    seccomp.BPF_LDX | seccomp.BPF_W | seccomp.BPF_LEN,
    seccomp.BPF_RET | seccomp.BPF_K,
    seccomp.BPF_RET | seccomp.BPF_A,
    *(
        seccomp.BPF_ALU | operation | source
        for operation in (
            seccomp.BPF_ADD, seccomp.BPF_SUB, seccomp.BPF_MUL,
            seccomp.BPF_DIV, seccomp.BPF_AND, seccomp.BPF_OR,
            seccomp.BPF_XOR, seccomp.BPF_LSH, seccomp.BPF_RSH,
        )
        for source in (seccomp.BPF_K, seccomp.BPF_X)
    ),
    seccomp.BPF_ALU | seccomp.BPF_NEG,
    seccomp.BPF_LD | seccomp.BPF_IMM,
    seccomp.BPF_LDX | seccomp.BPF_IMM,
    seccomp.BPF_MISC | seccomp.BPF_TAX,
    seccomp.BPF_MISC | seccomp.BPF_TXA,
    seccomp.BPF_LD | seccomp.BPF_MEM,
    seccomp.BPF_LDX | seccomp.BPF_MEM,
    seccomp.BPF_ST,
    seccomp.BPF_STX,
    seccomp.BPF_JMP | seccomp.BPF_JA,
    *(
        seccomp.BPF_JMP | operation | source
        for operation in (seccomp.BPF_JEQ, seccomp.BPF_JGE,
                          seccomp.BPF_JGT, seccomp.BPF_JSET)
        for source in (seccomp.BPF_K, seccomp.BPF_X)
    ),
})

# High-value syscalls missing from the older finite catalog.  Values are Linux
# UAPI numbers; the analyzer still only interprets caller-supplied filter bytes.
_EXTRA_SYSCALLS: Mapping[str, Mapping[str, int]] = {
    "amd64": {
        "dup3": 292, "pipe2": 293, "execveat": 322, "splice": 275,
        "tee": 276, "vmsplice": 278, "copy_file_range": 326,
        "process_vm_readv": 310, "process_vm_writev": 311,
        "pidfd_open": 434, "pidfd_getfd": 438, "seccomp": 317,
        "userfaultfd": 323,
    },
    "i386": {
        "dup3": 330, "pipe2": 331, "execveat": 358, "splice": 313,
        "tee": 315, "vmsplice": 316, "sendfile64": 239,
        "process_vm_readv": 347, "process_vm_writev": 348,
        "pidfd_open": 434, "pidfd_getfd": 438, "seccomp": 354,
        "userfaultfd": 374,
    },
    "arm": {
        "dup3": 358, "pipe2": 359, "execveat": 387, "splice": 340,
        "tee": 342, "vmsplice": 343, "sendfile64": 239,
        "process_vm_readv": 376, "process_vm_writev": 377,
        "pidfd_open": 434, "pidfd_getfd": 438, "seccomp": 383,
        "userfaultfd": 388,
    },
    "aarch64": {
        "dup3": 24, "pipe2": 59, "execveat": 281, "splice": 76,
        "tee": 77, "vmsplice": 75, "copy_file_range": 285,
        "process_vm_readv": 270, "process_vm_writev": 271,
        "pidfd_open": 434, "pidfd_getfd": 438, "seccomp": 277,
        "userfaultfd": 282,
    },
}


def syscall_catalog(architecture: str) -> dict[str, int]:
    """Return the deterministic analysis catalog for one supported ABI."""

    if not isinstance(architecture, str) or architecture not in seccomp.SYSCALLS:
        raise SeccompPatternError(
            f"unknown architecture {architecture!r}; choose {', '.join(sorted(seccomp.SYSCALLS))}"
        )
    table = dict(seccomp.SYSCALLS[architecture])
    table.update(_EXTRA_SYSCALLS.get(architecture, {}))
    return dict(sorted(table.items(), key=lambda item: (item[1], item[0])))


def _validate_linux_seccomp_subset(program: Sequence[seccomp.Instruction]) -> None:
    """Apply Linux ``seccomp_check_filter`` restrictions after generic cBPF checks."""

    for pc, ins in enumerate(program):
        if ins.code not in _SECCOMP_ALLOWED_CODES:
            raise SeccompPatternError(
                f"classic-BPF opcode {ins.code:#x} at instruction {pc} is not allowed by Linux seccomp"
            )
        if ins.code == (seccomp.BPF_LD | seccomp.BPF_W | seccomp.BPF_ABS):
            if ins.k >= SECCOMP_DATA_SIZE or ins.k & 3:
                raise SeccompPatternError(
                    f"seccomp_data load at instruction {pc} must be 32-bit aligned within 64 bytes"
                )
        if ins.code in {
            seccomp.BPF_LD | seccomp.BPF_MEM,
            seccomp.BPF_LDX | seccomp.BPF_MEM,
            seccomp.BPF_ST,
            seccomp.BPF_STX,
        } and ins.k >= 16:
            raise SeccompPatternError(f"classic-BPF scratch index at instruction {pc} must be below 16")
        if ins.code == (seccomp.BPF_ALU | seccomp.BPF_DIV | seccomp.BPF_K) and ins.k == 0:
            raise SeccompPatternError(f"constant division by zero at instruction {pc}")


def _filter_bytes(program: Sequence[seccomp.Instruction], endian: str) -> bytes:
    if endian not in {"little", "big"}:
        raise SeccompPatternError("endian must be 'little' or 'big'")
    return b"".join(
        int(ins.code).to_bytes(2, endian)
        + bytes((ins.jt, ins.jf))
        + int(ins.k).to_bytes(4, endian)
        for ins in program
    )


def decode_filter(
    source: bytes | bytearray | Sequence[object] | Mapping[str, object],
    *,
    endian: str = "little",
) -> tuple[seccomp.Instruction, ...]:
    """Normalize packed or decoded classic-BPF instructions without execution."""

    try:
        if isinstance(source, (bytes, bytearray)):
            program = seccomp.parse_sock_filters(bytes(source), endian)
        elif isinstance(source, Mapping):
            program = seccomp.parse_json_program(source)
        elif isinstance(source, Sequence) and not isinstance(source, (str, bytes, bytearray)):
            rows = list(source)
            if rows and all(isinstance(row, seccomp.Instruction) for row in rows):
                program = rows
            else:
                program = seccomp.parse_json_program(rows)
        else:
            raise SeccompPatternError("filter must be packed bytes or decoded instruction records")
        seccomp.validate_program(program)
    except seccomp.SeccompError as exc:
        raise SeccompPatternError(str(exc)) from exc
    _validate_linux_seccomp_subset(program)
    return tuple(program)


def _action_kind(raw: int) -> str:
    action = raw & seccomp.SECCOMP_RET_ACTION_FULL
    return {
        seccomp.SECCOMP_RET_ALLOW: "allow",
        seccomp.SECCOMP_RET_LOG: "log",
        seccomp.SECCOMP_RET_USER_NOTIF: "user_notif",
        seccomp.SECCOMP_RET_TRACE: "trace",
        seccomp.SECCOMP_RET_ERRNO: "errno",
        seccomp.SECCOMP_RET_TRAP: "trap",
        seccomp.SECCOMP_RET_KILL_THREAD: "kill_thread",
        seccomp.SECCOMP_RET_KILL_PROCESS: "kill_process",
    }.get(action, "unknown")


def _direct(raw: int) -> bool:
    return (raw & seccomp.SECCOMP_RET_ACTION_FULL) in {
        seccomp.SECCOMP_RET_ALLOW, seccomp.SECCOMP_RET_LOG,
    }


def _mediated(raw: int) -> bool:
    return (raw & seccomp.SECCOMP_RET_ACTION_FULL) in {
        seccomp.SECCOMP_RET_USER_NOTIF, seccomp.SECCOMP_RET_TRACE,
    }


def _reachable_returns(program: Sequence[seccomp.Instruction]) -> list[dict[str, object]]:
    todo = [0]
    seen: set[int] = set()
    returns: list[dict[str, object]] = []
    while todo:
        pc = todo.pop()
        if pc in seen:
            continue
        seen.add(pc)
        ins = program[pc]
        cls = ins.code & 0x07
        if cls == seccomp.BPF_RET:
            if (ins.code & 0x18) == seccomp.BPF_A:
                returns.append({"pc": pc, "action": "dynamic_accumulator", "raw": None})
            else:
                returns.append({
                    "pc": pc,
                    "action": seccomp.action_name(ins.k),
                    "raw": f"0x{ins.k & 0xFFFFFFFF:08x}",
                })
            continue
        if cls == seccomp.BPF_JMP:
            op = ins.code & 0xF0
            if op == seccomp.BPF_JA:
                successors = (pc + 1 + ins.k,)
            else:
                successors = (pc + 1 + ins.jt, pc + 1 + ins.jf)
        else:
            successors = (pc + 1,)
        todo.extend(reversed(successors))
    return sorted(returns, key=lambda row: int(row["pc"]))


def _return_constants_from(
    program: Sequence[seccomp.Instruction], start: int,
) -> tuple[int | None, ...]:
    """Return all statically reachable RET constants from one validated successor."""

    todo = [start]
    seen: set[int] = set()
    answers: set[int | None] = set()
    while todo:
        pc = todo.pop()
        if pc in seen:
            continue
        seen.add(pc)
        ins = program[pc]
        cls = ins.code & 0x07
        if cls == seccomp.BPF_RET:
            answers.add(None if (ins.code & 0x18) == seccomp.BPF_A else ins.k & 0xFFFFFFFF)
            continue
        if cls == seccomp.BPF_JMP:
            op = ins.code & 0xF0
            successors = ((pc + 1 + ins.k,) if op == seccomp.BPF_JA else
                          (pc + 1 + ins.jt, pc + 1 + ins.jf))
        else:
            successors = (pc + 1,)
        todo.extend(successors)
    return tuple(sorted(answers, key=lambda value: -1 if value is None else value))


def _arch_guard_facts(
    program: Sequence[seccomp.Instruction], expected_audit_arch: int,
) -> dict[str, object]:
    """Find data-flow-backed AUDIT_ARCH comparisons with restrictive mismatch arms."""

    # State says whether A is still the exact, unmodified seccomp_data.arch
    # value.  Merely loading arch and later comparing an unrelated accumulator
    # must not count as a guard.
    todo: list[tuple[int, bool]] = [(0, False)]
    seen: set[tuple[int, bool]] = set()
    comparisons: list[dict[str, object]] = []
    audit_values = set(seccomp.AUDIT_ARCH.values())
    while todo:
        pc, accumulator_is_arch = todo.pop()
        if (pc, accumulator_is_arch) in seen:
            continue
        seen.add((pc, accumulator_is_arch))
        ins = program[pc]
        cls = ins.code & 0x07
        if cls == seccomp.BPF_RET:
            continue

        if (ins.code == (seccomp.BPF_JMP | seccomp.BPF_JEQ | seccomp.BPF_K)
                and accumulator_is_arch and ins.k in audit_values):
            mismatch_start = pc + 1 + ins.jf
            mismatch_returns = _return_constants_from(program, mismatch_start)
            mismatch_kinds = sorted({
                "dynamic_accumulator" if raw is None else _action_kind(raw)
                for raw in mismatch_returns
            })
            restrictive = bool(mismatch_returns) and all(
                raw is not None and _action_kind(raw) in {
                    "kill_thread", "kill_process", "trap", "errno",
                }
                for raw in mismatch_returns
            )
            comparisons.append({
                "pc": pc,
                "compared_value": f"0x{ins.k:08x}",
                "matches_selected_architecture": ins.k == expected_audit_arch,
                "mismatch_reachable_actions": mismatch_kinds,
                "mismatch_is_restrictive": restrictive,
                "effective_selected_arch_guard": bool(
                    ins.k == expected_audit_arch and restrictive
                ),
            })

        next_state = accumulator_is_arch
        if cls == seccomp.BPF_LD:
            next_state = (
                ins.code == (seccomp.BPF_LD | seccomp.BPF_W | seccomp.BPF_ABS)
                and ins.k == 4
            )
        elif cls == seccomp.BPF_ALU:
            next_state = False
        elif (cls == seccomp.BPF_MISC
              and (ins.code & 0xF8) == seccomp.BPF_TXA):
            next_state = False

        if cls == seccomp.BPF_JMP:
            op = ins.code & 0xF0
            successors = ((pc + 1 + ins.k,) if op == seccomp.BPF_JA else
                          (pc + 1 + ins.jt, pc + 1 + ins.jf))
        else:
            successors = (pc + 1,)
        todo.extend((successor, next_state) for successor in successors)

    return {
        "arch_comparisons": sorted(comparisons, key=lambda row: int(row["pc"])),
        "has_effective_arch_guard": any(
            bool(row["effective_selected_arch_guard"]) for row in comparisons
        ),
    }


def _load_facts(
    program: Sequence[seccomp.Instruction], endian: str, expected_audit_arch: int,
) -> dict[str, object]:
    loads: list[dict[str, int]] = []
    for pc, ins in enumerate(program):
        if (ins.code & 0x07) not in (seccomp.BPF_LD, seccomp.BPF_LDX):
            continue
        if (ins.code & 0xE0) != seccomp.BPF_ABS:
            continue
        size_code = ins.code & 0x18
        size = {seccomp.BPF_W: 4, seccomp.BPF_H: 2, seccomp.BPF_B: 1}.get(size_code)
        if size is not None:
            loads.append({"pc": pc, "offset": ins.k, "size": size})

    argument_halves: dict[str, dict[str, bool]] = {}
    for index in range(6):
        base = 16 + 8 * index
        low, high = (base, base + 4) if endian == "little" else (base + 4, base)
        argument_halves[f"arg{index}"] = {
            "low32": any(row["offset"] == low and row["size"] == 4 for row in loads),
            "high32": any(row["offset"] == high and row["size"] == 4 for row in loads),
            "any": any(base <= row["offset"] < base + 8 for row in loads),
        }
    guard_facts = _arch_guard_facts(program, expected_audit_arch)
    compared_arches = sorted({
        int(str(row["compared_value"]), 16)
        for row in guard_facts["arch_comparisons"]
    })
    return {
        "absolute_loads": loads,
        "loads_syscall_number": any(row["offset"] == 0 for row in loads),
        "loads_audit_arch": any(row["offset"] == 4 for row in loads),
        "compared_audit_arch_values": [f"0x{value:08x}" for value in compared_arches],
        "argument_halves": argument_halves,
        **guard_facts,
    }


def _append_probe(
    rows: list[tuple[str, tuple[int, ...]]], seen: set[tuple[int, ...]],
    label: str, args: Sequence[int],
) -> None:
    normalized = tuple(ensure_uint(int(value), 64, name=f"probe {label} argument") for value in args)
    normalized = (normalized + (0,) * 6)[:6]
    if normalized not in seen and len(rows) < MAX_ARGUMENT_PROBES:
        seen.add(normalized)
        rows.append((label, normalized))


def _argument_probes(syscall_name: str) -> tuple[tuple[str, tuple[int, ...]], ...]:
    rows: list[tuple[str, tuple[int, ...]]] = []
    seen: set[tuple[int, ...]] = set()
    _append_probe(rows, seen, "zero", ())
    for index in range(6):
        args = [0] * 6
        args[index] = 1
        _append_probe(rows, seen, f"arg{index}.one", args)
        args[index] = 1 << 32
        _append_probe(rows, seen, f"arg{index}.high_bit", args)
        args[index] = (1 << 64) - 1
        _append_probe(rows, seen, f"arg{index}.all_ones", args)

    if syscall_name in {"read", "write", "pread64", "readv", "writev", "sendfile", "sendfile64"}:
        for fd in (0, 1, 2, 3, 1024, (1 << 64) - 1):
            _append_probe(rows, seen, f"fd.{fd:#x}", (fd, 0x10000, 0x100))
    if syscall_name == "open":
        for name, flags in (("rdonly", 0), ("wronly", 1), ("rdwr", 2),
                            ("creat", 0x40), ("trunc", 0x200), ("path", 0x200000)):
            _append_probe(rows, seen, f"open.flags_{name}", (0x10000, flags, 0o600))
    if syscall_name == "openat":
        at_fdcwd = ((1 << 64) - 100)
        for name, flags in (("rdonly", 0), ("wronly", 1), ("rdwr", 2), ("creat", 0x40)):
            _append_probe(rows, seen, f"openat.flags_{name}",
                          (at_fdcwd, 0x10000, flags, 0o600))
    if syscall_name == "openat2":
        at_fdcwd = ((1 << 64) - 100)
        # seccomp sees only the open_how pointer and size; it cannot inspect
        # flags within the pointed-to structure.
        _append_probe(rows, seen, "openat2.how_non_null", (at_fdcwd, 0x10000, 0x11000, 24))
        _append_probe(rows, seen, "openat2.how_high_pointer", (at_fdcwd, 0x10000, 0x100001000, 24))
    if syscall_name in {"mprotect", "mmap", "mmap2"}:
        for prot in range(8):
            args = (0x10000, 0x1000, prot, 0x22, (1 << 64) - 1, 0)
            _append_probe(rows, seen, f"{syscall_name}.prot_{prot}", args)
    if syscall_name in {"execve", "execveat"}:
        _append_probe(rows, seen, f"{syscall_name}.non_null", (0x10000, 0x11000, 0x12000))
        _append_probe(rows, seen, f"{syscall_name}.high_pointer", (0x100001000, 0x11000, 0x12000))
    if syscall_name in {"dup2", "dup3"}:
        for newfd in (0, 1, 2, 3, 100):
            _append_probe(rows, seen, f"{syscall_name}.newfd_{newfd}", (7, newfd, 0))
    if syscall_name == "fcntl":
        for command in (0, 1, 2, 3, 1030):
            _append_probe(rows, seen, f"fcntl.command_{command}", (7, command, 0))
    if syscall_name == "socket":
        for family, kind in ((2, 1), (2, 2), (10, 1), (1, 1)):
            _append_probe(rows, seen, f"socket.{family}.{kind}", (family, kind, 0))
    return tuple(rows)


def _classify(results: Sequence[dict[str, object]]) -> str:
    direct_count = sum(bool(row["direct"]) for row in results)
    mediated_count = sum(bool(row["mediated"]) for row in results)
    if direct_count == len(results):
        return "always_allowed_in_sampled_domain"
    if direct_count:
        return "conditionally_allowed"
    if mediated_count:
        return "externally_mediated"
    return "blocked_in_sampled_domain"


def _decision_usable(row: Mapping[str, object] | None) -> bool:
    return bool(row and row.get("classification") in {
        "always_allowed_in_sampled_domain", "conditionally_allowed",
    })


def _x32_number(name: str, native_number: int) -> int:
    return X32_SYSCALL_BIT | _X32_SPECIAL_NUMBERS.get(name, native_number)


def _parse_kernel_version(value: str | None) -> tuple[int, int, int] | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _KERNEL_VERSION_RE.fullmatch(value):
        raise SeccompPatternError("kernel_version must be MAJOR.MINOR or MAJOR.MINOR.PATCH")
    parts = [int(part) for part in value.split(".")]
    parts += [0] * (3 - len(parts))
    return tuple(parts)  # type: ignore[return-value]


def _trace_semantics(kernel_version: str | None) -> dict[str, object]:
    parsed = _parse_kernel_version(kernel_version)
    if parsed is None:
        return {
            "kernel_version": None,
            "seccomp_rechecked_after_ptrace_change": None,
            "detail": (
                "kernel version is unknown: before Linux 4.8 ptrace changes were not "
                "rechecked by seccomp; Linux 4.8+ rechecks the modified syscall"
            ),
        }
    rechecked = parsed >= (4, 8, 0)
    return {
        "kernel_version": kernel_version,
        "seccomp_rechecked_after_ptrace_change": rechecked,
        "detail": (
            "Linux 4.8+ rechecks a ptrace-modified syscall through seccomp"
            if rechecked else
            "before Linux 4.8, ptrace syscall changes are not rechecked through seccomp"
        ),
    }


def analyze_seccomp_patterns(
    source: bytes | bytearray | Sequence[object] | Mapping[str, object],
    *,
    architecture: str = "amd64",
    endian: str = "little",
    kernel_version: str | None = None,
) -> dict[str, object]:
    """Analyze named syscall/argument paths, ABI confusion, and compositions.

    The report distinguishes structural reachability from finite concrete
    probing.  ``always`` therefore means all values in the documented probe
    corpus, never a symbolic proof over all 64-bit argument tuples.
    """

    trace_model = _trace_semantics(kernel_version)
    program = decode_filter(source, endian=endian)
    table = syscall_catalog(architecture)
    audit_arch = seccomp.AUDIT_ARCH[architecture]
    load_facts = _load_facts(program, endian, audit_arch)
    decisions: dict[str, dict[str, object]] = {}
    action_buckets: dict[str, set[str]] = defaultdict(set)

    for name, number in table.items():
        results: list[dict[str, object]] = []
        for label, args in _argument_probes(name):
            try:
                raw = seccomp.execute_filter(program, number, audit_arch, args, endian)
            except seccomp.SeccompError as exc:
                raise SeccompPatternError(str(exc)) from exc
            kind = _action_kind(raw)
            action_buckets[kind].add(name)
            results.append({
                "sample": label,
                "args": [f"0x{value:016x}" for value in args],
                "action": seccomp.action_name(raw),
                "action_kind": kind,
                "raw": f"0x{raw:08x}",
                "direct": _direct(raw),
                "mediated": _mediated(raw),
            })
        decisions[name] = {
            "nr": number,
            "classification": _classify(results),
            "reachable_actions": sorted({str(row["action"]) for row in results}),
            "direct_samples": [row["sample"] for row in results if row["direct"]],
            "mediated_samples": [row["sample"] for row in results if row["mediated"]],
            "probes": results,
        }

    # This lane models the x86 compatibility boundary only.  Treating ARM or
    # AArch64 as alternate ABIs of an x86 process creates impossible bypasses.
    compatible_abis = {
        "amd64": ("i386",),
        "i386": ("amd64",),
        "arm": (),
        "aarch64": (),
    }[architecture]
    cross_arch: dict[str, list[str]] = {}
    for other_name in compatible_abis:
        other_value = seccomp.AUDIT_ARCH[other_name]
        direct_names = []
        # Use the alternate ABI's own syscall numbers.  On x86-64 an int 0x80
        # entry, for example, reports AUDIT_ARCH_I386 and i386 syscall numbers.
        for name, number in syscall_catalog(other_name).items():
            raw = seccomp.execute_filter(program, number, other_value, (), endian)
            if _direct(raw):
                direct_names.append(name)
        cross_arch[other_name] = direct_names

    x32: dict[str, object] = {
        "applicable": architecture == "amd64", "direct_syscalls": [],
        "differential_bypasses": [], "modeled_numbers": {},
    }
    if architecture == "amd64":
        direct_x32: list[str] = []
        bypasses: list[str] = []
        for name, number in table.items():
            normal = seccomp.execute_filter(program, number, audit_arch, (), endian)
            x32_raw = seccomp.execute_filter(program, _x32_number(name, number), audit_arch, (), endian)
            if _direct(x32_raw):
                direct_x32.append(name)
            if _direct(x32_raw) and not _direct(normal):
                bypasses.append(name)
        x32 = {
            "applicable": True, "direct_syscalls": direct_x32,
            "differential_bypasses": bypasses,
            "model": "__X32_SYSCALL_BIT plus native numbers, with 512+ pointer-layout overrides",
            "modeled_numbers": {
                name: _x32_number(name, number) for name, number in table.items()
            },
        }

    usable = lambda name: _decision_usable(decisions.get(name))
    openers = [name for name in ("openat", "open", "openat2") if usable(name)]
    readers = [name for name in ("read", "pread64", "readv") if usable(name)]
    writers = [name for name in ("write", "writev") if usable(name)]
    transfers = [name for name in ("sendfile", "sendfile64") if usable(name)]
    # Buffered and kernel-copy transfer shapes are deliberately disjoint:
    # sendfile is one operation, never a Cartesian-product read/write pair.
    orw_routes = ([
        {"kind": "buffered", "open": opener, "read": reader, "write": writer}
        for opener in openers for reader in readers for writer in writers
    ] + [
        {"kind": "sendfile", "open": opener, "transfer": transfer}
        for opener in openers for transfer in transfers
    ])[:32]
    fd_tools = [name for name in ("dup", "dup2", "dup3", "fcntl", "pidfd_getfd") if usable(name)]
    fd_routes: list[str] = []
    if readers and writers:
        fd_routes.append("inherited-fd-read-write")
    if fd_tools and readers and writers:
        fd_routes.append("duplicate-known-fd-then-read-write")
    if transfers:
        fd_routes.append("sendfile-between-existing-fds")
    if usable("pidfd_getfd"):
        fd_routes.append("pidfd-getfd-requires-accessible-process")

    compositions: list[str] = []
    if orw_routes:
        compositions.append("path-open-read-output")
    if (readers and writers) or transfers:
        compositions.append("inherited-fd-read-output")
    if usable("memfd_create") and usable("write") and usable("execveat"):
        compositions.append("memfd-write-execveat")
    if usable("read") and (usable("mprotect") or usable("mmap") or usable("mmap2")):
        compositions.append("read-then-executable-memory")
    if usable("socket") and usable("connect") and usable("read") and usable("write"):
        compositions.append("socket-connect-read-write")
    if (usable("pipe") or usable("pipe2")) and usable("splice"):
        compositions.append("pipe-splice")

    weaknesses: list[dict[str, object]] = []
    if not load_facts["has_effective_arch_guard"]:
        weaknesses.append({
            "kind": "missing_arch_guard",
            "detail": (
                "filter does not contain a data-flow-backed AUDIT_ARCH comparison "
                "whose mismatch arm is entirely restrictive"
            ),
        })
    permissive_other = {name: values for name, values in cross_arch.items() if values}
    if permissive_other:
        weaknesses.append({"kind": "cross_arch_direct_paths", "architectures": permissive_other})
    if x32["differential_bypasses"]:
        weaknesses.append({"kind": "x32_differential_bypass", "syscalls": x32["differential_bypasses"]})

    halves = load_facts["argument_halves"]
    for arg_name, status in halves.items():
        if status["any"] and status["low32"] != status["high32"]:
            weaknesses.append({
                "kind": "partial_64bit_argument_check", "argument": arg_name,
                "checked_half": "low32" if status["low32"] else "high32",
            })
    for name in ("execve", "execveat", "mprotect", "open", "openat", "openat2"):
        row = decisions.get(name)
        if row and row["classification"] == "always_allowed_in_sampled_domain":
            weaknesses.append({"kind": "dangerous_syscall_unrestricted_in_corpus", "syscall": name})
    for name in ("mprotect", "mmap", "mmap2"):
        row = decisions.get(name)
        if row and f"{name}.prot_7" in row["direct_samples"]:
            weaknesses.append({"kind": "writable_executable_memory_allowed", "syscall": name})
    for name in ("open", "openat"):
        row = decisions.get(name)
        if row and any(str(sample).endswith(("flags_wronly", "flags_rdwr", "flags_creat"))
                       for sample in row["direct_samples"]):
            weaknesses.append({"kind": "write_capable_open_flags_allowed", "syscall": name})
    if action_buckets.get("trace"):
        weaknesses.append({
            "kind": "trace_supervisor_dependency",
            "detail": trace_model["detail"],
            "seccomp_rechecked_after_ptrace_change": trace_model[
                "seccomp_rechecked_after_ptrace_change"
            ],
        })
    if action_buckets.get("user_notif"):
        weaknesses.append({
            "kind": "user_notification_dependency",
            "detail": "supervisor outcome and pointer-snapshot TOCTOU policy require review",
        })

    filter_bytes = _filter_bytes(program, endian)
    return {
        "format": "r5b-seccomp-pattern-report-v1",
        "architecture": architecture,
        "audit_arch": f"0x{audit_arch:08x}",
        "endian": endian,
        "kernel_version": kernel_version,
        "instruction_count": len(program),
        "filter_sha256": hashlib.sha256(filter_bytes).hexdigest(),
        "program": [ins.as_dict() for ins in program],
        "probe_model": "baseline + one-argument 1/high-bit/all-ones + syscall-specific cases; max 32",
        "structural": {
            "reachable_returns": _reachable_returns(program),
            **load_facts,
        },
        "decisions": decisions,
        "action_buckets": {key: sorted(values) for key, values in sorted(action_buckets.items())},
        "cross_arch": cross_arch,
        "x32": x32,
        "trace_semantics": trace_model,
        "capabilities": {
            "openers": openers, "readers": readers, "writers": writers,
            "transfers": transfers, "fd_tools": fd_tools, "orw_routes": orw_routes,
            "fd_reuse_routes": fd_routes, "allowed_compositions": compositions,
            "exec": [name for name in ("execve", "execveat") if usable(name)],
            "memory_exec": [name for name in ("mprotect", "mmap", "mmap2") if usable(name)],
        },
        "argument_filter_weaknesses": weaknesses,
        "limits": {
            "sampled_not_symbolic": True,
            "pointer_memory_not_dereferenced": True,
            "stacked_filters_not_composed": True,
        },
    }


def _bounded_text(value: object, name: str, *, maximum: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value or not value.strip():
        raise SeccompPatternError(f"{name} must be a non-empty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SeccompPatternError(f"{name} must be valid UTF-8") from exc
    if len(encoded) > maximum or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise SeccompPatternError(
            f"{name} must be printable and at most {maximum} UTF-8 bytes"
        )
    return value


def _report_program(report: Mapping[str, object]) -> tuple[seccomp.Instruction, ...]:
    endian = report.get("endian")
    if endian not in {"little", "big"}:
        raise SeccompPatternError("report has an unsupported endian value")
    source = report.get("program")
    if not isinstance(source, Sequence) or isinstance(source, (str, bytes, bytearray)):
        raise SeccompPatternError("report lacks its bounded decoded filter program")
    program = decode_filter(source, endian=str(endian))
    digest = report.get("filter_sha256")
    if not isinstance(digest, str) or not _HEX_DIGEST_RE.fullmatch(digest):
        raise SeccompPatternError("report has an invalid filter_sha256")
    if hashlib.sha256(_filter_bytes(program, str(endian))).hexdigest() != digest:
        raise SeccompPatternError("report filter program does not match filter_sha256")
    if report.get("instruction_count") != len(program):
        raise SeccompPatternError("report instruction count does not match its program")
    return program


def _report_arch(report: Mapping[str, object]) -> str:
    if not isinstance(report, Mapping) or report.get("format") != "r5b-seccomp-pattern-report-v1":
        raise SeccompPatternError("report must come from analyze_seccomp_patterns")
    architecture = report.get("architecture")
    if not isinstance(architecture, str) or architecture not in seccomp.SYSCALLS:
        raise SeccompPatternError("report has an unsupported architecture")
    expected_audit_arch = f"0x{seccomp.AUDIT_ARCH[architecture]:08x}"
    if report.get("audit_arch") != expected_audit_arch:
        raise SeccompPatternError("report audit_arch does not match its architecture")
    kernel_version = report.get("kernel_version")
    if kernel_version is not None:
        _parse_kernel_version(kernel_version if isinstance(kernel_version, str) else "")
    _report_program(report)
    return architecture


def _canonical_report(report: Mapping[str, object]) -> dict[str, object]:
    """Regenerate every derived fact from the bounded embedded filter.

    Reports are caller-controlled dictionaries, so their decisions,
    capabilities, action buckets, weaknesses, and TRACE prose are never trust
    anchors.  Only the validated program/digest plus the bounded analysis
    context are used to create the builder's private canonical copy.
    """

    architecture = _report_arch(report)
    program = _report_program(report)
    endian = str(report["endian"])
    kernel_version = report.get("kernel_version")
    return analyze_seccomp_patterns(
        program,
        architecture=architecture,
        endian=endian,
        kernel_version=(kernel_version if isinstance(kernel_version, str) else None),
    )


def _decision_row(report: Mapping[str, object], name: str) -> Mapping[str, object] | None:
    if not isinstance(name, str) or not _SYSCALL_NAME_RE.fullmatch(name):
        return None
    decisions = report.get("decisions")
    if not isinstance(decisions, Mapping):
        return None
    row = decisions.get(name)
    return row if isinstance(row, Mapping) else None


def _usable_decision(report: Mapping[str, object], name: str) -> Mapping[str, object] | None:
    row = _decision_row(report, name)
    return row if isinstance(row, Mapping) and _decision_usable(row) else None


def _exact_filter_action(
    report: Mapping[str, object], name: str, arguments: Sequence[int],
) -> tuple[int, tuple[int, ...]]:
    architecture = _report_arch(report)
    row = _decision_row(report, name)
    if row is None:
        raise SeccompPatternError(f"report has no decision for syscall {name}")
    number = row.get("nr")
    if isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= 0x7FFFFFFF:
        raise SeccompPatternError(f"report has an invalid syscall number for {name}")
    if syscall_catalog(architecture).get(name) != number:
        raise SeccompPatternError(f"report syscall number for {name} does not match {architecture}")
    normalized = tuple(
        ensure_uint(value, 64, name=f"{name} argument {index}")
        for index, value in enumerate(arguments)
    )
    if len(normalized) > 6:
        raise SeccompPatternError("a Linux syscall may contain at most six arguments")
    padded = (normalized + (0,) * 6)[:6]
    raw = seccomp.execute_filter(
        _report_program(report), number, seccomp.AUDIT_ARCH[architecture], padded,
        str(report["endian"]),
    )
    return raw, padded


def _encode_plan(
    report: Mapping[str, object], *, strategy: str,
    operations: Sequence[Mapping[str, object]], constraints: Sequence[str],
) -> PayloadBuild:
    architecture = _report_arch(report)
    if not operations or len(operations) > MAX_PLAN_OPERATIONS:
        raise SeccompPatternError(f"operation plan must contain 1..{MAX_PLAN_OPERATIONS} operations")
    if not 1 <= len(constraints) <= 32:
        raise SeccompPatternError("constraints must contain 1..32 entries")
    normalized_constraints = [
        _bounded_text(item, f"constraint {index}") for index, item in enumerate(constraints)
    ]
    payload = bytearray()
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}

    def add(label: str, value: Mapping[str, object]) -> None:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_PLAN_LINE_BYTES:
            raise SeccompPatternError(f"plan record {label} exceeds {MAX_PLAN_LINE_BYTES} bytes")
        if len(payload) + len(encoded) + 1 > MAX_PLAN_BYTES:
            raise SeccompPatternError(f"encoded plan exceeds {MAX_PLAN_BYTES} bytes")
        placements[label] = len(payload)
        widths[label] = len(encoded)
        payload.extend(encoded)
        payload.extend(b"\n")

    add("header", {
        "format": "r5b-seccomp-operation-plan-v1", "architecture": architecture,
        "strategy": strategy, "inert": True, "filter_sha256": report.get("filter_sha256", "unknown"),
    })
    for index, operation in enumerate(operations):
        row = dict(operation)
        row["index"] = index
        row["review_only"] = True
        add(f"operation.{index}", row)
    add("constraints", {"constraints": normalized_constraints, "never_execute_or_deliver": True})
    return PayloadBuild(
        payload=bytes(payload), placements=placements, widths=widths,
        architecture=architecture, strategy=strategy,
        metadata={
            "constraints_json": json.dumps(normalized_constraints, sort_keys=True),
            "filter_sha256": str(report["filter_sha256"]),
            "operation_count": str(len(operations)),
            "review_only": "true",
        },
    )


def _operation(
    report: Mapping[str, object], name: str, intent: str,
    arguments: Sequence[str], *, exact_arguments: Sequence[int] | None = None,
) -> dict[str, object]:
    architecture = _report_arch(report)
    if not isinstance(name, str) or not _SYSCALL_NAME_RE.fullmatch(name):
        raise SeccompPatternError("syscall name must be a safe 1..64 byte label")
    normalized_intent = _bounded_text(intent, "operation intent")
    if isinstance(arguments, (str, bytes)) or not 1 <= len(arguments) <= 8:
        raise SeccompPatternError("operation arguments must contain 1..8 review strings")
    normalized_arguments = [
        _bounded_text(value, f"operation argument {index}", maximum=256)
        for index, value in enumerate(arguments)
    ]
    row = _decision_row(report, name) if exact_arguments is not None else _usable_decision(report, name)
    if row is None:
        raise SeccompPatternError(f"{name} is not directly reachable in the sampled filter domain")
    number = row.get("nr")
    if isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= 0x7FFFFFFF:
        raise SeccompPatternError(f"report has an invalid syscall number for {name}")
    if syscall_catalog(architecture).get(name) != number:
        raise SeccompPatternError(f"report syscall number for {name} does not match {architecture}")
    classification = row.get("classification")
    if classification not in {
        "always_allowed_in_sampled_domain", "conditionally_allowed",
        "externally_mediated", "blocked_in_sampled_domain",
    }:
        raise SeccompPatternError(f"report has an invalid classification for {name}")
    samples = row.get("direct_samples", ())
    if (not isinstance(samples, Sequence) or isinstance(samples, (str, bytes))
            or len(samples) > MAX_ARGUMENT_PROBES):
        raise SeccompPatternError(f"report has invalid direct samples for {name}")
    normalized_samples = [
        _bounded_text(sample, f"{name} sample", maximum=64) for sample in samples
    ]
    operation = {
        "kind": "syscall", "syscall": name, "nr": int(row["nr"]),
        "intent": normalized_intent, "arguments": normalized_arguments,
        "filter_classification": classification,
        "allowed_samples": normalized_samples,
    }
    if exact_arguments is not None:
        raw, padded = _exact_filter_action(report, name, exact_arguments)
        if not _direct(raw):
            raise SeccompPatternError(
                f"the exact {name} arguments are not directly allowed ({seccomp.action_name(raw)})"
            )
        operation["exact_filter_action"] = seccomp.action_name(raw)
        operation["validated_numeric_arguments"] = [
            f"0x{value:016x}" for value in padded
        ]
    return operation


def _read_arguments(name: str, fd: str, count: int) -> list[str]:
    if name == "read":
        return [fd, "controlled_buffer", str(count)]
    if name == "pread64":
        return [fd, "controlled_buffer", str(count), "0"]
    if name == "readv":
        return [fd, "reviewed_input_iovec", "1"]
    raise SeccompPatternError(f"{name} is not a supported buffered-read operation")


def _write_arguments(name: str, fd: str) -> list[str]:
    if name == "write":
        return [fd, "controlled_buffer", "bytes_read"]
    if name == "writev":
        return [fd, "reviewed_output_iovec", "1"]
    raise SeccompPatternError(f"{name} is not a supported buffered-output operation")


def _numeric_read_arguments(name: str, fd: int, buffer_address: int, count: int) -> list[int]:
    if name == "read":
        return [fd, buffer_address, count]
    if name == "pread64":
        return [fd, buffer_address, count, 0]
    if name == "readv":
        return [fd, buffer_address, 1]
    raise SeccompPatternError(f"{name} is not a supported buffered-read operation")


def _numeric_write_arguments(name: str, fd: int, buffer_address: int, count: int) -> list[int]:
    if name == "write":
        return [fd, buffer_address, count]
    if name == "writev":
        return [fd, buffer_address, 1]
    raise SeccompPatternError(f"{name} is not a supported buffered-output operation")


@_wrap_pattern_errors
def build_orw_plan(
    report: Mapping[str, object], *, path: str = "/flag",
    assumed_fd: int = 3, output_fd: int = 1, max_bytes: int = 0x1000,
    allow_inherited_fd: bool = True,
) -> PayloadBuild:
    """Build a review-only open/read/output or inherited-FD operation plan."""

    report = _canonical_report(report)
    architecture = _report_arch(report)
    try:
        path = _bounded_text(path, "path", maximum=256)
    except SeccompPatternError as exc:
        raise SeccompPatternError("path must be 1..256 printable UTF-8 bytes") from exc
    fd = ensure_uint(assumed_fd, 32, name="assumed_fd")
    out = ensure_uint(output_fd, 32, name="output_fd")
    count = ensure_uint(max_bytes, 32, name="max_bytes")
    if count == 0 or count > 1 << 20:
        raise SeccompPatternError("max_bytes must be in 1..1048576")
    capabilities = report.get("capabilities")
    if not isinstance(capabilities, Mapping):
        raise SeccompPatternError("report lacks capability analysis")
    openers = list(capabilities.get("openers", ()))
    readers = list(capabilities.get("readers", ()))
    writers = list(capabilities.get("writers", ()))
    transfers = list(capabilities.get("transfers", ()))
    buffered_route = bool(readers and writers)
    transfer_route = bool(transfers)
    if not buffered_route and not transfer_route:
        raise SeccompPatternError("no sampled read/output composition is directly reachable")
    operations: list[dict[str, object]] = []
    constraints = [
        "confirm every conditional allowed_samples predicate against the exact target arguments",
        "file-descriptor numbers are assumptions until established from challenge state",
        "this document is inert and must not be delivered as a payload",
    ]
    if openers:
        opener = next((name for name in ("openat", "open", "openat2") if name in openers))
        if opener == "open":
            args = [json.dumps(path), "O_RDONLY", "0"]
        elif opener == "openat":
            args = ["AT_FDCWD", json.dumps(path), "O_RDONLY", "0"]
        else:
            args = ["AT_FDCWD", json.dumps(path), "&open_how{flags=O_RDONLY}", "sizeof(open_how)"]
        operations.append(_operation(report, opener, "acquire read-only file descriptor", args))
        fd_symbol = "returned_fd"
    elif allow_inherited_fd:
        fd_symbol = str(fd)
        constraints.append(f"assume descriptor {fd} already refers to desired readable object")
    else:
        raise SeccompPatternError("no opener is allowed and inherited-FD planning is disabled")

    reader = next((name for name in ("read", "pread64", "readv") if name in readers), None)
    writer = next((name for name in ("write", "writev") if name in writers), None)
    transfer = next((name for name in ("sendfile", "sendfile64") if name in transfers), None)
    if reader is None or writer is None:
        if transfer is None:
            raise SeccompPatternError("no semantically complete sampled read/output route is reachable")
        operations.append(_operation(
            report, transfer, "copy file bytes directly to output descriptor",
            [str(out), fd_symbol, "offset_or_NULL", str(count)],
        ))
    else:
        operations.append(_operation(
            report, reader, "read bytes into caller-controlled buffer",
            _read_arguments(reader, fd_symbol, count),
        ))
        operations.append(_operation(
            report, writer, "emit bytes through known output descriptor",
            _write_arguments(writer, str(out)),
        ))
    return _encode_plan(
        report, strategy="seccomp-orw-review", operations=operations,
        constraints=[f"target architecture is {architecture}", *constraints],
    )


@_wrap_pattern_errors
def build_fd_reuse_plan(
    report: Mapping[str, object], *, source_fd: int, destination_fd: int = 100,
    output_fd: int = 1, buffer_address: int = 0x10000,
    max_bytes: int = 0x1000,
) -> PayloadBuild:
    """Duplicate an input FD to a distinct FD while preserving the output FD."""

    report = _canonical_report(report)
    source = ensure_uint(source_fd, 32, name="source_fd")
    destination = ensure_uint(destination_fd, 32, name="destination_fd")
    output = ensure_uint(output_fd, 32, name="output_fd")
    buffer = ensure_uint(buffer_address, 64, name="buffer_address")
    count = ensure_uint(max_bytes, 32, name="max_bytes")
    if not 1 <= count <= 1 << 20:
        raise SeccompPatternError("max_bytes must be in 1..1048576")
    if buffer == 0 or buffer + count > 1 << 64:
        raise SeccompPatternError("buffer_address must name a non-wrapping range")
    if len({source, destination, output}) != 3:
        raise SeccompPatternError(
            "source_fd, destination_fd, and output_fd must be distinct to preserve output"
        )

    duplicator = None
    dup_numeric: list[int] = []
    for candidate in ("dup3", "dup2"):
        if _decision_row(report, candidate) is None:
            continue
        candidate_args = ([source, destination, 0] if candidate == "dup3"
                          else [source, destination])
        raw, _padded = _exact_filter_action(report, candidate, candidate_args)
        if _direct(raw):
            duplicator, dup_numeric = candidate, candidate_args
            break
    if duplicator is None:
        raise SeccompPatternError(
            "no deterministic dup2/dup3 route allows the exact source/destination descriptors"
        )

    reader = None
    read_numeric: list[int] = []
    for candidate in ("read", "pread64", "readv"):
        if _decision_row(report, candidate) is None:
            continue
        candidate_args = _numeric_read_arguments(candidate, destination, buffer, count)
        raw, _padded = _exact_filter_action(report, candidate, candidate_args)
        if _direct(raw):
            reader, read_numeric = candidate, candidate_args
            break
    writer = None
    write_numeric: list[int] = []
    for candidate in ("write", "writev"):
        if _decision_row(report, candidate) is None:
            continue
        candidate_args = _numeric_write_arguments(candidate, output, buffer, count)
        raw, _padded = _exact_filter_action(report, candidate, candidate_args)
        if _direct(raw):
            writer, write_numeric = candidate, candidate_args
            break
    if reader is None or writer is None:
        raise SeccompPatternError(
            "fd reuse requires exact allowed read-from-duplicate and write-to-output arguments"
        )
    dup_args = {
        "dup3": [str(source), str(destination), "0"],
        "dup2": [str(source), str(destination)],
    }[duplicator]
    operations = [
        _operation(
            report, duplicator, "duplicate known input descriptor without replacing output",
            dup_args, exact_arguments=dup_numeric,
        ),
        _operation(
            report, reader, "read through the distinct duplicated input descriptor",
            _read_arguments(reader, str(destination), count), exact_arguments=read_numeric,
        ),
        _operation(
            report, writer, "emit recovered bytes through the preserved output descriptor",
            ([str(output), "controlled_buffer", str(count)] if writer == "write"
             else _write_arguments(writer, str(output))),
            exact_arguments=write_numeric,
        ),
    ]
    return _encode_plan(
        report, strategy="seccomp-fd-reuse-review", operations=operations,
        constraints=(
            f"descriptor {source} must be valid and accessible",
            f"descriptor {destination} is the dedicated input duplicate",
            f"descriptor {output} remains the distinct output descriptor",
            f"controlled buffer range starts at 0x{buffer:x} and spans at most {count} bytes",
            f"the write step is reached only when the read result is exactly {count} bytes",
        ),
    )


@_wrap_pattern_errors
def build_mprotect_plan(
    report: Mapping[str, object], *, page_address: int, length: int,
    protection: int = 7,
) -> PayloadBuild:
    """Build an inert mprotect review operation for caller-supplied memory."""

    report = _canonical_report(report)
    address = ensure_uint(page_address, 64, name="page_address")
    size = ensure_uint(length, 64, name="length")
    prot = ensure_uint(protection, 32, name="protection")
    if size == 0 or size > 1 << 30:
        raise SeccompPatternError("length must be in 1..1GiB")
    if address + size > 1 << 64:
        raise SeccompPatternError("page_address plus length wraps the 64-bit address space")
    if prot & ~0x7:
        raise SeccompPatternError("protection may contain only PROT_READ/WRITE/EXEC bits")
    if _decision_row(report, "mprotect") is None:
        raise SeccompPatternError("report has no mprotect decision")
    operations = [_operation(
        report, "mprotect", "change reviewed memory permissions",
        [f"0x{address:x}", f"0x{size:x}", f"0x{prot:x}"],
        exact_arguments=[address, size, prot],
    )]
    return _encode_plan(
        report, strategy="seccomp-mprotect-review", operations=operations,
        constraints=(
            "page_address must be page-aligned for the target kernel",
            "mapped range ownership and W^X policy must be confirmed",
            "this plan does not place or execute code",
        ),
    )


def build_exec_plan(
    report: Mapping[str, object], *, path: str = "/bin/sh",
    directory_fd: int = -100,
) -> PayloadBuild:
    """Build a review-only execve/execveat operation when directly reachable."""

    report = _canonical_report(report)
    try:
        path = _bounded_text(path, "path", maximum=256)
    except SeccompPatternError as exc:
        raise SeccompPatternError("path must be 1..256 printable UTF-8 bytes") from exc
    choice = next((name for name in ("execve", "execveat") if _usable_decision(report, name)), None)
    if choice is None:
        raise SeccompPatternError("neither execve nor execveat is directly reachable")
    if choice == "execve":
        args = [json.dumps(path), "reviewed_argv", "reviewed_envp"]
    else:
        if not isinstance(directory_fd, int) or not -(1 << 31) <= directory_fd < (1 << 31):
            raise SeccompPatternError("directory_fd must be a signed 32-bit integer")
        args = [str(directory_fd), json.dumps(path), "reviewed_argv", "reviewed_envp", "0"]
    return _encode_plan(
        report, strategy="seccomp-exec-review",
        operations=[_operation(report, choice, "replace process image", args)],
        constraints=(
            "path and argument vectors must already exist in readable process memory",
            "stacked filters, LSMs, namespaces, and no_new_privs may impose additional constraints",
            "the plan is documentation, not executable payload bytes",
        ),
    )


def build_allowed_composition_plan(
    report: Mapping[str, object], *, syscalls: Sequence[str],
    purpose: str = "caller-reviewed syscall composition",
) -> PayloadBuild:
    """Serialize an explicit sequence only when every syscall has a direct sample."""

    report = _canonical_report(report)
    if isinstance(syscalls, (str, bytes)):
        raise SeccompPatternError("syscalls must be a sequence of names")
    try:
        names = list(syscalls)
    except TypeError as exc:
        raise SeccompPatternError("syscalls must be an iterable of names") from exc
    if not 1 <= len(names) <= MAX_PLAN_OPERATIONS or any(not isinstance(name, str) for name in names):
        raise SeccompPatternError(f"syscalls must contain 1..{MAX_PLAN_OPERATIONS} names")
    normalized_purpose = _bounded_text(purpose, "purpose", maximum=256)
    operations = [
        _operation(report, name, normalized_purpose, ["caller_supplied_arguments"])
        for name in names
    ]
    return _encode_plan(
        report, strategy="seccomp-explicit-composition-review", operations=operations,
        constraints=(
            "classification is sampled rather than a symbolic proof over all arguments",
            "caller must preserve data/control dependencies between operations",
            "no operation is executed by this builder",
        ),
    )


def build_supervisor_review_plan(report: Mapping[str, object]) -> PayloadBuild:
    """Serialize TRACE/USER_NOTIF/LOG dependencies without assuming supervisor behavior."""

    report = _canonical_report(report)
    _report_arch(report)
    buckets = report.get("action_buckets")
    if not isinstance(buckets, Mapping):
        raise SeccompPatternError("report lacks action buckets")
    operations: list[dict[str, object]] = []
    for action in ("user_notif", "trace", "log"):
        names = buckets.get(action)
        if names:
            if (not isinstance(names, Sequence) or isinstance(names, (str, bytes))
                    or len(names) > 128):
                raise SeccompPatternError(f"report has invalid {action} syscall names")
            normalized_names = []
            for name in names:
                if not isinstance(name, str) or not _SYSCALL_NAME_RE.fullmatch(name):
                    raise SeccompPatternError(f"report has invalid {action} syscall name")
                normalized_names.append(name)
            operations.append({
                "kind": "supervision-review", "action": action,
                "syscalls": normalized_names,
                "intent": "review external supervisor/logging semantics",
            })
    if not operations:
        raise SeccompPatternError("filter has no sampled USER_NOTIF, TRACE, or LOG action")
    trace = report.get("trace_semantics")
    if not isinstance(trace, Mapping):
        raise SeccompPatternError("report lacks version-qualified TRACE semantics")
    trace_detail = _bounded_text(trace.get("detail"), "TRACE detail")
    return _encode_plan(
        report, strategy="seccomp-supervisor-review", operations=operations,
        constraints=(
            "USER_NOTIF does not execute without a supervisor response and may return ENOSYS otherwise",
            f"TRACE behavior is kernel-version dependent: {trace_detail}",
            "LOG executes the syscall after optional logging and is directly permissive",
            "pointer arguments inspected by a supervisor require atomic snapshot/TOCTOU review",
        ),
    )


__all__ = [
    "SeccompPatternError", "X32_SYSCALL_BIT", "analyze_seccomp_patterns",
    "decode_filter", "syscall_catalog", "build_orw_plan", "build_fd_reuse_plan",
    "build_mprotect_plan", "build_exec_plan", "build_allowed_composition_plan",
    "build_supervisor_review_plan",
]
