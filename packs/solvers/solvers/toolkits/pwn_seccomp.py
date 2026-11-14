#!/usr/bin/env python3
"""Statically inspect Linux seccomp classic-BPF filters (offline; never executes a target).

The reusable API accepts either ``sock_filter`` bytes or JSON instruction records, validates the
forward-only control-flow graph, and interprets it for a bounded table of named syscalls.  This is
particularly useful for filters emitted by libseccomp: the result lists allowed/denied calls and
states when ``execve`` is blocked but an open/read/write path remains.

An ELF input is only *read*.  Imports/strings are inspected for ``seccomp``/``prctl`` markers and
bounded, structurally valid embedded BPF arrays are reported.  The module opens no sockets, runs no
binary, and sends no generated data anywhere.

CLI::

    .venv/bin/python solvers/toolkits/pwn_seccomp.py filter.bpf --arch amd64 [--json]
    .venv/bin/python solvers/toolkits/pwn_seccomp.py filter.json --arch aarch64 [--json]
    .venv/bin/python solvers/toolkits/pwn_seccomp.py challenge.elf [--json]
"""
from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(1, str(HERE))

import pwn as _pwn  # noqa: E402 - the adjacent static ELF reader, not pwntools

MAX_FILE = 64 * 1024 * 1024
MAX_SCAN_BYTES = 8 * 1024 * 1024
MAX_INSNS = 512
MAX_FILTERS = 16

# Classic-BPF instruction classes / fields (linux/filter.h).
BPF_LD, BPF_LDX, BPF_ST, BPF_STX = 0x00, 0x01, 0x02, 0x03
BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC = 0x04, 0x05, 0x06, 0x07
BPF_W, BPF_H, BPF_B = 0x00, 0x08, 0x10
BPF_IMM, BPF_ABS, BPF_IND, BPF_MEM, BPF_LEN, BPF_MSH = 0x00, 0x20, 0x40, 0x60, 0x80, 0xA0
BPF_K, BPF_X, BPF_A = 0x00, 0x08, 0x10
BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV = 0x00, 0x10, 0x20, 0x30
BPF_OR, BPF_AND, BPF_LSH, BPF_RSH = 0x40, 0x50, 0x60, 0x70
BPF_NEG, BPF_MOD, BPF_XOR = 0x80, 0x90, 0xA0
BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET = 0x00, 0x10, 0x20, 0x30, 0x40
BPF_TAX, BPF_TXA = 0x00, 0x80

# seccomp return actions (linux/seccomp.h).
SECCOMP_RET_KILL_THREAD = 0x00000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_TRACE = 0x7FF00000
SECCOMP_RET_LOG = 0x7FFC0000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_USER_NOTIF = 0x7FC00000
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ACTION_FULL = 0xFFFF0000
SECCOMP_RET_DATA = 0x0000FFFF

AUDIT_ARCH = {
    "amd64": 0xC000003E,
    "i386": 0x40000003,
    "arm": 0x40000028,
    "aarch64": 0xC00000B7,
}

# A deliberately finite high-value syscall catalog.  The interpreter accepts any numeric syscall;
# this table controls only which names the report explores.
SYSCALLS = {
    "amd64": {
        "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5,
        "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12,
        "rt_sigaction": 13, "rt_sigreturn": 15, "ioctl": 16, "pread64": 17,
        "readv": 19, "writev": 20, "access": 21, "pipe": 22, "dup": 32, "dup2": 33,
        "getpid": 39, "sendfile": 40, "socket": 41, "connect": 42, "accept": 43,
        "sendto": 44, "recvfrom": 45, "bind": 49, "listen": 50, "setsockopt": 54,
        "getsockopt": 55, "clone": 56, "fork": 57, "vfork": 58, "execve": 59,
        "exit": 60, "wait4": 61, "kill": 62, "uname": 63, "fcntl": 72,
        "getcwd": 79, "chdir": 80, "mkdir": 83, "unlink": 87, "readlink": 89,
        "arch_prctl": 158, "gettid": 186, "futex": 202, "getdents64": 217,
        "exit_group": 231, "openat": 257, "newfstatat": 262, "unlinkat": 263,
        "readlinkat": 267, "prlimit64": 302, "getrandom": 318, "memfd_create": 319,
        "statx": 332, "clone3": 435, "openat2": 437,
    },
    "i386": {
        "exit": 1, "fork": 2, "read": 3, "write": 4, "open": 5, "close": 6,
        "waitpid": 7, "creat": 8, "link": 9, "unlink": 10, "execve": 11,
        "chdir": 12, "lseek": 19, "getpid": 20, "kill": 37, "dup": 41,
        "pipe": 42, "brk": 45, "ioctl": 54, "fcntl": 55, "mmap2": 192,
        "mprotect": 125, "munmap": 91, "getdents64": 220, "exit_group": 252,
        "openat": 295, "unlinkat": 301, "readlinkat": 305, "getrandom": 355,
    },
    "arm": {
        "exit": 1, "fork": 2, "read": 3, "write": 4, "open": 5, "close": 6,
        "execve": 11, "lseek": 19, "getpid": 20, "brk": 45, "mmap2": 192,
        "mprotect": 125, "munmap": 91, "exit_group": 248, "openat": 322,
        "unlinkat": 328, "readlinkat": 332, "getrandom": 384,
    },
    "aarch64": {
        "getcwd": 17, "dup": 23, "fcntl": 25, "ioctl": 29, "unlinkat": 35,
        "openat": 56, "close": 57, "lseek": 62, "read": 63, "write": 64,
        "readv": 65, "writev": 66, "pread64": 67, "sendfile": 71,
        "exit": 93, "exit_group": 94, "futex": 98, "kill": 129, "getpid": 172,
        "gettid": 178, "socket": 198, "bind": 200, "listen": 201, "accept": 202,
        "connect": 203, "sendto": 206, "recvfrom": 207, "brk": 214,
        "munmap": 215, "clone": 220, "execve": 221, "mmap": 222,
        "mprotect": 226, "getrandom": 278, "statx": 291, "clone3": 435,
        "openat2": 437,
    },
}


class SeccompError(ValueError):
    """Malformed or unsupported classic-BPF input."""


@dataclass(frozen=True)
class Instruction:
    code: int
    jt: int
    jf: int
    k: int

    def as_dict(self) -> dict:
        return {"code": self.code, "jt": self.jt, "jf": self.jf, "k": self.k}


def _as_int(value, field: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise SeccompError(f"{field} must be an integer")
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError as exc:
            raise SeccompError(f"{field} is not an integer: {value!r}") from exc
    if not isinstance(value, int) or not 0 <= value <= maximum:
        raise SeccompError(f"{field} must be in 0..{maximum:#x}")
    return value


def parse_sock_filters(data: bytes, endian: str = "little") -> list[Instruction]:
    """Parse a packed ``struct sock_filter[]`` (``u16,u8,u8,u32``).

    The array must be exact and contain at most :data:`MAX_INSNS` instructions.  Use
    :func:`validate_program` after parsing when the bytes are supposed to be a complete filter.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise SeccompError("BPF input must be bytes")
    if not data or len(data) % 8:
        raise SeccompError("packed sock_filter data must be a non-empty multiple of 8 bytes")
    if len(data) // 8 > MAX_INSNS:
        raise SeccompError(f"filter exceeds {MAX_INSNS} instructions")
    if not isinstance(endian, str) or endian not in ("little", "big"):
        raise SeccompError("endian must be 'little' or 'big'")
    ec = "<" if endian == "little" else ">"
    return [Instruction(*vals) for vals in struct.iter_unpack(ec + "HBBI", bytes(data))]


def parse_json_program(value) -> list[Instruction]:
    """Parse JSON-compatible instruction records without evaluating any challenge text."""
    if isinstance(value, dict):
        value = value.get("instructions")
    if not isinstance(value, list) or not value:
        raise SeccompError("JSON filter must be a non-empty instruction list")
    if len(value) > MAX_INSNS:
        raise SeccompError(f"filter exceeds {MAX_INSNS} instructions")
    out = []
    for i, row in enumerate(value):
        if isinstance(row, (list, tuple)) and len(row) == 4:
            code, jt, jf, k = row
        elif isinstance(row, dict):
            try:
                code, jt, jf, k = row["code"], row.get("jt", 0), row.get("jf", 0), row["k"]
            except KeyError as exc:
                raise SeccompError(f"instruction {i} lacks {exc.args[0]}") from exc
        else:
            raise SeccompError(f"instruction {i} must be an object or four-item list")
        out.append(Instruction(_as_int(code, f"instruction {i} code", 0xFFFF),
                               _as_int(jt, f"instruction {i} jt", 0xFF),
                               _as_int(jf, f"instruction {i} jf", 0xFF),
                               _as_int(k, f"instruction {i} k", 0xFFFFFFFF)))
    return out


def _successors(ins: Instruction, pc: int) -> tuple[int, ...]:
    cls = ins.code & 0x07
    if cls == BPF_RET:
        return ()
    if cls == BPF_JMP:
        op = ins.code & 0xF0
        if op == BPF_JA:
            return (pc + 1 + ins.k,)
        if op in (BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET):
            return (pc + 1 + ins.jt, pc + 1 + ins.jf)
        raise SeccompError(f"unsupported BPF jump opcode {ins.code:#x} at instruction {pc}")
    return (pc + 1,)


def _validate_opcode(ins: Instruction, pc: int) -> None:
    """Reject class-bit-valid but nonsensical opcode combinations before interpretation."""
    cls = ins.code & 0x07
    if cls in (BPF_LD, BPF_LDX):
        mode, size = ins.code & 0xE0, ins.code & 0x18
        modes = {BPF_IMM, BPF_ABS, BPF_IND, BPF_MEM, BPF_LEN}
        if cls == BPF_LDX:
            modes.add(BPF_MSH)
        if mode not in modes:
            raise SeccompError(f"unsupported BPF load mode {mode:#x} at instruction {pc}")
        if size not in (BPF_W, BPF_H, BPF_B):
            raise SeccompError(f"unsupported BPF load size at instruction {pc}")
        if mode in (BPF_IMM, BPF_MEM, BPF_LEN) and size != BPF_W:
            raise SeccompError(f"BPF load mode {mode:#x} must use word size at instruction {pc}")
        if mode == BPF_MSH and (cls != BPF_LDX or size != BPF_B):
            raise SeccompError(f"invalid BPF MSH load at instruction {pc}")
    elif cls in (BPF_ST, BPF_STX):
        if ins.code != cls:
            raise SeccompError(f"invalid BPF store opcode {ins.code:#x} at instruction {pc}")
    elif cls == BPF_ALU:
        op = ins.code & 0xF0
        if op not in (BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_OR, BPF_AND,
                      BPF_LSH, BPF_RSH, BPF_NEG, BPF_MOD, BPF_XOR):
            raise SeccompError(f"unsupported BPF ALU opcode {ins.code:#x} at instruction {pc}")
        if op == BPF_NEG and ins.code & BPF_X:
            raise SeccompError(f"BPF_NEG takes no source operand at instruction {pc}")
        if op in (BPF_LSH, BPF_RSH) and not (ins.code & BPF_X) and ins.k >= 32:
            raise SeccompError(f"constant shift {ins.k} exceeds 31 at instruction {pc}")
    elif cls == BPF_JMP:
        op = ins.code & 0xF0
        if op not in (BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET):
            raise SeccompError(f"unsupported BPF jump opcode {ins.code:#x} at instruction {pc}")
        if op == BPF_JA and ins.code & BPF_X:
            raise SeccompError(f"BPF_JA takes no source operand at instruction {pc}")
    elif cls == BPF_RET:
        if (ins.code & 0x18) not in (BPF_K, BPF_A):
            raise SeccompError(f"unsupported BPF return opcode {ins.code:#x} at instruction {pc}")
    elif cls == BPF_MISC:
        if (ins.code & 0xF8) not in (BPF_TAX, BPF_TXA):
            raise SeccompError(f"unsupported BPF misc opcode {ins.code:#x} at instruction {pc}")


def validate_program(program: Sequence[Instruction]) -> None:
    """Validate reachable control flow and supported classic-BPF classes.

    Kernel classic BPF has forward jumps only.  Every reachable path must stay inside the supplied
    array and terminate at ``RET``; unreachable padding is tolerated, as the kernel does.
    """
    if not program or len(program) > MAX_INSNS:
        raise SeccompError(f"filter must contain 1..{MAX_INSNS} instructions")
    todo, seen, returns = [0], set(), 0
    while todo:
        pc = todo.pop()
        if pc in seen:
            continue
        if pc < 0 or pc >= len(program):
            raise SeccompError(f"control flow escapes filter at instruction {pc}")
        seen.add(pc)
        ins = program[pc]
        if not isinstance(ins, Instruction):
            raise SeccompError(f"instruction {pc} is not a sock_filter record")
        cls = ins.code & 0x07
        if cls not in (BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC):
            raise SeccompError(f"unsupported BPF class {cls:#x} at instruction {pc}")
        _validate_opcode(ins, pc)
        succ = _successors(ins, pc)
        if not succ:
            returns += 1
        for nxt in succ:
            if nxt <= pc:
                raise SeccompError(f"non-forward jump at instruction {pc}")
            todo.append(nxt)
    if not returns:
        raise SeccompError("filter has no reachable return")


def _load_abs(blob: bytes, at: int, size: int, endian: str) -> int:
    if at < 0 or at + size > len(blob):
        raise SeccompError(f"BPF load outside seccomp_data at offset {at}")
    return int.from_bytes(blob[at:at + size], endian)


def execute_filter(program: Sequence[Instruction], syscall_nr: int, audit_arch: int,
                   args: Sequence[int] = (), endian: str = "little") -> int:
    """Interpret one validated classic-BPF seccomp program and return its raw action word.

    ``seccomp_data`` is synthesized from the caller-supplied syscall number, audit architecture and
    up to six argument words.  No native code is involved.
    """
    validate_program(program)
    if endian not in ("little", "big"):
        raise SeccompError("endian must be 'little' or 'big'")
    if (isinstance(syscall_nr, bool) or not isinstance(syscall_nr, int)
            or not -(1 << 31) <= syscall_nr < (1 << 31)):
        raise SeccompError("syscall number must be a signed 32-bit integer")
    if (isinstance(audit_arch, bool) or not isinstance(audit_arch, int)
            or not 0 <= audit_arch <= 0xFFFFFFFF):
        raise SeccompError("audit architecture must be an unsigned 32-bit integer")
    if not isinstance(args, (list, tuple)):
        raise SeccompError("syscall arguments must be a sequence")
    argvals = [_as_int(v, "syscall argument", 0xFFFFFFFFFFFFFFFF) for v in args[:6]]
    argvals += [0] * (6 - len(argvals))
    ec = "<" if endian == "little" else ">"
    blob = struct.pack(ec + "iIQQQQQQQ", int(syscall_nr), audit_arch & 0xFFFFFFFF, 0, *argvals)
    a = x = 0
    mem = [0] * 16
    pc = 0
    for _step in range(len(program) + 1):
        ins = program[pc]
        cls = ins.code & 0x07
        if cls in (BPF_LD, BPF_LDX):
            mode, size_code = ins.code & 0xE0, ins.code & 0x18
            target_x = cls == BPF_LDX
            if mode == BPF_IMM:
                val = ins.k
            elif mode == BPF_LEN:
                val = len(blob)
            elif mode == BPF_MEM:
                if ins.k >= len(mem):
                    raise SeccompError(f"BPF memory index {ins.k} out of range")
                val = mem[ins.k]
            elif cls == BPF_LDX and mode == BPF_MSH:
                val = (_load_abs(blob, ins.k, 1, endian) & 0xF) << 2
            elif mode in (BPF_ABS, BPF_IND):
                width = {BPF_W: 4, BPF_H: 2, BPF_B: 1}.get(size_code)
                if width is None:
                    raise SeccompError(f"unsupported BPF load size at instruction {pc}")
                at = ins.k + (x if mode == BPF_IND else 0)
                val = _load_abs(blob, at, width, endian)
            else:
                raise SeccompError(f"unsupported BPF load mode {mode:#x} at instruction {pc}")
            if target_x:
                x = val & 0xFFFFFFFF
            else:
                a = val & 0xFFFFFFFF
            pc += 1
        elif cls == BPF_ST:
            if ins.k >= len(mem):
                raise SeccompError(f"BPF memory index {ins.k} out of range")
            mem[ins.k] = a
            pc += 1
        elif cls == BPF_STX:
            if ins.k >= len(mem):
                raise SeccompError(f"BPF memory index {ins.k} out of range")
            mem[ins.k] = x
            pc += 1
        elif cls == BPF_ALU:
            op, rhs = ins.code & 0xF0, (x if ins.code & BPF_X else ins.k)
            if op == BPF_ADD:
                a += rhs
            elif op == BPF_SUB:
                a -= rhs
            elif op == BPF_MUL:
                a *= rhs
            elif op == BPF_DIV:
                if rhs == 0:
                    raise SeccompError("BPF division by zero")
                a //= rhs
            elif op == BPF_OR:
                a |= rhs
            elif op == BPF_AND:
                a &= rhs
            elif op == BPF_LSH:
                a <<= rhs & 31
            elif op == BPF_RSH:
                a >>= rhs & 31
            elif op == BPF_NEG:
                a = -a
            elif op == BPF_MOD:
                if rhs == 0:
                    raise SeccompError("BPF modulo by zero")
                a %= rhs
            elif op == BPF_XOR:
                a ^= rhs
            else:
                raise SeccompError(f"unsupported BPF ALU opcode {ins.code:#x} at instruction {pc}")
            a &= 0xFFFFFFFF
            pc += 1
        elif cls == BPF_JMP:
            op, rhs = ins.code & 0xF0, (x if ins.code & BPF_X else ins.k)
            if op == BPF_JA:
                pc += 1 + ins.k
                continue
            cond = {BPF_JEQ: a == rhs, BPF_JGT: a > rhs, BPF_JGE: a >= rhs,
                    BPF_JSET: bool(a & rhs)}.get(op)
            if cond is None:
                raise SeccompError(f"unsupported BPF jump opcode {ins.code:#x} at instruction {pc}")
            pc += 1 + (ins.jt if cond else ins.jf)
        elif cls == BPF_RET:
            return (a if (ins.code & 0x18) == BPF_A else ins.k) & 0xFFFFFFFF
        elif cls == BPF_MISC:
            op = ins.code & 0xF8
            if op == BPF_TAX:
                x = a
            elif op == BPF_TXA:
                a = x
            else:
                raise SeccompError(f"unsupported BPF misc opcode {ins.code:#x} at instruction {pc}")
            pc += 1
        if pc < 0 or pc >= len(program):
            raise SeccompError(f"control flow escapes filter at instruction {pc}")
    raise SeccompError("filter did not terminate within its instruction bound")


def action_name(value: int) -> str:
    """Render a seccomp action word, preserving ERRNO/TRACE/USER_NOTIF data."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise SeccompError("action word must be an unsigned 32-bit integer")
    action, data = value & SECCOMP_RET_ACTION_FULL, value & SECCOMP_RET_DATA
    names = {
        SECCOMP_RET_KILL_THREAD: "kill_thread", SECCOMP_RET_KILL_PROCESS: "kill_process",
        SECCOMP_RET_TRAP: "trap", SECCOMP_RET_ERRNO: "errno", SECCOMP_RET_TRACE: "trace",
        SECCOMP_RET_LOG: "log", SECCOMP_RET_ALLOW: "allow", SECCOMP_RET_USER_NOTIF: "user_notif",
    }
    name = names.get(action, f"unknown_{action:#x}")
    return f"{name}({data})" if data and action in (SECCOMP_RET_ERRNO, SECCOMP_RET_TRACE,
                                                    SECCOMP_RET_USER_NOTIF) else name


def analyze_filter(program: Sequence[Instruction], arch: str = "amd64") -> dict:
    """Return named allow/deny decisions and an exploitation-oriented verdict.

    ``allowed`` means the action is ``ALLOW`` or ``LOG`` (which logs and continues).  TRACE and
    USER_NOTIF are kept in ``decisions`` but conservatively placed in ``denied`` because their
    outcome depends on an external supervisor.
    """
    if not isinstance(arch, str) or arch not in SYSCALLS:
        raise SeccompError(f"unknown architecture {arch!r}; choose {', '.join(sorted(SYSCALLS))}")
    validate_program(program)
    decisions, allowed, denied = {}, [], []
    for name, nr in sorted(SYSCALLS[arch].items(), key=lambda item: (item[1], item[0])):
        raw = execute_filter(program, nr, AUDIT_ARCH[arch])
        rendered = action_name(raw)
        decisions[name] = {"nr": nr, "action": rendered, "raw": f"0x{raw:08x}"}
        if (raw & SECCOMP_RET_ACTION_FULL) in (SECCOMP_RET_ALLOW, SECCOMP_RET_LOG):
            allowed.append(name)
        else:
            denied.append(name)
    sentinel = execute_filter(program, 0x3FFFFFFF, AUDIT_ARCH[arch])
    exec_blocked = "execve" in denied
    orw = ("read" in allowed and "write" in allowed
           and ("open" in allowed or "openat" in allowed or "openat2" in allowed))
    if exec_blocked and orw:
        verdict = "execve blocked \u2192 ORW"
    elif exec_blocked:
        verdict = "execve blocked; inspect the remaining allowlist"
    else:
        verdict = "execve allowed"
    return {"arch": arch, "instruction_count": len(program), "allowed": allowed, "denied": denied,
            "decisions": decisions, "default_action": action_name(sentinel), "verdict": verdict}


def detect_seccomp(data: bytes) -> dict:
    """Static seccomp/prctl markers in an ELF or arbitrary byte blob."""
    if not isinstance(data, (bytes, bytearray)):
        raise SeccompError("binary input must be bytes")
    imports = []
    if data[:4] == b"\x7fELF":
        info = _pwn.read_elf(data)
        if info:
            imports = sorted(set(info.get("imports", ())) & {"seccomp", "prctl", "syscall"})
    lower = data[:MAX_SCAN_BYTES].lower()
    strings = [s for s in ("seccomp", "prctl", "pr_set_seccomp", "pr_set_no_new_privs",
                           "no_new_privs", "libseccomp") if s.encode() in lower]
    return {"elf": data[:4] == b"\x7fELF", "imports": imports, "string_markers": strings,
            "likely_seccomp": bool(imports or strings)}


def _program_signature(program: Sequence[Instruction]) -> bool:
    loads_nr = any((i.code & 0x07) == BPF_LD and (i.code & 0xE0) == BPF_ABS and i.k == 0
                   for i in program)
    returns = [i.k & SECCOMP_RET_ACTION_FULL for i in program if (i.code & 0x07) == BPF_RET]
    known = {SECCOMP_RET_ALLOW, SECCOMP_RET_LOG, SECCOMP_RET_ERRNO, SECCOMP_RET_TRAP,
             SECCOMP_RET_KILL_THREAD, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_TRACE,
             SECCOMP_RET_USER_NOTIF}
    return loads_nr and len(returns) >= 2 and all(a in known for a in returns)


def find_embedded_filters(data: bytes, endian: str = "little") -> list[dict]:
    """Find bounded, structurally complete ``sock_filter`` arrays embedded in a byte blob.

    Candidates must begin with an absolute load of ``seccomp_data.nr`` or ``.arch``, contain a
    syscall-number load, and have at least two recognized seccomp return actions.  These constraints
    keep arbitrary ELF data from being mislabeled as BPF.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise SeccompError("binary input must be bytes")
    if not isinstance(endian, str) or endian not in ("little", "big"):
        raise SeccompError("endian must be 'little' or 'big'")
    blob = bytes(data[:MAX_SCAN_BYTES])
    ec = "<" if endian == "little" else ">"
    starts = set()
    for k in (0, 4):
        needle = struct.pack(ec + "HBBI", BPF_LD | BPF_W | BPF_ABS, 0, 0, k)
        pos = blob.find(needle)
        while pos >= 0 and len(starts) < MAX_FILTERS * 32:
            starts.add(pos)
            pos = blob.find(needle, pos + 1)
    out, covered = [], []
    for start in sorted(starts):
        if any(lo <= start < hi for lo, hi in covered):
            continue
        limit = min(MAX_INSNS, (len(blob) - start) // 8)
        for count in range(3, limit + 1):
            try:
                program = parse_sock_filters(blob[start:start + count * 8], endian)
                validate_program(program)
            except SeccompError:
                continue
            if _program_signature(program):
                out.append({"offset": start, "byte_length": count * 8, "instructions": program})
                covered.append((start, start + count * 8))
                break
        if len(out) >= MAX_FILTERS:
            break
    return out


def _read_bounded(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_FILE:
        raise SeccompError(f"input is {size} bytes; maximum is {MAX_FILE}")
    return path.read_bytes()


def inspect_file(path: str | Path, arch: str = "amd64", endian: str = "little",
                 fmt: str = "auto") -> dict:
    """Inspect a raw-BPF, JSON, or ELF file and return a JSON-safe report."""
    try:
        p = Path(path)
    except TypeError as exc:
        raise SeccompError("path must be a filesystem path") from exc
    try:
        data = _read_bounded(p)
    except OSError as exc:
        raise SeccompError(f"cannot read filter file: {exc}") from exc
    chosen = fmt
    if fmt == "auto":
        if p.suffix.lower() == ".json" or data.lstrip().startswith((b"[", b"{")):
            chosen = "json"
        elif data[:4] == b"\x7fELF":
            chosen = "elf"
        else:
            chosen = "bpf"
    if chosen == "json":
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SeccompError(f"invalid JSON filter: {exc}") from exc
        program = parse_json_program(value)
        validate_program(program)
        return {"file": str(p), "format": "json", "instructions": [i.as_dict() for i in program],
                "analysis": analyze_filter(program, arch)}
    if chosen == "bpf":
        program = parse_sock_filters(data, endian)
        validate_program(program)
        return {"file": str(p), "format": "sock_filter", "endian": endian,
                "instructions": [i.as_dict() for i in program], "analysis": analyze_filter(program, arch)}
    if chosen == "elf":
        detection = detect_seccomp(data)
        found = []
        for item in find_embedded_filters(data, endian):
            program = item.pop("instructions")
            found.append({**item, "instructions": [i.as_dict() for i in program],
                          "analysis": analyze_filter(program, arch)})
        return {"file": str(p), "format": "elf", "endian": endian,
                "detection": detection, "filters": found}
    raise SeccompError("format must be auto, elf, bpf, or json")


def _parse_argv(argv: Sequence[str]) -> dict:
    opts = {"arch": "amd64", "endian": "little", "format": "auto", "json": False, "path": None}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if not isinstance(arg, str):
            raise SeccompError("command-line arguments must be strings")
        if arg in ("-h", "--help"):
            opts["help"] = True
        elif arg == "--json":
            opts["json"] = True
        elif arg in ("--arch", "--endian", "--format"):
            if i + 1 >= len(argv):
                raise SeccompError(f"{arg} requires a value")
            opts[arg[2:]] = argv[i + 1]
            i += 1
        elif arg.startswith("--"):
            raise SeccompError(f"unknown option {arg}")
        elif opts["path"] is None:
            opts["path"] = arg
        else:
            raise SeccompError("exactly one input file is accepted")
        i += 1
    return opts


def main(argv: Sequence[str] | None = None) -> int:
    try:
        argv = list(sys.argv[1:] if argv is None else argv)
        opts = _parse_argv(argv)
        if opts.get("help"):
            print("usage: pwn_seccomp.py <filter.bpf|filter.json|elf> "
                  "[--arch amd64|i386|arm|aarch64] [--endian little|big] "
                  "[--format auto|bpf|json|elf] [--json]")
            return 0
        if not opts["path"]:
            raise SeccompError("usage: pwn_seccomp.py <filter.bpf|filter.json|elf> "
                               "[--arch amd64|i386|arm|aarch64] [--endian little|big] "
                               "[--format auto|bpf|json|elf] [--json]")
        report = inspect_file(opts["path"], opts["arch"], opts["endian"], opts["format"])
        if opts["json"]:
            print(json.dumps(report, indent=2, sort_keys=True))
        elif report["format"] == "elf":
            d = report["detection"]
            print(f"{report['file']}: ELF; seccomp markers={d['likely_seccomp']} "
                  f"imports={','.join(d['imports']) or '-'} strings={','.join(d['string_markers']) or '-'}")
            if not report["filters"]:
                print("  no structurally complete embedded sock_filter array found")
            for filt in report["filters"]:
                a = filt["analysis"]
                print(f"  filter @ {filt['offset']:#x}: {a['instruction_count']} instructions; "
                      f"default={a['default_action']}; {a['verdict']}")
                print("    allowed: " + (", ".join(a["allowed"]) or "(none in named catalog)"))
                print("    denied:  " + (", ".join(a["denied"]) or "(none in named catalog)"))
        else:
            a = report["analysis"]
            print(f"{report['file']}: {a['instruction_count']} instructions; "
                  f"default={a['default_action']}; {a['verdict']}")
            print("  allowed: " + (", ".join(a["allowed"]) or "(none in named catalog)"))
            print("  denied:  " + (", ".join(a["denied"]) or "(none in named catalog)"))
        return 0
    except (OSError, SeccompError, ValueError, TypeError) as exc:
        print(f"pwn_seccomp.py: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
