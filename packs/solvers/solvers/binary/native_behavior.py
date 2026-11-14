#!/usr/bin/env python3
"""Bounded semantic fallback for an explicitly described lone/static ELF decoder.

This is the production bridge from the Binary lane to ``common/native_image.py``.  It is intentionally
narrow: a question must state one integer ABI argument, return width and byte order; the stripped ELF's
entry point must bind that same argument at a direct call; and every viable call target must agree on the
returned value.  The whole-image emulator remains the primary evaluator, including its loader,
relocations, constructors, internal calls, lookup tables, definedness and two-layout agreement.

On a host where Unicorn is deliberately disabled by ``native_emulate``'s Darwin/arm64 capability guard,
an exact bounded x86-64 evaluator covers a pure integer decoder subset.  It is not a loader replacement:
``native_image.load`` must first accept the ELF, every instruction/operand and every read must be modelled,
and two distinct stack layouts must agree.  Unsupported code, unknown-register input, indirect control
flow, path explosion, malformed ELF, multiple differing callees, or incomplete answer wording is ``None``.

Since B-166 the decoder need not be called from the entry point.  When the entry binds nothing,
``decoder_discovery.unary_rows`` supplies the targets: every direct call anywhere in the image that passes
the stated integer to a one-argument function, else every one-argument function that looks like a decoder.
The rule is unchanged: every target must evaluate and agree, or the answer is ``None``.  The bounded
evaluator takes several integer / image-pointer arguments, runs its two layouts at different image
addresses as well as stacks (a result that depends on where the image is loaded declines), and declines a
read of a slot the loader would relocate.

All results are instance-scoped ``labels.candidates``.  This module establishes behavior, not the
challenge author's answer spelling.
"""
from __future__ import annotations

import hashlib
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import labels  # noqa: E402

MAX_ENTRY_BYTES = 1024
MAX_CANDIDATES = 16
MAX_STEPS = 50_000
MAX_VISITS = 4096
MAX_CALL_DEPTH = 32
MAX_STACK = 1 << 20
MAX_WIDTH = 8

_ASK = re.compile(r"\b(?:recover|derive|determine|find|compute|submit)\b", re.I)
_DECODER = re.compile(r"\b(?:decoder|decode|transform|verifier|checker|routine|function)\b", re.I)
_RETURN = re.compile(r"\b(?:return(?:ed|s|ing)?|result|output)\b", re.I)


class Decline(Exception):
    """The bounded evaluator cannot prove the behavior."""


@dataclass(frozen=True)
class Contract:
    argument: int
    width: int
    endian: str
    explicit_address: int | None = None


def _text(q) -> str:
    if not isinstance(q, dict):
        return str(q or "")
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    return " ".join(str(x or "") for x in
                    (q.get("qid"), q.get("id"), q.get("question"), fmt.get("syntax")))


def asks(q) -> bool:
    text = _text(q)
    return bool(_ASK.search(text) and _DECODER.search(text) and _RETURN.search(text))


def _one_int(patterns, text):
    vals = set()
    for pattern in patterns:
        for m in re.finditer(pattern, text, re.I):
            try:
                vals.add(int(m.group(1), 0))
            except (TypeError, ValueError):
                pass
    return next(iter(vals)) if len(vals) == 1 else None


def contract(q) -> Contract | None:
    """The one explicit integer-call contract the fallback may bind."""
    text = _text(q)
    if not asks(q):
        return None
    arg = _one_int((
        r"\b(?:seed|argument|arg(?:ument)?\s*0|input\s+integer)\s*(?:is|=|:|of)?\s*(0x[0-9a-f]+|\d+)\b",
        r"\b(?:rdi|edi|x0|w0)\s*=\s*(0x[0-9a-f]+|\d+)\b",
        r"\bcall(?:ed)?\s+with\s+(?:the\s+)?(?:integer\s+)?(0x[0-9a-f]+|\d+)\b",
    ), text)
    widths = set()
    for m in re.finditer(r"\b([1-8])[- ]byte\s+(?:return(?:ed)?\s+)?(?:value|integer|result|output|bytes?)\b", text, re.I):
        widths.add(int(m.group(1)))
    for m in re.finditer(r"\b(?:return(?:ed)?|result|output)\b.{0,32}\b(8|16|32|64)[- ]bit\b", text, re.I):
        widths.add(int(m.group(1)) // 8)
    little = bool(re.search(r"\blittle[- ]endian\b", text, re.I))
    big = bool(re.search(r"\bbig[- ]endian\b", text, re.I))
    if arg is None or arg < 0 or arg >= 1 << 64 or len(widths) != 1 or little == big:
        return None
    width = next(iter(widths))
    if not 1 <= width <= MAX_WIDTH:
        return None
    addrs = {int(m.group(1), 16) for m in re.finditer(
        r"\b(?:function|routine|decoder|address)\s+(?:at\s+)?(0x[0-9a-f]+)\b", text, re.I)}
    if len(addrs) > 1:
        return None
    return Contract(arg, width, "little" if little else "big", next(iter(addrs), None))


def _native():
    try:
        import native_image
        return native_image
    except Exception:
        return None


def _entry(img, data: bytes) -> int:
    if len(data) < 32:
        raise Decline("short ELF header")
    return struct.unpack_from("<Q", data, 24)[0]


def _file_bytes(img, addr: int, size: int) -> bytes:
    for va, memsz, filesz, off, _flags in img.loads:
        if va <= addr and addr + size <= va + filesz:
            at = off + addr - va
            return img.data[at:at + size]
    raise Decline("virtual address is not wholly file-backed")


def _in_exec(img, addr: int) -> bool:
    return any((flags & 1) and va <= addr < va + memsz for va, memsz, _fs, _off, flags in img.loads)


def _direct_calls_x86(img, entry: int, arg: int):
    try:
        import capstone
        from capstone import x86
    except Exception as exc:
        raise Decline(str(exc))
    raw = _file_bytes(img, entry, min(MAX_ENTRY_BYTES, max(
        (va + fs - entry for va, _ms, fs, _off, fl in img.loads if fl & 1 and va <= entry < va + fs),
        default=0)))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    known = {}
    out = []
    for count, ins in enumerate(md.disasm(raw, entry)):
        if count >= 256:
            break
        ops = ins.operands
        if ins.mnemonic == "mov" and len(ops) == 2 and ops[0].type == x86.X86_OP_REG and ops[1].type == x86.X86_OP_IMM:
            name = ins.reg_name(ops[0].reg)
            if name in ("edi", "rdi"):
                known["rdi"] = int(ops[1].imm) & ((1 << (32 if name == "edi" else 64)) - 1)
        elif ins.mnemonic == "xor" and len(ops) == 2 and all(op.type == x86.X86_OP_REG for op in ops):
            a, b = ins.reg_name(ops[0].reg), ins.reg_name(ops[1].reg)
            if a == b and a in ("edi", "rdi"):
                known["rdi"] = 0
            elif a in ("edi", "rdi"):
                known.pop("rdi", None)
        elif ins.mnemonic == "call" and len(ops) == 1 and ops[0].type == x86.X86_OP_IMM:
            target = int(ops[0].imm)
            if known.get("rdi") == arg and _in_exec(img, target):
                out.append((target, ins.address))
            # SysV caller-saved RDI is unknown after any call.
            known.pop("rdi", None)
        elif ops and ops[0].type == x86.X86_OP_REG and ins.reg_name(ops[0].reg) in ("edi", "rdi"):
            known.pop("rdi", None)
        if ins.mnemonic in ("ret", "hlt", "syscall", "ud2", "int3"):
            break
        if ins.mnemonic == "jmp":
            break
    return out


def _direct_calls_arm64(img, entry: int, arg: int):
    try:
        import capstone
        from capstone import arm64
    except Exception as exc:
        raise Decline(str(exc))
    raw = _file_bytes(img, entry, min(MAX_ENTRY_BYTES, max(
        (va + fs - entry for va, _ms, fs, _off, fl in img.loads if fl & 1 and va <= entry < va + fs),
        default=0)))
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    x0 = None
    out = []
    for count, ins in enumerate(md.disasm(raw, entry)):
        if count >= 256:
            break
        ops = ins.operands
        if ins.mnemonic in ("mov", "movz") and len(ops) >= 2 and ops[0].type == arm64.ARM64_OP_REG \
                and ops[1].type == arm64.ARM64_OP_IMM and ins.reg_name(ops[0].reg) in ("x0", "w0"):
            x0 = int(ops[1].imm) & ((1 << (32 if ins.reg_name(ops[0].reg) == "w0" else 64)) - 1)
        elif ins.mnemonic == "bl" and len(ops) == 1 and ops[0].type == arm64.ARM64_OP_IMM:
            target = int(ops[0].imm)
            if x0 == arg and _in_exec(img, target):
                out.append((target, ins.address))
            x0 = None
        elif ops and ops[0].type == arm64.ARM64_OP_REG and ins.reg_name(ops[0].reg) in ("x0", "w0"):
            x0 = None
        if ins.mnemonic in ("ret", "brk", "svc"):
            break
        if ins.mnemonic in ("b", "br"):
            break
    return out


def discover(data: bytes, spec: Contract):
    """(image, [(target, caller site)]) from explicit address or entry-point call evidence."""
    native = _native()
    if native is None:
        raise Decline("native_image is unavailable")
    try:
        img = native.load(data)
    except Exception as exc:
        raise Decline(str(exc))
    if img.problem:
        raise Decline(img.problem)
    if spec.explicit_address is not None:
        return img, [(spec.explicit_address, None)] if _in_exec(img, spec.explicit_address) else []
    entry = _entry(img, data)
    rows = []
    if _in_exec(img, entry):
        if img.arch == getattr(native, "ARCH_X86_64", "x86-64"):
            rows = _direct_calls_x86(img, entry, spec.argument)
        elif img.arch == getattr(native, "ARCH_ARM64", "arm64"):
            rows = _direct_calls_arm64(img, entry, spec.argument)
    if not rows:
        # B-166: the entry point does not bind the argument at a direct call (a shared object, a decoder
        # reached through main or a helper): take the targets from the image-wide discovery.
        rows = _discovered(img, spec.argument)
    # Repeated calls to the same function under the same established argument are one hypothesis.
    return img, list(dict.fromkeys(rows))[:MAX_CANDIDATES + 1]


def _discovered(img, argument: int):
    """[(target, call site | None)] from decoder_discovery (B-166); Decline when it cannot run."""
    try:
        import decoder_discovery
    except Exception as exc:
        raise Decline("decoder_discovery is unavailable: %s" % exc)
    try:
        return decoder_discovery.unary_rows(img, argument)
    except RuntimeError as exc:
        raise Decline(str(exc))


# -------------------------------------------------------------------------------------------------
# Exact x86-64 pure-function evaluator used only when native_image's guarded Unicorn backend is unavailable.

_BASE_REGS = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)


def _alias(name):
    if name in _BASE_REGS:
        return name, 0, 64
    legacy = {
        "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi", "edi": "rdi",
        "ebp": "rbp", "esp": "rsp", "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
        "si": "rsi", "di": "rdi", "bp": "rbp", "sp": "rsp", "al": "rax", "bl": "rbx",
        "cl": "rcx", "dl": "rdx", "sil": "rsi", "dil": "rdi", "bpl": "rbp", "spl": "rsp",
        "ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx",
    }
    if name in legacy:
        width = 32 if name.startswith("e") else 16 if name in {"ax", "bx", "cx", "dx", "si", "di", "bp", "sp"} else 8
        return legacy[name], 8 if name in {"ah", "bh", "ch", "dh"} else 0, width
    m = re.fullmatch(r"(r(?:1[0-5]|[8-9]))(d|w|b)", name)
    if m:
        return m.group(1), 0, {"d": 32, "w": 16, "b": 8}[m.group(2)]
    return None


_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


class _Eval:
    def __init__(self, img, argument, stack_top: int, bias: int = 0):
        """``argument``: one integer, or a sequence of integers and ``("ptr", image vaddr)`` pairs (at most
        six, the SysV register arguments).  ``bias``: where this layout loads the image (0 for ET_EXEC)."""
        self.img = img
        self.bias = bias
        self.reg = {r: None for r in _BASE_REGS}
        arguments = [argument] if isinstance(argument, int) else list(argument)
        if len(arguments) > len(_ARG_REGS):
            raise Decline("more than six arguments")
        for name, value in zip(_ARG_REGS, arguments):
            if isinstance(value, tuple):
                if len(value) != 2 or value[0] != "ptr":
                    raise Decline("unsupported argument kind")
                value = value[1] + bias
            self.reg[name] = int(value) & ((1 << 64) - 1)
        # A slot the loader relocates does not hold its file bytes at run time: never read one.
        self.relocated = set()
        for off, kind, payload in getattr(img, "plan", ()):
            self.relocated.add(off)
            if kind == "poison" and payload == 16:
                self.relocated.add(off + 8)
        self.reg["rsp"] = stack_top
        self.flags = None
        self.mem = {}
        self.stack_lo, self.stack_hi = stack_top - MAX_STACK, stack_top + 16
        self.steps = 0
        self.visits = {}
        self.trace = []
        self.branches = self.back_edges = self.calls = self.table_reads = 0
        self._push(0)
        try:
            import capstone
            self.capstone = capstone
            self.x86 = capstone.x86
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.md.detail = True
        except Exception as exc:
            raise Decline(str(exc))

    @staticmethod
    def _mask(bits):
        return (1 << bits) - 1

    def _read_reg(self, name):
        a = _alias(name)
        if a is None:
            raise Decline(f"unsupported register {name}")
        base, shift, bits = a
        value = self.reg[base]
        if value is None:
            raise Decline(f"undefined register {base}")
        return (value >> shift) & self._mask(bits)

    def _write_reg(self, name, value):
        a = _alias(name)
        if a is None:
            raise Decline(f"unsupported register {name}")
        base, shift, bits = a
        value &= self._mask(bits)
        if bits == 64:
            self.reg[base] = value
        elif bits == 32 and shift == 0:
            self.reg[base] = value                 # x86-64 zero-extension
        else:
            old = self.reg[base]
            if old is None:
                raise Decline(f"partial write to undefined register {base}")
            mask = self._mask(bits) << shift
            self.reg[base] = (old & ~mask) | (value << shift)

    def _mapped(self, addr, n, write=False):
        image = addr - self.bias
        for va, memsz, filesz, off, flags in self.img.loads:
            if va <= image and image + n <= va + memsz:
                if write and not (flags & 2):
                    raise Decline("write to non-writable image memory")
                if not write and any(o in self.relocated for o in range(image - 7, image + n)):
                    raise Decline("read of a slot the loader relocates")
                raw = bytearray(n)
                defined = bytearray(n)
                for i in range(n):
                    p = addr + i
                    if p in self.mem:
                        raw[i], defined[i] = self.mem[p], 1
                    elif image + i < va + filesz:
                        raw[i], defined[i] = self.img.data[off + image + i - va], 1
                if not write and not all(defined):
                    raise Decline("read from undefined bss/padding")
                if not write and not (flags & 1):
                    self.table_reads += 1
                return bytes(raw)
        if self.stack_lo <= addr and addr + n <= self.stack_hi:
            if write:
                return bytes(self.mem.get(addr + i, 0) for i in range(n))
            if not all(addr + i in self.mem for i in range(n)):
                raise Decline("read from undefined stack")
            return bytes(self.mem[addr + i] for i in range(n))
        raise Decline("memory access outside mapped image/stack")

    def _read_mem(self, addr, n):
        return int.from_bytes(self._mapped(addr, n), "little")

    def _write_mem(self, addr, n, value):
        self._mapped(addr, n, write=True)
        raw = int(value & self._mask(8 * n)).to_bytes(n, "little")
        for i, b in enumerate(raw):
            self.mem[addr + i] = b

    def _push(self, value):
        rsp = self._read_reg("rsp") - 8
        self._write_reg("rsp", rsp)
        self._write_mem(rsp, 8, value)

    def _pop(self):
        rsp = self._read_reg("rsp")
        value = self._read_mem(rsp, 8)
        self._write_reg("rsp", rsp + 8)
        return value

    def _address(self, ins, mem):
        if mem.segment:
            raise Decline("segment-relative memory")
        addr = int(mem.disp)
        if mem.base:
            name = ins.reg_name(mem.base)
            addr += ins.address + ins.size if name == "rip" else self._read_reg(name)
        if mem.index:
            addr += self._read_reg(ins.reg_name(mem.index)) * int(mem.scale)
        return addr & ((1 << 64) - 1)

    def _read_op(self, ins, op):
        if op.type == self.x86.X86_OP_REG:
            return self._read_reg(ins.reg_name(op.reg))
        if op.type == self.x86.X86_OP_IMM:
            return int(op.imm) & self._mask(max(8, op.size * 8))
        if op.type == self.x86.X86_OP_MEM:
            return self._read_mem(self._address(ins, op.mem), op.size)
        raise Decline("unsupported operand")

    def _write_op(self, ins, op, value):
        if op.type == self.x86.X86_OP_REG:
            self._write_reg(ins.reg_name(op.reg), value)
            return
        if op.type == self.x86.X86_OP_MEM:
            self._write_mem(self._address(ins, op.mem), op.size, value)
            return
        raise Decline("unsupported destination")

    @staticmethod
    def _arith_flags(a, b, result, bits, sub=False):
        mask, sign = (1 << bits) - 1, 1 << (bits - 1)
        a, b, r = a & mask, b & mask, result & mask
        if sub:
            cf = a < b
            of = bool(((a ^ b) & (a ^ r) & sign))
        else:
            cf = a + b > mask
            of = bool((~(a ^ b) & (a ^ r) & sign))
        return {"zf": r == 0, "sf": bool(r & sign), "cf": cf, "of": of, "pf": (r & 0xff).bit_count() % 2 == 0}

    def _condition(self, mnemonic):
        if self.flags is None:
            raise Decline("branch on undefined flags")
        f = self.flags
        table = {
            "je": f["zf"], "jz": f["zf"], "jne": not f["zf"], "jnz": not f["zf"],
            "ja": not f["cf"] and not f["zf"], "jnbe": not f["cf"] and not f["zf"],
            "jae": not f["cf"], "jnb": not f["cf"], "jnc": not f["cf"],
            "jb": f["cf"], "jc": f["cf"], "jnae": f["cf"],
            "jbe": f["cf"] or f["zf"], "jna": f["cf"] or f["zf"],
            "jg": not f["zf"] and f["sf"] == f["of"], "jnle": not f["zf"] and f["sf"] == f["of"],
            "jge": f["sf"] == f["of"], "jnl": f["sf"] == f["of"],
            "jl": f["sf"] != f["of"], "jnge": f["sf"] != f["of"],
            "jle": f["zf"] or f["sf"] != f["of"], "jng": f["zf"] or f["sf"] != f["of"],
            "js": f["sf"], "jns": not f["sf"], "jo": f["of"], "jno": not f["of"],
            "jp": f["pf"], "jpe": f["pf"], "jnp": not f["pf"], "jpo": not f["pf"],
        }
        if mnemonic not in table:
            raise Decline(f"unsupported condition {mnemonic}")
        return table[mnemonic]

    def _instruction(self, pc):
        raw = _file_bytes(self.img, pc - self.bias, 15)
        ins = next(self.md.disasm(raw, pc, count=1), None)
        if ins is None or ins.address != pc:
            raise Decline("instruction does not decode")
        return ins

    def run(self, start):
        """Run the function at image vaddr ``start``; every address inside the run carries the bias."""
        bias = self.bias
        pc, depth = start + bias, 0
        while self.steps < MAX_STEPS:
            if not _in_exec(self.img, pc - bias):
                raise Decline("control flow left executable memory")
            self.steps += 1
            self.visits[pc] = self.visits.get(pc, 0) + 1
            if self.visits[pc] > MAX_VISITS:
                raise Decline("loop visit cap")
            ins = self._instruction(pc)
            self.trace.append((pc - bias, bytes(ins.bytes)))
            nxt, ops, mn = pc + ins.size, ins.operands, ins.mnemonic

            if mn in ("nop", "endbr64"):
                pc = nxt
                continue
            if mn in ("mov", "movabs") and len(ops) == 2:
                self._write_op(ins, ops[0], self._read_op(ins, ops[1]))
            elif mn in ("movzx", "movsx", "movsxd") and len(ops) == 2:
                value = self._read_op(ins, ops[1])
                if mn != "movzx":
                    bits = ops[1].size * 8
                    if value & (1 << (bits - 1)):
                        value -= 1 << bits
                self._write_op(ins, ops[0], value)
            elif mn == "lea" and len(ops) == 2 and ops[1].type == self.x86.X86_OP_MEM:
                self._write_op(ins, ops[0], self._address(ins, ops[1].mem))
            elif mn in ("xor", "or", "and", "add", "sub") and len(ops) == 2:
                bits = ops[0].size * 8
                same = (mn == "xor" and ops[0].type == ops[1].type == self.x86.X86_OP_REG
                        and ops[0].reg == ops[1].reg)
                a, b = (0, 0) if same else (self._read_op(ins, ops[0]), self._read_op(ins, ops[1]))
                raw = {"xor": a ^ b, "or": a | b, "and": a & b, "add": a + b, "sub": a - b}[mn]
                result = raw & self._mask(bits)
                self._write_op(ins, ops[0], result)
                self.flags = (self._arith_flags(a, b, result, bits, mn == "sub") if mn in ("add", "sub")
                              else {"zf": result == 0, "sf": bool(result & (1 << (bits - 1))),
                                    "cf": False, "of": False, "pf": (result & 0xff).bit_count() % 2 == 0})
            elif mn == "imul" and len(ops) in (2, 3):
                if len(ops) == 3:
                    a, b = self._read_op(ins, ops[1]), self._read_op(ins, ops[2])
                else:
                    a, b = self._read_op(ins, ops[0]), self._read_op(ins, ops[1])
                self._write_op(ins, ops[0], a * b)
                self.flags = None
            elif mn in ("shl", "sal", "shr", "sar", "rol", "ror") and len(ops) == 2:
                bits = ops[0].size * 8
                a, count = self._read_op(ins, ops[0]), self._read_op(ins, ops[1]) & 0x3f
                if count == 0:
                    result = a
                elif mn in ("shl", "sal"):
                    result = a << count
                elif mn == "shr":
                    result = a >> count
                elif mn == "sar":
                    signed = a - (1 << bits) if a & (1 << (bits - 1)) else a
                    result = signed >> count
                elif mn == "rol":
                    count %= bits
                    result = (a << count) | (a >> (bits - count))
                else:
                    count %= bits
                    result = (a >> count) | (a << (bits - count))
                result &= self._mask(bits)
                self._write_op(ins, ops[0], result)
                self.flags = None
            elif mn in ("inc", "dec") and len(ops) == 1:
                bits, a = ops[0].size * 8, self._read_op(ins, ops[0])
                result = (a + (1 if mn == "inc" else -1)) & self._mask(bits)
                old_cf = self.flags.get("cf") if self.flags else None
                self._write_op(ins, ops[0], result)
                self.flags = self._arith_flags(a, 1, result, bits, mn == "dec")
                if old_cf is not None:
                    self.flags["cf"] = old_cf
            elif mn in ("cmp", "test") and len(ops) == 2:
                bits, a, b = ops[0].size * 8, self._read_op(ins, ops[0]), self._read_op(ins, ops[1])
                if mn == "cmp":
                    self.flags = self._arith_flags(a, b, a - b, bits, True)
                else:
                    result = (a & b) & self._mask(bits)
                    self.flags = {"zf": result == 0, "sf": bool(result & (1 << (bits - 1))),
                                  "cf": False, "of": False, "pf": (result & 0xff).bit_count() % 2 == 0}
            elif mn == "not" and len(ops) == 1:
                self._write_op(ins, ops[0], ~self._read_op(ins, ops[0]))
            elif mn == "neg" and len(ops) == 1:
                bits, a = ops[0].size * 8, self._read_op(ins, ops[0])
                result = (-a) & self._mask(bits)
                self._write_op(ins, ops[0], result)
                self.flags = self._arith_flags(0, a, result, bits, True)
            elif mn == "push" and len(ops) == 1:
                self._push(self._read_op(ins, ops[0]))
            elif mn == "pop" and len(ops) == 1:
                self._write_op(ins, ops[0], self._pop())
            elif mn == "leave":
                self._write_reg("rsp", self._read_reg("rbp"))
                self._write_reg("rbp", self._pop())
            elif mn == "call" and len(ops) == 1 and ops[0].type == self.x86.X86_OP_IMM:
                target = int(ops[0].imm)
                if not _in_exec(self.img, target - bias) or depth >= MAX_CALL_DEPTH:
                    raise Decline("unsupported call target/depth")
                self._push(nxt)
                self.calls += 1
                depth += 1
                pc = target
                continue
            elif mn == "ret":
                target = self._pop()
                if target == 0:
                    value = self._read_reg("rax")
                    return value, self
                if not _in_exec(self.img, target - bias) or depth <= 0:
                    raise Decline("invalid return target")
                depth -= 1
                pc = target
                continue
            elif mn == "jmp" and len(ops) == 1 and ops[0].type == self.x86.X86_OP_IMM:
                target = int(ops[0].imm)
                if target < pc:
                    self.back_edges += 1
                pc = target
                continue
            elif mn.startswith("j") and len(ops) == 1 and ops[0].type == self.x86.X86_OP_IMM:
                target = int(ops[0].imm)
                self.branches += 1
                if self._condition(mn):
                    if target < pc:
                        self.back_edges += 1
                    pc = target
                    continue
            else:
                raise Decline(f"unsupported instruction {mn}")
            pc = nxt
        raise Decline("instruction budget")


_FALLBACK_BIAS = 0x5A3C000          # the second layout's load address of an ET_DYN image (page aligned)


def _fallback_x86(img, address: int, argument):
    """(u64, _Eval) agreed by two layouts: different stacks and, for a position-independent image,
    different load addresses.  ``argument`` as for ``_Eval``."""
    runs = []
    dyn = getattr(img, "etype", None) == 3
    for stack, bias in ((0x700012345008, 0), (0x6000ABCDE008, _FALLBACK_BIAS if dyn else 0)):
        runs.append(_Eval(img, argument, stack, bias).run(address))
    if runs[0][0] != runs[1][0]:
        raise Decline("stack layouts disagree")
    # Branch/helper/table provenance is part of the evidence, and the fixture exercises all four.
    sig0 = (runs[0][1].branches, runs[0][1].back_edges, runs[0][1].calls, runs[0][1].table_reads)
    sig1 = (runs[1][1].branches, runs[1][1].back_edges, runs[1][1].calls, runs[1][1].table_reads)
    if sig0 != sig1:
        raise Decline("execution provenance differs")
    return runs[0]


def evaluate(data: bytes, img, address: int, argument: int):
    """(u64, provenance) agreed by native_image and/or the guarded exact fallback."""
    native = _native()
    native_value, native_error = None, None
    try:
        native_value = native.emulate_symbol(data, address, [argument], arch=img.arch, ret="int",
                                             max_blocks=MAX_STEPS, max_mem=200_000, init="skip")
    except Exception as exc:
        native_error = str(exc)

    fallback = None
    if img.arch == getattr(native, "ARCH_X86_64", "x86-64"):
        try:
            fallback = _fallback_x86(img, address, argument)
        except Decline:
            fallback = None
    if native_value is not None:
        if fallback is not None and native_value != fallback[0]:
            raise Decline("native and static evaluators disagree")
        return int(native_value) & ((1 << 64) - 1), (fallback[1] if fallback else None), "native_image"
    # Only the host-capability guard permits the narrower evaluator to stand in for Unicorn.  A loader,
    # relocation, constructor, import or semantic decline is not bypassed.
    if fallback is not None and native_error and "unicorn engine not available" in native_error.lower():
        return fallback[0], fallback[1], "bounded_x86"
    raise Decline(native_error or "no evaluator")


def _scope(*parts):
    h = hashlib.sha256()
    for part in parts:
        raw = part if isinstance(part, bytes) else str(part).encode("utf-8", "replace")
        h.update(len(raw).to_bytes(8, "big"))
        h.update(raw)
    return h.hexdigest()


def _render(q, raw: bytes, endian: str):
    text = _text(q).lower()
    options = []
    if re.search(r"\b(?:lowercase|lower-case)?\s*(?:hex|hexadecimal)\b", text):
        options.append(("entry_call_return_lower_hex", raw.hex()))
        if re.search(r"\b0x[- ]?prefix(?:ed)?\b", text):
            options.insert(0, ("entry_call_return_0x_lower_hex", "0x" + raw.hex()))
    if re.search(r"\bexact\s+text\b|\bascii\b|\bstring\b", text) and all(0x20 <= b < 0x7f for b in raw):
        options.append(("entry_call_return_ascii", raw.decode("ascii")))
    if re.search(r"\b(?:decimal|base[- ]?10)\b", text):
        options.append(("entry_call_return_unsigned_decimal", str(int.from_bytes(raw, endian))))
    return options[:labels.MAX_OPTIONS]


def answer(q, data: bytes):
    spec = contract(q)
    if spec is None or not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    try:
        img, rows = discover(data, spec)
    except Decline:
        return None
    if not rows or len(rows) > MAX_CANDIDATES:
        return None
    results = []
    for target, site in rows:
        try:
            value, trace, engine = evaluate(data, img, target, spec.argument)
        except Decline:
            continue
        raw = int(value).to_bytes(8, spec.endian)[:spec.width] if spec.endian == "little" \
            else int(value).to_bytes(8, "big")[-spec.width:]
        results.append((raw, target, site, trace, engine))
    # A caller-bound target that the evaluator cannot prove remains a plausible decoder.  Do not
    # let the first supported target win over that incomplete alternative.
    if len(results) != len(rows):
        return None
    values = {row[0] for row in results}
    if len(values) != 1:
        return None
    raw = next(iter(values))
    options = _render(q, raw, spec.endian)
    if not options:
        return None
    # Every viable target must agree.  Bind acceptance to this artifact, wording, ABI, targets and
    # behavior trace; a hypothesis accepted here can never become plain for another decoder.
    targets = tuple(sorted((target, site if site is not None else -1) for _r, target, site, _t, _e in results))
    traces = []
    for _r, target, _site, trace, engine in results:
        if trace is None:
            traces.append((target, engine, "native"))
        else:
            code = b"".join(addr.to_bytes(8, "little") + raw_ins for addr, raw_ins in trace.trace)
            traces.append((target, engine, hashlib.sha256(code).hexdigest(), trace.branches,
                           trace.back_edges, trace.calls, trace.table_reads))
    qscope = " ".join(_text(q).lower().split())
    scope = _scope(hashlib.sha256(data).digest(), qscope, spec, targets, tuple(traces))
    key = f"binary.native_behavior/elf+scope_sha256_{scope}"
    return labels.candidates(key, options)

