#!/usr/bin/env python3
"""General, bounded, syscall-free, memory-only single-function CPU emulation (Unicorn engine).

WHY THIS FILE EXISTS
--------------------
The Mobile "analysis" codec and the Binary lane both occasionally hide an answer behind a NATIVE
transform: a `static native (J)J` JNI function in a bundled `.so` (Mobile), or a small decode routine
in an ELF/PE (Binary). The lane's own hand-rolled interpreters
(`solvers/mobile-android/dex_chain_codec._emulate_x86` / `._emulate_arm64` /
`native_arm64.emulate`) model a fixed instruction subset and raise `_Decline`/`Decline` the moment they
meet anything outside it -- a branch, a loop, a call, an extra argument, a floating-point op. Day 25 cost
26 minutes to exactly this "we can't run the transform" class of miss.

This module runs ANY such single function GENERALLY, by emulating the real machine code in the Unicorn
CPU-emulation sandbox. The caller supplies the raw code bytes, the architecture, the input registers
(the ABI argument mapping is the caller's), and names the result register; `emulate_function` returns the
result register's 64-bit value after the function returns.

NOTHING FROM THE SAMPLE IS EVER RUN AS A PROCESS. The bytes are emulated instruction-by-instruction in
Unicorn's own virtual memory: no host process, no host memory, no files, no network, no threads. Syscalls
are trapped and denied (never forwarded to the host). It is deterministic and offline.

NEVER-WRONG CONTRACT (the bright line)
--------------------------------------
A value is returned ONLY when the emulation completes deterministically within budget and the result does
not depend on any undefined input. On ANYTHING else `EmulationError` is raised, so the caller treats the
read as unsure/None -- it can NEVER fabricate a plain wrong answer:

  * Bounded. At most `max_insns` instructions execute (default 200000); exceeding it is an error
    (a runaway loop never hangs and never "returns" a half value).
  * Syscall-free. Any software interrupt / `syscall` / `svc` is trapped and denied -> error.
  * Memory-only, fail-closed on UNDEFINED memory. Only the function's own code bytes are mapped (read+exec).
    The stack is grown lazily: a write to unmapped memory maps that page, a read of any byte that was never
    written (and is not in the code region) is an error -- exactly the "read of undefined stack" decline the
    hand-rolled readers make, but byte-granular. A read of a never-mapped page is an error. An instruction
    fetch outside the mapped code is an error.
  * Fail-closed on UNDEFINED registers. Every register the caller did not set is filled with a distinctive
    poison value; the function is emulated TWICE with two different poison fills, and the result is returned
    only when both runs agree. So a transform whose result depends on an uninitialised register (the JNIEnv
    pointer, the jclass, an uninitialised scratch register) yields two different values -> error, never a
    fabricated code. (The explicitly-set argument registers, the stack pointer and the code are identical in
    both runs, so a transform that ignores undefined inputs is deterministic and its single value is
    returned.)
  * Must actually RETURN. The function must reach a return instruction (`ret` / `ret Xn`); falling off the
    end of the code, or being cut by the budget, is an error. On 32-bit ARM, where any write to PC can be a
    return or a computed jump, the return is the moment control reaches the CALLER'S RETURN ADDRESS: LR holds
    an unmapped canary at entry and the function has returned when a fetch lands on it, whatever instruction
    put it there (`bx lr`, `mov pc, lr`, `pop {.., pc}`, `ldr pc, [sp], #4`). A write to PC of any other
    value (a jump table, a pushed code address) simply executes: it lands inside the body and runs on, or
    outside it and traps.
  * No machine-dependent instruction (KB-2 r2). rdtsc, cpuid, rdrand, xgetbv and the rest of X86_ENV_INSNS,
    and on AArch64 any MRS/MSR of a system register but TPIDR_EL0/NZCV/FPCR/FPSR and SYS/SYSL, are errors:
    an emulator check reads them (a timing gap, the hypervisor bit), and Unicorn answers them identically in
    both poison runs, so the double run alone cannot catch the decoy leg they select.

The engine is a strict superset of what the hand-rolled readers can do, so callers cross-check the two and
keep the stricter outcome (disagreement -> decline); this module never relaxes never-wrong, it only widens
the set of transforms that can be proven.

PUBLIC API
----------
    import native_emulate as ne
    ne.UNICORN_AVAILABLE                       -> bool  (False if the engine cannot initialize safely)
    ne.UNICORN_UNAVAILABLE_REASON              -> str naming why when UNICORN_AVAILABLE is False, else None
    (importing this module raises UnicornUnavailable, an ImportError, when Unicorn is not installed)
    ne.EmulationError                          -> the only exception emulate_* raise on a non-result
    ne.emulate_function(code, arch, regs_in, result_reg, max_insns=...) -> int
    ne.emulate_x86_sysv(code, int_args, max_insns=...)   -> rax  (SysV integer-arg order)
    ne.emulate_arm64_aapcs(code, int_args, max_insns=...)-> x0   (AAPCS64 integer-arg order)

`regs_in` is {register-name: value} (lowercase, e.g. "rdi"/"rdx", "x0".."x30", or "r0".."r12");
`result_reg` is a register name ("rax", "x0", "r0"). Values and the result are masked to 64 bits. `arch` is
"x86-64", "arm64", "arm32" (A32) or "thumb" (T32); the two 32-bit ARM modes share UC_ARCH_ARM and differ
only in the instruction encoding (B-164). On 32-bit ARM:
  * a machine-dependent instruction (a coprocessor or system-register read, MRS/MSR, VMRS, a mode or
    endianness change: ARM32_ENV_INSNS), conditional or not, is an error, as X86_ENV_INSNS is on x86;
  * the body runs in its entry instruction set only: an interworking switch inside it (`bx`/`blx` into the
    other of A32/T32) is an error, since every executed instruction is vetted with the entry decoder;
  * LR (the caller's return address), the APSR condition/GE flags, and the addresses the code and the stack
    sit at are UNDEFINED at entry like any other register: the runs differ in all of them (ARM32_RUNS), so a
    result that depends on any is an error. Over the runs EVERY BIT of each takes both values: all 32 bits of
    an undefined register and of LR, N Z C V Q GE, bits 3..31 of SP, and bits 2..31 (A32) or 1..31 (Thumb) of
    the function's entry address. That is the whole guarantee. A value DERIVED from one of them (lr + 4,
    sp - 8, the PC an instruction reads, which is the entry address plus its own offset) and any function of
    two or more bits are SAMPLED by the three runs, not covered bit by bit: a single-bit test of such a value
    can agree in all three. (The mobile dispatcher's device-like pointer run is a fourth sample for the JNIEnv
    and the jclass.)
  * The engine is given the bytes, not the symbol's address: where in its page the function starts, and for
    Thumb whether that is 0 or 2 modulo 4, vary by run as well. A Thumb `ldr rX, [pc, #imm]` / `adr` (they
    read from Align(PC, 4)) therefore has no value here and is an error; A32 PC-relative data is the same at
    any word-aligned address.
  * The body runs in USER mode, as on a device: an exception return (`movs pc, lr`, `ldm .. {pc}^`,
    `subs pc, lr, #n`) is no ordinary return there and is an error.
  * Only the symbol's own bytes execute: a jump into the rest of its page is an error.
"""
import ctypes
import platform
import struct
import sys

ARCH_X86_64 = "x86-64"
ARCH_ARM64 = "arm64"
ARCH_ARM32 = "arm32"             # 32-bit ARM, A32 (ARM) instruction set (armeabi-v7a, ARM mode)
ARCH_THUMB = "thumb"             # 32-bit ARM, T32 (Thumb-2) instruction set (armeabi-v7a, the common mode)
_ARM32_ARCHES = (ARCH_ARM32, ARCH_THUMB)

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
_PAGE = 0x1000
_CODE_BASE = 0x00400000          # where the function's code bytes are mapped (read + exec, not writable)
_STACK_TOP = 0x7fff0000          # initial SP; stack pages are mapped lazily on first write (grows down)
_MAX_CODE = 1 << 20              # a single function longer than 1 MiB is not a transform we emulate
_POISON_A = 0xA5A5A5A5A5A5A5A5   # two distinct fills for undefined registers; a result that differs
_POISON_B = 0x5C5C5C5C5C5C5C5C   # between the two runs depended on an undefined input -> fail closed


class EmulationError(Exception):
    """The emulation did not complete to a deterministic, fully-defined result (trap, timeout,
    undefined read, undefined-register dependence, no return). Never a wrong value."""


def _darwin_arm64_cacheline_usable(system=None, machine=None, sysctlbyname=None):
    """Whether Unicorn's lazy Darwin/arm64 cache initialization is safe.

    Unicorn 2.1.4 asks ``sysctlbyname("hw.cachelinesize")`` on its first memory map.  When a
    macOS sandbox denies that read, Unicorn's native fallback executes ``MRS CTR_EL0``; that
    instruction is an uncatchable SIGILL on Apple silicon in this environment.  Probe the same
    prerequisite before advertising the engine.  Other hosts retain their existing behavior.

    ``system``, ``machine`` and ``sysctlbyname`` are injectable so the fail-closed cases can be
    tested without executing Unicorn or depending on the host sandbox.
    """
    system = sys.platform if system is None else system
    if str(system).lower() != "darwin":
        return True
    try:
        machine = platform.machine() if machine is None else machine
        if str(machine).lower() not in ("arm64", "aarch64"):
            return True
        if sysctlbyname is None:
            sysctlbyname = ctypes.CDLL(None, use_errno=True).sysctlbyname
            sysctlbyname.argtypes = (ctypes.c_char_p, ctypes.c_void_p,
                                     ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p,
                                     ctypes.c_size_t)
            sysctlbyname.restype = ctypes.c_int
        value = ctypes.c_uint64()
        size = ctypes.c_size_t(ctypes.sizeof(value))
        result = sysctlbyname(b"hw.cachelinesize", ctypes.byref(value), ctypes.byref(size), None, 0)
        return (result == 0 and 0 < size.value <= ctypes.sizeof(value) and value.value > 0)
    except Exception:
        # This check protects a native call that can kill the process, so uncertainty must decline.
        return False


UNICORN_PIN = "unicorn==2.1.4"   # requirements.in; the Darwin guard above was written against this version


class UnicornUnavailable(ImportError):
    """The Unicorn engine is not installed or failed to load. Raised at import (B-240): this module is the
    primary native path, so a missing engine is a broken install, never a silent fall back to the readers."""


_uc = None
_x86c = None
_a64c = None
_a32c = None
UNICORN_AVAILABLE = False
UNICORN_UNAVAILABLE_REASON = None   # str naming why, whenever UNICORN_AVAILABLE is False
if _darwin_arm64_cacheline_usable():
    try:
        import unicorn as _uc
        from unicorn import x86_const as _x86c
        from unicorn import arm64_const as _a64c
        from unicorn import arm_const as _a32c
    except Exception as _exc:                          # not installed / failed to load: a broken install
        raise UnicornUnavailable(
            "native_emulate needs the Unicorn engine (%s, pinned in requirements.in) and it could not be "
            "imported: %s: %s. Install it with: uv pip install --python .venv/bin/python %s"
            % (UNICORN_PIN, type(_exc).__name__, _exc, UNICORN_PIN)) from _exc
    UNICORN_AVAILABLE = True
else:
    # Installed or not, Unicorn must not be touched here: its first mem_map would take an uncatchable SIGILL.
    # Declined by name, once per process, and every emulate_* call repeats the reason.
    UNICORN_UNAVAILABLE_REASON = (
        "Unicorn declined on this Darwin/arm64 host: sysctlbyname('hw.cachelinesize') is unreadable "
        "(a sandbox?), so Unicorn's fallback would execute MRS CTR_EL0 and die with SIGILL")
    import warnings as _warnings
    _warnings.warn("native_emulate: " + UNICORN_UNAVAILABLE_REASON, RuntimeWarning, stacklevel=2)


# --------------------------------------------------------------- register name tables (built lazily)
def _x86_regs():
    c = _x86c
    regs = {
        "rax": c.UC_X86_REG_RAX, "rbx": c.UC_X86_REG_RBX, "rcx": c.UC_X86_REG_RCX,
        "rdx": c.UC_X86_REG_RDX, "rsi": c.UC_X86_REG_RSI, "rdi": c.UC_X86_REG_RDI,
        "rbp": c.UC_X86_REG_RBP, "rsp": c.UC_X86_REG_RSP, "rip": c.UC_X86_REG_RIP,
    }
    for i in range(8, 16):
        regs["r%d" % i] = getattr(c, "UC_X86_REG_R%d" % i)
    return regs


def _arm64_regs():
    c = _a64c
    regs = {"sp": c.UC_ARM64_REG_SP, "pc": c.UC_ARM64_REG_PC, "lr": c.UC_ARM64_REG_X30}
    for i in range(31):
        regs["x%d" % i] = getattr(c, "UC_ARM64_REG_X%d" % i)
    return regs


def _arm32_regs():
    c = _a32c
    regs = {"sp": c.UC_ARM_REG_SP, "pc": c.UC_ARM_REG_PC, "lr": c.UC_ARM_REG_LR}
    for i in range(13):
        regs["r%d" % i] = getattr(c, "UC_ARM_REG_R%d" % i)
    return regs


# Instructions whose result depends on the machine or the moment, not on the bytes: an emulator check reads them
# (a timing gap, the hypervisor bit, a hardware random number), and Unicorn answers them the same way in both
# poison runs, so the double run cannot catch them. Executing one is an error (KB-2 r2; native_image.py shares
# these sets). AArch64: system-register access through Unicorn's MRS/MSR/SYS hooks, ordinary user state allowed.
X86_ENV_INSNS = frozenset({
    "rdtsc", "rdtscp", "rdrand", "rdseed", "rdpid", "rdpmc", "xgetbv", "cpuid", "sgdt", "sidt", "sldt", "str",
    "smsw", "lsl", "lar", "verr", "verw", "rdfsbase", "rdgsbase", "wrfsbase", "wrgsbase", "in", "out", "insb",
    "insw", "insd", "outsb", "outsw", "outsd", "xsave", "xsaveopt", "xsavec", "xsaves", "xrstor", "xrstors",
    "fxsave", "fxsave64", "fxrstor", "fxrstor64", "syscall", "sysenter", "int", "int1", "int3", "into", "hlt",
    # Non-privileged x87/MXCSR environment stores (backlog row 564). fnstenv/fnsave expose the x87 tag word,
    # whose post-init value under Unicorn differs from a real device's; fnstsw/fnstcw/stmxcsr/ldmxcsr expose
    # the x87 status/control and MXCSR words. A native that branches on any of these reads a machine-dependent
    # value both poison runs answer identically, so the double run cannot catch it; executing one is an error,
    # exactly as fxsave/xsave already are. native_image.py shares this set.
    "fnstenv", "fnsave", "fnstsw", "fnstcw", "stmxcsr", "ldmxcsr",
    "ud0", "ud1", "ud2"})
A64_MRS_OK = frozenset({(3, 3, 13, 0, 2),     # TPIDR_EL0
                        (3, 3, 4, 2, 0),      # NZCV
                        (3, 3, 4, 4, 0),      # FPCR
                        (3, 3, 4, 4, 1)})     # FPSR
A64_MSR_OK = frozenset({(3, 3, 4, 2, 0), (3, 3, 4, 4, 0), (3, 3, 4, 4, 1)})

# 32-bit ARM instructions whose value depends on the machine or mode, not on the bytes: a coprocessor or
# system-register read (the thread pointer in TPIDRURO, cache/feature IDs, the CPSR mode bits), the FP status
# word, or a mode/endianness change. Unicorn answers each the same way in both poison runs, so the double run
# cannot catch a decoy leg that reads one; executing one is an error, as X86_ENV_INSNS is on x86 (B-164).
# The names are capstone's CONDITION-FREE instruction names (Cs insn_name(), from the instruction id): an A32
# mnemonic carries its condition (`mrceq`, `mrseq`), so a match on the mnemonic alone let every conditional
# form through (verification round 1).
ARM32_ENV_INSNS = frozenset({
    "mrc", "mrc2", "mcr", "mcr2", "mrrc", "mrrc2", "mcrr", "mcrr2", "cdp", "cdp2",
    "ldc", "ldcl", "ldc2", "ldc2l", "stc", "stcl", "stc2", "stc2l", "mrs", "msr", "vmrs", "vmsr",
    "cps", "cpsie", "cpsid", "setend", "rfe", "rfeda", "rfedb", "rfeia", "rfeib",
    "srs", "srsda", "srsdb", "srsia", "srsib", "smc", "hvc", "eret", "wfi", "wfe",
})

# 32-bit ARM entry state the caller leaves behind, varied run by run so a result that depends on it differs
# (verification rounds 1 and 2): (register poison, LR canary, APSR fill, code base, stack top, code page offset).
# The second run is the first's COMPLEMENT in every field and the third differs from both, so over the three
# runs EVERY BIT of every field takes both values: a body that reads any one bit of the entry state gets two
# answers (round 2: the first set differed in a few bits only, so `lsr r0, lr, #24` and a test of bit 26 of the
# JNIEnv read plain). That is a guarantee about each field's own bits. A sum (lr + 4, sp - 8, the PC a later
# instruction reads) or any function of several bits is sampled three ways, which no finite set of runs turns
# into a proof: covering every bit of every PC-relative sum alone would take 31 runs (pairwise differences of n
# addresses have at most n - 1 distinct lowest set bits).
#   * The register poison fills every register the caller did not set (0xA5, 0x5C, 0x3A per byte: each of the
#     eight bit positions is set in one fill and clear in another).
#   * LR is the caller's return address, which a body may read (`mov r0, lr`) but no emulator here knows: an
#     A32 caller's (word-aligned), its 32-bit complement (a Thumb caller's, bit 0 set) and a third; all
#     unmapped. A body that jumps to one of them as a constant leaves in that run alone, which is an error.
#   * The APSR fill covers N Z C V, Q and GE[3:0]: over the three fills every one of the fourteen condition
#     codes (and each GE bit `sel` reads) takes both values, which two fills cannot give (GE and LT compare N
#     with V, so complementary fills agree on them). Q is readable through MRS alone, which is an error.
#   * The code base, the page offset and the stack top are where the loader and the thread happened to put
#     them: a body that returns or branches on its own address or its stack pointer (`mov r0, pc`,
#     `mov r0, sp`) has no value in the bytes. The base varies bits 12..31 of every code address, the offset
#     bits 2..11 (A32, word-aligned) or 1..11 (Thumb, so both residues modulo 4), the stack top bits 3..31 of
#     SP (it is 8-aligned at a call). A32 PC-relative code (a literal pool, a relative jump table inside the
#     symbol) is the same anywhere; a Thumb literal load reads from Align(PC, 4), which depends on the residue
#     the engine is not given, so it differs; an absolute address in the bytes is valid at no base.
_APSR_MASK = 0xF80F0000
ARM32_RUNS = ((0xA5A5A5A5A5A5A5A5, 0xFFF0A000, 0x00000000, 0x00400000, 0x7FFF0000, 0x000),
              (0x5C5C5C5C5C5C5C5C, 0x000F5FFF, 0xF80F0000, 0xFFBFF000, 0x8000FFF8, 0xFFE),
              (0x3A3A3A3A3A3A3A3A, 0xA5C3965C, 0xA00A0000, 0xB6E20000, 0xBEF4C5A8, 0x556))
_ARM_MODE_USR = 0x10             # CPSR.M of user mode: what a JNI function runs in on a device


_CS = []


def _x86_insn_env(code, off):
    """The mnemonic of the x86-64 instruction at `off` when it is machine-dependent, '' when it is not, or a
    reason when capstone is missing or cannot decode it (then it is not vetted: an error)."""
    if not _CS:
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            _CS.append(Cs(CS_ARCH_X86, CS_MODE_64))
        except Exception:
            return "an instruction capstone is not available to vet"
    for ins in _CS[0].disasm(bytes(code[off:off + 16]), off, 1):
        return ins.mnemonic if ins.mnemonic in X86_ENV_INSNS else ""
    return "an instruction capstone cannot decode"


# A capstone handle per ARM mode (ARM / Thumb), built lazily, detail on so regs_access() works.
_CS_ARM = {}


def _arm_cs(thumb):
    key = bool(thumb)
    md = _CS_ARM.get(key)
    if md is None:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if key else CS_MODE_ARM)
        md.detail = True
        _CS_ARM[key] = md
    return md


def _arm_insn_env(code, off, thumb):
    """The mnemonic of the 32-bit ARM instruction at `off` when it is machine/mode-dependent, '' when it is
    not, or a reason when capstone is missing or cannot decode it (then it is not vetted: an error). `thumb`
    selects the T32 decoder. Mirrors `_x86_insn_env` for the ARM32 native path (B-164). The match is on the
    instruction, not its spelling: `mrceq` and `mrseq` are `mrc` and `mrs`."""
    try:
        md = _arm_cs(thumb)
    except Exception:
        return "an instruction capstone is not available to vet"
    for ins in md.disasm(bytes(code[off:off + 4]), off, 1):
        # insn_name() is the name of the instruction id, without the condition suffix the mnemonic carries
        base = ins.insn_name() or ""
        if base in ARM32_ENV_INSNS or ins.mnemonic in ARM32_ENV_INSNS:
            return ins.mnemonic
        return ""
    return "an instruction capstone cannot decode"


# The general-purpose registers poison-filled when the caller leaves them unset (undefined on entry).
_X86_GP = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
           "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
_ARM64_GP = tuple("x%d" % i for i in range(31))          # x0..x30
_ARM32_GP = tuple("r%d" % i for i in range(13))          # r0..r12; lr is the per-run return canary, not sp/pc


# --------------------------------------------------------------- return-instruction addresses
def _x86_ret_offsets(code):
    """Byte offsets of every `ret`/`retf` in the code, via capstone (used to STOP before the return
    executes, so a return never has to pop a stack slot). Empty if capstone is unavailable."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except Exception:
        return set()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    out = set()
    try:
        for ins in md.disasm(bytes(code), 0):
            if ins.mnemonic in ("ret", "retf", "retn", "iret", "iretq"):
                out.add(ins.address)
    except Exception:
        return set()
    return out


def _arm64_ret_offsets(code):
    """Byte offsets of every AArch64 RET {Xn} (0b1101011001011111000000 Rn 00000)."""
    out = set()
    n = len(code) // 4
    for k in range(n):
        w = struct.unpack_from("<I", code, k * 4)[0]
        if (w & 0xFFFFFC1F) == 0xD65F0000:
            out.add(k * 4)
    return out


# --------------------------------------------------------------- one emulation run
def _run_once(arch, code, reg_ids, regs_in, poison_gp, poison_fill, result_id, stop_addrs, max_insns,
              lr_canary=None, apsr=None, code_base=_CODE_BASE, stack_top=_STACK_TOP, code_off=0):
    """One deterministic pass. Returns the result register (64-bit) on a clean return, else raises
    EmulationError. `regs_in` are the caller-set registers (defined); every GP register in `poison_gp`
    not set by the caller is filled with `poison_fill`. 32-bit ARM only: `lr_canary` is the caller's return
    address this run pretends (the function has returned when a fetch lands on it; `stop_addrs` is empty),
    `apsr` the fill of the condition/Q/GE flags the caller left, `code_base` (page-aligned) and `code_off`
    (an instruction-aligned offset inside the first page) where this run puts the code, and `stack_top` where
    it starts the stack."""
    arm32 = arch in _ARM32_ARCHES
    thumb_entry = arch == ARCH_THUMB
    if arch == ARCH_X86_64:
        uc = _uc.Uc(_uc.UC_ARCH_X86, _uc.UC_MODE_64)
    elif arch == ARCH_ARM64:
        uc = _uc.Uc(_uc.UC_ARCH_ARM64, _uc.UC_MODE_ARM)
    else:  # ARCH_ARM32 (A32) or ARCH_THUMB (T32), both UC_ARCH_ARM
        uc = _uc.Uc(_uc.UC_ARCH_ARM, _uc.UC_MODE_THUMB if arch == ARCH_THUMB else _uc.UC_MODE_ARM)
        # User mode, as a JNI function runs on a device (round 2). Unicorn starts in supervisor mode, where an
        # exception return (`movs pc, lr`, `ldm sp!, {pc}^`) is an ordinary jump to LR and so read as the
        # function's return; in user mode it is UNPREDICTABLE and the engine refuses it. Written before any
        # register: SP and LR are banked by mode.
        uc.reg_write(_a32c.UC_ARM_REG_CPSR, _ARM_MODE_USR)

    code = bytes(code)
    csize = (code_off + len(code) + _PAGE - 1) // _PAGE * _PAGE
    uc.mem_map(code_base, csize, _uc.UC_PROT_READ | _uc.UC_PROT_EXEC)
    code_lo = code_base + code_off
    code_hi = code_lo + len(code)
    uc.mem_write(code_lo, code)

    # Poison every undefined GP register, then apply the caller's values on top (they are authoritative).
    set_names = set(regs_in)
    for name in poison_gp:
        if name not in set_names and name in reg_ids:
            uc.reg_write(reg_ids[name], poison_fill)
    for name, val in regs_in.items():
        uc.reg_write(reg_ids[name], val & M64)

    # Stack pointer: a lazily-grown region (no readable zero-fill pre-mapping -> undefined reads trap).
    sp_name = "rsp" if arch == ARCH_X86_64 else "sp"
    uc.reg_write(reg_ids[sp_name], stack_top)
    if arch == ARCH_ARM64:
        # Return address: LR (x30) points at an address we never map; a return there would
        # fetch-fault, but the code hook stops us before the return executes. Give it a canary so an
        # accidental tail-return is caught by the fetch-unmapped trap rather than wandering.
        uc.reg_write(reg_ids["lr"], 0x1000)
    elif arm32:
        # The caller's return address, never mapped: the return is the fetch that lands on it (see
        # hook_fetch_unmapped). Written after the caller's registers, so it is the canary whatever they set.
        uc.reg_write(reg_ids["lr"], lr_canary)
        uc.reg_write(_a32c.UC_ARM_REG_APSR, apsr & _APSR_MASK)
    ret_pc = (lr_canary & ~1) & M32 if arm32 else None

    written = set()              # byte addresses the function itself wrote (defined thereafter)
    state = {"insns": 0, "returned": False, "error": None}
    vetted = {}                  # x86/arm32: instruction offset -> machine-dependent mnemonic ('' when ordinary)

    def fail(uc_, reason):
        # The FIRST reason stands (round 2). emu_stop does not always stop at once (inside a Thumb IT block the
        # body runs on to its return), and a later hook then named a consequence, not the cause: a conditional
        # `mrc` in an IT block was reported as "fetch outside mapped code".
        if state["error"] is None:
            state["error"] = reason
        uc_.emu_stop()

    def hook_code(uc_, address, size, _u):
        if address in stop_addrs:            # a return instruction: stop BEFORE it executes
            state["returned"] = True
            uc_.emu_stop()
            return
        state["insns"] += 1
        if state["insns"] > max_insns:
            fail(uc_, "instruction budget exceeded")
            return
        if arch == ARCH_X86_64:
            off = address - code_lo
            bad = vetted.get(off)
            if bad is None:
                bad = vetted[off] = _x86_insn_env(code, off)
            if bad:
                fail(uc_, "%s executed (its value depends on the machine, not on the bytes)" % bad)
        elif arm32:
            # The hook covers every address on 32-bit ARM: the code does not start its page there (code_off),
            # so the rest of the page is mapped, executable filler a jump could otherwise slide through.
            if not code_lo <= address < code_hi:
                fail(uc_, "execution left the symbol's bytes @%#x (the rest of its page is not the device's)"
                     % address)
                return
            # The body is vetted with the decoder of its ENTRY instruction set, so it must still be in it:
            # after a `bx`/`blx` into the other set the same bytes are other instructions (a Thumb `mrc` reads
            # as an A32 `svceq`), which this would wave through.
            if bool(uc_.reg_read(_a32c.UC_ARM_REG_CPSR) & 0x20) != thumb_entry:
                fail(uc_, "instruction-set switch inside the body (A32/Thumb interworking) @%#x is not "
                     "modelled" % address)
                return
            off = address - code_lo
            bad = vetted.get(off)
            if bad is None:
                bad = vetted[off] = _arm_insn_env(code, off, thumb_entry)
            if bad:
                fail(uc_, "%s executed (its value depends on the machine, not on the bytes)" % bad)

    def hook_sysreg(uc_, reg, cp, _u):       # AArch64 MRS / MSR / SYS / SYSL (UC_HOOK_INSN)
        key = (cp.op0, cp.op1, cp.crn, cp.crm, cp.op2)
        ok = A64_MRS_OK if _u == "mrs" else (A64_MSR_OK if _u == "msr" else ())
        if key in ok:
            return False
        fail(uc_, "system register / instruction %s %s (machine-dependent, not modelled)" % (_u, key))
        return True

    def hook_mem_write(uc_, access, address, size, value, _u):
        for b in range(size):
            written.add(address + b)
        return True

    def hook_write_unmapped(uc_, access, address, size, value, _u):
        page = address & ~(_PAGE - 1)
        try:
            uc_.mem_map(page, _PAGE, _uc.UC_PROT_READ | _uc.UC_PROT_WRITE)
        except Exception:
            return False
        return True                          # retry the write now that the page exists

    def hook_mem_read(uc_, access, address, size, value, _u):
        for b in range(size):
            a = address + b
            if a in written:
                continue
            if code_lo <= a < code_hi:       # reading the function's own code/constants is defined
                continue
            fail(uc_, "read of undefined memory @%#x" % a)
            return False
        return True

    def hook_read_unmapped(uc_, access, address, size, value, _u):
        fail(uc_, "read of unmapped memory @%#x" % address)
        return False                         # do not map: an undefined read must fail closed

    def hook_fetch_unmapped(uc_, access, address, size, value, _u):
        if ret_pc is not None and state["error"] is None and (address & ~1) == ret_pc:
            # 32-bit ARM: control reached the caller's return address, so the function returned (by whatever
            # instruction wrote PC). Nothing is mapped there, so emulation ends on this fetch.
            state["returned"] = True
            uc_.emu_stop()
            return False
        fail(uc_, "fetch outside mapped code @%#x" % address)
        return False

    def hook_intr(uc_, intno, _u):
        fail(uc_, "software interrupt / syscall denied")

    def hook_syscall(uc_, _u):               # the x86-64 `syscall` instruction (UC_HOOK_INSN callback)
        fail(uc_, "syscall denied")

    if arm32:                                # every address: hook_code refuses one outside the symbol's bytes
        uc.hook_add(_uc.UC_HOOK_CODE, hook_code, begin=1, end=0)
    else:
        uc.hook_add(_uc.UC_HOOK_CODE, hook_code, begin=code_lo, end=code_hi)
    uc.hook_add(_uc.UC_HOOK_MEM_WRITE, hook_mem_write)
    uc.hook_add(_uc.UC_HOOK_MEM_WRITE_UNMAPPED, hook_write_unmapped)
    uc.hook_add(_uc.UC_HOOK_MEM_READ, hook_mem_read)
    uc.hook_add(_uc.UC_HOOK_MEM_READ_UNMAPPED | _uc.UC_HOOK_MEM_READ_PROT, hook_read_unmapped)
    uc.hook_add(_uc.UC_HOOK_MEM_FETCH_UNMAPPED | _uc.UC_HOOK_MEM_FETCH_PROT, hook_fetch_unmapped)
    uc.hook_add(_uc.UC_HOOK_INTR, hook_intr)
    if arch == ARCH_X86_64:                  # the `syscall`/`sysenter` instruction (not an INT) on x86-64
        for _insn in ("UC_X86_INS_SYSCALL", "UC_X86_INS_SYSENTER"):
            try:
                uc.hook_add(_uc.UC_HOOK_INSN, hook_syscall, begin=1, end=0, aux1=getattr(_x86c, _insn))
            except Exception:
                pass
    elif arch == ARCH_ARM64:
        for _insn, _tag in (("UC_ARM64_INS_MRS", "mrs"), ("UC_ARM64_INS_MSR", "msr"), ("UC_ARM64_INS_SYS", "sys"),
                            ("UC_ARM64_INS_SYSL", "sysl")):
            uc.hook_add(_uc.UC_HOOK_INSN, hook_sysreg, _tag, 1, 0, getattr(_a64c, _insn))
    # ARM32 (A32/T32): its machine-dependent instructions (coprocessor, MRS/MSR, VMRS, mode changes) are
    # vetted per executed instruction in hook_code via capstone (ARM32_ENV_INSNS), not through UC_HOOK_INSN.

    try:
        # Thumb (T32) executes when the entry address has bit 0 set; the hook and stop addresses stay even.
        uc.emu_start(code_lo | (1 if thumb_entry else 0), code_hi, count=max_insns + 1)
    except _uc.UcError as e:
        # 32-bit ARM: the fetch at the caller's return address IS the return, and Unicorn reports it as a
        # fetch error; any other engine error is one
        if state["error"] is None and not state["returned"]:
            state["error"] = "unicorn error: %s" % e
    except Exception as e:
        state["error"] = "emulation aborted: %s" % e

    if state["error"]:
        raise EmulationError(state["error"])
    if not state["returned"]:
        raise EmulationError("function did not return within the code / budget")
    return uc.reg_read(result_id) & M64


# --------------------------------------------------------------- public: general entry
def emulate_function(code, arch, regs_in, result_reg, max_insns=200000):
    """Emulate a single function from raw `code` bytes and return `result_reg` (64-bit) after it returns.

    `arch` is ARCH_X86_64, ARCH_ARM64, ARCH_ARM32 (A32) or ARCH_THUMB (T32); `regs_in` is {name: value} for
    the registers the caller defines (the ABI argument mapping is the caller's); every other GP register is
    undefined. Raises EmulationError on any trap, timeout, undefined read, undefined-register dependence, or
    no return -- never a fabricated value (see the module docstring's never-wrong contract)."""
    if not UNICORN_AVAILABLE:
        raise EmulationError("unicorn engine not available: %s" % UNICORN_UNAVAILABLE_REASON)
    if arch not in (ARCH_X86_64, ARCH_ARM64, ARCH_ARM32, ARCH_THUMB):
        raise EmulationError("unsupported arch %r" % (arch,))
    code = bytes(code)
    if not code:
        raise EmulationError("empty code")
    if len(code) > _MAX_CODE:
        raise EmulationError("code too large (%d bytes)" % len(code))

    if arch == ARCH_X86_64:
        reg_ids, poison_gp, stop_offsets = _x86_regs(), _X86_GP, _x86_ret_offsets(code)
    elif arch == ARCH_ARM64:
        reg_ids, poison_gp, stop_offsets = _arm64_regs(), _ARM64_GP, _arm64_ret_offsets(code)
    else:  # ARCH_ARM32 / ARCH_THUMB: no static return scan, the return is a fetch at the LR canary
        reg_ids, poison_gp, stop_offsets = _arm32_regs(), _ARM32_GP, set()
    arm32 = arch in _ARM32_ARCHES
    for name in list(regs_in) + [result_reg]:
        if name not in reg_ids:
            raise EmulationError("unknown register %r for %s" % (name, arch))
        if arm32 and name in ("lr", "sp", "pc"):
            raise EmulationError("register %r is the engine's on 32-bit ARM (the return canary, the stack, the "
                                 "entry), not the caller's to set or read" % name)
    if not stop_offsets and not arm32:
        raise EmulationError("no return instruction found in the code")
    stop_addrs = {_CODE_BASE + off for off in stop_offsets}
    result_id = reg_ids[result_reg]

    regs_in = {k: (v & M64) for k, v in regs_in.items()}
    if arm32:
        # One run per ARM32_RUNS entry (register poison, LR canary, APSR flags, code base, stack top and the
        # code's offset in its page all vary); identical result required, so a dependence on an undefined
        # register, on the return address, on the entry flags or on where the code and the stack happen to be
        # fails. The offset keeps the instruction alignment: a multiple of 4 for A32, of 2 for Thumb.
        align = 1 if arch == ARCH_THUMB else 3
        vals = [_run_once(arch, code, reg_ids, regs_in, poison_gp, fill, result_id, stop_addrs, max_insns,
                          lr_canary=lr, apsr=flags, code_base=base, stack_top=top, code_off=off & ~align)
                for fill, lr, flags, base, top, off in ARM32_RUNS]
        if len(set(vals)) != 1:
            raise EmulationError("result depends on an undefined register, the return address, the entry flags "
                                 "or the load address (%s)" % " vs ".join("%#x" % v for v in vals))
        return vals[0]
    # Two runs with different poison fills for the undefined registers; identical result required.
    r_a = _run_once(arch, code, reg_ids, regs_in, poison_gp, _POISON_A, result_id, stop_addrs, max_insns)
    r_b = _run_once(arch, code, reg_ids, regs_in, poison_gp, _POISON_B, result_id, stop_addrs, max_insns)
    if r_a != r_b:
        raise EmulationError("result depends on an undefined register (%#x vs %#x)" % (r_a, r_b))
    return r_a


# --------------------------------------------------------------- public: ABI conveniences
def emulate_x86_sysv(code, int_args, max_insns=200000):
    """Emulate an x86-64 function whose integer arguments are in SysV order
    (rdi, rsi, rdx, rcx, r8, r9) and return rax. `int_args` is the integer-argument list; arguments past
    the sixth are not modelled (stack args) and must be absent. Raises EmulationError otherwise."""
    order = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
    if len(int_args) > len(order):
        raise EmulationError("more than 6 integer args (stack args not modelled)")
    regs_in = {order[i]: (int_args[i] & M64) for i in range(len(int_args))}
    return emulate_function(code, ARCH_X86_64, regs_in, "rax", max_insns=max_insns)


def emulate_arm64_aapcs(code, int_args, max_insns=200000):
    """Emulate an AArch64 function whose integer arguments are in AAPCS64 order (x0..x7) and return x0.
    `int_args` is the integer-argument list; more than eight are not modelled (stack args)."""
    if len(int_args) > 8:
        raise EmulationError("more than 8 integer args (stack args not modelled)")
    regs_in = {"x%d" % i: (int_args[i] & M64) for i in range(len(int_args))}
    return emulate_function(code, ARCH_ARM64, regs_in, "x0", max_insns=max_insns)


def emulate_arm32_aapcs(code, int_args, thumb=False, max_insns=200000):
    """Emulate a 32-bit ARM function whose integer arguments are in AAPCS (AAPCS32 core-register) order
    (r0..r3) and return r0 (masked to 64 bits; the caller keeps the low 32). `int_args` is the already-mapped
    list of single-register argument values -- a 64-bit (long/double) argument that occupies an even-aligned
    register PAIR is NOT handled here, so the caller must split and align it or decline. More than four
    core-register arguments are not modelled (stack args). `thumb` selects the T32 instruction set.
    Raises EmulationError on anything that is not a deterministic, fully-defined return."""
    if len(int_args) > 4:
        raise EmulationError("more than 4 core-register args (stack args not modelled)")
    regs_in = {"r%d" % i: (int_args[i] & M32) for i in range(len(int_args))}
    return emulate_function(code, ARCH_THUMB if thumb else ARCH_ARM32, regs_in, "r0", max_insns=max_insns)


def emulate_symbol(elf_bytes, symbol_or_vaddr, args, arch=None, **kw):
    """WHOLE-IMAGE emulation of one function of an ELF (KB-2): every PT_LOAD mapped, relocations applied, its
    constructors run, PLT calls to siblings and the modelled libc subset followed, .rodata/.data read. This is
    native_image.emulate_symbol (see its docstring for args / ret / init); it lives there and is re-exported
    here so a release-morning fields_dNN.py author finds it beside the single-function entries above. Raises
    EmulationError on anything it cannot prove. A reader, not a label: never a plain answer from it on its own."""
    import native_image as _ni                          # lazy: native_image imports this module
    return _ni.emulate_symbol(elf_bytes, symbol_or_vaddr, args, arch=arch, **kw)


if __name__ == "__main__":                              # tiny smoke test, no sample bytes
    import sys
    if not UNICORN_AVAILABLE:
        print("unicorn NOT available")
        sys.exit(1)
    # x86-64: mov rax, rdi ; add rax, rsi ; ret    -> 5 + 7 == 12
    x = bytes.fromhex("4889f84801f0c3")
    print("x86 add:", hex(emulate_x86_sysv(x, [5, 7])))
    # arm64: add x0, x0, x1 ; ret                  -> 5 + 7 == 12
    a = struct.pack("<II", 0x8B010000, 0xD65F03C0)
    print("arm64 add:", hex(emulate_arm64_aapcs(a, [5, 7])))
