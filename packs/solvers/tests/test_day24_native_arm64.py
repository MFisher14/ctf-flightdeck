"""Never-wrong tests for solvers/mobile-android/native_arm64.py (Day-24 arm64 JNI-transform look-ahead).

Strategy: hand-encode AArch64 instructions, assert via capstone that each word decodes to the intended
mnemonic (a mis-encode fails here, loudly, so a wrong emulator can never pass silently), run each transform
through the emulator, and compare x0 against an INDEPENDENT pure-Python reference. Plus the fail-closed
cases (memory, branch, unknown op, read-before-write, no-ret) that must all Decline, and ELF routing
(x86 .so is never routed to the arm64 emulator).

Run: .venv/bin/python -I -B -m pytest tests/test_day24_native_arm64.py -q
"""
import os
import random
import struct
import sys

import capstone
from capstone import arm64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "solvers", "mobile-android"))
import native_arm64 as na  # noqa: E402

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
_MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
_MD.detail = True


# --------------------------------------------------------------------------- encoders (64-bit forms)
def _u(w):
    return w & 0xFFFFFFFF


def movz(rd, imm16, sh=0):   return _u(0xD2800000 | ((sh // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd)
def movk(rd, imm16, sh=0):   return _u(0xF2800000 | ((sh // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd)
def movn(rd, imm16, sh=0):   return _u(0x92800000 | ((sh // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd)
def orr_sr(rd, rn, rm, amt=0): return _u(0xAA000000 | (rm << 16) | (amt << 10) | (rn << 5) | rd)
def mov_reg(rd, rm):         return orr_sr(rd, 31, rm)
def and_sr(rd, rn, rm, amt=0): return _u(0x8A000000 | (rm << 16) | (amt << 10) | (rn << 5) | rd)
def eor_sr(rd, rn, rm, amt=0): return _u(0xCA000000 | (rm << 16) | (amt << 10) | (rn << 5) | rd)
def add_sr(rd, rn, rm, amt=0): return _u(0x8B000000 | (rm << 16) | (amt << 10) | (rn << 5) | rd)
def sub_sr(rd, rn, rm, amt=0): return _u(0xCB000000 | (rm << 16) | (amt << 10) | (rn << 5) | rd)
def add_imm(rd, rn, imm12):  return _u(0x91000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd)
def sub_imm(rd, rn, imm12):  return _u(0xD1000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd)
def mul(rd, rn, rm):         return _u(0x9B007C00 | (rm << 16) | (rn << 5) | rd)   # madd rd,rn,rm,xzr
def neg(rd, rm):             return sub_sr(rd, 31, rm)
def mvn(rd, rm):             return _u(0xAA200000 | (rm << 16) | (31 << 5) | rd)   # orn rd,xzr,rm
def lslv(rd, rn, rm):        return _u(0x9AC02000 | (rm << 16) | (rn << 5) | rd)
def lsrv(rd, rn, rm):        return _u(0x9AC02400 | (rm << 16) | (rn << 5) | rd)
def asrv(rd, rn, rm):        return _u(0x9AC02800 | (rm << 16) | (rn << 5) | rd)
def rorv(rd, rn, rm):        return _u(0x9AC02C00 | (rm << 16) | (rn << 5) | rd)
def _ubfm(rd, rn, immr, imms): return _u(0xD3400000 | ((immr & 0x3F) << 16) | ((imms & 0x3F) << 10) | (rn << 5) | rd)
def _sbfm(rd, rn, immr, imms): return _u(0x93400000 | ((immr & 0x3F) << 16) | ((imms & 0x3F) << 10) | (rn << 5) | rd)
def lsl_imm(rd, rn, sh):     return _ubfm(rd, rn, (-sh) % 64, 63 - sh)
def lsr_imm(rd, rn, sh):     return _ubfm(rd, rn, sh, 63)
def asr_imm(rd, rn, sh):     return _sbfm(rd, rn, sh, 63)
def extr(rd, rn, rm, lsb):   return _u(0x93C00000 | (rm << 16) | ((lsb & 0x3F) << 10) | (rn << 5) | rd)
def ror_imm(rd, rn, sh):     return extr(rd, rn, rn, sh)
def clz(rd, rn):             return _u(0xDAC01000 | (rn << 5) | rd)
def rbit(rd, rn):            return _u(0xDAC00000 | (rn << 5) | rd)
def rev(rd, rn):             return _u(0xDAC00C00 | (rn << 5) | rd)
def sxtw(rd, rn):            return _sbfm(rd, rn, 0, 31)
# 32-bit (sf=0) forms used for the zero-extend test
def mov_reg_w(rd, rm):       return _u(0x2A000000 | (rm << 16) | (31 << 5) | rd)  # orr w,wzr,wm
def add_sr_w(rd, rn, rm):    return _u(0x0B000000 | (rm << 16) | (rn << 5) | rd)
def movz_w(rd, imm16):       return _u(0x52800000 | ((imm16 & 0xFFFF) << 5) | rd)
RET = 0xD65F03C0
NOP = 0xD503201F


def _dis(word):
    return next(_MD.disasm(struct.pack("<I", word), 0))


def _assemble(words):
    return b"".join(struct.pack("<I", w) for w in words)


# --------------------------------------------------------------------------- reference machine
class Ref:
    """Independent pure-Python model of the same ops, for cross-checking (never imports the emulator)."""

    def __init__(self, arg):
        self.r = {i: 0 for i in range(31)}
        self.r[2] = arg & M64

    def _s(self, v, b):
        v &= (1 << b) - 1
        return v - (1 << b) if v >> (b - 1) else v

    def run(self, prog):
        prog(self)
        return self.r[0] & M64


def test_encodings_decode_as_intended():
    """Every encoder must produce the mnemonic we think it does (guards the whole cross-check)."""
    cases = [
        (movz(2, 0x1234), "mov"), (movk(2, 0xabcd, 16), "movk"), (movn(3, 1), "mov"),
        (mov_reg(0, 2), "mov"), (and_sr(0, 1, 2), "and"), (eor_sr(0, 1, 2), "eor"),
        (add_sr(0, 1, 2), "add"), (sub_sr(0, 1, 2), "sub"), (add_sr(0, 1, 2, 3), "add"),
        (add_imm(0, 1, 5), "add"), (sub_imm(0, 1, 5), "sub"), (mul(0, 1, 2), "mul"),
        (neg(0, 2), "neg"), (mvn(0, 2), "mvn"), (lslv(0, 1, 2), "lsl"), (lsrv(0, 1, 2), "lsr"),
        (asrv(0, 1, 2), "asr"), (rorv(0, 1, 2), "ror"), (lsl_imm(0, 1, 3), "lsl"),
        (lsr_imm(0, 1, 3), "lsr"), (asr_imm(0, 1, 3), "asr"), (ror_imm(0, 1, 3), "ror"),
        (clz(0, 1), "clz"), (rbit(0, 1), "rbit"), (rev(0, 1), "rev"), (sxtw(0, 1), "sxtw"),
        (mov_reg_w(0, 2), "mov"), (add_sr_w(0, 1, 2), "add"), (movz_w(3, 7), "mov"),
        (RET, "ret"), (NOP, "nop"),
    ]
    for word, mnem in cases:
        got = _dis(word).mnemonic
        assert got == mnem, "word %08x decoded %r, expected %r" % (word, got, mnem)


def _check(words, prog, args):
    """Assert emulate(code) == reference for every arg in `args`."""
    code = _assemble(list(words) + [RET])
    for a in args:
        want = Ref(a).run(prog)
        got = na.emulate(code, a)
        assert got == want, "arg=%#x got=%#x want=%#x\n%s" % (a, got, want, [hex(w) for w in words])


ARGS = [0, 1, 2, 0x1234, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, M64,
        0xDEADBEEFCAFEF00D, 0x00000000FFFFFFFF, 0xA5A5A5A5A5A5A5A5]
RNG = random.Random(20260124)
ARGS = ARGS + [RNG.getrandbits(64) for _ in range(40)]


def test_classic_64bit_scramble():
    # x0 = ~(((x2 ^ 0xABCD1234) + 5) rotr 7) * 3   (all 64-bit, wrapping)
    words = [
        mov_reg(0, 2),
        movz(3, 0x1234), movk(3, 0xABCD, 16),
        eor_sr(0, 0, 3),
        add_imm(0, 0, 5),
        ror_imm(0, 0, 7),
        movz(4, 3),
        mul(0, 0, 4),
        mvn(0, 0),
    ]

    def prog(s):
        s.r[0] = s.r[2]
        s.r[3] = 0x1234 | (0xABCD << 16)
        s.r[0] ^= s.r[3]
        s.r[0] = (s.r[0] + 5) & M64
        a = s.r[0] & M64
        s.r[0] = ((a >> 7) | (a << (64 - 7))) & M64
        s.r[4] = 3
        s.r[0] = (s.r[0] * s.r[4]) & M64
        s.r[0] = (~s.r[0]) & M64
    _check(words, prog, ARGS)


def test_shifts_and_logical():
    # x0 = ((x2 lsl 3) eor (x2 lsr 5)) and 0xFF00FF00FF00FF ; then asr 2 ; then add x2,lsl#1
    words = [
        lsl_imm(0, 2, 3),
        lsr_imm(5, 2, 5),
        eor_sr(0, 0, 5),
        movz(6, 0x00FF), movk(6, 0xFF00, 16), movk(6, 0x00FF, 32), movk(6, 0xFF00, 48),
        and_sr(0, 0, 6),
        asr_imm(0, 0, 2),
        add_sr(0, 0, 2, 1),   # add x0, x0, x2, lsl #1
    ]

    def prog(s):
        s.r[0] = (s.r[2] << 3) & M64
        s.r[5] = (s.r[2] & M64) >> 5
        s.r[0] ^= s.r[5]
        s.r[6] = 0x00FF | (0xFF00 << 16) | (0x00FF << 32) | (0xFF00 << 48)
        s.r[0] &= s.r[6]
        s.r[0] = (s._s(s.r[0], 64) >> 2) & M64
        s.r[0] = (s.r[0] + ((s.r[2] << 1) & M64)) & M64
    _check(words, prog, ARGS)


def test_variable_shifts_and_extr():
    # amt = x2 and 63 ; x0 = (x2 lslv amt) rorv 11, via register amounts ; then extr mix
    words = [
        movz(7, 63), and_sr(7, 2, 7),
        lslv(0, 2, 7),
        movz(8, 11), rorv(0, 0, 8),
        extr(0, 0, 2, 20),
    ]

    def prog(s):
        s.r[7] = s.r[2] & 63
        amt = s.r[7] & 63
        s.r[0] = (s.r[2] << amt) & M64
        s.r[8] = 11
        a = s.r[0] & M64
        s.r[0] = ((a >> 11) | (a << (64 - 11))) & M64
        n, k = s.r[0] & M64, s.r[2] & M64
        s.r[0] = (((n << 64) | k) >> 20) & M64
    _check(words, prog, ARGS)


def test_bit_ops_clz_rbit_rev_sxtw():
    words = [
        rbit(0, 2),
        clz(3, 2),
        add_sr(0, 0, 3),
        rev(0, 0),
        sxtw(0, 0),
    ]

    def prog(s):
        s.r[0] = int(format(s.r[2] & M64, "064b")[::-1], 2)
        n = s.r[2] & M64
        s.r[3] = 64 if n == 0 else (64 - n.bit_length())
        s.r[0] = (s.r[0] + s.r[3]) & M64
        s.r[0] = int.from_bytes((s.r[0] & M64).to_bytes(8, "little")[::-1], "little")
        s.r[0] = s._s(s.r[0] & M32, 32) & M64
    _check(words, prog, ARGS)


def test_32bit_result_is_zero_extended():
    # w0 = w2 + 0x7 (32-bit) -> upper 32 bits of x0 MUST be zero
    words = [mov_reg_w(0, 2), movz_w(3, 7), add_sr_w(0, 0, 3)]

    def prog(s):
        s.r[0] = ((s.r[2] & M32) + 7) & M32   # 32-bit write zero-extends into x0
    _check(words, prog, ARGS)
    # explicit upper-half check on a value whose low-32 add overflows
    code = _assemble(words + [RET])
    assert na.emulate(code, 0xFFFFFFFFFFFFFFF0) == ((0xFFFFFFF0 + 7) & M32)


def test_movn_and_movk_build_64bit_constant():
    # x3 = 0x1122334455667788 via movz+movk*3 ; x4 = ~0 via movn ; x0 = x3 eor x4 eor x2
    words = [
        movz(3, 0x7788), movk(3, 0x5566, 16), movk(3, 0x3344, 32), movk(3, 0x1122, 48),
        movn(4, 0),
        eor_sr(0, 3, 4), eor_sr(0, 0, 2),
    ]

    def prog(s):
        s.r[3] = 0x1122334455667788
        s.r[4] = (~0) & M64
        s.r[0] = (s.r[3] ^ s.r[4]) ^ s.r[2]
    _check(words, prog, ARGS)


# --------------------------------------------------------------------------- fail-closed cases
def test_decline_memory():
    code = _assemble([mov_reg(0, 2), 0xF9400040, RET])  # ldr x0,[x2]
    try:
        na.emulate(code, 5)
        assert False, "memory access must Decline"
    except na.Decline:
        pass


def test_decline_branch():
    code = _assemble([mov_reg(0, 2), 0x14000001, RET])  # b .+4
    try:
        na.emulate(code, 5)
        assert False, "branch must Decline"
    except na.Decline:
        pass


def test_decline_unknown_fp():
    code = _assemble([0x9E670040, RET])  # fmov d0, x2
    try:
        na.emulate(code, 5)
        assert False, "fp op must Decline"
    except na.Decline:
        pass


def test_decline_read_before_write():
    # eor x0,x0,x0 reads x0 (uninitialised) before writing it -> indeterminate -> Decline
    code = _assemble([eor_sr(0, 0, 0), RET])
    try:
        na.emulate(code, 5)
        assert False, "read-before-write must Decline"
    except na.Decline:
        pass
    # using x1 (jclass) as a source is indeterminate too
    code = _assemble([add_sr(0, 1, 2), RET])
    try:
        na.emulate(code, 5)
        assert False, "reading x1 (jclass) must Decline"
    except na.Decline:
        pass


def test_decline_no_ret():
    code = _assemble([mov_reg(0, 2)])  # no ret appended
    try:
        na.emulate(code, 5)
        assert False, "a run with no ret must Decline"
    except na.Decline:
        pass


def test_x2_only_defined_input():
    # reading x2 is fine; a program that only moves x2 to x0 returns the arg unchanged
    code = _assemble([mov_reg(0, 2), RET])
    assert na.emulate(code, 0xCAFEBABE12345678) == 0xCAFEBABE12345678


# --------------------------------------------------------------------------- ELF routing
def _minimal_elf64(machine, code):
    """A tiny ELF64 LE object: one .text (vaddr 0x1000) and one global FUNC symbol 'Java_x_t'."""
    name = b"Java_x_t"
    ehdr_sz = 64
    code_off = ehdr_sz
    dynstr = b"\x00" + name + b"\x00"
    dynstr_off = code_off + len(code)
    dynsym_off = (dynstr_off + len(dynstr) + 7) & ~7
    sym0 = b"\x00" * 24
    sym1 = struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0x1000, len(code))  # name=1, FUNC|GLOBAL, shndx=1
    dynsym = sym0 + sym1
    sh_off = (dynsym_off + len(dynsym) + 7) & ~7
    shentsize = 64

    def shdr(name_, typ, flags, addr, off, size, link, info, align, entsize):
        return struct.pack("<IIQQQQIIQQ", name_, typ, flags, addr, off, size, link, info, align, entsize)

    shdrs = b"".join([
        shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),                                   # null
        shdr(0, 1, 6, 0x1000, code_off, len(code), 0, 0, 4, 0),               # .text PROGBITS
        shdr(0, 3, 0, 0, dynstr_off, len(dynstr), 0, 0, 1, 0),                # .dynstr STRTAB
        shdr(0, 11, 0, 0, dynsym_off, len(dynsym), 2, 1, 8, 24),              # .dynsym DYNSYM link=2
    ])
    e_shnum = 4
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2   # ELFCLASS64
    ehdr[5] = 1   # little-endian
    ehdr[6] = 1   # EV_CURRENT
    struct.pack_into("<H", ehdr, 0x10, 3)         # e_type ET_DYN
    struct.pack_into("<H", ehdr, 0x12, machine)   # e_machine
    struct.pack_into("<I", ehdr, 0x14, 1)
    struct.pack_into("<Q", ehdr, 0x28, sh_off)    # e_shoff
    struct.pack_into("<H", ehdr, 0x3a, shentsize)
    struct.pack_into("<H", ehdr, 0x3c, e_shnum)
    struct.pack_into("<H", ehdr, 0x3e, 2)         # e_shstrndx (unused by the parser)
    blob = bytearray(ehdr) + code
    blob += b"\x00" * (dynstr_off - len(blob)) + dynstr
    blob += b"\x00" * (dynsym_off - len(blob)) + dynsym
    blob += b"\x00" * (sh_off - len(blob)) + shdrs
    return bytes(blob)


def test_elf_machine_and_routing():
    code = _assemble([mov_reg(0, 2), RET])
    arm = _minimal_elf64(na.EM_AARCH64, code)
    x86 = _minimal_elf64(62, code)  # EM_X86_64
    assert na.elf_machine(arm) == na.EM_AARCH64
    assert na.elf_machine(x86) == 62
    assert na.elf_machine(b"not an elf") is None
    # the aarch64 FUNC symbol is extracted, and its bytes run through the emulator
    syms = na.aarch64_functions(arm)
    assert "Java_x_t" in syms
    assert na.emulate(syms["Java_x_t"], 0x4242) == 0x4242
    # an x86 .so is NEVER routed to the arm64 emulator (routing stays exclusive by architecture)
    assert na.aarch64_functions(x86) == {}
    assert na.aarch64_functions(b"junk") == {}


if __name__ == "__main__":
    import traceback
    g = dict(globals())
    passed = failed = 0
    for nm, fn in sorted(g.items()):
        if nm.startswith("test_") and callable(fn):
            try:
                fn()
                passed += 1
                print("ok   ", nm)
            except Exception:
                failed += 1
                print("FAIL ", nm)
                traceback.print_exc()
    print("\n%d passed, %d failed" % (passed, failed))
    sys.exit(1 if failed else 0)
