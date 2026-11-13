#!/usr/bin/env python3
"""Day-25 look-ahead closers for the Mobile "analysis" (dex-chain + native) codec.

Covers the three Day-25 gaps the look-ahead flagged (docs/retro/day-25/predictions-mobile-android.md):

  1. CRITICAL never-wrong: a real arm32 (EM_ARM) native .so must never give a confident WRONG plain code.
     The armed tree fed any ELF64's bytes to the x86 decoder, and 8/30 random arm32 transforms decoded as
     benign x86 arithmetic -> a wrong ANS code -> the whole batch rejected. B-164 now RESOLVES a provable
     32-bit ARM (A32/Thumb) native through Unicorn, but only from the container a device loads (a
     little-endian ELF32, whose definitions carry the sentinels EM_ARM_A32 / EM_ARM_THUMB). The raw machine
     40 (EM_ARM) these tests build -- an ELF64 file tagged e_machine 40, or a hand-made table entry -- still
     fails closed exactly as before, as do machine 3 (EM_386) and every other unmodelled machine. The arm32
     resolve-and-fail-closed behaviour is covered in tests/test_b164_native_arm.py.
  2. A fail-closed AArch64 emulator (_emulate_arm64): an arm64 native leg that the armed tree declined
     (-> None) now resolves to the true PLAIN code where it can prove it.
  3. Dalvik float/double arithmetic, conversions and neg: modelled exactly (IEEE / Java narrowing) so a
     chain that uses them resolves to the true code, and fails closed (None) on NaN/Inf/divide-by-zero.

Pure-function units always run. Integration cases that need the real Day-23 Mastery APK and the prep
specimens SKIP when those are absent (e.g. a checkout with no challenges/ data).

Run:  .venv/bin/python -I -B tests/test_day25_mobile_native.py
"""
import importlib.util
import math
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "solvers" / "mobile-android"))
sys.path.insert(0, str(ROOT / "solvers" / "common"))
sys.path.insert(0, str(ROOT / "tests"))

spec = importlib.util.spec_from_file_location("dex_chain_codec", ROOT / "solvers/mobile-android/dex_chain_codec.py")
dcc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dcc)
import labels  # noqa: E402

M64 = (1 << 64) - 1
M32 = 0xFFFFFFFF
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS", name)
    else:
        FAIL += 1
        print("FAIL", name)


# =================================================================== 1. e_machine guard (never-wrong)
def test_parse_so_carries_machine():
    # A minimal ELF64 with one FUNC symbol; _parse_so must return (e_machine, code) and the dispatcher
    # must DECLINE any non-x86-64/arm64 machine instead of decoding it as x86.
    for emach in (dcc.EM_X86_64, dcc.EM_AARCH64, dcc.EM_ARM, 3):
        so = _mini_so(b"\x90\xc3", emach)          # x86 `nop; ret` bytes, tagged with e_machine
        parsed = dcc._parse_so(so)
        vals = list(parsed.values())
        check("parse_so/machine=%d carried" % emach, len(vals) == 1 and vals[0][0] == emach)


def test_dispatch_declines_foreign_machine():
    # Build a VM whose native_syms hold an EM_ARM leg; invoking it must raise _Decline (fail closed),
    # NOT return an x86-decoded value. B-164 runs 32-bit ARM only under its two vetted sentinels (a little-endian
    # ELF32 body's definitions, tests/test_b164_native_arm.py); the raw machine 40 still declines, as before.
    # the method's exact JNI name: since the Day 27 so-ambig fix round 2 a method no dex declares native (this hand-built
    # dex has no class data) binds only by its own exact name, never by another symbol the loose rule matches
    sym = "Java_com_x_NativeLibrarySecrets_nativeShare"
    for emach, want_decline in ((dcc.EM_ARM, True), (3, True), (dcc.EM_X86_64, False), (dcc.EM_AARCH64, False)):
        vm = dcc.VM.__new__(dcc.VM)
        vm.dex = None
        vm.native_syms = {sym: (emach, dcc.arm64_nop_ret() if emach == dcc.EM_AARCH64 else b"\x90\xc3")}
        vm.steps = 0
        vm.max_steps = 1000
        declined = False
        try:
            # drive the native branch of _invoke directly with a fake class/name
            vm.dex = _FakeDex(sym)
            vm._invoke(0x71, 0, [123])
        except dcc._Decline:
            declined = True
        except Exception:
            declined = "other"
        check("dispatch/machine=%d declines=%s" % (emach, want_decline),
              (declined is True) == want_decline)


# =================================================================== 2. AArch64 emulator decoding
def test_arm64_basic_ops():
    cases = [
        ("add", _asm([_movz(0, 5), _movz(3, 3), _add(0, 0, 3), _ret()]), 0, 8),
        ("sub", _asm([_movz(0, 10), _movz(3, 3), _sub(0, 0, 3), _ret()]), 0, 7),
        ("eor", _asm([_movz(0, 0xF0), _movz(3, 0x0F), _eor(0, 0, 3), _ret()]), 0, 0xFF),
        ("orr", _asm([_movz(0, 0xF0), _movz(3, 0x0F), _orr(0, 0, 3), _ret()]), 0, 0xFF),
        ("and", _asm([_movz(0, 0xFF), _movz(3, 0x0F), _and(0, 0, 3), _ret()]), 0, 0x0F),
        ("mov_x2", _asm([_orr(0, 31, 2), _ret()]), 0x1234, 0x1234),
        ("lsr", _asm([_movz(0, 8), _lsr(0, 0, 1), _ret()]), 0, 4),
        ("lsl", _asm([_movz(0, 1), _lsl(0, 0, 4), _ret()]), 0, 16),
        ("ror1", _asm([_movz(0, 1), _ror(0, 0, 1), _ret()]), 0, 0x8000000000000000),
        ("mul", _asm([_movz(0, 6), _movz(3, 7), _mul(0, 0, 3), _ret()]), 0, 42),
        ("add_imm", _asm([_movz(0, 5), _add_imm(0, 0, 10), _ret()]), 0, 15),
        ("sub_imm", _asm([_movz(0, 20), _sub_imm(0, 0, 7), _ret()]), 0, 13),
        ("and_imm_0xF", _asm([_movz(0, 0xFF), _and_imm(0, 0, 1, 0, 3), _ret()]), 0, 0x0F),
        ("movk", _asm([_movz(0, 0x1234), _movk(0, 0xABCD, 1), _ret()]), 0, 0xABCD1234),
    ]
    for name, code, arg, want in cases:
        got = dcc._emulate_arm64(code, arg) & M64
        check("arm64/%s" % name, got == want)


T_CONSTS = dict(c1=0x605a865fc1f4570d, c2=0x1c9d09172467cb22, c3=0xfd3b0dd6f0bfd601,
                c4=0x84d74e693e415dcb, c5=0x81728d1eccb1e465, r1=0x25, s1=0x15, r2=4)


def _ref_T(arg):
    """An independent Python spec of the harness's arm64_T transform (arg in x2 -> result x0)."""
    c = T_CONSTS

    def ror(v, s):
        s %= 64
        return ((v >> s) | (v << (64 - s))) & M64 if s else v & M64
    x0 = arg & M64
    x0 = (x0 + c["c1"]) & M64
    x0 = (x0 ^ c["c2"]) & M64
    x0 = ror(x0, 64 - c["r1"])
    x0 = (x0 + c["c3"]) & M64
    x3 = x0 >> c["s1"]
    x0 = (x0 ^ x3) & M64
    x0 = (x0 + c["c4"]) & M64
    x0 = ror(x0, 64 - c["r2"])
    x0 = (x0 * c["c5"]) & M64
    return x0


def test_arm64_full_transform():
    bh = _load_harness()
    if bh is None:
        print("SKIP arm64/full-transform (harness unavailable)")
        return
    code = bh.arm64_T()
    ok = True
    for arg in (0, 1, 0x1122334455667788, 0xdeadbeef, 0x075bcd15, M64):
        if (dcc._emulate_arm64(code, arg) & M64) != _ref_T(arg):
            ok = False
    check("arm64/full-transform matches independent spec", ok)


def test_arm64_unknown_declines():
    # An unmodelled word (a load: LDR x0,[x1]) must fail closed.
    ldr = struct.pack("<I", 0xF9400020)
    declined = False
    try:
        dcc._emulate_arm64(ldr + struct.pack("<I", 0xD65F03C0), 0)
    except dcc._Decline:
        declined = True
    check("arm64/unknown-word declines", declined)


# =================================================================== 3. float/double arithmetic + conversions
def test_float_arith_units():
    f = dcc._f32_bits
    d = dcc._f64_bits
    # add-float/2addr 2.0 + 3.0 = 5.0 (float)
    r, wide = dcc._float_arith(0xc6, f(2.0), f(3.0))
    check("float/add 2+3=5", (not wide) and dcc._f32(r) == 5.0)
    # mul-float 6*7=42 (exact in float32)
    r, _ = dcc._float_arith(0xc8, f(6.0), f(7.0))
    check("float/mul 6*7=42", dcc._f32(r) == 42.0)
    # add-double 2.5 + 0.5 = 3.0
    r, wide = dcc._float_arith(0xcb, d(2.5), d(0.5))
    check("double/add 2.5+0.5=3.0", wide and dcc._f64(r) == 3.0)
    # rem-float 7.5 % 2 = 1.5
    r, _ = dcc._float_arith(0xca, f(7.5), f(2.0))
    check("float/rem 7.5%2=1.5", dcc._f32(r) == 1.5)
    # divide by zero fails closed
    for op in (0xc9, 0xce):
        decl = False
        try:
            dcc._float_arith(op, f(1.0) if op == 0xc9 else d(1.0), f(0.0) if op == 0xc9 else d(0.0))
        except dcc._Decline:
            decl = True
        check("float/div-by-zero declines op=%#x" % op, decl)
    # NaN operand fails closed
    decl = False
    try:
        dcc._float_arith(0xc6, 0x7FC00000, f(1.0))
    except dcc._Decline:
        decl = True
    check("float/nan-operand declines", decl)


def test_narrowing_units():
    check("d2i/3.9->3", dcc._d2i(3.9) == 3)
    check("d2i/-3.9->-3", dcc._d2i(-3.9) == -3)
    check("d2i/nan->0", dcc._d2i(float("nan")) == 0)
    check("d2i/huge->INT_MAX", dcc._d2i(1e30) == 2147483647)
    check("d2i/-huge->INT_MIN", dcc._d2i(-1e30) == -2147483648)
    check("d2l/nan->0", dcc._d2l(float("nan")) == 0)
    check("d2l/huge->LONG_MAX", dcc._d2l(1e40) == 9223372036854775807)
    check("d2l/2.5->2", dcc._d2l(2.5) == 2)


# =================================================================== integration through the full reader
def _solver():
    S = _import("day21_mobile_specimens")
    if S is None:
        return None, None
    try:
        return S._load(str(ROOT / "solvers"), "real")
    except Exception as e:
        print("  (solver load failed: %s)" % e)
        return None, None


def test_integration_specimens():
    S = _import("day21_mobile_specimens")
    C, lab = _solver()
    if S is None or C is None:
        print("SKIP integration (specimens/ledger unavailable)")
        return
    day23 = ROOT / "challenges/day-23/mobile-android-day-23-hook-line-and-signal/mastery/artifact"
    set5 = day23 / "delivery-05" / "hook_line_and_signal_mastery_05.apk"
    spec = ROOT / "challenges/_retro/day25-prep/mobile-android/specimens"
    if not set5.is_file():
        print("SKIP integration (Day-23 set5 APK absent)")
        return
    # x86-64 native leg still resolves PLAIN (no regression)
    true_code, _, _ = S.solve_with(C, set5.read_bytes(), 1)
    check("integ/x86 set5 plain", isinstance(true_code, str) and dcc.ANSWER.search(true_code) and
          not lab.is_unsure(true_code))

    def got(p):
        return S.solve_with(C, p.read_bytes(), 1)[0] if p.is_file() else "<absent>"

    arm64 = spec / "analysis_arm64.apk"
    if arm64.is_file():
        a = got(arm64)
        check("integ/arm64 None->PLAIN true code", a == true_code)
    arm_c = spec / "analysis_armT_container.apk"
    if arm_c.is_file():
        a = got(arm_c)
        check("integ/EM_ARM container fails closed (None)", a is None)
    arm32 = spec / "analysis_arm32_wrongplain.apk"
    if arm32.is_file():
        a = got(arm32)
        check("integ/arm32 never a wrong plain (None/unsure)", a is None or lab.is_unsure(a))


def test_integration_arm32_sweep():
    S = _import("day21_mobile_specimens")
    C, lab = _solver()
    bh = _load_harness()
    if S is None or C is None or bh is None:
        print("SKIP arm32-sweep (harness/specimens unavailable)")
        return
    day23 = ROOT / "challenges/day-23/mobile-android-day-23-hook-line-and-signal/mastery/artifact"
    set5 = day23 / "delivery-05" / "hook_line_and_signal_mastery_05.apk"
    if not set5.is_file():
        print("SKIP arm32-sweep (Day-23 set5 APK absent)")
        return
    import random
    set5b = set5.read_bytes()
    rnd = random.Random(25)
    wrong = 0
    for _ in range(30):
        so = bh.build_so(bh.NATIVE_FN, bh.arm32_random(rnd.randint(6, 14)), dcc.EM_ARM)
        apk = bh.swap_native(set5b, so, "armeabi-v7a")
        a = S.solve_with(C, apk, 1)[0]
        if a is not None and not lab.is_unsure(a):
            wrong += 1
    check("integ/arm32 sweep(30): 0 wrong plain (was 8 on armed tree)", wrong == 0)


def test_integration_float_dead_op():
    S = _import("day21_mobile_specimens")
    D24 = _import("day24_mobile_computed_specimens")
    C, lab = _solver()
    if S is None or D24 is None or C is None:
        print("SKIP float-dead-op (D24/solver unavailable)")
        return

    def emit(a_, d_):
        a_.const_wide(0, 0x0123456789ABCDEF)
        a_.const32(2, 0x40490FDB)          # float bits ~pi
        a_.const32(3, 0x402DF854)          # float bits ~e
        a_.binop2(0xc6, 2, 3)              # add-float/2addr v2,v3 -- DEAD (code comes from v0:v1)
    apk = D24.apk({"classes.dex": D24.value_dex(emit)})
    got = S.solve_with(C, apk, 1)[0]
    ref = D24.ref_code_16hex(0x0123456789ABCDEF)
    check("integ/float dead-op None->PLAIN true code", got == ref)


def test_integration_float_live_conversions():
    """Float/double CONVERSIONS and arithmetic that actually FEED the code must give the exact value."""
    S = _import("day21_mobile_specimens")
    D24 = _import("day24_mobile_computed_specimens")
    C, lab = _solver()
    if S is None or D24 is None or C is None:
        print("SKIP float-live (D24/solver unavailable)")
        return
    f = dcc._f32_bits

    def emit_intdouble(a_, d_):
        a_.const32(2, 0x12345678)          # int
        a_.unop(0x83, 0, 2)                # int-to-double v0,v2
        a_.unop(0x8b, 0, 0)                # double-to-long v0,v0 -> 0x12345678
    _one(S, C, D24, emit_intdouble, 0x12345678, "int->double->long")

    def emit_floatround(a_, d_):
        a_.const32(2, 100)                 # int 100
        a_.unop(0x82, 2, 2)                # int-to-float
        a_.unop(0x87, 2, 2)                # float-to-int -> 100
        a_.unop(0x81, 0, 2)                # int-to-long
    _one(S, C, D24, emit_floatround, 100, "int->float->int->long")

    def emit_mulfloat(a_, d_):
        a_.const32(2, f(6.0))              # float 6.0
        a_.const32(3, f(7.0))              # float 7.0
        a_.binop2(0xc8, 2, 3)              # mul-float -> 42.0
        a_.unop(0x87, 2, 2)                # float-to-int -> 42
        a_.unop(0x81, 0, 2)                # int-to-long
    _one(S, C, D24, emit_mulfloat, 42, "mul-float->int->long")


def _one(S, C, D24, emit, value, name):
    apk = D24.apk({"classes.dex": D24.value_dex(emit)})
    got = S.solve_with(C, apk, 1)[0]
    check("integ/float live %s" % name, got == D24.ref_code_16hex(value))


# =================================================================== helpers: tiny AArch64 assembler
def _asm(words):
    return b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)


def _movz(rd, imm16, hw=0):
    return 0xD2800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | rd


def _movk(rd, imm16, hw=0):
    return 0xF2800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | rd


def _add(rd, rn, rm):
    return 0x8B000000 | (rm << 16) | (rn << 5) | rd


def _sub(rd, rn, rm):
    return 0xCB000000 | (rm << 16) | (rn << 5) | rd


def _eor(rd, rn, rm):
    return 0xCA000000 | (rm << 16) | (rn << 5) | rd


def _orr(rd, rn, rm):
    return 0xAA000000 | (rm << 16) | (rn << 5) | rd


def _and(rd, rn, rm):
    return 0x8A000000 | (rm << 16) | (rn << 5) | rd


def _add_imm(rd, rn, imm12):
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd


def _sub_imm(rd, rn, imm12):
    return 0xD1000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd


def _and_imm(rd, rn, n, immr, imms):
    return 0x92000000 | (n << 22) | ((immr & 0x3F) << 16) | ((imms & 0x3F) << 10) | (rn << 5) | rd


def _lsr(rd, rn, shift):      # UBFM xd,xn,#shift,#63
    return 0xD3400000 | ((shift & 0x3F) << 16) | (63 << 10) | (rn << 5) | rd


def _lsl(rd, rn, shift):      # UBFM xd,xn,#(-shift mod 64),#(63-shift)
    immr = (-shift) % 64
    imms = 63 - shift
    return 0xD3400000 | (immr << 16) | (imms << 10) | (rn << 5) | rd


def _ror(rd, rn, shift):      # EXTR xd,xn,xn,#shift
    return 0x93C00000 | (rn << 16) | ((shift & 0x3F) << 10) | (rn << 5) | rd


def _mul(rd, rn, rm):         # MADD xd,xn,xm,xzr
    return 0x9B007C00 | (rm << 16) | (rn << 5) | rd


def _ret():
    return 0xD65F03C0


def _mini_so(code, e_machine):
    VADDR = 0x1000
    name = b"Java_x_NativeLibrarySecrets_nativeShare"
    dynstr = b"\x00" + name + b"\x00"
    shnames = [b".text", b".dynstr", b".dynsym", b".shstrtab"]
    shstr = b"\x00"
    off_of = {}
    for s in shnames:
        off_of[s] = len(shstr)
        shstr += s + b"\x00"

    def sym(nm, info, value, size, shndx):
        return struct.pack("<IBBHQQ", nm, info, 0, shndx, value, size)
    dynsym = sym(0, 0, 0, 0, 0) + sym(1, (1 << 4) | 2, VADDR, len(code), 1)
    o = 64
    text_off = o
    o += len(code)
    dynstr_off = o
    o += len(dynstr)
    dynsym_off = o
    o += len(dynsym)
    shstr_off = o
    o += len(shstr)
    while o % 8:
        o += 1
    shoff = o

    def shdr(nm, typ, flags, addr, offset, size, link, info, align, entsize):
        return struct.pack("<IIQQQQIIQQ", nm, typ, flags, addr, offset, size, link, info, align, entsize)
    shdrs = shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    shdrs += shdr(off_of[b".text"], 1, 6, VADDR, text_off, len(code), 0, 0, 16, 0)
    shdrs += shdr(off_of[b".dynstr"], 3, 0, 0, dynstr_off, len(dynstr), 0, 0, 1, 0)
    shdrs += shdr(off_of[b".dynsym"], 11, 0, 0, dynsym_off, len(dynsym), 2, 1, 8, 24)
    shdrs += shdr(off_of[b".shstrtab"], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr += struct.pack("<HHIQQQIHHHHHH", 3, e_machine, 1, 0, 0, shoff, 0, 64, 56, 0, 64, 5, 4)
    blob = ehdr + code + dynstr + dynsym + shstr
    blob += b"\x00" * (shoff - len(blob)) + shdrs
    return blob


class _FakeDex:
    """Minimal stand-in so _invoke can reach its native branch for a non-interpreted method."""
    def __init__(self, sym):
        self.code = {}            # method 0 has no body -> native path
        self.mname = {0: ("Lcom/x/NativeLibrarySecrets;", "nativeShare")}

    def meth(self, midx):
        return self.mname[midx]


def _nop_ret_arm64():
    return _asm([_ret()])


# a tiny arm64 "mov x0,x2; ret" so the x86/arm64 branches of the dispatch test actually return a value
def _arm64_nop_ret():
    return _asm([_orr(0, 31, 2), _ret()])


dcc.arm64_nop_ret = _arm64_nop_ret


def _import(modname):
    try:
        return __import__(modname)
    except Exception:
        return None


def _load_harness():
    p = ROOT / "challenges/_retro/day25-prep/mobile-android/build_day25_mobile.py"
    if not p.is_file():
        return None
    try:
        s = importlib.util.spec_from_file_location("bh25", p)
        m = importlib.util.module_from_spec(s)
        s.loader.exec_module(m)
        return m
    except Exception as e:
        print("  (harness load failed: %s)" % e)
        return None


def main():
    test_parse_so_carries_machine()
    test_dispatch_declines_foreign_machine()
    test_arm64_basic_ops()
    test_arm64_full_transform()
    test_arm64_unknown_declines()
    test_float_arith_units()
    test_narrowing_units()
    test_integration_specimens()
    test_integration_arm32_sweep()
    test_integration_float_dead_op()
    test_integration_float_live_conversions()
    print("\n%d passed, %d failed" % (PASS, FAIL))
    if FAIL == 0:
        print("OK: arm32 fails closed, arm64 resolves, float ops modelled; never a wrong plain.")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
