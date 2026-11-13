#!/usr/bin/env python3
"""KB-7: the never-wrong battery for the dex micro-VM's opcode remainder (solvers/mobile-android/dex_float.py and its
hooks in dex_chain_codec.py): exact float/double, the Java math library, static fields with <clinit>, the reflection
remainder, and the refusals.

Every truth here is computed INDEPENDENTLY of the module under test:
  * float/double arithmetic by an exact rational oracle (fractions.Fraction) with its own IEEE-754 round-to-nearest-even
    encoder (binary32 / binary64, subnormals, overflow, signed zeros) and Java's special-value table written out case by
    case (JLS 15.17 and 4.2.4); the encoder itself is checked against the C cast struct uses;
  * conversions and Math functions by the same encoder, integer square roots, and Java's specification text;
  * chains of synthetic Dalvik code built by a DEX assembler in this file (class_defs with a superclass, access flags,
    static and instance fields, encoded static_values, <clinit>, protos with parameter type lists, field_ids).

The one invariant every chain asserts: the reader emits the oracle code PLAIN only under a judge-accepted key, and a
code that needs a new capability is unsure under `mobile.codec/analysis+dex-*` until the judge accepts that exact name;
an adversarial decoy (an unmodelled opcode, a value the device could compute differently) gives None or unsure, never a
wrong plain answer.

Section R (section_review3) holds one check per finding of the adversarial review of 4917e79 (S1-S10): the union of
the producing runs' families (a featureless entry beside a static read gave the judged key), writers the static store's
scan missed (a subclass with interfaces, a store past the walk's bound, digest(buf, off, len), an app toString, a
Field.get alias, reflection on Field.setLong), code outside the VM's view (a native library, a System/Runtime load, a
class loader, a dex under another name), the <clinit> idioms modelled exactly (getSimpleName, Log.d) and their decoys,
getMethod's public filter, the scan's size bound and the class-index cache. Run against 4917e79 the section fails 51
checks, 5 of them WRONG-PLAIN; its controls (and one pin, a <clinit> writing the entry's own object) pass on both.
"Never plain" there is asserted with the judged name and every `+dex-*` name accepted in a private ledger
(private_ledger).

Section R4 (section_review4) holds one check per finding of the adversarial review of 5ffe7f3 (round 2), each built
on the review's own probe: another dex member that reaches a <clinit>'s object (a public getter it calls, an override
in classes2.dex: R1/R1b), a 32-bit or symbol-size-0 JNI_OnLoad beside a chain-written static (R2), a constructor of a
class of another dex member and an app class matched by the end of its name (R3), Class.forName and const-class of a
class only a dex off the app class loader's path defines, and the classes3.dex-after-a-gap case (R4), a method lookup
with no invoke after it (R5), a reflection token a <clinit> stored (R6), the unseen <clinit> of another dex member's
class (Class.forName, a superclass, a static write, a superinterface with default methods) after a static the run
stored, reflection on reflection in another dex member, the walks' charge to the step budget and a timing bound on
thousands of <clinit>s, and the memory a call leaves behind. Run against 5ffe7f3 the section fails 66 checks before it
reaches the perf and memory helpers that tree does not have; its controls pass on both.

Section Z (section_residuals, the dexfloat-residuals fix) holds the two residuals the KB-7 rule paragraph left open and
the shapes its adversarial passes found beside them, each a WRONG plain on af3dbf7 (kb7_rule() puts that tree's rules
back for the "before" column): a Lkotlin/ (Lkotlinx/, Landroidx/, Landroid/support/, android.graphics) class another
dex member defines (a constructor no-op, a superclass constructor, a method taken for Integer.valueOf, an unseen
<clinit>, a superinterface), a boot package's class the delivery defines (its body, its entry, its static),
Class.forName(name, init, loader) with a null or unprovable loader, a class modelled by the end of its name, a framework
constructor's field read as 0, one field under two field references, and the split reading's versions on a copy of Day
26's judged reader (skipped without the saved Day 26 Time Trial).

Run: .venv/bin/python -I -B tests/test_day27_dex_float_mobile.py
"""
import sys as _b240_sys  # noqa: E402
if "pytest" in _b240_sys.modules and __name__ != "__main__":
    # B-240 carry: a check()-style script. Its checks never fail a pytest run and its module-level setup changes
    # os.environ for the whole worker, so pytest does not collect it; tests/test_carry_checklist.py runs it as a
    # script (exit code and FAIL lines) and reports its saved-data sections as not run.
    import pytest
    pytest.skip("script-style test: run as a script by tests/test_carry_checklist.py", allow_module_level=True)
import contextlib
import math
import os
import random
import struct
import sys
import tempfile
from unittest import mock
import time
import weakref
from fractions import Fraction
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="d27dexfloat-")     # a private, empty ledger
os.environ["CTF_TESTING"] = "1"
os.environ["CTF_LEDGER_MASK"] = "mobile.codec/analysis"                   # the seed's judged key, masked
sys.path.insert(0, str(REPO / "solvers/mobile-android"))
sys.path.insert(0, str(REPO / "solvers/common"))
sys.path.insert(0, str(REPO / "tests"))

import dex_chain_codec as dcc                       # noqa: E402
import dex_float as DF                              # noqa: E402
import labels                                       # noqa: E402
import day24_mobile_computed_specimens as S         # noqa: E402

M32, M64 = 0xFFFFFFFF, (1 << 64) - 1
Q = {"answer_id": "answer", "answer_format": "ANS-XXXXXXXXXXXXXXXX"}
PASSED, FAILED, WRONG = [], [], []
T0 = time.time()


def check(label, ok, extra=None):
    (PASSED if ok else FAILED).append(label)
    if not ok:
        print("FAIL " + label + ("" if extra is None else "  <%r>" % (extra,)))


def s32(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def s64(x):
    x &= M64
    return x - (1 << 64) if x & (1 << 63) else x


# ============================================================================ the independent IEEE-754 oracle
FMT = {"f": (23, 8), "d": (52, 11)}


def enc(sign, fr, t):
    """Round a non-negative Fraction to IEEE binary32/64 (round to nearest, ties to even), with `sign`; overflow to
    infinity, underflow to signed zero / subnormal. Returns the bit pattern."""
    mant, eb = FMT[t]
    total = 1 + eb + mant
    sbit = (1 << (total - 1)) if sign else 0
    if fr == 0:
        return sbit
    bias = (1 << (eb - 1)) - 1
    emin = 1 - bias
    e = fr.numerator.bit_length() - fr.denominator.bit_length()
    if Fraction(2) ** e > fr:
        e -= 1
    if Fraction(2) ** (e + 1) <= fr:
        e += 1
    e = max(e, emin)
    scaled = fr * Fraction(2) ** (mant - e)
    n = scaled.numerator // scaled.denominator
    rem = scaled - n
    if rem > Fraction(1, 2) or (rem == Fraction(1, 2) and n & 1):
        n += 1
    if n == 1 << (mant + 1):
        n >>= 1
        e += 1
    if e > bias:
        return sbit | (((1 << eb) - 1) << mant)                  # infinity
    if n < (1 << mant):
        return sbit | n                                           # subnormal (or zero)
    return sbit | ((e + bias) << mant) | (n - (1 << mant))


def dec(bits, t):
    """('nan',) | ('inf', sign) | ('zero', sign) | ('fin', sign, Fraction magnitude)."""
    mant, eb = FMT[t]
    total = 1 + eb + mant
    bits &= (1 << total) - 1
    sign = bits >> (total - 1)
    ex = (bits >> mant) & ((1 << eb) - 1)
    m = bits & ((1 << mant) - 1)
    bias = (1 << (eb - 1)) - 1
    if ex == (1 << eb) - 1:
        return ("nan",) if m else ("inf", sign)
    if ex == 0:
        if m == 0:
            return ("zero", sign)
        return ("fin", sign, Fraction(m) * Fraction(2) ** (1 - bias - mant))
    return ("fin", sign, Fraction(m + (1 << mant)) * Fraction(2) ** (ex - bias - mant))


def val(v):
    """A decoded value as a signed Fraction (finite / zero only)."""
    if v[0] == "zero":
        return Fraction(0)
    return -v[2] if v[1] else v[2]


def from_frac(fr, t, zero_sign=0):
    if fr == 0:
        return enc(zero_sign, Fraction(0), t)
    return enc(1 if fr < 0 else 0, abs(fr), t)


NAN = "NAN"
INF = {"f": 0x7F800000, "d": 0x7FF0000000000000}
SGN = {"f": 0x80000000, "d": 0x8000000000000000}


def java_op(kind, t, xb, yb):
    """Java's float/double binop by the specification's case table; NAN for any NaN result."""
    x, y = dec(xb, t), dec(yb, t)
    if x[0] == "nan" or y[0] == "nan":
        return NAN
    inf = INF[t]
    sg = SGN[t]
    if kind == "sub":
        yb2 = yb ^ sg
        return java_op("add", t, xb, yb2)
    if kind == "add":
        if x[0] == "inf" and y[0] == "inf":
            return NAN if x[1] != y[1] else (inf | (sg if x[1] else 0))
        if x[0] == "inf":
            return inf | (sg if x[1] else 0)
        if y[0] == "inf":
            return inf | (sg if y[1] else 0)
        if x[0] == "zero" and y[0] == "zero":
            return sg if (x[1] and y[1]) else 0
        r = val(x) + val(y)
        return from_frac(r, t, 0)                    # an exact zero sum of non-zeros is +0 (round to nearest)
    xs = x[1] if x[0] != "nan" else 0
    ys = y[1] if y[0] != "nan" else 0
    neg = xs ^ ys
    if kind == "mul":
        if (x[0] == "inf" and y[0] == "zero") or (x[0] == "zero" and y[0] == "inf"):
            return NAN
        if x[0] == "inf" or y[0] == "inf":
            return inf | (sg if neg else 0)
        if x[0] == "zero" or y[0] == "zero":
            return sg if neg else 0
        b = from_frac(val(x) * val(y), t)
        return b if (b & ~sg) else (sg if neg else 0)    # underflow keeps the sign
    if kind == "div":
        if x[0] == "inf" and y[0] == "inf":
            return NAN
        if x[0] == "zero" and y[0] == "zero":
            return NAN
        if x[0] == "inf":
            return inf | (sg if neg else 0)
        if y[0] == "inf" or x[0] == "zero":
            return sg if neg else 0
        if y[0] == "zero":
            return inf | (sg if neg else 0)
        b = from_frac(val(x) / val(y), t)
        return b if (b & ~sg) else (sg if neg else 0)
    if kind == "rem":
        if x[0] == "inf" or y[0] == "zero":
            return NAN
        if y[0] == "inf" or x[0] == "zero":
            return xb & (M32 if t == "f" else M64)
        a, b = val(x), val(y)
        q = a / b
        qi = q.numerator // q.denominator if q >= 0 else -((-q.numerator) // q.denominator)
        r = a - qi * b
        if r == 0:
            return sg if x[1] else 0
        return from_frac(r, t)
    raise ValueError(kind)


def is_nan(bits, t):
    return dec(bits, t)[0] == "nan"


# ---- the encoder is checked against the C cast (struct) on values a double holds exactly
def oracle_selfcheck():
    rng = random.Random(27)
    ok = True
    for _ in range(3000):
        b = rng.getrandbits(64)
        v = dec(b, "d")
        if v[0] != "fin":
            continue
        d = struct.unpack("<d", struct.pack("<Q", b))[0]
        ok &= enc(v[1], v[2], "d") == b
        try:
            want = struct.unpack("<I", struct.pack("<f", d))[0]
        except OverflowError:
            want = 0xFF800000 if d < 0 else 0x7F800000
        ok &= enc(v[1], v[2], "f") == want
    check("oracle: the Fraction encoder equals the C cast on 3000 doubles (binary64 and binary32)", ok)


# ============================================================================ A. float/double opcode units
EDGE_F = [0x00000000, 0x80000000, 0x00000001, 0x80000001, 0x007FFFFF, 0x00800000, 0x3F800000, 0xBF800000,
          0x7F7FFFFF, 0xFF7FFFFF, 0x3DCCCCCD, 0x40490FDB, 0x4B800001, 0x7F800000, 0xFF800000, 0x7FC00000,
          0x7F800001, 0x3F000000, 0x40000000, 0xC0400000, 0x33800000, 0x34000000]
EDGE_D = [0, SGN["d"], 1, 0x8000000000000001, 0x000FFFFFFFFFFFFF, 0x0010000000000000, 0x3FF0000000000000,
          0xBFF0000000000000, 0x7FEFFFFFFFFFFFFF, 0xFFEFFFFFFFFFFFFF, 0x3FB999999999999A, 0x400921FB54442D18,
          0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000000, 0x7FF0000000000001, 0x3FE0000000000000,
          0x4330000000000001, 0x3CA0000000000000]


def unit_arith():
    rng = random.Random(7)
    ops = {"add": (0xa6, 0xab), "sub": (0xa7, 0xac), "mul": (0xa8, 0xad), "div": (0xa9, 0xae), "rem": (0xaa, 0xaf)}
    for t, edges, bits in (("f", EDGE_F, 32), ("d", EDGE_D, 64)):
        pairs = [(a, b) for a in edges for b in edges]
        pairs += [(rng.getrandbits(bits), rng.getrandbits(bits)) for _ in range(1500)]
        # values of nearby magnitude, where add/sub cancel and fmod has many quotient bits
        for _ in range(500):
            base = rng.getrandbits(bits)
            pairs.append((base, (base ^ rng.getrandbits(6)) & ((1 << bits) - 1)))
        for kind, (opf, opd) in ops.items():
            op = opf if t == "f" else opd
            bad = []
            for a, b in pairs:
                want = java_op(kind, t, a, b)
                got, wide, _special = DF.arith(op, a, b)
                for op2 in (op, op + 0x20):            # the /2addr form is the same operation
                    got2 = DF.arith(op2, a, b)[0]
                    if got2 != got:
                        bad.append(("2addr", hex(a), hex(b)))
                if want == NAN:
                    if not is_nan(got, t):
                        bad.append((hex(a), hex(b), hex(got), "want NaN"))
                elif got != want:
                    bad.append((hex(a), hex(b), hex(got), hex(want)))
                if wide != (t == "d"):
                    bad.append(("wide", hex(a), hex(b)))
            check("A %s-%s: %d pairs equal the exact Java oracle (incl. NaN, inf, +-0, subnormals, /0)"
                  % (kind, "float" if t == "f" else "double", len(pairs)), not bad, bad[:3])
    # spot facts written out from the specification, independent of the oracle above
    f = lambda x: struct.unpack("<I", struct.pack("<f", x))[0]   # noqa: E731
    check("A 1.0f/0.0f is +inf", DF.arith(0xa9, f(1.0), 0)[0] == 0x7F800000)
    check("A 1.0f/-0.0f is -inf", DF.arith(0xa9, f(1.0), 0x80000000)[0] == 0xFF800000)
    check("A 0.0f/0.0f is NaN", DF.is_nan32(DF.arith(0xa9, 0, 0)[0]))
    check("A -5.5f % 2f is -1.5f (sign of the dividend)", DF.arith(0xaa, f(-5.5), f(2.0))[0] == f(-1.5))
    check("A 5.5f % -2f is 1.5f", DF.arith(0xaa, f(5.5), f(-2.0))[0] == f(1.5))
    check("A -0.0f % 3f is -0.0f", DF.arith(0xaa, 0x80000000, f(3.0))[0] == 0x80000000)
    check("A 7f % +inf is 7f", DF.arith(0xaa, f(7.0), 0x7F800000)[0] == f(7.0))
    check("A FLT_MAX*2 overflows to +inf (float32 rounding after the op)", DF.arith(0xa8, 0x7F7FFFFF, f(2.0))[0]
          == 0x7F800000)
    check("A 16777216f + 1f stays 16777216f (rounded to float32 after EVERY op)",
          DF.arith(0xa6, f(16777216.0), f(1.0))[0] == f(16777216.0))
    check("A 0.1f+0.2f is the float32 sum 0x3E99999A, not the double one", DF.arith(0xa6, f(0.1), f(0.2))[0] == 0x3E99999A)
    check("A special flag set on a /0 and on NaN, not on finite ops",
          DF.arith(0xa9, f(1.0), 0)[2] and DF.arith(0xa6, 0x7FC00000, 0)[2] and not DF.arith(0xa6, f(1.0), f(2.0))[2])


def unit_conversions():
    rng = random.Random(11)
    # long-to-float: ONE rounding from the exact integer
    vals = [0, 1, -1, (1 << 24) + 1, (1 << 53) + 1, (1 << 62) + (1 << 38) + 1, -((1 << 62) + (1 << 38) + 1),
            (1 << 63) - 1, -(1 << 63), (1 << 54) + (1 << 30) + 1, 0x7FFFFFBFFFFFFFFF]
    vals += [s64(rng.getrandbits(64)) for _ in range(3000)]
    vals += [s64(rng.getrandbits(rng.randint(25, 64))) for _ in range(2000)]
    bad = [v for v in vals if DF.long_to_f32_bits(v) != from_frac(Fraction(v), "f")]
    check("A long-to-float: %d longs equal the exact oracle" % len(vals), not bad, bad[:3])
    v = (1 << 62) + (1 << 38) + 1
    naive = struct.unpack("<I", struct.pack("<f", float(v)))[0]
    check("A long-to-float: the double-rounding case differs from (float)(double)v, and the module is exact",
          naive != from_frac(Fraction(v), "f") and DF.long_to_f32_bits(v) == from_frac(Fraction(v), "f"))
    # float/double -> int/long: saturation, NaN -> 0, truncation toward zero (Java 5.1.3)
    cases = [(float("nan"), 0, 0), (float("inf"), 2147483647, (1 << 63) - 1), (-float("inf"), -(1 << 31), -(1 << 63)),
             (3.99, 3, 3), (-3.99, -3, -3), (2147483648.0, 2147483647, 2147483648), (-2147483649.0, -(1 << 31),
             -2147483649), (9.3e18, 2147483647, (1 << 63) - 1), (-0.0, 0, 0)]
    check("A f2i/d2i/f2l/d2l: Java's saturation, NaN -> 0, truncation",
          all(DF.d2i(x) == i and DF.d2l(x) == l for x, i, l in cases))
    # double -> float rounding
    dd = [rng.getrandbits(64) for _ in range(2000)] + EDGE_D
    bad = []
    for b in dd:
        v = dec(b, "d")
        got = DF.f32_bits(struct.unpack("<d", struct.pack("<Q", b))[0])
        if v[0] == "nan":
            ok = DF.is_nan32(got)
        elif v[0] == "inf":
            ok = got == (0xFF800000 if v[1] else 0x7F800000)
        elif v[0] == "zero":
            ok = got == (0x80000000 if v[1] else 0)
        else:
            ok = got == enc(v[1], v[2], "f")
        if not ok:
            bad.append(hex(b))
    check("A double-to-float: %d doubles round to nearest even exactly (overflow to inf, subnormals)" % len(dd),
          not bad, bad[:3])


def unit_math():
    f = lambda x: struct.unpack("<I", struct.pack("<f", x))[0]   # noqa: E731
    d = lambda x: struct.unpack("<Q", struct.pack("<d", x))[0]   # noqa: E731
    # floor / ceil / rint: the Java specification's signed-zero rules
    check("M floor(-0.5) = -1.0, floor(0.5) = 0.0, floor(-0.0) = -0.0",
          d(DF.j_floor(-0.5)) == d(-1.0) and d(DF.j_floor(0.5)) == 0 and d(DF.j_floor(-0.0)) == SGN["d"])
    check("M ceil(-0.5) = -0.0 (sign kept), ceil(0.2) = 1.0",
          d(DF.j_ceil(-0.5)) == SGN["d"] and DF.j_ceil(0.2) == 1.0)
    check("M rint(2.5) = 2.0, rint(3.5) = 4.0, rint(-0.5) = -0.0, rint(-2.5) = -2.0",
          DF.j_rint(2.5) == 2.0 and DF.j_rint(3.5) == 4.0 and d(DF.j_rint(-0.5)) == SGN["d"] and DF.j_rint(-2.5) == -2.0)
    # sqrt correctly rounded: an integer-square-root oracle
    rng = random.Random(5)
    bad = []
    for _ in range(1500):
        b = rng.getrandbits(63)                       # non-negative doubles
        v = dec(b, "d")
        if v[0] != "fin":
            continue
        x = v[2]
        k = 1100
        n = x * Fraction(2) ** (2 * k)
        s = math.isqrt(n.numerator // n.denominator)
        want = enc(0, Fraction(s, 1 << k), "d")
        got = d(DF.j_sqrt(struct.unpack("<d", struct.pack("<Q", b))[0]))
        if got != want:
            bad.append(hex(b))
    check("M sqrt: 1500 doubles correctly rounded (integer square root oracle)", not bad, bad[:3])
    check("M sqrt(-1) is NaN, sqrt(-0.0) is -0.0, sqrt(+inf) is +inf",
          math.isnan(DF.j_sqrt(-1.0)) and d(DF.j_sqrt(-0.0)) == SGN["d"] and DF.j_sqrt(math.inf) == math.inf)
    # round: Java 8 and Harmony must agree, else None (the VM declines)
    check("M round(2.5) = 3, round(-2.5) = -2, round(-0.5) = 0",
          DF.j_round(2.5, False) == 3 and DF.j_round(-2.5, False) == -2 and DF.j_round(-0.5, False) == 0)
    check("M round(0.49999999999999994): Java 8 says 0, Harmony 1 -> None",
          DF.j_round(0.49999999999999994, False) is None)
    check("M round(2^52 + 1): Java 8 exact, Harmony off by one -> None", DF.j_round(float(2 ** 52 + 1), False) is None)
    check("M round(0.49999997f): Java 8 says 0, Harmony 1 -> None",
          DF.j_round(struct.unpack("<f", struct.pack("<I", 0x3EFFFFFF))[0], True) is None)
    check("M round(NaN) = 0, round(1e20) = Long.MAX, round(-inf f) = Integer.MIN",
          DF.j_round(math.nan, False) == 0 and DF.j_round(1e20, False) == (1 << 63) - 1
          and DF.j_round(-math.inf, True) == -(1 << 31))
    # min/max/compare: -0.0 below +0.0, NaN wins / NaN above everything
    check("M min(0.0, -0.0) = -0.0 and max(-0.0, 0.0) = 0.0",
          d(DF.j_min(0.0, -0.0)) == SGN["d"] and d(DF.j_max(-0.0, 0.0)) == 0)
    check("M min(1, NaN) and max(NaN, 1) are NaN", math.isnan(DF.j_min(1.0, math.nan)) and math.isnan(DF.j_max(math.nan, 1.0)))
    cmp = lambda a, b: DF.j_compare(a, b, s32(DF._canon32(f(a))), s32(DF._canon32(f(b))))   # noqa: E731
    check("M Float.compare: (-0,0)=-1, (0,-0)=1, (NaN,inf)=1, (NaN,NaN)=0, (1,2)=-1",
          cmp(-0.0, 0.0) == -1 and cmp(0.0, -0.0) == 1 and cmp(math.nan, math.inf) == 1 and cmp(math.nan, math.nan) == 0
          and cmp(1.0, 2.0) == -1)


# ============================================================================ the DEX assembler
ACC_PUBLIC, ACC_PRIVATE, ACC_STATIC, ACC_FINAL, ACC_NATIVE, ACC_CONSTRUCTOR = 0x1, 0x2, 0x8, 0x10, 0x100, 0x10000
PRIM = set("VZBSCIJFD")


def tdesc(c):
    return c if c in PRIM else "Ljava/lang/Object;"


class ClassSpec:
    def __init__(self, desc, acc, sup):
        self.desc, self.acc, self.sup = desc, acc, sup
        self.sfields, self.ifields, self.direct, self.virtual = [], [], [], []
        self.svals = {}             # fidx -> encoded value bytes
        self.ifaces = []            # interface type descriptors (the class_def's interfaces type_list)
        self.annots = []            # class annotation type descriptors (SYSTEM visibility, no elements)


class DexB:
    """A DEX writer with everything the VM reads: strings, types, protos (shorty + return + parameter type list),
    field_ids, method_ids, class_defs (class, access, superclass, class_data, static_values), code items."""

    def __init__(self):
        self.strings, self.types, self.protos, self.fields, self.methods, self.classes = [], [], [], [], [], []

    def s(self, t):
        if t not in self.strings:
            self.strings.append(t)
        return self.strings.index(t)

    def t(self, d):
        self.s(d)
        if d not in self.types:
            self.types.append(d)
        return self.types.index(d)

    def proto(self, shorty, ret=None, params=None):
        ret = ret or tdesc(shorty[0])
        params = tuple(params) if params is not None else tuple(tdesc(c) for c in shorty[1:])
        self.s(shorty)
        self.t(ret)
        for p in params:
            self.t(p)
        k = (shorty, ret, params)
        if k not in self.protos:
            self.protos.append(k)
        return self.protos.index(k)

    def m(self, cls, name, shorty, ret=None, params=None):
        self.t(cls)
        self.s(name)
        k = (cls, name, self.proto(shorty, ret, params))
        if k not in self.methods:
            self.methods.append(k)
        return self.methods.index(k)

    def f(self, cls, ftype, name):
        self.t(cls)
        self.t(ftype)
        self.s(name)
        k = (cls, ftype, name)
        if k not in self.fields:
            self.fields.append(k)
        return self.fields.index(k)

    def cls(self, desc, acc=ACC_PUBLIC, sup="Ljava/lang/Object;"):
        self.t(desc)
        if sup:
            self.t(sup)
        c = ClassSpec(desc, acc, sup)
        self.classes.append(c)
        return c

    @staticmethod
    def uleb(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | 0x80 if n else b)
            if not n:
                return bytes(out)

    def build(self):
        H = 0x70
        o = H
        offs = {}
        for name, n, w in (("str", len(self.strings), 4), ("type", len(self.types), 4), ("proto", len(self.protos), 12),
                           ("field", len(self.fields), 8), ("meth", len(self.methods), 8),
                           ("cls", len(self.classes), 32)):
            offs[name] = o
            o += n * w
        data = bytearray()
        base = o

        def place(b, align=1):
            nonlocal data
            while (base + len(data)) % align:
                data.append(0)
            at = base + len(data)
            data += b
            return at

        plist = []
        for shorty, ret, params in self.protos:
            if params:
                b = struct.pack("<I", len(params)) + b"".join(struct.pack("<H", self.types.index(p)) for p in params)
                plist.append(place(b, 4))
            else:
                plist.append(0)
        ilist = []
        for c in self.classes:
            if c.ifaces:
                b = struct.pack("<I", len(c.ifaces)) + b"".join(struct.pack("<H", self.types.index(t)) for t in c.ifaces)
                ilist.append(place(b, 4))
            else:
                ilist.append(0)
        alist = []
        for c in self.classes:
            if c.annots:
                items = [place(bytes([2]) + self.uleb(self.types.index(t)) + self.uleb(0)) for t in c.annots]
                aset = place(struct.pack("<I", len(items)) + b"".join(struct.pack("<I", x) for x in items), 4)
                alist.append(place(struct.pack("<IIII", aset, 0, 0, 0), 4))
            else:
                alist.append(0)
        code_off = {}
        for c in self.classes:
            for lst in (c.direct, c.virtual):
                for midx, acc, code in lst:
                    if code is None:
                        continue
                    units, regs, ins, outs = code
                    b = struct.pack("<HHHHII", regs, ins, outs, 0, 0, len(units)) + struct.pack("<%dH" % len(units),
                                                                                              *units)
                    code_off[midx] = place(b, 4)
        cdata, sv = [], []
        for c in self.classes:
            b = bytearray()
            sf = sorted(c.sfields)
            inf = sorted(c.ifields)
            dm = sorted(c.direct)
            vm = sorted(c.virtual)
            b += self.uleb(len(sf)) + self.uleb(len(inf)) + self.uleb(len(dm)) + self.uleb(len(vm))
            for lst in (sf, inf):
                prev = 0
                for fidx, acc in lst:
                    b += self.uleb(fidx - prev) + self.uleb(acc)
                    prev = fidx
            for lst in (dm, vm):
                prev = 0
                for midx, acc, code in lst:
                    b += self.uleb(midx - prev) + self.uleb(acc) + self.uleb(code_off.get(midx, 0))
                    prev = midx
            cdata.append(place(bytes(b)))
            if c.svals:
                last = max(i for i, (fidx, _a) in enumerate(sf) if fidx in c.svals)
                arr = bytearray(self.uleb(last + 1))
                for fidx, _a in sf[:last + 1]:
                    arr += c.svals.get(fidx, EV.default(self.fields[fidx][1]))
                sv.append(place(bytes(arr)))
            else:
                sv.append(0)
        sdata = [place(self.uleb(len(t)) + t.encode() + b"\x00") for t in self.strings]
        buf = bytearray(base) + data
        buf[0:8] = b"dex\n035\x00"
        struct.pack_into("<I", buf, 32, len(buf))
        struct.pack_into("<I", buf, 36, H)
        struct.pack_into("<I", buf, 40, 0x12345678)
        for name, at in (("str", 56), ("type", 64), ("proto", 72), ("field", 80), ("meth", 88), ("cls", 96)):
            n = {"str": self.strings, "type": self.types, "proto": self.protos, "field": self.fields,
                 "meth": self.methods, "cls": self.classes}[name]
            struct.pack_into("<II", buf, at, len(n), offs[name] if n else 0)
        for i, so in enumerate(sdata):
            struct.pack_into("<I", buf, offs["str"] + 4 * i, so)
        for i, td in enumerate(self.types):
            struct.pack_into("<I", buf, offs["type"] + 4 * i, self.strings.index(td))
        for i, (shorty, ret, params) in enumerate(self.protos):
            struct.pack_into("<III", buf, offs["proto"] + 12 * i, self.strings.index(shorty), self.types.index(ret),
                             plist[i])
        for i, (cl, ft, nm) in enumerate(self.fields):
            struct.pack_into("<HHI", buf, offs["field"] + 8 * i, self.types.index(cl), self.types.index(ft),
                             self.strings.index(nm))
        for i, (cl, nm, p) in enumerate(self.methods):
            struct.pack_into("<HHI", buf, offs["meth"] + 8 * i, self.types.index(cl), p, self.strings.index(nm))
        for i, c in enumerate(self.classes):
            sup = self.types.index(c.sup) if c.sup else 0xFFFFFFFF
            struct.pack_into("<IIIIIIII", buf, offs["cls"] + 32 * i, self.types.index(c.desc), c.acc, sup, ilist[i],
                             0xFFFFFFFF, alist[i], cdata[i], sv[i])
        return bytes(buf)


class EV:
    """Encoded values for static_values (the dex format's encoded_value)."""

    @staticmethod
    def int(v):
        return bytes([(3 << 5) | 0x04]) + struct.pack("<i", s32(v))

    @staticmethod
    def long(v):
        return bytes([(7 << 5) | 0x06]) + struct.pack("<q", s64(v))

    @staticmethod
    def float_bits(b, size=4):
        raw = struct.pack("<I", b)[4 - size:]              # the high-order bytes (zero-extended to the right)
        return bytes([((size - 1) << 5) | 0x10]) + raw

    @staticmethod
    def double_bits(b, size=8):
        raw = struct.pack("<Q", b)[8 - size:]
        return bytes([((size - 1) << 5) | 0x11]) + raw

    @staticmethod
    def string(d, text):
        return bytes([(3 << 5) | 0x17]) + struct.pack("<I", d.s(text))

    @staticmethod
    def boolean(v):
        return bytes([((1 if v else 0) << 5) | 0x1F])

    @staticmethod
    def byte(v):
        return bytes([0x00, v & 0xFF])

    @staticmethod
    def char(v):
        return bytes([(1 << 5) | 0x03]) + struct.pack("<H", v)

    @staticmethod
    def short(v):
        return bytes([(1 << 5) | 0x02]) + struct.pack("<h", v)

    @staticmethod
    def array_of_ints(vals):
        b = bytes([0x1C]) + DexB.uleb(len(vals))
        for v in vals:
            b += EV.int(v)
        return b

    @staticmethod
    def default(ftype):
        if ftype[0] in "L[":
            return bytes([0x1E])
        if ftype in ("J",):
            return EV.long(0)
        if ftype == "D":
            return EV.double_bits(0)
        if ftype == "F":
            return EV.float_bits(0)
        if ftype == "Z":
            return EV.boolean(False)
        return EV.int(0)


# ---- assembler helpers on top of S.Asm
def sget(a, op, reg, fidx):
    a.u += [op | (reg << 8), fidx]


def sput(a, op, reg, fidx):
    a.u += [op | (reg << 8), fidx]


def ret(a, op, reg):
    a.u.append(op | (reg << 8))


def raw(a, *units):
    a.u += list(units)


LONG, STRING, INTEGER, FLOATC, DOUBLEC, MATH = ("Ljava/lang/Long;", "Ljava/lang/String;", "Ljava/lang/Integer;",
                                               "Ljava/lang/Float;", "Ljava/lang/Double;", "Ljava/lang/Math;")
CLASS, METHOD, FIELD = "Ljava/lang/Class;", "Ljava/lang/reflect/Method;", "Ljava/lang/reflect/Field;"
C = "Lcom/huntress/C;"


def chain(body, regs=24):
    """A dex whose entry C.run() runs body(a, d) (which leaves a long in v0:v1, and may add classes), then assembles
    String.format("ANS-%016X", Long.valueOf(v0))."""
    d = DexB()
    a = S.Asm()
    cc = d.cls(C)
    extra = body(a, d) or {}
    S.emit_tail_format(a, d, 0, "ANS-%016X")
    run = d.m(C, "run", "L", ret=STRING)
    cc.direct.append((run, ACC_PUBLIC | ACC_STATIC, (a.finish(), regs, 0, 5)))
    for midx, acc, code in extra.get("c_direct", []):
        cc.direct.append((midx, acc, code))
    for midx, acc, code in extra.get("c_virtual", []):
        cc.virtual.append((midx, acc, code))
    for fidx, acc, ev in extra.get("c_sfields", []):
        cc.sfields.append((fidx, acc))
        if ev is not None:
            cc.svals[fidx] = ev
    return d.build()


def method(units, regs, ins, outs=4):
    return (units, regs, ins, outs)


def code(v):
    return "ANS-%016X" % (v & M64)


def members(dex, so=None):
    m = {"classes.dex": dex}
    if so:
        m["lib/x86_64/libh.so"] = so
    return S.member_map(S.apk(m))


def plain_of(ans):
    if ans is None or labels.is_unsure(ans):
        return None
    return ans if isinstance(ans, str) and dcc.ANSWER.fullmatch(ans) else None


def unsure_of(ans):
    if not labels.is_unsure(ans):
        return None, None
    p = labels.parse(ans)
    return p.key, [v for _n, v in p.options]


def expect(name, dex, want, key=None, so=None):
    """The VM recovers exactly `want` with no decline; answer() is unsure under `key` (the judged key masked) and never
    a wrong plain."""
    codes, dcl = dcc.codes_in_dex_ex(dex, [so] if so else ())
    check(name + ": the VM computes the oracle code", codes == [want] and dcl == 0, (codes, dcl, want))
    ans = dcc.answer(Q, members(dex, so))
    pc = plain_of(ans)
    if pc is not None and pc != want:
        WRONG.append((name, pc, want))
    k, opts = unsure_of(ans)
    if key is not None:
        check(name + ": unsure under %s with the oracle" % key, k == key and opts == [want], (k, opts, ans))
    return ans


def decline_reasons(dex):
    """The decline message of every ANS entry of the dex, run on its own (an empty string for one that returned)."""
    d = dcc.Dex(dex)
    idx = {i for i in range(d.str_size) if d.string(i) in ("ANS-", "ANS-%016X")}
    out = []
    for e in dcc._entry_midxs(d, idx):
        try:
            dcc.VM(d).run(e, [None] * d.code[e][1])
            out.append("")
        except Exception as ex:
            out.append(str(ex))
    return out


def expect_none(name, dex, so=None, reason=None):
    """The VM gives no code (a decline); answer() is None. A code here would be the device-disagreeing value. With
    `reason`, the decline must be that one (a fixture that declines for an incidental reason proves nothing)."""
    codes, dcl = dcc.codes_in_dex_ex(dex, [so] if so else ())
    ans = dcc.answer(Q, members(dex, so))
    pc = plain_of(ans)
    if pc is not None:
        WRONG.append((name, pc, None))
    check(name + ": declines (no code)", codes == [] and ans is None, (codes, dcl, ans))
    if reason is not None:
        why = decline_reasons(dex)
        check(name + ": for the intended reason (%s)" % reason, bool(why) and all(reason in w for w in why), why)


KF = "mobile.codec/analysis+dex-float"
KS = "mobile.codec/analysis+dex-static"
KR = "mobile.codec/analysis+dex-reflect"
KRS = "mobile.codec/analysis+dex-reflect+dex-static"
K0 = "mobile.codec/analysis"

# float bit helpers for building chains
fb = lambda x: struct.unpack("<I", struct.pack("<f", x))[0]   # noqa: E731
db = lambda x: struct.unpack("<Q", struct.pack("<d", x))[0]   # noqa: E731


# ============================================================================ C. float chains through the VM
def to_long_from_float_bits(a, d, reg):
    """v0:v1 = (long) Float.floatToIntBits(v[reg]) -- the canonical bits as an int, sign-extended."""
    m = d.m(FLOATC, "floatToIntBits", "IF")
    a.invoke(0x71, m, [reg])
    a.move_result(2)
    a.unop(0x81, 0, 2)


def chain_float():
    # (((6.5f * 3.25f) + 0.1f) / 0.0f) -> +inf ; f2l(+inf) = Long.MAX ; plus (f2i(7.9f % -2f)) and a NaN compare
    def body(a, d):
        a.const32(2, fb(6.5))
        a.const32(3, fb(3.25))
        a.binop(0xa8, 4, 2, 3)              # mul-float v4 = v2*v3
        a.const32(5, fb(0.1))
        a.binop2(0xc6, 4, 5)                # add-float/2addr
        a.const4(6, 0)
        a.binop2(0xc9, 4, 6)                # div-float/2addr by +0.0 -> +inf
        a.unop(0x88, 0, 4)                  # float-to-long -> Long.MAX
        a.const32(7, fb(7.9))
        a.const32(8, fb(-2.0))
        a.binop(0xaa, 7, 7, 8)              # rem-float -> 1.9f
        a.const32(8, fb(10.0))
        a.binop2(0xc8, 7, 8)                # *10 -> 19.0f (float32 rounding)
        a.unop(0x87, 9, 7)                  # float-to-int -> 18 or 19 (float32 says which)
        a.unop(0x81, 10, 9)
        a.binop2(0xc2, 0, 10)               # xor-long/2addr v0 ^= v10
    rem = java_op("rem", "f", fb(7.9), fb(-2.0))
    prod = java_op("mul", "f", rem, fb(10.0))
    iv = int(val(dec(prod, "f")))
    return chain(body), ((1 << 63) - 1) ^ (iv & M64)


def chain_double():
    def body(a, d):
        a.const_wide(2, db(1e300))
        a.const_wide(4, db(1e10))
        a.binop(0xad, 6, 2, 4)              # mul-double -> +inf
        a.const_wide(8, db(-5.5))
        a.const_wide(10, db(2.0))
        a.binop(0xaf, 8, 8, 10)             # rem-double -> -1.5
        a.unop(0x80, 8, 8)                  # neg-double -> 1.5
        a.binop2(0xcb, 6, 8)                # inf + 1.5 = inf
        a.unop(0x8b, 0, 6)                  # double-to-long -> Long.MAX
        a.unop(0x8b, 12, 8)                 # (long)1.5 = 1
        a.binop2(0xbb, 0, 12)               # add-long/2addr -> Long.MIN (wraps)
    return chain(body), (((1 << 63) - 1) + 1) & M64


def chain_nan_bits():
    # 0.0f/0.0f is NaN; floatToIntBits gives Java's canonical 0x7fc00000 whatever the CPU's payload
    def body(a, d):
        a.const4(2, 0)
        a.const4(3, 0)
        a.binop(0xa9, 4, 2, 3)
        to_long_from_float_bits(a, d, 4)
    return chain(body), 0x7FC00000


def chain_nan_raw():
    def body(a, d):
        a.const4(2, 0)
        a.const4(3, 0)
        a.binop(0xa9, 4, 2, 3)
        m = d.m(FLOATC, "floatToRawIntBits", "IF")
        a.invoke(0x71, m, [4])
        a.move_result(2)
        a.unop(0x81, 0, 2)
    return chain(body)


def chain_cmp_nan():
    # cmpl-float NaN,1 = -1 ; cmpg-float NaN,1 = +1 ; cmpg-double -0.0, 0.0 = 0 -> 0x00000000FFFFFFFF ^ ...
    def body(a, d):
        a.const4(2, 0)
        a.binop(0xa9, 3, 2, 2)              # NaN
        a.const32(4, fb(1.0))
        # Dalvik's numbering (KB-2 fix round 1 corrected the VM's): 0x2d cmpl-float, 0x2e cmpg-float, 0x2f cmpl-double,
        # 0x30 cmpg-double, 0x31 cmp-long. These specimens were built on the VM's old numbering (0x2e/0x2f the float
        # compares, 0x30/0x31 the double ones), which they then passed against.
        a.cmp(0x2d, 5, 3, 4)                # cmpl-float -> -1
        a.cmp(0x2e, 6, 3, 4)                # cmpg-float -> 1
        a.const_wide(8, SGN["d"])
        a.const_wide(10, 0)
        a.cmp(0x30, 7, 8, 10)               # cmpg-double -0.0 vs 0.0 -> 0
        a.unop(0x81, 0, 5)                  # v0 = (long)-1
        a.unop(0x81, 12, 6)
        a.const4(14, 5)
        a.binop(0xa3, 12, 12, 14)           # shl-long 1 << 5 = 32
        a.binop2(0xc2, 0, 12)               # -1 ^ 32
        a.unop(0x81, 12, 7)
        a.binop2(0xbb, 0, 12)               # + 0
    return chain(body), ((-1) ^ 32) & M64


def chain_l2f():
    v = (1 << 62) + (1 << 38) + 1

    def body(a, d):
        a.const_wide(2, v)
        a.unop(0x85, 4, 2)                  # long-to-float (one rounding)
        to_long_from_float_bits(a, d, 4)
    return chain(body), from_frac(Fraction(v), "f")


def chain_high16():
    # const/high16 (float 2.5f = 0x40200000) and const-wide/high16 (double -3.0 = 0xC008...) feeding f2d and adds
    def body(a, d):
        raw(a, 0x15 | (2 << 8), 0x4020)     # const/high16 v2, 2.5f
        a.unop(0x89, 4, 2)                  # float-to-double
        raw(a, 0x19 | (6 << 8), 0xC008)     # const-wide/high16 v6:v7, -3.0
        a.binop2(0xcb, 4, 6)                # -0.5
        a.unop(0x8c, 8, 4)                  # double-to-float
        a.const32(9, fb(-64.0))
        a.binop2(0xc8, 8, 9)                # mul-float/2addr -> 32.0f
        a.unop(0x88, 0, 8)                  # float-to-long -> 32
    return chain(body), 32


def chain_int_to_float_rne():
    def body(a, d):
        a.const32(2, 16777217)
        a.unop(0x82, 3, 2)                  # int-to-float: 16777216 (ties to even)
        a.unop(0x87, 4, 3)                  # float-to-int
        a.unop(0x81, 0, 4)
    return chain(body), 16777216


# ---- library methods through the VM
def chain_math():
    def body(a, d):
        # Math.sqrt(2.0) bits ^ Math.floor(-0.5) bits ^ round(2.5) ^ abs(MIN) ^ floorMod(-7, 3) ^ Float.compare(-0,0)
        sq = d.m(MATH, "sqrt", "DD")
        fl = d.m(MATH, "floor", "DD")
        rd = d.m(MATH, "round", "JD")
        ab = d.m(MATH, "abs", "II")
        fm = d.m(MATH, "floorMod", "III")
        cp = d.m(FLOATC, "compare", "IFF")
        d2l = d.m(DOUBLEC, "doubleToLongBits", "JD")
        a.const_wide(2, db(2.0))
        a.invoke(0x71, sq, [2, 3])
        a.move_result_wide(4)
        a.invoke(0x71, d2l, [4, 5])
        a.move_result_wide(0)
        a.const_wide(2, db(-0.5))
        a.invoke(0x71, fl, [2, 3])
        a.move_result_wide(4)
        a.invoke(0x71, d2l, [4, 5])
        a.move_result_wide(6)
        a.binop2(0xc2, 0, 6)
        a.const_wide(2, db(2.5))
        a.invoke(0x71, rd, [2, 3])
        a.move_result_wide(6)
        a.binop2(0xc2, 0, 6)
        a.const32(2, 0x80000000)
        a.invoke(0x71, ab, [2])
        a.move_result(3)
        a.unop(0x81, 6, 3)
        a.binop2(0xc2, 0, 6)
        a.const32(2, s32(-7))
        a.const4(3, 3)
        a.invoke(0x71, fm, [2, 3])
        a.move_result(4)
        a.unop(0x81, 6, 4)
        a.binop2(0xbb, 0, 6)                # + floorMod(-7,3) = 2
        a.const32(2, 0x80000000)            # -0.0f
        a.const4(3, 0)
        a.invoke(0x71, cp, [2, 3])
        a.move_result(4)
        a.unop(0x81, 6, 4)
        a.binop2(0xbb, 0, 6)                # + compare(-0.0f, 0.0f) = -1
    sq = enc(0, Fraction(math.isqrt(2 << 2200), 1 << 1100), "d")
    v = sq ^ db(-1.0) ^ 3 ^ (s64(-(1 << 31)) & M64)
    v = (v + 2 - 1) & M64
    return chain(body), v


def chain_float_box():
    def body(a, d):
        vo = d.m(FLOATC, "valueOf", "LF")
        dv = d.m(FLOATC, "doubleValue", "D")
        iv = d.m(FLOATC, "intValue", "I")
        nan = d.m(FLOATC, "isNaN", "ZF")
        a.const32(2, fb(-7.75))
        a.invoke(0x71, vo, [2])
        a.move_result_object(3)
        a.invoke(0x6e, dv, [3])
        a.move_result_wide(4)               # -7.75 as a double
        a.unop(0x8b, 0, 4)                  # -7
        a.invoke(0x6e, iv, [3])
        a.move_result(6)
        a.unop(0x81, 8, 6)
        a.binop2(0xbd, 0, 8)                # -7 * -7 = 49
        a.const4(7, 0)
        a.binop(0xa9, 7, 7, 7)              # NaN
        a.invoke(0x71, nan, [7])
        a.move_result(9)
        a.unop(0x81, 10, 9)
        a.binop2(0xbb, 0, 10)               # + 1
    return chain(body), 50


def chain_all_binops():
    """EVERY float/double binop opcode (23x 0xa6-0xaf and /2addr 0xc6-0xcf) through the VM, each result folded into v0
    by its canonical bits (Float.floatToIntBits / Double.doubleToLongBits), against the exact oracle."""
    fpairs = [(fb(6.5), fb(-0.375)), (fb(1e30), fb(1e-30)), (fb(-7.25), 0), (0x7F800000, fb(2.0)),
              (fb(16777215.0), fb(3.0))]
    dpairs = [(db(1e300), db(1e300)), (db(-5.5), db(2.0)), (db(0.1), db(0.2)), (SGN["d"], db(3.0)),
              (db(2.0 ** 53), db(1.0))]
    want = 0
    ops = []
    for base_op, t, pairs in ((0xa6, "f", fpairs), (0xab, "d", dpairs)):
        for k, kind in enumerate(("add", "sub", "mul", "div", "rem")):
            for form in (0, 0x20):                         # 23x and /2addr
                x, y = pairs[(k + form // 0x20) % len(pairs)]
                ops.append((base_op + k + form, t, x, y))
                r = java_op(kind, t, x, y)
                if r == NAN:
                    r = 0x7FC00000 if t == "f" else 0x7FF8000000000000
                want ^= (s32(r) & M64) if t == "f" else r

    def body(a, d):
        f2i = d.m(FLOATC, "floatToIntBits", "IF")
        d2l = d.m(DOUBLEC, "doubleToLongBits", "JD")
        a.const_wide(0, 0)
        for op, t, x, y in ops:
            if t == "f":
                a.const32(2, x)
                a.const32(3, y)
                if op >= 0xc6:
                    a.binop2(op, 2, 3)
                    res = 2
                else:
                    a.binop(op, 4, 2, 3)
                    res = 4
                a.invoke(0x71, f2i, [res])
                a.move_result(6)
                a.unop(0x81, 6, 6)
            else:
                a.const_wide(2, x)
                a.const_wide(4, y)
                if op >= 0xc6:
                    a.binop2(op, 2, 4)
                    res = 2
                else:
                    a.binop(op, 8, 2, 4)
                    res = 8
                a.invoke(0x71, d2l, [res, res + 1])
                a.move_result_wide(6)
            a.binop2(0xc2, 0, 6)
    return chain(body), want


def chain_conversions():
    """int-to-double, long-to-double, double-to-int (saturating), float-to-int / float-to-long of NaN (0),
    double-to-long of -inf, neg-float / neg-double, cmpl-double of NaN (-1): folded into v0."""
    big = (1 << 62) + 12345                                # long-to-double rounds (62-bit value)

    def body(a, d):
        d2l = d.m(DOUBLEC, "doubleToLongBits", "JD")
        f2i = d.m(FLOATC, "floatToIntBits", "IF")
        a.const32(2, s32(-123456789))
        a.unop(0x83, 4, 2)                     # int-to-double
        a.invoke(0x71, d2l, [4, 5])
        a.move_result_wide(0)
        a.const_wide(2, big)
        a.unop(0x86, 4, 2)                     # long-to-double
        a.invoke(0x71, d2l, [4, 5])
        a.move_result_wide(6)
        a.binop2(0xc2, 0, 6)
        a.const_wide(2, db(3e10))
        a.unop(0x8a, 4, 2)                     # double-to-int saturates to Integer.MAX
        a.unop(0x81, 6, 4)
        a.binop2(0xbb, 0, 6)
        a.const4(2, 0)
        a.binop(0xa9, 3, 2, 2)                 # NaN (0f/0f)
        a.unop(0x87, 4, 3)                     # float-to-int NaN -> 0
        a.unop(0x81, 6, 4)
        a.binop2(0xbb, 0, 6)
        a.unop(0x88, 6, 3)                     # float-to-long NaN -> 0
        a.binop2(0xbb, 0, 6)
        a.const_wide(2, 0xFFF0000000000000)
        a.unop(0x8b, 6, 2)                     # double-to-long -inf -> Long.MIN
        a.binop2(0xc2, 0, 6)
        a.const32(2, fb(2.5))
        a.unop(0x7f, 4, 2)                     # neg-float -> -2.5f
        a.invoke(0x71, f2i, [4])
        a.move_result(6)
        a.unop(0x81, 6, 6)
        a.binop2(0xbb, 0, 6)
        a.const_wide(2, db(0.0))
        a.unop(0x80, 4, 2)                     # neg-double -> -0.0
        a.invoke(0x71, d2l, [4, 5])
        a.move_result_wide(6)
        a.binop2(0xc2, 0, 6)
        a.const_wide(2, 0x7FF8000000000000)
        a.const_wide(4, db(1.0))
        a.cmp(0x2f, 6, 2, 4)                   # cmpl-double NaN -> -1 (Dalvik's 0x2f; see chain_cmp_nan)
        a.unop(0x81, 8, 6)
        a.binop2(0xbb, 0, 8)
    v = db(float(-123456789))
    v ^= from_frac(Fraction(big), "d")
    v = (v + 2147483647) & M64
    v = (v + 0 + 0) & M64
    v ^= 1 << 63
    v = (v + (s32(fb(-2.5)) & M64)) & M64
    v ^= SGN["d"]
    v = (v - 1) & M64
    return chain(body), v


def section_chains():
    for name, (dex, want) in (("C float specials", chain_float()), ("C double specials", chain_double()),
                              ("C NaN -> floatToIntBits canonical", chain_nan_bits()),
                              ("C cmpl/cmpg NaN bias, -0.0 == 0.0", chain_cmp_nan()),
                              ("C long-to-float above 2^53", chain_l2f()),
                              ("C Math/Float/Double library", chain_math()),
                              ("C Float box methods", chain_float_box()),
                              ("C every float/double binop opcode (23x and /2addr) incl. inf/NaN/-0.0/overflow",
                               chain_all_binops()),
                              ("C int/long-to-double, saturating d2i, NaN f2i/f2l, -inf d2l, neg, cmpl-double NaN",
                               chain_conversions())):
        expect(name, dex, code(want), key=KF)
    # chains the old VM already computed: same code, same JUDGED key (no new capability used)
    expect("C const/high16 + const-wide/high16 + f2d/d2f (legacy-exact)", chain_high16()[0],
           code(chain_high16()[1]), key=K0)
    expect("C int-to-float rounds to nearest even (legacy-exact)", chain_int_to_float_rne()[0], code(16777216), key=K0)
    expect_none("C floatToRawIntBits of a computed NaN (CPU payload)", chain_nan_raw())


# ============================================================================ D. static fields and <clinit>
K = "Lcom/huntress/K;"


def chain_static_values():
    # static_values of every encodable kind, read by sget*; a float encoded in 2 bytes (zero-extended to the right)
    def body(a, d):
        fi = d.f(K, "I", "I0")
        fj = d.f(K, "J", "J0")
        ff = d.f(K, "F", "F0")
        fd = d.f(K, "D", "D0")
        fz = d.f(K, "Z", "Z0")
        fbt = d.f(K, "B", "B0")
        fc = d.f(K, "C", "C0")
        fs = d.f(K, "S", "S0")
        fstr = d.f(K, STRING, "S1")
        kc = d.cls(K)
        for fidx, ev in ((fi, EV.int(-123456)), (fj, EV.long(0x1122334455667788)), (ff, EV.float_bits(0x3F800000, 2)),
                         (fd, EV.double_bits(0x3FF0000000000000, 2)), (fz, EV.boolean(True)), (fbt, EV.byte(0x80)),
                         (fc, EV.char(0xFFFE)), (fs, EV.short(-2)), (fstr, EV.string(d, "huntress"))):
            kc.sfields.append((fidx, ACC_PUBLIC | ACC_STATIC))
            kc.svals[fidx] = ev
        ln = d.m(STRING, "length", "I")
        sget(a, 0x61, 0, fj)                # v0:v1 = J0
        sget(a, 0x60, 2, fi)
        a.unop(0x81, 4, 2)
        a.binop2(0xc2, 0, 4)                # ^ (long)I0
        sget(a, 0x60, 2, ff)                # 1.0f bits
        a.unop(0x88, 4, 2)                  # (long)1.0f = 1
        a.binop2(0xbb, 0, 4)
        sget(a, 0x61, 6, fd)                # 1.0 (2-byte encoding)
        a.unop(0x8b, 4, 6)
        a.binop2(0xbb, 0, 4)                # +1
        sget(a, 0x63, 2, fz)
        a.unop(0x81, 4, 2)
        a.binop2(0xbb, 0, 4)                # +1
        sget(a, 0x64, 2, fbt)               # (byte)0x80 = -128
        a.unop(0x81, 4, 2)
        a.binop2(0xbb, 0, 4)
        sget(a, 0x65, 2, fc)                # 0xFFFE (char: zero-extended)
        a.unop(0x81, 4, 2)
        a.binop2(0xbb, 0, 4)
        sget(a, 0x66, 2, fs)                # -2
        a.unop(0x81, 4, 2)
        a.binop2(0xbb, 0, 4)
        sget(a, 0x62, 8, fstr)
        a.invoke(0x6e, ln, [8])
        a.move_result(2)
        a.unop(0x81, 4, 2)
        a.binop2(0xbb, 0, 4)                # + len("huntress") = 8
    v = 0x1122334455667788 ^ (s64(-123456) & M64)
    v = (v + 1 + 1 + 1 - 128 + 0xFFFE - 2 + 8) & M64
    return chain(body), v


def clinit_seed_dex(decoy_writer=False, entry_writes_first=False, unmodelled_clinit=False, read_in_entry=True):
    """K.<clinit>: SEED = (0x5DEECE66DL * 31) ^ 0xB ; the entry reads K.SEED (and calls K.mix(SEED))."""
    def body(a, d):
        fs = d.f(K, "J", "SEED")
        kc = d.cls(K)
        kc.sfields.append((fs, ACC_PRIVATE | ACC_STATIC))
        cl = d.m(K, "<clinit>", "V")
        ca = S.Asm()
        ca.const_wide(0, 0x5DEECE66D)
        ca.const_wide(2, 31)
        ca.binop2(0xbd, 0, 2)
        ca.const_wide(2, 0xB)
        ca.binop2(0xc2, 0, 2)
        if unmodelled_clinit:
            un = d.m("Landroid/util/Log;", "d", "ILL")
            ca.invoke(0x71, un, [0, 0])
        sput(ca, 0x68, 0, fs)
        ret(ca, 0x0e, 0)
        kc.direct.append((cl, ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 4, 0)))
        mix = d.m(K, "mix", "JJ")
        ma = S.Asm()
        ma.const_wide(0, 0x9E3779B97F4A7C15)
        ma.binop2(0xc2, 0, 2)               # p0 = v2:v3 (regs 4, ins 2)
        ret(ma, 0x10, 0)
        kc.direct.append((mix, ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 4, 2)))
        if decoy_writer:
            dw = d.m(K, "tamper", "V")
            da = S.Asm()
            da.const_wide(0, 1)
            sput(da, 0x68, 0, fs)
            ret(da, 0x0e, 0)
            kc.direct.append((dw, ACC_PUBLIC | ACC_STATIC, method(da.finish(), 2, 0)))
        if entry_writes_first:
            a.const_wide(4, 0x77)
            sput(a, 0x68, 4, fs)
        if read_in_entry:
            sget(a, 0x61, 2, fs)
        else:
            a.const_wide(2, 5)
        a.invoke(0x71, mix, [2, 3])
        a.move_result_wide(0)
    seed = ((0x5DEECE66D * 31) ^ 0xB) & M64
    if entry_writes_first:
        seed = 0x77
    if not read_in_entry:
        seed = 5
    return chain(body), seed ^ 0x9E3779B97F4A7C15


def chain_super_init():
    """Sup.<clinit>: X = 7. Sub extends Sup; Sub.<clinit>: Y = Sup.X * 3 (read through a Sub->X field reference). The
    entry reads Sub.Y: superclass first, field resolution through the superclass."""
    SUP, SUB = "Lcom/huntress/Sup;", "Lcom/huntress/Sub;"

    def body(a, d):
        fx = d.f(SUP, "I", "X")
        fx_via_sub = d.f(SUB, "I", "X")
        fy = d.f(SUB, "I", "Y")
        sc = d.cls(SUP)
        sb = d.cls(SUB, sup=SUP)
        sc.sfields.append((fx, ACC_PUBLIC | ACC_STATIC))
        sb.sfields.append((fy, ACC_PUBLIC | ACC_STATIC))
        c1 = d.m(SUP, "<clinit>", "V")
        a1 = S.Asm()
        a1.const4(0, 7)
        sput(a1, 0x67, 0, fx)
        ret(a1, 0x0e, 0)
        sc.direct.append((c1, ACC_STATIC | ACC_CONSTRUCTOR, method(a1.finish(), 2, 0)))
        c2 = d.m(SUB, "<clinit>", "V")
        a2 = S.Asm()
        sget(a2, 0x60, 0, fx_via_sub)
        a2.const4(1, 3)
        a2.binop2(0xb2, 0, 1)
        sput(a2, 0x67, 0, fy)
        ret(a2, 0x0e, 0)
        sb.direct.append((c2, ACC_STATIC | ACC_CONSTRUCTOR, method(a2.finish(), 2, 0)))
        sget(a, 0x60, 2, fy)
        a.unop(0x81, 0, 2)
    return chain(body), 21


def chain_clinit_once():
    """K.<clinit>: N = N + 1 (static_values N = 40). The entry calls K.f() twice (two invoke-static), then reads N: 41,
    proving the class is initialized once."""
    def body(a, d):
        fn = d.f(K, "I", "N")
        kc = d.cls(K)
        kc.sfields.append((fn, ACC_STATIC))
        kc.svals[fn] = EV.int(40)
        cl = d.m(K, "<clinit>", "V")
        ca = S.Asm()
        sget(ca, 0x60, 0, fn)
        ca.const4(1, 1)
        ca.binop2(0xb0, 0, 1)
        sput(ca, 0x67, 0, fn)
        ret(ca, 0x0e, 0)
        kc.direct.append((cl, ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        fm = d.m(K, "f", "V")
        fa = S.Asm()
        ret(fa, 0x0e, 0)
        kc.direct.append((fm, ACC_PUBLIC | ACC_STATIC, method(fa.finish(), 1, 0)))
        a.invoke(0x71, fm, [])
        a.invoke(0x71, fm, [])
        sget(a, 0x60, 2, fn)
        a.unop(0x81, 0, 2)
    return chain(body), 41


def table_dex(mutator=None, helper=None, getter=False, reflect_call=False):
    """K.TABLE = new long[4] filled in K.<clinit> with 3, 5, 7, 11; the entry sums TABLE[0..3] (directly, or through a
    read-only helper, or through a getter). `mutator`: a method elsewhere that writes into the table ('direct' through
    sget, 'param' through a helper that writes its argument, 'escape' storing it into another static)."""
    def body(a, d):
        ft = d.f(K, "[J", "TABLE")
        fo = d.f(K, "[J", "OTHER")
        kc = d.cls(K)
        kc.sfields.append((ft, ACC_STATIC | ACC_FINAL))
        kc.sfields.append((fo, ACC_STATIC))
        cl = d.m(K, "<clinit>", "V")
        ca = S.Asm()
        tl = d.t("[J")
        ca.const4(0, 4)
        ca.new_array(1, 0, tl)
        for i, v in enumerate((3, 5, 7, 11)):
            ca.const_wide(2, v)
            ca.const4(4, i)
            ca.aput(0x4c, 2, 1, 4)
        sput(ca, 0x69, 1, ft)
        ret(ca, 0x0e, 0)
        kc.direct.append((cl, ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 6, 0)))
        sumf = d.m(K, "sum", "JL", params=["[J"])          # read-only helper: sum(long[] t)
        sa = S.Asm()
        sa.const_wide(0, 0)
        for i in range(4):
            sa.const4(2, i)
            sa.aget(0x45, 4, 7, 2)                          # p0 is v7 (regs 8, ins 1)
            sa.binop2(0xbb, 0, 4)
        ret(sa, 0x10, 0)
        kc.direct.append((sumf, ACC_STATIC, method(sa.finish(), 8, 1)))
        if mutator == "direct":
            mm = d.m(K, "tamper", "V")
            ma = S.Asm()
            sget(ma, 0x62, 0, ft)
            ma.const_wide(2, 99)
            ma.const4(1, 0)
            ma.aput(0x4c, 2, 0, 1)
            ret(ma, 0x0e, 0)
            kc.direct.append((mm, ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 4, 0)))
        if mutator == "param":
            wr = d.m(K, "zero", "VL", params=["[J"])
            wa = S.Asm()
            wa.const_wide(0, 0)
            wa.const4(2, 1)
            wa.aput(0x4c, 0, 3, 2)                          # p0 is v3 (regs 4, ins 1)
            ret(wa, 0x0e, 0)
            kc.direct.append((wr, ACC_STATIC, method(wa.finish(), 4, 1)))
            mm = d.m(K, "tamper", "V")
            ma = S.Asm()
            sget(ma, 0x62, 0, ft)
            ma.invoke(0x71, wr, [0])
            ret(ma, 0x0e, 0)
            kc.direct.append((mm, ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 2, 0)))
        if mutator == "escape":
            mm = d.m(K, "alias", "V")
            ma = S.Asm()
            sget(ma, 0x62, 0, ft)
            sput(ma, 0x69, 0, fo)
            ret(ma, 0x0e, 0)
            kc.direct.append((mm, ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 2, 0)))
        if mutator == "virtual-lib":
            mm = d.m(K, "fill", "V")
            ma = S.Asm()
            fill = d.m("Ljava/util/Arrays;", "fill", "VLJ", params=["[J", "J"])
            sget(ma, 0x62, 0, ft)
            ma.const_wide(2, 0)
            ma.invoke(0x71, fill, [0, 2, 3])
            ret(ma, 0x0e, 0)
            kc.direct.append((mm, ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 4, 0)))
        if getter:
            gm = d.m(K, "table", "L", ret="[J")
            ga = S.Asm()
            sget(ga, 0x62, 0, ft)
            ret(ga, 0x11, 0)
            kc.direct.append((gm, ACC_STATIC, method(ga.finish(), 1, 0)))
        if reflect_call:
            fn = d.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING])
            gd = d.m(CLASS, "getDeclaredMethod", "LLL", ret=METHOD, params=[STRING, "[Ljava/lang/Class;"])
            mm = d.m(K, "probe", "V")
            ma = S.Asm()
            ma.const_string(0, d.s("com.huntress.K"))
            ma.invoke(0x71, fn, [0])
            ma.move_result_object(0)
            ma.const_string(1, d.s("sum"))
            ma.const4(2, 0)
            ma.invoke(0x6e, gd, [0, 1, 2])
            ma.move_result_object(0)
            mi = d.m(METHOD, "invoke", "LLL", ret="Ljava/lang/Object;",
                     params=["Ljava/lang/Object;", "[Ljava/lang/Object;"])
            ma.const4(1, 0)
            ma.invoke(0x6e, mi, [0, 1, 2])
            ret(ma, 0x0e, 0)
            kc.direct.append((mm, ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 4, 0)))
        if getter:
            a.invoke(0x71, d.m(K, "table", "L", ret="[J"), [])
            a.move_result_object(8)
        else:
            sget(a, 0x62, 8, ft)
        if helper:
            a.invoke(0x71, sumf, [8])
            a.move_result_wide(0)
        else:
            a.const_wide(0, 0)
            for i in range(4):
                a.const4(2, i)
                a.aget(0x45, 4, 8, 2)
                a.binop2(0xbb, 0, 4)
    return chain(body), 3 + 5 + 7 + 11


def chain_framework_sget(field_cls, ftype, name, op):
    def body(a, d):
        fi = d.f(field_cls, ftype, name)
        sget(a, op, 2, fi)
        a.unop(0x81, 0, 2)
    return chain(body)


def chain_locale_format():
    """String.format(Locale.US, "ANS-%016X", Long.valueOf(v)) -- the sget of Locale.US must keep working."""
    d = DexB()
    a = S.Asm()
    cc = d.cls(C)
    fl = d.f("Ljava/util/Locale;", "Ljava/util/Locale;", "US")
    lv = d.m(LONG, "valueOf", "LJ")
    fm = d.m(STRING, "format", "LLLL")
    a.const_wide(0, 0x0123456789ABCDEF)
    a.const4(9, 1)
    a.new_array(10, 9, d.t("[Ljava/lang/Object;"))
    a.invoke(0x71, lv, [0, 1])
    a.move_result_object(12)
    a.const4(9, 0)
    a.aput(0x4d, 12, 10, 9)
    sget(a, 0x62, 11, fl)
    a.const_string(13, d.s("ANS-%016X"))
    a.invoke(0x71, fm, [11, 13, 10])
    a.move_result_object(14)
    a.return_object(14)
    run = d.m(C, "run", "L", ret=STRING)
    cc.direct.append((run, ACC_PUBLIC | ACC_STATIC, (a.finish(), 24, 0, 5)))
    return d.build(), 0x0123456789ABCDEF


def chain_native_declared():
    """A class that declares a native method: JNI could write K.SEED before the chain, so the read declines."""
    def body(a, d):
        fs = d.f(K, "J", "SEED")
        kc = d.cls(K)
        kc.sfields.append((fs, ACC_STATIC))
        kc.svals[fs] = EV.long(42)
        nm = d.m(K, "nat", "J")
        kc.direct.append((nm, ACC_STATIC | ACC_NATIVE, None))
        sget(a, 0x61, 0, fs)
    return chain(body)


def chain_unknown_static_value():
    def body(a, d):
        fs = d.f(K, "[I", "ARR")
        kc = d.cls(K)
        kc.sfields.append((fs, ACC_STATIC))
        kc.svals[fs] = EV.array_of_ints([1, 2])
        sget(a, 0x62, 2, fs)
        a.const4(3, 0)
        a.aget(0x44, 4, 2, 3)
        a.unop(0x81, 0, 4)
    return chain(body)


def chain_op_mismatch():
    def body(a, d):
        fs = d.f(K, "I", "N")
        kc = d.cls(K)
        kc.sfields.append((fs, ACC_STATIC))
        kc.svals[fs] = EV.int(5)
        sget(a, 0x61, 0, fs)                # sget-wide on an int field: the verifier refuses it
    return chain(body)


def chain_unstored_static(kind):
    """K.KEY, a static int nothing of the run stores, read by the entry: 'none' has no writer anywhere and no
    static_values entry (its default 0 would hold only if nothing outside the VM's view writes it); 'clinit-other' has
    a <clinit> that writes K.OTHER and never KEY. The VM before dex_float read every static as 0."""
    def body(a, d):
        fk = d.f(K, "I", "KEY")
        kc = d.cls(K)
        kc.sfields.append((fk, ACC_PUBLIC | ACC_STATIC))
        if kind == "clinit-other":
            fo = d.f(K, "I", "OTHER")
            kc.sfields.append((fo, ACC_PUBLIC | ACC_STATIC))
            cl = d.m(K, "<clinit>", "V")
            ca = S.Asm()
            ca.const4(0, 7)
            sput(ca, 0x67, 0, fo)
            ret(ca, 0x0e, 0)
            kc.direct.append((cl, ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        sget(a, 0x60, 2, fk)
        a.unop(0x81, 0, 2)
    return chain(body)


def chain_own_static_stored():
    """The entry stores 0x5A into K.KEY (a static int of a class the dex defines, no static_values) and reads it
    back: the run's own write (probe [A2s] of the mobile fold's second review, in an app that defines the class)."""
    def body(a, d):
        fk = d.f(K, "I", "KEY")
        kc = d.cls(K)
        kc.sfields.append((fk, ACC_PUBLIC | ACC_STATIC))
        a.const16(4, 0x5A)
        sput(a, 0x67, 4, fk)
        sget(a, 0x60, 2, fk)
        a.unop(0x81, 0, 2)
    return chain(body), 0x5A


def chain_undefined_static_stored():
    """Probe [A2s]'s own shape: the entry stores 0x5A into a static of a class no dex of the package defines, then
    reads it (the VM before dex_float dropped the sput and read 0: a WRONG plain under the judged key)."""
    def body(a, d):
        fk = d.f("Lcom/huntress/Undef;", "I", "key")
        a.const16(4, 0x5A)
        sput(a, 0x67, 4, fk)
        sget(a, 0x60, 2, fk)
        a.unop(0x81, 0, 2)
    return chain(body)


def chain_context_static(null_test=False):
    """The entry reads Release.ctx (an android.content.Context static nothing of the run stores) and returns 5; with
    `null_test`, 6 when it is null (if-eqz)."""
    rel = "Lcom/huntress/Release;"

    def body(a, d):
        fc = d.f(rel, "Landroid/content/Context;", "ctx")
        rc = d.cls(rel)
        rc.sfields.append((fc, ACC_PUBLIC | ACC_STATIC))
        sget(a, 0x62, 2, fc)
        a.const_wide(0, 5)
        if null_test:
            a.if_testz(0x39, 2, "set")      # if-nez v2 -> keep 5
            a.const_wide(0, 6)
            a.label("set")
    return chain(body), 5


def section_statics():
    dex, want = chain_static_values()
    expect("D static_values of every kind (float/double zero-extended right, byte sign, char zero)", dex, code(want),
           key=KS)
    dex, want = clinit_seed_dex()
    expect("D <clinit> computes a static seed the entry reads", dex, code(want), key=KS)
    dex, want = clinit_seed_dex(read_in_entry=False)
    expect("D invoke-static runs K.<clinit> but nothing reads a static: the judged key", dex, code(want), key=K0)
    # round 2: a <clinit> the VM cannot finish declines at the use that initializes the class (here the invoke-static),
    # whether or not a static is read afterwards: the device either threw there or ran something the VM cannot follow
    expect_none("D an unmodelled op inside <clinit> declines the invoke-static that initializes the class",
                clinit_seed_dex(unmodelled_clinit=True, read_in_entry=False)[0])
    expect_none("D an unmodelled op inside <clinit>, then a static read", clinit_seed_dex(unmodelled_clinit=True)[0])
    expect_none("D a static written outside its <clinit> (a decoy writer) is not read",
                clinit_seed_dex(decoy_writer=True)[0])
    dex, want = clinit_seed_dex(decoy_writer=True, entry_writes_first=True)
    expect("D ... unless the entry wrote it itself first (the run's own last write)", dex, code(want), key=KS)
    dex, want = chain_super_init()
    expect("D superclass initialized first, field resolved through the superclass", dex, code(want), key=KS)
    dex, want = chain_clinit_once()
    expect("D <clinit> runs once across two invoke-static", dex, code(want), key=KS)
    dex, want = table_dex()
    expect("D a static long[] filled in <clinit>, read directly", dex, code(want), key=KS)
    dex, want = table_dex(helper=True)
    expect("D ... passed to a read-only app helper", dex, code(want), key=KS)
    dex, want = table_dex(getter=True)
    expect("D ... returned by a static getter (no reflection in the dex)", dex, code(want), key=KS)
    expect_none("D ... a decoy writes into the table through sget", table_dex(mutator="direct")[0])
    expect_none("D ... a decoy hands the table to a helper that writes its argument", table_dex(mutator="param")[0])
    expect_none("D ... a decoy stores the table into another static (alias)", table_dex(mutator="escape")[0])
    expect_none("D ... a decoy passes the table to Arrays.fill (a library writer)", table_dex(mutator="virtual-lib")[0])
    expect_none("D ... a getter AND a reflective call anywhere (the getter's callers are not all visible)",
                table_dex(getter=True, reflect_call=True)[0])
    expect_none("D framework primitive static (Build.VERSION.SDK_INT) is not modelled",
                chain_framework_sget("Landroid/os/Build$VERSION;", "I", "SDK_INT", 0x60))
    dex, want = chain_locale_format()
    expect("D Locale.US through sget still formats (legacy-exact)", dex, code(want), key=K0)
    expect_none("D a dex that declares a native method: JNI may write the static", chain_native_declared())
    expect_none("D an unmodelled encoded static value (an array) declines when read", chain_unknown_static_value())
    expect_none("D sget-wide on an int field (verifier mismatch)", chain_op_mismatch())
    # the store answers only a value something of THIS run stored (a chain write, a <clinit> write, static_values)
    dex = chain_unstored_static("none")
    expect_none("D a static nothing of the run stores (no writer, no static_values): never its default", dex,
                reason="nothing of this run stored it")
    check("D ... (the VM before dex_float read it as 0)", old_vm_codes(dex) == [code(0)], old_vm_codes(dex))
    expect_none("D a static its <clinit> leaves unwritten (the <clinit> writes another field)",
                chain_unstored_static("clinit-other"), reason="nothing of this run stored it")
    dex, want = chain_own_static_stored()
    expect("D the entry stores a static of a class the dex defines, then reads it: the run's own write", dex,
           code(want), key=KS)
    dex = chain_undefined_static_stored()
    expect_none("D probe [A2s]'s shape: a static of a class no dex defines, stored and read back", dex,
                reason="does not define")
    check("D ... (the VM before dex_float dropped the sput and read 0: a WRONG plain)", old_vm_codes(dex) == [code(0)],
          old_vm_codes(dex))


# ============================================================================ E. reflection
MAZE = "Lcom/huntress/Maze;"
OBJ_ARR, CLS_ARR = "[Ljava/lang/Object;", "[Ljava/lang/Class;"


def reflect_dex(variant):
    """Maze has two overloads f(long)long = x*3 and f(int)long = x+1000, an instance method g()int = 41 on a receiver,
    and statics SECRET (private, long, set in <clinit>) and PUB (public int, static_values 9)."""
    def body(a, d):
        mc = d.cls(MAZE)
        f_l = d.m(MAZE, "f", "JJ")
        f_i = d.m(MAZE, "f", "JI")
        g = d.m(MAZE, "g", "I")
        init = d.m(MAZE, "<init>", "V")
        fsec = d.f(MAZE, "J", "SECRET")
        fpub = d.f(MAZE, "I", "PUB")
        mc.sfields.append((fsec, ACC_PRIVATE | ACC_STATIC))
        mc.sfields.append((fpub, ACC_PUBLIC | ACC_STATIC))
        mc.svals[fpub] = EV.int(9)
        cl = d.m(MAZE, "<clinit>", "V")
        ca = S.Asm()
        ca.const_wide(0, 0xCAFEBABE)
        sput(ca, 0x68, 0, fsec)
        ret(ca, 0x0e, 0)
        mc.direct.append((cl, ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        fa = S.Asm()
        fa.const_wide(0, 3)
        fa.binop2(0xbd, 0, 2)                # p0 = v2:v3
        ret(fa, 0x10, 0)
        mc.direct.append((f_l, ACC_PUBLIC | ACC_STATIC, method(fa.finish(), 4, 2)))
        fi = S.Asm()
        fi.unop(0x81, 0, 3)                  # p0 = v3 (regs 4, ins 1)
        fi.const_wide(4 - 2, 1000)
        fi.binop2(0xbb, 0, 2)
        ret(fi, 0x10, 0)
        mc.direct.append((f_i, ACC_PUBLIC | ACC_STATIC, method(fi.finish(), 4, 1)))
        ia = S.Asm()
        ret(ia, 0x0e, 0)
        mc.direct.append((init, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 1, 1)))
        ga = S.Asm()
        ga.const16(0, 41)
        ret(ga, 0x0f, 0)
        mc.virtual.append((g, ACC_PUBLIC, method(ga.finish(), 2, 1)))
        fn = d.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING])
        gdm = d.m(CLASS, "getDeclaredMethod", "LLL", ret=METHOD, params=[STRING, CLS_ARR])
        inv = d.m(METHOD, "invoke", "LLL", ret="Ljava/lang/Object;", params=["Ljava/lang/Object;", OBJ_ARR])
        lvo = d.m(LONG, "valueOf", "LJ", ret=LONG, params=["J"])
        ivo = d.m(INTEGER, "valueOf", "LI", ret=INTEGER, params=["I"])
        llv = d.m(LONG, "longValue", "J")
        iiv = d.m(INTEGER, "intValue", "I")
        gdf = d.m(CLASS, "getDeclaredField", "LL", ret=FIELD, params=[STRING])
        gfd = d.m(CLASS, "getField", "LL", ret=FIELD, params=[STRING])
        sac = d.m(FIELD, "setAccessible", "VZ")
        fgl = d.m(FIELD, "getLong", "JL", params=["Ljava/lang/Object;"])
        fgi = d.m(FIELD, "getInt", "IL", params=["Ljava/lang/Object;"])
        fsi = d.m(FIELD, "setInt", "VLI", params=["Ljava/lang/Object;", "I"])
        gnm = d.m(CLASS, "getName", "L", ret=STRING)
        sln = d.m(STRING, "length", "I")
        ftype = d.f("Ljava/lang/Long;", CLASS, "TYPE")
        itype = d.f("Ljava/lang/Integer;", CLASS, "TYPE")
        a.const_string(2, d.s("com.huntress.Maze"))
        a.invoke(0x71, fn, [2])
        a.move_result_object(3)              # v3 = Class Maze
        if variant in ("overload-long", "overload-int", "overload-unknown"):
            a.const4(4, 1)
            a.new_array(5, 4, d.t(CLS_ARR))
            a.const4(4, 0)
            if variant == "overload-long":
                sget(a, 0x62, 6, ftype)
            elif variant == "overload-int":
                sget(a, 0x62, 6, itype)
            else:
                a.const4(6, 0)               # an unknown (null) class: the overload cannot be told
            a.aput(0x4d, 6, 5, 4)
            a.const_string(7, d.s("f"))
            a.invoke(0x6e, gdm, [3, 7, 5])
            a.move_result_object(8)          # Method
            a.const4(4, 1)
            a.new_array(9, 4, d.t(OBJ_ARR))
            if variant == "overload-int":
                a.const16(10, 5)
                a.invoke(0x71, ivo, [10])
            else:
                a.const_wide(10, 5)
                a.invoke(0x71, lvo, [10, 11])
            a.move_result_object(12)
            a.const4(4, 0)
            a.aput(0x4d, 12, 9, 4)
            a.const4(13, 0)
            a.invoke(0x6e, inv, [8, 13, 9])
            a.move_result_object(14)
            a.invoke(0x6e, llv, [14])
            a.move_result_wide(0)
        elif variant == "instance":
            a.const4(4, 0)
            a.new_array(5, 4, d.t(CLS_ARR))
            a.const_string(7, d.s("g"))
            a.invoke(0x6e, gdm, [3, 7, 5])
            a.move_result_object(8)
            a.new_instance(13, d.t(MAZE))
            a.invoke(0x70, init, [13])
            a.new_array(9, 4, d.t(OBJ_ARR))
            a.invoke(0x6e, inv, [8, 13, 9])
            a.move_result_object(14)
            a.invoke(0x6e, iiv, [14])        # the box is an Integer (int return)
            a.move_result(2)
            a.unop(0x81, 0, 2)
        elif variant in ("field-private", "field-private-noaccess"):
            a.const_string(7, d.s("SECRET"))
            a.invoke(0x6e, gdf, [3, 7])
            a.move_result_object(8)
            if variant == "field-private":
                a.const4(4, 1)
                a.invoke(0x6e, sac, [8, 4])
            a.const4(13, 0)
            a.invoke(0x6e, fgl, [8, 13])
            a.move_result_wide(0)
        elif variant in ("field-public", "field-set"):
            a.const_string(7, d.s("PUB"))
            a.invoke(0x6e, gfd, [3, 7])
            a.move_result_object(8)
            a.const4(13, 0)
            if variant == "field-set":
                a.const16(4, 77)
                a.invoke(0x6e, fsi, [8, 13, 4])
            a.invoke(0x6e, fgi, [8, 13])
            a.move_result(2)
            a.unop(0x81, 0, 2)
        elif variant == "getname":
            a.invoke(0x6e, gnm, [3])
            a.move_result_object(4)
            a.invoke(0x6e, sln, [4])
            a.move_result(2)
            a.unop(0x81, 0, 2)
        elif variant == "const-class":
            raw(a, 0x1c | (4 << 8), d.t("[Ljava/lang/String;"))
            a.invoke(0x6e, gnm, [4])
            a.move_result_object(4)
            a.invoke(0x6e, sln, [4])
            a.move_result(2)
            a.unop(0x81, 0, 2)
    return chain(body)


def section_reflection():
    expect("E getDeclaredMethod(\"f\", Long.TYPE) resolves the long overload", reflect_dex("overload-long"),
           code(15), key=KR)
    expect("E getDeclaredMethod(\"f\", Integer.TYPE) resolves the int overload (Integer box)",
           reflect_dex("overload-int"), code(1005), key=KR)
    expect_none("E an overloaded name with an unknown parameter class does not resolve uniquely",
                reflect_dex("overload-unknown"))
    expect("E Method.invoke of an instance method passes the receiver; an int return boxes as Integer",
           reflect_dex("instance"), code(41), key=KR)
    expect("E getDeclaredField + setAccessible(true) + getLong of a private static set in <clinit>",
           reflect_dex("field-private"), code(0xCAFEBABE), key=KRS)
    expect_none("E a private static read reflectively without setAccessible", reflect_dex("field-private-noaccess"))
    expect("E getField(\"PUB\").getInt(null) of a public static", reflect_dex("field-public"), code(9), key=KRS)
    expect("E Field.setInt then getInt (the run's own write)", reflect_dex("field-set"), code(77), key=KRS)
    expect("E Class.getName of a forName class", reflect_dex("getname"), code(len("com.huntress.Maze")), key=KR)
    expect("E const-class [Ljava/lang/String; getName is \"[Ljava.lang.String;\"", reflect_dex("const-class"),
           code(len("[Ljava.lang.String;")), key=KR)


# ============================================================================ F. refusals and decoys
def chain_unmodelled_opcode(op_units):
    def body(a, d):
        a.const_wide(0, 7)
        a.const4(2, 0)
        raw(a, *op_units)
    return chain(body)


def chain_lib(cls, name, shorty, setup, params=None):
    def body(a, d):
        m = d.m(cls, name, shorty, params=params)
        regs = setup(a, d)
        a.invoke(0x71, m, regs)
        a.move_result_wide(0)
    return chain(body)


def chain_append(shorty):
    def body(a, d):
        sb = "Ljava/lang/StringBuilder;"
        init = d.m(sb, "<init>", "V")
        ap = d.m(sb, "append", "L" + shorty, ret=sb)
        ts = d.m(sb, "toString", "L", ret=STRING)
        a.new_instance(2, d.t(sb))
        a.invoke(0x70, init, [2])
        a.const32(3, fb(1.5))
        a.invoke(0x6e, ap, [2, 3])
        a.invoke(0x6e, ts, [2])
        a.move_result_object(4)
        a.const_wide(0, 1)
    return chain(body)


def chain_biginteger():
    """String.format("ANS-%016X", BigInteger.valueOf(v)) -- the old VM truncated v to 32 bits here."""
    d = DexB()
    a = S.Asm()
    cc = d.cls(C)
    bi = "Ljava/math/BigInteger;"
    vo = d.m(bi, "valueOf", "LJ", ret=bi)
    fm = d.m(STRING, "format", "LLL")
    a.const_wide(0, 0x1234567890ABCDEF)
    a.invoke(0x71, vo, [0, 1])
    a.move_result_object(12)
    a.const4(9, 1)
    a.new_array(10, 9, d.t(OBJ_ARR))
    a.const4(9, 0)
    a.aput(0x4d, 12, 10, 9)
    a.const_string(13, d.s("ANS-%016X"))
    a.invoke(0x71, fm, [13, 10])
    a.move_result_object(14)
    a.return_object(14)
    run = d.m(C, "run", "L", ret=STRING)
    cc.direct.append((run, ACC_PUBLIC | ACC_STATIC, (a.finish(), 24, 0, 5)))
    return d.build()


def chain_native_float():
    """A static native taking a float: SysV passes it in xmm0, the native path passes integer registers."""
    def body(a, d):
        nc = "Lcom/huntress/NativeLib;"
        kc = d.cls(nc)
        nm = d.m(nc, "mix", "JF")
        kc.direct.append((nm, ACC_STATIC | ACC_NATIVE, None))
        a.const32(2, fb(1.0))
        a.invoke(0x71, nm, [2])
        a.move_result_wide(0)
    return chain(body)


def mini_so(names, code_bytes=b"\x48\x89\xf8\xc3"):
    """An ELF64 x86-64 shared object whose FUNC symbols `names` all point at `code_bytes` (mov rax, rdi; ret)."""
    VADDR = 0x1000
    dynstr = b"\x00"
    offs = []
    for n in names:
        offs.append(len(dynstr))
        dynstr += n.encode() + b"\x00"
    shnames = [b".text", b".dynstr", b".dynsym", b".shstrtab"]
    shstr = b"\x00"
    off_of = {}
    for s_ in shnames:
        off_of[s_] = len(shstr)
        shstr += s_ + b"\x00"

    def sym(nm, info, value, size, shndx):
        return struct.pack("<IBBHQQ", nm, info, 0, shndx, value, size)
    dynsym = sym(0, 0, 0, 0, 0) + b"".join(sym(o, (1 << 4) | 2, VADDR, len(code_bytes), 1) for o in offs)
    o = 64
    text_off = o
    o += len(code_bytes)
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
    shdrs += shdr(off_of[b".text"], 1, 6, VADDR, text_off, len(code_bytes), 0, 0, 16, 0)
    shdrs += shdr(off_of[b".dynstr"], 3, 0, 0, dynstr_off, len(dynstr), 0, 0, 1, 0)
    shdrs += shdr(off_of[b".dynsym"], 11, 0, 0, dynsym_off, len(dynsym), 2, 1, 8, 24)
    shdrs += shdr(off_of[b".shstrtab"], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr += struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 0, shoff, 0, 64, 56, 0, 64, 5, 4)
    blob = ehdr + code_bytes + dynstr + dynsym + shstr
    return blob + b"\x00" * (shoff - len(blob)) + shdrs


def chain_jni_onload():
    """NativeLib.<clinit>: System.loadLibrary("h") with a JNI_OnLoad in the library (it may write statics); NativeLib
    declares no native method itself, the entry reads NativeLib.SEED (static_values 42)."""
    def body(a, d):
        nc = "Lcom/huntress/NativeLib;"
        kc = d.cls(nc)
        fs = d.f(nc, "J", "SEED")
        kc.sfields.append((fs, ACC_STATIC))
        kc.svals[fs] = EV.long(42)
        cl = d.m(nc, "<clinit>", "V")
        ca = S.Asm()
        ll = d.m("Ljava/lang/System;", "loadLibrary", "VL", params=[STRING])
        ca.const_string(0, d.s("h"))
        ca.invoke(0x71, ll, [0])
        ret(ca, 0x0e, 0)
        kc.direct.append((cl, ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 1, 0)))
        sget(a, 0x61, 0, fs)
    return chain(body)


def chain_virtual_override():
    """Base.val()J returns 1; Sub extends Base overrides val() returning 2; the entry calls Base->val on a Sub object.
    The device runs Sub.val; the VM dispatches statically, so it must decline."""
    BASE, SUB = "Lcom/huntress/Base;", "Lcom/huntress/Sub2;"

    def body(a, d):
        bc = d.cls(BASE)
        sc = d.cls(SUB, sup=BASE)
        bv = d.m(BASE, "val", "J")
        sv = d.m(SUB, "val", "J")
        si = d.m(SUB, "<init>", "V")
        for cls_, m_, v in ((bc, bv, 1), (sc, sv, 2)):
            ba = S.Asm()
            ba.const_wide(0, v)
            ret(ba, 0x10, 0)
            cls_.virtual.append((m_, ACC_PUBLIC, method(ba.finish(), 3, 1)))
        ia = S.Asm()
        ret(ia, 0x0e, 0)
        sc.direct.append((si, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 1, 1)))
        a.new_instance(2, d.t(SUB))
        a.invoke(0x70, si, [2])
        a.invoke(0x6e, bv, [2])
        a.move_result_wide(0)
    return chain(body)


def chain_lit_div_zero(op):
    def body(a, d):
        a.const4(2, 7)
        a.u += [op | (3 << 8), (0 << 8) | 2]    # div/rem-int/lit8 v3, v2, #0
        a.unop(0x81, 0, 3)
    return chain(body)


def chain_unbox_mismatch():
    def body(a, d):
        vo = d.m(FLOATC, "valueOf", "LF")
        iv = d.m(INTEGER, "intValue", "I")
        a.const32(2, fb(3.0))
        a.invoke(0x71, vo, [2])
        a.move_result_object(3)
        a.invoke(0x6e, iv, [3])                 # check-cast Integer would throw on the device
        a.move_result(4)
        a.unop(0x81, 0, 4)
    return chain(body)


def chain_two_entries():
    """Two ANS entries: one legacy (const) and one using a float special: candidates under the +dex-float key."""
    d = DexB()
    cc = d.cls(C)
    outs = []
    for name, use_float in (("a", False), ("b", True)):
        a = S.Asm()
        if use_float:
            a.const32(2, fb(1.0))
            a.const4(3, 0)
            a.binop(0xa9, 4, 2, 3)              # +inf
            a.unop(0x88, 0, 4)
        else:
            a.const_wide(0, 0x55)
        S.emit_tail_format(a, d, 0, "ANS-%016X")
        m = d.m(C, name, "L", ret=STRING)
        outs.append((m, ACC_PUBLIC | ACC_STATIC, (a.finish(), 24, 0, 5)))
    cc.direct.extend(outs)
    return d.build()


def section_refusals():
    expect_none("F unmodelled opcode monitor-enter", chain_unmodelled_opcode([0x1d | (2 << 8)]))
    expect_none("F unmodelled opcode instance-of", chain_unmodelled_opcode([0x20 | (0x23 << 8), 0]))
    expect_none("F unused opcode 0x3e", chain_unmodelled_opcode([0x3e]))
    expect_none("F StringBuilder.append(float) of 1.5f: Java's text of a non-integral value is not modelled",
                chain_append("F"))
    # (round 2: append(boolean) is now rendered exactly, "true"/"false"; section H checks the text)
    expect_none("F Math.pow (not correctly rounded in Java)",
                chain_lib(MATH, "pow", "DDD", lambda a, d: (a.const_wide(2, db(2.0)), a.const_wide(4, db(0.5)),
                                                            [2, 3, 4, 5])[-1]))
    expect_none("F Math.sin", chain_lib(MATH, "sin", "DD", lambda a, d: (a.const_wide(2, db(1.0)), [2, 3])[-1]))
    expect_none("F Float.toString (not modelled)", chain_lib(FLOATC, "toString", "LF",
                                                             lambda a, d: (a.const32(2, fb(1.5)), [2])[-1]))
    expect_none("F Math.round(0.49999999999999994): Java 8 and Harmony differ",
                chain_lib(MATH, "round", "JD", lambda a, d: (a.const_wide(2, db(0.49999999999999994)), [2, 3])[-1]))
    expect_none("F Math.addExact overflow (Java throws)",
                chain_lib(MATH, "addExact", "JJJ", lambda a, d: (a.const_wide(2, (1 << 63) - 1), a.const_wide(4, 1),
                                                                 [2, 3, 4, 5])[-1]))
    expect_none("F BigInteger.valueOf + %016X (the old VM truncated to 32 bits)", chain_biginteger())
    so = mini_so(["Java_com_huntress_NativeLib_mix"], b"\x48\x89\xd0\xc3")   # mov rax, rdx; ret
    expect_none("F a native taking a float (FP register not modelled)", chain_native_float(), so=so)
    so2 = mini_so(["JNI_OnLoad", "Java_com_huntress_Other_x"])
    expect_none("F loadLibrary with a JNI_OnLoad taints the statics", chain_jni_onload(), so=so2)
    expect_none("F a virtual call the receiver's class overrides", chain_virtual_override())
    expect_none("F div-int/lit8 by zero (the old VM gave 0)", chain_lit_div_zero(0xdb))
    expect_none("F rem-int/lit8 by zero", chain_lit_div_zero(0xdc))
    expect_none("F Integer.intValue on a Float box", chain_unbox_mismatch())
    # two entries: one legacy code and one new: candidates under the +dex-float key, never plain
    dex = chain_two_entries()
    codes_, dcl = dcc.codes_in_dex_ex(dex)
    ans = dcc.answer(Q, members(dex))
    k, opts = unsure_of(ans)
    check("F two entries (one legacy, one float special): two codes, a candidate key with +dex-float",
          sorted(codes_) == sorted([code(0x55), code((1 << 63) - 1)]) and k == KF + "#candidates", (codes_, k))
    if plain_of(ans):
        WRONG.append(("two entries", plain_of(ans), None))


# ============================================================================ G. the signed-semantics trap
def section_signed():
    rng = random.Random(3)

    def j_shl_i(x, n):
        return s32(x << (n & 31))

    def j_shr_i(x, n):
        return s32(x) >> (n & 31)

    def j_ushr_i(x, n):
        return s32((x & M32) >> (n & 31))

    def j_shl_l(x, n):
        return (x << (n & 63)) & M64

    def j_shr_l(x, n):
        return (s64(x) >> (n & 63)) & M64

    def j_ushr_l(x, n):
        return ((x & M64) >> (n & 63)) & M64

    for trial in range(6):
        xi = s32(rng.getrandbits(32) | 0x80000000)          # always negative: the trap
        xl = rng.getrandbits(64) | (1 << 63)
        n1, n2 = rng.choice([1, 5, 31, 33, 63]), rng.choice([1, 7, 63, 64, 65, 127])
        byte = rng.choice([0x80, 0xFF, 0x9C, 0x7F])

        def body(a, d, xi=xi, xl=xl, n1=n1, n2=n2, byte=byte):
            # aget-byte of a byte[] holding 0x80..0xFF sign-extends; int-to-long sign-extends; int-to-byte masks+signs
            a.const4(2, 1)
            a.new_array(3, 2, d.t("[B"))
            a.const16(4, s32(byte if byte < 0x80 else byte - 0x100))
            a.const4(5, 0)
            a.aput(0x4f, 4, 3, 5)            # aput-byte
            a.aget(0x48, 6, 3, 5)            # aget-byte (sign-extended)
            a.unop(0x81, 0, 6)               # int-to-long
            a.const32(7, xi)
            a.const16(8, n1)
            a.binop(0x98, 9, 7, 8)           # shl-int
            a.unop(0x81, 10, 9)
            a.binop2(0xc2, 0, 10)
            a.binop(0x99, 9, 7, 8)           # shr-int
            a.unop(0x81, 10, 9)
            a.binop2(0xbb, 0, 10)
            a.binop(0x9a, 9, 7, 8)           # ushr-int
            a.unop(0x81, 10, 9)
            a.binop2(0xc2, 0, 10)
            a.unop(0x8d, 9, 7)               # int-to-byte
            a.unop(0x81, 10, 9)
            a.binop2(0xbb, 0, 10)
            a.const_wide(12, xl)
            a.const16(14, n2)
            a.binop(0xa3, 16, 12, 14)        # shl-long (shift masked to 63)
            a.binop(0xa2, 0, 0, 16)          # xor-long (23x: v16 does not fit a /2addr nibble)
            a.binop(0xa4, 16, 12, 14)        # shr-long
            a.binop(0x9b, 0, 0, 16)          # add-long
            a.binop(0xa5, 16, 12, 14)        # ushr-long
            a.binop(0xa2, 0, 0, 16)
            raw(a, 0xe1 | (9 << 8), (n1 & 0xFF) << 8 | 7)   # shr-int/lit8 v9, v7, #n1
            a.unop(0x81, 10, 9)
            a.binop2(0xbb, 0, 10)
        sb = s32(byte if byte < 0x80 else byte - 0x100)
        v = sb & M64
        v ^= j_shl_i(xi, n1) & M64
        v = (v + (j_shr_i(xi, n1) & M64)) & M64
        v ^= j_ushr_i(xi, n1) & M64
        v = (v + (s32(((xi & 0xFF) ^ 0x80) - 0x80) & M64)) & M64
        v ^= j_shl_l(xl, n2)
        v = (v + j_shr_l(xl, n2)) & M64
        v ^= j_ushr_l(xl, n2)
        v = (v + (j_shr_i(xi, n1) & M64)) & M64
        expect("G signed trap %d (aget-byte %#x, int-to-long, int-to-byte, shifts by %d/%d)" % (trial, byte, n1, n2),
               chain(body, regs=24), code(v), key=K0)


# ============================================================================ H. round 2 (review of the paused build)
SBT = "Ljava/lang/StringBuilder;"
OBJ = "Ljava/lang/Object;"
KO = "mobile.codec/analysis+dex-ops"
SUBM = "Lcom/huntress/SubMaze;"
OTHER = "Lcom/huntress/Other;"


def chain_cls(cls, body, regs=24):
    """chain(), with the entry run() declared in `cls`; body(a, d, cc) gets that class's spec."""
    d = DexB()
    a = S.Asm()
    cc = d.cls(cls)
    body(a, d, cc)
    S.emit_tail_format(a, d, 0, "ANS-%016X")
    run = d.m(cls, "run", "L", ret=STRING)
    cc.direct.append((run, ACC_PUBLIC | ACC_STATIC, (a.finish(), regs, 0, 5)))
    return d.build()


def old_vm_codes(dex, so=()):
    """What the VM WITHOUT dex_float computes (the shipped VM before this build), for a decoy's contrast."""
    saved = dcc._dfl
    try:
        dcc._dfl = None
        return dcc.codes_in_dex_ex(dex, so)[0]
    finally:
        dcc._dfl = saved


def text_probe(a, d, sreg, expected):
    """v0:v1 = len(s) * 1000003 + s.indexOf(expected), using v2..v6: equals probe(expected) only for that text."""
    ln = d.m(STRING, "length", "I")
    io = d.m(STRING, "indexOf", "IL", params=[STRING])
    a.invoke(0x6e, ln, [sreg])
    a.move_result(2)
    a.const_string(3, d.s(expected))
    a.invoke(0x6e, io, [sreg, 3])
    a.move_result(4)
    a.unop(0x81, 0, 2)
    a.const_wide(5, 1000003)
    a.binop2(0xbd, 0, 5)
    a.unop(0x81, 5, 4)
    a.binop2(0xbb, 0, 5)


def probe(expected):
    return len(expected) * 1000003


def sb_new(a, d, reg):
    a.new_instance(reg, d.t(SBT))
    a.invoke(0x70, d.m(SBT, "<init>", "V"), [reg])


def sb_call(a, d, sb, name, shorty, regs, params=None):
    a.invoke(0x6e, d.m(SBT, name, shorty, ret=SBT if shorty[0] == "L" else None, params=params), [sb] + list(regs))


def sb_text(a, d, sb, dst):
    a.invoke(0x6e, d.m(SBT, "toString", "L", ret=STRING), [sb])
    a.move_result_object(dst)


def h_units():
    # Java's text of floats/doubles: only what every runtime prints alike
    tab = [((fb(3.0), True), "3.0"), ((fb(-42.0), True), "-42.0"), ((0x80000000, True), "-0.0"), ((0, True), "0.0"),
           ((0x7FC00000, True), "NaN"), ((0x7F800001, True), "NaN"), ((0xFF800000, True), "-Infinity"),
           ((fb(9999999.0), True), "9999999.0"), ((fb(1e7), True), None), ((fb(0.5), True), None),
           ((fb(0.1), True), None), ((db(1234567.0), False), "1234567.0"), ((SGN["d"], False), "-0.0"),
           ((db(-9999999.0), False), "-9999999.0"), ((db(1e7), False), None), ((db(123.25), False), None),
           ((0x7FF0000000000000, False), "Infinity"), ((db(4.9e-324), False), None)]
    bad = [(a, w, DF.float_text(*a)) for a, w in tab if DF.float_text(*a) != w]
    check("H float_text: NaN, infinities, signed zeros, integral |v| < 1e7 exact; anything else None", not bad, bad)
    # Math.pow: only what the specification makes exact
    nan = float("nan")
    ptab = [((3.0, 20.0), 3486784401.0), ((-2.0, 63.0), -9223372036854775808.0), ((7.0, 1.0), 7.0),
            ((nan, 0.0), 1.0), ((nan, -0.0), 1.0), ((-0.0, 3.0), "-0"), ((-0.0, 4.0), "+0"), ((0.0, 5.0), "+0"),
            ((-1.0, 1e15 + 1), -1.0), ((10.0, 23.0), None), ((2.0, -3.0), None), ((2.5, 2.0), None),
            ((2.0, 0.5), None), ((3.0, 700.0), None), ((math.inf, 2.0), None), ((0.0, -1.0), None)]
    pbad = []
    for (x, y), w in ptab:
        g = DF.j_pow_exact(x, y)
        if w == "-0":
            ok = g == 0.0 and math.copysign(1.0, g) < 0
        elif w == "+0":
            ok = g == 0.0 and math.copysign(1.0, g) > 0
        else:
            ok = g == w and (w is None or type(g) is float)
        if not ok:
            pbad.append(((x, y), w, g))
    check("H j_pow_exact: zero/1.0 exponents, integer powers that are doubles; negative or inexact None", not pbad, pbad)
    # Class.forName names ART accepts
    dtab = [("com.huntress.Maze", "Lcom/huntress/Maze;"), ("com.x.Outer$In", "Lcom/x/Outer$In;"),
            ("[Ljava.lang.String;", "[Ljava/lang/String;"), ("[[I", "[[I"), ("com/huntress/Maze", None),
            ("Lcom.huntress.Maze;", None), ("Lcom/huntress/Maze;", None), (" com.x.A", None), ("com..A", None),
            ("[Lcom/x/A;", None), ("[L;", None), ("[Q", None), ("", None), (None, None)]
    dbad = [(n, w, DF._desc_of(n)) for n, w in dtab if DF._desc_of(n) != w]
    check("H Class.forName name syntax: binary names and dotted array descriptors only", not dbad, dbad)


def h_append_text():
    def body(a, d):
        sb_new(a, d, 7)
        a.const4(8, 1)
        sb_call(a, d, 7, "append", "LZ", [8])
        a.const4(8, 0)
        sb_call(a, d, 7, "append", "LZ", [8])
        a.const4(8, 0)
        sb_call(a, d, 7, "append", "LL", [8], params=[STRING])          # append((String) null) -> "null"
        a.const16(8, -42)
        a.invoke(0x71, d.m(INTEGER, "valueOf", "LI", ret=INTEGER, params=["I"]), [8])
        a.move_result_object(8)
        sb_call(a, d, 7, "append", "LL", [8], params=[OBJ])             # append(Object) of an Integer
        a.const_wide(2, 123456789012)
        a.invoke(0x71, d.m(LONG, "valueOf", "LJ", ret=LONG, params=["J"]), [2, 3])
        a.move_result_object(8)
        sb_call(a, d, 7, "append", "LL", [8], params=[OBJ])             # append(Object) of a Long
        a.const4(8, 0)
        a.invoke(0x71, d.m(STRING, "valueOf", "LL", ret=STRING, params=[OBJ]), [8])
        a.move_result_object(8)
        sb_call(a, d, 7, "append", "LL", [8], params=[STRING])          # String.valueOf((Object) null) -> "null"
        sb_text(a, d, 7, 15)
        text_probe(a, d, 15, "truefalsenull-42123456789012null")
    return chain(body), probe("truefalsenull-42123456789012null")


def h_float_text():
    def body(a, d):
        sb_new(a, d, 7)
        a.const32(8, fb(3.0))
        a.invoke(0x71, d.m(STRING, "valueOf", "LF", ret=STRING, params=["F"]), [8])
        a.move_result_object(8)
        sb_call(a, d, 7, "append", "LL", [8], params=[STRING])
        dts = d.m(DOUBLEC, "toString", "LD", ret=STRING, params=["D"])
        a.const_wide(2, SGN["d"])
        a.invoke(0x71, dts, [2, 3])
        a.move_result_object(8)
        sb_call(a, d, 7, "append", "LL", [8], params=[STRING])
        a.const32(8, 0x7FC00000)
        a.invoke(0x71, d.m(FLOATC, "toString", "LF", ret=STRING, params=["F"]), [8])
        a.move_result_object(8)
        sb_call(a, d, 7, "append", "LL", [8], params=[STRING])
        a.const_wide(2, 0xFFF0000000000000)
        a.invoke(0x71, dts, [2, 3])
        a.move_result_object(8)
        sb_call(a, d, 7, "append", "LL", [8], params=[STRING])
        a.const_wide(2, db(1234567.0))
        sb_call(a, d, 7, "append", "LD", [2, 3])                         # append(double)
        a.const32(8, fb(-42.0))
        a.invoke(0x71, d.m(FLOATC, "valueOf", "LF", ret=FLOATC, params=["F"]), [8])
        a.move_result_object(8)
        sb_call(a, d, 7, "append", "LL", [8], params=[OBJ])             # append(Object) of a Float box
        a.invoke(0x6e, d.m(FLOATC, "toString", "L", ret=STRING), [8])    # the box's own toString()
        a.move_result_object(8)
        sb_call(a, d, 7, "append", "LL", [8], params=[STRING])
        sb_text(a, d, 7, 15)
        text_probe(a, d, 15, "3.0-0.0NaN-Infinity1234567.0-42.0-42.0")
    return chain(body), probe("3.0-0.0NaN-Infinity1234567.0-42.0-42.0")


def h_text_decoy(kind):
    def body(a, d):
        sb_new(a, d, 7)
        if kind == "append 1e7f":
            a.const32(8, fb(1e7))
            sb_call(a, d, 7, "append", "LF", [8])
        elif kind == "append 0.1f":
            a.const32(8, fb(0.1))
            sb_call(a, d, 7, "append", "LF", [8])
        elif kind == "valueOf 0.5d":
            a.const_wide(2, db(0.5))
            a.invoke(0x71, d.m(STRING, "valueOf", "LD", ret=STRING, params=["D"]), [2, 3])
        elif kind == "append(char[],int,int)":
            a.const4(2, 3)
            a.new_array(8, 2, d.t("[C"))
            a.const4(2, 0)
            a.const4(3, 1)
            sb_call(a, d, 7, "append", "LLII", [8, 2, 3], params=["[C", "I", "I"])
        elif kind == "insert(int,int)":
            a.const4(2, 0)
            a.const4(3, 7)
            sb_call(a, d, 7, "insert", "LII", [2, 3], params=["I", "I"])
        elif kind == "insert out of range":
            a.const4(2, 5)
            a.const_string(3, d.s("x"))
            sb_call(a, d, 7, "insert", "LIL", [2, 3], params=["I", STRING])
        elif kind == "append(Object) of an int[]":
            a.const4(2, 2)
            a.new_array(8, 2, d.t("[I"))
            sb_call(a, d, 7, "append", "LL", [8], params=[OBJ])
        elif kind == "append((char[]) null)":
            a.const4(8, 0)
            sb_call(a, d, 7, "append", "LL", [8], params=["[C"])
        a.const_wide(0, 1)
        sb_text(a, d, 7, 15)
        a.invoke(0x6e, d.m(STRING, "length", "I"), [15])
        a.move_result(2)
        a.unop(0x81, 4, 2)
        a.binop2(0xbb, 0, 4)                 # the text's length is in the code
    return chain(body)


def h_index_decoy(kind):
    """An index Java rejects (it throws), which Python would wrap or clamp: charAt(-1) gives the last char there."""
    def body(a, d):
        a.const_string(15, d.s("abc"))
        if kind in ("String.charAt(-1)", "StringBuilder.charAt(-1)", "StringBuilder.setLength(10)"):
            src = 15
            if kind.startswith("StringBuilder"):
                sb_new(a, d, 7)
                sb_call(a, d, 7, "append", "LL", [15], params=[STRING])
                src = 7
            a.const4(2, -1)
            if kind == "String.charAt(-1)":
                a.invoke(0x6e, d.m(STRING, "charAt", "CI"), [15, 2])
            elif kind == "StringBuilder.charAt(-1)":
                a.invoke(0x6e, d.m(SBT, "charAt", "CI"), [src, 2])
            else:
                a.const16(2, 10)
                a.invoke(0x6e, d.m(SBT, "setLength", "VI"), [src, 2])
                a.const4(2, 0)
                a.invoke(0x6e, d.m(SBT, "charAt", "CI"), [src, 2])
            a.move_result(3)
            a.unop(0x81, 0, 3)
        elif kind == "String.substring(-2)":
            a.const4(2, -2)
            a.invoke(0x6e, d.m(STRING, "substring", "LI", ret=STRING), [15, 2])
            a.move_result_object(8)
            a.invoke(0x6e, d.m(STRING, "length", "I"), [8])
            a.move_result(3)
            a.unop(0x81, 0, 3)
        elif kind == "String.indexOf(s, -1)":
            a.const_string(8, d.s("c"))
            a.const4(2, -1)
            a.invoke(0x6e, d.m(STRING, "indexOf", "ILI", params=[STRING, "I"]), [15, 8, 2])
            a.move_result(3)
            a.unop(0x81, 0, 3)
        elif kind == "String.valueOf(Object) of an int[]":
            a.const4(2, 2)
            a.new_array(8, 2, d.t("[I"))
            a.invoke(0x71, d.m(STRING, "valueOf", "LL", ret=STRING, params=[OBJ]), [8])
            a.move_result_object(8)
            a.invoke(0x6e, d.m(STRING, "length", "I"), [8])
            a.move_result(3)
            a.unop(0x81, 0, 3)
    return chain(body)


def h_pow():
    def body(a, d):
        pw = d.m(MATH, "pow", "DDD")
        d2l = d.m(DOUBLEC, "doubleToLongBits", "JD")
        a.const_wide(0, 0)
        for x, y in ((3.0, 20.0), (-0.0, 3.0), (float("nan"), 0.0), (7.0, 1.0), (-2.0, 63.0)):
            a.const_wide(2, db(x))
            a.const_wide(4, db(y))
            a.invoke(0x71, pw, [2, 3, 4, 5])
            a.move_result_wide(6)
            a.invoke(0x71, d2l, [6, 7])
            a.move_result_wide(6)
            a.binop2(0xc2, 0, 6)
    want = db(3486784401.0) ^ SGN["d"] ^ db(1.0) ^ db(7.0) ^ db(-9223372036854775808.0)
    return chain(body), want


def h_pow_decoy(x, y):
    def body(a, d):
        a.const_wide(2, db(x))
        a.const_wide(4, db(y))
        a.invoke(0x71, d.m(MATH, "pow", "DDD"), [2, 3, 4, 5])
        a.move_result_wide(6)
        a.unop(0x8b, 0, 6)                   # (long) result
    return chain(body)


def h_monitor(kind):
    def body(a, d):
        sb_new(a, d, 2)
        if kind == "enter/exit":
            raw(a, 0x1d | (2 << 8))
            raw(a, 0x1d | (2 << 8))
            raw(a, 0x1e | (2 << 8))
            raw(a, 0x1e | (2 << 8))
        else:                                # an exit of a monitor not held
            raw(a, 0x1e | (2 << 8))
        a.const_wide(0, 0x1234)
    return chain(body), 0x1234


def h_unbox_mismatch():
    def body(a, d):
        a.const4(2, 5)
        a.invoke(0x71, d.m(INTEGER, "valueOf", "LI", ret=INTEGER, params=["I"]), [2])
        a.move_result_object(3)
        a.invoke(0x6e, d.m(LONG, "longValue", "J"), [3])     # (Long) an Integer: ClassCastException on the device
        a.move_result_wide(0)
    return chain(body)


def h_virtual_external_super():
    """Base.val()J = 1 in this dex; Sub extends Lcom/huntress/Mid; (defined nowhere here, so in another dex, and Mid may
    override val); the entry calls Base->val on a Sub. The old VM ran Base.val."""
    BASE, SUB, MID = "Lcom/huntress/Base;", "Lcom/huntress/Sub3;", "Lcom/huntress/Mid;"

    def body(a, d):
        bc = d.cls(BASE)
        sc = d.cls(SUB, sup=MID)
        bv = d.m(BASE, "val", "J")
        ba = S.Asm()
        ba.const_wide(0, 1)
        ret(ba, 0x10, 0)
        bc.virtual.append((bv, ACC_PUBLIC, method(ba.finish(), 3, 1)))
        si = d.m(SUB, "<init>", "V")
        ia = S.Asm()
        ret(ia, 0x0e, 0)
        sc.direct.append((si, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 1, 1)))
        a.new_instance(2, d.t(SUB))
        a.invoke(0x70, si, [2])
        a.invoke(0x6e, bv, [2])
        a.move_result_wide(0)
    return chain(body)


def h_clinit_throws():
    """K.<clinit> divides by zero (ArithmeticException -> ExceptionInInitializerError on the device); the entry calls
    K.f() and returns a constant. The old VM never ran <clinit> and answered."""
    def body(a, d):
        kc = d.cls(K)
        cl = d.m(K, "<clinit>", "V")
        ca = S.Asm()
        ca.const4(0, 7)
        ca.const4(1, 0)
        ca.binop(0x93, 0, 0, 1)
        ret(ca, 0x0e, 0)
        kc.direct.append((cl, ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        fm = d.m(K, "f", "V")
        fa = S.Asm()
        ret(fa, 0x0e, 0)
        kc.direct.append((fm, ACC_PUBLIC | ACC_STATIC, method(fa.finish(), 1, 0)))
        a.invoke(0x71, fm, [])
        a.const_wide(0, 5)
    return chain(body)


def h_seed_with_extra(units, regs=1):
    """clinit_seed_dex's K.SEED chain, plus a never-run method K.odd()V with the given code units."""
    def body(a, d):
        fs = d.f(K, "J", "SEED")
        kc = d.cls(K)
        kc.sfields.append((fs, ACC_PRIVATE | ACC_STATIC))
        cl = d.m(K, "<clinit>", "V")
        ca = S.Asm()
        ca.const_wide(0, 0x5EED)
        sput(ca, 0x68, 0, fs)
        ret(ca, 0x0e, 0)
        kc.direct.append((cl, ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        if units is not None:
            om = d.m(K, "odd", "V")
            kc.direct.append((om, ACC_PUBLIC | ACC_STATIC, method(list(units), regs, 0)))
        sget(a, 0x61, 0, fs)
    return chain(body), 0x5EED


def h_sibling_dex(writes_seed):
    """classes2.dex: class W whose w() puts K.SEED (a writer the scan of classes.dex cannot see), or an unrelated
    field. Returns the package's members."""
    d1, _w = h_seed_with_extra(None)
    d = DexB()
    W = "Lcom/huntress/W;"
    wc = d.cls(W)
    fld = d.f(K, "J", "SEED") if writes_seed else d.f(W, "J", "X")
    if not writes_seed:
        wc.sfields.append((fld, ACC_STATIC))
    wm = d.m(W, "w", "V")
    wa = S.Asm()
    wa.const_wide(0, 1)
    sput(wa, 0x68, 0, fld)
    ret(wa, 0x0e, 0)
    wc.direct.append((wm, ACC_PUBLIC | ACC_STATIC, method(wa.finish(), 2, 0)))
    return S.member_map(S.apk({"classes.dex": d1, "classes2.dex": d.build()}))


def h_parse(text, radix=None):
    """v0:v1 = (long) Integer.parseInt(text[, radix])."""
    def body(a, d):
        a.const_string(7, d.s(text))
        if radix is None:
            a.invoke(0x71, d.m(INTEGER, "parseInt", "IL", params=[STRING]), [7])
        else:
            a.const16(8, radix)
            a.invoke(0x71, d.m(INTEGER, "parseInt", "ILI", params=[STRING, "I"]), [7, 8])
        a.move_result(2)
        a.unop(0x81, 0, 2)
    return chain(body)


def h_sb_init(kind):
    def body(a, d):
        a.new_instance(7, d.t(SBT))
        if kind == "null":
            a.const4(8, 0)
            a.invoke(0x70, d.m(SBT, "<init>", "VL", params=[STRING]), [7, 8])
        elif kind == "negative":
            a.const4(8, -1)
            a.invoke(0x70, d.m(SBT, "<init>", "VI"), [7, 8])
        else:
            a.const_string(8, d.s("ab"))
            a.invoke(0x70, d.m(SBT, "<init>", "VL", params=[STRING]), [7, 8])
        sb_text(a, d, 7, 15)
        a.invoke(0x6e, d.m(STRING, "length", "I"), [15])
        a.move_result(2)
        a.unop(0x81, 0, 2)
    return chain(body)


def h_loadlib(lib):
    """K.<clinit> runs System.loadLibrary(lib); the entry calls K.f() and returns 0x77 (no static read)."""
    def body(a, d):
        kc = d.cls(K)
        cl = d.m(K, "<clinit>", "V")
        ca = S.Asm()
        ca.const_string(0, d.s(lib))
        ca.invoke(0x71, d.m("Ljava/lang/System;", "loadLibrary", "VL", params=[STRING]), [0])
        ret(ca, 0x0e, 0)
        kc.direct.append((cl, ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 1, 0)))
        fm = d.m(K, "f", "V")
        fa = S.Asm()
        ret(fa, 0x0e, 0)
        kc.direct.append((fm, ACC_PUBLIC | ACC_STATIC, method(fa.finish(), 1, 0)))
        a.invoke(0x71, fm, [])
        a.const_wide(0, 0x77)
    return chain(body)


def h_forname(name):
    def body(a, d):
        a.const_string(7, d.s(name))
        a.invoke(0x71, d.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING]), [7])
        a.move_result_object(8)
        a.invoke(0x6e, d.m(CLASS, "getName", "L", ret=STRING), [8])
        a.move_result_object(15)
        text_probe(a, d, 15, name)
    return chain(body), probe(name)


def wide_plus(k):
    """A static (J)J body, regs 4 ins 2 (p0 = v2:v3): return p0 + k."""
    a = S.Asm()
    a.const_wide(0, k)
    a.binop2(0xbb, 0, 2)
    ret(a, 0x10, 0)
    return a.finish()


def maze_setup(d, cc, parts):
    """The Maze class (the entry's own class when the entry is declared in Maze) with the named parts."""
    mz = cc if cc.desc == MAZE else d.cls(MAZE)
    if "q" in parts:                         # public static q(J)J = p0 + 1000
        mz.direct.append((d.m(MAZE, "q", "JJ"), ACC_PUBLIC | ACC_STATIC, method(wide_plus(1000), 4, 2)))
    if "p" in parts:                         # private static p(J)J = p0 + 1
        mz.direct.append((d.m(MAZE, "p", "JJ"), ACC_PRIVATE | ACC_STATIC, method(wide_plus(1), 4, 2)))
    if "h" in parts:                         # native static h(J)J, and static h(I)J with a body
        mz.direct.append((d.m(MAZE, "h", "JJ"), ACC_PUBLIC | ACC_STATIC | ACC_NATIVE, None))
        ha = S.Asm()
        ha.unop(0x81, 0, 3)
        ret(ha, 0x10, 0)
        mz.direct.append((d.m(MAZE, "h", "JI"), ACC_PUBLIC | ACC_STATIC, method(ha.finish(), 4, 1)))
    if "init" in parts or "g" in parts:
        ia = S.Asm()
        ret(ia, 0x0e, 0)
        mz.direct.append((d.m(MAZE, "<init>", "V"), ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 1, 1)))
    if "g" in parts:                         # virtual g()I = 1; SubMaze overrides g()I = 2; Other is unrelated
        ga = S.Asm()
        ga.const4(0, 1)
        ret(ga, 0x0f, 0)
        mz.virtual.append((d.m(MAZE, "g", "I"), ACC_PUBLIC, method(ga.finish(), 2, 1)))
        sc = d.cls(SUBM, sup=MAZE)
        sa = S.Asm()
        sa.const4(0, 2)
        ret(sa, 0x0f, 0)
        sc.virtual.append((d.m(SUBM, "g", "I"), ACC_PUBLIC, method(sa.finish(), 2, 1)))
        oc = d.cls(OTHER)
        for c_, cs_ in ((SUBM, sc), (OTHER, oc)):
            ia2 = S.Asm()
            ret(ia2, 0x0e, 0)
            cs_.direct.append((d.m(c_, "<init>", "V"), ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia2.finish(), 1, 1)))
    if "s" in parts:                         # public static s(String)J = s.length()
        sa = S.Asm()
        sa.invoke(0x6e, d.m(STRING, "length", "I"), [2])
        sa.move_result(0)
        sa.unop(0x81, 0, 0)
        ret(sa, 0x10, 0)
        mz.direct.append((d.m(MAZE, "s", "JL", params=[STRING]), ACC_PUBLIC | ACC_STATIC, method(sa.finish(), 3, 1)))
    if "secret" in parts:                    # SECRET set in <clinit>; public static readSecret()J
        fsec = d.f(MAZE, "J", "SECRET")
        mz.sfields.append((fsec, ACC_PRIVATE | ACC_STATIC))
        ca = S.Asm()
        ca.const_wide(0, 0xCAFE)
        sput(ca, 0x68, 0, fsec)
        ret(ca, 0x0e, 0)
        mz.direct.append((d.m(MAZE, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        ra = S.Asm()
        sget(ra, 0x61, 0, fsec)
        ret(ra, 0x10, 0)
        mz.direct.append((d.m(MAZE, "readSecret", "J"), ACC_PUBLIC | ACC_STATIC, method(ra.finish(), 2, 0)))


def refl_chain(parts, target, cls_ptypes, call_args, result="J", recv=None, accessible=False, entry_cls=C,
               const_class=False):
    """Class.forName("com.huntress.Maze") (or const-class), getDeclaredMethod(target, Class[] cls_ptypes), optionally
    setAccessible(true), Method.invoke(recv or null, Object[] call_args), unboxed into v0:v1."""
    def body(a, d, cc):
        maze_setup(d, cc, parts)
        if const_class:
            raw(a, 0x1c | (7 << 8), d.t(MAZE))
        else:
            a.const_string(7, d.s("com.huntress.Maze"))
            a.invoke(0x71, d.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING]), [7])
            a.move_result_object(7)
        a.const16(2, len(cls_ptypes))
        a.new_array(8, 2, d.t(CLS_ARR))
        for i, pt in enumerate(cls_ptypes):
            if pt is None:
                a.const4(3, 0)
            elif pt in ("J", "I"):
                sget(a, 0x62, 3, d.f(LONG if pt == "J" else INTEGER, CLASS, "TYPE"))
            else:
                raw(a, 0x1c | (3 << 8), d.t(pt))
            a.const16(4, i)
            a.aput(0x4d, 3, 8, 4)
        a.const_string(9, d.s(target))
        a.invoke(0x6e, d.m(CLASS, "getDeclaredMethod", "LLL", ret=METHOD, params=[STRING, CLS_ARR]), [7, 9, 8])
        a.move_result_object(10)
        if accessible:
            a.const4(2, 1)
            a.invoke(0x6e, d.m(METHOD, "setAccessible", "VZ"), [10, 2])
        a.const16(2, len(call_args))
        a.new_array(11, 2, d.t(OBJ_ARR))
        for i, (k, v) in enumerate(call_args):
            if k == "J":
                a.const_wide(3, v)
                a.invoke(0x71, d.m(LONG, "valueOf", "LJ", ret=LONG, params=["J"]), [3, 4])
                a.move_result_object(5)
            else:
                a.const_string(5, d.s(v))
            a.const16(6, i)
            a.aput(0x4d, 5, 11, 6)
        if recv is None:
            a.const4(12, 0)
        else:
            a.new_instance(12, d.t(recv))
            a.invoke(0x70, d.m(recv, "<init>", "V"), [12])
        a.invoke(0x6e, d.m(METHOD, "invoke", "LLL", ret=OBJ, params=[OBJ, OBJ_ARR]), [10, 12, 11])
        a.move_result_object(13)
        if result == "J":
            a.invoke(0x6e, d.m(LONG, "longValue", "J"), [13])
            a.move_result_wide(0)
        else:
            a.invoke(0x6e, d.m(INTEGER, "intValue", "I"), [13])
            a.move_result(2)
            a.unop(0x81, 0, 2)
    return chain_cls(entry_cls, body)


def section_round2():
    h_units()
    dex, want = h_append_text()
    expect("H append(boolean) true/false, append(null) and String.valueOf(null) \"null\", append(Object) of boxes",
           dex, code(want), key=KO)
    dex, want = h_float_text()
    expect("H float text: valueOf(3.0f), Double.toString(-0.0), NaN, -Infinity, append(1234567.0), Float box",
           dex, code(want), key=KF)
    for kind, why in (("append 1e7f", "differs between runtimes"), ("append 0.1f", "differs between runtimes"),
                      ("valueOf 0.5d", "differs between runtimes"), ("append(char[],int,int)", "overload LLII"),
                      ("insert(int,int)", "insert(int, I)"), ("insert out of range", "offset out of range"),
                      ("append(Object) of an int[]", "Java text is not modelled"),
                      ("append((char[]) null)", "null or non-char array")):
        expect_none("H StringBuilder/String text decoy: %s" % kind, h_text_decoy(kind), reason=why)
    for kind, why in (("String.charAt(-1)", "charAt index out of range"),
                      ("StringBuilder.charAt(-1)", "charAt index out of range"),
                      ("StringBuilder.setLength(10)", "setLength beyond"), ("String.substring(-2)", "substring range"),
                      ("String.indexOf(s, -1)", "negative start"),
                      ("String.valueOf(Object) of an int[]", "Java text is not modelled")):
        expect_none("H index Java rejects: %s" % kind, h_index_decoy(kind), reason=why)
    # The shipped VM before this build answered String.charAt(-1) with the LAST char. Since the KB-2 port (fix round 2,
    # the review of 4250749, item a) the VM itself bounds-checks every index as Java does, so even the VM without
    # dex_float declines it now (the contrast this check drew is closed one level lower, never reopened)
    check("H ... the VM without dex_float declines String.charAt(-1) too since the KB-2 port (it gave the LAST char)",
          old_vm_codes(h_index_decoy("String.charAt(-1)")) == [])
    dex, want = h_pow()
    expect("H Math.pow exact cases: 3^20, (-0.0)^3, NaN^0, 7^1, (-2)^63", dex, code(want), key=KF)
    for x, y in ((10.0, 23.0), (2.0, -3.0), (2.5, 2.0), (2.0, 0.5)):
        expect_none("H Math.pow(%r, %r): not made exact by the specification" % (x, y), h_pow_decoy(x, y),
                    reason="Math.pow")
    dex, want = h_monitor("enter/exit")
    expect("H monitor-enter x2 / monitor-exit x2 on an object (one thread: no value changes)", dex, code(want),
           key=KO)
    expect_none("H monitor-exit of a monitor not held (IllegalMonitorStateException)", h_monitor("exit")[0],
                reason="not held")
    expect_none("H Long.longValue on an Integer box (a check-cast the VM skips would throw)", h_unbox_mismatch(),
                reason="ClassCastException")
    dex = h_virtual_external_super()
    expect_none("H a virtual call whose receiver's class chain leaves the dex (another dex may override)", dex,
                reason="not provable")
    check("H ... the shipped VM before this build ran Base.val (now declined)", old_vm_codes(dex) == [code(1)])
    dex = h_clinit_throws()
    expect_none("H a <clinit> that throws (div by zero): the invoke-static that initializes the class declines", dex,
                reason="did not complete")
    check("H ... the shipped VM before this build never ran <clinit> and answered", old_vm_codes(dex) == [code(5)])
    # the whole-dex scan: a method it cannot size, a method handle, an invoke-custom anywhere blind the writers rule
    dex, want = h_seed_with_extra([0x0e])
    expect("H control: K.SEED from <clinit>, a harmless extra method", dex, code(want), key=KS)
    for nm, units, why in (("an unused opcode 0x3e", [0x3e, 0x0e], "could not be decoded"),
                           ("const-method-handle (a STATIC_PUT handle writes with no sput)", [0x00fe, 0, 0x0e],
                            "reflectively"),
                           ("invoke-custom", [0x00fc, 0, 0, 0x0e], "reflectively"),
                           ("a truncated instruction", [0x0018, 1], "could not be decoded")):
        expect_none("H a never-run method with %s blinds the static read" % nm, h_seed_with_extra(units)[0],
                    reason=why)
    # another dex of the package: a field reference by name is a writer the scan of this dex cannot see
    m_bad = h_sibling_dex(True)
    c_bad, d_bad = dcc.analysis_codes_ex(m_bad)
    a_bad = dcc.answer(Q, m_bad)
    if plain_of(a_bad):
        WRONG.append(("sibling writer", plain_of(a_bad), None))
    check("H classes2.dex puts K.SEED: the static read in classes.dex declines", c_bad == [] and a_bad is None,
          (c_bad, d_bad, a_bad))
    m_ok = h_sibling_dex(False)
    c_ok, d_ok = dcc.analysis_codes_ex(m_ok)
    k_ok, o_ok = unsure_of(dcc.answer(Q, m_ok))
    check("H classes2.dex writes only its own static: the read answers under +dex-static",
          c_ok == [code(0x5EED)] and d_ok == 0 and k_ok == KS and o_ok == [code(0x5EED)], (c_ok, d_ok, k_ok))
    # Integer.parseInt: Java's grammar only (Python's int() took whitespace, underscores, prefixes, any size)
    ptab = [(("12", 10), 12), (("-7f", 16), -127), (("+101", 2), 5), (("2147483647", 10), 2147483647),
            (("-2147483648", 10), -2147483648), (("2147483648", 10), None), (("1_000", 10), None), ((" 12", 10), None),
            (("12 ", 10), None), (("0x1f", 16), None), (("0b101", 2), None), (("", 10), None), (("-", 10), None),
            (("12", 1), None), (("12", 37), None), (("١٢", 10), None), (("z", 36), 35)]
    pbad = [(a, w, DF.java_parse_int(a[0], a[1], 32)) for a, w in ptab if DF.java_parse_int(a[0], a[1], 32) != w]
    check("H java_parse_int: Java's grammar and range; everything else None", not pbad, pbad)
    expect("H Integer.parseInt(\"-7f\", 16) (the shipped model, unchanged)", h_parse("-7f", 16), code(-127 & M64),
           key=K0)
    for text, radix, old in (("1_000", None, 1000), (" 12", None, 12), ("0x1f", 16, 31),
                             ("2147483648", None, -2147483648)):
        dex = h_parse(text, radix)
        expect_none("H Integer.parseInt(%r): NumberFormatException on the device" % text, dex,
                    reason="NumberFormatException")
        check("H ... the shipped VM before this build answered parseInt(%r) as %d" % (text, old),
              old_vm_codes(dex) == [code(old & M64)])
    expect("H new StringBuilder(\"ab\")", h_sb_init("text"), code(2), key=K0)
    expect_none("H new StringBuilder((String) null) (NullPointerException)", h_sb_init("null"),
                reason="NullPointerException")
    expect_none("H new StringBuilder(-1) (NegativeArraySizeException)", h_sb_init("negative"),
                reason="NegativeArraySizeException")
    # a class two dex members define: the device loads ONE copy; here classes.dex's C (no ANS method) wins on the
    # device and classes2.dex's C.run is dead code that the old VM answered from (a lone code, plain once judged)
    dl = DexB()
    live = dl.cls(C)
    la = S.Asm()
    ret(la, 0x0e, 0)
    live.direct.append((dl.m(C, "other", "V"), ACC_PUBLIC | ACC_STATIC, method(la.finish(), 1, 0)))
    m_dup = S.member_map(S.apk({"classes.dex": dl.build(),
                                "classes2.dex": chain(lambda a, d: a.const_wide(0, 0x66))}))
    c_dup, d_dup = dcc.analysis_codes_ex(m_dup)
    a_dup = dcc.answer(Q, m_dup)
    if plain_of(a_dup):
        WRONG.append(("duplicated class", plain_of(a_dup), None))
    check("H an ANS entry in a class another dex member also defines (maybe dead on the device) is not run",
          c_dup == [] and d_dup == 1 and a_dup is None, (c_dup, d_dup, a_dup))
    saved_dfl = dcc._dfl
    try:
        dcc._dfl = None
        check("H ... the shipped VM before this build answered that dead copy's code",
              dcc.analysis_codes_ex(m_dup) == ([code(0x66)], 0))
    finally:
        dcc._dfl = saved_dfl
    # the runner's files hold the SAME classes.dex twice ('<apk> -> classes.dex' and 'classes.dex'): one member, not a
    # duplicated class (the first cut of the duplicate rule turned every saved Day 23-26 timed mode into None)
    dex, want = h_seed_with_extra([0x0e])
    m_twice = members(dex)
    m_twice["set.apk -> classes.dex"] = m_twice["classes.dex"]
    c_tw, d_tw = dcc.analysis_codes_ex(m_twice)
    k_tw, o_tw = unsure_of(dcc.answer(Q, m_twice))
    check("H the same classes.dex under two names (the runner's files) is one member: the chain answers",
          c_tw == [code(want)] and d_tw == 0 and k_tw == KS and o_tw == [code(want)], (c_tw, d_tw, k_tw))
    # System.loadLibrary: the package must ship lib<name>.so (or it is a public NDK library); else the device throws
    # UnsatisfiedLinkError (the `try { loadLibrary("frida-gadget") } catch` probe) and the VM takes no catch path
    so = mini_so(["Java_com_huntress_Other_x"])
    for lib, with_so, want in (("h", True, code(0x77)), ("log", False, code(0x77)), ("frida-gadget", True, None),
                               ("h", False, None)):
        m = members(h_loadlib(lib), so if with_so else None)
        c_, d_ = dcc.analysis_codes_ex(m)
        a_ = dcc.answer(Q, m)
        if plain_of(a_) and plain_of(a_) != want:
            WRONG.append(("loadLibrary %s" % lib, plain_of(a_), want))
        if want is None:
            check("H System.loadLibrary(%r) %s: declines (UnsatisfiedLinkError on the device)"
                  % (lib, "beside libh.so only" if with_so else "with no library in the package"),
                  c_ == [] and a_ is None, (c_, d_, a_))
        else:
            k_, o_ = unsure_of(a_)
            check("H System.loadLibrary(%r) %s: loads (judged key, nothing new read)"
                  % (lib, "with libh.so shipped" if with_so else "(a public NDK library)"),
                  c_ == [want] and d_ == 0 and k_ == K0 and o_ == [want], (c_, d_, k_))
    # Class.forName: only a name ART accepts, only a class certain to exist
    dex, want = h_forname("java.lang.String")
    expect("H Class.forName(\"java.lang.String\").getName()", dex, code(want), key=KR)
    dex, want = h_forname("com.huntress.C")
    expect("H Class.forName of the package's own class", dex, code(want), key=KR)
    for nm, why in (("de.robv.android.xposed.XposedBridge", "absent"), ("java/lang/String", "binary name"),
                    ("Ljava.lang.String;", "binary name"), ("int", "absent"), ("com.huntress.Missing", "absent")):
        expect_none("H Class.forName(%r): may throw ClassNotFoundException on the device" % nm, h_forname(nm)[0],
                    reason=why)
    # Method.invoke: unique resolution, access, receiver, argument types
    expect("H getDeclaredMethod(\"q\", Long.TYPE) + invoke of a public static", refl_chain("q", "q", ["J"], [("J", 5)]),
           code(1005), key=K0)
    expect_none("H getDeclaredMethod with a null in the Class[] (NoSuchMethodException on the device)",
                refl_chain("q", "q", [None], [("J", 5)]), reason="not all known")
    check("H ... the shipped VM before this build ran q anyway",
          old_vm_codes(refl_chain("q", "q", [None], [("J", 5)])) == [code(1005)])
    expect_none("H getDeclaredMethod resolves to a native overload (no body to run)",
                refl_chain("h", "h", ["J"], [("J", 5)]), reason="no body")
    expect_none("H getDeclaredMethod(\"<init>\") (NoSuchMethodException)", refl_chain("init", "<init>", [], []),
                reason="NoSuchMethodException")
    expect_none("H a private method of another class without setAccessible (IllegalAccessException)",
                refl_chain("p", "p", ["J"], [("J", 41)]), reason="IllegalAccessException")
    expect("H ... with Method.setAccessible(true)", refl_chain("p", "p", ["J"], [("J", 41)], accessible=True),
           code(42), key=KR)
    expect("H ... from the declaring class itself (no setAccessible needed)",
           refl_chain("p", "p", ["J"], [("J", 41)], entry_cls=MAZE), code(42), key=K0)
    expect("H instance g() on a Maze receiver", refl_chain("g", "g", [], [], result="I", recv=MAZE), code(1), key=KR)
    expect_none("H instance g() on a SubMaze receiver that overrides g (the device runs SubMaze.g)",
                refl_chain("g", "g", [], [], result="I", recv=SUBM), reason="overrides")
    expect_none("H instance g() on an unrelated receiver (IllegalArgumentException)",
                refl_chain("g", "g", [], [], result="I", recv=OTHER), reason="not provably")
    expect_none("H a Long box for a String parameter (IllegalArgumentException)",
                refl_chain("s", "s", [STRING], [("J", 5)]), reason="does not certainly fit")
    expect("H a String for a String parameter", refl_chain("s", "s", [STRING], [("S", "hello")]), code(5), key=KR)
    expect("H a reflective static call through const-class initializes Maze first (SECRET from <clinit>)",
           refl_chain("secret", "readSecret", [], [], const_class=True), code(0xCAFE), key=KRS)


# ============================================================================ B. the split reading's base mode
class BaseVM(dcc.VM):
    """A stand-in for split_bundle.SplitVM: a VM class that asks dex_float for the base VM's semantics."""
    dex_float_base = True


def base_run(dex):
    """[(result, decline text)] of every ANS entry of the dex, each run by BaseVM (a null argument frame)."""
    d = dcc.Dex(dex)
    idx = {i for i in range(d.str_size) if d.string(i) in ("ANS-", "ANS-%016X")}
    out = []
    for e in dcc._entry_midxs(d, idx):
        try:
            out.append((BaseVM(d).run(e, [None] * d.code[e][1]), ""))
        except Exception as ex:
            out.append((None, str(ex)))
    return out


def base_field_dex(cls, ftype, name):
    """(Dex, field index) of a small dex that holds one field reference."""
    d = DexB()
    fi = d.f(cls, ftype, name)
    d.cls(C)
    return dcc.Dex(d.build()), fi


def declined(got, why=""):
    return bool(got) and all(r is None and why in w for r, w in got)


def section_base_mode():
    import split_bundle
    sv = split_bundle._vm_class(dcc)
    check("B split_bundle.SplitVM asks for the base VM's semantics (dex_float_base)",
          getattr(sv, "dex_float_base", None) is True and DF._base(object.__new__(sv)), sv)
    check("B ... and the VM of one APK does not", not DF._base(dcc.VM(dcc.Dex(chain_int_to_float_rne()[0]))))
    # a static read declines in the split reading, where the base VM read 0
    dex, _want = chain_static_values()
    got = base_run(dex)
    check("B an app static with static_values: declines in the split reading (one APK's VM answers it unsure)",
          declined(got, "split reading"), got)
    dex, _want = chain_own_static_stored()
    got = base_run(dex)
    check("B the entry stores an app static and reads it back: declines in the split reading (the base VM read 0)",
          declined(got, "split reading") and old_vm_codes(dex) == [code(0)], (got, old_vm_codes(dex)))
    got = base_run(chain_framework_sget("Landroid/os/Build$VERSION;", "I", "SDK_INT", 0x60))
    check("B Build.VERSION.SDK_INT declines in the split reading (the base VM read 0)", declined(got), got)
    # the framework statics dex_float models, and the app's Context
    dx, fi = base_field_dex("Lcom/huntress/Release;", "Landroid/content/Context;", "ctx")
    ctx = DF.base_sget(BaseVM(dx), 0x62, fi)
    check("B sget-object of a Context-typed app static: the stand-in for the app's Context (a ContextRef)",
          isinstance(ctx, DF.ContextRef), ctx)
    refused = []
    for what in (lambda: ctx == 0, lambda: ctx != 0, lambda: ctx < 0, lambda: 0 == ctx, lambda: hash(ctx),
                 lambda: bool(ctx), lambda: str(ctx), lambda: "%s" % (ctx,)):
        try:
            what()
            refused.append(False)
        except dcc._Decline:
            refused.append(True)
    check("B ... every observation that could tell a null from a Context declines (comparisons, hash, truth, text)",
          all(refused), refused)
    dex, want = chain_context_static(null_test=True)
    got = base_run(dex)
    check("B ... a null test of it (if-eqz) declines in the split reading (the device's static may be null)",
          declined(got, "may be null"), got)
    dx, fi = base_field_dex("Lcom/huntress/Release;", "Ljava/lang/Object;", "ctx")
    try:
        DF.base_sget(BaseVM(dx), 0x62, fi)
        refused = False
    except dcc._Decline:
        refused = True
    check("B ... but an Object-typed one of the same name declines", refused)
    dx, fi = base_field_dex("Ljava/nio/charset/StandardCharsets;", "Ljava/nio/charset/Charset;", "UTF_8")
    v = DF.base_sget(BaseVM(dx), 0x62, fi)
    check("B StandardCharsets.UTF_8: the charset token, as the base VM had it", isinstance(v, dcc._Charset), v)
    dex, want = chain_locale_format()
    got = base_run(dex)
    check("B Locale.US through sget still formats in the split reading", got == [(code(want), "")], got)
    dex, want = chain_context_static()
    got = base_run(dex)
    check("B a Context-typed static nothing stored: the split reading reads the stand-in and goes on",
          got == [(code(want), "")], got)
    expect_none("B ... while one APK's VM declines it (nothing of this run stored it)", dex,
                reason="nothing of this run stored it")
    # KB-7's new models stay out of the split reading: it computes what the VM without dex_float computes
    for label, fn in (("a float special (division by zero)", chain_float), ("Math and Float", chain_math),
                      ("long-to-float from 2**53", chain_l2f)):
        dex = fn()[0]
        got = base_run(dex)
        check("B %s: declines in the split reading, as the VM without dex_float does" % label,
              declined(got) and old_vm_codes(dex) == [], (got, old_vm_codes(dex)))
    dex, want = chain_int_to_float_rne()
    got = base_run(dex)
    check("B a legacy float chain computes the same code in the split reading", got == [(code(want), "")], got)
    # reflection: the base VM's tokens, the ones split_bundle.SplitVM._reflect resolves
    d = DexB()
    fn = d.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING])
    gm = d.m(CLASS, "getMethod", "LLL", ret=METHOD, params=[STRING, CLS_ARR])
    d.cls(C)
    dx = dcc.Dex(d.build())
    vm = BaseVM(dx)
    ct = vm._invoke(0x71, fn, ["com.huntress.C"])
    mt = vm._invoke(0x6e, gm, [ct, "run", 0])
    check("B Class.forName/getMethod give the base VM's _ClassTok/_MethTok in the split reading",
          isinstance(ct, dcc._ClassTok) and isinstance(mt, dcc._MethTok) and (mt.desc, mt.name) == (C, "run"),
          (ct, mt))


# ============================================================================ R. the review of 4917e79
GOLD = 0x9E3779B97F4A7C15
DECOY = 0x1234
KDS = "mobile.codec/analysis+dex-float+dex-static"
KRSO = "mobile.codec/analysis+dex-reflect+dex-static"
SERIAL = "Ljava/io/Serializable;"


@contextlib.contextmanager
def private_ledger(*accepted):
    """A fresh, empty ledger for the block, with each (key, name) in `accepted` learned as accepted; the suite's own
    ledger comes back afterwards (labels reads $CTF_WORKDIR on every call)."""
    with mock.patch.dict(os.environ, {"CTF_WORKDIR": tempfile.mkdtemp(prefix="d27dexfloat-r3-")}):
        for key, name in accepted:
            labels.learn(key, name, "accepted", scope="key")
        yield


ACCEPT_ALL = ((K0, dcc.ROUTE), (KS, dcc.ROUTE + "+dex-static"), (KR, dcc.ROUTE + "+dex-reflect"),
              (KRS, dcc.ROUTE + "+dex-reflect+dex-static"), (KO, dcc.ROUTE + "+dex-ops"))


def seed_class(d, value=DECOY, ftype="J", acc=ACC_PUBLIC | ACC_STATIC):
    """K with a static SEED of `ftype` that K.<clinit> sets to `value`; returns (K's spec, the field index)."""
    fs = d.f(K, ftype, "SEED")
    kc = d.cls(K)
    kc.sfields.append((fs, acc))
    ca = S.Asm()
    ca.const_wide(0, value)
    sput(ca, 0x68, 0, fs)
    ret(ca, 0x0e, 0)
    kc.direct.append((d.m(K, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
    return kc, fs


def add_loader(d, kind):
    """App.onCreate(), a method the chain never runs: 'jni' loads libh.so (System.loadLibrary), 'dcl' builds a
    DexClassLoader over a payload and loads a class from it, 'runtime' calls Runtime.load of a path."""
    app = "Lcom/huntress/App;"
    ac = d.cls(app)
    ba = S.Asm()
    if kind == "jni":
        ba.const_string(0, d.s("h"))
        ba.invoke(0x71, d.m("Ljava/lang/System;", "loadLibrary", "VL", params=[STRING]), [0])
    elif kind == "runtime":
        rt = "Ljava/lang/Runtime;"
        ba.invoke(0x71, d.m(rt, "getRuntime", "L", ret=rt), [])
        ba.move_result_object(1)
        ba.const_string(0, d.s("/data/local/tmp/x.so"))
        ba.invoke(0x6e, d.m(rt, "load", "VL", params=[STRING]), [1, 0])
    else:
        dcl, cl = "Ldalvik/system/DexClassLoader;", "Ljava/lang/ClassLoader;"
        ba.new_instance(1, d.t(dcl))
        ba.const_string(2, d.s("/data/data/com.huntress/files/payload.bin"))
        ba.const4(3, 0)
        ba.invoke(0x70, d.m(dcl, "<init>", "VLLLL", params=[STRING] * 3 + [cl]), [1, 2, 3, 3, 3])
        ba.const_string(2, d.s("com.payload.Boot"))
        ba.invoke(0x6e, d.m(cl, "loadClass", "LL", ret=CLASS, params=[STRING]), [1, 2])
    ret(ba, 0x0e, 0)
    ac.virtual.append((d.m(app, "onCreate", "V"), ACC_PUBLIC, method(ba.finish(), 6, 1)))


def two_entry_seed(hole=None):
    """Two ANS entries of ONE code: C.debugCode() = code(DECOY * GOLD) from a constant (no new capability), and
    C.code() = code(K.SEED * GOLD), K.SEED = DECOY set in K.<clinit> (read through the static store). `hole`: a writer
    of K.SEED a device may run before the chain: 'jni' (App.onCreate loads libh.so, whose JNI_OnLoad may set it),
    'iface' (Release extends K implements Serializable; Release.install(long) puts Release.SEED, which a device
    resolves to K.SEED), or None (no other writer)."""
    d = DexB()
    cc = d.cls(C)
    _kc, fs = seed_class(d)
    if hole == "jni":
        add_loader(d, "jni")
    elif hole == "iface":
        rel = "Lcom/huntress/Release;"
        d.t(SERIAL)
        rc = d.cls(rel, sup=K)
        rc.ifaces.append(SERIAL)
        ia = S.Asm()
        sput(ia, 0x68, 2, d.f(rel, "J", "SEED"))
        ret(ia, 0x0e, 0)
        rc.direct.append((d.m(rel, "install", "VJ"), ACC_PUBLIC | ACC_STATIC, method(ia.finish(), 4, 2)))
    for name, from_static in (("debugCode", False), ("code", True)):
        a = S.Asm()
        if from_static:
            sget(a, 0x61, 0, fs)
        else:
            a.const_wide(0, DECOY)
        a.const_wide(2, GOLD)
        a.binop2(0xbd, 0, 2)
        S.emit_tail_format(a, d, 0, "ANS-%016X")
        cc.direct.append((d.m(C, name, "L", ret=STRING), ACC_PUBLIC | ACC_STATIC, (a.finish(), 24, 0, 5)))
    return d.build()


def iface_writer_dex(decoy=True, iface=True):
    """S1: K.SEED from K.<clinit>; Sub extends K (implementing Runnable when `iface`) and Sub.tamper() puts
    Sub.SEED = 99, which JVM field resolution maps to K.SEED. The chain reads K.SEED."""
    def body(a, d):
        _kc, fs = seed_class(d)
        sub = "Lcom/huntress/Sub;"
        d.t("Ljava/lang/Runnable;")
        sc = d.cls(sub, sup=K)
        if iface:
            sc.ifaces.append("Ljava/lang/Runnable;")
        if decoy:
            ta = S.Asm()
            ta.const_wide(0, 99)
            sput(ta, 0x68, 0, d.f(sub, "J", "SEED"))
            ret(ta, 0x0e, 0)
            sc.direct.append((d.m(sub, "tamper", "V"), ACC_PUBLIC | ACC_STATIC, method(ta.finish(), 2, 0)))
        sget(a, 0x61, 0, fs)
    return chain(body)


def big_store_dex(key_first=True, decoy=True, n_big=DF.REACH_LIMIT + 900):
    """S2: K.<clinit> builds KEY = long[]{3,5,7,11} and BIG = int[n_big][1]; K.tamper() writes KEY[0] = 99; the chain
    sums KEY. `key_first` puts KEY before BIG in the class's static list."""
    def body(a, d):
        names = ("AKEY", "BIG") if key_first else ("KEY", "ABIG")
        fk = d.f(K, "[J", names[0]) if key_first else None
        fb_ = d.f(K, "[[I", names[1])
        if not key_first:
            fk = d.f(K, "[J", names[0])
        kc = d.cls(K)
        kc.sfields.append((fk, ACC_STATIC | ACC_FINAL))
        kc.sfields.append((fb_, ACC_STATIC | ACC_FINAL))
        ca = S.Asm()
        ca.const4(0, 4)
        ca.new_array(1, 0, d.t("[J"))
        for i, v in enumerate((3, 5, 7, 11)):
            ca.const_wide(2, v)
            ca.const4(4, i)
            ca.aput(0x4c, 2, 1, 4)
        sput(ca, 0x69, 1, fk)
        ca.const16(5, n_big)
        ca.new_array(6, 5, d.t("[[I"))
        ca.const4(7, 0)
        ca.const4(8, 1)
        ca.label("loop")
        ca.if_test(0x35, 7, 5, "done")
        ca.new_array(9, 8, d.t("[I"))
        ca.aput(0x4d, 9, 6, 7)
        raw(ca, 0xd8 | (7 << 8), (1 << 8) | 7)
        ca.goto16("loop")
        ca.label("done")
        sput(ca, 0x69, 6, fb_)
        ret(ca, 0x0e, 0)
        kc.direct.append((d.m(K, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 10, 0)))
        if decoy:
            ma = S.Asm()
            sget(ma, 0x62, 0, fk)
            ma.const_wide(2, 99)
            ma.const4(1, 0)
            ma.aput(0x4c, 2, 0, 1)
            ret(ma, 0x0e, 0)
            kc.direct.append((d.m(K, "tamper", "V"), ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 4, 0)))
        sget(a, 0x62, 8, fk)
        a.const_wide(0, 0)
        for i in range(4):
            a.const4(2, i)
            a.aget(0x45, 4, 8, 2)
            a.binop2(0xbb, 0, 4)
    return chain(body)


def digest_dex(writer):
    """S3: K.KEY = byte[]{1,2,3,4} from K.<clinit>; K.seal() hands KEY to MessageDigest.digest: digest(KEY, 0, 4)
    WRITES the digest into it (`writer`), digest(KEY) only reads it. The chain sums KEY."""
    md = "Ljava/security/MessageDigest;"

    def body(a, d):
        fk = d.f(K, "[B", "KEY")
        kc = d.cls(K)
        kc.sfields.append((fk, ACC_STATIC | ACC_FINAL))
        ca = S.Asm()
        ca.const4(0, 4)
        ca.new_array(1, 0, d.t("[B"))
        for i, v in enumerate((1, 2, 3, 4)):
            ca.const4(2, v)
            ca.const4(4, i)
            ca.aput(0x4f, 2, 1, 4)
        sput(ca, 0x69, 1, fk)
        ret(ca, 0x0e, 0)
        kc.direct.append((d.m(K, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 6, 0)))
        ma = S.Asm()
        ma.const_string(0, d.s("SHA-256"))
        ma.invoke(0x71, d.m(md, "getInstance", "LL", ret=md, params=[STRING]), [0])
        ma.move_result_object(0)
        sget(ma, 0x62, 1, fk)
        if writer:
            ma.const4(2, 0)
            ma.const4(3, 4)
            ma.invoke(0x6e, d.m(md, "digest", "ILII", ret="I", params=["[B", "I", "I"]), [0, 1, 2, 3])
        else:
            ma.invoke(0x6e, d.m(md, "digest", "LL", ret="[B", params=["[B"]), [0, 1])
        ret(ma, 0x0e, 0)
        kc.direct.append((d.m(K, "seal", "V"), ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 4, 0)))
        sget(a, 0x62, 8, fk)
        a.const_wide(0, 0)
        for i in range(4):
            a.const4(2, i)
            a.aget(0x48, 4, 8, 2)
            a.unop(0x81, 4, 4)
            a.binop2(0xbb, 0, 4)
    return chain(body)


def holder_dex(decoy=True):
    """S6: K.HOLDER = new Holder() in K.<clinit> (Holder.n = 5); Holder.toString() increments n; K.log() calls
    String.valueOf(K.HOLDER) (which runs toString on a device). The chain reads HOLDER.n."""
    hd = "Lcom/huntress/Holder;"

    def body(a, d):
        fh = d.f(K, hd, "HOLDER")
        fn = d.f(hd, "I", "n")
        kc = d.cls(K)
        kc.sfields.append((fh, ACC_STATIC | ACC_FINAL))
        hc = d.cls(hd)
        hc.ifields.append((fn, 0))
        hinit = d.m(hd, "<init>", "V")
        ia = S.Asm()
        ia.const4(0, 5)
        ia.iop(0x59, 0, 1, fn)
        ret(ia, 0x0e, 0)
        hc.direct.append((hinit, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 2, 1)))
        ta = S.Asm()
        ta.iop(0x52, 0, 2, fn)
        raw(ta, 0xd8 | (0 << 8), (1 << 8) | 0)
        ta.iop(0x59, 0, 2, fn)
        ta.const_string(1, d.s("h"))
        ta.return_object(1)
        hc.virtual.append((d.m(hd, "toString", "L", ret=STRING), ACC_PUBLIC, method(ta.finish(), 3, 1)))
        ca = S.Asm()
        ca.new_instance(0, d.t(hd))
        ca.invoke(0x70, hinit, [0])
        sput(ca, 0x69, 0, fh)
        ret(ca, 0x0e, 0)
        kc.direct.append((d.m(K, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        if decoy:
            da = S.Asm()
            sget(da, 0x62, 0, fh)
            da.invoke(0x71, d.m(STRING, "valueOf", "LL", ret=STRING, params=[OBJ]), [0])
            ret(da, 0x0e, 0)
            kc.direct.append((d.m(K, "log", "V"), ACC_PUBLIC | ACC_STATIC, method(da.finish(), 2, 0)))
        sget(a, 0x62, 8, fh)
        a.iop(0x52, 2, 8, fn)
        a.unop(0x81, 0, 2)
    return chain(body)


def field_get_dex(decoy=True):
    """S7: K.TABLE = long[]{3,5,7,11} from K.<clinit>; Init.patch() reads TABLE with Field.get and writes TABLE[0] =
    99 (no sget-object of it anywhere outside the chain). The chain sums TABLE."""
    def body(a, d):
        ft = d.f(K, "[J", "TABLE")
        kc = d.cls(K)
        kc.sfields.append((ft, ACC_PUBLIC | ACC_STATIC | ACC_FINAL))
        ca = S.Asm()
        ca.const4(0, 4)
        ca.new_array(1, 0, d.t("[J"))
        for i, v in enumerate((3, 5, 7, 11)):
            ca.const_wide(2, v)
            ca.const4(4, i)
            ca.aput(0x4c, 2, 1, 4)
        sput(ca, 0x69, 1, ft)
        ret(ca, 0x0e, 0)
        kc.direct.append((d.m(K, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 6, 0)))
        if decoy:
            ini = "Lcom/huntress/Init;"
            ic = d.cls(ini)
            ma = S.Asm()
            raw(ma, 0x1c | (0 << 8), d.t(K))
            ma.const_string(1, d.s("TABLE"))
            ma.invoke(0x6e, d.m(CLASS, "getDeclaredField", "LL", ret=FIELD, params=[STRING]), [0, 1])
            ma.move_result_object(0)
            ma.const4(1, 0)
            ma.invoke(0x6e, d.m(FIELD, "get", "LL", ret=OBJ, params=[OBJ]), [0, 1])
            ma.move_result_object(2)
            raw(ma, 0x1f | (2 << 8), d.t("[J"))
            ma.const_wide(4, 99)
            ma.const4(1, 0)
            ma.aput(0x4c, 4, 2, 1)
            ret(ma, 0x0e, 0)
            ic.direct.append((d.m(ini, "patch", "V"), ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 6, 0)))
        sget(a, 0x62, 8, ft)
        a.const_wide(0, 0)
        for i in range(4):
            a.const4(2, i)
            a.aget(0x45, 4, 8, 2)
            a.binop2(0xbb, 0, 4)
    return chain(body)


def seed_with_loader(kind=None):
    """S4/S5: K.SEED from K.<clinit>, read by the chain; `kind` adds App.onCreate's loader (add_loader)."""
    def body(a, d):
        _kc, fs = seed_class(d)
        if kind:
            add_loader(d, kind)
        sget(a, 0x61, 0, fs)
    return chain(body)


def clinit_idiom_dex(idiom, read_tag=False, use_log_result=False):
    """S8: the entry's own class C has a <clinit> with a common idiom; the entry calls C.helper() (0x77). `idiom`:
    'simplename' (TAG = C.class.getSimpleName()), 'canonical' (getCanonicalName), 'log' (Log.d("init", "ready")),
    'nested' (TAG = C$Inner.class.getSimpleName(): a member class), 'annotated' (TAG of a class whose annotations say
    InnerClass, no `$` in its name), 'nullmsg' (Log.d("init", null): NullPointerException on a device). `read_tag`:
    the entry also adds TAG.length(). `use_log_result`: the entry adds what Log.d returned."""
    d = DexB()
    a = S.Asm()
    cc = d.cls(C)
    ft = d.f(C, STRING, "TAG")
    cc.sfields.append((ft, ACC_PRIVATE | ACC_STATIC | ACC_FINAL))
    ca = S.Asm()
    gs = d.m(CLASS, "getSimpleName", "L", ret=STRING)
    if idiom in ("simplename", "canonical", "nested", "annotated"):
        target = {"nested": "Lcom/huntress/C$Inner;", "annotated": "Lcom/huntress/Inner;"}.get(idiom, C)
        if target != C:
            tc = d.cls(target)
            if idiom == "annotated":
                d.t("Ldalvik/annotation/InnerClass;")
                tc.annots.append("Ldalvik/annotation/InnerClass;")
        raw(ca, 0x1c | (0 << 8), d.t(target))
        ca.invoke(0x6e, gs if idiom != "canonical" else d.m(CLASS, "getCanonicalName", "L", ret=STRING), [0])
        ca.move_result_object(0)
    else:
        ca.const_string(0, d.s("init"))
        if idiom == "nullmsg":
            ca.const4(1, 0)
        else:
            ca.const_string(1, d.s("ready"))
        ca.invoke(0x71, d.m("Landroid/util/Log;", "d", "ILL", ret="I", params=[STRING, STRING]), [0, 1])
    sput(ca, 0x69, 0, ft)
    ret(ca, 0x0e, 0)
    cc.direct.append((d.m(C, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
    ha = S.Asm()
    ha.const_wide(0, 0x77)
    ret(ha, 0x10, 0)
    helper = d.m(C, "helper", "J")
    cc.direct.append((helper, ACC_PRIVATE | ACC_STATIC, method(ha.finish(), 2, 0)))
    a.invoke(0x71, helper, [])
    a.move_result_wide(0)
    if read_tag:
        sget(a, 0x62, 3, ft)
        a.invoke(0x6e, d.m(STRING, "length", "I"), [3])
        a.move_result(4)
        a.unop(0x81, 4, 4)
        a.binop2(0xbb, 0, 4)
    if use_log_result:
        a.const_string(3, d.s("t"))
        a.const_string(4, d.s("m"))
        a.invoke(0x71, d.m("Landroid/util/Log;", "d", "ILL", ret="I", params=[STRING, STRING]), [3, 4])
        a.move_result(5)
        a.unop(0x81, 4, 5)
        a.binop2(0xbb, 0, 4)
    S.emit_tail_format(a, d, 0, "ANS-%016X")
    cc.direct.append((d.m(C, "run", "L", ret=STRING), ACC_PUBLIC | ACC_STATIC, (a.finish(), 24, 0, 5)))
    return d.build()


def public_narrow_dex():
    """S9: Maze declares a PRIVATE static f(int) (= x + 1000) and a PUBLIC static f(long) (= 3x); the chain calls
    getMethod("f", Long.TYPE).invoke(null, 5L). The VM before this module ran the first f with a body (f(int))."""
    def body(a, d):
        mc = d.cls(MAZE)
        fa = S.Asm()
        fa.unop(0x81, 0, 3)
        fa.const_wide(2, 1000)
        fa.binop2(0xbb, 0, 2)
        ret(fa, 0x10, 0)
        mc.direct.append((d.m(MAZE, "f", "JI"), ACC_PRIVATE | ACC_STATIC, method(fa.finish(), 4, 1)))
        fb2 = S.Asm()
        fb2.const_wide(0, 3)
        fb2.binop2(0xbd, 0, 2)
        ret(fb2, 0x10, 0)
        mc.direct.append((d.m(MAZE, "f", "JJ"), ACC_PUBLIC | ACC_STATIC, method(fb2.finish(), 4, 2)))
        a.const_string(2, d.s("com.huntress.Maze"))
        a.invoke(0x71, d.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING]), [2])
        a.move_result_object(2)
        a.const4(3, 1)
        a.new_array(4, 3, d.t(CLS_ARR))
        sget(a, 0x62, 5, d.f(LONG, CLASS, "TYPE"))
        a.const4(3, 0)
        a.aput(0x4d, 5, 4, 3)
        a.const_string(6, d.s("f"))
        a.invoke(0x6e, d.m(CLASS, "getMethod", "LLL", ret=METHOD, params=[STRING, CLS_ARR]), [2, 6, 4])
        a.move_result_object(2)
        a.const4(3, 1)
        a.new_array(4, 3, d.t(OBJ_ARR))
        a.const_wide(6, 5)
        a.invoke(0x71, d.m(LONG, "valueOf", "LJ", ret=LONG), [6, 7])
        a.move_result_object(5)
        a.const4(3, 0)
        a.aput(0x4d, 5, 4, 3)
        a.const4(8, 0)
        a.invoke(0x6e, d.m(METHOD, "invoke", "LLL", ret=OBJ, params=[OBJ, OBJ_ARR]), [2, 8, 4])
        a.move_result_object(5)
        a.invoke(0x6e, d.m(LONG, "longValue", "J"), [5])
        a.move_result_wide(0)
    return chain(body)


def clinit_float_dex(read_static):
    """K.<clinit> stores 1.0f / 0.0f (+Infinity, a float special: FLOAT) into K.F; the entry calls K.f() (which
    initializes K) and returns 0x31, or with `read_static` adds (long) K.F (Long.MAX_VALUE)."""
    def body(a, d):
        ff = d.f(K, "F", "F")
        kc = d.cls(K)
        kc.sfields.append((ff, ACC_PUBLIC | ACC_STATIC))
        ca = S.Asm()
        ca.const32(0, fb(1.0))
        ca.const4(1, 0)
        ca.binop(0xa9, 0, 0, 1)
        sput(ca, 0x67, 0, ff)
        ret(ca, 0x0e, 0)
        kc.direct.append((d.m(K, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        fa = S.Asm()
        ret(fa, 0x0e, 0)
        fm = d.m(K, "f", "V")
        kc.direct.append((fm, ACC_PUBLIC | ACC_STATIC, method(fa.finish(), 1, 0)))
        a.invoke(0x71, fm, [])
        a.const_wide(0, 0x31)
        if read_static:
            sget(a, 0x60, 2, ff)
            a.unop(0x88, 4, 2)                  # float-to-long: +Infinity -> Long.MAX_VALUE
            a.binop2(0xbb, 0, 4)
    want = 0x31 + (((1 << 63) - 1) if read_static else 0)
    return chain(body), want & M64


def refl_on_refl_dex(decoy=True):
    """K.SEED from K.<clinit>, read by the chain; Init.poke() (never run) reaches Field.setLong through Method.invoke
    (Class.forName("java.lang.reflect.Field").getMethod("setLong", ...)): a field write with no Field.set* method
    reference in the dex. The control's Init.poke() invokes an app method reflectively instead."""
    def body(a, d):
        _kc, fs = seed_class(d)
        ini = "Lcom/huntress/Init;"
        ic = d.cls(ini)
        ma = S.Asm()
        ma.const_string(0, d.s("java.lang.reflect.Field" if decoy else "com.huntress.Init"))
        ma.invoke(0x71, d.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING]), [0])
        ma.move_result_object(0)
        ma.const_string(1, d.s("setLong" if decoy else "poke"))
        ma.const4(2, 0)
        ma.invoke(0x6e, d.m(CLASS, "getMethod", "LLL", ret=METHOD, params=[STRING, CLS_ARR]), [0, 1, 2])
        ma.move_result_object(0)
        ma.const4(1, 0)
        ma.invoke(0x6e, d.m(METHOD, "invoke", "LLL", ret=OBJ, params=[OBJ, OBJ_ARR]), [0, 1, 2])
        ret(ma, 0x0e, 0)
        ic.direct.append((d.m(ini, "poke", "V"), ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 4, 0)))
        sget(a, 0x61, 0, fs)
    return chain(body)


def clinit_writes_chain_object():
    """The entry makes long[1] arr, puts it in Box.X, then calls K.f(); K.<clinit> computes 1.0f / 0.0f (FLOAT) and
    writes it into Box.X[0]; the entry then sums arr[0] from its own register (no static read of its own). A device
    may have initialized K long before (then arr stays 0): the <clinit>'s read of Box.X must decline."""
    bx = "Lcom/huntress/Box;"

    def body(a, d):
        fx = d.f(bx, "[J", "X")
        bc = d.cls(bx)
        bc.sfields.append((fx, ACC_PUBLIC | ACC_STATIC))
        kc = d.cls(K)
        ca = S.Asm()
        ca.const32(0, fb(1.0))
        ca.const4(1, 0)
        ca.binop(0xa9, 0, 0, 1)
        ca.unop(0x88, 2, 0)                     # float-to-long: Long.MAX_VALUE
        sget(ca, 0x62, 4, fx)
        ca.const4(5, 0)
        ca.aput(0x4c, 2, 4, 5)
        ret(ca, 0x0e, 0)
        kc.direct.append((d.m(K, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 6, 0)))
        fa = S.Asm()
        ret(fa, 0x0e, 0)
        fm = d.m(K, "f", "V")
        kc.direct.append((fm, ACC_PUBLIC | ACC_STATIC, method(fa.finish(), 1, 0)))
        a.const4(2, 1)
        a.new_array(8, 2, d.t("[J"))
        sput(a, 0x69, 8, fx)
        a.invoke(0x71, fm, [])
        a.const4(2, 0)
        a.aget(0x45, 0, 8, 2)
    return chain(body)


def huge_dex():
    """K.SEED from K.<clinit>, read by the chain, beside a never-run method of SCAN_MAX_UNITS + 1 code units."""
    def body(a, d):
        kc, fs = seed_class(d)
        kc.direct.append((d.m(K, "pad", "V"), ACC_PUBLIC | ACC_STATIC,
                          method([0x0000] * DF.SCAN_MAX_UNITS + [0x000e], 1, 0)))
        sget(a, 0x61, 0, fs)
    return chain(body)


def never_plain(name, m, accepted=ACCEPT_ALL, want_codes=None):
    """answer() over the package's members `m` is never plain, also once every name in `accepted` is accepted (a
    private ledger); with `want_codes`, analysis_codes_ex gives exactly those."""
    with private_ledger(*accepted):
        ans = dcc.answer(Q, m)
    pc = plain_of(ans)
    if pc is not None:
        WRONG.append((name, pc, None))
    check(name + ": never plain, also with the judged and +dex-* names accepted", pc is None, ans)
    if want_codes is not None:
        got = dcc.analysis_codes_ex(m)[0]
        check(name + ": the VM's codes", got == want_codes, (got, want_codes))


def section_review3():
    jso = mini_so(["JNI_OnLoad"])
    # S10: one code from a featureless run and from a static read: the UNION of the runs' families is the code's
    fam = DF.families({"c": [frozenset(), frozenset({DF.STATIC})], "d": [frozenset()]}, ["c", "d"])
    check("R families(): the union of every producing run's families (S10)",
          fam == {DF.STATIC} and DF.key_suffix({"c": [frozenset(), frozenset({DF.STATIC})]}, ["c"]) == "+dex-static",
          fam)
    m = members(two_entry_seed())
    codes_, dcl = dcc.analysis_codes_ex(m)
    with private_ledger((K0, dcc.ROUTE)):
        k_, o_ = unsure_of(dcc.answer(Q, m))
    want = code(DECOY * GOLD)
    check("R S10 two entries, one code: a debug constant and the same code through the static store: unsure under "
          "+dex-static, also with the judged key accepted (the intersection gave the judged key)",
          codes_ == [want] and dcl == 0 and k_ == KS and o_ == [want], (codes_, dcl, k_, o_))
    for hole in ("jni", "iface"):
        mh = members(two_entry_seed(hole), jso if hole == "jni" else None)
        never_plain("R S10 the same with a writer the VM cannot see (%s): the real chain declines, the debug code "
                    "stays unsure" % hole, mh, want_codes=[want])
    # S1: a sput through a subclass with interfaces does not resolve in the scan: a writer of every SEED of type J
    dex = iface_writer_dex()
    expect_none("R S1 Sub implements Runnable and puts Sub.SEED (K.SEED on a device): declines", dex,
                reason="does not resolve in the scan")
    never_plain("R S1 ...", members(dex))
    expect("R S1 control: the same subclass, no writer", iface_writer_dex(decoy=False), code(DECOY), key=KS)
    expect_none("R S1 control: the writer without the interface (the scan resolves it)",
                iface_writer_dex(iface=False), reason="written outside its <clinit>")
    # S2: a store past the walk's bound: every mutable read declines, whichever static is visited first
    for key_first in (True, False):
        for decoy in (True, False):
            dex = big_store_dex(key_first, decoy)
            expect_none("R S2 KEY beside %d <clinit> arrays (KEY %s, %s): declines" % (
                DF.REACH_LIMIT + 900, "first" if key_first else "last", "a decoy writes KEY" if decoy else "no decoy"),
                dex, reason="more objects than the VM follows")
    objs, complete = DF._reach(dcc.VM(dcc.Dex(chain_int_to_float_rne()[0])), [[[0]] * 3, [[1]]], limit=2)
    check("R _reach says when it stopped at its bound", not complete and len(objs) == 2, (len(objs), complete))
    dex, want_t = table_dex()
    expect("R S2 control: a small table still answers", dex, code(want_t), key=KS)
    # S3: MessageDigest.digest(byte[], int, int) writes its buffer; digest(byte[]) only reads it
    expect_none("R S3 a decoy passes K.KEY to digest(buf, 0, 4): declines", digest_dex(True),
                reason="may be written outside its <clinit>")
    expect("R S3 control: digest(K.KEY) reads it", digest_dex(False), code(10), key=KS)
    # S6: String.valueOf(Object) of an app object runs its toString
    expect_none("R S6 a decoy calls String.valueOf(K.HOLDER), whose toString writes HOLDER.n: declines",
                holder_dex(True), reason="may be written outside its <clinit>")
    expect("R S6 control: no decoy", holder_dex(False), code(5), key=KS)
    # S7: what Field.get returns is an alias of every static's object
    expect_none("R S7 a decoy writes TABLE[0] through Field.get: declines", field_get_dex(True),
                reason="may be written outside its <clinit>")
    expect("R S7 control: no decoy", field_get_dex(False), code(26), key=KS)
    # S4 / S5: code outside the VM's view
    expect("R S4/S5 control: K.SEED from <clinit>, nothing else in the package", seed_with_loader(), code(DECOY),
           key=KS)
    expect_none("R S4 App.onCreate loads libh.so (JNI_OnLoad may set K.SEED): declines", seed_with_loader("jni"),
                so=jso, reason="native")
    never_plain("R S4 ...", members(seed_with_loader("jni"), jso))
    expect_none("R S4 a library ships, no loader in the dex (a NativeActivity may run it): declines",
                seed_with_loader(), so=jso)
    expect_none("R S4 Runtime.getRuntime().load(path) in App.onCreate: declines", seed_with_loader("runtime"),
                reason="Runtime.load")
    expect_none("R S5 a DexClassLoader in App.onCreate (the payload may set K.SEED): declines",
                seed_with_loader("dcl"), reason="ClassLoader")
    never_plain("R S5 ...", members(seed_with_loader("dcl")))
    mp = members(seed_with_loader())
    mp["assets/payload.bin"] = b"dex\n035\x00" + bytes(104)
    cp, dp = dcc.analysis_codes_ex(mp)
    check("R S5 a dex under another name in the package (assets/payload.bin): the read declines",
          cp == [] and dp == 1 and dcc.answer(Q, mp) is None, (cp, dp))
    m2 = S.member_map(S.apk({"classes.dex": seed_with_loader(), "classes2.dex": seed_with_loader("dcl")}))
    never_plain("R S5 another dex member names a class loader", m2)
    # S8: the <clinit> idioms: modelled exactly, so the class initializes and the entry answers as before
    for idiom in ("simplename", "canonical", "log"):
        dex = clinit_idiom_dex(idiom)
        expect("R S8 %s in the entry's own <clinit>: the judged key, as the VM before this module" % idiom, dex,
               code(0x77), key=K0)
        check("R S8 ... the VM without dex_float agrees (%s)" % idiom, old_vm_codes(dex) == [code(0x77)],
              old_vm_codes(dex))
    expect("R S8 the entry reads TAG = getSimpleName() (\"C\".length()): the <clinit>'s REFLECT counts from the read",
           clinit_idiom_dex("simplename", read_tag=True), code(0x77 + 1), key=KRSO)
    for idiom, why in (("nested", "not a top-level class"), ("annotated", "not a top-level class"),
                       ("nullmsg", "message that is not known text")):
        expect_none("R S8 decoy idiom %s: the <clinit> does not complete, the invoke-static declines" % idiom,
                    clinit_idiom_dex(idiom), reason=why)
    expect_none("R S8 the entry adds what Log.d returned (the bytes it wrote, unknown): declines",
                clinit_idiom_dex("log", use_log_result=True), reason="Log.d returns")
    # reflection on reflection: Method.invoke of Field.setLong writes with no Field.set* method reference
    expect_none("R Method.invoke reaching Field.setLong (Class.forName(\"java.lang.reflect.Field\")): declines",
                refl_on_refl_dex(), reason="writes fields reflectively")
    expect("R ... control: Method.invoke of an app method", refl_on_refl_dex(decoy=False), code(DECOY), key=KS)
    # S9: getMethod's public filter picked another body than the VM before this module ran
    expect("R S9 getMethod(\"f\", Long.TYPE) over a private f(int) and a public f(long): +dex-reflect, never the "
           "judged key", public_narrow_dex(), code(15), key=KR)
    # the families of a <clinit> count from the chain's first static read on
    dex, want_f = clinit_float_dex(False)
    expect("R a <clinit> with a float special, no static read by the entry: the judged key", dex, code(want_f), key=K0)
    dex, want_f = clinit_float_dex(True)
    expect("R ... the entry reads the static it set: +dex-float+dex-static", dex, code(want_f), key=KDS)
    expect_none("R ... a <clinit> that writes into the entry's own object through a static it reads: declines (no "
                "<clinit> family is lost: the <clinit>'s read takes the history-free rule)",
                clinit_writes_chain_object(), reason="written outside its <clinit>")
    # the scan's size bound, the index cache, the weak class map
    expect_none("R a dex over SCAN_MAX_UNITS code units: a static read declines without a scan", huge_dex(),
                reason="too large to scan")
    raw_dex = chain_static_values()[0]
    d1, d2 = dcc.Dex(raw_dex), dcc.Dex(raw_dex)
    check("R the class index is built once per dex bytes (two Dex objects share it)", DF._ci(d1) is DF._ci(d2))
    check("R the VM-class map holds its classes weakly", isinstance(DF._GLOBALS, weakref.WeakKeyDictionary))


# ============================================================================ R4. the review of 5ffe7f3 (round 2)
ACCEPT_MORE = ACCEPT_ALL + ((KDS, dcc.ROUTE + "+dex-float+dex-static"), (KF, dcc.ROUTE + "+dex-float"))
APP, BASEC, SUBC, FACT = "Lcom/huntress/App;", "Lcom/huntress/Base;", "Lcom/huntress/Sub;", "Lcom/huntress/Factory;"
OTHERC, BOOT = "Lcom/huntress/Other;", "Lcom/payload/Boot;"


def pkg(**members_):
    """A package of the named members (`classes_dex=...` for classes.dex, `lib_x=...` paths with '/' as '__')."""
    return S.member_map(S.apk({k.replace("__", "/").replace("_dex", ".dex").replace("_so", ".so"): v
                               for k, v in members_.items()}))


def pkg_reasons(m):
    """The decline message of every ANS entry of the package's classes.dex, run with the package's information
    (dex_float.package_info and attach, its native libraries), as analysis_codes_ex runs it ('' for one that ran)."""
    dexes = dcc._dex_members(m)
    exts = DF.package_info(m, dexes)
    so = dcc._so_members(m)
    d = dcc.Dex(dexes[0])
    DF.attach(d, so, exts[0])
    syms = {}
    for sob in so:
        syms.update(dcc._parse_so(sob))
    idx = {i for i in range(d.str_size) if d.string(i) in ("ANS-", "ANS-%016X")}
    out = []
    for e in dcc._entry_midxs(d, idx):
        try:
            dcc.VM(d, syms).run(e, [None] * d.code[e][1])
            out.append("")
        except Exception as ex:
            out.append(str(ex))
    return out


def declines_pkg(name, m, reason, accepted=ACCEPT_MORE):
    """The package gives no code at all (one decline), the decline is for `reason`, and answer() is never plain, also
    with every name in `accepted` accepted (a private ledger)."""
    codes_, dcl = dcc.analysis_codes_ex(m)
    check(name + ": declines (no code)", codes_ == [] and dcl >= 1, (codes_, dcl))
    why = pkg_reasons(m)
    check(name + ": for the intended reason (%s)" % reason, bool(why) and all(reason in w for w in why), why)
    never_plain(name, m, accepted)


def answers_pkg(name, m, want, key):
    """The package gives exactly `want` with no decline, unsure under `key` (the judged key masked), and plain only as
    `want` once that key's name is accepted."""
    codes_, dcl = dcc.analysis_codes_ex(m)
    check(name + ": the VM computes the device's code", codes_ == [want] and dcl == 0, (codes_, dcl, want))
    k_, o_ = unsure_of(dcc.answer(Q, m))
    check(name + ": unsure under %s" % key, k_ == key and o_ == [want], (k_, o_))
    with private_ledger(*ACCEPT_MORE):
        pc = plain_of(dcc.answer(Q, m))
    if pc is not None and pc != want:
        WRONG.append((name, pc, want))
    check(name + ": with the names accepted, plain only as the device's code", pc == want, pc)


def key_clinit(d, values=(3, 5, 7, 11)):
    """K.<clinit>: KEY = long[]{values}; returns (K's spec, KEY's field index)."""
    fk = d.f(K, "[J", "KEY")
    kc = d.cls(K)
    kc.sfields.append((fk, ACC_STATIC | ACC_FINAL))
    ca = S.Asm()
    ca.const4(0, len(values))
    ca.new_array(1, 0, d.t("[J"))
    for i, v in enumerate(values):
        ca.const_wide(2, v)
        ca.const4(4, i)
        ca.aput(0x4c, 2, 1, 4)
    sput(ca, 0x69, 1, fk)
    ret(ca, 0x0e, 0)
    kc.direct.append((d.m(K, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 6, 0)))
    return kc, fk


def sum_key(a, fk):
    """The chain's read of K.KEY into v8 and v0:v1 = KEY[0] + ... + KEY[3]."""
    sget(a, 0x62, 8, fk)
    a.const_wide(0, 0)
    for i in range(4):
        a.const4(2, i)
        a.aget(0x45, 4, 8, 2)
        a.binop2(0xbb, 0, 4)


def r1_classes_dex():
    """K.KEY from K.<clinit> and a public static getter K.getKey(); the chain sums K.KEY."""
    def body(a, d):
        kc, fk = key_clinit(d)
        ga = S.Asm()
        sget(ga, 0x62, 0, fk)
        ga.return_object(0)
        kc.direct.append((d.m(K, "getKey", "L", ret="[J"), ACC_PUBLIC | ACC_STATIC, method(ga.finish(), 1, 0)))
        sum_key(a, fk)
    return chain(body)


def r1_classes2_dex(tamper=True):
    """App.onCreate() of classes2.dex: K.getKey()[0] = 99 (a device runs it before the chain), or nothing."""
    d = DexB()
    ac = d.cls(APP)
    ba = S.Asm()
    if tamper:
        ba.invoke(0x71, d.m(K, "getKey", "L", ret="[J"), [])
        ba.move_result_object(0)
        ba.const_wide(2, 99)
        ba.const4(1, 0)
        ba.aput(0x4c, 2, 0, 1)
    ret(ba, 0x0e, 0)
    ac.virtual.append((d.m(APP, "onCreate", "V"), ACC_PUBLIC, method(ba.finish(), 4, 1)))
    return d.build()


def r1b_dexes():
    """classes.dex: K.KEY from K.<clinit>; Base.process(long[]) does nothing; App.onCreate() calls
    Factory.make().process(K.KEY), whose receiver is a Sub of classes2.dex on a device (Sub.process writes a[0] = 99).
    The chain sums K.KEY."""
    def body(a, d):
        _kc, fk = key_clinit(d)
        bc = d.cls(BASEC)
        pa = S.Asm()
        ret(pa, 0x0e, 0)
        proc = d.m(BASEC, "process", "VL", params=["[J"])
        bc.virtual.append((proc, ACC_PUBLIC, method(pa.finish(), 2, 2)))
        fc = d.cls(FACT)
        ma = S.Asm()
        ma.const4(0, 0)
        ma.return_object(0)
        make = d.m(FACT, "make", "L", ret=BASEC)
        fc.direct.append((make, ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 1, 0)))
        ac = d.cls(APP)
        oa = S.Asm()
        oa.invoke(0x71, make, [])
        oa.move_result_object(0)
        sget(oa, 0x62, 1, fk)
        oa.invoke(0x6e, proc, [0, 1])
        ret(oa, 0x0e, 0)
        ac.virtual.append((d.m(APP, "onCreate", "V"), ACC_PUBLIC, method(oa.finish(), 3, 1)))
        sum_key(a, fk)
    d2 = DexB()
    sc = d2.cls(SUBC, sup=BASEC)
    pa = S.Asm()
    pa.const_wide(0, 99)
    pa.const4(2, 0)
    pa.aput(0x4c, 0, 4, 2)
    ret(pa, 0x0e, 0)
    sc.virtual.append((d2.m(SUBC, "process", "VL", params=["[J"]), ACC_PUBLIC, method(pa.finish(), 5, 2)))
    return pkg(classes_dex=chain(body), classes2_dex=d2.build())


def elf32_so():
    """A 32-bit ARM ELF header and a JNI_OnLoad string (the VM's ELF readers take ELF64 only; a device loads it and
    runs its JNI_OnLoad)."""
    h = bytearray(52)
    h[0:4] = b"\x7fELF"
    h[4] = 1
    h[5] = 1
    h[6] = 1
    struct.pack_into("<HHI", h, 16, 3, 40, 1)
    return bytes(h) + b"JNI_OnLoad\x00" + bytes(64)


def elf64_size0_so():
    """mini_so(["JNI_OnLoad"]) with the symbol's st_size 0 (an assembly function with no .size; dlsym still finds it)."""
    blob = bytearray(mini_so(["JNI_OnLoad"]))
    shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    dyn_off = struct.unpack_from("<Q", blob, shoff + 3 * 64 + 24)[0]
    struct.pack_into("<Q", blob, dyn_off + 24 + 16, 0)
    return bytes(blob)


def r2_dex(in_clinit=False, lib_name="h"):
    """The chain stores A.X = 5, loads lib<lib_name> (directly, or through B.<clinit> when `in_clinit`), then reads A.X
    back. A device's JNI_OnLoad of libh.so sets A.X = 7."""
    a_, b_ = "Lcom/huntress/A;", "Lcom/huntress/B;"

    def body(a, d):
        fx = d.f(a_, "J", "X")
        ac = d.cls(a_)
        ac.sfields.append((fx, ACC_PUBLIC | ACC_STATIC))
        a.const_wide(0, 5)
        sput(a, 0x68, 0, fx)
        lib = d.m("Ljava/lang/System;", "loadLibrary", "VL", params=[STRING])
        if in_clinit:
            bc = d.cls(b_)
            ca = S.Asm()
            ca.const_string(0, d.s(lib_name))
            ca.invoke(0x71, lib, [0])
            ret(ca, 0x0e, 0)
            bc.direct.append((d.m(b_, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 1, 0)))
            fa = S.Asm()
            ret(fa, 0x0e, 0)
            fm = d.m(b_, "f", "V")
            bc.direct.append((fm, ACC_PUBLIC | ACC_STATIC, method(fa.finish(), 1, 0)))
            a.invoke(0x71, fm, [])
        else:
            a.const_string(2, d.s(lib_name))
            a.invoke(0x71, lib, [2])
        sget(a, 0x61, 0, fx)
    return chain(body)


def r3_dexes(in_clinit=True):
    """Sub (classes2.dex) extends Base (classes.dex); Sub.<init> sets Base.n = 42 on a device. `in_clinit`: K.<clinit>
    stores new Sub() in K.INST and the chain reads K.INST.n; else the chain itself makes the Sub and reads n."""
    def body(a, d):
        fn = d.f(BASEC, "J", "n")
        bc = d.cls(BASEC)
        bc.ifields.append((fn, 0))
        ia = S.Asm()
        ret(ia, 0x0e, 0)
        bc.direct.append((d.m(BASEC, "<init>", "V"), ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 1, 1)))
        if in_clinit:
            fi = d.f(K, BASEC, "INST")
            kc = d.cls(K)
            kc.sfields.append((fi, ACC_STATIC | ACC_FINAL))
            ca = S.Asm()
            ca.new_instance(0, d.t(SUBC))
            ca.invoke(0x70, d.m(SUBC, "<init>", "V"), [0])
            sput(ca, 0x69, 0, fi)
            ret(ca, 0x0e, 0)
            kc.direct.append((d.m(K, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
            sget(a, 0x62, 8, fi)
        else:
            a.new_instance(8, d.t(SUBC))
            a.invoke(0x70, d.m(SUBC, "<init>", "V"), [8])
        a.iop(0x53, 0, 8, fn)
    d2 = DexB()
    sc = d2.cls(SUBC, sup=BASEC)
    fn2 = d2.f(BASEC, "J", "n")
    ia = S.Asm()
    ia.invoke(0x70, d2.m(BASEC, "<init>", "V"), [2])
    ia.const_wide(0, 42)
    ia.iop(0x5a, 0, 2, fn2)
    ret(ia, 0x0e, 0)
    sc.direct.append((d2.m(SUBC, "<init>", "V"), ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 3, 1)))
    return chain(body), d2.build()


def super_init_dex():
    """Sub (this dex) extends Lcom/huntress/Ext; (no dex here defines it): Sub.<init> calls Ext.<init> (no body here),
    then sets n = 1; the chain reads new Sub().n. A device runs Ext.<init>; the base VM made it a no-op."""
    ext = "Lcom/huntress/Ext;"

    def body(a, d):
        fn = d.f(SUBC, "J", "n")
        sc = d.cls(SUBC, sup=ext)
        sc.ifields.append((fn, 0))
        ia = S.Asm()
        ia.invoke(0x70, d.m(ext, "<init>", "V"), [2])
        ia.const_wide(0, 1)
        ia.iop(0x5a, 0, 2, fn)
        ret(ia, 0x0e, 0)
        si = d.m(SUBC, "<init>", "V")
        sc.direct.append((si, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 3, 1)))
        a.new_instance(8, d.t(SUBC))
        a.invoke(0x70, si, [8])
        a.iop(0x53, 0, 8, fn)
    return chain(body)


def suffix_dex():
    """invoke-static Lcom/huntress/MyInteger;->valueOf(I) of a class no dex here defines: the base VM took it for
    Integer.valueOf by the end of its name."""
    myi = "Lcom/huntress/MyInteger;"

    def body(a, d):
        a.const4(2, 5)
        a.invoke(0x71, d.m(myi, "valueOf", "LI", ret=INTEGER, params=["I"]), [2])
        a.move_result_object(3)
        a.invoke(0x6e, d.m(INTEGER, "intValue", "I"), [3])
        a.move_result(4)
        a.unop(0x81, 0, 4)
    return chain(body)


def forname_dex(cname):
    """Class.forName(cname) (the hook-framework probe's shape: on a device a missing class throws and a catch handler
    gives the real code; the VM takes no catch path), then 0xDEC0."""
    def body(a, d):
        a.const_string(2, d.s(cname))
        a.invoke(0x71, d.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING]), [2])
        a.move_result_object(2)
        a.const_wide(0, 0xDEC0)
    return chain(body)


def payload_dex(desc=BOOT):
    d = DexB()
    bc = d.cls(desc)
    ba = S.Asm()
    ret(ba, 0x0e, 0)
    bc.direct.append((d.m(desc, "go", "V"), ACC_PUBLIC | ACC_STATIC, method(ba.finish(), 1, 0)))
    return d.build()


def constclass_dex(desc):
    """const-class of `desc` (NoClassDefFoundError on a device that lacks the class), then 0xDEC2."""
    def body(a, d):
        raw(a, 0x1c | (2 << 8), d.t(desc))
        a.const_wide(0, 0xDEC2)
    return chain(body)


def lookup_dex(kind):
    """Class.forName("com.huntress.C") and a lookup with NO invoke after it (the NoSuchMethodException probe), then
    0xDEC1: 'missing' getDeclaredMethod("hookedCheck") (C declares none), 'present' getDeclaredMethod("run"),
    'getmethod-private' getMethod("helper") of C's private helper."""
    def body(a, d):
        extra = {}
        if kind == "getmethod-private":
            ha = S.Asm()
            ret(ha, 0x0e, 0)
            extra["c_direct"] = [(d.m(C, "helper", "V"), ACC_PRIVATE | ACC_STATIC, method(ha.finish(), 1, 0))]
        a.const_string(2, d.s("com.huntress.C"))
        a.invoke(0x71, d.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING]), [2])
        a.move_result_object(2)
        a.const_string(3, d.s({"missing": "hookedCheck", "present": "run", "getmethod-private": "helper"}[kind]))
        a.const4(4, 0)
        gm = "getMethod" if kind == "getmethod-private" else "getDeclaredMethod"
        a.invoke(0x6e, d.m(CLASS, gm, "LLL", ret=METHOD, params=[STRING, CLS_ARR]), [2, 3, 4])
        a.move_result_object(2)
        a.const_wide(0, 0xDEC1)
        return extra
    return chain(body)


def token_dex(toggle=True):
    """K.<clinit>: M = Secret.class.getDeclaredMethod("real"), M.setAccessible(true). With `toggle`, App.onCreate
    (never run by the VM) does K.M.setAccessible(false). The chain calls K.M.invoke(null) of Secret's PRIVATE static
    real() = 0x5EC. A device that ran onCreate first throws IllegalAccessException there."""
    sec = "Lcom/huntress/Secret;"
    sa = "Ljava/lang/reflect/AccessibleObject;"

    def body(a, d):
        fm = d.f(K, METHOD, "M")
        kc = d.cls(K)
        kc.sfields.append((fm, ACC_STATIC | ACC_FINAL))
        scs = d.cls(sec)
        ra = S.Asm()
        ra.const_wide(0, 0x5EC)
        ra.invoke(0x71, d.m(LONG, "valueOf", "LJ", ret=LONG), [0, 1])
        ra.move_result_object(0)
        ra.return_object(0)
        scs.direct.append((d.m(sec, "real", "L", ret=LONG), ACC_PRIVATE | ACC_STATIC, method(ra.finish(), 2, 0)))
        ca = S.Asm()
        raw(ca, 0x1c | (0 << 8), d.t(sec))
        ca.const_string(1, d.s("real"))
        ca.const4(2, 0)
        ca.invoke(0x6e, d.m(CLASS, "getDeclaredMethod", "LLL", ret=METHOD, params=[STRING, CLS_ARR]), [0, 1, 2])
        ca.move_result_object(0)
        ca.const4(1, 1)
        ca.invoke(0x6e, d.m(sa, "setAccessible", "VZ"), [0, 1])
        sput(ca, 0x69, 0, fm)
        ret(ca, 0x0e, 0)
        kc.direct.append((d.m(K, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 3, 0)))
        if toggle:
            ac = d.cls(APP)
            oa = S.Asm()
            sget(oa, 0x62, 0, fm)
            oa.const4(1, 0)
            oa.invoke(0x6e, d.m(sa, "setAccessible", "VZ"), [0, 1])
            ret(oa, 0x0e, 0)
            ac.virtual.append((d.m(APP, "onCreate", "V"), ACC_PUBLIC, method(oa.finish(), 3, 1)))
        sget(a, 0x62, 2, fm)
        a.const4(3, 0)
        a.const4(4, 0)
        a.new_array(4, 4, d.t(OBJ_ARR))
        a.invoke(0x6e, d.m(METHOD, "invoke", "LLL", ret=OBJ, params=[OBJ, OBJ_ARR]), [2, 3, 4])
        a.move_result_object(5)
        a.invoke(0x6e, d.m(LONG, "longValue", "J"), [5])
        a.move_result_wide(0)
    return chain(body)


def unseen_pkg(trigger, order="after"):
    """K.X (a static long of classes.dex) written by the chain (5) and read back, beside a trigger of an app class of
    classes2.dex whose <clinit> calls K.setX(7) on a device: 'forname' (Class.forName("com.huntress.Other")), 'super'
    (an invoke-static of Util.f(), Util extends Base2 of classes2.dex), 'sput' (a write of Other.Y). `order`: the
    trigger after the chain's write (a device that had not initialized the class reads 7) or before it (5, the run's
    own write after the <clinit>)."""
    base2, util = "Lcom/huntress/Base2;", "Lcom/huntress/Util;"

    def body(a, d):
        fx = d.f(K, "J", "X")
        kc = d.cls(K)
        kc.sfields.append((fx, ACC_PUBLIC | ACC_STATIC))
        sa = S.Asm()
        sput(sa, 0x68, 1, fx)                   # setX(long): p0 = v1:v2 (regs 3, ins 2)
        ret(sa, 0x0e, 0)
        kc.direct.append((d.m(K, "setX", "VJ"), ACC_PUBLIC | ACC_STATIC, method(sa.finish(), 3, 2)))

        def trig():
            if trigger == "forname":
                a.const_string(2, d.s("com.huntress.Other"))
                a.invoke(0x71, d.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING]), [2])
            elif trigger == "super":
                uc = d.cls(util, sup=base2)
                ua = S.Asm()
                ret(ua, 0x0e, 0)
                uf = d.m(util, "f", "V")
                uc.direct.append((uf, ACC_PUBLIC | ACC_STATIC, method(ua.finish(), 1, 0)))
                a.invoke(0x71, uf, [])
            else:
                a.const4(2, 1)
                sput(a, 0x67, 2, d.f(OTHERC, "I", "Y"))
        if order == "before":
            trig()
        a.const_wide(0, 5)
        sput(a, 0x68, 0, fx)
        if order == "after":
            trig()
        sget(a, 0x61, 0, fx)
    d2 = DexB()
    for desc in (OTHERC, base2):
        c2 = d2.cls(desc)
        if desc == OTHERC:
            c2.sfields.append((d2.f(OTHERC, "I", "Y"), ACC_PUBLIC | ACC_STATIC))
        ca = S.Asm()
        ca.const_wide(0, 7)
        ca.invoke(0x71, d2.m(K, "setX", "VJ"), [0, 1])
        ret(ca, 0x0e, 0)
        c2.direct.append((d2.m(desc, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
    return pkg(classes_dex=chain(body), classes2_dex=d2.build())


def iface_pkg(kind):
    """K.X written by the chain (5), then Impl.f() (an invoke-static that initializes Impl, which implements I), then
    the read. 'default': I (this dex) declares a default method and a <clinit> that calls K.setX(7), so a device
    initializes I with Impl (JLS 12.4.2 step 7); 'plain': I declares no default method (not initialized with Impl: the
    run's own 5); 'other': I is an interface of classes2.dex (what its <clinit> does is not known here)."""
    ifc, impl = "Lcom/huntress/I;", "Lcom/huntress/Impl;"

    def body(a, d):
        fx = d.f(K, "J", "X")
        kc = d.cls(K)
        kc.sfields.append((fx, ACC_PUBLIC | ACC_STATIC))
        sa = S.Asm()
        sput(sa, 0x68, 1, fx)
        ret(sa, 0x0e, 0)
        setx = d.m(K, "setX", "VJ")
        kc.direct.append((setx, ACC_PUBLIC | ACC_STATIC, method(sa.finish(), 3, 2)))
        if kind == "other":
            d.t(ifc)
        else:
            ic = d.cls(ifc, acc=ACC_PUBLIC | 0x200 | 0x400)
            ca = S.Asm()
            ca.const_wide(0, 7)
            ca.invoke(0x71, setx, [0, 1])
            ret(ca, 0x0e, 0)
            ic.direct.append((d.m(ifc, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
            if kind == "default":
                da = S.Asm()
                ret(da, 0x0e, 0)
                ic.virtual.append((d.m(ifc, "hello", "V"), ACC_PUBLIC, method(da.finish(), 1, 1)))
            else:
                ic.virtual.append((d.m(ifc, "hello", "V"), ACC_PUBLIC | 0x400, None))
        mc = d.cls(impl)
        mc.ifaces.append(ifc)
        fa = S.Asm()
        ret(fa, 0x0e, 0)
        f = d.m(impl, "f", "V")
        mc.direct.append((f, ACC_PUBLIC | ACC_STATIC, method(fa.finish(), 1, 0)))
        a.const_wide(0, 5)
        sput(a, 0x68, 0, fx)
        a.invoke(0x71, f, [])
        sget(a, 0x61, 0, fx)
    parts = {"classes_dex": chain(body)}
    if kind == "other":
        d2 = DexB()
        d2.cls(ifc, acc=ACC_PUBLIC | 0x200 | 0x400)
        parts["classes2_dex"] = d2.build()
    return pkg(**parts)


def sibling_refl_pkg(decoy=True):
    """classes.dex: K.SEED from K.<clinit>, read by the chain. classes2.dex: Init.poke() reaches Field.setLong through
    Method.invoke (Class.forName("java.lang.reflect.Field").getMethod("setLong", ...)): a field write with no field or
    Field.set* reference there. The control's poke() invokes an app method reflectively instead."""
    def body(a, d):
        _kc, fs = seed_class(d)
        sget(a, 0x61, 0, fs)
    d2 = DexB()
    ini = "Lcom/huntress/Init;"
    ic = d2.cls(ini)
    ma = S.Asm()
    ma.const_string(0, d2.s("java.lang.reflect.Field" if decoy else "com.huntress.Init"))
    ma.invoke(0x71, d2.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING]), [0])
    ma.move_result_object(0)
    ma.const_string(1, d2.s("setLong" if decoy else "poke"))
    ma.const4(2, 0)
    ma.invoke(0x6e, d2.m(CLASS, "getMethod", "LLL", ret=METHOD, params=[STRING, CLS_ARR]), [0, 1, 2])
    ma.move_result_object(0)
    ma.const4(1, 0)
    ma.invoke(0x6e, d2.m(METHOD, "invoke", "LLL", ret=OBJ, params=[OBJ, OBJ_ARR]), [0, 1, 2])
    ret(ma, 0x0e, 0)
    ic.direct.append((d2.m(ini, "poke", "V"), ACC_PUBLIC | ACC_STATIC, method(ma.finish(), 4, 0)))
    return pkg(classes_dex=chain(body), classes2_dex=d2.build())


def held_into_marked_dex():
    """K1.<clinit>: HOLDER = new long[1][]; K2.<clinit> (run by the chain's K2.f()) puts a new long[]{7} into
    K1.HOLDER[0]. The chain sums K1.HOLDER[0][0]: the object the later <clinit> put into a held one is covered by the
    holder's contents check (K2.<clinit> writes into K1's object outside K1.<clinit>)."""
    k1, k2 = "Lcom/huntress/K1;", "Lcom/huntress/K2;"

    def body(a, d):
        fh = d.f(k1, "[[J", "HOLDER")
        c1 = d.cls(k1)
        c1.sfields.append((fh, ACC_PUBLIC | ACC_STATIC | ACC_FINAL))
        ca = S.Asm()
        ca.const4(0, 1)
        ca.new_array(1, 0, d.t("[[J"))
        sput(ca, 0x69, 1, fh)
        ret(ca, 0x0e, 0)
        c1.direct.append((d.m(k1, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        c2 = d.cls(k2)
        cb = S.Asm()
        cb.const4(0, 1)
        cb.new_array(1, 0, d.t("[J"))
        cb.const_wide(2, 7)
        cb.const4(4, 0)
        cb.aput(0x4c, 2, 1, 4)
        sget(cb, 0x62, 5, fh)
        cb.aput(0x4d, 1, 5, 4)
        ret(cb, 0x0e, 0)
        c2.direct.append((d.m(k2, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(cb.finish(), 6, 0)))
        fa = S.Asm()
        ret(fa, 0x0e, 0)
        f2 = d.m(k2, "f", "V")
        c2.direct.append((f2, ACC_PUBLIC | ACC_STATIC, method(fa.finish(), 1, 0)))
        sget(a, 0x62, 8, fh)                    # K1.<clinit> runs, HOLDER read (marked, its check holds so far)
        a.invoke(0x71, f2, [])                  # K2.<clinit> puts long[]{7} into HOLDER[0]
        sget(a, 0x62, 8, fh)
        a.const4(2, 0)
        a.aget(0x46, 3, 8, 2)
        a.aget(0x45, 0, 3, 2)
    return chain(body)


class FastDexB(DexB):
    """DexB with dict-backed indexes (its list lookups are quadratic for thousands of classes)."""

    def __init__(self):
        super().__init__()
        self._si, self._ti, self._pi, self._fi, self._mi = {}, {}, {}, {}, {}

    def s(self, t):
        i = self._si.get(t)
        if i is None:
            i = self._si[t] = len(self.strings)
            self.strings.append(t)
        return i

    def t(self, d):
        self.s(d)
        i = self._ti.get(d)
        if i is None:
            i = self._ti[d] = len(self.types)
            self.types.append(d)
        return i

    def proto(self, shorty, ret=None, params=None):
        ret = ret or tdesc(shorty[0])
        params = tuple(params) if params is not None else tuple(tdesc(c) for c in shorty[1:])
        self.s(shorty)
        self.t(ret)
        for p in params:
            self.t(p)
        k = (shorty, ret, params)
        i = self._pi.get(k)
        if i is None:
            i = self._pi[k] = len(self.protos)
            self.protos.append(k)
        return i

    def m(self, cls, name, shorty, ret=None, params=None):
        self.t(cls)
        self.s(name)
        k = (cls, name, self.proto(shorty, ret, params))
        i = self._mi.get(k)
        if i is None:
            i = self._mi[k] = len(self.methods)
            self.methods.append(k)
        return i

    def f(self, cls, ftype, name):
        self.t(cls)
        self.t(ftype)
        self.s(name)
        k = (cls, ftype, name)
        i = self._fi.get(k)
        if i is None:
            i = self._fi[k] = len(self.fields)
            self.fields.append(k)
        return i

    def build(self):
        si, ti = self._si, self._ti

        class Indexed(list):
            def __init__(self, items, idx):
                super().__init__(items)
                self._idx = idx

            def index(self, x, *_a):
                return self._idx[x]
        self.strings = Indexed(self.strings, si)
        self.types = Indexed(self.types, ti)
        return DexB.build(self)


def many_clinits_dex(n, entries, mode):
    """n classes Ki, each with a <clinit> that makes int[1] into Ki.A; C.touch() touches them all ('invoke':
    invoke-static Ki.f(); 'sget': sget-object Ki.A); `entries` ANS entries each call touch() and return 0x1000 + e
    (review of 5ffe7f3's perf probe)."""
    d = FastDexB()
    cc = d.cls(C)
    touch = d.m(C, "touch", "V")
    ta = S.Asm()
    for i in range(n):
        k = "Lcom/huntress/K%d;" % i
        kc = d.cls(k)
        fa = d.f(k, "[I", "A")
        kc.sfields.append((fa, ACC_STATIC))
        ca = S.Asm()
        ca.const4(0, 1)
        ca.new_array(1, 0, d.t("[I"))
        sput(ca, 0x69, 1, fa)
        ret(ca, 0x0e, 0)
        kc.direct.append((d.m(k, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        if mode == "invoke":
            fm = d.m(k, "f", "V")
            fb_ = S.Asm()
            ret(fb_, 0x0e, 0)
            kc.direct.append((fm, ACC_PUBLIC | ACC_STATIC, method(fb_.finish(), 1, 0)))
            ta.invoke(0x71, fm, [])
        else:
            sget(ta, 0x62, 0, fa)
    ret(ta, 0x0e, 0)
    cc.direct.append((touch, ACC_PUBLIC | ACC_STATIC, method(ta.finish(), 2, 0)))
    for e in range(entries):
        a = S.Asm()
        a.invoke(0x71, touch, [])
        a.const_wide(0, 0x1000 + e)
        S.emit_tail_format(a, d, 0, "ANS-%016X")
        cc.direct.append((d.m(C, "run%d" % e, "L", ret=STRING), ACC_PUBLIC | ACC_STATIC, (a.finish(), 24, 0, 5)))
    return d.build()


def padded_dex(pad, salt):
    """An entry that returns code(7 + salt) through a private helper, beside a never-run method of `pad` distinct code
    units (review of 5ffe7f3's memory probe)."""
    d = DexB()
    cc = d.cls(C)
    h = d.m(C, "h", "J")
    ha = S.Asm()
    ha.const_wide(0, 7 + salt)
    ret(ha, 0x10, 0)
    cc.direct.append((h, ACC_PRIVATE | ACC_STATIC, method(ha.finish(), 2, 0)))
    body = []
    for i in range(pad // 2):
        body += [0x13 | (1 << 8), (i * 7 + salt) & 0xFFFF]
    cc.direct.append((d.m(C, "pad", "V"), ACC_PUBLIC | ACC_STATIC, method(body + [0x000e], 2, 0)))
    a = S.Asm()
    a.invoke(0x71, h, [])
    a.move_result_wide(0)
    S.emit_tail_format(a, d, 0, "ANS-%016X")
    cc.direct.append((d.m(C, "run", "L", ret=STRING), ACC_PUBLIC | ACC_STATIC, (a.finish(), 24, 0, 5)))
    return d.build()


def section_review4():
    # R1 / R1b: another dex member reaches a <clinit>'s object through a public getter or an override
    m1 = pkg(classes_dex=r1_classes_dex(), classes2_dex=r1_classes2_dex(True))
    declines_pkg("R4 R1 classes2's App.onCreate writes K.getKey()[0] = 99 (a device sums 0x7A)", m1,
                 "another dex member")
    declines_pkg("R4 R1 control: classes2 never touches it (the scan of classes.dex cannot tell, so it declines too)",
                 pkg(classes_dex=r1_classes_dex(), classes2_dex=r1_classes2_dex(False)), "another dex member")
    expect("R4 R1 control: the same classes.dex alone (its getter's callers all followed) answers", r1_classes_dex(),
           code(26), key=KS)
    declines_pkg("R4 R1b Sub.process of classes2 overrides Base.process and writes KEY[0] = 99", r1b_dexes(),
                 "another dex member")
    # R2: a chain-written static beside a library whose JNI_OnLoad the ELF readers miss
    so0 = elf64_size0_so()
    check("R4 R2 fixture: _parse_so misses a JNI_OnLoad with st_size 0 and finds it with its size",
          "JNI_OnLoad" not in dcc._parse_so(so0) and "JNI_OnLoad" in dcc._parse_so(mini_so(["JNI_OnLoad"])))
    for in_clinit in (False, True):
        where = "B.<clinit>" if in_clinit else "the chain"
        declines_pkg("R4 R2 an ELF32 libh.so (JNI_OnLoad sets A.X = 7), loaded in %s after A.X = 5" % where,
                     pkg(classes_dex=r2_dex(in_clinit), lib__armeabi_v7a__libh_so=elf32_so()), "tainted")
    declines_pkg("R4 R2 an ELF64 libh.so whose JNI_OnLoad has st_size 0", pkg(classes_dex=r2_dex(),
                                                                                lib__x86_64__libh_so=so0), "tainted")
    answers_pkg("R4 R2 control: A.X = 5, then a public NDK library the package does not ship (liblog, the system's "
                "own): the store is not tainted", pkg(classes_dex=r2_dex(lib_name="log")), code(5), KS)
    # R3: a constructor of a class of another dex member (no body here)
    d1, d2 = r3_dexes(in_clinit=True)
    declines_pkg("R4 R3 K.<clinit> stores new Sub() (classes2.dex: its <init> sets n = 42); the chain reads K.INST.n",
                 pkg(classes_dex=d1, classes2_dex=d2), "does not define")
    d1, d2 = r3_dexes(in_clinit=False)
    declines_pkg("R4 R3b the chain itself makes new Sub() of classes2.dex and reads n", pkg(classes_dex=d1,
                                                                                             classes2_dex=d2),
                 "does not define")
    check("R4 R3b ... the VM before this build answered 0, a WRONG plain under the judged key (the device: 42)",
          old_vm_codes(d1) == [code(0)], old_vm_codes(d1))
    dex = super_init_dex()
    expect_none("R4 R3 Sub (this dex) calls the constructor of its superclass of another dex (no body here)", dex,
                reason="has no body in this dex")
    check("R4 R3 ... the VM before this build made that constructor a no-op", old_vm_codes(dex) == [code(1)],
          old_vm_codes(dex))
    dex = suffix_dex()
    expect_none("R4 R3 an app class MyInteger with no body here: never Integer.valueOf by the end of its name", dex,
                reason="has no body in this dex")
    check("R4 R3 ... the VM before this build took it for Integer.valueOf", old_vm_codes(dex) == [code(5)],
          old_vm_codes(dex))
    # R4: Class.forName of a class only a dex the app class loader does not open defines
    for where in ("assets/payload.dex", "assets/classes2.dex", "lib/classes2.dex"):
        declines_pkg("R4 R4 Class.forName(\"com.payload.Boot\"), Boot only in %s (ClassNotFoundException)" % where,
                     S.member_map(S.apk({"classes.dex": forname_dex("com.payload.Boot"), where: payload_dex()})),
                     "absent")
    declines_pkg("R4 R4 Boot only in classes3.dex with no classes2.dex (ART opens classes2.dex first and stops at a gap)",
                 S.member_map(S.apk({"classes.dex": forname_dex("com.payload.Boot"), "classes3.dex": payload_dex()})),
                 "absent")
    m4 = S.member_map(S.apk({"classes.dex": forname_dex("com.payload.Boot"), "classes2.dex": payload_dex()}))
    c4, d4 = dcc.analysis_codes_ex(m4)
    with private_ledger((K0, dcc.ROUTE)):
        p4 = plain_of(dcc.answer(Q, m4))
    check("R4 R4 control: Boot in classes2.dex (on the app class loader's path): the device's code under the judged key",
          c4 == [code(0xDEC0)] and d4 == 0 and p4 == code(0xDEC0), (c4, d4, p4))
    for desc, why in (("Lde/robv/android/xposed/XposedBridge;", "NoClassDefFoundError"),):
        expect_none("R4 R4 const-class of a class nothing here defines (%s)" % desc, constclass_dex(desc), reason=why)
    declines_pkg("R4 R4 const-class of Boot, only in assets/payload.dex",
                 S.member_map(S.apk({"classes.dex": constclass_dex(BOOT), "assets/payload.dex": payload_dex()})),
                 "NoClassDefFoundError")
    expect("R4 R4 control: const-class of the dex's own class", constclass_dex(C), code(0xDEC2), key=KR)
    expect("R4 R4 control: const-class of a core framework class", constclass_dex(STRING), code(0xDEC2), key=KR)
    # R5: a method lookup with no invoke after it
    expect_none("R4 R5 getDeclaredMethod(\"hookedCheck\") of a class that declares none, no invoke after it",
                lookup_dex("missing"), reason="NoSuchMethodException")
    expect_none("R4 R5 getMethod of a private method (getMethod finds public methods only)",
                lookup_dex("getmethod-private"), reason="NoSuchMethodException")
    expect("R4 R5 control: getDeclaredMethod(\"run\") of the class itself, no invoke: the judged key",
           lookup_dex("present"), code(0xDEC1), key=K0)
    # R6: a reflection token a <clinit> stored in a static is mutable (setAccessible)
    expect_none("R4 R6 App.onCreate toggles K.M.setAccessible(false); the chain invokes K.M (IllegalAccessException on "
                "a device)", token_dex(True), reason="may be written outside its <clinit>")
    never_plain("R4 R6 ...", members(token_dex(True)), ACCEPT_MORE)
    expect_none("R4 R6 control: no toggle anywhere still declines (the chain's own Method.invoke of the token is no "
                "known reader: a decline, never a value)", token_dex(False), reason="may be written outside")
    # code of another dex member that runs DURING the chain: a value the run stored before it is stale
    for trigger in ("forname", "super", "sput"):
        declines_pkg("R4 unseen <clinit>: A.X = 5, then %s of a class of classes2.dex (its <clinit> sets 7), then the "
                     "read" % trigger, unseen_pkg(trigger, "after"), "since then")
        answers_pkg("R4 unseen <clinit> control: %s BEFORE the chain's write: the run's own write (5)" % trigger,
                    unseen_pkg(trigger, "before"), code(5), KS)
    declines_pkg("R4 unseen <clinit>: a superinterface with a default method and a <clinit> (initialized with the "
                 "class on a device) runs after the chain's write", iface_pkg("default"), "since then")
    declines_pkg("R4 unseen <clinit>: a superinterface of classes2.dex", iface_pkg("other"), "since then")
    answers_pkg("R4 unseen <clinit> control: a superinterface with no default method is not initialized with the class",
                iface_pkg("plain"), code(5), KS)
    # reflection on reflection in another dex member
    declines_pkg("R4 classes2.dex reaches Field.setLong through Method.invoke (no Field.set* reference there)",
                 sibling_refl_pkg(True), "another dex")
    answers_pkg("R4 ... control: classes2.dex invokes an app method reflectively", sibling_refl_pkg(False),
                code(DECOY), KS)
    expect_none("R4 an object a later <clinit> puts into a held one: the holder's contents check declines",
                held_into_marked_dex(), reason="may be written outside its <clinit>")
    # perf: the walks and analyses are charged to the step budget (TOTAL_STEPS bounds them)
    vm = dcc.VM(dcc.Dex(chain_int_to_float_rne()[0]))
    vm.max_steps = 10
    try:
        DF._charge(vm, 11)
        charged = False
    except dcc._Decline as e:
        charged = "step budget" in str(e)
    check("R4 perf: _charge counts against the VM's step budget and declines past it", charged)
    for n, entries, mode, bound in ((2000, 4, "invoke", 1.0), (2000, 4, "sget", 2.0), (8000, 1, "invoke", 1.0)):
        dex = many_clinits_dex(n, entries, mode)
        t = time.time()
        got, dcl = dcc.codes_in_dex_ex(dex)
        el = time.time() - t
        want = [code(0x1000 + e) for e in range(entries)]
        check("R4 perf: %d <clinit>s, %d entries (%s) in %.2f s (bound %.1f s; 11 to 29 s before)" % (
              n, entries, mode, el, bound), el < bound and all(c in want for c in got), (el, got, dcl))
        if mode == "invoke":
            check("R4 perf: ... every entry answers (%s)" % mode, got == want and dcl == 0, (got, dcl))
    dex, _w = table_dex()
    vm1 = dcc.VM(dcc.Dex(dex))
    ci1 = DF._ci(vm1.dex)
    fk = (K, "TABLE", "[J")
    ex = frozenset({ci1.cls[K].clinit})
    r1 = DF._scan(vm1).contents_mutable(fk, ex)
    r1b = DF._scan(vm1).contents_mutable(fk, ex)
    DF._CI_CACHE.clear()
    vm2 = dcc.VM(dcc.Dex(dex))
    r2 = DF._scan(vm2).contents_mutable(fk, ex)
    check("R4 perf: an escape analysis's cost is the same cached or not (the budget charged never depends on the "
          "process's history)", r1 == r1b == r2 and r1[1] > 0, (r1, r1b, r2))
    saved_work = DF.ESCAPE_WORK
    try:
        DF.ESCAPE_WORK = 5
        DF._CI_CACHE.clear()
        vm3 = dcc.VM(dcc.Dex(dex))
        r3 = DF._scan(vm3).contents_mutable(fk, ex)
    finally:
        DF.ESCAPE_WORK = saved_work
        DF._CI_CACHE.clear()
    check("R4 perf: an analysis past ESCAPE_WORK stops and counts as \"may write\"", r3[0] is True, r3)
    # memory: nothing of a Dex outlives its call
    import gc
    import tracemalloc
    small = chain_static_values()[0]
    dx = dcc.Dex(small)
    ci_ = DF._ci(dx)
    rdx = weakref.ref(dx)
    del dx
    gc.collect()
    check("R4 memory: the class-index cache keeps no Dex alive (it holds its Dex weakly)",
          rdx() is None and ci_ in DF._CI_CACHE.values(), rdx())
    vmx = dcc.VM(dcc.Dex(small))
    DF._vs(vmx)
    rvm = weakref.ref(vmx)
    del vmx
    gc.collect()
    check("R4 memory: the hooks' hot path keeps no VM (nor its Dex) alive", rvm() is None and DF._LAST[0]() is None)
    gc.collect()
    tracemalloc.start()
    base_mem = tracemalloc.get_traced_memory()[0]
    for salt in range(3):
        big = padded_dex(150_000, salt)
        got, _d = dcc.codes_in_dex_ex(big)
        del big
    gc.collect()
    kept = tracemalloc.get_traced_memory()[0] - base_mem
    tracemalloc.stop()
    check("R4 memory: three dexes of 150,000 code units keep %.1f MB after their calls (80 MB each before)" % (
          kept / 2 ** 20), kept < 4 * 2 ** 20 and got == [code(9)], (kept, got))
    check("R4 memory: the class-index cache holds at most two dexes, none past _CI_MAX_UNITS code units",
          len(DF._CI_CACHE) <= DF._CI_KEEP, len(DF._CI_CACHE))
    cache = {}
    DF._cache_put(cache, "a", 1, keep=2)
    DF._cache_put(cache, "b", 2, keep=2)
    DF._cache_get(cache, "a")
    DF._cache_put(cache, "c", 3, keep=2)
    check("R4 memory: the caches drop the least recently used entry", sorted(cache) == ["a", "c"], cache)


# ============================================================================ the plain path and the old VM
def section_plain_and_legacy():
    # accept the new route in the PRIVATE ledger: the code is then plain, and only ever the oracle
    labels.learn(KF, dcc.ROUTE + "+dex-float", "accepted", scope="key")
    dex, want = chain_float()
    ans = dcc.answer(Q, members(dex))
    check("P +dex-float accepted in the private ledger: the oracle code goes plain", plain_of(ans) == code(want), ans)
    # a float chain's code under the JUDGED key alone stays unsure (the judged key never answers it)
    labels.learn(K0, dcc.ROUTE, "accepted", scope="key")
    dex, want = chain_nan_bits()
    ans2 = dcc.answer(Q, members(dex))
    check("P a NaN chain under the +dex-float key: plain only because that name is accepted",
          plain_of(ans2) == code(want), ans2)
    dex, _w = clinit_seed_dex()
    ans3 = dcc.answer(Q, members(dex))
    check("P a static chain is NOT plain under the accepted analysis or analysis+dex-float names",
          plain_of(ans3) is None and labels.is_unsure(ans3), ans3)
    # without the module the VM declines what it declined before (fail-closed float), never a different code
    saved = dcc._dfl
    try:
        dcc._dfl = None
        old = dcc.codes_in_dex_ex(chain_float()[0])
        check("P the VM without dex_float declines a float special (as before)", old[0] == [], old)
        old2 = dcc.codes_in_dex_ex(chain_int_to_float_rne()[0])
        check("P ... and computes a legacy float chain to the same code", old2[0] == [code(16777216)], old2)
    finally:
        dcc._dfl = saved


def section_speed():
    t = time.time()
    n = 0
    for fn in (chain_float, chain_math, chain_static_values, chain_super_init):
        dex = fn()[0]
        for _ in range(10):
            dcc.codes_in_dex_ex(dex)
            n += 1
    per = (time.time() - t) / n
    check("S a specimen solves in under 50 ms (%.2f ms)" % (per * 1000), per < 0.050, per)


def r5_escape_dex(via_sub=True, sub_ifaces=True):
    """Final review of aa8a367: another method reaches a <clinit>-built static array through an sget-object whose
    field reference names a subclass with interfaces (the scan's resolve() gives None there), and writes into it.
    On a device that method may run before the chain, so the array's contents depend on what ran first."""
    acc_public, acc_static, acc_abstract = 0x1, 0x8, 0x400
    k_cls, sub_cls, m_cls = "Lcom/huntress/K;", "Lcom/huntress/Sub;", "Lcom/huntress/M;"
    d = DexB()
    a = S.Asm()
    cc = d.cls(C)
    kc = d.cls(k_cls)
    sc = d.cls(sub_cls, acc_public | acc_abstract, k_cls)
    if sub_ifaces:
        d.t("Ljava/lang/Runnable;")
        sc.ifaces = ["Ljava/lang/Runnable;"]
    mc = d.cls(m_cls)
    arrf = d.f(k_cls, "[I", "arr")
    kc.sfields.append((arrf, acc_public | acc_static))
    cl = d.m(k_cls, "<clinit>", "V")
    ka = S.Asm()
    ka.const4(0, 4)
    ka.new_array(1, 0, d.t("[I"))
    ka.const16(2, 0x77)
    ka.const4(3, 0)
    ka.aput(0x4b, 2, 1, 3)                  # v1[0] = 0x77
    ka.u += [0x69 | (1 << 8), arrf]          # sput-object v1, K.arr
    ka.u.append(0x0e)
    kc.direct.append((cl, acc_static | 0x10000, (ka.finish(), 4, 0, 0)))
    subf = d.f(sub_cls if via_sub else k_cls, "[I", "arr")
    pm = d.m(m_cls, "poison", "V")
    pa = S.Asm()
    pa.u += [0x62 | (0 << 8), subf]          # sget-object v0, Sub.arr (or K.arr)
    pa.const16(1, 0x99)
    pa.const4(2, 0)
    pa.aput(0x4b, 1, 0, 2)                  # v0[0] = 0x99
    pa.u.append(0x0e)
    mc.direct.append((pm, acc_public | acc_static, (pa.finish(), 3, 0, 0)))
    a.u += [0x62 | (4 << 8), arrf]           # the entry reads K.arr[0]
    a.const4(3, 0)
    a.aget(0x44, 5, 4, 3)
    a.unop(0x81, 0, 5)                      # int-to-long v0, v5
    S.emit_tail_format(a, d, 0, "ANS-%016X")
    run = d.m(C, "run", "L", ret=STRING)
    cc.direct.append((run, acc_public | acc_static, (a.finish(), 24, 0, 5)))
    return d.build()


def section_review5():
    # Final review of aa8a367 (issue 1): an unresolved sget-object (a subclass with interfaces) is a holder alias the
    # escape scan does not follow, so its static object is declined (it was unsure under +dex-static: latent wrong plain)
    for label, dex in (("R5 Sub implements Runnable: the write through Sub.arr is not followed -> None",
                        r5_escape_dex(via_sub=True, sub_ifaces=True)),
                       ("R5 control: the write through K.arr (resolves) -> None", r5_escape_dex(via_sub=False)),
                       ("R5 control: Sub without interfaces -> None", r5_escape_dex(via_sub=True, sub_ifaces=False))):
        ans = dcc.answer(Q, members(dex))
        check(label, ans is None, ans)


# ============================================================================ Z. the residuals of KB-7 (dexfloat-residuals)
# The two WRONG-plain residuals the KB-7 rule paragraph left open, the same on the tree before: (1) classes under
# Lkotlin/ were the framework's, so a constructor of such a class that another dex of the delivery defines read as a
# no-op; (2) Class.forName(name, initialize, null), the bootstrap loader, resolved an app class. Each repro below was a
# WRONG plain on af3dbf7 (the armed tree): kb7_rule() puts the KB-7 tree's rules back for the "before" column. The
# adversarial pass of the fix added the shapes beside them (a boot package's class a dex of the delivery defines, a
# ClassLoader other than null, a superinterface, a class modelled by the end of its name, a framework object's field)
# and the split reading's versions (split_bundle.SplitVM runs on the base VM's semantics).
LOADER = "Ljava/lang/ClassLoader;"
FORNAME3 = ("LLZL", CLASS, [STRING, "Z", LOADER])


@contextlib.contextmanager
def kb7_rule():
    """The KB-7 tree's rules for one block: Lkotlin/ in the framework set and no class of the delivery checked, no
    boot-shadow check, the forName loader ignored, the suffix models for any class, an unwritten field read as 0."""
    names = ("_framework", "_boot_shadow", "_shadows", "_forname_loader", "_suffix_guard", "_spec_guard", "iget_unset",
             "iget_alias", "_base_invoke", "split_body", "init_catchall", "_super_target_ok", "_null_ref",
             "_runtime_class_known", "split_reflect_access")
    saved = {n: getattr(DF, n) for n in names}
    DF._framework = lambda vm, desc: desc.startswith(DF._FRAMEWORK_KB7)
    DF._boot_shadow = lambda desc: False
    DF._shadows = lambda vm: []
    DF._forname_loader = lambda *a: None
    DF._suffix_guard = lambda *a: None
    DF._spec_guard = lambda *a: None
    DF.iget_unset = lambda vm, obj, fid: 0
    DF.iget_alias = lambda vm, obj, fid: None
    DF._base_invoke = lambda *a: (False, None)
    DF.split_body = lambda *a: None
    DF.init_catchall = lambda *a: None
    DF._super_target_ok = lambda *a: None
    DF._null_ref = lambda v: False
    DF._runtime_class_known = lambda *a: None
    DF.split_reflect_access = lambda *a: None
    try:
        yield
    finally:
        for n, f in saved.items():
            setattr(DF, n, f)


def kb7_codes(m):
    with kb7_rule():
        return dcc.analysis_codes_ex(m)[0]


def kb7_codes_nocast(m):
    with kb7_rule(), patched_attr(DF, "check_cast", lambda *a: None):
        return dcc.analysis_codes_ex(m)[0]


@contextlib.contextmanager
def patched_attr(obj, name, value):
    saved = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, saved)


def rz_ctor_dex(holder, k=42):
    """A dex that defines `holder` with a long field n its constructor sets to k."""
    d = DexB()
    hc = d.cls(holder)
    fn = d.f(holder, "J", "n")
    hc.ifields.append((fn, 0))
    ia = S.Asm()
    ia.const_wide(0, k)
    ia.iop(0x5a, 0, 2, fn)
    ret(ia, 0x0e, 0)
    hc.direct.append((d.m(holder, "<init>", "V"), ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 3, 1)))
    return d.build()


def rz_new_read(holder, define_here=False, k=42):
    """The chain: v8 = new holder(); v0:v1 = v8.n (holder defined in this dex too when `define_here`)."""
    def body(a, d):
        fn = d.f(holder, "J", "n")
        if define_here:
            hc = d.cls(holder)
            hc.ifields.append((fn, 0))
            ia = S.Asm()
            ia.const_wide(0, k)
            ia.iop(0x5a, 0, 2, fn)
            ret(ia, 0x0e, 0)
            hc.direct.append((d.m(holder, "<init>", "V"), ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 3, 1)))
        a.new_instance(8, d.t(holder))
        a.invoke(0x70, d.m(holder, "<init>", "V"), [8])
        a.iop(0x53, 0, 8, fn)
    return chain(body)


def rz_holder_pkg(holder="Lkotlin/Holder;", where="classes2.dex"):
    return S.member_map(S.apk({"classes.dex": rz_new_read(holder), where: rz_ctor_dex(holder)}))


def rz_super_pkg(base="Lkotlin/Base;", sub=SUBC):
    """Sub (classes.dex) extends `base` (classes2.dex); Sub.<init> calls base.<init> (n = 42 on a device); the chain
    reads new Sub().n."""
    def body(a, d):
        fn = d.f(base, "J", "n")
        sc = d.cls(sub, sup=base)
        ia = S.Asm()
        ia.invoke(0x70, d.m(base, "<init>", "V"), [2])
        ret(ia, 0x0e, 0)
        si = d.m(sub, "<init>", "V")
        sc.direct.append((si, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 3, 1)))
        a.new_instance(8, d.t(sub))
        a.invoke(0x70, si, [8])
        a.iop(0x53, 0, 8, fn)
    return pkg(classes_dex=chain(body), classes2_dex=rz_ctor_dex(base))


def rz_valueof_chain(myi):
    def body(a, d):
        a.const4(2, 5)
        a.invoke(0x71, d.m(myi, "valueOf", "LI", ret=INTEGER, params=["I"]), [2])
        a.move_result_object(3)
        a.invoke(0x6e, d.m(INTEGER, "intValue", "I"), [3])
        a.move_result(4)
        a.unop(0x81, 0, 4)
    return chain(body)


def rz_suffix_pkg(myi="Lkotlin/x/MyInteger;", define=True):
    """myi.valueOf(5): classes2.dex defines it as Integer.valueOf(p0 + 1) (a device: 6), or no dex defines it."""
    if not define:
        return pkg(classes_dex=rz_valueof_chain(myi))
    d2 = DexB()
    mc = d2.cls(myi)
    va = S.Asm()
    va.u += [0xd8, (1 << 8) | 1]                    # add-int/lit8 v0, v1, #1
    va.invoke(0x71, d2.m(INTEGER, "valueOf", "LI", ret=INTEGER, params=["I"]), [0])
    va.move_result_object(0)
    va.return_object(0)
    mc.direct.append((d2.m(myi, "valueOf", "LI", ret=INTEGER, params=["I"]), ACC_PUBLIC | ACC_STATIC,
                      method(va.finish(), 2, 1)))
    return pkg(classes_dex=rz_valueof_chain(myi), classes2_dex=d2.build())


def rz_unseen_pkg(other="Lkotlin/Other;"):
    """The chain stores K.X = 5, then Class.forName(<other>) (classes2.dex: its <clinit> calls K.setX(7)), then reads
    K.X (a device: 7)."""
    def body(a, d):
        fx = d.f(K, "J", "X")
        kc = d.cls(K)
        kc.sfields.append((fx, ACC_PUBLIC | ACC_STATIC))
        sa = S.Asm()
        sput(sa, 0x68, 1, fx)
        ret(sa, 0x0e, 0)
        kc.direct.append((d.m(K, "setX", "VJ"), ACC_PUBLIC | ACC_STATIC, method(sa.finish(), 3, 2)))
        a.const_wide(0, 5)
        sput(a, 0x68, 0, fx)
        a.const_string(2, d.s(other[1:-1].replace("/", ".")))
        a.invoke(0x71, d.m(CLASS, "forName", "LL", ret=CLASS, params=[STRING]), [2])
        sget(a, 0x61, 0, fx)
    d2 = DexB()
    c2 = d2.cls(other)
    ca = S.Asm()
    ca.const_wide(0, 7)
    ca.invoke(0x71, d2.m(K, "setX", "VJ"), [0, 1])
    ret(ca, 0x0e, 0)
    c2.direct.append((d2.m(other, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
    return pkg(classes_dex=chain(body), classes2_dex=d2.build())


def rz_iface_pkg(ifc="Lkotlin/I;", other_dex=False):
    """The chain stores K.X = 5, calls Impl.f() (Impl implements `ifc`, which declares a default method and a <clinit>
    calling K.setX(7): a device initializes it with Impl), then reads K.X (a device: 7). `ifc` in this dex, or in
    classes2.dex."""
    impl = "Lcom/huntress/Impl;"

    def iface(d):
        ic = d.cls(ifc, acc=ACC_PUBLIC | 0x200 | 0x400)
        ca = S.Asm()
        ca.const_wide(0, 7)
        ca.invoke(0x71, d.m(K, "setX", "VJ"), [0, 1])
        ret(ca, 0x0e, 0)
        ic.direct.append((d.m(ifc, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        da = S.Asm()
        ret(da, 0x0e, 0)
        ic.virtual.append((d.m(ifc, "hello", "V"), ACC_PUBLIC, method(da.finish(), 1, 1)))

    def body(a, d):
        fx = d.f(K, "J", "X")
        kc = d.cls(K)
        kc.sfields.append((fx, ACC_PUBLIC | ACC_STATIC))
        sa = S.Asm()
        sput(sa, 0x68, 1, fx)
        ret(sa, 0x0e, 0)
        kc.direct.append((d.m(K, "setX", "VJ"), ACC_PUBLIC | ACC_STATIC, method(sa.finish(), 3, 2)))
        if other_dex:
            d.t(ifc)
        else:
            iface(d)
        mc = d.cls(impl)
        mc.ifaces.append(ifc)
        fa = S.Asm()
        ret(fa, 0x0e, 0)
        f = d.m(impl, "f", "V")
        mc.direct.append((f, ACC_PUBLIC | ACC_STATIC, method(fa.finish(), 1, 0)))
        a.const_wide(0, 5)
        sput(a, 0x68, 0, fx)
        a.invoke(0x71, f, [])
        sget(a, 0x61, 0, fx)
    parts = {"classes_dex": chain(body)}
    if other_dex:
        d2 = DexB()
        iface(d2)
        parts["classes2_dex"] = d2.build()
    return pkg(**parts)


def rz_shadow_long_pkg(where="classes.dex"):
    """A dex of the delivery DEFINES java.lang.Long with a static toHexString(J) returning "1111111111111111"; the chain
    makes "ANS-" + upper(Long.toHexString(0x123456789ABCDEF0)). A device's boot class path holds java.lang.Long, and
    its class loaders ask the boot class path first: ANS-123456789ABCDEF0."""
    def shadow(d):
        lc = d.cls(LONG, sup="Ljava/lang/Number;")
        th = d.m(LONG, "toHexString", "LJ", ret=STRING, params=["J"])
        ta = S.Asm()
        ta.const_string(0, d.s("1111111111111111"))
        ta.return_object(0)
        lc.direct.append((th, ACC_PUBLIC | ACC_STATIC, method(ta.finish(), 3, 2)))
        return th

    d = DexB()
    a = S.Asm()
    cc = d.cls(C)
    th = shadow(d) if where == "classes.dex" else d.m(LONG, "toHexString", "LJ", ret=STRING, params=["J"])
    a.const_wide(0, 0x123456789ABCDEF0)
    a.invoke(0x71, th, [0, 1])
    a.move_result_object(2)
    a.invoke(0x6e, d.m(STRING, "toUpperCase", "L", ret=STRING), [2])
    a.move_result_object(2)
    a.new_instance(4, d.t(SBT))
    a.invoke(0x70, d.m(SBT, "<init>", "V"), [4])
    a.const_string(5, d.s("ANS-"))
    a.invoke(0x6e, d.m(SBT, "append", "LL", ret=SBT, params=[STRING]), [4, 5])
    a.invoke(0x6e, d.m(SBT, "append", "LL", ret=SBT, params=[STRING]), [4, 2])
    a.invoke(0x6e, d.m(SBT, "toString", "L", ret=STRING), [4])
    a.move_result_object(6)
    a.return_object(6)
    cc.direct.append((d.m(C, "run", "L", ret=STRING), ACC_PUBLIC | ACC_STATIC, (a.finish(), 12, 0, 5)))
    parts = {"classes_dex": d.build()}
    if where != "classes.dex":
        d2 = DexB()
        shadow(d2)
        parts["classes2_dex"] = d2.build()
    return pkg(**parts)


def rz_forname3(cname="com.huntress.C", init=True, loader="null"):
    """Class.forName(cname, init, <loader>), then v0:v1 = 0xDEC0. loader: 'null'; 'app' (new MyLoader(), an app
    ClassLoader subclass); 'parent' (C.class.getClassLoader().getParent()); 'static' (K.L, a static the chain set to
    null first)."""
    def body(a, d):
        if loader == "null":
            a.const4(4, 0)
        elif loader == "app":
            ml = "Lcom/huntress/MyLoader;"
            lc = d.cls(ml, sup=LOADER)
            ia = S.Asm()
            ia.invoke(0x70, d.m(LOADER, "<init>", "V"), [0])
            ret(ia, 0x0e, 0)
            mi = d.m(ml, "<init>", "V")
            lc.direct.append((mi, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 1, 1)))
            a.new_instance(4, d.t(ml))
            a.invoke(0x70, mi, [4])
        elif loader == "parent":
            raw(a, 0x1c | (5 << 8), d.t(C))
            a.invoke(0x6e, d.m(CLASS, "getClassLoader", "L", ret=LOADER), [5])
            a.move_result_object(5)
            a.invoke(0x6e, d.m(LOADER, "getParent", "L", ret=LOADER), [5])
            a.move_result_object(4)
        else:
            fl = d.f(K, LOADER, "L")
            kc = d.cls(K)
            kc.sfields.append((fl, ACC_PUBLIC | ACC_STATIC))
            a.const4(4, 0)
            sput(a, 0x69, 4, fl)
            sget(a, 0x62, 4, fl)
        a.const_string(2, d.s(cname))
        a.const4(3, 1 if init else 0)
        a.invoke(0x71, d.m(CLASS, "forName", FORNAME3[0], ret=FORNAME3[1], params=FORNAME3[2]), [2, 3, 4])
        a.move_result_object(2)
        a.const_wide(0, 0xDEC0)
    return pkg(classes_dex=chain(body))


def rz_forname3_invoke():
    """Class.forName("com.huntress.Maze", true, null).getDeclaredMethod("q", long).invoke(null, 41L) (Maze.q = p0 +
    1000): a device throws ClassNotFoundException at forName."""
    def body(a, d, cc):
        maze_setup(d, cc, {"q"})
        a.const_string(7, d.s("com.huntress.Maze"))
        a.const4(5, 1)
        a.const4(6, 0)
        a.invoke(0x71, d.m(CLASS, "forName", FORNAME3[0], ret=FORNAME3[1], params=FORNAME3[2]), [7, 5, 6])
        a.move_result_object(7)
        a.const16(2, 1)
        a.new_array(8, 2, d.t(CLS_ARR))
        sget(a, 0x62, 3, d.f(LONG, CLASS, "TYPE"))
        a.const16(4, 0)
        a.aput(0x4d, 3, 8, 4)
        a.const_string(9, d.s("q"))
        a.invoke(0x6e, d.m(CLASS, "getDeclaredMethod", "LLL", ret=METHOD, params=[STRING, CLS_ARR]), [7, 9, 8])
        a.move_result_object(10)
        a.const16(2, 1)
        a.new_array(11, 2, d.t(OBJ_ARR))
        a.const_wide(3, 41)
        a.invoke(0x71, d.m(LONG, "valueOf", "LJ", ret=LONG, params=["J"]), [3, 4])
        a.move_result_object(5)
        a.const16(6, 0)
        a.aput(0x4d, 5, 11, 6)
        a.const4(12, 0)
        a.invoke(0x6e, d.m(METHOD, "invoke", "LLL", ret=OBJ, params=[OBJ, OBJ_ARR]), [10, 12, 11])
        a.move_result_object(13)
        a.invoke(0x6e, d.m(LONG, "longValue", "J"), [13])
        a.move_result_wide(0)
    return pkg(classes_dex=chain_cls(C, body))


def rz_loadclass_null():
    """((ClassLoader) null).loadClass("com.huntress.C") (a device throws NullPointerException), then 0xDEC0."""
    def body(a, d):
        a.const4(4, 0)
        a.const_string(2, d.s("com.huntress.C"))
        a.invoke(0x6e, d.m(LOADER, "loadClass", "LL", ret=CLASS, params=[STRING]), [4, 2])
        a.move_result_object(2)
        a.const_wide(0, 0xDEC0)
    return pkg(classes_dex=chain(body))


def rz_random_sub(through_sub=False):
    """R extends java.util.Random and overrides next(int) (returns 5); new R(1).nextInt() through Random's method ref or
    R's own: a device runs the override (5), the Random model would not."""
    rcls, rnd = "Lcom/huntress/R;", "Ljava/util/Random;"

    def body(a, d):
        rc = d.cls(rcls, sup=rnd)
        ia = S.Asm()
        ia.invoke(0x70, d.m(rnd, "<init>", "VJ", params=["J"]), [2, 3, 4])
        ret(ia, 0x0e, 0)
        ri = d.m(rcls, "<init>", "VJ", params=["J"])
        rc.direct.append((ri, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 5, 3)))
        na = S.Asm()
        na.const4(0, 5)
        ret(na, 0x0f, 0)
        rc.virtual.append((d.m(rcls, "next", "II", params=["I"]), 0x4, method(na.finish(), 3, 2)))
        a.new_instance(8, d.t(rcls))
        a.const_wide(2, 1)
        a.invoke(0x70, ri, [8, 2, 3])
        a.invoke(0x6e, d.m(rcls if through_sub else rnd, "nextInt", "I"), [8])
        a.move_result(4)
        a.unop(0x81, 0, 4)
    return pkg(classes_dex=chain(body))


def rz_shadow_entry():
    """The ANS entry itself is a method of Landroid/app/Fake;, a class of a boot package this dex defines."""
    return pkg(classes_dex=chain_cls("Landroid/app/Fake;", lambda a, d, cc: a.const_wide(0, 0x31)))


def rz_static_pkg(cfg):
    """`cfg` (this dex): <clinit> sets X = 0x77; the chain reads cfg.X."""
    def body(a, d):
        fs = d.f(cfg, "J", "X")
        kc = d.cls(cfg)
        kc.sfields.append((fs, ACC_PUBLIC | ACC_STATIC | ACC_FINAL))
        ca = S.Asm()
        ca.const_wide(0, 0x77)
        sput(ca, 0x68, 0, fs)
        ret(ca, 0x0e, 0)
        kc.direct.append((d.m(cfg, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        sget(a, 0x61, 0, fs)
    return pkg(classes_dex=chain(body))


def rz_point_pkg(sub=False):
    """new android.graphics.Point(42, 43).x (a framework class whose constructor sets public fields: the base VM's
    <init> catch-all made it a no-op and .x read 0), or the same through an app subclass MyPoint's field reference."""
    point, myp = "Landroid/graphics/Point;", "Lcom/huntress/MyPoint;"

    def body(a, d):
        if sub:
            mc = d.cls(myp, sup=point)
            ia = S.Asm()
            ia.invoke(0x70, d.m(point, "<init>", "VII", params=["I", "I"]), [3, 4, 5])
            ret(ia, 0x0e, 0)
            mi = d.m(myp, "<init>", "VII", params=["I", "I"])
            mc.direct.append((mi, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 6, 3)))
            fx = d.f(myp, "I", "x")
            a.new_instance(8, d.t(myp))
        else:
            mi = d.m(point, "<init>", "VII", params=["I", "I"])
            fx = d.f(point, "I", "x")
            a.new_instance(8, d.t(point))
        a.const16(2, 0x2A)
        a.const16(3, 0x2B)
        a.invoke(0x70, mi, [8, 2, 3])
        a.iop(0x52, 4, 8, fx)
        a.unop(0x81, 0, 4)
    return pkg(classes_dex=chain(body))


def rz_alias_pkg(write_ref, read_ref, sub_writes=None, sub_own=False):
    """Base declares long n; Base.<init> sets n = 42 through `write_ref`'s field reference ('base' or 'sub'); Sub extends
    Base and its <init> calls Base.<init>, then (with sub_writes) sets n through Sub's reference (with sub_own, a field
    n of Sub's own that hides Base's); the chain reads new Sub().n through `read_ref`'s reference."""
    def body(a, d):
        fb = d.f(BASEC, "J", "n")
        fs = d.f(SUBC, "J", "n")
        bc = d.cls(BASEC)
        bc.ifields.append((fb, 0))
        ia = S.Asm()
        ia.const_wide(0, 42)
        ia.iop(0x5a, 0, 2, fb if write_ref == "base" else fs)
        ret(ia, 0x0e, 0)
        bi = d.m(BASEC, "<init>", "V")
        bc.direct.append((bi, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 3, 1)))
        sc = d.cls(SUBC, sup=BASEC)
        if sub_own:
            sc.ifields.append((fs, 0))
        sa = S.Asm()
        sa.invoke(0x70, bi, [2])
        if sub_writes is not None:
            sa.const_wide(0, sub_writes)
            sa.iop(0x5a, 0, 2, fs)
        ret(sa, 0x0e, 0)
        si = d.m(SUBC, "<init>", "V")
        sc.direct.append((si, ACC_PUBLIC | ACC_CONSTRUCTOR, method(sa.finish(), 3, 1)))
        a.new_instance(8, d.t(SUBC))
        a.invoke(0x70, si, [8])
        a.iop(0x53, 0, 8, fb if read_ref == "base" else fs)
    return pkg(classes_dex=chain(body))


SKS, CIPHERC, KEYC, MYKEY = ("Ljavax/crypto/spec/SecretKeySpec;", "Ljavax/crypto/Cipher;", "Ljava/security/Key;",
                             "Lcom/huntress/MyKey;")
RZ_K1, RZ_K2, RZ_BLOCK = bytes(range(16)), bytes(range(100, 116)), bytes(range(32, 48))


def rz_bytes(a, d, reg, data, tmp=9):
    """v<reg> = new byte[]{data} (v<tmp>, v<tmp+1> scratch)."""
    a.const16(tmp, len(data))
    a.new_array(reg, tmp, d.t("[B"))
    for i, b in enumerate(data):
        a.const16(tmp, b - 256 if b > 127 else b)
        a.const16(tmp + 1, i)
        a.aput(0x4f, tmp, reg, tmp + 1)


def rz_cipher_pkg(sub=True, override=True):
    """AES/ECB/NoPadding of a block under SecretKeySpec(K1, "AES"), or under MyKey(K1) (MyKey extends SecretKeySpec,
    with `override` its getEncoded() returns K2: a device's Cipher.init asks the key for its bytes); v0:v1 = the first
    8 bytes of the ciphertext, big-endian."""
    def body(a, d):
        if sub:
            mk = d.cls(MYKEY, sup=SKS)
            ia = S.Asm()
            ia.const_string(0, d.s("AES"))
            ia.invoke(0x70, d.m(SKS, "<init>", "VLL", params=["[B", STRING]), [1, 2, 0])
            ret(ia, 0x0e, 0)
            mi = d.m(MYKEY, "<init>", "VL", params=["[B"])
            mk.direct.append((mi, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 3, 2)))
            if override:
                ga = S.Asm()
                rz_bytes(ga, d, 0, RZ_K2, tmp=1)
                ga.return_object(0)
                mk.virtual.append((d.m(MYKEY, "getEncoded", "L", ret="[B"), ACC_PUBLIC, method(ga.finish(), 4, 1)))
        a.const_string(2, d.s("AES/ECB/NoPadding"))
        a.invoke(0x71, d.m(CIPHERC, "getInstance", "LL", ret=CIPHERC, params=[STRING]), [2])
        a.move_result_object(3)
        rz_bytes(a, d, 4, RZ_K1)
        if sub:
            a.new_instance(5, d.t(MYKEY))
            a.invoke(0x70, mi, [5, 4])
        else:
            a.new_instance(5, d.t(SKS))
            a.const_string(6, d.s("AES"))
            a.invoke(0x70, d.m(SKS, "<init>", "VLL", params=["[B", STRING]), [5, 4, 6])
        a.const4(6, 1)
        a.invoke(0x6e, d.m(CIPHERC, "init", "VIL", params=["I", KEYC]), [3, 6, 5])
        rz_bytes(a, d, 7, RZ_BLOCK)
        a.invoke(0x6e, d.m(CIPHERC, "doFinal", "LL", ret="[B", params=["[B"]), [3, 7])
        a.move_result_object(7)
        a.const_wide(0, 0)
        a.const_wide(12, 0xFF)
        for i in range(8):
            a.const4(8, i)
            a.aget(0x48, 9, 7, 8)
            a.unop(0x81, 10, 9)
            a.binop2(0xc0, 10, 12)
            a.const16(14, 8)
            a.binop2(0xc3, 0, 14)
            a.binop2(0xc1, 0, 10)
    return pkg(classes_dex=chain(body))


def rz_aes_code(key):
    """The device's code: AES-128-ECB(key, RZ_BLOCK), the first 8 bytes big-endian (an independent implementation)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return "ANS-%016X" % int.from_bytes((e.update(RZ_BLOCK) + e.finalize())[:8], "big")


# ---- the independent review of the fix (each a WRONG plain on af3dbf7 and on the fix's first commits)
THROWABLE = "Ljava/lang/Throwable;"


def rz_ctor(d, cls, sup=OBJ):
    """A no-argument constructor of `cls` calling sup.<init>(): (its method index, its direct-method entry)."""
    ia = S.Asm()
    ia.invoke(0x70, d.m(sup, "<init>", "V"), [0])
    ret(ia, 0x0e, 0)
    mi = d.m(cls, "<init>", "V")
    return mi, (mi, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 1, 1))


def rz_boom_pkg(exc="Ljava/lang/Exception;"):
    """Boom extends `exc` and overrides fillInStackTrace() to set its own long n = 0x42; the chain reads new Boom().n.
    Every Throwable constructor calls the virtual fillInStackTrace(): a device reads 0x42."""
    boom = "Lcom/huntress/Boom;"

    def body(a, d):
        fn = d.f(boom, "J", "n")
        bc = d.cls(boom, sup=exc)
        bc.ifields.append((fn, 0))
        bi, bd = rz_ctor(d, boom, exc)
        bc.direct.append(bd)
        fa = S.Asm()
        fa.const_wide(0, 0x42)
        fa.iop(0x5a, 0, 2, fn)
        fa.return_object(2)
        bc.virtual.append((d.m(boom, "fillInStackTrace", "L", ret=THROWABLE), ACC_PUBLIC, method(fa.finish(), 3, 1)))
        a.new_instance(8, d.t(boom))
        a.invoke(0x70, bi, [8])
        a.iop(0x53, 0, 8, fn)
    return pkg(classes_dex=chain(body))


def rz_setseed_pkg():
    """R2 extends java.util.Random, overrides setSeed(long) to set its own n = 0x42; the chain reads new R2(1).n.
    Random(long) calls the virtual setSeed: a device reads 0x42."""
    r2, rnd = "Lcom/huntress/R2;", "Ljava/util/Random;"

    def body(a, d):
        fn = d.f(r2, "J", "n")
        rc = d.cls(r2, sup=rnd)
        rc.ifields.append((fn, 0))
        ia = S.Asm()
        ia.invoke(0x70, d.m(rnd, "<init>", "VJ", params=["J"]), [0, 1, 2])
        ret(ia, 0x0e, 0)
        ri = d.m(r2, "<init>", "VJ", params=["J"])
        rc.direct.append((ri, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 3, 3)))
        sa = S.Asm()
        sa.const_wide(0, 0x42)
        sa.iop(0x5a, 0, 2, fn)
        ret(sa, 0x0e, 0)
        rc.virtual.append((d.m(r2, "setSeed", "VJ", params=["J"]), ACC_PUBLIC, method(sa.finish(), 5, 3)))
        a.new_instance(8, d.t(r2))
        a.const_wide(2, 1)
        a.invoke(0x70, ri, [8, 2, 3])
        a.iop(0x53, 0, 8, fn)
    return pkg(classes_dex=chain(body))


def rz_new_then(desc, shorty="V", params=None, argv=()):
    """new desc(argv...) (its result unused), then v0:v1 = 0xBEEF."""
    def body(a, d):
        a.new_instance(8, d.t(desc))
        for i, v in enumerate(argv):
            a.const4(2 + i, v)
        a.invoke(0x70, d.m(desc, "<init>", shorty, params=params), [8] + [2 + i for i in range(len(argv))])
        a.const_wide(0, 0xBEEF)
    return pkg(classes_dex=chain(body))


def rz_coll_pkg():
    """MyColl extends AbstractCollection, its toArray() sets its own n = 0x42; new ArrayList(myColl) (which calls
    c.toArray()), then the chain reads myColl.n: a device 0x42."""
    mcls, ac, al = "Lcom/huntress/MyColl;", "Ljava/util/AbstractCollection;", "Ljava/util/ArrayList;"

    def body(a, d):
        fn = d.f(mcls, "J", "n")
        mc = d.cls(mcls, sup=ac)
        mc.ifields.append((fn, 0))
        mi, md = rz_ctor(d, mcls, ac)
        mc.direct.append(md)
        ta = S.Asm()
        ta.const_wide(0, 0x42)
        ta.iop(0x5a, 0, 3, fn)
        ta.const4(0, 0)
        ta.new_array(1, 0, d.t(OBJ_ARR))
        ta.return_object(1)
        mc.virtual.append((d.m(mcls, "toArray", "L", ret=OBJ_ARR), ACC_PUBLIC, method(ta.finish(), 4, 1)))
        a.new_instance(8, d.t(mcls))
        a.invoke(0x70, mi, [8])
        a.new_instance(7, d.t(al))
        a.invoke(0x70, d.m(al, "<init>", "VL", params=["Ljava/util/Collection;"]), [7, 8])
        a.iop(0x53, 0, 8, fn)
    return pkg(classes_dex=chain(body))


def rz_nofield_pkg():
    """iget-wide X.zz, a field no class declares (NoSuchFieldError on a device), + 0x77."""
    x = "Lcom/huntress/X;"

    def body(a, d):
        fz = d.f(x, "J", "zz")
        xc = d.cls(x)
        xi, xd = rz_ctor(d, x)
        xc.direct.append(xd)
        a.new_instance(8, d.t(x))
        a.invoke(0x70, xi, [8])
        a.iop(0x53, 0, 8, fz)
        a.const_wide(2, 0x77)
        a.binop2(0xbb, 0, 2)
    return pkg(classes_dex=chain(body))


def rz_super_pkg2(direct_super=False):
    """Base.f() = 1, Mid extends Base overrides f() = 2, Sub extends Mid; Sub.g() runs invoke-super of Base.f (ART
    dispatches from the caller's superclass: Mid.f, 2), or with `direct_super` of Mid.f (2 either way)."""
    b, mcl, sb = BASEC, "Lcom/huntress/Mid;", SUBC

    def body(a, d):
        bc = d.cls(b)
        _bi, bd = rz_ctor(d, b)
        bc.direct.append(bd)
        fa = S.Asm()
        fa.const_wide(0, 1)
        ret(fa, 0x10, 0)
        bf = d.m(b, "f", "J")
        bc.virtual.append((bf, ACC_PUBLIC, method(fa.finish(), 3, 1)))
        mc = d.cls(mcl, sup=b)
        _mi, md = rz_ctor(d, mcl, b)
        mc.direct.append(md)
        ma = S.Asm()
        ma.const_wide(0, 2)
        ret(ma, 0x10, 0)
        mf = d.m(mcl, "f", "J")
        mc.virtual.append((mf, ACC_PUBLIC, method(ma.finish(), 3, 1)))
        sc = d.cls(sb, sup=mcl)
        si, sd = rz_ctor(d, sb, mcl)
        sc.direct.append(sd)
        ga = S.Asm()
        ga.invoke(0x6f, mf if direct_super else bf, [2])
        ga.move_result_wide(0)
        ret(ga, 0x10, 0)
        sg = d.m(sb, "g", "J")
        sc.virtual.append((sg, ACC_PUBLIC, method(ga.finish(), 3, 1)))
        a.new_instance(8, d.t(sb))
        a.invoke(0x70, si, [8])
        a.invoke(0x6e, sg, [8])
        a.move_result_wide(0)
    return pkg(classes_dex=chain(body))


def rz_null_recv_pkg():
    """H.compute() (never touches `this`) called on null: NullPointerException on a device."""
    hcl = "Lcom/huntress/H;"

    def body(a, d):
        hc = d.cls(hcl)
        _hi, hd = rz_ctor(d, hcl)
        hc.direct.append(hd)
        ca = S.Asm()
        ca.const_wide(0, 0x99)
        ret(ca, 0x10, 0)
        cm = d.m(hcl, "compute", "J")
        hc.virtual.append((cm, ACC_PUBLIC, method(ca.finish(), 3, 1)))
        a.const4(8, 0)
        a.invoke(0x6e, cm, [8])
        a.move_result_wide(0)
    return pkg(classes_dex=chain(body))


def rz_decoy_getter_pkg(cls, getter, shorty="V", params=None, argv=(), sup=OBJ):
    """The APK's classes.dex DEFINES `cls` (a boot class path class) with a decoy getter()I = 0x42; the chain returns
    new cls(argv...).getter(). A device runs the boot copy."""
    def body(a, d):
        cc = d.cls(cls, sup=sup)
        ia = S.Asm()
        ia.invoke(0x70, d.m(sup, "<init>", "V"), [0])
        ret(ia, 0x0e, 0)
        nins = 1 + len(params or [])
        mi = d.m(cls, "<init>", shorty, params=params)
        cc.direct.append((mi, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), nins, nins)))
        ga = S.Asm()
        ga.const16(0, 0x42)
        ret(ga, 0x0f, 0)
        cc.virtual.append((d.m(cls, getter, "I"), ACC_PUBLIC, method(ga.finish(), 2, 1)))
        a.new_instance(8, d.t(cls))
        regs = [8]
        for i, v in enumerate(argv):
            a.const_string(2 + i, d.s(v))
            regs.append(2 + i)
        a.invoke(0x70, mi, regs)
        a.invoke(0x6e, d.m(cls, getter, "I"), [8])
        a.move_result(4)
        a.unop(0x81, 0, 4)
    return pkg(classes_dex=chain(body))


def rz_md_class_pkg():
    """MessageDigest.getInstance("SHA-256").getClass().getName().length(): a device's object is a provider's subclass
    (java.security.MessageDigest$Delegate on Android 7+), the VM's typed MessageDigest."""
    md = "Ljava/security/MessageDigest;"

    def body(a, d):
        a.const_string(2, d.s("SHA-256"))
        a.invoke(0x71, d.m(md, "getInstance", "LL", ret=md, params=[STRING]), [2])
        a.move_result_object(3)
        a.invoke(0x6e, d.m(OBJ, "getClass", "L", ret=CLASS), [3])
        a.move_result_object(4)
        a.invoke(0x6e, d.m(CLASS, "getName", "L", ret=STRING), [4])
        a.move_result_object(5)
        a.invoke(0x6e, d.m(STRING, "length", "I"), [5])
        a.move_result(6)
        a.unop(0x81, 0, 6)
    return pkg(classes_dex=chain(body))


def rz_cast_pkg(kind):
    """check-cast then a use: 'unrelated' (a Y cast to X, then X.n: ClassCastException on a device), 'own' (an X to
    X), 'super' (a Sub to Base), 'iface' (an Impl to the interface Runnable it names), 'string' (a String to
    CharSequence, then its length), 'box' (a Long to Number, then longValue)."""
    x, y = "Lcom/huntress/X;", "Lcom/huntress/Y;"

    def body(a, d):
        if kind in ("unrelated", "own"):
            fn = d.f(x, "J", "n")
            xc = d.cls(x)
            xc.ifields.append((fn, 0))
            xi, xd = rz_ctor(d, x)
            xc.direct.append(xd)
            yc = d.cls(y)
            yi, yd = rz_ctor(d, y)
            yc.direct.append(yd)
            a.new_instance(8, d.t(y if kind == "unrelated" else x))
            a.invoke(0x70, yi if kind == "unrelated" else xi, [8])
            raw(a, 0x1f | (8 << 8), d.t(x))
            a.iop(0x53, 0, 8, fn)
            a.const_wide(2, 0x77)
            a.binop2(0xbb, 0, 2)
        elif kind in ("super", "iface"):
            target = BASEC if kind == "super" else "Ljava/lang/Runnable;"
            bc = d.cls(BASEC)
            _bi, bd = rz_ctor(d, BASEC)
            bc.direct.append(bd)
            sc = d.cls(SUBC, sup=BASEC)
            if kind == "iface":
                sc.ifaces = ["Ljava/lang/Runnable;"]
                d.t("Ljava/lang/Runnable;")
            si, sd = rz_ctor(d, SUBC, BASEC)
            sc.direct.append(sd)
            a.new_instance(8, d.t(SUBC))
            a.invoke(0x70, si, [8])
            raw(a, 0x1f | (8 << 8), d.t(target))
            a.const_wide(0, 0x55)
        elif kind == "string":
            a.const_string(8, d.s("abcdef"))
            raw(a, 0x1f | (8 << 8), d.t("Ljava/lang/CharSequence;"))
            a.invoke(0x6e, d.m(STRING, "length", "I"), [8])
            a.move_result(4)
            a.unop(0x81, 0, 4)
        else:
            a.const_wide(2, 0x66)
            a.invoke(0x71, d.m(LONG, "valueOf", "LJ", ret=LONG, params=["J"]), [2, 3])
            a.move_result_object(8)
            raw(a, 0x1f | (8 << 8), d.t("Ljava/lang/Number;"))
            raw(a, 0x1f | (8 << 8), d.t(LONG))
            a.invoke(0x6e, d.m(LONG, "longValue", "J"), [8])
            a.move_result_wide(0)
    return pkg(classes_dex=chain(body))


def rz_review_checks():
    m = rz_cast_pkg("unrelated")
    declines_pkg("Z review: an object of Y cast to the unrelated X, then X.n (ClassCastException on a device)", m,
                 "check-cast")
    check("Z review ... the VM before (check-cast a no-op) gave ANS-..77 plain under the judged key",
          kb7_codes_nocast(m) == [code(0x77)], kb7_codes_nocast(m))
    for kind, want in (("own", 0x77), ("super", 0x55), ("iface", 0x55), ("string", 6), ("box", 0x66)):
        answers_pkg("Z review control: check-cast (%s) the VM proves" % kind, rz_cast_pkg(kind), code(want), K0)
    for exc in ("Ljava/lang/Exception;", "Ljava/lang/RuntimeException;", THROWABLE):
        m = rz_boom_pkg(exc)
        declines_pkg("Z review: Boom extends %s, fillInStackTrace() sets its n: the framework constructor declines"
                     % exc, m, "no model of this constructor")
        check("Z review ... the KB-7 tree read n as 0 under the judged key (a device: 0x42)",
              kb7_codes(m) == [code(0)], kb7_codes(m))
    m = rz_setseed_pkg()
    declines_pkg("Z review: R2 extends Random, setSeed() sets its n (Random(long) calls it)", m, "may override")
    check("Z review ... the KB-7 tree read 0 (a device: 0x42)", kb7_codes(m) == [code(0)], kb7_codes(m))
    for label, m, why in (
            ("new ArrayList(-1) (IllegalArgumentException)", rz_new_then("Ljava/util/ArrayList;", "VI", ["I"], (-1,)),
             "no model of this constructor"),
            ("new java.lang.Fictional() (NoClassDefFoundError)", rz_new_then("Ljava/lang/Fictional;"),
             "no model of this constructor"),
            ("new ArrayList(myColl), myColl.toArray() sets its n", rz_coll_pkg(), "no model of this constructor"),
            ("iget of X.zz, a field no class declares (NoSuchFieldError)", rz_nofield_pkg(), "never wrote it"),
            ("invoke-super Base.f from Sub, Mid overrides f (a device runs Mid.f)", rz_super_pkg2(), "declares it"),
            ("H.compute() on a null receiver (NullPointerException)", rz_null_recv_pkg(), "null receiver"),
            ("the APK defines org.xml.sax.helpers.AttributesImpl (a decoy getLength)",
             rz_decoy_getter_pkg("Lorg/xml/sax/helpers/AttributesImpl;", "getLength"), "boot copy"),
            ("the APK defines org.xmlpull.v1.XmlPullParserException(String) (a decoy getLineNumber)",
             rz_decoy_getter_pkg("Lorg/xmlpull/v1/XmlPullParserException;", "getLineNumber", "VL", [STRING], ("x",),
                                 sup="Ljava/lang/Exception;"), "boot copy"),
            ("MessageDigest.getInstance(..).getClass().getName() (a provider's subclass on a device)",
             rz_md_class_pkg(), "runtime class")):
        declines_pkg("Z review: %s" % label, m, why)
        before = kb7_codes(m)
        check("Z review ... the KB-7 tree gave a code (plain under its key): %s" % before, len(before) == 1, before)
    answers_pkg("Z review control: invoke-super of Mid.f from Sub (the direct superclass): Mid.f's 2",
                rz_super_pkg2(direct_super=True), code(2), K0)


def rz_many_fields(n):
    """Holder (this dex) with n long fields f0..f(n-1); the chain writes f_i = i on one object, then sums them all back."""
    holder = "Lcom/huntress/Many;"

    def body(a, d):
        hc = d.cls(holder)
        fids = [d.f(holder, "J", "f%d" % i) for i in range(n)]
        for fi in fids:
            hc.ifields.append((fi, 0))
        ia = S.Asm()
        ret(ia, 0x0e, 0)
        hi = d.m(holder, "<init>", "V")
        hc.direct.append((hi, ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 1, 1)))
        a.new_instance(8, d.t(holder))
        a.invoke(0x70, hi, [8])
        for i, fi in enumerate(fids):
            a.const_wide(2, i)
            a.iop(0x5a, 2, 8, fi)
        a.const_wide(0, 0)
        for fi in fids:
            a.iop(0x53, 2, 8, fi)
            a.binop2(0xbb, 0, 2)
    return chain(body)


def rz_split_checks():
    """The split reading (split_bundle.SplitVM, the base VM's semantics) on synthetic bundles whose base dex is a copy
    of Day 26's judged readSplit (test_day27_split_fold_mobile.judged_app): tier A answers under the judged
    mobile.codec/analysis+split-asset. Needs the saved Day 26 Time Trial (skipped without it)."""
    keep = dict(os.environ)
    try:
        os.environ.pop("CTF_WORKDIR", None)     # the split test finds the saved Day 26 bytes through it
        import test_day27_split_fold_mobile as SF
    finally:
        os.environ.clear()
        os.environ.update(keep)
    src, rm = SF.real_reader() if SF.DAY26.is_dir() else (None, None)
    if src is None:
        print("SKIP Z split reading: the saved Day 26 Time Trial is not on disk")
        return
    import hashlib
    import io
    raw16 = hashlib.sha256(b"rv2-judged").digest()[:16]
    feat16 = {"AndroidManifest.xml": b"m", "assets/huntress_feature.bin": raw16}
    import split_bundle as SBM
    accepted = ((SBM.AKEY, SBM.AROUTE),)

    def solve(blob):
        with private_ledger(*accepted), contextlib.redirect_stderr(io.StringIO()):
            return SF.solve(blob)

    def holder_dex(h):
        d = SF.Dx()
        init = d.m(h, "<init>", "V")
        a = S.Asm()
        a.const16(0, 0x21)
        a.iop(0x59, 0, 1, d.f(h, "I", "k"))
        a.return_void()
        d.body(init, a.finish(), 2, 1)
        return d.build()

    def xor_with(a, key_reg):
        SF.arrlen(a, 10, 1)
        a.const4(11, 0)
        a.label("zx")
        a.if_test(0x35, 11, 10, "zd")
        a.aget(0x48, 13, 1, 11)
        a.binop2(0xb7, 13, key_reg)
        a.unop(0x8d, 13, 13)
        a.aput(0x4f, 13, 1, 11)
        SF.lit8(a, 0xd8, 11, 11, 1)
        a.goto16("zx")
        a.label("zd")

    def holder_xor(h):
        def middle(d, a):
            a.new_instance(2, d.t(h))
            a.invoke(0x70, d.m(h, "<init>", "V"), [2])
            a.iop(0x52, 12, 2, d.f(h, "I", "k"))
            xor_with(a, 12)
        return middle

    def shadow_xor(d, a):
        bc = d.m(INTEGER, "bitCount", "I", ["I"])
        b = S.Asm()
        b.u.append(0x0f | (1 << 8))                 # return p0: the bundle's own java.lang.Integer.bitCount
        d.body(bc, b.finish(), 2, 1)
        a.const16(12, 0x21)
        a.invoke(0x71, bc, [12])
        a.move_result(12)
        xor_with(a, 12)

    def forname_pre(cname):
        def pre(d, a):
            a.const_string(0, d.s(cname))
            a.const4(1, 1)
            a.const4(2, 0)
            a.invoke(0x71, d.m(CLASS, "forName", CLASS, [STRING, "Z", LOADER]), [0, 1, 2])
            a.move_result_object(3)
        return pre

    jd, _ = SF.judged_app(src, rm)
    got, last = solve(SF.analysis_bundle(jd, feat16))
    check("Z split control: the judged reader, the entry makes the code: plain under the judged split-asset key",
          plain_of(got) == SF.code_of(raw16) and last.get("key") == SBM.AKEY, (got, last.get("key")))
    for h in ("Lkotlin/Holder;", "Landroidx/core/Holder;", "Lcom/q/Holder;"):
        jd, _ = SF.judged_app(src, rm, middle=holder_xor(h))
        blob = SF.analysis_bundle(jd, feat16, base_extra={"classes2.dex": holder_dex(h)})
        got, last = solve(blob)
        if plain_of(got) is not None:
            WRONG.append(("Z split " + h, got, SF.code_of(raw16, 0x21)))
        check("Z split: the bytes XOR new %s().k, %s in the base split's classes2.dex (its <init> sets k = 0x21): None "
              "(a device gives %s)" % (h, h, SF.code_of(raw16, 0x21)), got is None, (got, last.get("key")))
        with kb7_rule():
            before = solve(blob)[0]
        check("Z split ... the KB-7 tree's base VM made that constructor a no-op: %s plain under the judged key, a WRONG "
              "plain" % SF.code_of(raw16), before == SF.code_of(raw16), before)
    jd, _ = SF.judged_app(src, rm, middle=holder_xor("Lcom/q/Holder;"))
    got = solve(SF.analysis_bundle(jd, feat16))[0]
    check("Z split: the same, the class in no dex (NoClassDefFoundError on a device): None", got is None, got)
    jd, _ = SF.judged_app(src, rm, pre=forname_pre("com.q.Main"))
    blob = SF.analysis_bundle(jd, feat16)
    got = solve(blob)[0]
    with kb7_rule():
        before = solve(blob)[0]
    check("Z split: Class.forName(\"com.q.Main\", true, null) before the read (ClassNotFoundException on a device): None "
          "(the KB-7 tree: %s plain)" % before, got is None and before == SF.code_of(raw16), (got, before))
    jd, _ = SF.judged_app(src, rm, pre=forname_pre("java.lang.String"))
    got = solve(SF.analysis_bundle(jd, feat16))[0]
    check("Z split control: Class.forName(\"java.lang.String\", true, null) before the read: plain, the exact code",
          plain_of(got) == SF.code_of(raw16), got)

    def forname1_pre(cname):
        def pre(d, a):
            a.const_string(0, d.s(cname))
            a.invoke(0x71, d.m(CLASS, "forName", CLASS, [STRING]), [0])
            a.move_result_object(3)
        return pre

    def fictional_pre(d, a):
        a.new_instance(3, d.t("Ljava/lang/Fictional;"))
        a.invoke(0x70, d.m("Ljava/lang/Fictional;", "<init>", "V"), [3])

    for label, pre in (("Class.forName(\"de.robv.android.xposed.XposedBridge\") (1 argument), a class no dex of the "
                        "bundle defines", forname1_pre("de.robv.android.xposed.XposedBridge")),
                       ("Class.forName(\"com/q/Main\") (a slash: ART refuses the name)", forname1_pre("com/q/Main")),
                       ("new java.lang.Fictional() (no model of its constructor, no such class on a device)",
                        fictional_pre)):
        jd, _ = SF.judged_app(src, rm, pre=pre)
        blob = SF.analysis_bundle(jd, feat16)
        got = solve(blob)[0]
        with kb7_rule():
            before = solve(blob)[0]
        check("Z split (review): %s before the read: None (the KB-7 tree: %s plain)" % (label, before),
              got is None and before == SF.code_of(raw16), (got, before))
    jd, _ = SF.judged_app(src, rm, pre=forname1_pre("com.q.Main"))
    got = solve(SF.analysis_bundle(jd, feat16))[0]
    check("Z split control: Class.forName(\"com.q.Main\") (the entry's own class) before the read: plain",
          plain_of(got) == SF.code_of(raw16), got)
    jd, _ = SF.judged_app(src, rm, middle=shadow_xor)
    blob = SF.analysis_bundle(jd, feat16)
    got = solve(blob)[0]
    with kb7_rule():
        before = solve(blob)[0]
    check("Z split: the base dex defines java.lang.Integer.bitCount (the identity) and the entry XORs with bitCount(0x21) "
          "(a device runs the boot copy: %s): None (the KB-7 tree ran the bundle's body: %s plain)"
          % (SF.code_of(raw16, 2), before), got is None and before == SF.code_of(raw16, 0x21), (got, before))


def section_residuals():
    # ---- residual 1: a class under Lkotlin/ (and every framework package) that a dex of the delivery defines
    m = rz_holder_pkg()
    declines_pkg("Z new kotlin.Holder() of classes2.dex (its <init> sets n = 42), the chain reads n", m, "does not define")
    check("Z ... the KB-7 tree made that constructor a no-op: ANS-0..0 under the judged key, a WRONG plain (a device: 42)",
          kb7_codes(m) == [code(0)], kb7_codes(m))
    for prefix in ("Lkotlinx/coroutines/", "Landroidx/core/", "Landroid/support/v4/", "Landroid/graphics/"):
        holder = prefix + "Holder;"
        declines_pkg("Z the same, Holder under %s (classes2.dex)" % prefix, rz_holder_pkg(holder), "does not define")
    for where, holder in (("assets/payload.dex", "Lkotlin/Holder;"), ("assets/payload.dex", "Landroid/graphics/Pt;")):
        declines_pkg("Z the same, %s only in %s (off the class path: NoClassDefFoundError)" % (holder, where),
                     rz_holder_pkg(holder, where), "does not define")
    answers_pkg("Z control: kotlin.Holder defined in this dex (the app's class, run): the judged key, the device's code",
                pkg(classes_dex=rz_new_read("Lkotlin/Holder;", define_here=True)), code(42), K0)
    m = rz_super_pkg()
    declines_pkg("Z Sub (this dex) extends kotlin.Base of classes2.dex: Base.<init> (n = 42) has no body here", m,
                 "has no body in this dex")
    check("Z ... the KB-7 tree: Base.<init> a no-op, ANS-0..0 under the judged key (a device: 42)",
          kb7_codes(m) == [code(0)], kb7_codes(m))
    m = rz_suffix_pkg()
    declines_pkg("Z kotlin.x.MyInteger.valueOf of classes2.dex (p0 + 1): never Integer.valueOf by the end of its name", m,
                 "has no body in this dex")
    check("Z ... the KB-7 tree took it for Integer.valueOf: ANS-..05 under the judged key (a device: 6)",
          kb7_codes(m) == [code(5)], kb7_codes(m))
    m = rz_unseen_pkg()
    declines_pkg("Z K.X = 5, then Class.forName(\"kotlin.Other\") of classes2.dex (its <clinit> sets 7), then the read", m,
                 "since then")
    check("Z ... the KB-7 tree: kotlin.Other was the framework's, its <clinit> unseen: 5 (a device: 7)",
          kb7_codes(m) == [code(5)], kb7_codes(m))
    for other_dex in (False, True):
        m = rz_iface_pkg(other_dex=other_dex)
        where = "classes2.dex" if other_dex else "this dex"
        declines_pkg("Z K.X = 5, Impl.f() (Impl implements kotlin.I of %s: a default method, a <clinit> setting 7)"
                     % where, m, "since then")
        check("Z ... the KB-7 tree skipped every Lkotlin/ superinterface: 5 (a device: 7) [%s]" % where,
              kb7_codes(m) == [code(5)], kb7_codes(m))
    answers_pkg("Z control: Impl implements a kotlin.I with no default method (not initialized with Impl): the run's 5",
                rz_iface_plain_pkg(), code(5), KS)
    m = rz_shadow_long_pkg()
    declines_pkg("Z this dex DEFINES java.lang.Long (toHexString a decoy): a device runs the boot copy (parent-first)", m,
                 "boot copy")
    check("Z ... the KB-7 tree ran the app's copy: ANS-1111111111111111 under the judged key (a device: "
          "ANS-123456789ABCDEF0)", kb7_codes(m) == ["ANS-1111111111111111"], kb7_codes(m))
    declines_pkg("Z classes2.dex defines java.lang.Long: which copy a device runs is not known here, a decline",
                 rz_shadow_long_pkg("classes2.dex"), "has no body in this dex")
    m = rz_shadow_entry()
    codes_, dcl = dcc.analysis_codes_ex(m)
    dx = dcc.Dex(m["classes.dex"])
    entry = next(mi for mi in dx.code if dx.mname[mi] == ("Landroid/app/Fake;", "run"))
    try:
        DF.pre_entry(dcc.VM(dx), entry)
        why = ""
    except dcc._Decline as e:
        why = str(e)
    check("Z the ANS entry is a method of Landroid/app/Fake; (this dex defines that boot package's class): no code, "
          "pre_entry refuses it (boot copy)", codes_ == [] and dcl == 1 and "boot copy" in why, (codes_, dcl, why))
    never_plain("Z ... the entry of Landroid/app/Fake;", m, ACCEPT_MORE)
    check("Z ... the KB-7 tree ran it as the app's: ANS-..31", kb7_codes(m) == [code(0x31)], kb7_codes(m))
    declines_pkg("Z a static of Landroid/os/Cfg; (this dex: its <clinit> sets X = 0x77)", rz_static_pkg("Landroid/os/Cfg;"),
                 "boot copy")
    answers_pkg("Z control: the same static of kotlin.Cfg (this dex: the app's class, its <clinit> run)",
                rz_static_pkg("Lkotlin/Cfg;"), code(0x77), KS)
    # ---- residual 2: Class.forName(name, initialize, loader)
    m = rz_forname3()
    declines_pkg("Z Class.forName(\"com.huntress.C\", true, null): the bootstrap loader loads no app class", m,
                 "bootstrap loader")
    check("Z ... the KB-7 tree ignored the loader: ANS-..DEC0 under the judged key (a device throws "
          "ClassNotFoundException)", kb7_codes(m) == [code(0xDEC0)], kb7_codes(m))
    m = rz_forname3_invoke()
    declines_pkg("Z Class.forName(\"com.huntress.Maze\", true, null).getDeclaredMethod(\"q\", long).invoke(null, 41L)", m,
                 "bootstrap loader")
    check("Z ... the KB-7 tree ran Maze.q: ANS-..411 under the judged key", kb7_codes(m) == [code(1041)], kb7_codes(m))
    for label, kw, why in (("false, null", {"init": False}, "bootstrap loader"),
                           ("true, new MyLoader() (an app ClassLoader subclass: its super() is ClassLoader's own "
                            "constructor, no model)", {"loader": "app"}, "no model of this constructor"),
                           # getClassLoader() is modeled since the Day 31 "Loaded Later" fold (the loader chain
                           # needs it as the InMemoryDexClassLoader parent), so this hostile construct now declines
                           # one step later at getParent instead of at getClassLoader -- still a decline, no code.
                           ("true, C.class.getClassLoader().getParent()", {"loader": "parent"}, "getParent"),
                           ("true, K.L (the chain set it to null)", {"loader": "static"}, "bootstrap loader")):
        declines_pkg("Z Class.forName(\"com.huntress.C\", %s)" % label, rz_forname3(**kw), why)
    declines_pkg("Z Class.forName(\"[Lcom.huntress.C;\", false, null): an array of an app class", rz_forname3(
        "[Lcom.huntress.C;", False), "bootstrap loader")
    declines_pkg("Z Class.forName(\"kotlin.Holder\", true, null), Holder in this dex", pkg(classes_dex=chain(
        lambda a, d: rz_forname3_body(a, d, "kotlin.Holder"))), "bootstrap loader")
    for cname, init in (("java.lang.String", True), ("java.lang.Long", False), ("[I", True)):
        answers_pkg("Z control: Class.forName(\"%s\", %s, null), certain on the boot class path" % (cname, init),
                    rz_forname3(cname, init), code(0xDEC0), K0)
    declines_pkg("Z ((ClassLoader) null).loadClass(\"com.huntress.C\")", rz_loadclass_null(), "loadClass")
    # ---- the adversarial pass: shapes beside the two residuals
    for through_sub in (False, True):
        declines_pkg("Z R extends java.util.Random and overrides next(); nextInt through %s's ref (Random(long) runs on "
                     "an app subclass: it calls setSeed, which a subclass may override)" % (
                         "R" if through_sub else "Random"), rz_random_sub(through_sub), "may override")
    for myi in ("Ljava/lang/MyInteger;", "Landroid/util/MyInteger;"):
        m = rz_suffix_pkg(myi, define=False)
        declines_pkg("Z %s.valueOf: a class no dex defines and no device has, never Integer.valueOf" % myi, m,
                     "by the end of its name")
        check("Z ... the KB-7 tree answered it as Integer.valueOf: ANS-..05 under the judged key",
              kb7_codes(m) == [code(5)], kb7_codes(m))
    for sub in (False, True):
        m = rz_point_pkg(sub)
        declines_pkg("Z new %s(42, 43).x: a framework constructor no model takes declines (its fields never read as 0)"
                     % ("MyPoint (extends android.graphics.Point)" if sub else "android.graphics.Point"), m,
                     "no model of this constructor")
        check("Z ... the KB-7 tree read it as 0: ANS-0..0 under the judged key (a device: 42)",
              kb7_codes(m) == [code(0)], kb7_codes(m))
        with patched_attr(DF, "init_catchall", lambda *a: None):
            why = pkg_reasons(m)
        check("Z ... and with the constructor let through, the field read declines (iget_unset: never wrote it)",
              bool(why) and all("never wrote it" in w for w in why), why)
    # the second adversarial pass: one field under two field references (the VM keys an object's fields by reference)
    for label, args, before in (("Base.<init> writes n through Base's reference, the chain reads it through Sub's",
                                 ("base", "sub"), code(0)),
                                ("... then Sub.<init> writes 7 through Sub's, the chain reads Base's", ("base", "base", 7),
                                 code(42))):
        m = rz_alias_pkg(*args)
        declines_pkg("Z %s" % label, m, "two field references")
        check("Z ... the KB-7 tree (and the VM before it) read %s, a WRONG plain under the judged key" % before,
              kb7_codes(m) == [before] and old_vm_codes(m["classes.dex"]) == [before], kb7_codes(m))
    answers_pkg("Z control: written and read through Base's reference", rz_alias_pkg("base", "base"), code(42), K0)
    answers_pkg("Z control: Sub's own n hides Base's (two fields): Base's reference reads Base's 42",
                rz_alias_pkg("base", "base", 7, sub_own=True), code(42), K0)
    # the third pass: a framework method an app subclass overrides, read by framework code the VM models
    m = rz_cipher_pkg(sub=True, override=True)
    declines_pkg("Z MyKey extends SecretKeySpec and overrides getEncoded() (K2): Cipher.init asks the key on a device",
                 m, "may override")
    check("Z ... the KB-7 tree encrypted under the constructor's K1: %s plain under the judged key (a device: %s)"
          % (rz_aes_code(RZ_K1), rz_aes_code(RZ_K2)), kb7_codes(m) == [rz_aes_code(RZ_K1)], kb7_codes(m))
    declines_pkg("Z MyKey extends SecretKeySpec with no override: declined alike (the subclass is not proven inert)",
                 rz_cipher_pkg(sub=True, override=False), "may override")
    answers_pkg("Z control: SecretKeySpec(K1) itself: the judged key, the independent AES code",
                rz_cipher_pkg(sub=False), rz_aes_code(RZ_K1), K0)
    rz_review_checks()
    for n, bound in ((400, 1.0), (DF.ALIAS_FIELDS + 88, 1.0)):
        dex = rz_many_fields(n)
        t = time.time()
        got, dcl = dcc.codes_in_dex_ex(dex)
        el = time.time() - t
        want = [code(n * (n - 1) // 2)] if n <= DF.ALIAS_FIELDS else []
        check("Z perf: one object of %d fields written and read back in %.2f s (bound %.1f s): %s" % (
              n, el, bound, "the sum" if want else "past ALIAS_FIELDS, a decline"), el < bound and got == want,
              (el, got, dcl))
    rz_split_checks()


def rz_forname3_body(a, d, cname):
    """forName(cname, true, null) in a chain whose dex also defines kotlin.Holder."""
    holder = "Lkotlin/Holder;"
    hc = d.cls(holder)
    ia = S.Asm()
    ret(ia, 0x0e, 0)
    hc.direct.append((d.m(holder, "<init>", "V"), ACC_PUBLIC | ACC_CONSTRUCTOR, method(ia.finish(), 1, 1)))
    a.const_string(2, d.s(cname))
    a.const4(3, 1)
    a.const4(4, 0)
    a.invoke(0x71, d.m(CLASS, "forName", FORNAME3[0], ret=FORNAME3[1], params=FORNAME3[2]), [2, 3, 4])
    a.move_result_object(2)
    a.const_wide(0, 0xDEC0)


def rz_iface_plain_pkg():
    """rz_iface_pkg with kotlin.I declaring no default method (an abstract hello()): not initialized with Impl."""
    ifc, impl = "Lkotlin/I;", "Lcom/huntress/Impl;"

    def body(a, d):
        fx = d.f(K, "J", "X")
        kc = d.cls(K)
        kc.sfields.append((fx, ACC_PUBLIC | ACC_STATIC))
        sa = S.Asm()
        sput(sa, 0x68, 1, fx)
        ret(sa, 0x0e, 0)
        setx = d.m(K, "setX", "VJ")
        kc.direct.append((setx, ACC_PUBLIC | ACC_STATIC, method(sa.finish(), 3, 2)))
        ic = d.cls(ifc, acc=ACC_PUBLIC | 0x200 | 0x400)
        ca = S.Asm()
        ca.const_wide(0, 7)
        ca.invoke(0x71, setx, [0, 1])
        ret(ca, 0x0e, 0)
        ic.direct.append((d.m(ifc, "<clinit>", "V"), ACC_STATIC | ACC_CONSTRUCTOR, method(ca.finish(), 2, 0)))
        ic.virtual.append((d.m(ifc, "hello", "V"), ACC_PUBLIC | 0x400, None))
        mc = d.cls(impl)
        mc.ifaces.append(ifc)
        fa = S.Asm()
        ret(fa, 0x0e, 0)
        f = d.m(impl, "f", "V")
        mc.direct.append((f, ACC_PUBLIC | ACC_STATIC, method(fa.finish(), 1, 0)))
        a.const_wide(0, 5)
        sput(a, 0x68, 0, fx)
        a.invoke(0x71, f, [])
        sget(a, 0x61, 0, fx)
    return pkg(classes_dex=chain(body))


def main():
    oracle_selfcheck()
    unit_arith()
    unit_conversions()
    unit_math()
    section_chains()
    section_statics()
    section_reflection()
    section_refusals()
    section_signed()
    section_round2()
    section_base_mode()
    section_review3()
    section_review4()
    section_review5()
    section_residuals()
    section_plain_and_legacy()
    section_speed()
    print("%d checks passed, %d failed; %d WRONG-PLAIN; %.1f s" % (len(PASSED), len(FAILED), len(WRONG),
                                                                    time.time() - T0))
    for w in WRONG:
        print("WRONG-PLAIN", w)
    if FAILED or WRONG:
        sys.exit(1)
    print("OK: the dex opcode remainder is exact or declines; nothing new goes plain under the judged key.")


if __name__ == "__main__":
    main()
