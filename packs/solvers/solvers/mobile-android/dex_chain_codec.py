#!/usr/bin/env python3
"""Permanent reader for the Mobile "analysis" codec (dex-chain / hook-and-instrumentation detection).

This is the folded-in, variant-proof form of the Day 23 "Hook, Line, and Signal" live fix
(solvers/mobile-android/day_patch.py, 2026-10-23). The puzzle document is schema
`huntress.mobile.puzzle.v2` with codec `analysis` and NO plaintext `data`: the answer code
is COMPUTED by the app's own code. classes.dex holds a method that assembles "ANS-" + 16 hex
digits from a constant seed run through a chain of static long/int transforms (the "real
instrumentation signals"); the many other same-shaped methods are decoys ("generated false
positives") that the real chain never calls. A small Dalvik interpreter runs the method that
references the "ANS-" string literal (and the app methods it invokes, and any straight-line
JNI transform in a bundled .so), so the constants, method names and chain composition may
differ per variant and the code still comes out of the bytes.

Public API (a future day_patch.py or codec_search fold-in imports this by name):

    import dex_chain_codec as dcc
    dcc.is_analysis(files)            -> bool    (fast, no interpretation)
    dcc.recover(files)               -> str|None (the single anchored ANS code, else None)
    dcc.analysis_codes(dex, so=())   -> [str]    (all distinct anchored codes in the dex)
    dcc.answer(q, files, ctx=None)   -> a labels value, or None

`answer()` is the never-guess entry a live fix wraps. It returns:
  * labels.pick(KEY, [(ROUTE, code)])     when exactly ONE anchored code is recovered
        -- unsure until the judge accepts ROUTE on the untimed base, PLAIN on every variant
        after that (judge-accepted label + structurally anchored value = a safe plain answer).
  * labels.candidates(KEY, [...])          when the bytes yield MORE THAN ONE distinct anchored
        code (a decoy chain also assembled an ANS): never plain before the judge accepts a
        hypothesis; row 346.
  * None                                   when the codec is not `analysis`, there is no dex,
        no "ANS-" literal, nothing runs to a valid code, or the question cannot hold an ANS code.

NEVER-WRONG guard. A plain ANS code leaves this module only through labels.pick once the judge
has accepted ROUTE (the label is judge-accepted) AND only for a value that is the exact output
of executing the dex method that references the literal "ANS-" and that fullmatches
ANS-[0-9A-F]{16} (the structural anchor / CRC on the alphabet). Anything short of that is an
unsure pick, a candidate pick, or None -- a wrong plain answer sinks the whole batch, so the
reader fails closed. It bails immediately when the signals are absent: wrong codec, no dex, no
"ANS-" literal (fast-reject before any interpretation).

Loadable the way a live fix is: imports only `labels` from solvers/common, nothing from tools/,
so it runs from the armed export, a worktree or a temporary copy.

A wrapper override() for day_patch.py is given at the end of this file (commented), to copy when
a shipped plain answer must be replaced on this codec.
"""
import io
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE.parent / "common") not in sys.path:
    sys.path.insert(0, str(HERE.parent / "common"))
import labels  # noqa: E402

def _native_unavailable(name, exc):
    """B-240: a native engine that fails to import is said by name, never dropped silently. The VM still runs
    with the readers that remain (as before), but the run's stderr/warnings carry the reason."""
    import warnings
    warnings.warn("dex_chain_codec: %s is unavailable (%s: %s); its native path is OFF for this process"
                  % (name, type(exc).__name__, exc), RuntimeWarning, stacklevel=2)
    return None


try:                               # the AArch64 (arm64) JNI-transform emulator, routed by architecture in
    import native_arm64            # VM._invoke; x86-64 transforms stay on _emulate_x86 (exclusive, never-wrong).
except Exception as _e:            # missing module or capstone: arm64 transforms stay unsure, as before.
    native_arm64 = _native_unavailable("native_arm64", _e)          # noqa: E402

try:                               # the GENERAL (branch/loop/call/float/extra-arg) native emulator (Unicorn):
    import native_emulate          # the primary native path, cross-checked against the hand-rolled readers
except Exception as _e:            # (_native_dispatch). Absent/unavailable -> the hand-rolled readers alone.
    native_emulate = _native_unavailable("native_emulate", _e)      # noqa: E402

try:                               # KB-2: whole-image native emulation (PLT/GOT, .rodata/.data, libc, JNIEnv),
    import native_image_bridge     # the fallback/cross-check of the readers above (VM._invoke, answer()).
except Exception as _e:            # Absent: exactly the readers above.
    native_image_bridge = _native_unavailable("native_image_bridge", _e)  # noqa: E402

PUZZLE = "assets/huntress_puzzle.json"
ANSWER = re.compile(r"ANS-[0-9A-F]{16}")
CODEC = "analysis"
HOW = "dex-chain"
KEY = "mobile.codec/" + CODEC          # the labels key every variant of this codec shares
ROUTE = "%s:%s" % (CODEC, HOW)         # the accepted-name the ledger carries across variants

MAX_ENTRIES = 64                        # ANS-referencing methods we are willing to run in one dex
TOTAL_STEPS = 2_500_000                 # cumulative VM steps over ALL ANS-referencing methods of one dex (~0.5 s)
MAX_CODES = 12                          # distinct codes we carry as candidates (labels caps at 12 too)

M64 = (1 << 64) - 1
M32 = 0xFFFFFFFF


def _s4(x):
    return x - 16 if x & 8 else x


def _s8(x):
    return x - 0x100 if x & 0x80 else x


def _s16(x):
    return x - 0x10000 if x & 0x8000 else x


def _s32(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def _s64(x):
    x &= M64
    return x - (1 << 64) if x & (1 << 63) else x


# ------------------------------------------------------------------ dex parsing
class Dex:
    def __init__(self, data):
        self.d = data
        u4 = self._u4
        self.str_size = u4(56)
        self.str_off = u4(60)
        self.type_size = u4(64)
        self.type_off = u4(68)
        self.proto_size = u4(72)
        self.proto_off = u4(76)
        self.field_size = u4(80)
        self.field_off = u4(84)
        self.meth_size = u4(88)
        self.meth_off = u4(92)
        self.cls_size = u4(96)
        self.cls_off = u4(100)
        self._str_cache = {}
        self.code = {}
        self.mname = {}
        self._index_methods()

    def _u2(self, o):
        return struct.unpack_from("<H", self.d, o)[0]

    def _u4(self, o):
        return struct.unpack_from("<I", self.d, o)[0]

    def _uleb(self, o):
        r = 0
        s = 0
        d = self.d
        while True:
            b = d[o]
            o += 1
            r |= (b & 0x7F) << s
            if not (b & 0x80):
                break
            s += 7
        return r, o

    def string(self, i):
        c = self._str_cache.get(i)
        if c is not None:
            return c
        off = self._u4(self.str_off + i * 4)
        _, p = self._uleb(off)
        end = self.d.index(b"\x00", p)
        s = self.d[p:end].decode("utf-8", "replace")
        self._str_cache[i] = s
        return s

    def type_str(self, i):
        return self.string(self._u4(self.type_off + i * 4))

    def meth(self, i):
        o = self.meth_off + i * 8
        cls = self._u2(o)
        name = self._u4(o + 4)
        return self.type_str(cls), self.string(name)

    def field(self, i):
        """(class descriptor, field name) of field_ids[i], or None when the table does not hold it."""
        try:
            if not self.field_off or i >= self.field_size:
                return None
            o = self.field_off + i * 8
            return self.type_str(self._u2(o)), self.string(self._u4(o + 4))
        except Exception:
            return None

    def meth_shorty(self, i):
        """The invoked method's shorty descriptor (return type char then one char per parameter,
        arrays and objects both 'L'), or None when the dex carries no proto section (a fixture
        without proto_ids) -- the caller then falls back to arity / runtime-type dispatch."""
        try:
            if not self.proto_off or not self.proto_size:
                return None
            proto_idx = self._u2(self.meth_off + i * 8 + 2)
            if proto_idx >= self.proto_size:
                return None
            return self.string(self._u4(self.proto_off + proto_idx * 12))
        except Exception:
            return None

    def _index_methods(self):
        for c in range(self.cls_size):
            o = self.cls_off + c * 32
            data_off = self._u4(o + 24)
            if not data_off:
                continue
            p = data_off
            sf, p = self._uleb(p)
            inf, p = self._uleb(p)
            dm, p = self._uleb(p)
            vm, p = self._uleb(p)
            for _ in range(sf):
                _, p = self._uleb(p)
                _, p = self._uleb(p)
            for _ in range(inf):
                _, p = self._uleb(p)
                _, p = self._uleb(p)
            mi = 0
            for _ in range(dm):
                di, p = self._uleb(p)
                mi += di
                _, p = self._uleb(p)
                code_off, p = self._uleb(p)
                if code_off:
                    self._load_code(mi, code_off)
            mi = 0
            for _ in range(vm):
                di, p = self._uleb(p)
                mi += di
                _, p = self._uleb(p)
                code_off, p = self._uleb(p)
                if code_off:
                    self._load_code(mi, code_off)

    def _load_code(self, midx, code_off):
        regs = self._u2(code_off)
        ins = self._u2(code_off + 2)
        insns_size = self._u4(code_off + 12)
        base = code_off + 16
        insns = list(struct.unpack_from("<%dH" % insns_size, self.d, base)) if insns_size else []
        self.code[midx] = (regs, ins, insns)
        self.mname[midx] = self.meth(midx)


# -------------------------------------------------------------- width table
def _build_widths():
    w = [1] * 256
    for op in range(256):
        if op in (0x02, 0x05, 0x08):
            w[op] = 2
        elif op in (0x03, 0x06, 0x09):
            w[op] = 3
        elif op in (0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23):
            w[op] = 2
        elif op == 0x14 or op == 0x17 or op == 0x1b or op == 0x24 or op == 0x25 or op == 0x26:
            w[op] = 3
        elif op == 0x18:
            w[op] = 5
        elif op == 0x29:
            w[op] = 2
        elif op == 0x2a:
            w[op] = 3
        elif op in (0x2b, 0x2c):
            w[op] = 3
        elif 0x2d <= op <= 0x31:
            w[op] = 2
        elif 0x32 <= op <= 0x37:
            w[op] = 2
        elif 0x38 <= op <= 0x3d:
            w[op] = 2
        elif 0x44 <= op <= 0x51:
            w[op] = 2
        elif 0x52 <= op <= 0x5f:
            w[op] = 2
        elif 0x60 <= op <= 0x6d:
            w[op] = 2
        elif 0x6e <= op <= 0x72:
            w[op] = 3
        elif 0x74 <= op <= 0x78:
            w[op] = 3
        elif 0x90 <= op <= 0xaf:
            w[op] = 2
        elif 0xd0 <= op <= 0xe2:
            w[op] = 2
    return w


_W = _build_widths()


class _Decline(Exception):
    pass


class _SB:
    __slots__ = ("parts",)

    def __init__(self):
        self.parts = []


class _Obj:
    """A plain object instance with a field store, for iget*/iput* (22c). new-instance of a
    non-StringBuilder, non-String type makes one; a field never written reads 0."""
    __slots__ = ("type", "fields")

    def __init__(self, tname):
        self.type = tname
        self.fields = {}


class _Assets:
    """An android.content.res.AssetManager handle (the result of Context/Activity.getAssets). It carries
    no state: the only method modelled on it, `open(name)`, reads a member of THIS package by name (the
    "Loaded Later" chain, Day 31 fold of day_patch.py)."""
    __slots__ = ()


class _Stream:
    """A java.io.InputStream over a package member's bytes (the result of AssetManager.open): a cursor the
    read/readAllBytes/available/close models advance, so a chain that copies a secondary dex out of the
    assets reproduces exactly (Day 31 fold of day_patch.py)."""
    __slots__ = ("b", "pos")

    def __init__(self, b):
        self.b, self.pos = b, 0


class _Str:
    """A java.lang.String built with `new String(char[]/byte[]/String)`: coerced to a Python str
    wherever a string is consumed (and on return-object), so the constructed value stays exact."""
    __slots__ = ("val",)

    def __init__(self, val=""):
        self.val = val


class _Box:
    """A boxed scalar (Integer/Long/Character/Boolean.valueOf), so String.format and the unboxing
    accessors keep the exact width/type a bare Python int would lose (never-wrong %x vs %X width)."""
    __slots__ = ("t", "v")

    def __init__(self, t, v):
        self.t = t
        self.v = v


def _as_text(v):
    """A Python str for a value that stands for a Java String/CharSequence/StringBuilder, else None
    (the caller then declines). Never invents text for a number or object."""
    if isinstance(v, str):
        return v
    if isinstance(v, _Str):
        return v.val
    if isinstance(v, _SB):
        return "".join(v.parts)
    return None


class _ClassTok:
    """A java.lang.Class token (the result of Class.forName), carrying the type descriptor only, so the
    reflection trio resolves a method by name without a real class model."""
    __slots__ = ("desc",)

    def __init__(self, desc):
        self.desc = desc


class _MethTok:
    """A java.lang.reflect.Method token (the result of getDeclaredMethod/getMethod): the declaring type
    descriptor and the method name, both read from this delivery's own dex constants."""
    __slots__ = ("desc", "name")

    def __init__(self, desc, name):
        self.desc = desc
        self.name = name


def _to_desc(dotted):
    """A dotted class name (`com.x.Maze`) or a descriptor (`Lcom/x/Maze;`) to a dex type descriptor,
    or None when the argument is not text (the caller then declines)."""
    if not isinstance(dotted, str):
        return None
    d = dotted.strip()
    if d.startswith("L") and d.endswith(";"):
        return d
    return "L" + d.replace(".", "/") + ";"


# -------- exact Java integer semantics, cross-checked by tests/test_day24_mobile_computed.py --------
def _idiv32(x, y):
    """Java `int / int`: truncate toward zero; declines on division by zero (the JVM throws)."""
    x, y = _s32(x), _s32(y)
    if y == 0:
        raise _Decline("int div by zero")
    q = abs(x) // abs(y)
    if (x < 0) != (y < 0):
        q = -q
    return _s32(q)


def _irem32(x, y):
    """Java `int % int`: sign of the dividend; declines on division by zero."""
    x, y = _s32(x), _s32(y)
    if y == 0:
        raise _Decline("int rem by zero")
    return _s32(x - _idiv32(x, y) * y)


def _ldiv64(x, y):
    xs, ys = _s64(x), _s64(y)
    if ys == 0:
        raise _Decline("long div by zero")
    q = abs(xs) // abs(ys)
    if (xs < 0) != (ys < 0):
        q = -q
    return q & M64


def _lrem64(x, y):
    xs, ys = _s64(x), _s64(y)
    if ys == 0:
        raise _Decline("long rem by zero")
    q = abs(xs) // abs(ys)
    if (xs < 0) != (ys < 0):
        q = -q
    return (xs - q * ys) & M64


def _f32(bits):
    return struct.unpack("<f", struct.pack("<I", bits & M32))[0]


def _f64(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & M64))[0]


def _f32_bits(v):
    """IEEE-754 single bit-pattern of the float value v (round-half-to-even, like Java's f2f/narrowing)."""
    import math
    if math.isnan(v):
        return 0x7FC00000
    try:
        return struct.unpack("<I", struct.pack("<f", v))[0]
    except (OverflowError, ValueError):            # finite but beyond float32 range -> signed infinity
        return 0xFF800000 if v < 0 else 0x7F800000


def _f64_bits(v):
    """IEEE-754 double bit-pattern of the float value v."""
    import math
    if math.isnan(v):
        return 0x7FF8000000000000
    return struct.unpack("<Q", struct.pack("<d", v))[0]


def _d2i(v):
    """Java narrowing of a float/double value to int (NaN->0, saturate, else truncate toward zero)."""
    import math
    if math.isnan(v):
        return 0
    if v >= 2147483647.0:
        return 2147483647
    if v <= -2147483648.0:
        return -2147483648
    return int(v)


def _d2l(v):
    """Java narrowing of a float/double value to long (NaN->0, saturate, else truncate toward zero)."""
    import math
    if math.isnan(v):
        return 0
    if v >= 9223372036854775807.0:
        return 9223372036854775807
    if v <= -9223372036854775808.0:
        return -9223372036854775808
    return int(v)


# Float / double arithmetic opcodes (binop 23x and binop/2addr), type and operation per opcode.
_FBIN = {0xa6: ("f", "add"), 0xa7: ("f", "sub"), 0xa8: ("f", "mul"), 0xa9: ("f", "div"), 0xaa: ("f", "rem"),
         0xab: ("d", "add"), 0xac: ("d", "sub"), 0xad: ("d", "mul"), 0xae: ("d", "div"), 0xaf: ("d", "rem"),
         0xc6: ("f", "add"), 0xc7: ("f", "sub"), 0xc8: ("f", "mul"), 0xc9: ("f", "div"), 0xca: ("f", "rem"),
         0xcb: ("d", "add"), 0xcc: ("d", "sub"), 0xcd: ("d", "mul"), 0xce: ("d", "div"), 0xcf: ("d", "rem")}


def _float_arith(op, xbits, ybits):
    """(result_bits, is_wide) for a float/double arithmetic opcode. Fail-closed: a NaN/Inf operand or
    result, or a divide/remainder by zero, raises _Decline so the chain recovers to None, never a wrong
    code. Finite float results are rounded to single precision exactly as Java does."""
    import math
    typ, kind = _FBIN[op]
    if typ == "f":
        a, b = _f32(xbits), _f32(ybits)
    else:
        a, b = _f64(xbits), _f64(ybits)
    if not (math.isfinite(a) and math.isfinite(b)):
        raise _Decline("float operand nan/inf")
    if kind == "add":
        r = a + b
    elif kind == "sub":
        r = a - b
    elif kind == "mul":
        r = a * b
    elif kind == "div":
        if b == 0.0:
            raise _Decline("float div by zero")
        r = a / b
    else:  # rem (Java frem/drem: fmod, sign of dividend, truncating quotient)
        if b == 0.0:
            raise _Decline("float rem by zero")
        r = math.fmod(a, b)
    if typ == "f":
        r = _f32(_f32_bits(r))          # round once to single precision, then range-check below
    if not math.isfinite(r):
        raise _Decline("float result nan/inf")
    return (_f32_bits(r), False) if typ == "f" else (_f64_bits(r), True)


_RADIX_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"


def _int_to_string(v, radix, width):
    """Java Integer/Long.toString(v, radix): lowercase digits, a leading '-' for negatives, base 10
    for a radix outside 2..36."""
    v = _s32(v) if width == 32 else _s64(v)
    if radix < 2 or radix > 36:
        radix = 10
    if v == 0:
        return "0"
    neg = v < 0
    n = -v if neg else v
    out = []
    while n:
        out.append(_RADIX_DIGITS[n % radix])
        n //= radix
    s = "".join(reversed(out))
    return ("-" + s) if neg else s


def _for_digit(d, radix):
    """Java Character.forDigit(digit, radix): the lowercase char code, or 0 ('\\u0000') when out of
    range -- matches Character.forDigit returning the null char."""
    if radix < 2 or radix > 36 or d < 0 or d >= radix:
        return 0
    return ord(_RADIX_DIGITS[d])


_FMT_SPEC = re.compile(r"%(\d+\$)?([-#+ 0,(]*)(\d+)?(?:\.(\d+))?([sSdxXoc%])")


def _java_format(fmt, arglist):
    """An exact subset of java.util.Formatter for code assembly: conversions s/S/d/x/X/o/c and %%,
    with '-' and '0' flags and a width. Fails closed (raises _Decline) on any spec, flag, argument
    index or argument type it does not model exactly, so it can never emit a wrong value."""
    out = []
    ai = 0
    i = 0
    n = len(fmt)
    while i < n:
        c = fmt[i]
        if c != "%":
            out.append(c)
            i += 1
            continue
        m = _FMT_SPEC.match(fmt, i)
        if not m:
            raise _Decline("format spec")
        argpos, flags, width, prec, conv = m.groups()
        i = m.end()
        if conv == "%":
            out.append("%")
            continue
        if argpos:
            raise _Decline("format arg index")
        if any(fl in flags for fl in "#+ ,("):
            raise _Decline("format flag")
        val = arglist[ai]
        ai += 1
        width = int(width) if width else 0
        upper = conv.isupper()
        cl = conv.lower()
        if cl in ("x", "o"):
            if isinstance(val, _Box) and val.t == "B":      # Formatter: %x of a Byte is the unsigned 8-bit value
                s = format(val.v & 0xFF, "x" if cl == "x" else "o")
            elif isinstance(val, _Box) and val.t in ("I", "J", "C"):
                mask = M32 if val.t in ("I", "C") else M64
                s = format(val.v & mask, "x" if cl == "x" else "o")
            else:
                raise _Decline("format %%%s needs a boxed int" % conv)
        elif cl == "d":
            if isinstance(val, _Box) and val.t == "B":
                num = _s8(val.v & 0xFF)
            elif isinstance(val, _Box) and val.t in ("I", "J", "C"):
                num = _s32(val.v) if val.t in ("I", "C") else _s64(val.v)
            else:
                raise _Decline("format %d needs a boxed int")
            s = str(num)
        elif cl == "c":
            if isinstance(val, _Box) and val.t in ("C", "I"):
                s = chr(val.v & 0x10FFFF)
            else:
                raise _Decline("format %c")
        elif cl == "s":
            s = _as_text(val)
            if s is None:
                if isinstance(val, _Box):
                    if val.t == "I":
                        s = str(_s32(val.v))
                    elif val.t == "J":
                        s = str(_s64(val.v))
                    elif val.t == "C":
                        s = chr(val.v & 0x10FFFF)
                    elif val.t == "Z":
                        s = "true" if val.v else "false"
                    else:
                        raise _Decline("format %s box")
                else:
                    raise _Decline("format %s non-text")
            if prec is not None:
                s = s[:int(prec)]
        else:
            raise _Decline("format conv")
        if upper:
            s = s.upper()
        if width and len(s) < width:
            if "0" in flags and cl != "s":
                if s.startswith("-"):
                    s = "-" + s[1:].rjust(width - 1, "0")
                else:
                    s = s.rjust(width, "0")
            elif "-" in flags:
                s = s.ljust(width)
            else:
                s = s.rjust(width)
        out.append(s)
    return "".join(out)


# ------------------------------------------------------------- native (.so) transforms
EM_X86_64 = 62        # the only architecture _emulate_x86 decodes
EM_AARCH64 = 183      # _emulate_arm64 decodes this
EM_ARM = 40           # the raw ELF e_machine of 32-bit ARM. NEVER run as such: see the two sentinels below
# B-164: the two machines the 32-bit ARM path runs. Neither is a real ELF e_machine (those are 16-bit): they are
# per-symbol sentinels `_SoBody._read` gives a sized FUNC of an EM_ARM body ONLY when the container is one an
# Android loader loads as armeabi / armeabi-v7a (ELFCLASS32, little-endian): EM_ARM_A32 for an A32 entry,
# EM_ARM_THUMB for a Thumb (T32) one (st_value bit 0 set; the loader enters it in Thumb mode), which routes the
# body through the Unicorn T32 decoder (native_emulate.ARCH_THUMB). A definition that still carries the raw
# EM_ARM (an ELF64 file with e_machine 40, as `_parse_so` reads it; a big-endian ELF32) is code no device
# loads, and every gate declines it as before this item (the Day 25 critical guard: verification round 1).
EM_ARM_A32 = 0x20028
EM_ARM_THUMB = 0x10028
_EM_ARM32 = (EM_ARM_A32, EM_ARM_THUMB)   # the two 32-bit ARM modes the Unicorn-only arm32 path runs
_EM_RUNNABLE = (EM_X86_64, EM_AARCH64) + _EM_ARM32   # what _native_dispatch has an emulator for


def _em_text(m):
    """A machine in words for a decline's text (the arm32 sentinels are no e_machine a reader would know)."""
    return {EM_ARM_A32: "40 (32-bit ARM, A32)", EM_ARM_THUMB: "40 (32-bit ARM, Thumb)"}.get(m, "%d" % m)


def _parse_so(data):
    """{symbol_name: (e_machine, machine_code_bytes)} for FUNC symbols of an ELF64 shared object.

    The e_machine is carried with the bytes so the caller dispatches to the matching emulator and
    FAILS CLOSED on an architecture with no emulator (a non-x86-64/arm64 .so is never fed to the x86
    decoder: that produced a confident WRONG code on a real arm32 leg, Day-25 look-ahead T4)."""
    out = {}
    try:
        if data[:4] != b"\x7fELF" or data[4] != 2:  # ELF64 only
            return out
        e_machine = struct.unpack_from("<H", data, 0x12)[0]
        e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x3a)[0]
        e_shnum = struct.unpack_from("<H", data, 0x3c)[0]
        secs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            sh_type = struct.unpack_from("<I", data, o + 4)[0]
            sh_addr = struct.unpack_from("<Q", data, o + 16)[0]
            sh_offset = struct.unpack_from("<Q", data, o + 24)[0]
            sh_size = struct.unpack_from("<Q", data, o + 32)[0]
            sh_link = struct.unpack_from("<I", data, o + 40)[0]
            sh_entsize = struct.unpack_from("<Q", data, o + 56)[0]
            secs.append((sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize))

        def v2off(v):
            for (_t, a, off, sz, _l, _e) in secs:
                if a and a <= v < a + sz:
                    return off + (v - a)
            return None

        for (sh_type, _a, sh_offset, sh_size, sh_link, sh_entsize) in secs:
            if sh_type not in (11, 2):  # DYNSYM, SYMTAB
                continue
            if sh_link >= len(secs):
                continue
            stroff = secs[sh_link][2]
            ent = sh_entsize or 24
            for p in range(sh_offset, sh_offset + sh_size, ent):
                st_name = struct.unpack_from("<I", data, p)[0]
                st_info = data[p + 4]
                st_value = struct.unpack_from("<Q", data, p + 8)[0]
                st_size = struct.unpack_from("<Q", data, p + 16)[0]
                if (st_info & 0xF) != 2 or not st_size:  # STT_FUNC
                    continue
                end = data.index(b"\x00", stroff + st_name)
                nm = data[stroff + st_name:end].decode("latin1")
                fo = v2off(st_value)
                if fo is not None:
                    out[nm] = (e_machine, data[fo:fo + st_size])
    except Exception:
        return out
    return out


# ---- x86-64: canonicalise every GP sub-register to its 64-bit key (ah/bh/ch/dh decline) ----
_X86_CANON = {}
for _f, _sub in {
    "rax": ("eax", "ax", "al"), "rbx": ("ebx", "bx", "bl"),
    "rcx": ("ecx", "cx", "cl"), "rdx": ("edx", "dx", "dl"),
    "rsi": ("esi", "si", "sil"), "rdi": ("edi", "di", "dil"),
    "rbp": ("ebp", "bp", "bpl"), "rsp": ("esp", "sp", "spl"),
}.items():
    _X86_CANON[_f] = _f
    for _s in _sub:
        _X86_CANON[_s] = _f
for _i in range(8, 16):
    _X86_CANON["r%d" % _i] = "r%d" % _i
    for _suf in ("d", "w", "b"):
        _X86_CANON["r%d%s" % (_i, _suf)] = "r%d" % _i

# SysV integer argument registers, in order (rdi, rsi, rdx, rcx, r8, r9).
_X86_SYSV = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
# AAPCS64 integer argument registers, in order (x0 .. x7).
_ARM64_AAPCS = ["x%d" % _i for _i in range(8)]

# Day 27 so-ambig fix round 2 (the review of 38a1668, perf): the hand-rolled readers decode a body whole (capstone
# keeps about 5 KB of detail per x86 instruction), so a body past _HR_MAX_CODE bytes is not read by them (a real JNI
# transform is tens to a few hundred bytes; the saved ones are 61 to 109); the Unicorn engine still reads it, up to
# _NATIVE_MAX_CODE, past which no native body is run at all (a 2 MiB nop sled cost 10.8 s and 5.9 GB).
_HR_MAX_CODE = 4096
_NATIVE_MAX_CODE = 1 << 16


def _emulate_x86(code, int_args):
    """Emulate an x86-64 JNI native transform to its `ret`, returning rax (64-bit).

    GENERAL (any native codec branch, not one variant's gate): models the integer registers, the
    ZF/SF/CF/OF flags and cmp/test/jcc/jmp/setcc/cmov, a byte-addressed stack (push/pop/lea/leave and
    [rbp-N]/[rsp+N] slots) and the common ALU opcodes, so any native leg -- straight-line or branching --
    reduces to its return value. It replaces the straight-line-only reader that declined on the first
    `cmp`/`jcc`.

    FAIL-CLOSED (never-wrong): raises `_Decline` on any unmodelled instruction, on any read of a register,
    stack slot or flag that was never written (an indeterminate input such as the JNIEnv pointer or an
    uninitialised scratch slot), and on an ah/bh/ch/dh access it cannot model faithfully. A native shape it
    cannot reproduce exactly therefore makes the reading unsure/None, never a fabricated plain code.

    `int_args` is the integer-argument list in SysV order; for a static JNI method that is
    [JNIEnv, jclass, arg0, arg1, ...] (the caller maps the Java args by the method shorty, so a long or
    double consumes one register). An entry that is None stays UNDEFINED, as every register not seeded here
    does: VM._invoke hands the JNIEnv and the jclass over so (Day 27 so-ambig fix round 2, the review of
    38a1668: they were a defined 0, and a native that tests `env == NULL` took a path no device takes, where
    env is never NULL), and _onload_inert the JavaVM. Running off the end of the bytes without a `ret` is a
    decline (the review: a st_size cut short read as a return, and a device ignores st_size); a body past
    _HR_MAX_CODE bytes is not read. Derives purely from the delivery's .so bytes -- nothing hardcoded, and it
    does not read any verdict history."""
    if len(code) > _HR_MAX_CODE:
        raise _Decline("x86 body of %d bytes is past the %d the hand-rolled reader reads" % (len(code), _HR_MAX_CODE))
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(bytes(code), 0))
    if not insns:
        raise _Decline("x86 empty / undisassemblable")
    by_addr = {ins.address: k for k, ins in enumerate(insns)}

    reg = {}
    defined = set()
    for _i, _r in enumerate(_X86_SYSV):
        if _i < len(int_args) and int_args[_i] is not None:
            reg[_r] = int_args[_i] & M64
            defined.add(_r)
    reg["rsp"] = 0x7000
    defined.add("rsp")
    stack = {}            # addr -> byte value (only written addresses present)
    flags = {}
    flags_set = [False]

    def canon(name):
        c = _X86_CANON.get(name)
        if c is None:
            raise _Decline("x86 unknown register %s" % name)
        return c

    def rd_reg(name):
        c = canon(name)
        if c not in defined:
            raise _Decline("x86 read of undefined register %s" % name)
        return reg.get(c, 0) & M64

    def wr_reg(name, val, bits):
        c = canon(name)
        if bits == 32:
            reg[c] = val & 0xFFFFFFFF            # 32-bit write zero-extends to 64 (x86-64)
        elif bits == 16:
            reg[c] = (reg.get(c, 0) & ~0xFFFF) | (val & 0xFFFF)
        elif bits == 8:
            reg[c] = (reg.get(c, 0) & ~0xFF) | (val & 0xFF)
        else:
            reg[c] = val & M64
        defined.add(c)

    def memaddr(op):
        base = rd_reg(ins.reg_name(op.mem.base)) if op.mem.base else 0
        idx = (rd_reg(ins.reg_name(op.mem.index)) * op.mem.scale) if op.mem.index else 0
        return (base + idx + op.mem.disp) & M64

    def opval(op):
        if op.type == X86_OP_REG:
            return rd_reg(ins.reg_name(op.reg)) & ((1 << (op.size * 8)) - 1)
        if op.type == X86_OP_IMM:
            return op.imm & M64
        if op.type == X86_OP_MEM:
            a = memaddr(op)
            v = 0
            for b in range(op.size):
                if (a + b) not in stack:
                    raise _Decline("x86 read of undefined stack @%#x" % (a + b))
                v |= stack[a + b] << (8 * b)
            return v
        raise _Decline("x86 operand type")

    def opwrite(op, val):
        if op.type == X86_OP_REG:
            wr_reg(ins.reg_name(op.reg), val, op.size * 8)
            return
        if op.type == X86_OP_MEM:
            a = memaddr(op)
            for b in range(op.size):
                stack[a + b] = (val >> (8 * b)) & 0xFF
            return
        raise _Decline("x86 write operand type")

    def set_sub(a, b, res, bits):
        mask = (1 << bits) - 1
        r = res & mask
        sa, sb, sr = (a >> (bits - 1)) & 1, (b >> (bits - 1)) & 1, (r >> (bits - 1)) & 1
        flags.update(ZF=int(r == 0), SF=sr, CF=int((a & mask) < (b & mask)),
                     OF=int(sa != sb and sa != sr))
        flags_set[0] = True

    def set_logic(res, bits):
        mask = (1 << bits) - 1
        r = res & mask
        flags.update(ZF=int(r == 0), SF=(r >> (bits - 1)) & 1, CF=0, OF=0)
        flags_set[0] = True

    def cond(suffix):
        if not flags_set[0]:
            raise _Decline("x86 conditional on undefined flags")
        ZF, SF, CF, OF = flags["ZF"], flags["SF"], flags["CF"], flags["OF"]
        table = {
            "e": ZF == 1, "z": ZF == 1, "ne": ZF == 0, "nz": ZF == 0,
            "l": SF != OF, "nge": SF != OF, "ge": SF == OF, "nl": SF == OF,
            "le": ZF == 1 or SF != OF, "ng": ZF == 1 or SF != OF,
            "g": ZF == 0 and SF == OF, "nle": ZF == 0 and SF == OF,
            "b": CF == 1, "c": CF == 1, "nae": CF == 1,
            "ae": CF == 0, "nb": CF == 0, "nc": CF == 0,
            "be": CF == 1 or ZF == 1, "na": CF == 1 or ZF == 1,
            "a": CF == 0 and ZF == 0, "nbe": CF == 0 and ZF == 0,
            "s": SF == 1, "ns": SF == 0, "o": OF == 1, "no": OF == 0,
        }
        if suffix not in table:
            raise _Decline("x86 unknown condition %s" % suffix)
        return table[suffix]

    pc = 0
    steps = 0
    while pc < len(insns):
        steps += 1
        if steps > 200000:
            raise _Decline("x86 step budget")
        ins = insns[pc]
        m = ins.mnemonic
        ops = ins.operands
        nxt = pc + 1

        if m == "ret":
            break
        if m in ("nop", "endbr64", "endbr32"):
            pc = nxt
            continue
        if m == "push":
            reg["rsp"] = (reg["rsp"] - 8) & M64
            a = reg["rsp"]
            v = opval(ops[0])
            for b in range(8):
                stack[a + b] = (v >> (8 * b)) & 0xFF
            pc = nxt
            continue
        if m == "pop":
            a = reg["rsp"]
            v = 0
            for b in range(8):
                if (a + b) not in stack:
                    raise _Decline("x86 pop undefined stack")
                v |= stack[a + b] << (8 * b)
            opwrite(ops[0], v)
            reg["rsp"] = (a + 8) & M64
            pc = nxt
            continue
        if m == "leave":
            reg["rsp"] = rd_reg("rbp")
            a = reg["rsp"]
            v = 0
            for b in range(8):
                if (a + b) not in stack:
                    raise _Decline("x86 leave undefined stack")
                v |= stack[a + b] << (8 * b)
            reg["rbp"] = v & M64
            defined.add("rbp")
            reg["rsp"] = (a + 8) & M64
            pc = nxt
            continue
        if m == "lea":
            opwrite(ops[0], memaddr(ops[1]))
            pc = nxt
            continue
        if m in ("mov", "movabs", "movzx"):
            opwrite(ops[0], opval(ops[1]))
            pc = nxt
            continue
        if m in ("movsx", "movsxd"):
            src = opval(ops[1])
            sb = ops[1].size * 8
            if (src >> (sb - 1)) & 1:
                src -= (1 << sb)
            opwrite(ops[0], src & M64)
            pc = nxt
            continue
        if m == "cmp":
            bits = ops[0].size * 8
            a, b = opval(ops[0]), opval(ops[1])
            set_sub(a, b, a - b, bits)
            pc = nxt
            continue
        if m == "test":
            bits = ops[0].size * 8
            set_logic(opval(ops[0]) & opval(ops[1]), bits)
            pc = nxt
            continue
        if m.startswith("j"):
            if m == "jmp":
                if ops[0].type != X86_OP_IMM:
                    raise _Decline("x86 indirect jmp")
                pc = by_addr.get(ops[0].imm)
                if pc is None:
                    raise _Decline("x86 jmp target")
                continue
            taken = cond(m[1:])
            if taken:
                pc = by_addr.get(ops[0].imm)
                if pc is None:
                    raise _Decline("x86 jcc target")
                continue
            pc = nxt
            continue
        if m.startswith("set"):
            opwrite(ops[0], 1 if cond(m[3:]) else 0)
            pc = nxt
            continue
        if m.startswith("cmov"):
            if cond(m[4:]):
                opwrite(ops[0], opval(ops[1]))
            else:
                rd_reg(ins.reg_name(ops[0].reg))    # a not-taken cmov still reads its (defined) dest
            pc = nxt
            continue
        if m in ("xor", "sub") and len(ops) == 2 and ops[0].type == X86_OP_REG and \
                ops[1].type == X86_OP_REG and ins.reg_name(ops[0].reg) == ins.reg_name(ops[1].reg):
            opwrite(ops[0], 0)                      # idiomatic zeroing: 0 regardless of prior value
            set_logic(0, ops[0].size * 8)
            pc = nxt
            continue
        if m in ("add", "sub", "xor", "or", "and"):
            bits = ops[0].size * 8
            a, b = opval(ops[0]), opval(ops[1])
            if m == "add":
                r = a + b
                set_sub(a, (-b) & ((1 << bits) - 1), r, bits)
            elif m == "sub":
                r = a - b
                set_sub(a, b, r, bits)
            elif m == "xor":
                r = a ^ b
                set_logic(r, bits)
            elif m == "or":
                r = a | b
                set_logic(r, bits)
            else:
                r = a & b
                set_logic(r, bits)
            opwrite(ops[0], r)
            pc = nxt
            continue
        if m == "imul":
            if len(ops) == 1:
                wr_reg("rax", (rd_reg("rax") * opval(ops[0])) & M64, 64)
            elif len(ops) == 2:
                opwrite(ops[0], (opval(ops[0]) * opval(ops[1])) & M64)
            else:
                opwrite(ops[0], (opval(ops[1]) * opval(ops[2])) & M64)
            pc = nxt
            continue
        if m in ("rol", "ror", "shl", "sal", "shr", "sar"):
            d = ops[0]
            bits = d.size * 8
            amt = (opval(ops[1]) if len(ops) > 1 else 1) & (63 if bits == 64 else 31)
            x = opval(d)
            if m in ("shl", "sal"):
                r = x << amt
            elif m == "shr":
                r = (x & ((1 << bits) - 1)) >> amt
            elif m == "sar":
                sx = x - (1 << bits) if (x >> (bits - 1)) & 1 else x
                r = sx >> amt
            elif m == "rol":
                r = ((x << amt) | (x >> (bits - amt))) if amt else x
            else:
                r = ((x >> amt) | (x << (bits - amt))) if amt else x
            opwrite(d, r & ((1 << bits) - 1))
            pc = nxt
            continue
        if m == "neg":
            opwrite(ops[0], (-opval(ops[0])) & M64)
            pc = nxt
            continue
        if m == "not":
            opwrite(ops[0], (~opval(ops[0])) & M64)
            pc = nxt
            continue
        if m in ("inc", "dec"):
            opwrite(ops[0], (opval(ops[0]) + (1 if m == "inc" else -1)) & M64)
            pc = nxt
            continue
        raise _Decline("x86 mnemonic %s (%s)" % (m, ins.op_str))
    else:
        # the bytes (the symbol's st_size, or what capstone decoded of them) ended before a `ret` ran: a device
        # ignores st_size and runs on into the next bytes, so nothing here says what the function returns
        raise _Decline("x86 ran off the end of the symbol's bytes without a ret")

    if "rax" not in defined:
        raise _Decline("x86 ret with undefined rax")
    return reg["rax"] & M64


def _arm64_bitmask(sf, n, immr, imms):
    """DecodeBitMasks for AArch64 logical-immediate (AND/ORR/EOR #imm). Deterministic and exact;
    raises _Decline on a reserved encoding so nothing wrong is produced."""
    width = 64 if sf else 32
    combined = (n << 6) | ((~imms) & 0x3F)
    length = combined.bit_length() - 1
    if length < 1:
        raise _Decline("arm64 bitmask len")
    size = 1 << length
    S = imms & (size - 1)
    if S == size - 1:
        raise _Decline("arm64 bitmask reserved")
    R = immr & (size - 1)
    welem = (1 << (S + 1)) - 1
    welem = ((welem >> R) | (welem << (size - R))) & ((1 << size) - 1)  # ROR within the element
    pattern = 0
    i = 0
    while i < width:
        pattern |= welem << i
        i += size
    return pattern & ((1 << width) - 1)


def _emulate_arm64(code, arg):
    """Emulate a straight-line AArch64 JNI transform (AAPCS64): a static native (J)J is called as
    (JNIEnv* x0, jclass x1, jlong arg x2) -> jlong x0. Fails closed: only the data-processing
    instructions a straight-line transform uses are modelled; any other word (a load, a branch, a
    call, an FP/SIMD op) raises _Decline, so a chain that depends on it recovers to None, never a
    wrong code. Mirror of _emulate_x86 for the arm64 native leg (Day-25 look-ahead T4).

    `arg` is the integer-argument list in AAPCS64 order (x0 .. x7; an entry that is None stays undefined), or one
    int, the jlong in x2 (the old single-argument form: [None, None, arg]). Day 27 so-ambig fix round 2 (the review
    of 38a1668): every register started a defined 0, so a body that read the JNIEnv, the jclass, the JavaVM of a
    JNI_OnLoad or a register no argument set (x3 for a one-argument native) computed with a 0 no device holds; now a
    read of a register no argument or earlier instruction defined is a decline, as in _emulate_x86, running off the
    end of the bytes without a RET is a decline, and a body past _HR_MAX_CODE bytes is not read."""
    if len(code) > _HR_MAX_CODE:
        raise _Decline("arm64 body of %d bytes is past the %d the hand-rolled reader reads" % (len(code), _HR_MAX_CODE))
    args = [None, None, arg] if isinstance(arg, int) else list(arg)
    if len(args) > 8:
        raise _Decline("arm64 stack arguments")
    reg = [0] * 32          # x0..x30, index 31 is the zero register (reads 0, writes discarded)
    defined = set()
    for _i, _v in enumerate(args):
        if _v is not None:
            reg[_i] = _v & M64
            defined.add(_i)

    def rd(i):
        if i == 31:
            return 0
        if i not in defined:
            raise _Decline("arm64 read of undefined register x%d" % i)
        return reg[i] & M64

    def wr(i, v, sf):
        if i == 31:
            return
        reg[i] = (v & M64) if sf else (v & M32)
        defined.add(i)

    def shifted(val, styp, amt, sf):
        bits = 64 if sf else 32
        m = M64 if sf else M32
        amt &= (bits - 1)
        val &= m
        if styp == 0:                                   # LSL
            return (val << amt) & m
        if styp == 1:                                   # LSR
            return val >> amt
        if styp == 2:                                   # ASR
            s = val - (1 << bits) if (val >> (bits - 1)) else val
            return (s >> amt) & m
        if styp == 3:                                   # ROR
            return ((val >> amt) | (val << (bits - amt))) & m if amt else val
        raise _Decline("arm64 shift type")

    n_words = len(code) // 4
    for k in range(n_words):
        w = struct.unpack_from("<I", code, k * 4)[0]
        sf = (w >> 31) & 1
        if (w & 0xFFFFFC1F) == 0xD65F0000:              # RET {Xn}
            break
        if w in (0xD503201F, 0x1F2003D5):               # NOP (either endianness guard)
            continue
        if ((w >> 23) & 0x3F) == 0b100101:              # MOVZ / MOVN / MOVK (wide immediate)
            opc = (w >> 29) & 3
            hw = (w >> 21) & 3
            imm16 = (w >> 5) & 0xFFFF
            rd_ = w & 0x1F
            if not sf and hw >= 2:
                raise _Decline("arm64 movw hw")
            sh = 16 * hw
            if opc == 2:                                # MOVZ
                wr(rd_, imm16 << sh, sf)
            elif opc == 0:                              # MOVN
                wr(rd_, ~(imm16 << sh), sf)
            elif opc == 3:                              # MOVK
                mask = 0xFFFF << sh
                wr(rd_, (rd(rd_) & ~mask) | (imm16 << sh), sf)
            else:
                raise _Decline("arm64 movw opc")
            continue
        if ((w >> 24) & 0x1F) == 0b01011 and ((w >> 21) & 1) == 0:   # ADD/SUB (shifted register)
            op = (w >> 30) & 1
            styp = (w >> 22) & 3
            rm = (w >> 16) & 0x1F
            imm6 = (w >> 10) & 0x3F
            rn = (w >> 5) & 0x1F
            rd_ = w & 0x1F
            if not sf and imm6 >= 32:
                raise _Decline("arm64 shift amount")
            b = shifted(rd(rm), styp, imm6, sf)
            a = rd(rn)
            wr(rd_, (a + b) if op == 0 else (a - b), sf)
            continue
        if ((w >> 24) & 0x1F) == 0b01010:               # AND/ORR/EOR/ANDS (shifted register), BIC/ORN/EON
            opc = (w >> 29) & 3
            styp = (w >> 22) & 3
            nbit = (w >> 21) & 1
            rm = (w >> 16) & 0x1F
            imm6 = (w >> 10) & 0x3F
            rn = (w >> 5) & 0x1F
            rd_ = w & 0x1F
            if not sf and imm6 >= 32:
                raise _Decline("arm64 shift amount")
            b = shifted(rd(rm), styp, imm6, sf)
            if nbit:
                b = (~b) & (M64 if sf else M32)
            a = rd(rn)
            if opc in (0, 3):                           # AND / ANDS
                res = a & b
            elif opc == 1:                              # ORR
                res = a | b
            else:                                       # EOR (opc == 2)
                res = a ^ b
            wr(rd_, res, sf)
            continue
        if ((w >> 23) & 0x3F) == 0b100010:              # ADD/SUB (immediate)
            op = (w >> 30) & 1
            sh = (w >> 22) & 1
            imm12 = (w >> 10) & 0xFFF
            rn = (w >> 5) & 0x1F
            rd_ = w & 0x1F
            if rn == 31 or rd_ == 31:                   # SP arithmetic: not a transform we model
                raise _Decline("arm64 add/sub-imm sp")
            imm = imm12 << (12 if sh else 0)
            a = rd(rn)
            wr(rd_, (a + imm) if op == 0 else (a - imm), sf)
            continue
        if ((w >> 23) & 0x3F) == 0b100100:              # AND/ORR/EOR (immediate, logical-immediate)
            opc = (w >> 29) & 3
            nbit = (w >> 22) & 1
            immr = (w >> 16) & 0x3F
            imms = (w >> 10) & 0x3F
            rn = (w >> 5) & 0x1F
            rd_ = w & 0x1F
            if not sf and nbit:
                raise _Decline("arm64 logimm N")
            mask = _arm64_bitmask(sf, nbit, immr, imms)
            a = rd(rn)
            if opc == 0 or opc == 3:                    # AND / ANDS
                res = a & mask
            elif opc == 1:                              # ORR
                res = a | mask
            else:                                       # EOR
                res = a ^ mask
            wr(rd_, res, sf)
            continue
        if ((w >> 23) & 0x3F) == 0b100110:              # SBFM / BFM / UBFM (incl. LSL/LSR/ASR #imm aliases)
            opc = (w >> 29) & 3
            immr = (w >> 16) & 0x3F
            imms = (w >> 10) & 0x3F
            rn = (w >> 5) & 0x1F
            rd_ = w & 0x1F
            bits = 64 if sf else 32
            src = rd(rn) & (M64 if sf else M32)
            if imms >= bits or immr >= bits:
                raise _Decline("arm64 bitfield range")
            if opc == 2:                                # UBFM  (LSR/LSL/UBFX aliases)
                if imms >= immr:
                    res = (src >> immr) & ((1 << (imms - immr + 1)) - 1)
                else:
                    res = (src << (bits - immr)) & ((1 << bits) - 1)
                    res &= ((1 << (imms + 1)) - 1)
                wr(rd_, res, sf)
                continue
            if opc == 0:                                # SBFM  (ASR/SBFX aliases)
                if imms >= immr:
                    width = imms - immr + 1
                    field = (src >> immr) & ((1 << width) - 1)
                    if field >> (width - 1):            # sign-extend
                        field |= (~0) << width
                    wr(rd_, field & (M64 if sf else M32), sf)
                    continue
                raise _Decline("arm64 sbfm insert")     # bitfield-insert forms: not modelled
            raise _Decline("arm64 bfm")                 # BFM (opc == 1): merges dest, not modelled
        if ((w >> 23) & 0x3F) == 0b100111 and ((w >> 21) & 1) == 0:   # EXTR (ROR alias when Rn==Rm)
            rm = (w >> 16) & 0x1F
            imms = (w >> 10) & 0x3F
            rn = (w >> 5) & 0x1F
            rd_ = w & 0x1F
            bits = 64 if sf else 32
            if imms >= bits:
                raise _Decline("arm64 extr range")
            hi = rd(rn) & (M64 if sf else M32)
            lo = rd(rm) & (M64 if sf else M32)
            concat = (hi << bits) | lo
            res = (concat >> imms) & (M64 if sf else M32)
            wr(rd_, res, sf)
            continue
        if ((w >> 24) & 0x1F) == 0b11011 and ((w >> 21) & 7) == 0:    # MADD / MSUB (3-source)
            o0 = (w >> 15) & 1
            rm = (w >> 16) & 0x1F
            ra = (w >> 10) & 0x1F
            rn = (w >> 5) & 0x1F
            rd_ = w & 0x1F
            prod = rd(rn) * rd(rm)
            acc = rd(ra)
            res = (acc - prod) if o0 else (acc + prod)
            wr(rd_, res, sf)
            continue
        if ((w >> 21) & 0x3FF) == 0b0011010110:         # data-processing (2 source): shifts, div
            rm = (w >> 16) & 0x1F
            opcode = (w >> 10) & 0x3F
            rn = (w >> 5) & 0x1F
            rd_ = w & 0x1F
            bits = 64 if sf else 32
            a = rd(rn)
            amt = rd(rm) % bits
            if opcode == 0x08:                          # LSLV
                wr(rd_, shifted(a, 0, amt, sf), sf)
            elif opcode == 0x09:                        # LSRV
                wr(rd_, shifted(a, 1, amt, sf), sf)
            elif opcode == 0x0a:                        # ASRV
                wr(rd_, shifted(a, 2, amt, sf), sf)
            elif opcode == 0x0b:                        # RORV
                wr(rd_, shifted(a, 3, amt, sf), sf)
            else:
                raise _Decline("arm64 dp2src 0x%02x" % opcode)
            continue
        raise _Decline("arm64 word 0x%08x" % w)
    else:
        # the symbol's bytes ended before a RET ran (a st_size cut short): a device runs on past st_size
        raise _Decline("arm64 ran off the end of the symbol's bytes without a RET")
    return rd(0) & M64


# ------------------------------------------------- general native dispatch (Unicorn + hand-rolled cross-check)
# Day 27 so-ambig fix round 2: what a device hands a native in the argument slots VM._invoke leaves undefined (None):
# a JNIEnv* (16-aligned heap; on arm64 a Scudo pointer carries the 0xb4 top-byte tag) and a jclass (an aligned slot
# of the managed stack). The Unicorn engine already runs an undefined register under two poison fills (0xa5.., 0x5c..),
# both odd or unaligned and far outside a user address space, so a body that tests a property of the pointer both
# poisons share (`env >> 47`, `env & 7`) took a path no device takes; a run with these values must agree as well.
_DEVICE_ARGS = {EM_X86_64: (0x00007F3A5C2E1A40, 0x00007FFD9C3E2B58),
                EM_AARCH64: (0xB400007A3C2E1A40, 0x0000007FD9C3E2B58),
                # B-164: 32-bit, odd/unaligned device-like JNIEnv*/jclass pointers for the arm32 cross-check,
                # distinct from each other and from both poison fills' low 32 bits (0xA5A5A5A5, 0x5C5C5C5C)
                EM_ARM_A32: (0xBEEF1241, 0xCAFE2B59),
                EM_ARM_THUMB: (0xBEEF1241, 0xCAFE2B59)}

# AAPCS32 core-register integer argument order (r0..r3); further integer args go on the stack (not modelled).
_ARM32_AAPCS = ["r0", "r1", "r2", "r3"]


def _unicorn_value(codeb, int_args, arch, fill=None):
    """The Unicorn engine's value of a native body called with `int_args` in ABI order (native_emulate.
    emulate_function): an entry that is None is left undefined (poisoned two ways by the engine), or, with `fill`,
    given fill's value of its slot. Raises native_emulate.EmulationError (or any error) when there is no value."""
    if arch == EM_X86_64:
        names, ne_arch, result_reg = _X86_SYSV, native_emulate.ARCH_X86_64, "rax"
    elif arch == EM_AARCH64:
        names, ne_arch, result_reg = _ARM64_AAPCS, native_emulate.ARCH_ARM64, "x0"
    elif arch in _EM_ARM32:                   # B-164: 32-bit ARM, A32 or (EM_ARM_THUMB) T32
        names, result_reg = _ARM32_AAPCS, "r0"
        ne_arch = native_emulate.ARCH_THUMB if arch == EM_ARM_THUMB else native_emulate.ARCH_ARM32
    else:
        raise native_emulate.EmulationError("no emulator for e_machine %d" % arch)
    if len(int_args) > len(names):
        raise native_emulate.EmulationError("stack arguments are not modelled")
    regs = {}
    for i, v in enumerate(int_args):
        if v is None:
            if fill is None:
                continue
            v = fill[i] if i < len(fill) else fill[0] + 0x40 * i
        regs[names[i]] = v & M64
    return native_emulate.emulate_function(codeb, ne_arch, regs, result_reg) & M64


def _arm32_dispatch(codeb, int_args, arch):
    """Run a 32-bit ARM (A32 or, for EM_ARM_THUMB, T32) native JNI transform to its return value through the
    Unicorn engine alone (B-164). NEVER-WRONG: there is no hand-rolled arm32 reader, so the engine is the only
    path; it declines (never a value) when the engine is unavailable, when the body traps / reads undefined
    state / depends on an undefined register (native_emulate's double-poison), and -- when the JNIEnv/jclass
    are undefined (None), as VM._invoke hands them -- when a run with device-like pointers in those slots gives
    a different value (the body read them). `int_args` is the ABI integer list [JNIEnv, jclass, r2-arg, r3-arg]
    in AAPCS32 core-register order; a 64-bit (pair) argument is split and declined by the caller, not here."""
    if native_emulate is None or not native_emulate.UNICORN_AVAILABLE:
        why = "" if native_emulate is None else (": %s" % native_emulate.UNICORN_UNAVAILABLE_REASON)
        raise _Decline("arm32 native needs the Unicorn engine, which is unavailable%s" % why)
    try:
        val = _unicorn_value(codeb, int_args, arch) & M64
    except native_emulate.EmulationError as e:
        raise _Decline("arm32 native declined: %s" % e)
    except Exception as e:
        raise _Decline("arm32 native error: %s" % type(e).__name__)
    if any(v is None for v in int_args):
        try:
            dev = _unicorn_value(codeb, int_args, arch, _DEVICE_ARGS.get(arch))
        except Exception:
            dev = None
        if dev != val:
            raise _Decline("arm32 native value %#x with the JNIEnv/jclass undefined is not what device-like pointers "
                           "give (%s): the body reads them" % (val, "no value" if dev is None else "%#x" % dev))
    return val


def _native_dispatch(codeb, int_args, arch):
    """Run a native JNI transform to its return value, GENERALLY (branches, loops, calls, float, extra
    arguments) via the Unicorn engine, cross-checked against the lane's hand-rolled reader. Never-wrong:

      * Unicorn is the general primary path; the hand-rolled reader (`_emulate_x86` / `_emulate_arm64`) is
        kept as both a cross-check and a fallback.
      * When BOTH produce a value they MUST agree, else `_Decline` (the stricter outcome): a disagreement
        means one modelled the code wrong, and we never let a maybe-wrong value reach the judge.
      * When only one produces a value, that value is used: the hand-rolled reader is exact for the
        straight-line subset it models (so it stands if Unicorn traps), and Unicorn resolves the branch /
        loop / call / float / extra-argument shapes the hand-rolled reader declines on.
      * When both decline, `_Decline`.

    `int_args` is the integer-argument list in ABI order: for a static JNI method [JNIEnv, jclass, arg0,
    ...] (x86-64 SysV -> rdi, rsi, rdx, ...; AArch64 AAPCS -> x0, x1, x2, ...). `arch` is EM_X86_64 /
    EM_AARCH64. Nothing from the sample is run as a process: Unicorn emulates it in its own sandbox.

    Day 27 so-ambig fix round 2 (the review of 38a1668): an entry of `int_args` that is None (VM._invoke's JNIEnv and
    jclass) is UNDEFINED for both readers (the hand-rolled one declines on a read of it; the engine poisons it two
    ways), where both had a defined 0 and a native testing `env == NULL` gave a code no device computes. When the
    engine alone answers such a call, a run with device-like pointers in those slots (_DEVICE_ARGS) must give the same
    value; the hand-rolled reader, when it answers, read none of them. Both readers now take every argument (the
    arm64 one took x2 alone, with x3 and up a defined 0). A body past _NATIVE_MAX_CODE bytes declines.

    B-164: a 32-bit ARM body (EM_ARM_A32 / EM_ARM_THUMB) has no hand-rolled reader; it runs through the Unicorn
    engine alone (the correct general decoder), with the same device-pointer cross-check, and declines when the
    engine is unavailable or traps -- fail closed, never a hand-decoded foreign word. Any other machine (the raw
    EM_ARM of a container no loader loads, EM_386, ...) declines here too: the readers below decode x86-64 or
    AArch64 only, and this used to hand every other machine's bytes to the AArch64 one."""
    if len(codeb) > _NATIVE_MAX_CODE:
        raise _Decline("native body of %d bytes is past the %d any emulator here runs" % (len(codeb), _NATIVE_MAX_CODE))
    if arch in _EM_ARM32:
        return _arm32_dispatch(codeb, int_args, arch)
    if arch not in _EM_RUNNABLE:
        raise _Decline("native e_machine %s not modelled" % _em_text(arch))
    # --- hand-rolled reader (exact for its modelled subset) ---
    hr_val = None
    hr_ok = False
    try:
        if arch == EM_X86_64:
            hr_val = _emulate_x86(codeb, int_args) & M64
        else:  # EM_AARCH64: every argument register, as the engine gets them
            hr_val = _emulate_arm64(codeb, list(int_args)) & M64
        hr_ok = True
    except _Decline:
        hr_ok = False
    except Exception:
        hr_ok = False

    # --- Unicorn general emulator (primary path) ---
    uc_val = None
    uc_ok = False
    if native_emulate is not None and native_emulate.UNICORN_AVAILABLE:
        try:
            uc_val = _unicorn_value(codeb, int_args, arch)
            uc_ok = True
        except native_emulate.EmulationError:
            uc_ok = False
        except Exception:
            uc_ok = False

    if hr_ok and uc_ok:
        if hr_val == uc_val:
            return hr_val
        raise _Decline("native cross-check disagreement: hand-rolled %#x vs unicorn %#x" % (hr_val, uc_val))
    if uc_ok:
        if any(v is None for v in int_args):
            try:
                dev = _unicorn_value(codeb, int_args, arch, _DEVICE_ARGS.get(arch, _DEVICE_ARGS[EM_X86_64]))
            except Exception:
                dev = None
            if dev != uc_val:
                raise _Decline("native value %#x with the JNIEnv/jclass undefined is not what device-like pointers give "
                               "(%s): the body reads them" % (uc_val, "no value" if dev is None else "%#x" % dev))
        return uc_val
    if hr_ok:
        return hr_val
    raise _Decline("native emulation declined (hand-rolled and unicorn both)")


# ------------------------------------------------------------- interpreter

# ------------------------------------------------------------- crypto / checksum / Random library invokes
# java.security.MessageDigest, javax.crypto.Mac / Cipher (AES ECB/CBC/CTR/GCM, RC4) with SecretKeySpec /
# IvParameterSpec / GCMParameterSpec, bounded PBKDF2 SecretKeyFactory/PBEKeySpec flows,
# java.util.zip.CRC32 and java.util.Random (the exact JDK LCG). byte[] is a list of
# SIGNED ints (-128..127) exactly as aput-byte / aget-byte keep them; every consumer masks with 0xFF and
# every producer returns signed bytes, so a digest byte >= 0x80 sign-extends under int-to-long exactly as
# Dalvik does. Anything not modelled (an unknown algorithm or mode, an unseeded Random, an unexpected
# argument shape, a failed AEAD tag, or work past a resource bound) raises _Decline.
import hashlib as _hashlib
import hmac as _hmac
import zlib as _zlib

_MD_ALGS = {"MD5": "md5", "SHA-1": "sha1", "SHA1": "sha1", "SHA": "sha1", "SHA-224": "sha224",
            "SHA-256": "sha256", "SHA256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512",
            "SHA512": "sha512"}
_MAC_ALGS = {"HMACMD5": "md5", "HMACSHA1": "sha1", "HMACSHA224": "sha224", "HMACSHA256": "sha256",
             "HMACSHA384": "sha384", "HMACSHA512": "sha512"}
_PBKDF2_ALGS = {"PBKDF2WITHHMACSHA1": "sha1", "PBKDF2WITHHMACSHA224": "sha224",
                "PBKDF2WITHHMACSHA256": "sha256", "PBKDF2WITHHMACSHA384": "sha384",
                "PBKDF2WITHHMACSHA512": "sha512"}
_MAX_CRYPTO_BYTES = 1 << 20
_MAX_PBKDF2_ITERS = 1_000_000
_MAX_PBKDF2_BYTES = 4096
_MAX_PASSWORD_CHARS = 4096
_GCM_TAG_BITS = {32, 64, 96, 104, 112, 120, 128}
_RND_MULT = 0x5DEECE66D
_RND_MASK = (1 << 48) - 1


def _ubytes(v):
    """A Java byte[] (list of ints, signed or not) to Python bytes; declines on anything else."""
    if not isinstance(v, list) or len(v) > _MAX_CRYPTO_BYTES:
        raise _Decline("crypto: byte[] expected")
    out = bytearray()
    for c in v:
        if isinstance(c, bool) or not isinstance(c, int):
            raise _Decline("crypto: non-int in byte[]")
        out.append(c & 0xFF)
    return bytes(out)


def _sbytes(b):
    """Python bytes to a Java byte[]: signed ints."""
    return [x - 256 if x > 127 else x for x in b]


_MAX_NEW_ARRAY = 1 << 25      # elements one new-array may allocate (a split member's buffer is at most 16 MiB)


def _jindex(v, n, what, end_ok=False):
    """A Java int index into a sequence of `n` elements: in [0, n) (with `end_ok`, [0, n], a String/StringBuilder
    position), else _Decline: Java throws an IndexOutOfBoundsException there and the path gives no code. KB-2 fix
    round 2 (the review of 4250749, item a): the VM indexed Python lists and strings with the Java int as it stood, so a
    negative index read from the end (a jint native returning -1, kept signed since fix round 1, used as an index gave
    the LAST element, a wrong plain code) and a position past the end was clipped. Only the low 32 bits of an int
    register are its value."""
    if isinstance(v, bool) or not isinstance(v, int):
        raise _Decline("%s: index of type %s" % (what, type(v).__name__))
    i = _s32(v & M32)
    if i < 0 or i > n or (i == n and not end_ok):
        raise _Decline("%s: index %d out of range for length %d (Java throws)" % (what, i, n))
    return i


def _slice_args(arr, off, ln):
    off, ln = _s32(off), _s32(ln)
    if off < 0 or ln < 0 or off + ln > len(arr):
        raise _Decline("crypto: offset/length out of range")
    return arr[off:off + ln]


def _rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 255])
    return bytes(out)


def _aes_raw(mode, key, iv, data, enc):
    """AES ECB/CBC/CTR with NO padding, or decline when no AES library is present."""
    if len(key) not in (16, 24, 32) or (mode in ("ECB", "CBC") and len(data) % 16):
        raise _Decline("AES key/data size")
    if mode in ("CBC", "CTR") and (iv is None or len(iv) != 16):
        raise _Decline("AES %s needs a 16-byte IV/counter" % mode)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _C, algorithms as _A, modes as _M
        m = _M.ECB() if mode == "ECB" else (_M.CBC(iv) if mode == "CBC" else _M.CTR(iv))
        c = _C(_A.AES(key), m)
        x = c.encryptor() if enc else c.decryptor()
        return x.update(data) + x.finalize()
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES as _AES
    except ImportError:
        raise _Decline("no AES library")
    if mode == "ECB":
        c = _AES.new(key, _AES.MODE_ECB)
    elif mode == "CBC":
        c = _AES.new(key, _AES.MODE_CBC, iv)
    else:
        c = _AES.new(key, _AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
    return c.encrypt(data) if enc else c.decrypt(data)


def _aes_gcm(f, data):
    """One complete AES-GCM operation. Decrypt returns bytes only after the supplied tag verifies."""
    key, iv, bits = f.get("key"), f.get("iv"), f.get("tag_bits")
    if len(key or b"") not in (16, 24, 32) or not isinstance(iv, bytes) or not (1 <= len(iv) <= 64) \
            or bits not in _GCM_TAG_BITS:
        raise _Decline("GCM key/nonce/tag size")
    tag_len = bits // 8
    enc = f.get("op") == 1
    aad = bytes(f.get("aad") or b"")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _C, algorithms as _A, modes as _M
        if enc:
            x = _C(_A.AES(key), _M.GCM(iv)).encryptor()
            if aad:
                x.authenticate_additional_data(aad)
            body = x.update(data) + x.finalize()
            return body + x.tag[:tag_len]
        if len(data) < tag_len:
            raise _Decline("GCM ciphertext is shorter than its tag")
        body, tag = data[:-tag_len], data[-tag_len:]
        x = _C(_A.AES(key), _M.GCM(iv, tag, min_tag_length=tag_len)).decryptor()
        if aad:
            x.authenticate_additional_data(aad)
        return x.update(body) + x.finalize()       # finalize authenticates; InvalidTag is a decline below
    except _Decline:
        raise
    except ImportError:
        pass
    except Exception as e:
        raise _Decline("GCM authentication/operation failed (%s)" % type(e).__name__)
    try:
        from Crypto.Cipher import AES as _AES
        c = _AES.new(key, _AES.MODE_GCM, nonce=iv, mac_len=tag_len)
        if aad:
            c.update(aad)
        if enc:
            body, tag = c.encrypt_and_digest(data)
            return body + tag
        if len(data) < tag_len:
            raise _Decline("GCM ciphertext is shorter than its tag")
        return c.decrypt_and_verify(data[:-tag_len], data[-tag_len:])
    except _Decline:
        raise
    except ImportError:
        raise _Decline("no AES-GCM library")
    except Exception as e:
        raise _Decline("GCM authentication/operation failed (%s)" % type(e).__name__)


def _cipher_final(f, data):
    alg, mode, pad = f["alg"], f["mode"], f["pad"]
    key = f.get("key")
    if key is None or f.get("op") not in (1, 2):
        raise _Decline("Cipher not initialised for ENCRYPT/DECRYPT")
    enc = f["op"] == 1
    if alg == "RC4":
        return _rc4(key, data)
    iv = f.get("iv")
    if mode == "GCM":
        return _aes_gcm(f, data)
    if mode in ("CBC", "CTR") and (iv is None or len(iv) != 16):
        raise _Decline("%s needs the IV/counter the bytecode supplies" % mode)
    if mode in ("CTR", "GCM") and pad != "NONE":
        raise _Decline("%s does not take padding" % mode)
    if enc and pad == "PKCS5":
        n = 16 - len(data) % 16
        data = data + bytes([n]) * n
    out = _aes_raw(mode, key, iv, data, enc)
    if not enc and pad == "PKCS5":
        n = out[-1] if out else 0
        if n < 1 or n > 16 or out[-n:] != bytes([n]) * n:
            raise _Decline("BadPaddingException")
        out = out[:-n]
    return out


def _cipher_update(f, data):
    """One Java Cipher.update result while retaining state through the final call.

    The implementation recomputes the deterministic prefix from the exact accumulated input and returns
    only bytes not returned by an earlier update. This is equivalent to a streaming provider for RC4/CTR,
    complete ECB/CBC blocks and GCM encryption. GCM decryption deliberately releases nothing before
    doFinal verifies the trailing tag; it can therefore lose coverage, never authenticate a wrong answer.
    """
    if f.get("op") not in (1, 2):
        raise _Decline("Cipher not initialised for update")
    buf = f.setdefault("buf", bytearray())
    if len(buf) + len(data) > _MAX_CRYPTO_BYTES:
        raise _Decline("Cipher input too large")
    buf += data
    f["data_started"] = bool(buf)
    alg, mode, pad, enc = f["alg"], f["mode"], f["pad"], f["op"] == 1
    emitted = f.setdefault("emitted", 0)
    if mode == "GCM" and not enc:
        return b""                         # no unauthenticated plaintext leaves the model
    if alg == "RC4" or mode == "CTR":
        safe = len(buf)
    elif mode == "GCM":                    # encryption ciphertext is stable; the tag comes from doFinal
        safe = len(buf)
    elif pad == "PKCS5" and not enc:
        safe = max(0, (len(buf) // 16 - 1) * 16)   # retain the block whose padding final checks
    else:
        safe = len(buf) // 16 * 16
    if safe <= emitted:
        return b""
    prefix = bytes(buf[:safe])
    if alg == "RC4":
        out = _rc4(f["key"], prefix)
    elif mode == "GCM":
        tag_len = f["tag_bits"] // 8
        out = _aes_gcm(f, prefix)[:-tag_len]
    else:
        out = _aes_raw(mode, f["key"], f.get("iv"), prefix, enc)
    piece = out[emitted:safe]
    f["emitted"] = safe
    return piece


def _cipher_finish(f, data):
    buf = f.setdefault("buf", bytearray())
    if len(buf) + len(data) > _MAX_CRYPTO_BYTES:
        raise _Decline("Cipher input too large")
    buf += data
    out = _cipher_final(f, bytes(buf))
    emitted = f.get("emitted", 0)
    if emitted > len(out):
        raise _Decline("Cipher streaming output accounting")
    piece = out[emitted:]
    # Java Cipher returns to its post-init state after doFinal. AAD and accumulated input do not carry.
    f["buf"], f["aad"], f["emitted"], f["data_started"] = bytearray(), bytearray(), 0, False
    return piece


def _password_bytes(chars):
    """A Java PBEKeySpec char[] as the UTF-8 octets Android PBKDF2 providers consume."""
    if not isinstance(chars, list) or len(chars) > _MAX_PASSWORD_CHARS:
        raise _Decline("PBEKeySpec password char[]")
    if any(isinstance(c, bool) or not isinstance(c, int) or c < 0 or c > 0x10FFFF for c in chars):
        raise _Decline("PBEKeySpec password character")
    try:
        if all(c <= 0xFFFF for c in chars):
            raw = b"".join(int(c).to_bytes(2, "big") for c in chars)
            text = raw.decode("utf-16-be")              # combines a valid surrogate pair; rejects a lone one
        else:                                            # current VM String.toCharArray uses Python code points
            text = "".join(chr(c) for c in chars)
        return text.encode("utf-8")
    except (UnicodeError, ValueError, OverflowError):
        raise _Decline("PBEKeySpec password encoding")


def _feed(buf, args, what):
    """update(byte[]) / update(byte) / update(byte[],int,int) into a bytearray."""
    v = args[1] if len(args) > 1 else None
    if len(args) == 2 and isinstance(v, list):
        buf += _ubytes(v)
    elif len(args) == 2 and isinstance(v, int) and not isinstance(v, bool):
        buf.append(v & 0xFF)
    elif len(args) == 4 and isinstance(v, list):
        buf += _ubytes(_slice_args(v, args[2], args[3]))
    else:
        raise _Decline("%s.update shape" % what)
    if len(buf) > _MAX_CRYPTO_BYTES:
        raise _Decline("%s input too large" % what)


def _crypto_invoke(cls, name, args):
    """(handled, result). handled False leaves the invoke to the rest of _invoke."""
    if cls == "Ljava/security/MessageDigest;":
        if name == "getInstance":
            if len(args) != 1:
                raise _Decline("MessageDigest.getInstance provider")
            a = _as_text(args[0])
            h = _MD_ALGS.get(a.upper()) if a is not None else None
            if h is None:
                raise _Decline("MessageDigest algorithm")
            o = _Obj(cls)
            o.fields["alg"] = h
            o.fields["buf"] = bytearray()
            return True, o
        o = args[0] if args else None
        if not isinstance(o, _Obj) or "buf" not in o.fields or o.type != cls:
            raise _Decline("MessageDigest receiver")
        buf = o.fields["buf"]
        if name == "update":
            _feed(buf, args, "MessageDigest")
            return True, None
        if name == "digest":
            if len(args) == 2 and isinstance(args[1], list):
                buf += _ubytes(args[1])
            elif len(args) != 1:
                raise _Decline("MessageDigest.digest shape")
            d = _hashlib.new(o.fields["alg"], bytes(buf)).digest()
            o.fields["buf"] = bytearray()
            return True, _sbytes(d)
        if name == "reset":
            o.fields["buf"] = bytearray()
            return True, None
        raise _Decline("MessageDigest.%s" % name)

    if cls == "Ljavax/crypto/spec/SecretKeySpec;":
        if name != "<init>":
            raise _Decline("SecretKeySpec.%s" % name)
        o = args[0]
        if not isinstance(o, _Obj):
            raise _Decline("SecretKeySpec receiver")
        if len(args) == 3 and isinstance(args[1], list):
            kb = _ubytes(args[1])
            alg = _as_text(args[2])
        elif len(args) == 5 and isinstance(args[1], list):
            kb = _ubytes(_slice_args(args[1], args[2], args[3]))
            alg = _as_text(args[4])
        else:
            raise _Decline("SecretKeySpec shape")
        if not kb or alg is None:
            raise _Decline("SecretKeySpec empty key")
        o.fields["key"] = kb
        o.fields["kalg"] = alg.upper()
        return True, None
    if cls == "Ljavax/crypto/spec/IvParameterSpec;":
        if name != "<init>":
            raise _Decline("IvParameterSpec.%s" % name)
        o = args[0]
        if not isinstance(o, _Obj):
            raise _Decline("IvParameterSpec receiver")
        if len(args) == 2 and isinstance(args[1], list):
            o.fields["iv"] = _ubytes(args[1])
        elif len(args) == 4 and isinstance(args[1], list):
            o.fields["iv"] = _ubytes(_slice_args(args[1], args[2], args[3]))
        else:
            raise _Decline("IvParameterSpec shape")
        return True, None

    if cls == "Ljavax/crypto/spec/GCMParameterSpec;":
        if name != "<init>":
            raise _Decline("GCMParameterSpec.%s" % name)
        o = args[0] if args else None
        if not isinstance(o, _Obj) or len(args) not in (3, 5):
            raise _Decline("GCMParameterSpec receiver/shape")
        bits = args[1]
        if isinstance(bits, bool) or not isinstance(bits, int) or _s32(bits) not in _GCM_TAG_BITS:
            raise _Decline("GCMParameterSpec tag length")
        if len(args) == 3 and isinstance(args[2], list):
            iv = _ubytes(args[2])
        elif len(args) == 5 and isinstance(args[2], list):
            iv = _ubytes(_slice_args(args[2], args[3], args[4]))
        else:
            raise _Decline("GCMParameterSpec nonce")
        if not (1 <= len(iv) <= 64):
            raise _Decline("GCMParameterSpec nonce length")
        o.fields.update(iv=iv, tag_bits=_s32(bits))
        return True, None

    if cls == "Ljavax/crypto/spec/PBEKeySpec;":
        o = args[0] if args else None
        if not isinstance(o, _Obj) or o.type != cls:
            raise _Decline("PBEKeySpec receiver")
        if name == "<init>":
            if len(args) != 5 or not isinstance(args[2], list) or any(isinstance(x, bool) or not isinstance(x, int)
                                                                     for x in args[3:5]):
                raise _Decline("PBEKeySpec shape")
            iters, bits = _s32(args[3]), _s32(args[4])
            if iters <= 0 or iters > _MAX_PBKDF2_ITERS or bits <= 0 or bits % 8 \
                    or bits // 8 > _MAX_PBKDF2_BYTES:
                raise _Decline("PBEKeySpec work/key length")
            salt = _ubytes(args[2])
            if not salt:
                raise _Decline("PBEKeySpec empty salt")
            o.fields.update(password=_password_bytes(args[1]), salt=salt, iterations=iters, key_bytes=bits // 8)
            return True, None
        if name == "clearPassword" and len(args) == 1:
            o.fields["password"] = None
            return True, None
        if name == "getPassword" and len(args) == 1:
            raise _Decline("PBEKeySpec.getPassword is not reconstructed from encoded octets")
        raise _Decline("PBEKeySpec.%s" % name)

    if cls == "Ljavax/crypto/SecretKeyFactory;":
        if name == "getInstance":
            if len(args) != 1:
                raise _Decline("SecretKeyFactory.getInstance provider")
            alg = _as_text(args[0])
            digest = _PBKDF2_ALGS.get(alg.upper()) if alg is not None else None
            if digest is None:
                raise _Decline("SecretKeyFactory algorithm")
            o = _Obj(cls)
            o.fields.update(kdf=digest, kalg=alg.upper())
            return True, o
        o = args[0] if args else None
        if not isinstance(o, _Obj) or o.type != cls or "kdf" not in o.fields:
            raise _Decline("SecretKeyFactory receiver")
        if name != "generateSecret" or len(args) != 2:
            raise _Decline("SecretKeyFactory.%s shape" % name)
        spec = args[1]
        if not isinstance(spec, _Obj) or spec.type != "Ljavax/crypto/spec/PBEKeySpec;" \
                or spec.fields.get("password") is None:
            raise _Decline("SecretKeyFactory PBEKeySpec")
        try:
            key = _hashlib.pbkdf2_hmac(o.fields["kdf"], spec.fields["password"], spec.fields["salt"],
                                       spec.fields["iterations"], spec.fields["key_bytes"])
        except (ValueError, OverflowError):
            raise _Decline("PBKDF2 derivation")
        out = _Obj("Ljavax/crypto/SecretKey;")
        out.fields.update(key=key, kalg=o.fields["kalg"])
        return True, out

    if cls in ("Ljavax/crypto/SecretKey;", "Ljava/security/Key;"):
        o = args[0] if args else None
        if not isinstance(o, _Obj) or "key" not in o.fields:
            raise _Decline("SecretKey receiver")
        if name == "getEncoded" and len(args) == 1:
            return True, _sbytes(o.fields["key"])
        if name == "getAlgorithm" and len(args) == 1:
            return True, o.fields.get("kalg")
        if name == "getFormat" and len(args) == 1:
            return True, "RAW"
        raise _Decline("SecretKey.%s" % name)

    if cls == "Ljavax/crypto/Mac;":
        if name == "getInstance":
            if len(args) != 1:
                raise _Decline("Mac.getInstance provider")
            a = _as_text(args[0])
            h = _MAC_ALGS.get(a.upper()) if a is not None else None
            if h is None:
                raise _Decline("Mac algorithm")
            o = _Obj(cls)
            o.fields["alg"] = h
            o.fields["buf"] = bytearray()
            o.fields["mkey"] = None
            return True, o
        o = args[0] if args else None
        if not isinstance(o, _Obj) or "mkey" not in o.fields or o.type != cls:
            raise _Decline("Mac receiver")
        if name == "init":
            k = args[1] if len(args) == 2 else None
            if not isinstance(k, _Obj) or "key" not in k.fields:
                raise _Decline("Mac.init key")
            o.fields["mkey"] = k.fields["key"]
            o.fields["buf"] = bytearray()
            return True, None
        if o.fields["mkey"] is None:
            raise _Decline("Mac not initialised")
        buf = o.fields["buf"]
        if name == "update":
            _feed(buf, args, "Mac")
            return True, None
        if name == "doFinal":
            if len(args) == 2 and isinstance(args[1], list):
                buf += _ubytes(args[1])
            elif len(args) != 1:
                raise _Decline("Mac.doFinal shape")
            d = _hmac.new(o.fields["mkey"], bytes(buf), o.fields["alg"]).digest()
            o.fields["buf"] = bytearray()
            return True, _sbytes(d)
        if name == "reset":
            o.fields["buf"] = bytearray()
            return True, None
        raise _Decline("Mac.%s" % name)

    if cls == "Ljavax/crypto/Cipher;":
        if name == "getInstance":
            if len(args) != 1:
                raise _Decline("Cipher.getInstance provider")
            t = _as_text(args[0])
            if t is None:
                raise _Decline("Cipher transformation")
            parts = t.upper().split("/")
            if parts[0] in ("RC4", "ARCFOUR") and len(parts) == 1:
                f = {"alg": "RC4", "mode": "", "pad": ""}
            elif parts[0] == "AES" and len(parts) == 1:
                f = {"alg": "AES", "mode": "ECB", "pad": "PKCS5"}
            elif parts[0] == "AES" and len(parts) == 3 and parts[1] in ("ECB", "CBC", "CTR", "GCM") and \
                    parts[2] in ("PKCS5PADDING", "PKCS7PADDING", "NOPADDING"):
                f = {"alg": "AES", "mode": parts[1], "pad": "NONE" if parts[2] == "NOPADDING" else "PKCS5"}
                if parts[1] in ("CTR", "GCM") and f["pad"] != "NONE":
                    raise _Decline("Cipher transformation %s not modelled" % t)
            else:
                raise _Decline("Cipher transformation %s not modelled" % t)
            o = _Obj(cls)
            o.fields.update(f, buf=bytearray(), aad=bytearray(), emitted=0, data_started=False)
            return True, o
        o = args[0] if args else None
        if not isinstance(o, _Obj) or "alg" not in o.fields or o.type != cls:
            raise _Decline("Cipher receiver")
        f = o.fields
        if name == "init":
            if len(args) not in (3, 4) or isinstance(args[1], bool) or not isinstance(args[1], int) \
                    or args[1] not in (1, 2):
                raise _Decline("Cipher.init shape/mode")
            k = args[2]
            if not isinstance(k, _Obj) or "key" not in k.fields:
                raise _Decline("Cipher.init key")
            if f["alg"] == "AES" and not k.fields["kalg"].startswith("AES"):
                raise _Decline("Cipher key algorithm mismatch")
            f["key"] = k.fields["key"]
            f["op"] = args[1]
            f["iv"] = None
            f["tag_bits"] = None
            if len(args) == 4:
                ivs = args[3]
                if not isinstance(ivs, _Obj) or "iv" not in ivs.fields:
                    raise _Decline("Cipher.init parameter spec")
                if f["mode"] == "GCM":
                    if "tag_bits" not in ivs.fields:
                        raise _Decline("Cipher.init GCMParameterSpec")
                    f["tag_bits"] = ivs.fields["tag_bits"]
                elif f["mode"] not in ("CBC", "CTR") or "tag_bits" in ivs.fields:
                    raise _Decline("Cipher.init parameter spec")
                f["iv"] = ivs.fields["iv"]
            elif f["mode"] in ("CBC", "CTR", "GCM"):
                raise _Decline("Cipher.init parameter spec required")
            f["buf"], f["aad"], f["emitted"], f["data_started"] = bytearray(), bytearray(), 0, False
            return True, None
        if name == "update":
            piece = bytearray()
            _feed(piece, args, "Cipher")
            return True, _sbytes(_cipher_update(f, bytes(piece)))
        if name == "updateAAD":
            if f.get("mode") != "GCM" or f.get("op") not in (1, 2) or f.get("data_started"):
                raise _Decline("Cipher.updateAAD state")
            _feed(f["aad"], args, "Cipher.updateAAD")
            return True, None
        if name == "doFinal":
            piece = bytearray()
            if len(args) != 1:
                _feed(piece, args, "Cipher.doFinal")
            return True, _sbytes(_cipher_finish(f, bytes(piece)))
        raise _Decline("Cipher.%s" % name)

    if cls == "Ljava/util/zip/CRC32;":
        if name == "<init>":
            return True, None
        o = args[0] if args else None
        if not isinstance(o, _Obj) or o.type != cls:
            raise _Decline("CRC32 receiver")
        crc = o.fields.get("crc", 0)
        if name == "update":
            v = args[1] if len(args) > 1 else None
            if len(args) == 2 and isinstance(v, list):
                crc = _zlib.crc32(_ubytes(v), crc)
            elif len(args) == 2 and isinstance(v, int) and not isinstance(v, bool):
                crc = _zlib.crc32(bytes([v & 0xFF]), crc)
            elif len(args) == 4 and isinstance(v, list):
                crc = _zlib.crc32(_ubytes(_slice_args(v, args[2], args[3])), crc)
            else:
                raise _Decline("CRC32.update shape")
            o.fields["crc"] = crc
            return True, None
        if name == "getValue":
            return True, crc & M32            # a long 0..2^32-1 (never negative)
        if name == "reset":
            o.fields["crc"] = 0
            return True, None
        raise _Decline("CRC32.%s" % name)

    if cls == "Ljava/util/Random;":
        if name == "<init>":
            o = args[0] if args else None
            if not isinstance(o, _Obj) or len(args) != 3:     # Random() is seeded from the clock: not deterministic
                raise _Decline("Random() is unseeded")
            o.fields["seed"] = (args[1] ^ _RND_MULT) & _RND_MASK
            return True, None
        o = args[0] if args else None
        if not isinstance(o, _Obj) or o.type != cls:
            raise _Decline("Random receiver")
        if name == "setSeed":
            if len(args) != 3:
                raise _Decline("Random.setSeed shape")
            o.fields["seed"] = (args[1] ^ _RND_MULT) & _RND_MASK
            return True, None
        if "seed" not in o.fields:
            raise _Decline("Random not seeded")

        def nxt(bits):
            sd = (o.fields["seed"] * _RND_MULT + 0xB) & _RND_MASK
            o.fields["seed"] = sd
            return _s32(sd >> (48 - bits))

        if name == "nextInt":
            if len(args) == 1:
                return True, nxt(32)
            if len(args) != 2:
                raise _Decline("Random.nextInt shape")
            bound = _s32(args[1])
            if bound <= 0:
                raise _Decline("IllegalArgumentException")
            r = nxt(31)
            m = bound - 1
            if bound & m == 0:
                return True, _s32((bound * r) >> 31)
            u = r
            while True:
                r = u % bound
                if _s32(u - r + m) >= 0:
                    return True, r
                u = nxt(31)
        if name == "nextLong" and len(args) == 1:
            hi = nxt(32)
            lo = nxt(32)
            return True, ((hi << 32) + lo) & M64
        if name == "nextBoolean" and len(args) == 1:
            return True, 1 if nxt(1) != 0 else 0
        if name == "nextBytes" and len(args) == 2 and isinstance(args[1], list):
            arr = args[1]
            i = 0
            while i < len(arr):
                rnd = nxt(32)
                for _ in range(min(len(arr) - i, 4)):
                    arr[i] = _s8(rnd & 0xFF)
                    i += 1
                    rnd >>= 8
            return True, None
        if name == "nextDouble" and len(args) == 1:
            a = nxt(26)
            b = nxt(27)
            return True, _f64_bits(((a << 27) + b) * (1.0 / (1 << 53)))
        if name == "nextFloat" and len(args) == 1:
            return True, _f32_bits(nxt(24) / float(1 << 24))
        raise _Decline("Random.%s" % name)

    if cls == "Ljava/util/Arrays;" and name in ("copyOf", "copyOfRange"):
        arr = args[0] if args else None
        if not isinstance(arr, list) or any(isinstance(c, bool) or not isinstance(c, int) for c in arr):
            raise _Decline("Arrays.%s array" % name)
        if name == "copyOf" and len(args) == 2:
            n = _s32(args[1])
            if n < 0 or n > _MAX_CRYPTO_BYTES:
                raise _Decline("Arrays.copyOf length")
            return True, (arr[:n] + [0] * max(0, n - len(arr)))
        if name == "copyOfRange" and len(args) == 3:
            f0, t0 = _s32(args[1]), _s32(args[2])
            if f0 < 0 or f0 > len(arr) or t0 < f0 or t0 - f0 > _MAX_CRYPTO_BYTES:
                raise _Decline("Arrays.copyOfRange bounds")
            seg = arr[f0:t0]
            return True, seg + [0] * ((t0 - f0) - len(seg))
        raise _Decline("Arrays.%s shape" % name)
    return False, None


class _Charset:
    """A java.nio.charset.Charset resolved from StandardCharsets.<FIELD> (sget-object) or Charset.forName."""
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name


_CHARSETS = {"UTF-8": "utf-8", "UTF8": "utf-8", "UTF_8": "utf-8",
             "US-ASCII": "ascii", "ASCII": "ascii", "US_ASCII": "ascii",
             "ISO-8859-1": "latin-1", "ISO8859_1": "latin-1", "ISO_8859_1": "latin-1", "LATIN1": "latin-1",
             "UTF-16LE": "utf-16-le", "UTF_16LE": "utf-16-le",
             "UTF-16BE": "utf-16-be", "UTF_16BE": "utf-16-be",
             "UTF-16": "utf-16", "UTF_16": "utf-16"}


def _charset_codec(cs):
    """The Python codec name for a charset argument (a String name or a _Charset), or a _Decline for
    anything unresolved or unmodelled -- never a silent UTF-8."""
    nm = cs.name if isinstance(cs, _Charset) else _as_text(cs)
    codec = _CHARSETS.get(nm.upper()) if isinstance(nm, str) else None
    if codec is None:
        raise _Decline("charset not modelled / unresolved")
    return codec


def _java_encode(text, codec):
    """String.getBytes(charset) as signed bytes. Java replaces an unmappable char with '?'; the VM
    declines instead (an unmappable char, a lone surrogate)."""
    try:
        if codec == "utf-16":                       # Java's "UTF-16": big-endian with a FE FF byte-order mark
            b = b"\xfe\xff" + text.encode("utf-16-be")
        else:
            b = text.encode(codec)
    except (UnicodeEncodeError, ValueError):
        raise _Decline("getBytes: char not encodable in the charset")
    return _sbytes(b)


def _java_decode(raw, codec):
    try:
        if codec == "utf-16":                       # BOM decides, big-endian by default (Java)
            if raw[:2] == b"\xff\xfe":
                return raw[2:].decode("utf-16-le")
            return (raw[2:] if raw[:2] == b"\xfe\xff" else raw).decode("utf-16-be")
        return raw.decode(codec)
    except (UnicodeDecodeError, ValueError):
        raise _Decline("new String: malformed bytes for the charset")


try:                               # KB-7 (dex_float.py): exact float/double specials, Java math, static fields and
    import dex_float as _dfl       # <clinit>, the reflection remainder. Absent: the VM behaves exactly as before.
except Exception:
    try:
        import importlib.util as _ilu
        _dspec = _ilu.spec_from_file_location("dex_float", str(HERE / "dex_float.py"))
        _dfl = _ilu.module_from_spec(_dspec)
        _dspec.loader.exec_module(_dfl)
    except Exception as _e:
        _dfl = _native_unavailable("dex_float", _e)
_NOFIELD = object()                # an instance field this run never wrote (VM._exec's iget asks dex_float.iget_unset)


class VM:
    native_images = None                     # KB-2: native_image_bridge.Bundle of the delivery's .so files

    def __init__(self, dex, native_syms=None, native_arm=None):
        self.dex = dex
        native_syms = native_syms or {}
        # a table handed over as a plain dict (split_bundle's natives, a VM built by hand) is indexed and memoised like
        # codes_in_dex_ex's own (Day 27 so-ambig fix round 1: no scan of the table per native call); its view is itself
        self.native_syms = (native_syms if isinstance(native_syms, _NativeTable) or not isinstance(native_syms, dict)
                            else _NativeTable(native_syms))
        self.native_arm = native_arm or {}   # {sym: code bytes} of AArch64 .so FUNCs (routed to native_arm64)
        self._so_full = self.native_syms     # the delivery's whole table (_so_verdict), whatever the bridge narrows
        self.steps = 0
        self.max_steps = 8_000_000
        # Day 31 fold (the "Loaded Later" chain, from day_patch.py): the package's own member map, so
        # AssetManager.open can read a secondary dex out of THIS APK's assets, and the dexes a chain loads at
        # runtime with dalvik.system.InMemoryDexClassLoader (each (class token, parsed Dex)). Both default empty,
        # so a VM built by hand or one whose chain never touches the assets/loader behaves exactly as before.
        self.members = None
        self.loaded = []
        self.loaded_inmemory = False   # this run loaded a secondary dex with InMemoryDexClassLoader (the Day 31 chain)

    def run(self, midx, args):
        regs_size, ins_size, insns = self.dex.code[midx]
        R = [0] * max(regs_size, 1)
        start = regs_size - ins_size
        for k, v in enumerate(args):
            R[start + k] = v
        return self._exec(insns, R)

    def _exec(self, ins, R):
        dex = self.dex
        W = _W
        pc = 0
        n = len(ins)
        result = None
        while pc < n:
            self.steps += 1
            if self.steps > self.max_steps:
                raise _Decline("step budget")
            unit = ins[pc]
            op = unit & 0xFF
            b1 = unit >> 8
            w = W[op]

            if op == 0x00:  # nop
                pc += w
                continue

            if op in (0x01, 0x04, 0x07):  # move / move-wide / move-object (12x)
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                R[a] = R[b]
                if op == 0x04:
                    R[a + 1] = R[b + 1] if b + 1 < len(R) else 0
                pc += w
                continue
            if op in (0x02, 0x05, 0x08):  # move/from16
                a = b1
                src = ins[pc + 1]
                R[a] = R[src]
                if op == 0x05:
                    R[a + 1] = R[src + 1]
                pc += w
                continue
            if op in (0x03, 0x06, 0x09):  # move/16 / move-wide/16 / move-object/16 (32x)
                a = ins[pc + 1]
                src = ins[pc + 2]
                R[a] = R[src]
                if op == 0x06:
                    R[a + 1] = R[src + 1] if src + 1 < len(R) else 0
                pc += w
                continue
            if op in (0x0a, 0x0c):  # move-result / move-result-object
                R[b1] = result
                pc += w
                continue
            if op == 0x0b:  # move-result-wide
                R[b1] = result
                R[b1 + 1] = 0
                pc += w
                continue

            if op == 0x0e:
                return None
            if op in (0x0f, 0x10):  # return / return-wide
                return R[b1]
            if op == 0x11:  # return-object (a constructed String returns its text)
                v = R[b1]
                return v.val if isinstance(v, _Str) else v

            if op == 0x12:  # const/4
                R[b1 & 0xF] = _s4((b1 >> 4) & 0xF)
                pc += w
                continue
            if op == 0x13:  # const/16
                R[b1] = _s16(ins[pc + 1])
                pc += w
                continue
            if op == 0x14:  # const (31i)
                R[b1] = _s32(ins[pc + 1] | (ins[pc + 2] << 16))
                pc += w
                continue
            if op == 0x15:  # const/high16
                R[b1] = _s32((_s16(ins[pc + 1]) << 16) & M32)
                pc += w
                continue
            if op == 0x16:  # const-wide/16
                R[b1] = _s16(ins[pc + 1]) & M64
                R[b1 + 1] = 0
                pc += w
                continue
            if op == 0x17:  # const-wide/32
                R[b1] = _s32(ins[pc + 1] | (ins[pc + 2] << 16)) & M64
                R[b1 + 1] = 0
                pc += w
                continue
            if op == 0x18:  # const-wide (51l)
                v = ins[pc + 1] | (ins[pc + 2] << 16) | (ins[pc + 3] << 32) | (ins[pc + 4] << 48)
                R[b1] = v & M64
                R[b1 + 1] = 0
                pc += w
                continue
            if op == 0x19:  # const-wide/high16
                R[b1] = (_s16(ins[pc + 1]) << 48) & M64
                R[b1 + 1] = 0
                pc += w
                continue
            if op in (0x1a, 0x1b):  # const-string(/jumbo)
                idx = ins[pc + 1] if op == 0x1a else (ins[pc + 1] | (ins[pc + 2] << 16))
                R[b1] = dex.string(idx)
                pc += w
                continue

            if op == 0x22:  # new-instance
                tname = dex.type_str(ins[pc + 1])
                if _dfl is not None:                 # KB-7: new-instance initializes an app class (<clinit>)
                    _dfl.on_new_instance(self, tname)
                if tname.endswith("StringBuilder;") or tname.endswith("StringBuffer;"):
                    R[b1] = _SB()
                elif tname.endswith("/String;"):
                    R[b1] = _Str()
                else:
                    R[b1] = _Obj(tname)
                pc += w
                continue
            if op == 0x1f:  # check-cast
                if _dfl is not None:      # dexfloat-residuals: ClassCastException on a device (dex_float.check_cast)
                    _dfl.check_cast(self, R[b1], ins[pc + 1])
                pc += w
                continue

            if op == 0x21:  # array-length (12x)
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                R[a] = len(R[b])
                pc += w
                continue
            if op == 0x23:  # new-array (22c)
                a = b1 & 0xF
                bsz = (b1 >> 4) & 0xF
                asz = R[bsz]                         # (not `n`: _exec's own code length)
                if isinstance(asz, bool) or not isinstance(asz, int):
                    raise _Decline("new-array: size of type %s" % type(asz).__name__)
                asz = _s32(asz & M32)
                if asz < 0:
                    # KB-2 fix round 2 (the review of 4250749): Java throws NegativeArraySizeException; the size masked
                    # with 0x7FFFFFFF allocated 2^31 elements
                    raise _Decline("new-array: negative size %d (Java throws NegativeArraySizeException)" % asz)
                if asz > _MAX_NEW_ARRAY:
                    raise _Decline("new-array: %d elements is past the %d the VM allocates" % (asz, _MAX_NEW_ARRAY))
                R[a] = [0] * asz
                pc += w
                continue
            if op == 0x24:  # filled-new-array (35c)
                acount = (b1 >> 4) & 0xF
                g = b1 & 0xF
                regword = ins[pc + 2]
                argregs = [regword & 0xF, (regword >> 4) & 0xF, (regword >> 8) & 0xF, (regword >> 12) & 0xF, g][:acount]
                result = [R[r] for r in argregs]
                pc += w
                continue
            if op == 0x25:  # filled-new-array/range (3rc)
                acount = b1
                cfirst = ins[pc + 2]
                result = [R[cfirst + i] for i in range(acount)]
                pc += w
                continue
            if op == 0x26:  # fill-array-data (31t)
                aa = b1
                off = _s32(ins[pc + 1] | (ins[pc + 2] << 16))
                pp = pc + off
                if pp < 0 or ins[pp] != 0x0300:
                    raise _Decline("fill-array-data: no array-data payload at the target")
                ew = ins[pp + 1]
                size = ins[pp + 2] | (ins[pp + 3] << 16)
                data_units = ins[pp + 4:pp + 4 + (size * ew + 1) // 2] if ew in (1, 2, 4, 8) else []
                raw = struct.pack("<%dH" % len(data_units), *data_units)
                arr = R[aa]
                if ew not in (1, 2, 4, 8) or size * ew > len(raw):
                    raise _Decline("fill-array-data: payload of width %d and %d elements does not read" % (ew, size))
                if size > len(arr):
                    # KB-2 fix round 2: Java throws ArrayIndexOutOfBoundsException (this filled the first len(arr))
                    raise _Decline("fill-array-data: %d elements into an array of %d (Java throws)" % (size, len(arr)))
                for k in range(size):
                    arr[k] = int.from_bytes(raw[k * ew:(k + 1) * ew], "little", signed=True)
                pc += w
                continue
            if 0x44 <= op <= 0x51:  # aget*/aput* (23x)
                aa = b1
                u2 = ins[pc + 1]
                arr = R[u2 & 0xFF]
                # KB-2 fix round 2 (the review of 4250749, item a): bounds-checked as Java checks them (an index out of
                # range throws ArrayIndexOutOfBoundsException; Python's negative indexing read from the end)
                idx = _jindex(R[(u2 >> 8) & 0xFF], len(arr), "aget/aput")
                if op == 0x44:
                    R[aa] = arr[idx]
                elif op == 0x45:
                    R[aa] = arr[idx] & M64
                    R[aa + 1] = 0
                elif op == 0x46:
                    R[aa] = arr[idx]
                elif op == 0x47:
                    R[aa] = arr[idx] & 1
                elif op == 0x48:
                    R[aa] = _s8(arr[idx] & 0xFF)
                elif op == 0x49:
                    R[aa] = arr[idx] & 0xFFFF
                elif op == 0x4a:
                    R[aa] = _s16(arr[idx] & 0xFFFF)
                elif op == 0x4b:
                    arr[idx] = _s32(R[aa])
                elif op == 0x4c:
                    arr[idx] = R[aa] & M64
                elif op == 0x4d:
                    arr[idx] = R[aa]
                elif op == 0x4e:
                    arr[idx] = R[aa] & 1
                elif op == 0x4f:
                    arr[idx] = _s8(R[aa] & 0xFF)
                elif op == 0x50:
                    arr[idx] = R[aa] & 0xFFFF
                elif op == 0x51:
                    arr[idx] = _s16(R[aa] & 0xFFFF)
                pc += w
                continue

            if 0x60 <= op <= 0x66:  # sget*
                if _dfl is not None:                 # KB-7: the run's static store, <clinit> first (dex_float.sget)
                    R[b1] = _dfl.sget(self, op, ins[pc + 1])
                    if op == 0x61:
                        R[b1 + 1] = 0
                    pc += w
                    continue
                R[b1] = 0
                if op == 0x62:              # sget-object: StandardCharsets.<X> resolves to a charset token
                    fl = dex.field(ins[pc + 1])
                    if fl and fl[0] == "Ljava/nio/charset/StandardCharsets;" and fl[1] in _CHARSETS:
                        R[b1] = _Charset(fl[1])
                pc += w
                continue
            if 0x67 <= op <= 0x6d:  # sput*
                if _dfl is not None:                 # KB-7: into the run's static store (dex_float.sput)
                    _dfl.sput(self, op, ins[pc + 1], R[b1])
                pc += w
                continue
            if 0x52 <= op <= 0x5f:  # iget* / iput* (22c, instance fields)
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                field_idx = ins[pc + 1]
                obj = R[b]
                if not isinstance(obj, _Obj):     # a null / non-object target: fail closed
                    raise _Decline("iget/iput on non-object")
                if op <= 0x58:                    # iget*
                    v = obj.fields.get(field_idx, _NOFIELD)
                    if v is _NOFIELD:             # dexfloat-residuals: a field this run never wrote (dex_float.iget_unset)
                        v = 0 if _dfl is None else _dfl.iget_unset(self, obj, field_idx)
                    elif _dfl is not None and len(obj.fields) > 1:
                        _dfl.iget_alias(self, obj, field_idx)   # dexfloat-residuals: one field under two references
                    if op == 0x53:                # iget-wide
                        R[a] = v & M64
                        R[a + 1] = 0
                    elif op in (0x52, 0x54):      # iget / iget-object
                        R[a] = v
                    elif op == 0x55:              # iget-boolean
                        R[a] = v & 1
                    elif op == 0x56:              # iget-byte
                        R[a] = _s8(v & 0xFF)
                    elif op == 0x57:              # iget-char
                        R[a] = v & 0xFFFF
                    else:                         # iget-short (0x58)
                        R[a] = _s16(v & 0xFFFF)
                else:                             # iput* (0x59-0x5f): store the register value
                    obj.fields[field_idx] = R[a]
                pc += w
                continue

            if op == 0x28:  # goto
                off = _s8(b1)
                pc += off if off else w
                continue
            if op == 0x29:  # goto/16
                off = _s16(ins[pc + 1])
                pc += off
                continue
            if op == 0x2a:  # goto/32
                off = _s32(ins[pc + 1] | (ins[pc + 2] << 16))
                pc += off
                continue
            if op in (0x2b, 0x2c):  # packed-switch / sparse-switch (31t)
                val = _s32(R[b1])
                off = _s32(ins[pc + 1] | (ins[pc + 2] << 16))
                pp = pc + off
                ident = ins[pp]
                size = ins[pp + 1]
                target = None
                if op == 0x2b and ident == 0x0100:         # packed-switch payload
                    first_key = _s32(ins[pp + 2] | (ins[pp + 3] << 16))
                    base = pp + 4
                    k = val - first_key
                    if 0 <= k < size:
                        target = _s32(ins[base + k * 2] | (ins[base + k * 2 + 1] << 16))
                elif op == 0x2c and ident == 0x0200:       # sparse-switch payload
                    kbase = pp + 2
                    tbase = kbase + size * 2
                    for j in range(size):
                        key = _s32(ins[kbase + j * 2] | (ins[kbase + j * 2 + 1] << 16))
                        if key == val:
                            target = _s32(ins[tbase + j * 2] | (ins[tbase + j * 2 + 1] << 16))
                            break
                else:
                    raise _Decline("switch payload 0x%04x" % ident)
                pc += target if target is not None else w
                continue
            if 0x2d <= op <= 0x31:  # cmpl-float / cmpg-float / cmpl-double / cmpg-double / cmp-long (23x)
                # KB-2 fix round 1 (review of e281f95): the Dalvik numbering is 0x2d cmpl-float, 0x2e cmpg-float,
                # 0x2f cmpl-double, 0x30 cmpg-double, 0x31 cmp-long (this read 0x2d as cmp-long and 0x31 as a double
                # compare, so cmp-long(-1L, 0L) gave +1); an "l" compare gives -1 on a NaN, a "g" compare +1
                dst = b1
                u2 = ins[pc + 1]
                x = R[u2 & 0xFF]
                y = R[(u2 >> 8) & 0xFF]
                if op == 0x31:
                    xs, ys = _s64(x), _s64(y)
                    R[dst] = (xs > ys) - (xs < ys)
                else:
                    if op in (0x2d, 0x2e):
                        fa, fb, bias = _f32(x), _f32(y), (-1 if op == 0x2d else 1)
                    else:
                        fa, fb, bias = _f64(x), _f64(y), (-1 if op == 0x2f else 1)
                    if fa != fa or fb != fb:   # NaN
                        R[dst] = bias
                    else:
                        R[dst] = (fa > fb) - (fa < fb)
                pc += w
                continue
            if 0x32 <= op <= 0x37:  # if-test (22t)
                a = R[b1 & 0xF]
                b = R[(b1 >> 4) & 0xF]
                off = _s16(ins[pc + 1])
                take = (op == 0x32 and a == b) or (op == 0x33 and a != b) or \
                       (op == 0x34 and a < b) or (op == 0x35 and a >= b) or \
                       (op == 0x36 and a > b) or (op == 0x37 and a <= b)
                pc += off if take else w
                continue
            if 0x38 <= op <= 0x3d:  # if-testz (21t)
                a = R[b1]
                off = _s16(ins[pc + 1])
                take = (op == 0x38 and a == 0) or (op == 0x39 and a != 0) or \
                       (op == 0x3a and a < 0) or (op == 0x3b and a >= 0) or \
                       (op == 0x3c and a > 0) or (op == 0x3d and a <= 0)
                pc += off if take else w
                continue

            if op in (0x6e, 0x6f, 0x70, 0x71, 0x72):  # invoke-kind (35c)
                acount = (b1 >> 4) & 0xF
                g = b1 & 0xF
                midx = ins[pc + 1]
                regword = ins[pc + 2]
                argregs = [regword & 0xF, (regword >> 4) & 0xF, (regword >> 8) & 0xF, (regword >> 12) & 0xF, g][:acount]
                result = self._invoke(op, midx, [R[r] for r in argregs])
                pc += w
                continue
            if 0x74 <= op <= 0x78:  # invoke/range (3rc)
                acount = b1
                midx = ins[pc + 1]
                cfirst = ins[pc + 2]
                result = self._invoke(op, midx, [R[cfirst + i] for i in range(acount)])
                pc += w
                continue

            if op == 0x81:  # int-to-long
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                R[a] = _s32(R[b]) & M64
                R[a + 1] = 0
                pc += w
                continue
            if op == 0x84:  # long-to-int
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                R[a] = _s32(R[b] & M32)
                pc += w
                continue
            if op == 0x7b:  # neg-int
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                R[a] = _s32(-R[b])
                pc += w
                continue
            if op == 0x7d:  # neg-long
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                R[a] = (-R[b]) & M64
                R[a + 1] = 0
                pc += w
                continue
            if op == 0x7c:  # not-int
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                R[a] = _s32(~R[b])
                pc += w
                continue
            if op == 0x7e:  # not-long
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                R[a] = (~R[b]) & M64
                R[a + 1] = 0
                pc += w
                continue
            if op == 0x7f:  # neg-float (flip the sign bit; exact Java semantics, even for NaN)
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                R[a] = (R[b] ^ 0x80000000) & M32
                pc += w
                continue
            if op == 0x80:  # neg-double (flip the sign bit)
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                R[a] = (R[b] ^ 0x8000000000000000) & M64
                R[a + 1] = 0
                pc += w
                continue
            if 0x82 <= op <= 0x8c:  # int/long/float/double numeric conversions (12x)
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                x = R[b]
                if op == 0x82:                       # int-to-float
                    R[a] = _f32_bits(float(_s32(x)))
                elif op == 0x83:                     # int-to-double
                    R[a] = _f64_bits(float(_s32(x)))
                    R[a + 1] = 0
                elif op == 0x85:                     # long-to-float
                    if _dfl is not None:             # KB-7: one exact rounding from the 64-bit integer
                        R[a] = _dfl.l2f(self, x)
                        pc += w
                        continue
                    lv = _s64(x)
                    if abs(lv) >= (1 << 53):         # double-rounding risk: fail closed
                        raise _Decline("long-to-float precision")
                    R[a] = _f32_bits(float(lv))
                elif op == 0x86:                     # long-to-double
                    R[a] = _f64_bits(float(_s64(x)))
                    R[a + 1] = 0
                elif op == 0x87:                     # float-to-int
                    R[a] = _s32(_d2i(_f32(x)))
                elif op == 0x88:                     # float-to-long
                    R[a] = _d2l(_f32(x)) & M64
                    R[a + 1] = 0
                elif op == 0x89:                     # float-to-double
                    R[a] = _f64_bits(_f32(x))
                    R[a + 1] = 0
                elif op == 0x8a:                     # double-to-int
                    R[a] = _s32(_d2i(_f64(x)))
                elif op == 0x8b:                     # double-to-long
                    R[a] = _d2l(_f64(x)) & M64
                    R[a + 1] = 0
                else:                                # 0x8c double-to-float
                    R[a] = _f32_bits(_f64(x))
                pc += w
                continue
            if op in (0x8d, 0x8e, 0x8f):  # int-to-byte / int-to-char / int-to-short (12x)
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                x = R[b]
                if op == 0x8d:
                    R[a] = _s8(x & 0xFF)
                elif op == 0x8e:
                    R[a] = x & 0xFFFF
                else:
                    R[a] = _s16(x & 0xFFFF)
                pc += w
                continue

            if 0x90 <= op <= 0xaf:  # binop 23x
                dst = b1
                u2 = ins[pc + 1]
                sb = u2 & 0xFF
                sc = (u2 >> 8) & 0xFF
                R[dst] = self._binop(op, R[sb], R[sc], dst, R)
                pc += w
                continue
            if 0xb0 <= op <= 0xcf:  # binop/2addr
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                R[a] = self._binop2(op, R[a], R[b], a, R)
                pc += w
                continue
            if 0xd0 <= op <= 0xd7:  # binop/lit16
                a = b1 & 0xF
                b = (b1 >> 4) & 0xF
                lit = _s16(ins[pc + 1])
                R[a] = self._litop(op, R[b], lit, lit16=True)
                pc += w
                continue
            if 0xd8 <= op <= 0xe2:  # binop/lit8
                dst = b1
                u2 = ins[pc + 1]
                sb = u2 & 0xFF
                lit = _s8((u2 >> 8) & 0xFF)
                R[dst] = self._litop(op, R[sb], lit, lit16=False)
                pc += w
                continue

            if _dfl is not None:                     # KB-7: const-class (dex_float.exec_extra); anything else declines
                npc = _dfl.exec_extra(self, op, b1, ins, pc, R)
                if npc is not None:
                    pc = npc
                    continue
            raise _Decline("opcode 0x%02x" % op)
        return result

    def _binop(self, op, x, y, dst, R):
        if op == 0x90:
            return _s32(x + y)
        if op == 0x91:
            return _s32(x - y)
        if op == 0x92:
            return _s32(x * y)
        if op == 0x93:
            return _idiv32(x, y)
        if op == 0x94:
            return _irem32(x, y)
        if op == 0x95:
            return _s32(x & y)
        if op == 0x96:
            return _s32(x | y)
        if op == 0x97:
            return _s32(x ^ y)
        if op == 0x98:
            return _s32((x << (y & 31)) & M32)
        if op == 0x99:
            return _s32(x) >> (y & 31)
        if op == 0x9a:
            return _s32((x & M32) >> (y & 31))   # ushr by 0 of a negative int is still a negative int
        if op in (0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5):
            R[dst + 1] = 0
            if op == 0x9b:
                return (x + y) & M64
            if op == 0x9c:
                return (x - y) & M64
            if op == 0x9d:
                return (x * y) & M64
            if op == 0x9e:
                return _ldiv64(x, y)
            if op == 0x9f:
                return _lrem64(x, y)
            if op == 0xa0:
                return (x & y) & M64
            if op == 0xa1:
                return (x | y) & M64
            if op == 0xa2:
                return (x ^ y) & M64
            if op == 0xa3:
                return (x << (y & 63)) & M64
            if op == 0xa4:
                return (_s64(x) >> (y & 63)) & M64
            if op == 0xa5:
                return (x & M64) >> (y & 63)
        if op in _FBIN:                       # float/double add/sub/mul/div/rem (KB-7: exact IEEE, inf/NaN)
            bits, wide = _float_arith(op, x, y) if _dfl is None else _dfl.binop_float(self, op, x, y)
            if wide:
                R[dst + 1] = 0
            return bits
        raise _Decline("binop 0x%02x" % op)

    def _binop2(self, op, x, y, dst, R):
        if op == 0xb0:
            return _s32(x + y)
        if op == 0xb1:
            return _s32(x - y)
        if op == 0xb2:
            return _s32(x * y)
        if op == 0xb3:
            return _idiv32(x, y)
        if op == 0xb4:
            return _irem32(x, y)
        if op == 0xb5:
            return _s32(x & y)
        if op == 0xb6:
            return _s32(x | y)
        if op == 0xb7:
            return _s32(x ^ y)
        if op == 0xb8:
            return _s32((x << (y & 31)) & M32)
        if op == 0xb9:
            return _s32(x) >> (y & 31)
        if op == 0xba:
            return _s32((x & M32) >> (y & 31))
        if op in (0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5):
            R[dst + 1] = 0
            if op == 0xbb:
                return (x + y) & M64
            if op == 0xbc:
                return (x - y) & M64
            if op == 0xbd:
                return (x * y) & M64
            if op == 0xbe:
                return _ldiv64(x, y)
            if op == 0xbf:
                return _lrem64(x, y)
            if op == 0xc0:
                return (x & y) & M64
            if op == 0xc1:
                return (x | y) & M64
            if op == 0xc2:
                return (x ^ y) & M64
            if op == 0xc3:
                return (x << (y & 63)) & M64
            if op == 0xc4:
                return (_s64(x) >> (y & 63)) & M64
            if op == 0xc5:
                return (x & M64) >> (y & 63)
        if op in _FBIN:                       # float/double add/sub/mul/div/rem /2addr (KB-7: exact IEEE)
            bits, wide = _float_arith(op, x, y) if _dfl is None else _dfl.binop_float(self, op, x, y)
            if wide:
                R[dst + 1] = 0
            return bits
        raise _Decline("binop2 0x%02x" % op)

    def _litop(self, op, x, lit, lit16):
        if lit16:
            if op == 0xd0:
                return _s32(x + lit)
            if op == 0xd1:
                return _s32(lit - x)
            if op == 0xd2:
                return _s32(x * lit)
            if op in (0xd3, 0xd4) and not lit:
                raise _Decline("div/rem-int/lit16 by zero (Java throws ArithmeticException)")
            if op == 0xd3:
                return _s32(int(_s32(x) / lit)) if lit else 0
            if op == 0xd4:
                return _s32(_s32(x) - int(_s32(x) / lit) * lit) if lit else 0
            if op == 0xd5:
                return _s32(x & lit)
            if op == 0xd6:
                return _s32(x | lit)
            if op == 0xd7:
                return _s32(x ^ lit)
        else:
            if op == 0xd8:
                return _s32(x + lit)
            if op == 0xd9:
                return _s32(lit - x)
            if op == 0xda:
                return _s32(x * lit)
            if op in (0xdb, 0xdc) and not lit:
                raise _Decline("div/rem-int/lit8 by zero (Java throws ArithmeticException)")
            if op == 0xdb:
                return _s32(int(_s32(x) / lit)) if lit else 0
            if op == 0xdc:  # rem-int/lit8 (java trunc toward zero)
                xx = _s32(x)
                return _s32(xx - int(xx / lit) * lit) if lit else 0
            if op == 0xdd:
                return _s32(x & lit)
            if op == 0xde:
                return _s32(x | lit)
            if op == 0xdf:
                return _s32(x ^ lit)
            if op == 0xe0:
                return _s32((x << (lit & 31)) & M32)
            if op == 0xe1:
                return _s32(x) >> (lit & 31)
            if op == 0xe2:
                return _s32((x & M32) >> (lit & 31))
        raise _Decline("litop 0x%02x" % op)

    def _invoke(self, op, midx, args):
        if _dfl is not None:  # KB-7: invoke-static initializes its class; native float ABI / virtual override decline
            _dfl.pre_invoke(self, op, midx, args)   # (before any binding: the whole-image path too)
        if self.native_images and native_image_bridge is not None and midx not in self.dex.code:   # KB-2
            # the bridge answers plain only where so-ambig's binding rules (_so_verdict, over the whole table) agree
            return native_image_bridge.invoke(self, op, midx, args, self._invoke_legacy, _Decline,
                                              verdict=lambda m: _so_verdict(self, m))
        return self._invoke_legacy(op, midx, args)

    def _invoke_loader(self, op, midx, cls, name, args):
        """Day 31 fold (from day_patch.py, "Loaded Later"): the Android calls a chain uses to read a secondary
        dex out of THIS APK's assets and run a method of it by reflection. Returns (handled, result); (False, None)
        when the call is not one of these, so the ordinary dispatch continues. Every branch FAILS CLOSED: a shape
        it cannot reproduce exactly raises _Decline (the chain then declines, never a fabricated code). These calls
        all declined in the shipped VM, so this only reaches a formerly-unreachable code, under the judged route.

            Context/Activity.getAssets -> _Assets
            AssetManager.open(name)    -> _Stream over members["assets/" + name] (of THIS package only)
            InputStream.read/readAllBytes/available/close
            ByteBuffer.wrap(byte[][, off, len])
            getClassLoader             -> the parent-loader sentinel
            InMemoryDexClassLoader.<init>(buffer, parent) -> parse the buffer's bytes as a Dex on the instance
            ClassLoader.loadClass(name)-> a class token bound to that loaded dex (recorded in self.loaded)
            Class.getDeclaredMethod / getMethod on a loaded class -> a Method token
            Method.invoke of a loaded-class method -> run it on this same interpreter in the loaded dex
        """
        a0 = args[0] if args else None
        if name == "getAssets" and cls in ("Landroid/content/Context;", "Landroid/app/Activity;",
                                           "Landroid/content/ContextWrapper;"):
            return True, _Assets()
        if cls == "Landroid/content/res/AssetManager;" and name == "open" and isinstance(a0, _Assets):
            path = _as_text(args[1]) if len(args) > 1 else None
            b = self.members.get("assets/" + path) if (path and self.members is not None) else None
            if b is None:
                raise _Decline("asset not in this package")
            return True, _Stream(bytes(b))
        if isinstance(a0, _Stream):
            s = a0
            if name == "close" and len(args) == 1:
                return True, None
            if name == "available" and len(args) == 1:
                return True, len(s.b) - s.pos
            if name == "readAllBytes" and len(args) == 1:
                out = _sbytes(s.b[s.pos:])
                s.pos = len(s.b)
                return True, out
            if name == "read" and len(args) in (2, 4) and isinstance(args[1], list):
                buf = args[1]
                off, ln = (0, len(buf)) if len(args) == 2 else (args[2], args[3])
                if not (isinstance(off, int) and isinstance(ln, int) and 0 <= off and 0 <= ln
                        and off + ln <= len(buf)):
                    raise _Decline("read bounds")
                if ln == 0:
                    return True, 0
                if s.pos >= len(s.b):
                    return True, -1
                chunk = s.b[s.pos:s.pos + ln]
                buf[off:off + len(chunk)] = _sbytes(chunk)
                s.pos += len(chunk)
                return True, len(chunk)
            raise _Decline("stream %s" % name)
        if cls == "Ljava/nio/ByteBuffer;" and name == "wrap" and isinstance(a0, list):
            if len(args) == 1:
                return True, ("bytebuffer", bytes(_ubytes(a0)))
            if len(args) == 3 and isinstance(args[1], int) and isinstance(args[2], int):
                o, n = args[1], args[2]
                if not (0 <= o and 0 <= n and o + n <= len(a0)):
                    raise _Decline("wrap bounds")
                return True, ("bytebuffer", bytes(_ubytes(a0[o:o + n])))
            raise _Decline("wrap args")
        if name == "getClassLoader" and len(args) == 1:
            # The Day 31 chain obtains the parent loader via Class.getClassLoader() and passes it straight to
            # InMemoryDexClassLoader.<init>. The hostile getClassLoader().getParent() construct uses the same
            # getClassLoader() call, so it cannot be distinguished here; it declines one step later at getParent
            # (the ("parentloader",) sentinel has no getParent model), never a fabricated code.
            return True, ("parentloader",)
        if cls == "Ldalvik/system/InMemoryDexClassLoader;" and name == "<init>":
            if not (isinstance(a0, _Obj) and len(args) == 3 and isinstance(args[1], tuple)
                    and args[1][0] == "bytebuffer"):
                raise _Decline("loader init")
            a0.fields["__dex__"] = Dex(args[1][1])
            return True, None
        if name == "loadClass" and isinstance(a0, _Obj) and "__dex__" in a0.fields and len(args) == 2:
            ct = _ClassTok(_to_desc(_as_text(args[1])))
            self.loaded.append((ct, a0.fields["__dex__"]))
            self.loaded_inmemory = True
            return True, ct
        if (cls == "Ljava/lang/Class;" and name in ("getDeclaredMethod", "getMethod")
                and any(a0 is t for t, _ in self.loaded)):
            return True, _MethTok(a0.desc, _as_text(args[1]))
        if cls == "Ljava/lang/reflect/Method;" and name == "invoke" and isinstance(a0, _MethTok):
            hits = [px for t, px in self.loaded if t.desc == a0.desc]
            if hits:
                if len(hits) != 1:
                    raise _Decline("two loaded dexes")
                px = hits[0]
                tgt = [m for m, mn in px.mname.items() if mn == (a0.desc, a0.name) and m in px.code]
                if len(tgt) != 1:
                    raise _Decline("payload method not unique")
                arr = args[2] if len(args) > 2 else None
                frame = []
                for el in (arr if isinstance(arr, list) else []):
                    if isinstance(el, _Box):
                        frame.append(el.v & M64 if el.t in ("J", "D") else el.v)
                        if el.t in ("J", "D"):
                            frame.append(0)
                    elif isinstance(el, int) or el is None:
                        frame.append(el)
                    else:
                        raise _Decline("reflect arg type")
                sub = VM(px, _NativeTable(), {})
                sub.members, sub.loaded = self.members, self.loaded
                sub.max_steps = max(0, self.max_steps - self.steps)
                try:
                    out = sub.run(tgt[0], frame)
                finally:
                    self.steps += sub.steps
                if isinstance(out, int):
                    shorty = px.meth_shorty(tgt[0]) or ""
                    if shorty[:1] == "J":
                        return True, _Box("J", out & M64)
                    if shorty[:1] == "I":
                        return True, _Box("I", out)
                    raise _Decline("payload return type")
                return True, out
            # a Method token for a class NOT loaded from an in-memory dex: the ordinary reflection dispatch owns it
        return False, None

    def _invoke_legacy(self, op, midx, args):
        """VM._invoke past KB-7's pre_invoke (which _invoke runs once for every invoke): an app method's body, KB-7's
        framework models, a native bound by the so-ambig rules, the framework models. The KB-2 bridge asks it about
        exactly one native body (a one-entry native table) or a framework method (an empty one)."""
        dex = self.dex
        if midx in dex.code:  # an app method with a body: interpret it
            return self.run(midx, args)
        cls, name = dex.mname.get(midx, dex.meth(midx))
        # Day 31 fold (the "Loaded Later" chain, from day_patch.py): the asset read, the in-memory dex loader
        # and the reflection INTO a loaded dex are modelled here, before KB-7's reflection on the running dex, so
        # a loaded-class getDeclaredMethod/Method.invoke resolves in the loaded dex and not classes.dex. Each of
        # these calls declined in the shipped VM, so a chain that does not touch them is unchanged (never-wrong:
        # it only turns a former decline into a resolution, under the judged `analysis` route).
        lhit, lout = self._invoke_loader(op, midx, cls, name, args)
        if lhit:
            return lout
        if _dfl is not None:  # KB-7: Float/Double/Math, reflection, loadLibrary, and the refusals (dex_float.invoke)
            hit, out = _dfl.invoke(self, op, midx, cls, name, args)
            if hit:
                return out
        if self.native_syms and not _boot_class(cls):  # a native app method: emulate its JNI code from the .so
            # the first symbol the loose rule matches in table order (one ending in '_' + the method's name), found
            # through the table's binding-key index (Day 27 so-ambig fix round 1: no scan of the table per call).
            # Day 27 so-ambig fix round 2: a method of a boot class (java.*, android.*, ...) is the framework's on every
            # device, never a JNI function of the app's library, so a library exporting `Java_..._rotateLeft` no longer
            # stands in for Long.rotateLeft (the models below answer it, as without the library)
            first = _so_first(self.native_syms, cls, name)
            if first is not None:
                sym, emach, codeb = _so_bind(self.native_syms, dex, midx, cls, name, first)   # Day 27 so-ambig r2
                if emach == EM_ARM:
                    # B-164 (verification round 1): a 32-bit ARM definition that is not one of the two vetted
                    # sentinels came out of a container no Android loader loads as armeabi (an ELF64 file with
                    # e_machine 40, a big-endian ELF32): on a device the library fails to load and none of its
                    # code runs, so there is no value to read
                    raise _Decline("native e_machine 40 (32-bit ARM) is in a container no Android loader loads "
                                   "(not a little-endian ELF32): not modelled")
                if emach not in _EM_RUNNABLE + (EM_MULTI,):
                    # An architecture with no emulator here: fail closed rather than decode foreign words
                    # (the WRONG-plain vector). B-164 added the 32-bit ARM modes (EM_ARM_A32/EM_ARM_THUMB).
                    raise _Decline("native e_machine %d not modelled" % emach)
                is_arm32 = emach in _EM_ARM32
                # Map the Java arguments to ABI argument registers by the method shorty: a static JNI
                # native takes JNIEnv*, jclass, then the Java args (x86-64 SysV: rdi, rsi, rdx, rcx, r8,
                # r9; AArch64 AAPCS: x0, x1, x2, ...), and a long/double (two Dalvik slots) consumes
                # exactly one register. This is what lets a branching native read a second argument --
                # e.g. a 16-bit length gate -- that a single-arg mapping would leave as 0 (gate-FAIL).
                # B-164: on 32-bit ARM each core register is 32-bit, so a jlong/jdouble occupies a register
                # PAIR (even-aligned) that this 1-register-per-arg mapping cannot place; such an argument and
                # a jlong RETURN (it comes back in r0:r1) are declined there, fail closed.
                shorty = dex.meth_shorty(midx)
                java_args = []
                if shorty:
                    if shorty[0] in ("F", "D", "L"):
                        # KB-2 fix round 1: these readers read the INTEGER return register only. A float or
                        # double comes back in a vector register, and a reference is a handle no Java value
                        # equals: either would hand the chain a made-up value.
                        raise _Decline("native return type %s not modelled by the readers" % shorty[0])
                    if is_arm32 and shorty[0] == "J":
                        raise _Decline("arm32 jlong return comes back in a register pair (r0:r1), not modelled")
                    ai = 0
                    for p in shorty[1:]:                     # shorty[0] is the return type
                        v = args[ai] if ai < len(args) else 0
                        if p in ("F", "D"):
                            # a float or double argument is passed in a vector register, not the next integer
                            # register these readers fill
                            raise _Decline("native float/double argument not modelled by the readers")
                        if is_arm32 and p == "J":
                            raise _Decline("arm32 jlong argument uses an even-aligned register pair, not modelled")
                        if isinstance(v, _Box):
                            if p == "L":
                                # Integer.valueOf(0) and the like is a non-null OBJECT on a device: unboxed,
                                # its 0 would reach the native as NULL (KB-2, the review of e281f95)
                                raise _Decline("native reference argument holds a boxed value (an object)")
                            v = v.v
                        if not isinstance(v, int):
                            raise _Decline("native non-integer argument")
                        java_args.append(v & M64)
                        ai += 2 if p in ("J", "D") else 1    # a wide type occupies two Dalvik slots
                elif is_arm32:
                    # Without a proto the arm32 argument widths are unknown, so a jlong could be mis-placed:
                    # decline (the x86/arm64 one-register-per-slot fallback does not hold on 32-bit ARM).
                    raise _Decline("arm32 native needs the method proto (shorty) to map arguments")
                else:
                    # No proto section to read the shorty from: pass the raw Dalvik argument registers
                    # in order (preserves the single-jlong behaviour the arm64 reader relied on).
                    for v in args:
                        if isinstance(v, _Box):
                            v = v.v
                        if not isinstance(v, int):
                            raise _Decline("native non-integer argument")
                        java_args.append(v & M64)
                # GENERAL native path: Unicorn, cross-checked against the hand-rolled reader (never-wrong). The JNIEnv
                # and the jclass are UNDEFINED (None), as on a device they are pointers no emulator here holds (Day 27
                # so-ambig fix round 2: a defined 0 made a native testing `env == NULL` compute a code no device does)
                result = (_native_multi(codeb, [None, None] + java_args) if emach == EM_MULTI   # Day 27 so-ambig r2
                          else _native_dispatch(codeb, [None, None] + java_args, emach)) & M64
                # KB-2 fix round 1 (review of e281f95): a jint/jshort/jbyte/jchar/jboolean return is the low
                # bits of the register (the ABI leaves the rest unspecified), kept as the VM keeps that Java
                # type: signed for int, short and byte, so a negative jint takes the if-ltz leg a device takes
                ret_t = shorty[0] if shorty else None
                if ret_t == "I":
                    result = _s32(result)
                elif ret_t == "S":
                    result = _s16(result & 0xFFFF)
                elif ret_t == "B":
                    result = _s8(result & 0xFF)
                elif ret_t == "C":
                    result = result & 0xFFFF
                elif ret_t == "Z":
                    if (result & 0xFF) not in (0, 1):
                        raise _Decline("native jboolean return outside 0/1")
                    result = result & 0xFF
                if emach == EM_X86_64 and result == 0:
                    # NEVER-WRONG: a native JNI authorization transform returning 0 is the
                    # "denied / missing binding" sentinel (the gate-FAIL branch). Its chain assembles
                    # a decoy code, never the real answer, so decline rather than ever let that decoy
                    # reach the judge as a plain answer (Day 25 set6: the gate-FAIL leg returned 0 and
                    # produced the judge-rejected decoy ANS-<decoy code>; the gate-PASS leg returns the
                    # mixed hash -> ANS-<judged code>). Declining only ever makes the reading
                    # unsure/None; it can never introduce a wrong answer.
                    raise _Decline("x86 native returned the denied sentinel 0 (gate-fail)")
                if is_arm32 and result == 0:
                    # B-164 (verification round 2): the same rule on the new 32-bit ARM path. The same build
                    # compiled for armeabi-v7a has the same gate-fail leg, and a jint that is 0 by chance is
                    # one call in 2**32. arm64 keeps its imported behaviour (0 reads as a value): see the
                    # build log's gaps.
                    raise _Decline("arm32 native returned the denied sentinel 0 (gate-fail)")
                return result
        if cls.endswith("StringBuilder;") or cls.endswith("StringBuffer;"):
            if name in ("<init>",):
                # StringBuilder(int capacity) / () return None; StringBuilder(String) seeds the buffer
                if len(args) >= 2 and isinstance(args[0], _SB):
                    t = _as_text(args[1])
                    if t is not None:
                        args[0].parts.append(t)
                return None
            if name == "append":
                sb = args[0]
                v = args[1]
                if isinstance(v, list):                                  # append(char[])
                    sb.parts.append("".join(chr(c & 0x10FFFF) for c in v))
                elif isinstance(v, int):
                    # append(int|short|byte|long) renders the DECIMAL string (Java); append(char) renders
                    # the character. A register holds both as a Python int, so decide by the method shorty;
                    # keep the shipped single-char behaviour when the shorty is unavailable, so only an
                    # append DEFINITELY typed int/short/byte/long changes (the hex-formatting loops are
                    # append(char), shorty 'C', and are untouched -- no regression).
                    shorty = self.dex.meth_shorty(midx)
                    ptype = shorty[1] if isinstance(shorty, str) and len(shorty) > 1 else "C"
                    if ptype in ("I", "S", "B"):
                        sb.parts.append(str(_s32(v)))
                    elif ptype == "J":
                        sb.parts.append(str(_s64(v)))
                    else:                                                # 'C' and anything unknown: char
                        sb.parts.append(chr(v & 0x10FFFF))
                else:
                    t = _as_text(v)
                    sb.parts.append("" if v is None else (t if t is not None else str(v)))
                return sb
            if name == "toString":
                return "".join(args[0].parts)
            if name == "reverse":
                sb = args[0]
                sb.parts = ["".join(sb.parts)[::-1]]
                return sb
            if name == "insert":
                sb = args[0]
                idx = args[1]
                v = args[2] if len(args) > 2 else None
                if isinstance(v, list):
                    piece = "".join(chr(c & 0x10FFFF) for c in v)
                elif isinstance(v, int):
                    piece = chr(v & 0x10FFFF)
                else:
                    t = _as_text(v)
                    piece = t if t is not None else ("" if v is None else str(v))
                s = "".join(sb.parts)
                idx = _jindex(idx, len(s), "StringBuilder.insert", end_ok=True)   # KB-2 fix round 2: as Java checks
                sb.parts = [s[:idx] + piece + s[idx:]]
                return sb
            if name == "length":
                return len("".join(args[0].parts))
            if name == "charAt":
                s = "".join(args[0].parts)
                return ord(s[_jindex(args[1], len(s), "StringBuilder.charAt")])
            if name == "setCharAt":
                sb = args[0]
                s = list("".join(sb.parts))
                s[_jindex(args[1], len(s), "StringBuilder.setCharAt")] = chr(args[2] & 0x10FFFF)
                sb.parts = ["".join(s)]
                return None
            if name == "setLength":
                sb = args[0]
                s = "".join(sb.parts)
                nlen = args[1]
                if isinstance(nlen, bool) or not isinstance(nlen, int) or _s32(nlen & M32) < 0:
                    raise _Decline("StringBuilder.setLength: a negative or non-int length (Java throws)")
                nlen = _s32(nlen & M32)
                if nlen > _MAX_NEW_ARRAY:
                    raise _Decline("StringBuilder.setLength: %d characters is past what the VM builds" % nlen)
                # KB-2 fix round 2: Java pads with NUL characters past the current length (this kept the shorter text)
                sb.parts = [s[:nlen] + "\x00" * max(0, nlen - len(s))]
                return None
            raise _Decline("StringBuilder.%s" % name)
        if cls.endswith("/String;"):
            if name == "<init>":                                         # new String(char[]/byte[]/String)
                obj = args[0]
                if isinstance(obj, _Str):
                    if len(args) == 1:
                        obj.val = ""
                        return None
                    src = args[1]
                    if len(args) == 3 and isinstance(src, list):         # new String(byte[], charset|name)
                        obj.val = _java_decode(_ubytes(src), _charset_codec(args[2]))
                        return None
                    if len(args) > 2:
                        raise _Decline("String.<init> shape")
                    if isinstance(src, list):                            # char[] / byte[] of char codes
                        if any((not isinstance(c, int)) or c < 0 for c in src):
                            raise _Decline("String.<init> of a signed byte[] (Java decodes UTF-8)")
                        obj.val = "".join(chr(c & 0x10FFFF) for c in src)
                        return None
                    t = _as_text(src)
                    if t is not None:
                        obj.val = t
                        return None
                raise _Decline("String.<init> args")
            if name == "valueOf":
                return self._string_value_of(args[0] if args else None, dex.meth_shorty(midx))
            if name == "format":
                if len(args) == 2:
                    fmt, arr = _as_text(args[0]), args[1]
                elif len(args) == 3:                                     # (Locale, String, Object[])
                    fmt, arr = _as_text(args[1]), args[2]
                else:
                    raise _Decline("String.format arity")
                if fmt is None or not isinstance(arr, list):
                    raise _Decline("String.format args")
                return _java_format(fmt, arr)
            s = _as_text(args[0])
            if s is not None:
                if name == "charAt":
                    return ord(s[_jindex(args[1], len(s), "String.charAt")])   # KB-2 fix round 2: as Java checks
                if name == "length":
                    return len(s)
                if name == "toUpperCase":
                    return s.upper()
                if name == "toLowerCase":
                    return s.lower()
                if name == "trim":
                    return s.strip()
                if name == "substring":
                    # KB-2 fix round 2: 0 <= begin <= end <= length, else Java throws (Python clipped or counted from the
                    # end)
                    b0 = _jindex(args[1], len(s), "String.substring", end_ok=True)
                    e0 = len(s) if len(args) == 2 else _jindex(args[2], len(s), "String.substring", end_ok=True)
                    if b0 > e0:
                        raise _Decline("String.substring: begin %d past end %d (Java throws)" % (b0, e0))
                    return s[b0:e0]
                if name == "concat":
                    t = _as_text(args[1])
                    if t is None:
                        raise _Decline("String.concat")
                    return s + t
                if name == "toCharArray":
                    return [ord(c) for c in s]
                if name == "getBytes":
                    if len(args) == 1:                                   # default charset: UTF-8 (Android)
                        return _java_encode(s, "utf-8")
                    if len(args) == 2:
                        return _java_encode(s, _charset_codec(args[1]))
                    raise _Decline("String.getBytes shape")
                if name == "replace":
                    a, b = args[1], args[2]
                    fa = chr(a & 0x10FFFF) if isinstance(a, int) else _as_text(a)
                    fb = chr(b & 0x10FFFF) if isinstance(b, int) else _as_text(b)
                    if fa is None or fb is None:
                        raise _Decline("String.replace")
                    return s.replace(fa, fb)
                if name == "indexOf":
                    a = args[1]
                    sub = chr(a & 0x10FFFF) if isinstance(a, int) else _as_text(a)
                    if sub is None:
                        raise _Decline("String.indexOf")
                    start = 0
                    if len(args) > 2:
                        f = args[2]
                        if isinstance(f, bool) or not isinstance(f, int):
                            raise _Decline("String.indexOf fromIndex")
                        # KB-2 fix round 2: Java clamps a negative fromIndex to 0 (Python counted it from the end); past
                        # the end a String needle finds only "" (at the length), a char nothing
                        start = max(0, _s32(f & M32))
                    if start > len(s):
                        return len(s) if (sub == "" and not isinstance(a, int)) else -1
                    return s.find(sub, start)
            raise _Decline("String.%s" % name)
        if cls.endswith("Integer;"):
            if name == "toHexString":
                return format(args[0] & M32, "x")
            if name == "toOctalString":
                return format(args[0] & M32, "o")
            if name == "toBinaryString":
                return format(args[0] & M32, "b")
            if name == "toString":
                return _int_to_string(args[0], args[1] if len(args) > 1 else 10, 32)
            if name == "valueOf":
                return _Box("I", _s32(args[0]))
            if name == "parseInt":
                t = _as_text(args[0])
                if t is None:
                    raise _Decline("Integer.parseInt")
                try:
                    return _s32(int(t.strip(), args[1] if len(args) > 1 else 10))
                except ValueError:
                    raise _Decline("Integer.parseInt value")
            if name == "bitCount":
                return bin(args[0] & M32).count("1")
            if name == "intValue":
                v = args[0]
                return _s32(v.v) if isinstance(v, _Box) else _s32(v)
            raise _Decline("Integer.%s" % name)
        if cls.endswith("Long;"):
            if name == "toHexString":
                return format(args[0] & M64, "x")
            if name == "toOctalString":
                return format(args[0] & M64, "o")
            if name == "toBinaryString":
                return format(args[0] & M64, "b")
            if name == "toString":
                # the long occupies two argument slots; the radix (if any) is the slot after it
                return _int_to_string(args[0], args[2] if len(args) > 2 else 10, 64)
            if name == "valueOf":
                return _Box("J", args[0] & M64)
            if name == "longValue":
                v = args[0]
                return (v.v & M64) if isinstance(v, _Box) else (v & M64)
            raise _Decline("Long.%s" % name)
        if cls.endswith("Character;"):
            if name == "forDigit":
                return _for_digit(args[0], args[1])
            if name == "toString":
                return chr(args[0] & 0x10FFFF)
            if name == "toUpperCase":
                u = chr(args[0] & 0x10FFFF).upper()
                return ord(u) if len(u) == 1 else (args[0] & 0xFFFF)
            if name == "toLowerCase":
                lo = chr(args[0] & 0x10FFFF).lower()
                return ord(lo) if len(lo) == 1 else (args[0] & 0xFFFF)
            if name == "digit":
                ch = chr(args[0] & 0x10FFFF)
                try:
                    d = int(ch, args[1])
                    return d
                except (ValueError, TypeError):
                    return -1
            if name == "getNumericValue":
                ch = chr(args[0] & 0x10FFFF)
                try:
                    return int(ch, 36)
                except ValueError:
                    return -1
            if name == "valueOf":
                return _Box("C", args[0] & 0xFFFF)
            if name == "charValue":
                v = args[0]
                return (v.v & 0xFFFF) if isinstance(v, _Box) else (v & 0xFFFF)
            raise _Decline("Character.%s" % name)
        if cls.endswith("Boolean;") and name == "valueOf":
            return _Box("Z", bool(args[0]))
        if cls == "Ljava/lang/Byte;" and name == "valueOf" and len(args) == 1 and isinstance(args[0], int):
            return _Box("B", _s8(args[0] & 0xFF))
        if cls == "Ljava/nio/charset/Charset;" and name == "forName" and len(args) == 1:
            _charset_codec(args[0])
            return _Charset(_as_text(args[0]))
        handled, crypto_out = _crypto_invoke(cls, name, args)
        if handled:
            return crypto_out
        # Reflection: Class.forName / getDeclaredMethod|getMethod / Method.invoke, resolving an app
        # method in THIS delivery's dex and running it on the proven interpreter. Every class and method
        # name comes from the dex string constants of this delivery, so it is variant-proof; an
        # unresolved target declines (never guesses a code).
        if cls == "Ljava/lang/Class;" and name == "forName":
            return _ClassTok(_to_desc(_as_text(args[0])))
        if cls == "Ljava/lang/Class;" and name in ("getDeclaredMethod", "getMethod"):
            ct = args[0]
            desc = ct.desc if isinstance(ct, _ClassTok) else None
            nm = _as_text(args[1]) if len(args) > 1 else None
            return _MethTok(desc, nm)
        if cls == "Ljava/lang/reflect/AccessibleObject;" and name == "setAccessible":
            return None
        if cls == "Ljava/lang/reflect/Method;" and name == "invoke":
            mt = args[0]                                    # this (the Method); args[1] receiver (null here)
            if not isinstance(mt, _MethTok) or mt.desc is None or mt.name is None:
                raise _Decline("reflect target unresolved")
            tgt = None
            for mi2, mn in dex.mname.items():
                if mn == (mt.desc, mt.name) and mi2 in dex.code:
                    tgt = mi2
                    break
            if tgt is None:
                raise _Decline("reflect method not found %s->%s" % (mt.desc, mt.name))
            arr = args[2] if len(args) > 2 else None        # the Object[] of boxed arguments
            frame = []
            if isinstance(arr, list):
                for el in arr:
                    if isinstance(el, _Box):
                        frame.append(el.v & M64 if el.t in ("J", "D") else el.v)
                        if el.t in ("J", "D"):
                            frame.append(0)                 # a wide value occupies two register slots
                    elif isinstance(el, int):
                        frame.append(el)
                    elif el is None:
                        frame.append(None)
                    else:
                        raise _Decline("reflect arg type")
            out = self.run(tgt, frame)
            if isinstance(out, int):
                return _Box("J", out & M64)                 # autobox the primitive long return
            return out
        if name == "<init>":
            if _dfl is not None:      # dexfloat-residuals: a constructor no model takes (dex_float.init_catchall)
                _dfl.init_catchall(self, cls, args)
            return None
        raise _Decline("invoke %s->%s" % (cls, name))

    def _string_value_of(self, v, shorty):
        """String.valueOf(x): resolved by the method's shorty descriptor when the dex carries one
        (char vs int is otherwise indistinguishable from the runtime int), else by the runtime type
        for the cases that are unambiguous. Declines (never guesses) when it cannot be sure."""
        if shorty and len(shorty) >= 2:
            p = shorty[1]
            if p == "I":
                return str(_s32(v))
            if p == "J":
                return str(_s64(v))
            if p == "C":
                return chr(v & 0x10FFFF)
            if p == "Z":
                return "true" if v else "false"
            if p == "L":
                if isinstance(v, list):
                    return "".join(chr(c & 0x10FFFF) for c in v)
                t = _as_text(v)
                if t is not None:
                    return t
                raise _Decline("String.valueOf(L) non-text")
            raise _Decline("String.valueOf shorty %s" % shorty)
        if isinstance(v, list):
            return "".join(chr(c & 0x10FFFF) for c in v)
        t = _as_text(v)
        if t is not None:
            return t
        raise _Decline("String.valueOf ambiguous (no proto)")


# --------------------------------------------------------------- entry finding and recovery
def _dex_members(files):
    """Every classes*.dex (and any .dex) member of the package, classes.dex first."""
    out = []
    if not isinstance(files, dict):
        return out
    primary = files.get("classes.dex")
    if primary:
        out.append(bytes(primary))
    for k, v in files.items():
        if not (isinstance(k, str) and v):
            continue
        if k == "classes.dex":
            continue
        if k.endswith(".dex") or k.rsplit("/", 1)[-1].startswith("classes"):
            if k.endswith(".dex"):
                out.append(bytes(v))
    return out


def _so_members(files):
    out = []
    if isinstance(files, dict):
        for k, v in files.items():
            if isinstance(k, str) and k.endswith(".so") and v:
                out.append(bytes(v))
    return out


# Day 27 (so-ambig): one JNI method bound differently by two native libraries of one delivery.
EM_AMBIGUOUS = -1            # no ELF machine: VM._invoke declines a symbol so marked, as it declines an unmodelled one
SO_AMBIG_GROUP = 64          # definitions of one binding key past which the key is ambiguous whole (bounded work)
_SO_AMBIG_SAID = set()       # the conflicts this process has already printed


def _bind_key(sym):
    """'_' + name for the shortest suffix of `sym` of that form with a non-empty name, else None. VM._invoke binds a
    method without dex code to a symbol ending in '_' + its name, so two symbols can be bound to one method exactly
    when their keys are equal (a suffix both end in holds the shorter key of each)."""
    i = sym.rfind("_", 0, len(sym) - 1)
    return sym[i:] if i >= 0 else None


# Day 27 (so-ambig, fix round 1 of the review of 6f0ed2a): what a device's loader exports, body by body.
SO_ELF32_LEGS = "ignore"     # a 32-bit (ELF32) entry of a name a 64-bit body exports too: "ignore" (it is not run
#                              beside the 64-bit one, so the 64-bit binding answers, as on the base) or "decline" (it
#                              withholds, as an arm64 leg no emulator runs does): the player's or the integrator's decision
SO_CTORS = "decline"         # fix round 2: a library with DT_INIT or a non-empty DT_INIT_ARRAY (a constructor may bind
#                              natives as JNI_OnLoad does) withholds every binding ("decline", as rule 1 does for an
#                              unproven JNI_OnLoad), or is read as before ("ignore"). No saved Day 15-26 library has one
_JNI_VERSIONS = (0x10002, 0x10004, 0x10006)   # what ART takes back from JNI_OnLoad (java_vm_ext.cc, IsBadJniVersion)
_SO_EXPORT_BINDS = (1, 2, 10)                 # STB_GLOBAL, STB_WEAK, STB_GNU_UNIQUE: what a loader COULD return
_SO_MAX_SYMS = 1 << 18                        # .dynsym entries past which a body is not read (opaque)
_SO_NAME_MAX = 4096                           # a dynamic symbol name longer than this makes the body opaque
_SO_MAX_TABLE = 1 << 22                       # hash buckets, chain entries or bloom words past which likewise
_SO_ELF32_SAID = set()                        # the ELF32 NOTEs this process has already printed
_UNSET = object()


def _gnu_hash(name):
    """The GNU hash of a symbol name (bytes), as bionic's SymbolName::gnu_hash computes it."""
    h = 5381
    for c in name:
        h = (h * 33 + c) & 0xFFFFFFFF
    return h


def _sysv_hash(name):
    """The SysV ELF hash of a symbol name (bytes), as bionic's SymbolName::elf_hash computes it."""
    h = 0
    for c in name:
        h = ((h << 4) + c) & 0xFFFFFFFF
        g = h & 0xF0000000
        h ^= g
        h ^= g >> 24
    return h


class _SoBody:
    """One .so body as a device's loader reads its exports.

    `_parse_so` merges .dynsym with .symtab, keeps only sized FUNC symbols and reads ELF64 alone, so round 2's exact
    binding took a LOCAL static (dlsym never returns one) for the name ART binds, and never saw a NOTYPE, size-0 or
    IFUNC export, a JNI_OnLoad of such a type, or an ELF32 body, though dlsym returns each and ART calls them (the
    review's Q1 to Q3 and P1 to P3). This reads the body's own dynamic symbol table, ELF32 and ELF64, either byte order:
      recs         one [name, bind, type, shndx, defn, hidden] per .dynsym entry, in table order: defn the
                   (machine, code) `_parse_so` gives a sized FUNC (the very bytes, by its own address mapping), else
                   None; hidden the GNU version's hidden bit
      exported(n)  every entry under the name a loader COULD return: defined (shndx not 0), GLOBAL, WEAK or GNU_UNIQUE,
                   of any type, size, visibility or version, reached by the hash table or not (the over-estimate every
                   disagreement check of _so_bind reads)
      found(n)     the one entry dlsym DOES return: through the hash table the loader walks (GNU before SysV, its bloom
                   filter and chain), a hidden version passed over, GLOBAL or WEAK and defined (bionic's
                   is_symbol_global_and_defined); a body with no hash table at all, as the tests' hand-built ones,
                   in table order (the under-estimate a binding needs)
    A body with a PT_DYNAMIC segment must name the sections read here in its DT_SYMTAB, DT_STRTAB, DT_GNU_HASH (else
    DT_HASH) and DT_VERSYM, else it is `opaque` (its section headers do not describe the tables the loader reads), as is
    a body whose tables do not read; every native binding of the delivery then declines. One whose hash table bionic
    refuses (none at all beside a dynamic segment, a GNU bloom size that is no power of two, no bucket) is not
    `loadable`: dlsym finds nothing in it. A body that is no ELF, or whose header no loader reads, exports nothing.

    Fix round 2 (the review of 38a1668): a defn is read through the section headers (as `_parse_so` reads the code the
    VM runs), but a device maps code through PT_LOAD; a body whose .text section points at other bytes than PT_LOAD maps
    for the same address bound code no device runs. Now, in a body with PT_LOAD segments, a sized FUNC's defn is kept
    only when every segment that maps [st_value, st_value + st_size) holds those very bytes and is executable (else
    None, so the binding declines). A body whose code the loader may patch is not `loadable`: text relocations (DT_TEXTREL, DF_TEXTREL;
    bionic refuses them in a 64-bit library) or a writable and executable PT_LOAD (refused from targetSdk 26). `ctors`:
    why the loader runs code of this body before any JNI call (DT_INIT, a non-empty DT_INIT_ARRAY: a constructor may
    RegisterNatives through JNI_GetCreatedJavaVMs as JNI_OnLoad does), else None; bionic ignores DT_PREINIT_ARRAY in a
    shared object."""

    __slots__ = ("data", "_done", "_elf", "_elfclass", "_machine", "_opaque", "_loadable", "_recs", "_e", "_names",
                 "_hash", "_found", "_funcs", "_ctors")

    def __init__(self, data):
        self.data = data
        self._done = False          # the tables are read on first use: a chain that calls no native pays nothing
        self._found = {}
        self._funcs = None

    def _ensure(self):
        if self._done:
            return
        self._done = True
        self._elf = False
        self._elfclass = self._machine = None
        self._opaque = None
        self._loadable = True
        self._recs = []
        self._e = "<"
        self._names = {}
        self._hash = None
        self._ctors = None
        try:
            self._read()
        except Exception as e:      # a table that does not read: what the body exports is not known
            if self._elf:
                self._opaque = "its symbol tables do not read (%s)" % type(e).__name__
            self._recs, self._names, self._hash = [], {}, None

    @property
    def elf(self):
        self._ensure()
        return self._elf

    @property
    def ctors(self):
        self._ensure()
        return self._ctors

    @property
    def elfclass(self):
        self._ensure()
        return self._elfclass

    @property
    def machine(self):
        self._ensure()
        return self._machine

    @property
    def opaque(self):
        self._ensure()
        return self._opaque

    @property
    def loadable(self):
        self._ensure()
        return self._loadable

    @property
    def recs(self):
        self._ensure()
        return self._recs

    @property
    def funcs(self):
        """`_parse_so`'s table of this body ({symbol: (machine, code)}), read once."""
        if self._funcs is None:
            self._funcs = _parse_so(self.data)
        return self._funcs

    def exported(self, name):
        self._ensure()
        return [self._recs[i] for i in self._names.get(name, ())]

    def exported_prefix(self, prefix):
        self._ensure()
        return [self._recs[i] for nm, idx in self._names.items() if nm.startswith(prefix) for i in idx]

    def found(self, name):
        got = self._found.get(name, _UNSET)
        if got is _UNSET:
            got = None
            if self.elf and self.loadable and not self.opaque:
                try:
                    got = self._lookup(name)
                except Exception:
                    got = None      # a chain that does not read finds nothing (the under-estimate)
            self._found[name] = got
        return got

    def _lookup(self, name):
        recs = self._recs

        def hit(i):
            r = recs[i] if 0 < i < len(recs) else None
            return r is not None and r[0] == name and r[1] in (1, 2) and r[3] != 0 and not r[5]
        h = self._hash
        if h is None:
            return next((recs[i] for i in range(1, len(recs)) if hit(i)), None)
        nb = name.encode("latin1")
        if h[0] == "gnu":
            _, nbucket, symndx, maskwords, shift2, bloom, buckets, coff, bits = h
            hv = _gnu_hash(nb)
            word = bloom[(hv // bits) & (maskwords - 1)]
            if not ((word >> (hv % bits)) & (word >> ((hv >> shift2) % bits)) & 1):
                return None
            i = buckets[hv % nbucket]
            if i == 0:
                return None
            for _ in range(len(recs) + 1):
                if i < symndx or i >= len(recs):
                    return None
                c = struct.unpack_from(self._e + "I", self.data, coff + 4 * (i - symndx))[0]
                if ((c ^ hv) >> 1) == 0 and hit(i):
                    return recs[i]
                if c & 1:
                    return None
                i += 1
            return None
        _, nbucket, nchain, buckets, chains = h
        i = buckets[_sysv_hash(nb) % nbucket]
        # fix round 2 (the review's minor finding): a chain visits each symbol once, so a walk longer than the table is
        # a cycle (0.13 s a lookup at nchain 2,000,000; bionic would loop forever): nothing found
        for _ in range(min(nchain, len(recs)) + 1):
            if i == 0 or i >= nchain or i >= len(recs):
                return None
            if hit(i):
                return recs[i]
            i = chains[i]
        return None

    def _read(self):
        d = self.data
        if len(d) < 52 or d[:4] != b"\x7fELF" or d[4] not in (1, 2) or d[5] not in (1, 2):
            return                                   # no ELF header a loader reads: it exports nothing
        c64 = d[4] == 2
        if c64 and len(d) < 64:
            return
        e = self._e = "<" if d[5] == 1 else ">"
        self._elf = True
        self._elfclass = 2 if c64 else 1
        self._machine = struct.unpack_from(e + "H", d, 0x12)[0]
        if c64:
            phoff, shoff = struct.unpack_from(e + "QQ", d, 0x20)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", d, 0x36)
        else:
            phoff, shoff = struct.unpack_from(e + "II", d, 0x1C)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", d, 0x2A)
        loads, dyn, wx = [], None, False
        if phoff and phnum:
            if phentsize < (56 if c64 else 32):
                raise ValueError("program header size %d" % phentsize)
            for i in range(phnum):
                o = phoff + i * phentsize
                if c64:
                    p_type, p_flags, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(e + "IIQQQQ", d, o)
                else:
                    p_type, p_offset, p_vaddr, _, p_filesz, _, p_flags = struct.unpack_from(e + "IIIIIII", d, o)
                if p_type == 1:
                    loads.append((p_vaddr, p_offset, p_filesz, p_flags))
                    wx = wx or (p_flags & 3) == 3     # PF_W and PF_X: code the loader's relocations may patch
                elif p_type == 2:
                    if dyn is not None:
                        raise ValueError("two PT_DYNAMIC segments")
                    dyn = (p_offset, p_filesz)
        if wx:
            # fix round 2: a writable and executable PT_LOAD (bionic refuses one from targetSdk 26; below that, the
            # loader's relocations may patch the code in it): not loadable, as for text relocations below
            self._loadable = False
        secs = []
        if shoff and shnum:
            if shentsize < (64 if c64 else 40):
                raise ValueError("section header size %d" % shentsize)
            for i in range(shnum):
                o = shoff + i * shentsize
                if c64:
                    _, t, _, addr, off, size, link, _, _, ent = struct.unpack_from(e + "IIQQQQIIQQ", d, o)
                else:
                    _, t, _, addr, off, size, link, _, _, ent = struct.unpack_from(e + "IIIIIIIIII", d, o)
                secs.append((t, addr, off, size, link, ent))
        dynsyms = [i for i, s in enumerate(secs) if s[0] == 11]
        if not dynsyms:
            if dyn is not None:
                self._opaque = "a dynamic segment and no .dynsym section to read its exports from"
            return
        if len(dynsyms) > 1:
            self._opaque = "%d .dynsym sections" % len(dynsyms)
            return
        si = dynsyms[0]
        _, _, off, size, link, ent = secs[si]
        if link >= len(secs):
            self._opaque = "its .dynsym names no string table"
            return
        stroff = secs[link][2]
        ent = ent or (24 if c64 else 16)
        if ent < (24 if c64 else 16):
            raise ValueError("symbol entry size %d" % ent)
        n = size // ent
        if n > _SO_MAX_SYMS:
            self._opaque = "%d dynamic symbols" % n
            return

        def v2off(v):                                # _parse_so's own address mapping: a defn is its very bytes
            for (_t, a, o2, sz, _l, _e) in secs:
                if a and a <= v < a + sz:
                    return o2 + (v - a)
            return None

        recs = []
        kept = 0                                     # bytes of names and code copies held (final review of 476f452)
        budget = 4 * len(d) + (1 << 20)
        for k in range(n):
            p = off + k * ent
            if c64:
                st_name, info, _, shndx, value, ssize = struct.unpack_from(e + "IBBHQQ", d, p)
            else:
                st_name, value, ssize, info, _, shndx = struct.unpack_from(e + "IIIBBH", d, p)
            end = d.index(b"\x00", stroff + st_name)
            if end - (stroff + st_name) > _SO_NAME_MAX:
                self._opaque = "a dynamic symbol name of %d bytes" % (end - (stroff + st_name))
                return
            kept += end - (stroff + st_name)
            typ = info & 0xF
            defn = None
            if typ == 2 and ssize:
                # B-164: a FUNC of an EM_ARM body in the container an Android loader loads as armeabi(-v7a)
                # (ELFCLASS32, little-endian: bionic refuses any other for the 32-bit ARM ABI) gets one of the two
                # runnable sentinels. Its st_value bit 0 set means a Thumb (T32) function: the loader masks that
                # bit to reach the code and enters it in Thumb mode, so clear it before mapping the address and
                # route the body through the Unicorn T32 decoder (EM_ARM_THUMB) rather than A32 (EM_ARM_A32).
                # In any other container (ELF64, big-endian) the definition keeps the raw EM_ARM and its bytes
                # as `_parse_so` reads them: no loader loads it, and every gate declines the raw machine.
                arm32 = self._machine == EM_ARM and not c64 and e == "<"
                thumb = arm32 and bool(value & 1)
                vaddr = value & ~1 if thumb else value
                mach = (EM_ARM_THUMB if thumb else EM_ARM_A32) if arm32 else self._machine
                fo = v2off(vaddr)
                if fo is not None and loads:
                    # fix round 2: the bytes a device runs are the ones PT_LOAD maps at the address; every segment that
                    # maps the whole function must hold the bytes the section headers give (_parse_so's, the VM's), and
                    # be executable (code in a segment without PF_X faults on a device)
                    cover = [(o2 + (vaddr - va), fl) for va, o2, fs, fl in loads if va <= vaddr and vaddr + ssize <= va + fs]
                    if not cover or any(not fl & 1 or d[s:s + ssize] != d[fo:fo + ssize] for s, fl in cover):
                        fo = None
                if fo is not None:
                    defn = (mach, d[fo:fo + ssize])
                    kept += len(defn[1])
            if kept > budget:
                # crafted tables (many entries with long names or large repeated code copies) would hold memory as
                # entries x size: past the budget the body is not read, so every binding it would make declines
                self._opaque = "its dynamic symbols hold %d bytes of names and code (past %d)" % (kept, budget)
                return
            recs.append([d[stroff + st_name:end].decode("latin1"), info >> 4, typ, shndx, defn, False])
        self._recs = recs
        for i, r in enumerate(recs):
            if r[1] in _SO_EXPORT_BINDS and r[3] != 0:
                self._names.setdefault(r[0], []).append(i)
        gnu = [s for s in secs if s[0] == 0x6FFFFFF6 and s[4] == si]
        sysv = [s for s in secs if s[0] == 5 and s[4] == si]
        ver = [s for s in secs if s[0] == 0x6FFFFFFF and s[4] == si]
        if dyn is not None:
            # the loader reads the dynamic segment and never the section headers: they must name the same tables
            tags, width = {}, 16 if c64 else 8
            for k in range(min(dyn[1] // width, _SO_MAX_TABLE)):
                tag, val = struct.unpack_from(e + ("qQ" if c64 else "iI"), d, dyn[0] + k * width)
                if tag == 0:
                    break
                if tag in (4, 5, 6, 0x6FFFFEF5, 0x6FFFFFF0, 12, 25, 27, 22, 30):
                    if tag in tags:
                        raise ValueError("DT tag %#x twice" % tag)
                    tags[tag] = val
            # fix round 2 (the review's minor finding): DT_INIT, and DT_INIT_ARRAY with a size, are code the loader runs
            # before System.loadLibrary returns, as it runs JNI_OnLoad (bionic ignores DT_PREINIT_ARRAY in a library)
            if 12 in tags or (25 in tags and tags.get(27, 0) > 0):
                self._ctors = ("DT_INIT" if 12 in tags else "a DT_INIT_ARRAY of %d entries"
                               % (tags.get(27, 0) // (8 if c64 else 4)))
            # fix round 2 (F3's family: the bytes a device runs are the file's): text relocations (DT_TEXTREL, DF_TEXTREL),
            # which bionic refuses in a 64-bit library and which patch code at load: not loadable, so no binding stands
            # on this body (dlsym finds nothing in it)
            if 22 in tags or (tags.get(30, 0) & 4):
                self._loadable = False

            def at(tag):
                if tag not in tags:
                    return None
                return next((fo + (tags[tag] - va) for va, fo, fs, _fl in loads if va <= tags[tag] < va + fs), None)
            if at(6) is None or at(6) != off or at(5) != stroff:
                self._opaque = "its DT_SYMTAB and DT_STRTAB are not its .dynsym section and that section's strings"
                return
            if 0x6FFFFEF5 in tags:
                gnu, sysv = [s for s in gnu if s[2] == at(0x6FFFFEF5)], []
                if not gnu:
                    self._opaque = "its DT_GNU_HASH is no .gnu.hash section of its .dynsym"
                    return
            elif 4 in tags:
                gnu, sysv = [], [s for s in sysv if s[2] == at(4)]
                if not sysv:
                    self._opaque = "its DT_HASH is no .hash section of its .dynsym"
                    return
            else:
                gnu, sysv = [], []
                self._loadable = False                # bionic: "empty/missing DT_HASH/DT_GNU_HASH"
            if 0x6FFFFFF0 in tags:
                ver = [s for s in ver if s[2] == at(0x6FFFFFF0)]
                if not ver:
                    self._opaque = "its DT_VERSYM is no .gnu.version section of its .dynsym"
                    return
            else:
                ver = []
        if ver:
            for k in range(n):
                recs[k][5] = bool(struct.unpack_from(e + "H", d, ver[0][2] + 2 * k)[0] & 0x8000)
        if gnu:
            o = gnu[0][2]
            nbucket, symndx, maskwords, shift2 = struct.unpack_from(e + "IIII", d, o)
            if nbucket > _SO_MAX_TABLE or maskwords > _SO_MAX_TABLE:
                self._opaque = "a GNU hash table of %d buckets and %d bloom words" % (nbucket, maskwords)
                return
            if not nbucket or not maskwords or maskwords & (maskwords - 1):
                self._loadable = False                # bionic refuses it ("invalid maskwords"), or finds nothing
            else:
                w = 8 if c64 else 4
                bloom = struct.unpack_from(e + ("Q" if c64 else "I") * maskwords, d, o + 16)
                buckets = struct.unpack_from(e + "I" * nbucket, d, o + 16 + w * maskwords)
                self._hash = ("gnu", nbucket, symndx, maskwords, shift2, bloom, buckets,
                              o + 16 + w * maskwords + 4 * nbucket, w * 8)
        elif sysv:
            o = sysv[0][2]
            nbucket, nchain = struct.unpack_from(e + "II", d, o)
            if nbucket > _SO_MAX_TABLE or nchain > _SO_MAX_TABLE:
                self._opaque = "a SysV hash table of %d buckets and %d chain entries" % (nbucket, nchain)
                return
            if not nbucket:
                self._loadable = False
            else:
                self._hash = ("sysv", nbucket, nchain, struct.unpack_from(e + "I" * nbucket, d, o + 8),
                              struct.unpack_from(e + "I" * nchain, d, o + 8 + 4 * nbucket))


class _SoBodies(list):
    """The delivery's .so members in its order (bytes, as codes_in_dex_ex has always merged them), each distinct body
    read once (`distinct`, first seen first; `body(b)`): one parse feeds the merge, _so_ambiguous, _so_multi_arch and
    the export view (the review: round 2 parsed every body three times a call)."""

    def __init__(self, members=()):
        raw = []
        for sob in members or ():
            try:
                raw.append(bytes(sob))
            except Exception:
                continue                             # the merge loop skips such a member too
        list.__init__(self, raw)
        self.distinct, self._of = [], {}
        for b in raw:
            if b and b not in self._of:
                self._of[b] = _SoBody(b)
                self.distinct.append(self._of[b])

    def body(self, b):
        return self._of.get(b)


class _NativeTable(dict):
    """codes_in_dex_ex's merged symbol table ({symbol: (machine, code)}, as before) with what binding needs beside it:
    the delivery's export view (`so_view`), every decision _so_bind made over it (`bind_memo`) and its symbols by
    binding key (`bucket`), so neither VM._invoke nor _so_bind scans the whole table per call (the review: 0.84
    against 0.42 ms a native call at 5,000 symbols, 4.42 against 0.41 ms at 50,000)."""

    def __init__(self, *a, **k):
        dict.__init__(self, *a, **k)
        self.so_view = None
        self.bind_memo = {}
        self.dexes = None           # fix round 2: the delivery's parsed dexes, over which a native is resolved
        self._buckets = None
        self._at = -1

    def bucket(self, want):
        """The table's symbols, in its order, that can end in `want` ('_' + a method name): those of its binding key."""
        if self._buckets is None or self._at != len(self):
            got = {}
            for s in self:
                k = _bind_key(s)
                if k is not None:
                    got.setdefault(k, []).append(s)
            self._buckets, self._at = got, len(self)
        k = _bind_key(want)
        return self._buckets.get(k, ()) if k is not None else tuple(self)


class _SoView:
    """A delivery's .so bodies as its loader exports them (_SoBody), for _so_bind: exported(name) and found(name) as
    (body, entry) pairs over every ELF body, `opaque` (why a body cannot be read) and the JNI_OnLoad verdict."""

    def __init__(self, bodies):
        self._all = list(bodies)
        self._bodies = self._opaque = None
        self._onload = _UNSET

    @property
    def bodies(self):
        if self._bodies is None:
            self._bodies = [b for b in self._all if b.elf]
        return self._bodies

    @property
    def opaque(self):
        if self._opaque is None:
            self._opaque = [b.opaque for b in self.bodies if b.opaque]
        return self._opaque

    def exported(self, name):
        return [(b, r) for b in self.bodies for r in b.exported(name)]

    def exported_prefix(self, prefix):
        return [(b, r) for b in self.bodies for r in b.exported_prefix(prefix)]

    def found(self, name):
        return [(b, r) for b in self.bodies for r in (b.found(name),) if r is not None]

    def has_onload(self):
        return bool(self.exported("JNI_OnLoad"))

    def onload_why(self):
        """None when every JNI_OnLoad any body exports provably binds nothing (_onload_inert), else why not."""
        if self._onload is _UNSET:
            self._onload = next((why for _, r in self.exported("JNI_OnLoad") for why in (_onload_inert(r[4]),) if why),
                                None)
        return self._onload

    def ctor_why(self):
        """Why a body's loader runs constructors before any JNI call (fix round 2: DT_INIT, a DT_INIT_ARRAY), or None."""
        return next(("a library of the delivery has %s, code its loader runs before any JNI call (a constructor may "
                     "RegisterNatives as JNI_OnLoad does)" % b.ctors for b in self.bodies if b.ctors), None)


class _TableBody:
    """The one pseudo-body of a _TableView: 64-bit, as every table entry `_parse_so` read."""
    elfclass = 2


class _TableView(_SoView):
    """The view of a table with no delivery behind it (a VM built by hand, split_bundle's natives): every symbol of the
    table is exported and found under its own definition, as round 2 took them (an EM_MULTI symbol under each of its
    definitions, an EM_AMBIGUOUS one under none it could run)."""

    def __init__(self, table):
        _SoView.__init__(self, ())
        self._t = table
        self._b = _TableBody()

    def _recs(self, name):
        v = self._t.get(name)
        if not isinstance(v, tuple) or len(v) != 2:
            return []
        if v[0] == EM_MULTI:
            return [[name, 1, 2, 1, d, False] for d in v[1]]
        return [[name, 1, 2, 1, None if v[0] == EM_AMBIGUOUS else v, False]]

    def exported(self, name):
        return [(self._b, r) for r in self._recs(name)]

    def exported_prefix(self, prefix):
        return [(self._b, r) for nm in self._t if nm.startswith(prefix) for r in self._recs(nm)]

    def found(self, name):
        return self.exported(name)


def _view_of(native_syms):
    view = getattr(native_syms, "so_view", None)
    return view if view is not None else _TableView(native_syms)


_ONLOAD_MAX = 1024           # bytes of a JNI_OnLoad body _onload_inert reads (an inert one is a few instructions)


def _onload_inert(defn):
    """None when a JNI_OnLoad body provably binds nothing: with the JavaVM UNDEFINED (and the reserved argument
    NULL, as ART calls it), the hand-rolled reader runs it to its return (it declines on every read of the JavaVM or
    any other undefined register, and on every load, store, call or branch it does not model, so the body never
    looked at the JavaVM, touched no memory but its own stack and called nothing: no GetEnv, no RegisterNatives),
    the Unicorn engine (when present) gives the same value with the JavaVM poisoned two ways, and that value is a JNI
    version ART accepts (any other fails System.loadLibrary, and no method of the library binds at all). Else why
    not (so-ambig).

    Day 27 so-ambig fix round 2 (the review of 38a1668): the JavaVM was a defined 0, which a device never hands over,
    so `test rdi, rdi; je .ret` before GetEnv / FindClass / RegisterNatives(nativeShare -> a local function) took the
    null path in both emulators and passed as inert (the exported decoy then bound, plain), and so did `lea eax,
    [rdi+0x10006]`. A body past _ONLOAD_MAX bytes is not read (capstone keeps ~5 KB a decoded instruction: a 2 MiB
    nop sled took 10.8 s and 5.9 GB)."""
    if defn is None:
        return "a library exports JNI_OnLoad as a symbol whose code is not read here (not a sized FUNC)"
    m, code = defn
    if m not in (EM_X86_64, EM_AARCH64):
        return ("a library exports JNI_OnLoad for machine %s, whose JNI_OnLoad no reader here proves inert"
                % _em_text(m))
    if len(code) > _ONLOAD_MAX:
        return "a library's JNI_OnLoad of %d bytes is past the %d read here" % (len(code), _ONLOAD_MAX)
    try:
        v = (_emulate_x86(code, [None, 0]) if m == EM_X86_64 else _emulate_arm64(code, [None, 0])) & M64
    except Exception:
        return ("a library's JNI_OnLoad does not run to its return without reading the JavaVM it is handed or memory "
                "past its own stack (its RegisterNatives may bind any method to any function)")
    if native_emulate is not None and native_emulate.UNICORN_AVAILABLE:
        try:
            u = _unicorn_value(code, [None, 0], m)
        except Exception:
            u = None
        if u != v:
            return "the two emulators do not agree on a library's JNI_OnLoad"
    if (v & 0xFFFFFFFF) not in _JNI_VERSIONS:
        return ("a library's JNI_OnLoad returns %#x, no JNI version ART accepts (System.loadLibrary would fail)"
                % (v & 0xFFFFFFFF))
    return None


def _elf32_filter(pairs):
    """`pairs` less the 32-bit (ELF32) entries of every name some 64-bit body exports too, under SO_ELF32_LEGS
    'ignore' (one NOTE a name and process): a device of the 32-bit ABI runs a body this reading does not run beside
    the 64-bit one, as the base always let it (since B-164 an arm32 body CAN be run, but only for a name no 64-bit
    body exports: beside a 64-bit binding it is still not run, nor compared). A name only 32-bit bodies export keeps
    its entries. Under 'decline' every entry stays."""
    if SO_ELF32_LEGS != "ignore":
        return pairs
    wide = {r[0] for b, r in pairs if b.elfclass == 2}
    keep = [(b, r) for b, r in pairs if not (b.elfclass == 1 and r[0] in wide)]
    if len(keep) != len(pairs):
        for nm in sorted({r[0] for b, r in pairs if b.elfclass == 1 and r[0] in wide} - _SO_ELF32_SAID):
            _SO_ELF32_SAID.add(nm)
            print("NOTE mobile dex_chain_codec: %s is also exported by a 32-bit (ELF32) library of the delivery, whose "
                  "code is not run beside a 64-bit one: the 64-bit binding answers (so-ambig; SO_ELF32_LEGS='ignore', "
                  "and 'decline' would withhold it)" % nm, file=sys.stderr)
    return keep


def _so_entry(b, r):
    """An export entry in words, for a decline's text."""
    if r[4] is None:
        return "%s as a %s symbol of %s whose code is not read here" % (
            r[0], {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 6: "TLS", 10: "IFUNC"}.get(r[2], "type-%d" % r[2]),
            "an ELF32 body" if b.elfclass == 1 else "its body")
    return "%s with other code (machine %s%s)" % (r[0], _em_text(r[4][0]), ", ELF32" if b.elfclass == 1 else "")


def _so_ambiguous(so_members):
    """The symbols whose native binding would depend on the ORDER of the delivery's .so bodies.

    codes_in_dex_ex merges every .so member into one map (a later body replaces an earlier body's symbol of the same
    name) and VM._invoke binds a method to the FIRST symbol of it that ends in '_' + the method's name. With two
    different libraries in one delivery (two splits of an .apks, the base and a split, two libraries of a package)
    a plain code came from whichever body the delivery lists last or first, and nothing in the bytes says which
    library the runtime loads (Day 27 look-ahead x17, x17b, x17c). A symbol is ambiguous when two DIFFERENT bodies
    OF ONE MACHINE give its binding key (_bind_key) two different definitions ((machine, code bytes), as _parse_so
    returns them): the same symbol, or two different symbols. Not ambiguous: a body repeated byte for byte, the same
    definition in two bodies, and the symbols of one library among themselves (as before), nor anything two bodies of
    two machines define (fix round 1, the review's minor finding: lib/x86_64 beside lib/arm64-v8a, each with a decoy
    class's symbol beside the method's own, made a normal two-ABI app ambiguous whole; a device of each ABI loads the
    library of its own ABI, so one symbol of two machines is _so_multi_arch's, every body run and all agreeing, and two
    symbols of two machines are _so_bind's, which binds the method's exact JNI name only). codes_in_dex_ex gives an
    ambiguous symbol the machine EM_AMBIGUOUS, so a VM call bound to it declines and the reading is unsure or None,
    never plain. Restrict-only: one library, or one repeated, gives the empty set (exactly as before). Bounded by the
    symbol tables, never by a clock: a key with more than SO_AMBIG_GROUP definitions over two or more bodies is
    ambiguous whole. No load call of the dex resolves a conflict: the x17 libraries share their path and name, and a
    System.loadLibrary string does not prove the binding (DT_NEEDED, System.load, RegisterNatives). A _SoBodies hands
    over the tables it read; any other list of bodies is read here."""
    if isinstance(so_members, _SoBodies):
        tables = [b.funcs for b in so_members.distinct]
    else:
        seen, tables = [], []
        for sob in so_members or ():
            try:
                b = bytes(sob)
            except Exception:
                continue                              # the merge loop skips such a member too
            if b and not any(len(b) == len(x) and b == x for x in seen):
                seen.append(b)
                tables.append(_parse_so(b))
    if len(tables) < 2:
        return set()
    out = set()
    try:
        groups = {}
        for i, t in enumerate(tables):
            for sym, val in t.items():
                k = _bind_key(sym)
                if k is not None:
                    groups.setdefault(k, []).append((i, sym, val))
        for ents in groups.values():
            if len({e[0] for e in ents}) < 2:
                continue                              # one library's own symbols: as before
            if len(ents) > SO_AMBIG_GROUP:
                out.update(e[1] for e in ents)
                continue
            # an entry is in a conflict when ANOTHER body of its machine gives the key another definition (every
            # pair, counted by body: the review's 1,000 keys of 64 entries took 0.387 s pair by pair)
            per = {}
            for i, s, v in ents:
                per.setdefault(v[0], {}).setdefault(i, set()).add(v)
            for i, s, v in ents:
                if any(j != i and (len(vs) > 1 or v not in vs) for j, vs in per[v[0]].items()):
                    out.add(s)
    except Exception:
        out = {s for t in tables for s in t}          # never expected: fail closed
    if out:
        said = (frozenset(out), len(tables))
        if said not in _SO_AMBIG_SAID:
            _SO_AMBIG_SAID.add(said)
            print("NOTE mobile dex_chain_codec: %d native symbol(s) defined differently by %d .so bodies of the "
                  "delivery are ambiguous; a call bound to one declines (so-ambig): %s"
                  % (len(out), len(tables), ", ".join(sorted(out))[:300]), file=sys.stderr)
    return out


# Day 27 (so-ambig, round 2): what ONE library, or two architectures of one symbol, left to the order of a table.
EM_MULTI = -2                # one symbol, a body for each of several machines: every body runs and all must agree
ACC_NATIVE = 0x100           # access_flags of an encoded method declared `native`
_JNI_ESCAPES = {"/": "_", ".": "_", "_": "_1", ";": "_2", "[": "_3"}


def _jni_mangle(text):
    """The JNI escape of a class name, a method name or a parameter descriptor (the JNI specification's "Resolving
    Native Method Names"; ART's MangleForJni): ASCII letters and digits stand, '/' and '.' are '_', '_' is '_1',
    ';' is '_2', '[' is '_3', and every other UTF-16 unit is '_0' and four lower-case hex digits."""
    out = []
    for ch in text:
        if ch.isascii() and ch.isalnum():
            out.append(ch)
        elif ch in _JNI_ESCAPES:
            out.append(_JNI_ESCAPES[ch])
        else:
            units = ch.encode("utf-16-be")
            out.extend("_0%04x" % int.from_bytes(units[k:k + 2], "big") for k in range(0, len(units), 2))
    return "".join(out)


def _meth_params(dex, midx):
    """The parameter type descriptors of method_ids[midx] (its proto's type_list), or None when they do not read."""
    try:
        if not dex.proto_off or not dex.proto_size:
            return None
        proto_idx = dex._u2(dex.meth_off + midx * 8 + 2)
        if proto_idx >= dex.proto_size:
            return None
        poff = dex._u4(dex.proto_off + proto_idx * 12 + 8)
        if not poff:
            return []
        n = dex._u4(poff)
        if n > 255:
            return None
        return [dex.type_str(dex._u2(poff + 4 + 2 * k)) for k in range(n)]
    except Exception:
        return None


def _jni_names(dex, midx, cls, name):
    """(short, long): the names ART looks a native method up by, the short first (Java_<class>_<method>) and then
    the long (the short + '__' + its parameter descriptors), every part escaped (_jni_mangle). long is None when the
    parameters do not read; both are None for a class that is no 'L...;' descriptor or an empty name."""
    if not (isinstance(cls, str) and len(cls) > 2 and cls[0] == "L" and cls[-1] == ";" and isinstance(name, str)
            and name):
        return None, None
    short = "Java_" + _jni_mangle(cls[1:-1]) + "_" + _jni_mangle(name)
    params = _meth_params(dex, midx)
    return short, (None if params is None else short + "__" + _jni_mangle("".join(params)))


def _native_decls(dex):
    """The method indexes this dex's class data declares `native` (ACC_NATIVE), read once per Dex. A method so
    declared is its method id's class's own (the dex format lists a class's methods in its own class data), so
    its JNI name is that class's. A table that does not read gives none."""
    got = getattr(dex, "_so_native_decls", None)
    if got is not None:
        return got
    out = set()
    try:
        for c in range(dex.cls_size):
            p = dex._u4(dex.cls_off + c * 32 + 24)
            if not p:
                continue
            counts = []
            for _ in range(4):
                n, p = dex._uleb(p)
                counts.append(n)
            for _ in range(2 * (counts[0] + counts[1])):
                _, p = dex._uleb(p)
            for n in counts[2:]:
                mi = 0
                for _ in range(n):
                    di, p = dex._uleb(p)
                    flags, p = dex._uleb(p)
                    _, p = dex._uleb(p)
                    mi += di
                    if flags & ACC_NATIVE:
                        out.add(mi)
    except Exception:
        out = set()
    try:
        dex._so_native_decls = out
    except Exception:
        pass
    return out


# Day 27 so-ambig fix round 2 (the review of 38a1668, F5): `declared` and the exact names came from the method id alone,
# so a subclass-qualified reference (Lcom/x/Sub;->nativeShare, declared native in its superclass Native) was "not
# declared", its names were Sub's, and the loose rule's decoy bound; multidex alike (a method with a Java body in
# classes2.dex bound to a decoy symbol). ART resolves a method through its class's superclass chain, over every dex of
# the app, and binds the DECLARING class's exact JNI name; a boot class's method is never one of the app's natives.
_BOOT_PREFIXES = ("Ljava/", "Ljavax/", "Landroid/", "Ldalvik/", "Llibcore/", "Lsun/", "Lorg/json/", "Lorg/w3c/",
                  "Lorg/xml/", "Lorg/xmlpull/", "[")


def _boot_class(cls):
    """True for a class of the device's boot class path (java.*, javax.*, android.*, dalvik.*, ...; an array): ART
    resolves it there before any dex of the app, and its methods are never JNI functions of the app's library."""
    return isinstance(cls, str) and cls.startswith(_BOOT_PREFIXES)


def _dex_classes(dex):
    """{class descriptor: superclass descriptor or None} of this dex's class_defs (the first definition of a name),
    read once per Dex; None for a dex with no class table to read (a hand-built one); {} when it does not read."""
    got = getattr(dex, "_so_classes", _UNSET)
    if got is not _UNSET:
        return got
    out = None
    if all(hasattr(dex, a) for a in ("cls_size", "cls_off", "_u4", "type_str")):
        out = {}
        try:
            for c in range(dex.cls_size):
                o = dex.cls_off + c * 32
                sup = dex._u4(o + 8)
                out.setdefault(dex.type_str(dex._u4(o)), None if sup == 0xFFFFFFFF else dex.type_str(sup))
        except Exception:
            out = {}
    try:
        dex._so_classes = out
    except Exception:
        pass
    return out


def _meth_sig(dex, midx):
    """(parameter descriptors, return descriptor) of method_ids[midx], or None when its prototype does not read; kept
    per Dex in `_so_sigs` (which a hand-built dex may carry, as it may carry `_so_native_decls`)."""
    sigs = getattr(dex, "_so_sigs", None)
    if sigs is None:
        sigs = {}
        try:
            dex._so_sigs = sigs
        except Exception:
            pass
    if midx in sigs:
        return sigs[midx]
    got = None
    try:
        params = _meth_params(dex, midx)
        if params is not None:
            proto_idx = dex._u2(dex.meth_off + midx * 8 + 2)
            got = tuple(params), dex.type_str(dex._u4(dex.proto_off + proto_idx * 12 + 4))
    except Exception:
        got = None
    sigs[midx] = got
    return got


def _meth_index(dex):
    """{(class, name): [method index, ...]} of this dex's method_ids, built once per Dex ({} when it does not read);
    the prototypes are read only for the methods a resolution asks about (_meth_find)."""
    got = getattr(dex, "_so_meth_index", None)
    if got is not None:
        return got
    out = {}
    try:
        for mi in range(dex.meth_size):
            out.setdefault(dex.meth(mi), []).append(mi)
    except Exception:
        out = {}
    try:
        dex._so_meth_index = out
    except Exception:
        pass
    return out


def _meth_find(dex, cls, name, sig):
    """The method index of (cls, name) with prototype `sig` among this dex's method_ids, or None."""
    return next((m for m in _meth_index(dex).get((cls, name), ()) if _meth_sig(dex, m) == sig), None)


def _meth_flags(dex):
    """{method index: access_flags} of every method this dex's class data declares (direct and virtual), read once
    per Dex ({} when it does not read)."""
    got = getattr(dex, "_so_meth_flags", None)
    if got is not None:
        return got
    out = {}
    try:
        for c in range(dex.cls_size):
            p = dex._u4(dex.cls_off + c * 32 + 24)
            if not p:
                continue
            counts = []
            for _ in range(4):
                n, p = dex._uleb(p)
                counts.append(n)
            for _ in range(2 * (counts[0] + counts[1])):
                _, p = dex._uleb(p)
            for n in counts[2:]:
                mi = 0
                for _ in range(n):
                    di, p = dex._uleb(p)
                    flags, p = dex._uleb(p)
                    _, p = dex._uleb(p)
                    mi += di
                    out.setdefault(mi, flags)
    except Exception:
        out = {}
    try:
        dex._so_meth_flags = out
    except Exception:
        pass
    return out


def _resolve_native(dexes, dex, midx, cls, name):
    """How ART resolves method_ids[midx] of `dex` (class `cls`, `name`, its prototype) over the app's dexes (`dex`
    first, then `dexes`), class by class up the superclass chain:
      ("native", dex, method index, class)  a declaration `native` of cls or a superclass (its exact JNI names bind)
      ("app", why)                          cls is the app's, and nothing native resolves it: a declaration with a Java
                                            body or abstract, a superclass no dex of the delivery defines, a loop
      ("outside", None)                     no dex of the delivery defines cls
      None                                  not known (a dex with no class table: a hand-built one)"""
    tables = [(d, _dex_classes(d)) for d in [dex] + [d for d in dexes or () if d is not dex]]
    if tables[0][1] is None:
        return None
    sig = _meth_sig(dex, midx)
    if sig is None:
        return ("app", "its prototype does not read")
    c, seen = cls, set()
    while True:
        if c in seen or len(seen) >= 64:
            return ("app", "its class hierarchy loops or runs past 64 classes")
        seen.add(c)
        owners = [] if _boot_class(c) else [(d, t) for d, t in tables if t is not None and c in t]
        if not owners:
            if c == cls:
                return ("outside", None)
            return ("app", "it would be inherited from %s, which no dex of the delivery defines" % c)
        found = []
        for d, t in owners:
            m = _meth_find(d, c, name, sig)
            f = _meth_flags(d).get(m) if m is not None else None
            found.append((d, m, None if f is None else bool(f & ACC_NATIVE), t.get(c)))
        if len({(x[2], x[3]) for x in found}) > 1:
            # two dexes of the delivery define the class apart (which one a device loads is the class path's order)
            return ("app", "%d dexes of the delivery define %s differently" % (len(found), c))
        d, m, native, sup = found[0]
        if native is not None:
            if native:
                return ("native", d, m, c)
            return ("app", "%s declares it with a Java body or abstract, not native" % c)
        c = sup
        if c is None:
            return ("app", "no class of its hierarchy declares it")


def _exact_named(native_syms, short, long_):
    """The symbols of the table that carry a method's exact JNI name (_jni_names): its short name, and its long name
    (with parameters that did not read, `long_` None, any `<short>__...` form)."""
    if short is None:
        return []
    if long_ is not None:
        return [s for s in (short, long_) if s in native_syms]
    return [s for s in native_syms if s == short or s.startswith(short + "__")]


def _so_cands(native_syms, cls, name):
    """Every symbol of the table, in its order, that VM._invoke's loose rule binds the method (cls, name) to: one
    ending in '_' + its name, of a class whose name says native, or itself saying jni or starting Java_."""
    want = "_" + name
    native = "native" in cls.lower()
    pool = native_syms.bucket(want) if isinstance(native_syms, _NativeTable) else native_syms
    return [s for s in pool if s.endswith(want) and (native or "jni" in s.lower() or s.startswith("Java_"))]


def _so_first(native_syms, cls, name):
    """The first of _so_cands (the symbol VM._invoke's loop met first, before round 2), or None."""
    want = "_" + name
    native = "native" in cls.lower()
    pool = native_syms.bucket(want) if isinstance(native_syms, _NativeTable) else native_syms
    return next((s for s in pool if s.endswith(want) and (native or "jni" in s.lower() or s.startswith("Java_"))),
                None)


def _so_bind(native_syms, dex, midx, cls, name, first):
    """(symbol, machine, code) VM._invoke binds the method (cls, name) to, given `first`, the symbol its loose rule
    meets first (a name ending in '_' + the method's name), or a decline (so-ambig): a device's binding, or nothing.

    Round 2 (6f0ed2a), unchanged: when every symbol the loose rule matches holds the same definition, `first`, unless
    this dex declares the method `native` and a symbol of the table carrying its EXACT JNI name (_jni_names: its long
    form, or a short name with escapes, neither of which the loose rule matches) defines it otherwise; when they hold
    two or more, only its exact name binds it, and only when this dex declares the method native, no candidate is
    round 1's ambiguous, the table holds no JNI_OnLoad, exactly one symbol of the table carries the short or long name
    and the loose rule matches it.

    Fix round 1 (the review of 6f0ed2a): round 2 read `_parse_so`'s table, which keeps LOCAL .symtab statics and drops
    NOTYPE, size-0, IFUNC and ELF32 exports, so its exact binding sent codes no device computes (Q1 to Q3, P1 to P3).
    ART binds a native method by its exact name through dlsym (the short name, then the long, library by library),
    after each library's JNI_OnLoad, whose RegisterNatives may bind it to any function; dlsym returns only a defined
    GLOBAL or WEAK entry of a library's dynamic symbol table, of any type or size. So the binding round 2 makes stands
    only when, over the delivery's export view (_so_device; _SoView, or for a table with no delivery behind it the
    table itself, _TableView):
      0  every .so body reads as its loader reads it (an opaque body declines every binding);
      1  no body exports JNI_OnLoad (any type, size or class), or, with one definition among the candidates, every
         such JNI_OnLoad provably binds nothing (_onload_inert: the JavaVM undefined since fix round 2); and (fix round
         2, SO_CTORS) no body has DT_INIT or a non-empty DT_INIT_ARRAY, constructors that may bind natives as well;
      2  every entry any body exports under the chosen symbol's name or under the method's exact names (short and
         long, from the method id, for a method this dex does not declare too: its class may be defined in another
         dex) holds the definition that runs (EM_MULTI: one of its definitions): a NOTYPE, size-0, IFUNC or OBJECT
         export, a 32-bit one (but see SO_ELF32_LEGS), another class's code or another body's declines (P1, P3, a
         .symtab static shadowing an export);
      3  dlsym returns the chosen symbol itself, with that definition, from some body (a LOCAL or .symtab-only symbol,
         a hidden version, one its hash table does not reach: Q1, P2);
      4  for a method this dex declares native, dlsym returns one of its exact names from some body (else ART throws
         UnsatisfiedLinkError on every device, and the loose rule's code is no device's).
    Each rule only withholds: this binds exactly where round 2 bound, or declines. One decision per (dex, method,
    first) and table (`bind_memo`), so a loop's calls cost one dict lookup.

    Fix round 2 (the review of 38a1668, F5): a method this dex does not declare native is resolved as ART resolves it
    (_resolve_native: up its class's superclass chain, over every dex of the delivery, `native_syms.dexes`): a native
    declaration of the class or a superclass makes it declared under THAT class's exact JNI names (rules 2 and 4 then
    hold them); a class of the app with no native declaration on its chain (a Java body, an abstract method, a
    superclass outside the delivery) declines; a class no dex of the delivery defines (or a hand-built dex) binds only
    by its own exact JNI name, never by the loose rule's other symbol. The memo is keyed by the dex too: split_bundle's
    tables are shared by every VM of a bundle, whose dexes number their methods apart."""
    memo = native_syms.bind_memo if isinstance(native_syms, _NativeTable) else None
    key = (id(dex), midx, cls, name, first)
    if memo is not None and key in memo:
        got = memo[key]
        if isinstance(got, str):
            raise _Decline(got)
        return got
    try:
        got = _so_bind_now(native_syms, dex, midx, cls, name, first)
    except _Decline as e:
        if memo is not None:
            memo[key] = str(e)
        raise
    if memo is not None:
        memo[key] = got
    return got


def _so_bind_now(native_syms, dex, midx, cls, name, first):
    """_so_bind without its memo."""
    cands = _so_cands(native_syms, cls, name)
    defs = []
    for s in cands:
        if native_syms[s] not in defs:
            defs.append(native_syms[s])
    short, long_ = _jni_names(dex, midx, cls, name)
    declared = midx in _native_decls(dex)
    exact_only = False
    if not declared:
        # fix round 2 (F5): resolved as ART resolves it, over the delivery's dexes
        res = _resolve_native(getattr(native_syms, "dexes", None), dex, midx, cls, name)
        if res is None or res[0] == "outside":
            exact_only = True
        elif res[0] == "native":
            declared = True
            short, long_ = _jni_names(res[1], res[2], res[3], name)
        else:
            raise _Decline("native %s: this dex does not declare it native, and %s (so-ambig)" % (name, res[1]))
    if len(defs) <= 1:
        if declared:
            other = [s for s in _exact_named(native_syms, short, long_) if native_syms[s] != native_syms[first]]
            if other:
                raise _Decline("native %s: the loose rule binds %s, and %s, its exact JNI name, defines it otherwise "
                               "(so-ambig)" % (name, first, other[0]))
        elif exact_only and first not in _exact_named(native_syms, short, long_):
            raise _Decline("native %s: no dex of the delivery declares it native, and the loose rule's %s is not its "
                           "exact JNI name %s (its declaring class may be another, so-ambig)" % (name, first, short))
        chosen = first
    else:
        why = None
        if short is None:
            why = "its class is no type descriptor"
        elif any(native_syms[s][0] == EM_AMBIGUOUS for s in cands):
            # round 1 found two libraries defining this method's symbols differently: which library loads is not in
            # the bytes, and a library without the exact name leaves the method unbound on a device (x17's principle)
            why = "two libraries of the delivery define its symbols differently"
        elif "JNI_OnLoad" in native_syms:
            why = "a library defines JNI_OnLoad, whose RegisterNatives may bind it"
        elif not declared:
            why = "this dex does not declare it native"
        else:
            exact = _exact_named(native_syms, short, long_)
            if len(exact) == 1 and exact[0] in cands:
                chosen = exact[0]
            else:
                why = "%d symbol(s) carry its exact JNI name %s" % (len(exact), short)
        if why:
            raise _Decline("native %s: %d symbols the loose rule binds define it %d ways, and %s (so-ambig)"
                           % (name, len(cands), len(defs), why))
    run = native_syms[chosen]
    if run[0] == EM_AMBIGUOUS:
        return chosen, run[0], run[1]                 # round 1's mark: VM._invoke declines it, as before
    why = _so_device(_view_of(native_syms), chosen, run, short, long_, declared, len(defs))
    if why:
        raise _Decline("native %s: %s (so-ambig)" % (name, why))
    return chosen, run[0], run[1]


def _so_device(view, chosen, run, short, long_, declared, ndefs):
    """Why a device's loader would not run `run` (native_syms[chosen]) for the method, or None: rules 0 to 4 of
    _so_bind over the export view."""
    if view.opaque:
        return ("a .so body of the delivery does not read as its loader reads it (%s), so what it exports is not known"
                % view.opaque[0])
    if view.has_onload():
        if ndefs > 1:
            return "a library exports JNI_OnLoad, whose RegisterNatives may bind it to any function"
        why = view.onload_why()
        if why:
            return why
    if SO_CTORS == "decline":
        why = view.ctor_why()
        if why:
            return why
    allowed = set(run[1]) if run[0] == EM_MULTI else {run}
    pairs, seen = [], set()
    names = [chosen]
    if short is not None:
        names.append(short)
        if long_ is not None:
            names.append(long_)
    for nm in names:
        for b, r in view.exported(nm):
            if id(r) not in seen:
                seen.add(id(r))
                pairs.append((b, r))
    if short is not None and long_ is None:
        for b, r in view.exported_prefix(short + "__"):
            if id(r) not in seen:
                seen.add(id(r))
                pairs.append((b, r))
    for b, r in _elf32_filter(pairs):
        if r[4] not in allowed:
            return "the loose rule binds %s, and a library of the delivery exports %s" % (chosen, _so_entry(b, r))
    if not any(r[4] in allowed for _, r in view.found(chosen)):
        return ("%s is not what dlsym returns from any library of the delivery (a LOCAL or .symtab-only symbol, a "
                "hidden version, or one its hash table does not reach)" % chosen)
    if declared and short is not None:
        dev = view.found(short) + (view.found(long_) if long_ is not None else [])
        if not any(r[4] in allowed for _, r in dev):
            return ("no library's dlsym returns its exact JNI name %s, so a device throws UnsatisfiedLinkError and "
                    "runs no library code for it" % short)
    return None


def _so_verdict(vm, midx):
    """so-ambig's reading of a call of method_ids[midx] (a method without dex code) over the delivery's WHOLE native
    table, for the KB-2 bridge (native_image_bridge.invoke). The bridge reads a native its own way (the exact JNI name or
    a RegisterNatives binding, library by library, in the whole image); since the KB-2 port onto so-ambig its reading
    stands only where these rules bind the call too, and a call these rules decline declines:
      None                these rules bind no native for it: a boot class's method (java.*, android.*, ...: ART never
                          lets an app class there be one of the app's natives), or no symbol the loose rule matches (a
                          native exported under its long name only, or bound by RegisterNatives alone)
      ("bind", allowed)   they bind it: `allowed` the (machine, code) definitions that run (every architecture's of an
                          EM_MULTI symbol)
      ("hard", why)       they decline it: two .so bodies of one machine (EM_AMBIGUOUS, x17), an exact-name conflict, a
                          method no dex declares native, an export no loader returns (LOCAL, hidden, unreached, NOTYPE,
                          IFUNC, text relocations), an opaque body, a JNI_OnLoad not proven inert, DT_INIT /
                          DT_INIT_ARRAY, a machine no emulator models
    The table is the one codes_in_dex_ex built (VM._so_full), not vm.native_syms, which the bridge narrows to one
    entry (or none) while it asks the shipped reader about one body."""
    table = getattr(vm, "_so_full", None)
    if table is None:
        table = vm.native_syms
    if not table or not isinstance(table, dict):
        return None
    dex = vm.dex
    try:
        cls, name = dex.mname.get(midx) or dex.meth(midx)
    except Exception:
        return ("hard", "the method reference does not read")
    if _boot_class(cls):
        return None
    try:
        first = _so_first(table, cls, name)
    except Exception as e:
        return ("hard", "the loose rule does not read (%s)" % type(e).__name__)
    if first is None:
        return None
    try:
        sym, emach, codeb = _so_bind(table, dex, midx, cls, name, first)
    except _Decline as e:
        return ("hard", str(e))
    except Exception as e:                       # never expected: no binding is proven
        return ("hard", "the so-ambig binding raised %s" % type(e).__name__)
    if emach not in _EM_RUNNABLE + (EM_MULTI,):   # B-164 added the two vetted 32-bit ARM modes (never the raw EM_ARM)
        return ("hard", "native %s: %s binds a machine-%d body no emulator here models (EM_AMBIGUOUS: two .so bodies "
                        "of one machine define it, so-ambig)" % (name, sym, emach))
    return ("bind", frozenset(codeb) if emach == EM_MULTI else frozenset([(emach, codeb)]))


def _so_multi_arch(so_members):
    """{symbol: ((machine, code), ...)}: each symbol the delivery's .so bodies define for two or more machines.

    _so_ambiguous leaves one symbol in two architectures alone (lib/x86_64 beside lib/arm64-v8a, the normal case),
    and codes_in_dex_ex merged the bodies by name, so the body listed LAST answered: two architectures whose bodies
    compute differently gave a code that hung on the order, though a device runs the one of its own ABI (Day 27
    look-ahead, round 1's residual shape). Such a symbol gets the machine EM_MULTI and every definition (sorted, so
    the order of the bodies changes nothing), and VM._invoke runs each (_native_multi): the call answers only when
    every body is of a modelled machine and all run to one value. A symbol of one machine is not here; two bodies
    of one machine that differ are _so_ambiguous's (codes_in_dex_ex keeps that mark). A _SoBodies hands over the
    tables it read; any other list of bodies is read here."""
    if isinstance(so_members, _SoBodies):
        tables = [b.funcs for b in so_members.distinct]
    else:
        tables = []
        for sob in so_members or ():
            try:
                tables.append(_parse_so(bytes(sob)))
            except Exception:
                continue
    defs = {}
    for got in tables:
        for sym, val in got.items():
            seen = defs.setdefault(sym, [])
            if val not in seen:
                seen.append(val)
    return {s: tuple(sorted(v)) for s, v in defs.items() if len({d[0] for d in v}) > 1}


def _native_multi(defs, int_args):
    """The value of a symbol with a body for each of several machines (EM_MULTI): every body runs (_native_dispatch,
    the x86-64 gate-fail sentinel 0 declining as for one body) and all must give the same 64-bit value. A body of a
    machine no emulator models, a body that declines, or two values: a decline (so-ambig), since the bytes do not
    say which architecture's device the answer is computed on."""
    vals = []
    for emach, codeb in defs:
        if emach not in (EM_X86_64, EM_AARCH64):
            raise _Decline("native e_machine %d not modelled (one of %d architectures, so-ambig)" % (emach, len(defs)))
        v = _native_dispatch(codeb, int_args, emach) & M64
        if emach == EM_X86_64 and v == 0:
            raise _Decline("x86 native returned the denied sentinel 0 (gate-fail)")
        vals.append(v)
    if len(set(vals)) != 1:
        raise _Decline("native architectures compute differently: %s (so-ambig)"
                       % ", ".join("%d=%#x" % (m, v) for (m, _), v in zip(defs, vals)))
    return vals[0]


def _entry_midxs(dex, ans_idx):
    """Every method whose bytecode loads the "ANS-" string literal (const-string[/jumbo]).

    `ans_idx` is one string index or a set of them (Day 24 look-ahead: also the split prefix "ANS" and a
    short "ANS-..." format literal; a code is still only accepted when it fullmatches ANS-[0-9A-F]{16})."""
    idxs = {ans_idx} if isinstance(ans_idx, int) else set(ans_idx)
    out = []
    for midx, (regs, ins_size, insns) in dex.code.items():
        i = 0
        n = len(insns)
        while i < n:
            op = insns[i] & 0xFF
            if op == 0x1a and insns[i + 1] in idxs:
                out.append(midx)
                break
            if op == 0x1b and (insns[i + 1] | (insns[i + 2] << 16)) in idxs:
                out.append(midx)
                break
            w = _W[op]
            if w <= 0 or i + w > n:
                break
            i += w
    return out


_RUN_EPOCH = 0


def _bump_run():
    """Count one more run of the chain (it notes codes into the whole-image bridge): see AnalysisRun."""
    global _RUN_EPOCH
    _RUN_EPOCH += 1


def _fold_arm32(native_syms, bodies):
    """B-164: fold the 32-bit ARM exports of the delivery's ELF32 bodies into codes_in_dex_ex's flat symbol table.

    `body.funcs` (via _parse_so) reads ELF64 only, so an armeabi-v7a (ELF32) FUNC never entered the table,
    _so_first could not find it, and an arm32-only native declined unresolved. Each sized FUNC of an ELF32 EM_ARM
    body is added under its name with the definition `_SoBody._read` gave it:
      * only an entry a loader could return: bound GLOBAL, WEAK or GNU_UNIQUE (_SO_EXPORT_BINDS) and defined
        (st_shndx not 0). A LOCAL static or an undefined reference of the same name is no binding of the method,
        and would shadow the real export that follows it in the table;
      * only under a name the table does not hold yet, so a name a 64-bit body also exports keeps its 64-bit
        binding (as _elf32_filter('ignore') does), and of two arm32 bodies the first in delivery order is the
        table's (when the two differ, _so_device's rule 2 declines the binding whichever came first);
      * a little-endian body's definition is one of the runnable sentinels (EM_ARM_A32 / EM_ARM_THUMB); a
        big-endian one keeps the raw EM_ARM, which VM._invoke declines by name (no Android loader loads it), so
        the decline says why instead of the call reading as no native at all.
    Called after every 64-bit body is merged and before _so_ambiguous / _so_multi_arch mark the table."""
    for sob in bodies:
        body = bodies.body(sob)
        if body is None or body.elfclass != 1:       # an ELF64 body is _parse_so's to read, raw machine and all
            continue
        for r in body.recs:
            defn = r[4]
            if (defn and (defn[0] in _EM_ARM32 or defn[0] == EM_ARM) and r[1] in _SO_EXPORT_BINDS and r[3] != 0
                    and r[0] not in native_syms):
                native_syms[r[0]] = defn


def _note_entry(trace, dex, entry, outcome, reason="", vm=None, code=None):
    """B-229: one entry method's outcome into a caller's trace list (see codes_in_dex_ex's `_trace`). Never raises:
    a trace is a report for the person or agent reading a decline, and must not change what the chain returns."""
    if trace is None:
        return
    try:
        cls, name = dex.mname.get(entry) or dex.meth(entry)
        where = "%s->%s" % (cls, name)
    except Exception:
        where = "method#%d" % entry
    trace.append({"entry": where, "outcome": outcome, "reason": str(reason)[:300], "code": code,
                  "steps": getattr(vm, "steps", 0) if vm is not None else 0,
                  "loaded_inmemory": bool(getattr(vm, "loaded_inmemory", False)) if vm is not None else False})


def codes_in_dex_ex(dex_data, so_members=(), _feats=None, _ext=None, _dexes=None, package=None, members=None,
                    _trace=None):
    """(codes, declines): every DISTINCT valid ANS code the dex produces, by running each method that
    references the "ANS-" literal with a null argument frame, and the number of ANS-referencing methods
    that could NOT be read to a result (an unimplemented opcode, an exception, the per-method or the
    cumulative step budget, or entries cut off by MAX_ENTRIES). A decline means a real chain may have been
    missed, so a lone code beside a decline is not proven (answer() makes it unsure). Discovery order kept;
    at most MAX_CODES. ([], 0) on any structural failure -- never a partial or made-up value.

    `dex_data` is the dex's bytes or a parsed Dex; `_dexes` the delivery's other parsed dexes (analysis_codes_ex),
    over which a native method this dex does not declare is resolved (_resolve_native; Day 27 so-ambig fix round 2).

    `_trace` (B-229): a list that receives one dict per ANS-referencing method (entry, outcome code / decline /
    no-code / skipped, the decline's reason, steps, whether a dex was loaded in memory), so a decline names the
    call or opcode the VM did not model. It never changes the codes or the declines returned."""
    _bump_run()   # Day 30 fold: this run notes codes into the whole-image bridge (AnalysisRun.fresh_for)
    try:
        dex = dex_data if isinstance(dex_data, Dex) else Dex(dex_data)
    except Exception:
        return [], 0
    if _dfl is not None:
        # KB-7: what the package's OTHER dex members can reach (dex_float.package_info), and whether native code or
        # anything else the VM does not see ships beside this dex (a static's history-free reading declines then)
        _dfl.attach(dex, so_members, _ext)
    # Day 27 (so-ambig fix round 1): each distinct .so body is read once (_SoBodies), and the table carries the
    # delivery's export view, which _so_bind holds every binding against (_NativeTable, _SoView)
    bodies = so_members if isinstance(so_members, _SoBodies) else _SoBodies(so_members)
    native_syms = _NativeTable()
    native_arm = {}   # {sym: code} of AArch64 .so FUNCs (aarch64_functions returns {} for any other machine)
    for sob in bodies:
        body = bodies.body(sob)
        if body is not None:
            native_syms.update(body.funcs)
        if native_arm64 is not None:
            try:
                native_arm.update(native_arm64.aarch64_functions(sob))
            except Exception:
                pass
    _fold_arm32(native_syms, bodies)   # B-164: the ELF32 arm32 exports `_parse_so` (ELF64 only) never reads
    for sym in _so_ambiguous(bodies):   # Day 27 (so-ambig): two libraries define it differently -> a call declines
        if sym in native_syms:
            native_syms[sym] = (EM_AMBIGUOUS, b"")
        if sym in native_arm:
            native_arm[sym] = b""
    for sym, defs in _so_multi_arch(bodies).items():   # Day 27 (so-ambig r2): one symbol, two architectures
        if native_syms.get(sym, (EM_AMBIGUOUS,))[0] != EM_AMBIGUOUS:
            native_syms[sym] = (EM_MULTI, defs)            # every body runs, and all must agree (_native_multi)
    native_syms.so_view = _SoView(bodies.distinct)
    native_syms.dexes = [dex] + [d for d in (_dexes or ()) if d is not dex]
    try:
        ans_idx = next(i for i in range(dex.str_size) if dex.string(i) == "ANS-")
        ans_idx = {ans_idx}
    except (StopIteration, Exception):
        ans_idx = set()
    try:  # look-ahead: the prefix split ("ANS" + "-") or kept in a short format literal ("ANS-%016X")
        for i in range(dex.str_size):
            t = dex.string(i)
            if t == "ANS" or (t.startswith("ANS-") and 4 < len(t) <= 12):
                ans_idx.add(i)
    except Exception:
        pass
    if not ans_idx:
        return [], 0
    allentries = _entry_midxs(dex, ans_idx)
    entries = allentries[:MAX_ENTRIES]
    declines = len(allentries) - len(entries)
    for cut in allentries[MAX_ENTRIES:]:
        _note_entry(_trace, dex, cut, "skipped", "past MAX_ENTRIES (%d)" % MAX_ENTRIES)
    found = []
    budget = TOTAL_STEPS
    # KB-2: `package` [(member name, bytes)] is every dex of the delivery, which the bridge resolves a call against
    images = native_image_bridge.Bundle(so_members, package or [("classes.dex", dex.d)]) \
        if native_image_bridge is not None and so_members and entries else None
    for entry in entries:
        if budget <= 0:
            declines += 1          # cumulative budget spent: this method is not run at all
            _note_entry(_trace, dex, entry, "skipped", "cumulative step budget (%d) spent" % TOTAL_STEPS)
            continue
        _, ins_size, _ = dex.code[entry]
        vm = VM(dex, native_syms, native_arm)
        vm.native_images = images  # KB-2: whole-image fallback / cross-check of a JNI native
        vm.members = members       # Day 31 fold: the package member map for AssetManager.open / InMemoryDexClassLoader
        vm.max_steps = min(vm.max_steps, budget)
        try:
            if _dfl is not None:
                _dfl.pre_entry(vm, entry)    # KB-7: an entry of a class another dex member also defines is not run
            out = vm.run(entry, [None] * ins_size)
        except BaseException as e:  # _Decline, step budget, any decode error: counted, never fatal
            if isinstance(e, (KeyboardInterrupt, SystemExit)):
                raise
            budget -= vm.steps
            declines += 1
            _note_entry(_trace, dex, entry, "decline", "%s: %s" % (type(e).__name__, e), vm)
            continue
        budget -= vm.steps
        if isinstance(out, str) and ANSWER.fullmatch(out):
            _note_entry(_trace, dex, entry, "code", "", vm, out)
            if _feats is not None and _dfl is not None:
                _dfl.note(_feats, out, vm)   # KB-7: the new VM capabilities this code needed (answer()'s key)
                if vm.loaded_inmemory and _feats.get(out):
                    # Day 31 fold: this code came out of the "Loaded Later" chain (a secondary dex loaded with
                    # InMemoryDexClassLoader and invoked by reflection). The reflection and static reads that
                    # drives are the mechanics of the judged `analysis` chain, not a KB-7 risk of their own, so
                    # the run contributes no capability suffix: the code answers under the judged route, plain,
                    # exactly as the Day 31 live fix (day_patch.py) did. Loader chains are all new, so this moves
                    # no saved answer (none ever reached a code through the loader before this fold).
                    _feats[out][-1] = frozenset()
            if native_image_bridge is not None:
                native_image_bridge.note(vm, out)   # KB-2: did this code need the whole-image path?
            if out not in found:
                found.append(out)
                if len(found) >= MAX_CODES:
                    break
        else:
            declines += 1          # ran, but not to a valid code: not proven to be a decoy either
            _note_entry(_trace, dex, entry, "no-code", "returned %s, not ANS-[0-9A-F]{16}" % type(out).__name__, vm)
    return found, declines


def codes_in_dex(dex_data, so_members=()):
    """The codes of codes_in_dex_ex (kept for callers that want only the list)."""
    return codes_in_dex_ex(dex_data, so_members)[0]


def analysis_codes_ex(files, _so=None, _feats=None, _trace=None):
    """(codes, declines) over every dex member; see codes_in_dex_ex (and its `_trace`: each record also carries
    `dex`, the index of the dex member it came from in the order the members are run, classes.dex first)."""
    _bump_run()   # Day 30 fold: an AnalysisRun made before this call no longer stands in for answer()'s own run
    if isinstance(files, (bytes, bytearray)):
        return codes_in_dex_ex(bytes(files), _so or (), _feats, _trace=_trace)
    so = _SoBodies(_so_members(files))   # read once for every dex member (Day 27 so-ambig fix round 1)
    raw = _dex_members(files)
    exts = _dfl.package_info(files, raw) if _dfl is not None else [None] * len(raw)  # KB-7
    dexes, dexts, done = [], [], set()
    for dex_data, ext in zip(raw, exts):
        # KB-2 fix round 1: the runner's files hold each dex twice (`<delivery> -> classes.dex` beside `classes.dex`);
        # a member is parsed and run once (the same bytes give the same codes and declines, dex_float.sibling_refs
        # hands an identical copy the same ext, and _resolve_native reads two identical copies as one)
        if dex_data in done:
            continue
        done.add(dex_data)
        try:
            dexes.append(Dex(dex_data))  # parsed once; a dex that does not parse gives nothing, as before
        except Exception:
            continue
        dexts.append(ext)
    package = [(k, bytes(v)) for k, v in (files.items() if isinstance(files, dict) else ())
               if isinstance(k, str) and k.endswith(".dex") and isinstance(v, (bytes, bytearray)) and v]   # KB-2
    # Day 31 fold: the whole package member map, keyed by the bare member name (a runner key may be
    # "<delivery> -> assets/payload.dex"), so a chain's AssetManager.open / InMemoryDexClassLoader reads
    # a secondary dex out of THIS APK's own assets.
    members = {}
    if isinstance(files, dict):
        for k, v in files.items():
            if isinstance(k, str) and isinstance(v, (bytes, bytearray)):
                members[k.split(" -> ", 1)[-1]] = bytes(v)
    seen, declines = [], 0
    for n, (dex, ext) in enumerate(zip(dexes, dexts)):
        sub = [] if _trace is not None else None
        c, d = codes_in_dex_ex(dex, so, _feats, ext, dexes, package=package, members=members,  # natives + assets
                               _trace=sub)
        if sub:
            _trace.extend(dict(rec, dex=n) for rec in sub)
        declines += d
        for code in c:
            if code not in seen:
                seen.append(code)
    return seen[:MAX_CODES], declines


def analysis_codes(files, _so=None):
    """Every distinct valid ANS code assembled anywhere in the package's dex members.

    `files` may be the {name: bytes} member map, or raw dex bytes (then pass the .so list as `_so`)."""
    return analysis_codes_ex(files, _so)[0]


def recover(files):
    """The single anchored ANS code of an `analysis` package, or None.

    None unless the puzzle document's codec is `analysis`, there is a dex, and EXACTLY ONE
    distinct valid code is assembled (more than one is ambiguous -> never a plain guess here). A document read
    under a layer (document_ex) is not this shape: None (Day 27 so-ambig fix round 2)."""
    doc, layer = document_ex(files)
    if layer or not (isinstance(doc, dict) and str(doc.get("codec")).strip().lower() == CODEC):
        return None
    if native_image_bridge is not None:
        native_image_bridge.reset()
    codes, declines = analysis_codes_ex(files)
    if native_image_bridge is not None and native_image_bridge.image_suffix(codes):
        return None                # KB-2: a code only the whole-image path proved is never returned plain here
    return codes[0] if len(codes) == 1 and not declines else None


# --------------------------------------------------------------- document / codec gate
# Day 27 so-ambig fix round 2 (the review of 38a1668, F2): document() parsed strict JSON only, while codec_search reads
# the puzzle document under a whole-document layer and inside a member of the app's code too, so such an `analysis`
# document never ran the chain here (and codec_search's rule 3 missed it: the classes.dex decoy went out plain).
_DOC_SCHEMA = b"huntress.mobile.puzzle"
_DOC_AT = re.compile(rb'\{\s*"schema"\s*:\s*"huntress\.mobile\.puzzle')
_DOC_MAX = 1 << 16           # codec_search.MAX_WRAPPED: bytes of a puzzle member read under a layer
_DOC_INFLATE = 1 << 18       # codec_search.MAX_INFLATED: bytes a zlib layer may inflate to
_DOC_EMBEDDED = 4            # codec_search.MAX_EMBEDDED: documents read out of one member of the app's code
_DOC_MEMBERS = 64            # members holding the schema literal read for an embedded document


def _puzzle_doc(text):
    """The parsed object when `text` is JSON with a huntress.mobile.puzzle schema, else None (codec_search's proof
    for a document read under a layer or out of the app's code)."""
    if _DOC_SCHEMA not in text:
        return None
    try:
        obj = json.loads(text.decode("utf-8-sig"))
    except Exception:
        return None
    s = obj.get("schema") if isinstance(obj, dict) else None
    return obj if isinstance(s, str) and s.strip().startswith(_DOC_SCHEMA.decode()) else None


def _doc_layer(body):
    """(document, layer) for the puzzle member's bytes: strict JSON, layer '' (as before); else, for a member of at
    most _DOC_MAX bytes, the readings codec_search names as layers of the document (`doc-encoded`, `doc-zlib`,
    `doc-xor`: never the judged shape of its codec): a JSON object under base64 or hex, UTF-16 behind its byte order
    mark, the whole member under zlib (complete, inflated to _DOC_INFLATE at most) or a one-byte XOR keyed by its first
    byte XOR '{' (each of these two only with the huntress.mobile.puzzle schema). (None, '') when none reads."""
    b = bytes(body)
    try:
        return json.loads(b.decode("utf-8-sig")), ""
    except Exception:
        pass
    if not 2 <= len(b) <= _DOC_MAX:
        return None, ""
    import base64 as _b64
    texts = []
    try:
        texts.append(("base64", _b64.b64decode(b"".join(b.split()), validate=True)))
    except Exception:
        pass
    try:
        texts.append(("hex", bytes.fromhex(b.decode("ascii").strip())))
    except Exception:
        pass
    for layer, raw in texts:
        try:
            obj = json.loads(raw.decode("utf-8-sig"))
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj, layer
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            obj = json.loads(b.decode("utf-16"))
            if isinstance(obj, dict):
                return obj, "utf16"
        except Exception:
            pass
    if len(b) >= 16 and b[:1] == b"\x78":
        try:
            d = _zlib.decompressobj(15)
            text = d.decompress(b, _DOC_INFLATE)
            if d.eof and not d.unconsumed_tail:
                obj = _puzzle_doc(text)
                if obj is not None:
                    return obj, "zlib"
        except Exception:
            pass
    key = b[0] ^ 0x7B
    if key:
        obj = _puzzle_doc(b.translate(bytes(c ^ key for c in range(256))))
        if obj is not None:
            return obj, "xor"
    return None, ""


def _balanced_doc(body, start):
    """The bytes of the JSON object that begins at `start` (strings and escapes respected), or None when it does not
    close within _DOC_MAX bytes (codec_search._balanced)."""
    depth, quoted, i, end = 0, False, start, min(len(body), start + _DOC_MAX)
    while i < end:
        c = body[i]
        if quoted:
            if c == 0x5C:
                i += 2
                continue
            if c == 0x22:
                quoted = False
        elif c == 0x22:
            quoted = True
        elif c == 0x7B:
            depth += 1
        elif c == 0x7D:
            depth -= 1
            if depth == 0:
                return body[start:i + 1]
        i += 1
    return None


def _embedded_doc(files):
    """The one puzzle document standing as JSON text in a .dex or .bin member of the package (codec_search.
    embedded_docs: cut out at its schema literal as one balanced object, at most _DOC_EMBEDDED a member); None for
    none, for two different ones (nothing says which is meant), or past _DOC_MEMBERS members holding the literal (not
    all read: nothing proves there is one)."""
    found, seen = [], 0
    for n, v in files.items():
        if not (isinstance(n, str) and n.endswith((".dex", ".bin")) and isinstance(v, (bytes, bytearray))):
            continue
        body = bytes(v)
        if _DOC_SCHEMA not in body:
            continue
        seen += 1
        if seen > _DOC_MEMBERS:
            return None
        k = 0
        for m in _DOC_AT.finditer(body):
            text = _balanced_doc(body, m.start())
            obj = _puzzle_doc(text) if text else None
            if obj is not None and obj not in found:
                found.append(obj)
            k += 1
            if k >= _DOC_EMBEDDED or len(found) > 1:
                break
        if len(found) > 1:
            return None
    return found[0] if len(found) == 1 else None


def document_ex(files, ctx=None):
    """(document, layer): the puzzle document as codec_search's reading finds it. From the set's delivery (the APK in
    ctx), else from `files`: assets/huntress_puzzle.json as strict JSON (layer '') or under a layer (_doc_layer:
    'base64', 'hex', 'utf16', 'zlib', 'xor'); when that member is absent or no reading parses it, the one document
    standing in a .dex or .bin member (layer 'embedded'). (None, '') for none. A document under a layer is never the
    judged shape: answer() and answer_any() answer it under a key of its own (`<key>:doc-<layer>`)."""
    body = None
    if isinstance(ctx, dict):
        blob = ctx.get("delivery")
        if blob:
            try:
                with zipfile.ZipFile(io.BytesIO(bytes(blob))) as zf:
                    body = zf.read(PUZZLE)
            except Exception:
                body = None
    if body is None and isinstance(files, dict):
        body = files.get(PUZZLE)
    if body is not None:
        try:
            doc, layer = _doc_layer(body)
        except Exception:
            doc, layer = None, ""
        if doc is not None:
            return doc, layer
    if isinstance(files, dict):
        try:
            emb = _embedded_doc(files)
        except Exception:
            emb = None
        if emb is not None:
            return emb, "embedded"
    return None, ""


def document(files, ctx=None):
    """The parsed puzzle document (document_ex without its layer)."""
    return document_ex(files, ctx)[0]


def is_analysis(files, ctx=None):
    """True only when the puzzle document states codec `analysis`. The fast-reject gate: a package
    whose codec is anything else is not this reader's, so it returns False and the reader bails."""
    doc = document(files, ctx)
    return isinstance(doc, dict) and str(doc.get("codec")).strip().lower() == CODEC


def _layered(key, route, layer):
    """(key, route) for a document read under `layer` (document_ex): a name of its own, unsure until judged."""
    return (key, route) if not layer else ("%s:doc-%s" % (key, layer), "%s:doc-%s" % (route, layer))


def _wants_code(q):
    """False only when the question's answer_format cannot possibly hold an ANS code (an integer,
    an enum): then this reader must not answer. An absent/unknown format is allowed through."""
    if not isinstance(q, dict):
        return True
    fmt = q.get("answer_format")
    if fmt is None:
        return True
    try:
        blob = json.dumps(fmt, default=str)
    except Exception:
        blob = str(fmt)
    return "ANS-" in blob or "ans-" in blob.lower()


class AnalysisRun:
    """One run of the package's dex chain exactly as answer() makes it (the whole-image bridge reset, then
    analysis_codes_ex with the KB-7 feature record), kept for the very `files` mapping it ran over. Day 30 fold
    (speed): codec_search's `analysis` gate ran the chain once to decide its fast path and answer() ran it again
    over the same bytes, so every `analysis` set paid the chain twice. answer(..., run=) takes this run's
    (codes, declines, feats) ONLY when `files` is the same object it ran over and nothing reset the bridge since;
    any other call computes as before."""

    __slots__ = ("files", "codes", "declines", "feats", "epoch")

    def __init__(self, files):
        if native_image_bridge is not None:
            native_image_bridge.reset()
        self.files = files
        self.feats = {}
        self.codes, self.declines = analysis_codes_ex(files, _feats=self.feats)
        self.epoch = _RUN_EPOCH

    def fresh_for(self, files) -> bool:
        """True when `files` is the mapping this run read and no other run (or bridge reset through one) came since."""
        return files is self.files and self.epoch == _RUN_EPOCH


def answer(q, files, ctx=None, run=None):
    """The never-guess reader a live fix wraps. labels.pick for one code, labels.candidates for
    several, None for nothing. See the module docstring for the never-wrong guarantee. A document read under a
    layer (document_ex) answers under `<KEY>:doc-<layer>`, a key of its own (Day 27 so-ambig fix round 2).
    `run` (an AnalysisRun over this very `files` object, the latest run) stands in for the chain's own run."""
    if not _wants_code(q):
        return None
    doc, layer = document_ex(files, ctx)
    if not (isinstance(doc, dict) and str(doc.get("codec")).strip().lower() == CODEC):
        return None
    if isinstance(run, AnalysisRun) and run.fresh_for(files):
        codes, declines, feats = list(run.codes), run.declines, run.feats
    else:
        if native_image_bridge is not None:
            native_image_bridge.reset()
        feats = {}
        codes, declines = analysis_codes_ex(files, _feats=feats)
    if not codes:
        return None
    # KB-7: a code only the new VM capabilities (dex_float.py) produce is never under the judged key: its own key
    # and route (`mobile.codec/analysis+dex-float`, ...), an unsure pick until the judge accepts that exact name.
    sfx = _dfl.key_suffix(feats, codes) if _dfl is not None else ""
    key, route = _layered(KEY, ROUTE, layer)
    if native_image_bridge is not None:   # KB-2: a code only the whole-image path proved -> a NEW unsure key
        key, route = native_image_bridge.keyed(key, route, codes)
    key, route = key + sfx, route + sfx
    if len(codes) == 1 and declines:
        # An ANS-referencing method could not be read (declined, cut by a budget, or beyond MAX_ENTRIES): the
        # lone code may be a decoy's. Never plain: a key the judge has never accepted, so always an unsure pick.
        return labels.pick(key + "#partial", [(route + ":partial", codes[0])])
    if len(codes) == 1:
        # Unsure until the judge accepts ROUTE on the base; plain on every variant after that.
        return labels.pick(key, [(route, codes[0])])
    # More than one distinct chain produced an ANS code: the bytes do not prove which is asked.
    # Candidate pick (row 346): never plain before the judge accepts a hypothesis.
    opts = [("%s#%d" % (HOW, i + 1), c) for i, c in enumerate(codes[:MAX_CODES])]
    return labels.candidates(key, opts)


# --------------------------------------------------------------- Day 24 look-ahead: any codec name
GENERIC_KEY = "mobile.codec/dex-chain"


def has_data(doc):
    """True when the puzzle document carries a payload a codec could decode (a non-empty `data`/`payload`)."""
    if not isinstance(doc, dict):
        return False
    for k in ("data", "payload", "blob", "cipher", "ciphertext", "encoded"):
        v = doc.get(k)
        if v not in (None, "", [], {}):
            return True
    return False


def answer_any(q, files, ctx=None, beside=False):
    """UNSURE-ONLY reading for a v2-style document that is NOT codec `analysis` but has NO payload at all
    (Day 24 may rename the codec): the code can only come from the app's own dex chain. Never plain: the
    key mobile.codec/dex-chain is not judged, and a document with a payload is left to the shipped codecs.
    None unless every condition holds and exactly the dex chain yields code(s).

    `beside` (Day 27 so-ambig fix round 2): codec_search asks for a document its rule 3 found no payload of to prove
    the package look's code (codec_search._beside_analysis: a payload that names no member holding it and that the
    document's own codec does not decode to it), so the chain is read whatever the payload fields hold. A document read
    under a layer (document_ex) answers under `<key>:doc-<layer>`."""
    if not _wants_code(q):
        return None
    doc, layer = document_ex(files, ctx)
    if not isinstance(doc, dict) or (has_data(doc) and not beside) or str(doc.get("codec")).strip().lower() == CODEC:
        return None
    if native_image_bridge is not None:
        native_image_bridge.reset()
    feats = {}
    codes, declines = analysis_codes_ex(files, _feats=feats)
    if not codes:
        return None
    sfx = _dfl.key_suffix(feats, codes) if _dfl is not None else ""     # KB-7, as in answer()
    gkey, route = _layered(GENERIC_KEY, "dex-chain", layer)
    if native_image_bridge is not None:   # KB-2: a code only the whole-image path proved -> a NEW unsure key
        gkey, route = native_image_bridge.keyed(gkey, route, codes)
    gkey, route = gkey + sfx, route + sfx
    if has_data(doc):
        # `beside` only: a document with payload fields is another shape than the no-payload one GENERIC_KEY names (the
        # payload may encode the answer a reader here cannot read), so a name accepted there never answers it plain
        gkey, route = gkey + ":payload", route + ":payload"
    if len(codes) == 1 and declines:
        # Day 27 so-ambig fix round 1 (codec_search now hears this beside a package-look code too): a lone code beside
        # an ANS method that did not read may be a decoy chain's, answer()'s rule: under a key of its own, never plain
        return labels.pick(gkey + "#partial", [(route + ":partial", codes[0])])
    if len(codes) == 1:
        return labels.pick(gkey, [(route, codes[0])])
    return labels.candidates(gkey, [("%s#%d" % (route, i + 1), c) for i, c in enumerate(codes[:MAX_CODES])])


# ===================================================================================================
# Wrapper for solvers/mobile-android/day_patch.py (copy, uncomment) -- only to answer or replace the
# `analysis` codec from a live fix. `answer()`/`override()` are what codec_search.py calls.
#
# import dex_chain_codec as _dcc            # when this module ships beside day_patch.py
#
# def answer(q, files, ctx):
#     return _dcc.answer(q, files, ctx)      # asked for ids the shipped solver left None/unsure
#
# WITHDRAW = "<<withdraw>>"
#
# def override(q, shipped, files, ctx):
#     if _dcc.labels.is_unsure(shipped) or shipped is None:
#         return None                        # not a shipped PLAIN answer: leave it for answer()
#     if not _dcc.is_analysis(files, ctx):
#         return None                        # another codec: the shipped plain answer stands
#     mine = _dcc.answer(q, files, ctx)      # the analysis reading of THIS delivery
#     return mine if mine is not None else WITHDRAW   # replace a rejected plain, else withdraw it
