#!/usr/bin/env python3
"""Synthetic Android packages for the Day 27 Mobile split look-ahead (tests/day27_mobile_splits_lib.py).

Moved here from tests/day27_mobile_splits_synth.py (B-229 fix round 1) so the mobile Layer-1 opener can build the
Day 26 split bundle (ctf.openers.mobile_fixtures.apk_split_asset_bundle); that test module name is now an alias of
this one. The bytes it builds did not change (the MANIFEST.MF `Created-By` keeps the old name on purpose).

The look-ahead's cases were first built around real challenge deliveries (the Day 26 split bundles, the Day 23 and
25 native and reflection APKs, with their judged answers beside them). Real deliveries do not belong in the master
(R-04), so this module builds packages of the same SHAPES from scratch, here, at test time:

  dex      a complete classes.dex (header with checksum and signature, string/type/proto/field/method ids, class
           defs, class data, code items, type lists and a map list), so androguard (the reference runtime's
           decoder) and the shipped solver's own reader both read it;
  axml     a compiled AndroidManifest.xml (string pool, resource map, namespace and element chunks): the base names
           its package, a split names the same package and its `split`;
  elf      an x86-64 ELF shared object with PT_LOAD/PT_DYNAMIC, .dynsym, .dynstr, a SysV .hash, .text and the
           section headers, exporting hand-assembled JNI functions;
  apk      a zip of those members with a META-INF/MANIFEST.MF of SHA-256 digests (unsigned: nothing reads a
           signature).

The apps follow the judged shapes (an `analysis` dex chain: Release.code(Context) builds 'ANS-' + 16 hex digits from
a 64-bit token mixed through app methods), each with its own constants:

  d26_base   codec `split`: the base's puzzle document leaves a part empty, the feature split's JSON part fills it
  d26_tt     codec `analysis`: the chain reads assets/huntress_feature.bin of a non-base split through a reader
             with the judged reader's code shape (Assets.readSplit: Context.getApplicationInfo().splitSourceDirs,
             ZipFile.getEntry, InputStream.read into a 16-byte buffer), so the judged key applies to it
  d26_m10    the same reader shape in another app, other constants and other asset bytes
  d25_set6   a JNI leg: JNIBoundary.nativeShare(long, int) in lib/x86_64/libarena.so with a gate (a branch that
             returns 0 unless the int passes) before the mixing
  d23_set5   a straight-line JNI leg: NativeLibrarySecrets.nativeShare(long)
  d25_set7   reflection: Class.forName / getDeclaredMethod / Method.invoke on Maze.m<k>, k from a packed-switch

Every answer is known by construction: `Oracle` evaluates the same chain spec in Python (uint64/int32 arithmetic,
the reader's 16-byte buffer, the native leg's gate), independently of how the bytecode and machine code encode it.
The tests hold the shipped solver (which decodes the bytes) and the reference runtime (androguard + its own
interpreter) against it. Nothing here is a challenge file or comes from one; nothing here imports a solver.
"""
import hashlib
import io
import json
import random
import struct
import zipfile
import zlib

M32, M64 = 0xFFFFFFFF, (1 << 64) - 1
PUZZLE = "assets/huntress_puzzle.json"
FEATURE_BIN = "assets/huntress_feature.bin"
SO_PATH = "lib/x86_64/libarena.so"

OBJ = "Ljava/lang/Object;"
STR = "Ljava/lang/String;"
SB = "Ljava/lang/StringBuilder;"
CTX = "Landroid/content/Context;"
AI = "Landroid/content/pm/ApplicationInfo;"
ZF = "Ljava/util/zip/ZipFile;"
ZE = "Ljava/util/zip/ZipEntry;"
IS = "Ljava/io/InputStream;"
LONG = "Ljava/lang/Long;"
CLASS = "Ljava/lang/Class;"
METHOD = "Ljava/lang/reflect/Method;"

ACC_PUBLIC, ACC_STATIC, ACC_FINAL, ACC_NATIVE, ACC_CONSTRUCTOR = 0x1, 0x8, 0x10, 0x100, 0x10000


def s32(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def s64(x):
    x &= M64
    return x - (1 << 64) if x & (1 << 63) else x


def uleb(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _align(buf, n):
    while len(buf) % n:
        buf.append(0)


# ===================================================================================== Dalvik assembler
# name -> (opcode, format). Formats follow the Dalvik bytecode reference (the instruction formats page).
_OPS = {
    "nop": (0x00, "10x"), "move-wide": (0x04, "12x"), "move-result": (0x0a, "11x"),
    "move-result-wide": (0x0b, "11x"), "move-result-object": (0x0c, "11x"), "return-void": (0x0e, "10x"),
    "return": (0x0f, "11x"), "return-wide": (0x10, "11x"), "return-object": (0x11, "11x"),
    "const/4": (0x12, "11n"), "const/16": (0x13, "21s"), "const": (0x14, "31i"), "const-wide": (0x18, "51l"),
    "const-string": (0x1a, "21c"), "check-cast": (0x1f, "21c"), "array-length": (0x21, "12x"),
    "new-instance": (0x22, "21c"), "new-array": (0x23, "22c"), "throw": (0x27, "11x"), "goto": (0x28, "10t"),
    "packed-switch": (0x2b, "31t"),
    "if-eq": (0x32, "22t"), "if-ne": (0x33, "22t"), "if-lt": (0x34, "22t"), "if-ge": (0x35, "22t"),
    "if-gt": (0x36, "22t"), "if-le": (0x37, "22t"),
    "if-eqz": (0x38, "21t"), "if-nez": (0x39, "21t"), "if-ltz": (0x3a, "21t"), "if-gez": (0x3b, "21t"),
    "if-gtz": (0x3c, "21t"), "if-lez": (0x3d, "21t"),
    "aget-object": (0x46, "23x"), "aget-byte": (0x48, "23x"), "aput-object": (0x4d, "23x"),
    "iget-object": (0x54, "22c"), "sget-object": (0x62, "21c"), "sput-object": (0x69, "21c"),
    "invoke-virtual": (0x6e, "35c"), "invoke-super": (0x6f, "35c"), "invoke-direct": (0x70, "35c"),
    "invoke-static": (0x71, "35c"),
    "int-to-long": (0x81, "12x"), "long-to-int": (0x84, "12x"),
    "add-int": (0x90, "23x"), "mul-int": (0x92, "23x"), "xor-int": (0x97, "23x"),
    "shl-long": (0xa3, "23x"), "ushr-long": (0xa5, "23x"), "or-long": (0xa1, "23x"),
    "add-int/2addr": (0xb0, "12x"), "sub-int/2addr": (0xb1, "12x"), "mul-int/2addr": (0xb2, "12x"),
    "xor-int/2addr": (0xb7, "12x"), "add-long/2addr": (0xbb, "12x"), "mul-long/2addr": (0xbd, "12x"),
    "or-long/2addr": (0xc1, "12x"), "xor-long/2addr": (0xc2, "12x"), "shl-long/2addr": (0xc3, "12x"),
    "and-int/lit16": (0xd5, "22s"), "add-int/lit8": (0xd8, "22b"), "and-int/lit8": (0xdd, "22b"),
    "shl-int/lit8": (0xe0, "22b"), "or-int/2addr": (0xb6, "12x"),
}


class Asm:
    """Dalvik code units with label fixups: `a.op(name, *operands)`; a branch target is a label name, a
    packed-switch names its payload's label and `a.packed_payload(label, first_key, [target labels])` places it."""

    def __init__(self):
        self.u = []
        self.labels = {}
        self.fix = []          # (unit index, instruction start, label, kind) kind: 8 (high byte), 16, 32
        self.payloads = []     # (label, first key, [target labels], switch start)
        self._switch_at = {}

    def label(self, name):
        assert name not in self.labels, name
        self.labels[name] = len(self.u)

    def op(self, name, *a):
        code, fmt = _OPS[name]
        u, start = self.u, len(self.u)
        if fmt == "10x":
            u.append(code)
        elif fmt == "12x":
            assert a[0] < 16 and a[1] < 16, (name, a)
            u.append(code | (a[1] << 12) | (a[0] << 8))
        elif fmt == "11n":
            assert a[0] < 16 and -8 <= a[1] <= 7, (name, a)
            u.append(code | ((a[1] & 0xF) << 12) | (a[0] << 8))
        elif fmt == "11x":
            u.append(code | (a[0] << 8))
        elif fmt == "21s":
            assert -0x8000 <= a[1] <= 0x7FFF
            u += [code | (a[0] << 8), a[1] & 0xFFFF]
        elif fmt == "31i":
            u += [code | (a[0] << 8), a[1] & 0xFFFF, (a[1] >> 16) & 0xFFFF]
        elif fmt == "51l":
            v = a[1] & M64
            u += [code | (a[0] << 8)] + [(v >> s) & 0xFFFF for s in (0, 16, 32, 48)]
        elif fmt == "21c":
            u += [code | (a[0] << 8), a[1]]
        elif fmt == "22c":
            assert a[0] < 16 and a[1] < 16
            u += [code | (a[1] << 12) | (a[0] << 8), a[2]]
        elif fmt == "23x":
            u += [code | (a[0] << 8), (a[2] << 8) | a[1]]
        elif fmt == "22b":
            assert -0x80 <= a[2] <= 0x7F
            u += [code | (a[0] << 8), ((a[2] & 0xFF) << 8) | a[1]]
        elif fmt == "22s":
            assert a[0] < 16 and a[1] < 16 and -0x8000 <= a[2] <= 0x7FFF
            u += [code | (a[1] << 12) | (a[0] << 8), a[2] & 0xFFFF]
        elif fmt == "22t":
            assert a[0] < 16 and a[1] < 16
            u += [code | (a[1] << 12) | (a[0] << 8), 0]
            self.fix.append((start + 1, start, a[2], 16))
        elif fmt == "21t":
            u += [code | (a[0] << 8), 0]
            self.fix.append((start + 1, start, a[1], 16))
        elif fmt == "10t":
            u.append(code)
            self.fix.append((start, start, a[0], 8))
        elif fmt == "31t":
            u += [code | (a[0] << 8), 0, 0]
            self.fix.append((start + 1, start, a[1], 32))
            self._switch_at[a[1]] = start
        elif fmt == "35c":
            meth, regs = a[0], list(a[1])
            assert len(regs) <= 5 and all(r < 16 for r in regs), (name, regs)
            p = regs + [0] * (5 - len(regs))
            u += [code | (len(regs) << 12) | (p[4] << 8), meth, (p[3] << 12) | (p[2] << 8) | (p[1] << 4) | p[0]]
        else:  # pragma: no cover
            raise ValueError(fmt)
        return self

    def packed_payload(self, label, first, targets):
        self.payloads.append((label, first, list(targets)))

    def finish(self):
        for label, first, targets in self.payloads:
            if len(self.u) % 2:
                self.op("nop")            # a payload sits on a 4-byte boundary
            self.label(label)
            start = self._switch_at[label]
            self.u += [0x0100, len(targets), first & 0xFFFF, (first >> 16) & 0xFFFF]
            for t in targets:
                off = self.labels[t] - start
                self.u += [off & 0xFFFF, (off >> 16) & 0xFFFF]
        for at, start, label, kind in self.fix:
            off = self.labels[label] - start
            if kind == 8:
                assert -128 <= off <= 127, (label, off)
                self.u[at] = (self.u[at] & 0xFF) | ((off & 0xFF) << 8)
            elif kind == 16:
                assert -0x8000 <= off <= 0x7FFF
                self.u[at] = off & 0xFFFF
            else:
                self.u[at], self.u[at + 1] = off & 0xFFFF, (off >> 16) & 0xFFFF
        return list(self.u)


# ===================================================================================== dex writer
def _shorty(t):
    return t if len(t) == 1 else "L"


def _wide(t):
    return t in ("J", "D")


class DexWriter:
    """A complete, unsorted-but-consistent classes.dex. Ids are handed out as they are asked for (the instructions
    carry them), so tables keep request order; every table, the class data and the map list are what the format
    describes, and the header carries a real adler32 checksum and SHA-1 signature."""

    def __init__(self):
        self.strings, self._s = [], {}
        self.types, self._t = [], {}
        self.protos, self._p = [], {}
        self.fields, self._f = [], {}
        self.methods, self._m = [], {}
        self.classes = {}       # descriptor -> {"flags", "super", "sfields": [(fidx, flags)], "direct", "virtual"}

    # ---- ids
    def s(self, text):
        if text not in self._s:
            assert all(ord(c) < 0x80 for c in text), "ASCII only (MUTF-8 = UTF-8 there)"
            self._s[text] = len(self.strings)
            self.strings.append(text)
        return self._s[text]

    def t(self, desc):
        if desc not in self._t:
            self.s(desc)
            self._t[desc] = len(self.types)
            self.types.append(desc)
        return self._t[desc]

    def proto(self, ret, params=()):
        key = (ret, tuple(params))
        if key not in self._p:
            self.s(_shorty(ret) + "".join(_shorty(p) for p in params))
            self.t(ret)
            for p in params:
                self.t(p)
            self._p[key] = len(self.protos)
            self.protos.append(key)
        return self._p[key]

    def f(self, cls, typ, name):
        key = (cls, typ, name)
        if key not in self._f:
            self.t(cls), self.t(typ), self.s(name)
            self._f[key] = len(self.fields)
            self.fields.append(key)
        return self._f[key]

    def m(self, cls, name, ret="V", params=()):
        key = (cls, name, ret, tuple(params))
        if key not in self._m:
            self.t(cls), self.s(name), self.proto(ret, params)
            self._m[key] = len(self.methods)
            self.methods.append(key)
        return self._m[key]

    # ---- definitions
    def cls(self, desc, flags=ACC_PUBLIC, super_=OBJ):
        if desc not in self.classes:
            self.t(desc), self.t(super_)
            self.classes[desc] = {"flags": flags, "super": super_, "sfields": [], "direct": [], "virtual": []}
        return self.classes[desc]

    def static_field(self, cls, typ, name, flags=ACC_STATIC):
        self.cls(cls)["sfields"].append((self.f(cls, typ, name), flags))

    def method(self, cls, name, ret, params, units=None, regs=0, flags=ACC_PUBLIC | ACC_STATIC, outs=5):
        """Define a method of `cls` (direct: static, private or a constructor; else virtual). units None: no code
        (native or abstract). regs: registers_size; ins_size is the parameters' (+ `this`)."""
        midx = self.m(cls, name, ret, params)
        ins = sum(2 if _wide(p) else 1 for p in params) + (0 if flags & ACC_STATIC else 1)
        if units is not None:
            assert regs >= ins, (cls, name, regs, ins)
        direct = bool(flags & (ACC_STATIC | 0x2 | ACC_CONSTRUCTOR))
        self.cls(cls)["direct" if direct else "virtual"].append((midx, flags, units, regs, ins, outs))
        return midx

    # ---- bytes
    def build(self):
        ns, nt, np_, nf, nm, nc = (len(self.strings), len(self.types), len(self.protos), len(self.fields),
                                   len(self.methods), len(self.classes))
        off_str = 0x70
        off_type = off_str + 4 * ns
        off_proto = off_type + 4 * nt
        off_field = off_proto + 12 * np_
        off_meth = off_field + 8 * nf
        off_cls = off_meth + 8 * nm
        data_off = off_cls + 32 * nc
        out = bytearray(data_off)
        mapl = [(0x0000, 1, 0), (0x0001, ns, off_str), (0x0002, nt, off_type), (0x0003, np_, off_proto),
                (0x0004, nf, off_field), (0x0005, nm, off_meth), (0x0006, nc, off_cls)]

        # code items
        _align(out, 4)
        code_start, ncode, code_off = len(out), 0, {}
        for desc, c in self.classes.items():
            for midx, _fl, units, regs, ins, outs in c["direct"] + c["virtual"]:
                if units is None:
                    continue
                _align(out, 4)
                code_off[(desc, midx)] = len(out)
                out += struct.pack("<HHHHII", regs, ins, outs, 0, 0, len(units))
                out += struct.pack("<%dH" % len(units), *units)
                ncode += 1
        if ncode:
            mapl.append((0x2001, ncode, code_start))
        # type lists (proto parameters)
        _align(out, 4)
        tl_start, tl_off = len(out), {}
        for key in self.protos:
            params = key[1]
            if params and params not in tl_off:
                _align(out, 4)
                tl_off[params] = len(out)
                out += struct.pack("<I", len(params)) + b"".join(struct.pack("<H", self._t[p]) for p in params)
        if tl_off:
            mapl.append((0x1001, len(tl_off), tl_start))
        # string data
        sd_start, sd_off = len(out), []
        for text in self.strings:
            sd_off.append(len(out))
            out += uleb(len(text)) + text.encode() + b"\0"
        mapl.append((0x2002, ns, sd_start))
        # class data
        cd_start, cd_off = len(out), {}
        for desc, c in self.classes.items():
            cd_off[desc] = len(out)
            sf = sorted(c["sfields"])
            dm = sorted(c["direct"], key=lambda x: x[0])
            vm = sorted(c["virtual"], key=lambda x: x[0])
            blk = bytearray(uleb(len(sf)) + uleb(0) + uleb(len(dm)) + uleb(len(vm)))
            prev = 0
            for fidx, fl in sf:
                blk += uleb(fidx - prev) + uleb(fl)
                prev = fidx
            for group in (dm, vm):
                prev = 0
                for midx, fl, units, *_ in group:
                    blk += uleb(midx - prev) + uleb(fl) + uleb(code_off.get((desc, midx), 0))
                    prev = midx
            out += blk
        if self.classes:
            mapl.append((0x2000, nc, cd_start))
        # map list
        _align(out, 4)
        map_off = len(out)
        mapl.append((0x1000, 1, map_off))
        mapl = sorted((e for e in mapl if e[1]), key=lambda e: e[2])
        out += struct.pack("<I", len(mapl)) + b"".join(struct.pack("<HHII", t, 0, n, o) for t, n, o in mapl)

        # id tables
        for i, o in enumerate(sd_off):
            struct.pack_into("<I", out, off_str + 4 * i, o)
        for i, d in enumerate(self.types):
            struct.pack_into("<I", out, off_type + 4 * i, self._s[d])
        for i, (ret, params) in enumerate(self.protos):
            shorty = _shorty(ret) + "".join(_shorty(p) for p in params)
            struct.pack_into("<III", out, off_proto + 12 * i, self._s[shorty], self._t[ret], tl_off.get(params, 0))
        for i, (c, typ, name) in enumerate(self.fields):
            struct.pack_into("<HHI", out, off_field + 8 * i, self._t[c], self._t[typ], self._s[name])
        for i, (c, name, ret, params) in enumerate(self.methods):
            struct.pack_into("<HHI", out, off_meth + 8 * i, self._t[c], self._p[(ret, params)], self._s[name])
        for i, (desc, c) in enumerate(self.classes.items()):
            struct.pack_into("<IIIIIIII", out, off_cls + 32 * i, self._t[desc], c["flags"], self._t[c["super"]], 0,
                             0xFFFFFFFF, 0, cd_off[desc], 0)
        # header
        out[0:8] = b"dex\n035\0"
        struct.pack_into("<I", out, 32, len(out))
        struct.pack_into("<II", out, 36, 0x70, 0x12345678)
        struct.pack_into("<III", out, 44, 0, 0, map_off)
        for k, (n, o) in enumerate(((ns, off_str), (nt, off_type), (np_, off_proto), (nf, off_field), (nm, off_meth),
                                    (nc, off_cls))):
            struct.pack_into("<II", out, 56 + 8 * k, n, o if n else 0)
        struct.pack_into("<II", out, 104, len(out) - data_off, data_off)
        return seal_dex(out)


def seal_dex(dex):
    """The header's SHA-1 signature (of bytes 32..) and adler32 checksum (of bytes 12..)."""
    b = bytearray(dex)
    b[12:32] = hashlib.sha1(bytes(b[32:])).digest()
    b[8:12] = struct.pack("<I", zlib.adler32(bytes(b[12:])) & M32)
    return bytes(b)


# ===================================================================================== mixers: spec, dex, oracle
def _rotl(x, r):
    r %= 64
    return ((x << r) | (x >> (64 - r))) & M64 if r else x


def mix_eval(spec, x):
    """The value of a mixer spec on a uint64, as the emitted (J)J method computes it."""
    x &= M64
    for op, k in spec:
        if op == "mul":
            x = (x * k) & M64
        elif op == "add":
            x = (x + k) & M64
        elif op == "xor":
            x ^= k & M64
        elif op == "rotl":
            x = _rotl(x, k)
        elif op == "xshr":
            x ^= x >> k
        else:  # pragma: no cover
            raise ValueError(op)
    return x


def mix_units(d, spec, regs=10):
    """A static (J)J body: the argument (v8:v9 with regs=10) into v0, then each op; v2:v3 a constant, v4/v5 shift
    counts, v6:v7 a temporary."""
    a = Asm()
    a.op("move-wide", 0, regs - 2)
    for op, k in spec:
        if op in ("mul", "add", "xor"):
            a.op("const-wide", 2, k)
            a.op({"mul": "mul-long/2addr", "add": "add-long/2addr", "xor": "xor-long/2addr"}[op], 0, 2)
        elif op == "rotl":
            a.op("const/16", 4, k % 64).op("const/16", 5, (64 - k) % 64)
            a.op("shl-long", 6, 0, 4).op("ushr-long", 2, 0, 5).op("or-long", 0, 6, 2)
        elif op == "xshr":
            a.op("const/16", 4, k).op("ushr-long", 6, 0, 4).op("xor-long/2addr", 0, 6)
    a.op("return-wide", 0)
    return a.finish()


def rand_spec(rng, n):
    ops = []
    for _ in range(n):
        op = rng.choice(("mul", "add", "xor", "rotl", "xshr"))
        if op == "mul":
            ops.append((op, rng.getrandbits(64) | 1))
        elif op in ("add", "xor"):
            ops.append((op, rng.getrandbits(64)))
        elif op == "rotl":
            ops.append((op, rng.randrange(1, 64)))
        else:
            ops.append((op, rng.randrange(7, 48)))
    return ops


def define_mixer(d, cls, name, spec):
    return d.method(cls, name, "J", ["J"], mix_units(d, spec), regs=10)


# ---- the 'ANS-' + 16 upper-case hex tail of Release.code (charAt over "0123456789ABCDEF", 60 down to 0)
def ans_of(x):
    return "ANS-%016X" % (x & M64)


# ===================================================================================== probes (int searches)
def probe_s1(a, b, c, d):
    """Probe.s1: the first i in [0, 4096) with ((i*a + b) ^ c) & 4095 == d, else -1 (int32 arithmetic)."""
    for i in range(4096):
        if (s32(s32(i * a) + b) ^ c) & 4095 == d:
            return i
    return -1


def probe_s2(a, b, c, d):
    """Probe.s2: the first i in [0, 4096) with (((i ^ c) * a) + b) & 4095 == d, else -1."""
    for i in range(4096):
        if s32(s32((i ^ c) * a) + b) & 4095 == d:
            return i
    return -1


def _probe_args(rng, fn):
    while True:
        a, b, c = rng.randrange(1, 4096), rng.randrange(4096), rng.randrange(4096)
        i0 = rng.randrange(64, 3000)
        d = (s32(s32(i0 * a) + b) ^ c) & 4095 if fn is probe_s1 else s32(s32((i0 ^ c) * a) + b) & 4095
        if fn(a, b, c, d) >= 0:
            return a, b, c, d


def define_probes(d, cls):
    """Probe.s1 / s2 (I I I I)I: regs 7, parameters v3..v6."""
    a = Asm()
    a.op("const/4", 0, 0)
    a.label("top")
    a.op("mul-int", 1, 0, 3).op("add-int/2addr", 1, 4).op("xor-int/2addr", 1, 5).op("and-int/lit16", 1, 1, 4095)
    a.op("if-eq", 1, 6, "hit")
    a.op("add-int/lit8", 0, 0, 1).op("const/16", 2, 4096).op("if-lt", 0, 2, "top")
    a.op("const/4", 0, -1)
    a.label("hit")
    a.op("return", 0)
    s1 = d.method(cls, "s1", "I", ["I", "I", "I", "I"], a.finish(), regs=7)
    a = Asm()
    a.op("const/4", 0, 0)
    a.label("top")
    a.op("xor-int", 1, 0, 5).op("mul-int/2addr", 1, 3).op("add-int/2addr", 1, 4).op("and-int/lit16", 1, 1, 4095)
    a.op("if-eq", 1, 6, "hit")
    a.op("add-int/lit8", 0, 0, 1).op("const/16", 2, 4096).op("if-lt", 0, 2, "top")
    a.op("const/4", 0, -1)
    a.label("hit")
    a.op("return", 0)
    s2 = d.method(cls, "s2", "I", ["I", "I", "I", "I"], a.finish(), regs=7)
    return s1, s2


# ===================================================================================== the analysis app skeleton
class App:
    """One analysis app: its dex, its members and an oracle `code(**inputs)` for its answer."""

    def __init__(self, tag, pkg):
        self.tag = tag
        self.pkg = pkg                       # dotted package
        self.base = "L" + pkg.replace(".", "/") + "/"
        self.rng = random.Random("r04-synth:" + tag)
        self.d = DexWriter()

    def c(self, simple):
        return self.base + simple + ";"


def _release(app, token_midx, f1_spec, fin_spec, final_xor):
    """Release.code(Context) / proof(Context) / the static Release.ctx; token() is the app's own."""
    d, rel = app.d, app.c("Release")
    d.cls(rel)
    d.static_field(rel, CTX, "ctx")
    ctx = d.f(rel, CTX, "ctx")
    f1 = define_mixer(d, app.c("Mix"), "f1", f1_spec)
    fin = define_mixer(d, app.c("Core"), "fin" + app.tag.title().replace("_", "")[:6], fin_spec)
    a = Asm()
    a.op("sput-object", 9, ctx)
    a.op("invoke-static", token_midx, []).op("move-result-wide", 0)
    a.op("invoke-static", f1, [0, 1]).op("move-result-wide", 0)
    a.op("invoke-static", fin, [0, 1]).op("move-result-wide", 0)
    a.op("const-wide", 5, final_xor).op("xor-long/2addr", 0, 5)
    a.op("new-instance", 2, d.t(SB)).op("invoke-direct", d.m(SB, "<init>"), [2])
    a.op("const-string", 3, d.s("ANS-")).op("invoke-virtual", d.m(SB, "append", SB, [STR]), [2, 3])
    a.op("const-string", 3, d.s("0123456789ABCDEF")).op("const/16", 4, 60)
    a.label("hex")
    a.op("ushr-long", 5, 0, 4).op("long-to-int", 7, 5).op("and-int/lit8", 7, 7, 15)
    a.op("invoke-virtual", d.m(STR, "charAt", "C", ["I"]), [3, 7]).op("move-result", 8)
    a.op("invoke-virtual", d.m(SB, "append", SB, ["C"]), [2, 8])
    a.op("add-int/lit8", 4, 4, -4).op("if-gez", 4, "hex")
    a.op("invoke-virtual", d.m(SB, "toString", STR), [2]).op("move-result-object", 2).op("return-object", 2)
    d.method(rel, "code", STR, [CTX], a.finish(), regs=10)
    a = Asm()
    a.op("sput-object", 4, ctx)
    a.op("invoke-static", token_midx, []).op("move-result-wide", 0)
    a.op("invoke-static", d.m(LONG, "toHexString", STR, ["J"]), [0, 1]).op("move-result-object", 0)
    a.op("return-object", 0)
    d.method(rel, "proof", STR, [CTX], a.finish(), regs=5)
    return lambda token: ans_of(mix_eval(fin_spec, mix_eval(f1_spec, token)) ^ final_xor)


def _token(app, seed, steps):
    """Release.token()J: const-wide seed, then each (J)J method of `steps` [midx] in turn."""
    a = Asm()
    a.op("const-wide", 0, seed)
    for midx in steps:
        a.op("invoke-static", midx, [0, 1]).op("move-result-wide", 0)
    a.op("return-wide", 0)
    return app.d.method(app.c("Release"), "token", "J", [], a.finish(), regs=4)


def _activity(app, text):
    """MainActivity: onCreate shows a TextView (app code the chain never runs, as a real app carries)."""
    d, act = app.d, app.c("MainActivity")
    d.cls(act, super_="Landroid/app/Activity;")
    a = Asm()
    a.op("invoke-direct", d.m("Landroid/app/Activity;", "<init>"), [0]).op("return-void")
    d.method(act, "<init>", "V", [], a.finish(), regs=1, flags=ACC_PUBLIC | ACC_CONSTRUCTOR)
    tv = "Landroid/widget/TextView;"
    a = Asm()
    a.op("invoke-super", d.m("Landroid/app/Activity;", "onCreate", "V", ["Landroid/os/Bundle;"]), [2, 3])
    a.op("new-instance", 0, d.t(tv)).op("invoke-direct", d.m(tv, "<init>", "V", [CTX]), [0, 2])
    a.op("const-string", 1, d.s(text))
    a.op("invoke-virtual", d.m(tv, "setText", "V", ["Ljava/lang/CharSequence;"]), [0, 1])
    a.op("invoke-virtual", d.m("Landroid/app/Activity;", "setContentView", "V", ["Landroid/view/View;"]), [2, 0])
    a.op("return-void")
    d.method(act, "onCreate", "V", ["Landroid/os/Bundle;"], a.finish(), regs=4, flags=0x4)


# ---------------------------------------------------------------- d26_tt / d26_m10: the split-asset reader chain
def reader_units(d, ctx_field):
    """Assets.readSplit(String)[B, the judged reader's code shape: walk splitSourceDirs, open each with ZipFile,
    getEntry("assets/" + name), read up to 16 bytes into a new byte[16]; none holds it: FileNotFoundException. Its
    registers, literals and framework references are what split_bundle.JUDGED_READERS fingerprints."""
    fnf = "Ljava/io/FileNotFoundException;"
    a = Asm()
    a.op("sget-object", 0, ctx_field)
    a.op("invoke-virtual", d.m(CTX, "getApplicationInfo", AI), [0]).op("move-result-object", 0)
    a.op("iget-object", 0, 0, d.f(AI, "[Ljava/lang/String;", "splitSourceDirs"))
    a.op("array-length", 1, 0).op("const/4", 2, 0)
    a.label("loop")
    a.op("if-ge", 2, 1, "missing")
    a.op("aget-object", 3, 0, 2).op("add-int/lit8", 2, 2, 1)
    a.op("new-instance", 4, d.t(ZF)).op("invoke-direct", d.m(ZF, "<init>", "V", [STR]), [4, 3])
    a.op("new-instance", 5, d.t(SB)).op("invoke-direct", d.m(SB, "<init>"), [5])
    a.op("const-string", 6, d.s("assets/"))
    app_ = d.m(SB, "append", SB, [STR])
    a.op("invoke-virtual", app_, [5, 6]).op("invoke-virtual", app_, [5, 12])
    a.op("invoke-virtual", d.m(SB, "toString", STR), [5]).op("move-result-object", 5)
    a.op("invoke-virtual", d.m(ZF, "getEntry", ZE, [STR]), [4, 5]).op("move-result-object", 5)
    a.op("if-eqz", 5, "next")
    a.op("invoke-virtual", d.m(ZF, "getInputStream", IS, [ZE]), [4, 5]).op("move-result-object", 6)
    a.op("const/16", 7, 16).op("new-array", 7, 7, d.t("[B")).op("const/4", 8, 0)
    a.label("read")
    a.op("array-length", 9, 7).op("sub-int/2addr", 9, 8).op("if-lez", 9, "done")
    a.op("invoke-virtual", d.m(IS, "read", "I", ["[B", "I", "I"]), [6, 7, 8, 9]).op("move-result", 9)
    a.op("if-ltz", 9, "done")
    a.op("add-int/2addr", 8, 9).op("goto", "read")
    a.label("done")
    a.op("invoke-virtual", d.m(IS, "close"), [6]).op("invoke-virtual", d.m(ZF, "close"), [4]).op("return-object", 7)
    a.label("next")
    a.op("invoke-virtual", d.m(ZF, "close"), [4]).op("goto", "loop")
    a.label("missing")
    a.op("new-instance", 0, d.t(fnf)).op("invoke-direct", d.m(fnf, "<init>"), [0]).op("throw", 0)
    return a.finish()


def _merge_units(d, reader, asset, k_mul, k_xor, k_mul2):
    """Util.merge(J)J: the reader's 16 bytes as two big-endian u64 (hi = bytes 0-7, lo = 8-15); x ^= hi,
    x = rotl(x, 55), x *= k_mul, x += lo, x ^= k_xor, x = rotl(x, 32), x *= k_mul2. Parameter v12:v13."""
    a = Asm()
    a.op("move-wide", 0, 12)
    a.op("const-string", 2, d.s(asset)).op("invoke-static", reader, [2]).op("move-result-object", 2)
    a.op("const-wide", 3, 0).op("const-wide", 5, 0).op("const/4", 7, 0).op("const/16", 8, 8)
    a.label("bytes")
    a.op("aget-byte", 9, 2, 7).op("and-int/lit16", 9, 9, 255)
    a.op("shl-long/2addr", 3, 8).op("int-to-long", 10, 9).op("or-long/2addr", 3, 10)
    a.op("add-int/lit8", 9, 7, 8).op("aget-byte", 9, 2, 9).op("and-int/lit16", 9, 9, 255)
    a.op("shl-long/2addr", 5, 8).op("int-to-long", 10, 9).op("or-long/2addr", 5, 10)
    a.op("add-int/lit8", 7, 7, 1).op("if-lt", 7, 8, "bytes")
    a.op("xor-long/2addr", 0, 3)
    a.op("const/16", 8, 55).op("const/16", 9, 9).op("shl-long", 3, 0, 8).op("ushr-long", 0, 0, 9)
    a.op("or-long/2addr", 0, 3)
    a.op("const-wide", 3, k_mul).op("mul-long/2addr", 0, 3).op("add-long/2addr", 0, 5)
    a.op("const-wide", 3, k_xor).op("xor-long/2addr", 0, 3)
    a.op("const/16", 8, 32).op("const/16", 9, 32).op("shl-long", 5, 0, 8).op("ushr-long", 3, 0, 9)
    a.op("or-long", 0, 5, 3)
    a.op("const-wide", 3, k_mul2).op("mul-long/2addr", 0, 3).op("return-wide", 0)
    return a.finish()


def _scan_units(d, s1, s2, split_index, p2, p1, k1, k2, k3, k4, k5, k6):
    """Guard.scan(J)J (parameter v15:v16): p = s2(...), q = s1(...), i = splitIndex(p, q) = (p << 4) | q;
    x ^= (long(p)*k1) ^ (long(q)*k2); x *= k3; x += long(i)*k4; x *= k5; x ^= k6."""
    a = Asm()
    a.op("move-wide", 0, 15)
    for reg, args, fn in ((4, p2, s2), (5, p1, s1)):
        for r, v in zip((11, 12, 13, 14), args):
            a.op("const/16", r, v)
        a.op("invoke-static", fn, [11, 12, 13, 14]).op("move-result", reg)
    a.op("invoke-static", split_index, [4, 5]).op("move-result", 8)
    a.op("const-wide", 2, 0)
    a.op("int-to-long", 9, 4).op("const-wide", 11, k1).op("mul-long/2addr", 9, 11).op("xor-long/2addr", 2, 9)
    a.op("int-to-long", 9, 5).op("const-wide", 11, k2).op("mul-long/2addr", 9, 11).op("xor-long/2addr", 2, 9)
    a.op("xor-long/2addr", 0, 2)
    a.op("const-wide", 9, k3).op("mul-long/2addr", 0, 9)
    a.op("int-to-long", 2, 8).op("const-wide", 9, k4).op("mul-long/2addr", 2, 9).op("add-long/2addr", 0, 2)
    a.op("const-wide", 2, k5).op("mul-long/2addr", 0, 2)
    a.op("const-wide", 2, k6).op("xor-long/2addr", 0, 2)
    a.op("return-wide", 0)
    return a.finish()


def _scan_eval(x, p2, p1, k1, k2, k3, k4, k5, k6):
    p, q = probe_s2(*p2), probe_s1(*p1)
    i = s32((p << 4) | q)
    x ^= ((p * k1) ^ (q * k2)) & M64
    x = (x * k3) & M64
    x = (x + (i * k4)) & M64
    x = (x * k5) & M64
    return x ^ k6


def _merge_eval(x, buf, k_mul, k_xor, k_mul2):
    hi, lo = int.from_bytes(buf[:8], "big"), int.from_bytes(buf[8:16], "big")
    x ^= hi
    x = _rotl(x, 55)
    x = (x * k_mul + lo) & M64
    x ^= k_xor
    x = _rotl(x, 32)
    return (x * k_mul2) & M64


def split_reader_buffer(asset):
    """What the reader hands back for an asset: its first 16 bytes, zeros for the rest (None: no asset)."""
    return None if asset is None else (bytes(asset[:16]) + bytes(16))[:16]


def build_split_asset_app(tag, pkg, asset_name="huntress_feature.bin"):
    """The d26_tt / d26_m10 shape. Returns (dex bytes, oracle(asset bytes) -> code)."""
    app = App(tag, pkg)
    d, r = app.d, app.rng
    rel = app.c("Release")
    d.cls(rel)
    ctx = d.f(rel, CTX, "ctx")
    reader = d.method(app.c("Assets"), "readSplit", "[B", [STR], reader_units(d, ctx), regs=13)
    s1, s2 = define_probes(d, app.c("Probe"))
    a = Asm()
    a.op("shl-int/lit8", 0, 1, 4).op("or-int/2addr", 0, 2).op("return", 0)
    split_index = d.method(app.c("SplitDecision"), "splitIndex", "I", ["I", "I"], a.finish(), regs=3)
    p2, p1 = _probe_args(r, probe_s2), _probe_args(r, probe_s1)
    ks = [r.getrandbits(64) for _ in range(6)]
    scan = d.method(app.c("Guard"), "scanBase", "J", ["J"],
                    _scan_units(d, s1, s2, split_index, p2, p1, *ks), regs=17)
    mk = (r.getrandbits(64) | 1, r.getrandbits(64), r.getrandbits(64) | 1)
    merge = d.method(app.c("Util"), "mergeFeature", "J", ["J"], _merge_units(d, reader, asset_name, *mk), regs=14)
    mix_base = rand_spec(r, 4)
    mixb = define_mixer(d, app.c("Core"), "mixBase", mix_base)
    seed = r.getrandbits(64)
    token = _token(app, seed, [mixb, scan, merge])
    tail = _release(app, token, rand_spec(r, 6), rand_spec(r, 5), r.getrandbits(64))
    _activity(app, "Split Decision (synthetic)")
    dex = d.build()

    def oracle(asset):
        buf = split_reader_buffer(asset)
        if buf is None:
            return None
        x = mix_eval(mix_base, seed)
        x = _scan_eval(x, p2, p1, *ks)
        x = _merge_eval(x, buf, *mk)
        return tail(x)
    return dex, oracle


# ---------------------------------------------------------------- d25_set6 / d23_set5: a JNI leg in libarena.so
def jni_mangle(s):
    out = []
    for ch in s:
        if ch.isalnum() and ord(ch) < 128:
            out.append(ch)
        else:
            out.append({"/": "_", ".": "_", "_": "_1", ";": "_2", "[": "_3"}.get(ch) or "_0%04x" % ord(ch))
    return "".join(out)


def jni_symbol(cls_desc, name):
    return "Java_" + jni_mangle(cls_desc[1:-1]) + "_" + jni_mangle(name)


# x86-64 machine code for the leg's ops on rax (rcx scratch); the encodings are checked against capstone by the tests
def x86_ops(spec):
    b = bytearray()
    for op, k in spec:
        if op in ("xor", "add", "mul"):
            b += b"\x48\xb9" + struct.pack("<Q", k & M64)                         # movabs rcx, k
            b += {"xor": b"\x48\x31\xc8", "add": b"\x48\x01\xc8", "mul": b"\x48\x0f\xaf\xc1"}[op]
        elif op == "rotl":
            b += b"\x48\xc1\xc0" + bytes([k])                                        # rol rax, k
        elif op == "xshr":
            b += b"\x48\x89\xc1" + b"\x48\xc1\xe9" + bytes([k]) + b"\x48\x31\xc8"   # mov rcx,rax; shr rcx,k; xor
        else:  # pragma: no cover
            raise ValueError(op)
    return bytes(b)


def x86_straight(spec):
    """(JNIEnv*, jclass, jlong x) -> jlong: rax = x (rdx), the ops, ret."""
    return b"\x48\x89\xd0" + x86_ops(spec) + b"\xc3"


def x86_gated(spec, low):
    """(JNIEnv*, jclass, jlong x, jint n) -> jlong: n <= 0xffff or (n & 0xffff) != low: return 0 (the gate);
    else rax = x, the ops, ret."""
    body = b"\x48\x89\xd0" + x86_ops(spec) + b"\xc3"
    fail = len(body)
    head_len = 6 + 2 + 3 + 6 + 2
    pre = (b"\x81\xf9\xff\xff\x00\x00"                          # cmp ecx, 0xffff
           + b"\x7e" + bytes([head_len - 8 + fail])             # jle fail
           + b"\x0f\xb7\xf1"                                     # movzx esi, cx
           + b"\x81\xfe" + struct.pack("<I", low)              # cmp esi, low
           + b"\x75" + bytes([fail]))                            # jne fail
    assert len(pre) == head_len and fail < 128
    return pre + body + b"\x31\xc0\xc3"                         # fail: xor eax, eax; ret


def gated_eval(spec, low, x, n):
    if s32(n) <= 0xFFFF or (n & 0xFFFF) != low:
        return 0
    return mix_eval(spec, x)


def _sysv_hash(name):
    h = 0
    for c in name.encode():
        h = ((h << 4) + c) & M32
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & M32
    return h


def elf_so(funcs, soname="libarena.so", machine=62):
    """An ELF64 little-endian ET_DYN exporting `funcs` [(name, code)] as sized global FUNC symbols, laid out as a
    linker does: PT_LOAD R (headers, .hash, .dynsym, .dynstr), PT_LOAD R+X (.text), PT_LOAD RW (.dynamic) with
    PT_DYNAMIC, DT_HASH/DT_SYMTAB/DT_STRTAB/DT_STRSZ/DT_SYMENT/DT_SONAME naming the very sections."""
    names = [n for n, _ in funcs]
    dynstr = bytearray(b"\0")
    name_off = {}
    for n in [soname] + names:
        name_off[n] = len(dynstr)
        dynstr += n.encode() + b"\0"
    nsym = len(funcs) + 1
    # .hash: one bucket per symbol, chains through the symbol table
    nbucket = max(1, len(funcs))
    buckets, chains = [0] * nbucket, [0] * nsym
    for i, n in enumerate(names, 1):
        b = _sysv_hash(n) % nbucket
        chains[i], buckets[b] = buckets[b], i
    hash_ = struct.pack("<II", nbucket, nsym) + struct.pack("<%dI" % nbucket, *buckets) + struct.pack("<%dI" % nsym,
                                                                                                    *chains)
    phnum = 4
    off = 64 + 56 * phnum
    hash_off = off
    dynsym_off = (hash_off + len(hash_) + 7) & ~7
    dynstr_off = dynsym_off + 24 * nsym
    ro_end = dynstr_off + len(dynstr)
    text_off = 0x1000
    text = bytearray()
    sym_addr = []
    for _, code in funcs:
        while len(text) % 16:
            text.append(0xCC)
        sym_addr.append(text_off + len(text))
        text += code
    dyn_off = (text_off + len(text) + 0xFFF) & ~0xFFF
    dyn_vaddr = dyn_off
    dyn_entries = [(14, name_off[soname]), (4, hash_off), (5, dynstr_off), (6, dynsym_off), (10, len(dynstr)),
                   (11, 24), (0, 0)]
    dynamic = b"".join(struct.pack("<qQ", t, v) for t, v in dyn_entries)
    shstr = bytearray(b"\0")
    sec_name = {}
    for n in (".hash", ".dynsym", ".dynstr", ".text", ".dynamic", ".shstrtab"):
        sec_name[n] = len(shstr)
        shstr += n.encode() + b"\0"
    shstr_off = dyn_off + len(dynamic)
    sh_off = (shstr_off + len(shstr) + 7) & ~7
    shnum = 7
    out = bytearray(sh_off + 64 * shnum)
    # ELF header
    out[0:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    struct.pack_into("<HHIQQQIHHHHHH", out, 16, 3, machine, 1, 0, 64, sh_off, 0, 64, 56, phnum, 64, shnum, 6)
    # program headers: (type, flags, offset, vaddr, filesz, memsz, align)
    phs = [(1, 4, 0, 0, ro_end, ro_end, 0x1000), (1, 5, text_off, text_off, len(text), len(text), 0x1000),
           (1, 6, dyn_off, dyn_vaddr, len(dynamic), len(dynamic), 0x1000),
           (2, 6, dyn_off, dyn_vaddr, len(dynamic), len(dynamic), 8)]
    for i, (pt, pf, po, pv, fs, ms, al) in enumerate(phs):
        struct.pack_into("<IIQQQQQQ", out, 64 + 56 * i, pt, pf, po, pv, pv, fs, ms, al)
    out[hash_off:hash_off + len(hash_)] = hash_
    for i, (n, code) in enumerate(funcs, 1):
        # st_name, st_info (GLOBAL << 4 | FUNC), st_other, st_shndx (.text = 4), st_value, st_size
        struct.pack_into("<IBBHQQ", out, dynsym_off + 24 * i, name_off[n], 0x12, 0, 4, sym_addr[i - 1], len(code))
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    out[text_off:text_off + len(text)] = text
    out[dyn_off:dyn_off + len(dynamic)] = dynamic
    out[shstr_off:shstr_off + len(shstr)] = shstr
    # section headers: name, type, flags, addr, offset, size, link, info, addralign, entsize
    secs = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (sec_name[".hash"], 5, 2, hash_off, hash_off, len(hash_), 2, 0, 8, 4),
            (sec_name[".dynsym"], 11, 2, dynsym_off, dynsym_off, 24 * nsym, 3, 1, 8, 24),
            (sec_name[".dynstr"], 3, 2, dynstr_off, dynstr_off, len(dynstr), 0, 0, 1, 0),
            (sec_name[".text"], 1, 6, text_off, text_off, len(text), 0, 0, 16, 0),
            (sec_name[".dynamic"], 6, 3, dyn_vaddr, dyn_off, len(dynamic), 3, 0, 8, 16),
            (sec_name[".shstrtab"], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)]
    for i, s in enumerate(secs):
        struct.pack_into("<IIQQQQIIQQ", out, sh_off + 64 * i, *s)
    return bytes(out)


def build_native_app(tag, pkg, cls_simple, gated):
    """d25_set6 (gated: nativeShare(long, int)) or d23_set5 (straight: nativeShare(long)). Returns (dex, so, code)."""
    app = App(tag, pkg)
    d, r = app.d, app.rng
    jcls = app.c(cls_simple)
    d.cls(jcls)
    a = Asm()
    a.op("const-string", 0, d.s("arena"))
    a.op("invoke-static", d.m("Ljava/lang/System;", "loadLibrary", "V", [STR]), [0]).op("return-void")
    d.method(jcls, "<clinit>", "V", [], a.finish(), regs=1, flags=ACC_STATIC | ACC_CONSTRUCTOR)
    a = Asm()
    a.op("const-string", 0, d.s("synthetic JNI boundary")).op("return-object", 0)
    d.method(jcls, "describe", STR, [], a.finish(), regs=1)
    params = ["J", "I"] if gated else ["J"]
    native = d.method(jcls, "nativeShare", "J", params, None, flags=ACC_PUBLIC | ACC_STATIC | ACC_NATIVE)
    leg = rand_spec(r, 6)
    low = r.randrange(0x100, 0xFFFF)
    gate = 0x10000 * r.randrange(1, 8) + low
    a = Asm()
    a.op("move-wide", 0, 4)
    if gated:
        a.op("const", 2, gate).op("invoke-static", native, [0, 1, 2])
    else:
        a.op("invoke-static", native, [0, 1])
    a.op("move-result-wide", 0).op("return-wide", 0)
    nat = d.method(app.c("Util"), "nativeLength", "J", ["J"], a.finish(), regs=6)
    pre, post = rand_spec(r, 4), rand_spec(r, 5)
    mpre = define_mixer(d, app.c("Util"), "mixNarrow", pre)
    mpost = define_mixer(d, app.c("Guard"), "sealNative", post)
    seed = r.getrandbits(64)
    token = _token(app, seed, [mpre, nat, mpost])
    tail = _release(app, token, rand_spec(r, 6), rand_spec(r, 6), r.getrandbits(64))
    _activity(app, "Integrity Signals (synthetic)")
    dex = d.build()
    code = x86_gated(leg, low) if gated else x86_straight(leg)
    decoy = b"\x31\xc0\xc3"                                     # another export: xor eax, eax; ret
    so = elf_so([("huntress_arena_day", b"\xb8" + struct.pack("<I", 16 if gated else 15) + b"\xc3"),
                 (jni_symbol(jcls, "nativeShare"), code), (jni_symbol(jcls, "nativeEvidence"), decoy)])
    x = mix_eval(pre, seed)
    leg_value = gated_eval(leg, low, x, gate) if gated else mix_eval(leg, x)
    assert leg_value != 0, "the gate must pass with the chain's own argument"
    answer = tail(mix_eval(post, leg_value))
    return dex, so, answer


# ---------------------------------------------------------------- d25_set7: reflection over Maze.m<k>
def build_reflection_app(tag, pkg):
    """ReflectionMaze.dispatch(I)I is a packed-switch {0: k0, 1: k1}; Util.routeMaze(J)J calls Maze.m<k1> then
    Maze.m<k0> through Class.forName / getDeclaredMethod(name, [Long.TYPE]) / Method.invoke(null, [Long]). Returns
    (dex, code)."""
    app = App(tag, pkg)
    d, r = app.d, app.rng
    maze = app.c("Maze")
    mazes = [rand_spec(r, 5) for _ in range(8)]
    for i, spec in enumerate(mazes):
        define_mixer(d, maze, "m%d" % i, spec)
    k0, k1 = r.sample(range(8), 2)
    a = Asm()
    a.op("packed-switch", 1, "sw").op("const/4", 0, -1).op("return", 0)
    a.label("c0")
    a.op("const/4", 0, k0).op("return", 0)
    a.label("c1")
    a.op("const/4", 0, k1).op("return", 0)
    a.packed_payload("sw", 0, ["c0", "c1"])
    dispatch = d.method(app.c("ReflectionMaze"), "dispatch", "I", ["I"], a.finish(), regs=2)
    a = Asm()
    a.op("move-wide", 0, 10)
    for sel in (1, 0):
        a.op("const/4", 2, sel).op("invoke-static", dispatch, [2]).op("move-result", 2)
        a.op("new-instance", 3, d.t(SB)).op("invoke-direct", d.m(SB, "<init>"), [3])
        a.op("const-string", 4, d.s("m")).op("invoke-virtual", d.m(SB, "append", SB, [STR]), [3, 4])
        a.op("invoke-virtual", d.m(SB, "append", SB, ["I"]), [3, 2])
        a.op("invoke-virtual", d.m(SB, "toString", STR), [3]).op("move-result-object", 3)
        a.op("const-string", 4, d.s(pkg + ".Maze"))
        a.op("invoke-static", d.m(CLASS, "forName", CLASS, [STR]), [4]).op("move-result-object", 4)
        a.op("const/4", 5, 1).op("new-array", 5, 5, d.t("[Ljava/lang/Class;"))
        a.op("sget-object", 6, d.f(LONG, CLASS, "TYPE")).op("const/4", 7, 0).op("aput-object", 6, 5, 7)
        a.op("invoke-virtual", d.m(CLASS, "getDeclaredMethod", METHOD, [STR, "[Ljava/lang/Class;"]), [4, 3, 5])
        a.op("move-result-object", 4)
        a.op("invoke-static", d.m(LONG, "valueOf", LONG, ["J"]), [0, 1]).op("move-result-object", 6)
        a.op("const/4", 5, 1).op("new-array", 5, 5, d.t("[Ljava/lang/Object;")).op("aput-object", 6, 5, 7)
        a.op("const/4", 6, 0)
        a.op("invoke-virtual", d.m(METHOD, "invoke", OBJ, [OBJ, "[Ljava/lang/Object;"]), [4, 6, 5])
        a.op("move-result-object", 4).op("check-cast", 4, d.t(LONG))
        a.op("invoke-virtual", d.m(LONG, "longValue", "J"), [4]).op("move-result-wide", 0)
    a.op("return-wide", 0)
    route = d.method(app.c("Util"), "routeMaze", "J", ["J"], a.finish(), regs=12)
    pre, post = rand_spec(r, 4), rand_spec(r, 5)
    mpre = define_mixer(d, app.c("Util"), "mixHop", pre)
    mpost = define_mixer(d, app.c("Core"), "mixHop2", post)
    seed = r.getrandbits(64)
    token = _token(app, seed, [mpre, route, mpost])
    tail = _release(app, token, rand_spec(r, 6), rand_spec(r, 5), r.getrandbits(64))
    _activity(app, "Reflection Maze (synthetic)")
    x = mix_eval(pre, seed)
    x = mix_eval(mazes[k0], mix_eval(mazes[k1], x))
    return d.build(), tail(mix_eval(post, x))


# ---------------------------------------------------------------- d26_base: codec split, no chain
def build_split_doc_dex(pkg):
    app = App("split-doc", pkg)
    d = app.d
    a = Asm()
    a.op("const-string", 0, d.s("DAY-26:split_apk:base and feature split correlation (synthetic)"))
    a.op("return-object", 0)
    d.method(app.c("SplitDecision"), "describe", STR, [], a.finish(), regs=1)
    _activity(app, "Split Decision (synthetic)")
    return d.build()


# ===================================================================================== compiled AndroidManifest.xml
ANDROID_NS = "http://schemas.android.com/apk/res/android"
_ATTR_IDS = {"versionCode": 0x0101021B, "versionName": 0x0101021C, "minSdkVersion": 0x0101020C,
             "targetSdkVersion": 0x01010270, "name": 0x01010003, "label": 0x01010001, "hasCode": 0x0101000C,
             "exported": 0x01010010}


def axml(elements):
    """A compiled XML document. elements: [(depth, tag, [(attr, value)])] in document order; an attribute in
    _ATTR_IDS is android:-namespaced (resource map), others (`package`, `split`) carry no namespace. A str value is
    TYPE_STRING, a bool TYPE_INT_BOOLEAN, an int TYPE_INT_DEC."""
    attr_names = [n for n in _ATTR_IDS if any(n == k for _, _, at in elements for k, _ in at)]
    strings = list(attr_names)

    def si(x):
        if x not in strings:
            strings.append(x)
        return strings.index(x)
    si("android"), si(ANDROID_NS)
    for _, tag, at in elements:
        si(tag)
        for k, v in at:
            si(k)
            if isinstance(v, str):
                si(v)
    body = bytearray()
    line = 1

    def chunk(typ, hsize, payload):
        return struct.pack("<HHI", typ, hsize, 8 + len(payload)) + payload
    body += chunk(0x0100, 16, struct.pack("<IiII", line, -1, si("android"), si(ANDROID_NS)))
    stack = []
    for depth, tag, at in elements:
        while len(stack) > depth:
            body += chunk(0x0103, 16, struct.pack("<Iiii", line, -1, -1, si(stack.pop())))
        attrs = bytearray()
        for k, v in sorted(at, key=lambda kv: _ATTR_IDS.get(kv[0], 0)):
            ns = si(ANDROID_NS) if k in _ATTR_IDS else -1
            if isinstance(v, bool):
                raw, typ, data = -1, 0x12, 0xFFFFFFFF if v else 0
            elif isinstance(v, int):
                raw, typ, data = -1, 0x10, v & M32
            else:
                raw, typ, data = si(v), 0x03, si(v)
            attrs += struct.pack("<iiiHBBI", ns, si(k), raw, 8, 0, typ, data)
        body += chunk(0x0102, 16, struct.pack("<IiiiHHHHHH", line, -1, -1, si(tag), 20, 20, len(at), 0, 0, 0)
                      + bytes(attrs))
        stack.append(tag)
        line += 1
    while stack:
        body += chunk(0x0103, 16, struct.pack("<Iiii", line, -1, -1, si(stack.pop())))
    body += chunk(0x0101, 16, struct.pack("<IiII", line, -1, si("android"), si(ANDROID_NS)))
    # string pool (UTF-16)
    data, offs = bytearray(), []
    for s in strings:
        offs.append(len(data))
        data += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\0\0"
    _align(data, 4)
    start = 28 + 4 * len(strings)
    pool = struct.pack("<IIIII", len(strings), 0, 0, start, 0) + b"".join(struct.pack("<I", o) for o in offs) + data
    pool = struct.pack("<HHI", 0x0001, 28, 8 + len(pool)) + pool
    resmap = b"".join(struct.pack("<I", _ATTR_IDS[n]) for n in attr_names)
    resmap = struct.pack("<HHI", 0x0180, 8, 8 + len(resmap)) + resmap
    doc = pool + resmap + bytes(body)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(doc)) + doc


def base_manifest(pkg, label):
    return axml([(0, "manifest", [("versionCode", 26), ("versionName", "1.0"), ("package", pkg)]),
                 (1, "uses-sdk", [("minSdkVersion", 23), ("targetSdkVersion", 23)]),
                 (1, "application", [("label", label)]),
                 (2, "activity", [("name", ".MainActivity"), ("exported", True)])])


def split_manifest(pkg, split):
    return axml([(0, "manifest", [("versionCode", 26), ("versionName", "1.0"), ("package", pkg), ("split", split)]),
                 (1, "uses-sdk", [("minSdkVersion", 23), ("targetSdkVersion", 23)]),
                 (1, "application", [("hasCode", False)])])


# ===================================================================================== APK zip
STORED = (".bin", ".so", ".png", ".arsc")


def apk(members):
    """An APK: AndroidManifest.xml first, then the members in order, then META-INF/MANIFEST.MF (SHA-256 digests)."""
    import base64
    out = io.BytesIO()
    names = [n for n, _ in members]
    assert names[0] == "AndroidManifest.xml" and len(set(names)) == len(names), names
    mf = "Manifest-Version: 1.0\r\nCreated-By: tests/day27_mobile_splits_synth.py\r\n\r\n"
    for n, b in members:
        mf += "Name: %s\r\nSHA-256-Digest: %s\r\n\r\n" % (n, base64.b64encode(hashlib.sha256(b).digest()).decode())
    with zipfile.ZipFile(out, "w") as z:
        for n, b in list(members) + [("META-INF/MANIFEST.MF", mf.encode())]:
            zi = zipfile.ZipInfo(n, date_time=(2026, 10, 26, 9, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED if n.endswith(STORED) else zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, b)
    return out.getvalue()


def puzzle_v2(day, build):
    return json.dumps({"schema": "huntress.mobile.puzzle.v2", "day": day, "codec": "analysis", "build": build},
                      separators=(",", ":")).encode()


def split_doc(parts, order):
    return json.dumps({"schema": "huntress.mobile.puzzle.v1", "day": 26, "codec": "split", "data": "", "parts": parts,
                       "order": order}, separators=(",", ":")).encode()


def feature_doc(part, index, feature="arena_feature"):
    return json.dumps({"codec": "split", "day": 26, "feature": feature, "part": part, "part_index": index},
                      separators=(",", ":"), sort_keys=True).encode()


def synthetic_code(tag):
    return "ANS-" + hashlib.sha256(("r04-synth:" + tag).encode()).hexdigest()[:16].upper()


# ===================================================================================== the fixture set
_CACHE = {}

PKG = {"d26_base": "com.huntress.mobile.d26.vsynbase0001", "d26_tt": "com.huntress.mobile.d26.vsyntt000002",
       "d26_m10": "com.huntress.mobile.d26.vsynm1000003", "d25_set6": "com.huntress.mobile.d16.vsynnat00004",
       "d23_set5": "com.huntress.mobile.d15.vsynnat00005", "d25_set7": "com.huntress.mobile.d19.vsynref00006"}


def _build():
    files, truths, oracles = {}, {}, {}
    # d26_base: codec split, part 0 empty in the base and carried by the feature split
    code = synthetic_code("d26_base")
    lens, order = [9, 5, 6], [2, 0, 1]
    seq, i = [], 0
    for n in lens:
        seq.append(code[i:i + n])
        i += n
    parts = [seq[o] for o in order]
    pkg = PKG["d26_base"]
    files["d26_base.base.apk"] = apk([("AndroidManifest.xml", base_manifest(pkg, "Split Decision")),
                                      (PUZZLE, split_doc([""] + parts[1:], order)),
                                      ("classes.dex", build_split_doc_dex(pkg))])
    files["d26_base.feature.apk"] = apk([("AndroidManifest.xml", split_manifest(pkg, "arena_feature")),
                                         ("assets/huntress_feature.json", feature_doc(parts[0], 0))])
    truths["d26_base"] = code
    # d26_tt, d26_m10: the split-asset reader chain
    for tag, day_build in (("d26_tt", "5ynt7e3a9b10"), ("d26_m10", "5ynm10c4d2e8")):
        pkg = PKG[tag]
        dex, oracle = build_split_asset_app(tag, pkg)
        asset = random.Random("r04-asset:" + tag).randbytes(16)
        files[tag + ".base.apk"] = apk([("AndroidManifest.xml", base_manifest(pkg, "Split Decision")),
                                        (PUZZLE, puzzle_v2(26, day_build)), ("classes.dex", dex)])
        files[tag + ".feature.apk"] = apk([("AndroidManifest.xml", split_manifest(pkg, "arena_feature")),
                                           (FEATURE_BIN, asset)])
        truths[tag] = oracle(asset)
        oracles[tag] = oracle
    # d25_set6 (gated JNI), d23_set5 (straight-line JNI)
    for tag, fname, cls, gated, day, build in (
            ("d25_set6", "d25_set6_native.apk", "JNIBoundary", True, 16, "5yn6b9ca96e9"),
            ("d23_set5", "d23_set5_native.apk", "NativeLibrarySecrets", False, 15, "5yn5d0a88f0c")):
        pkg = PKG[tag]
        dex, so, answer = build_native_app(tag, pkg, cls, gated)
        files[fname] = apk([("AndroidManifest.xml", base_manifest(pkg, "Integrity Signals")),
                            (PUZZLE, puzzle_v2(day, build)), ("classes.dex", dex), (SO_PATH, so)])
        truths[tag] = answer
    # d25_set7: reflection
    pkg = PKG["d25_set7"]
    dex, answer = build_reflection_app("d25_set7", pkg)
    files["d25_set7_reflection.apk"] = apk([("AndroidManifest.xml", base_manifest(pkg, "Reflection Maze")),
                                            (PUZZLE, puzzle_v2(19, "5yn748643ba7")), ("classes.dex", dex)])
    truths["d25_set7"] = answer
    return files, truths, oracles


def _get():
    if "set" not in _CACHE:
        _CACHE["set"] = _build()
    return _CACHE["set"]


def fixture(name):
    """The bytes of one synthetic package, by the look-ahead's fixture name."""
    files = _get()[0]
    if name not in files:
        raise KeyError("no synthetic fixture %r (have %s)" % (name, ", ".join(sorted(files))))
    return files[name]


def fixture_names():
    return sorted(_get()[0])


def truths():
    """{tag: {"answer": code, "from": how it is known}}: every answer by construction (the Oracle)."""
    return {k: {"answer": v, "from": "ctf/openers/mobile_splits_synth.py: computed from the chain spec"}
            for k, v in _get()[1].items()}


def split_asset_oracle(tag):
    """The d26_tt / d26_m10 chain as a function of the asset's bytes (None: no asset read)."""
    return _get()[2][tag]
