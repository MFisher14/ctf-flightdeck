#!/usr/bin/env python3
"""DEX assembler + synthetic "computed codec" specimens for the Day-24 mobile harness
(tests/test_day24_mobile_computed.py).

The harness is the never-wrong GATE for every Dalvik opcode / library-invoke widening of
solvers/mobile-android/dex_chain_codec.py. These specimens SYNTHESISE `analysis`/computed APKs
whose answer code is produced by a dex method chain built here from a high-level op spec, with the
EXACT same spec applied in Python as the reference oracle. The reader must recover exactly the
oracle code (or stay unsure / None) -- never a wrong plain answer.

Nothing here imports the reader; the harness drives it. This module only knows how to (a) encode
Dalvik bytecode, (b) assemble a minimal classes.dex the reader's parser accepts, (c) wrap it in a
puzzle APK, and (d) compute the reference value of each op spec.
"""
import io
import json
import struct
import zipfile

PUZZLE = "assets/huntress_puzzle.json"
SB = "Ljava/lang/StringBuilder;"
STRING = "Ljava/lang/String;"
INTEGER = "Ljava/lang/Integer;"
LONG = "Ljava/lang/Long;"
CHARACTER = "Ljava/lang/Character;"
OBJ_ARR = "[Ljava/lang/Object;"
CHAR_ARR = "[C"

M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1


def _s32(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def _s64(x):
    x &= M64
    return x - (1 << 64) if x & (1 << 63) else x


# ------------------------------------------------------------------ Python reference oracle
def ref_long_op(v, op, operand):
    """Apply one long-domain op to a 64-bit value exactly as the matching Dalvik opcode does."""
    v &= M64
    y = operand & M64
    if op == "add":
        return (v + y) & M64
    if op == "sub":
        return (v - y) & M64
    if op == "mul":
        return (v * y) & M64
    if op == "div":
        xs, ys = _s64(v), _s64(y)
        q = abs(xs) // abs(ys)
        if (xs < 0) != (ys < 0):
            q = -q
        return q & M64
    if op == "rem":
        xs, ys = _s64(v), _s64(y)
        q = abs(xs) // abs(ys)
        if (xs < 0) != (ys < 0):
            q = -q
        return (xs - q * ys) & M64
    if op == "and":
        return v & y
    if op == "or":
        return v | y
    if op == "xor":
        return v ^ y
    if op == "shl":
        return (v << (operand & 63)) & M64
    if op == "shr":
        return (_s64(v) >> (operand & 63)) & M64
    if op == "ushr":
        return (v >> (operand & 63)) & M64
    if op == "not":
        return (~v) & M64
    if op == "neg":
        return (-v) & M64
    raise ValueError("ref op %s" % op)


_LONG_2ADDR = {"add": 0xbb, "sub": 0xbc, "mul": 0xbd, "div": 0xbe, "rem": 0xbf,
               "and": 0xc0, "or": 0xc1, "xor": 0xc2, "shl": 0xc3, "shr": 0xc4, "ushr": 0xc5}


# ------------------------------------------------------------------ Dalvik assembler
class Asm:
    """Emits a list of 16-bit code units with label/branch/switch fixups."""

    def __init__(self):
        self.u = []
        self.labels = {}
        self.fix = []        # (operand_index, instr_start, label, width)
        self.switches = []   # (instr_start, payload_label, kind, [(key, target_label)])

    def here(self):
        return len(self.u)

    def label(self, name):
        self.labels[name] = len(self.u)

    # -- simple emitters -------------------------------------------------
    def nop(self):
        self.u.append(0x0000)

    def const4(self, dst, val):
        self.u.append(0x12 | (((val & 0xF) << 4 | (dst & 0xF)) << 8))

    def const16(self, dst, val):
        self.u += [0x13 | (dst & 0xFF) << 8, val & 0xFFFF]

    def const32(self, dst, val):
        self.u += [0x14 | (dst & 0xFF) << 8, val & 0xFFFF, (val >> 16) & 0xFFFF]

    def const_wide(self, dst, val):
        self.u += [0x18 | (dst & 0xFF) << 8, val & 0xFFFF, (val >> 16) & 0xFFFF,
                   (val >> 32) & 0xFFFF, (val >> 48) & 0xFFFF]

    def const_string(self, dst, sidx):
        self.u += [0x1a | (dst & 0xFF) << 8, sidx & 0xFFFF]

    def move16(self, dst, src):           # move/16 (0x03): b1 is 0
        self.u += [0x03, dst & 0xFFFF, src & 0xFFFF]

    def move_wide16(self, dst, src):      # move-wide/16 (0x06)
        self.u += [0x06, dst & 0xFFFF, src & 0xFFFF]

    def unop(self, op, dst, src):         # 12x unary (int-to-*, not-*, neg-*, int-to-long, ...)
        self.u.append(op | (((src & 0xF) << 4 | (dst & 0xF)) << 8))

    def binop2(self, op, dst, src):       # 2addr
        self.u.append(op | (((src & 0xF) << 4 | (dst & 0xF)) << 8))

    def binop(self, op, dst, a, b):       # 23x
        self.u += [op | (dst & 0xFF) << 8, ((b & 0xFF) << 8) | (a & 0xFF)]

    def cmp(self, op, dst, a, b):         # 23x
        self.binop(op, dst, a, b)

    def iop(self, op, va, vb, fidx):      # iget*/iput* (22c)
        self.u += [op | (((vb & 0xF) << 4 | (va & 0xF)) << 8), fidx & 0xFFFF]

    def new_instance(self, dst, tidx):
        self.u += [0x22 | (dst & 0xFF) << 8, tidx & 0xFFFF]

    def new_array(self, dst, size_reg, tidx):     # 22c
        self.u += [0x23 | (((size_reg & 0xF) << 4 | (dst & 0xF)) << 8), tidx & 0xFFFF]

    def aput(self, op, src, arr, idx):            # 23x
        self.u += [op | (src & 0xFF) << 8, ((idx & 0xFF) << 8) | (arr & 0xFF)]

    def aget(self, op, dst, arr, idx):            # 23x
        self.u += [op | (dst & 0xFF) << 8, ((idx & 0xFF) << 8) | (arr & 0xFF)]

    def invoke(self, op, meth, regs):             # 35c
        regs = list(regs)
        a = len(regs)
        padded = regs + [0] * (5 - a)
        g = padded[4] & 0xF
        self.u += [op | (((a & 0xF) << 4 | g) << 8), meth & 0xFFFF,
                   (padded[3] & 0xF) << 12 | (padded[2] & 0xF) << 8 | (padded[1] & 0xF) << 4 | (padded[0] & 0xF)]

    def move_result(self, dst):
        self.u.append(0x0a | (dst & 0xFF) << 8)

    def move_result_wide(self, dst):
        self.u.append(0x0b | (dst & 0xFF) << 8)

    def move_result_object(self, dst):
        self.u.append(0x0c | (dst & 0xFF) << 8)

    def return_object(self, src):
        self.u.append(0x11 | (src & 0xFF) << 8)

    def return_void(self):
        self.u.append(0x0e)

    # -- branches (fixups resolved in finish) ----------------------------
    def goto16(self, label):
        start = len(self.u)
        self.u += [0x29, 0]
        self.fix.append((start + 1, start, label, 1))

    def if_testz(self, op, reg, label):           # 21t
        start = len(self.u)
        self.u += [op | (reg & 0xFF) << 8, 0]
        self.fix.append((start + 1, start, label, 1))

    def if_test(self, op, va, vb, label):         # 22t
        start = len(self.u)
        self.u += [op | (((vb & 0xF) << 4 | (va & 0xF)) << 8), 0]
        self.fix.append((start + 1, start, label, 1))

    def switch(self, kind, reg, entries):
        """kind 'packed' (0x2b) or 'sparse' (0x2c). entries: [(key, target_label)]. The payload is
        emitted by finish() after the body and labelled uniquely."""
        start = len(self.u)
        op = 0x2b if kind == "packed" else 0x2c
        plabel = "__sw%d" % len(self.switches)
        self.u += [op | (reg & 0xFF) << 8, 0, 0]
        self.fix.append((start + 1, start, plabel, 2))
        self.switches.append((start, plabel, kind, list(entries)))

    def finish(self):
        """Append switch payloads, resolve all fixups, return the padded code-unit list."""
        for start, plabel, kind, entries in self.switches:
            self.label(plabel)
            if kind == "packed":
                first = entries[0][0]
                self.u += [0x0100, len(entries), first & 0xFFFF, (first >> 16) & 0xFFFF]
                for _k, tl in entries:
                    off = self.labels[tl] - start
                    self.u += [off & 0xFFFF, (off >> 16) & 0xFFFF]
            else:
                self.u += [0x0200, len(entries)]
                for k, _tl in entries:
                    self.u += [k & 0xFFFF, (k >> 16) & 0xFFFF]
                for _k, tl in entries:
                    off = self.labels[tl] - start
                    self.u += [off & 0xFFFF, (off >> 16) & 0xFFFF]
        for operand_index, start, label, width in self.fix:
            off = self.labels[label] - start
            if width == 1:
                self.u[operand_index] = off & 0xFFFF
            else:
                self.u[operand_index] = off & 0xFFFF
                self.u[operand_index + 1] = (off >> 16) & 0xFFFF
        return list(self.u)


class DexBuilder:
    """Assembles a minimal classes.dex the reader's Dex parser + VM accept, with optional proto_ids
    (so a method can carry a shorty for overload resolution) and arbitrary code-unit bodies."""

    def __init__(self):
        self.strings = []
        self.types = []
        self.protos = []          # shorty strings
        self.methods = []         # (cls, name, proto_idx|None)
        self.classes = []         # [(midx, units, regs, outs)]

    def s(self, t):
        if t not in self.strings:
            self.strings.append(t)
        return self.strings.index(t)

    def t(self, t):
        self.s(t)
        if t not in self.types:
            self.types.append(t)
        return self.types.index(t)

    def proto(self, shorty):
        self.s(shorty)
        if shorty not in self.protos:
            self.protos.append(shorty)
        return self.protos.index(shorty)

    def m(self, cls, name, shorty=None):
        self.s(name)
        self.t(cls)
        pidx = self.proto(shorty) if shorty is not None else None
        key = (cls, name, pidx)
        if key not in self.methods:
            self.methods.append(key)
        return self.methods.index(key)

    def add_class(self, methods):
        """methods: [(midx, units, regs, outs)] or [(midx, units, regs, outs, ins)] (ins_size, default 0: a method
        the VM calls with arguments, such as a constructor with its `this`, needs it)"""
        self.classes.append(methods)

    @staticmethod
    def _uleb(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | 0x80 if n else b)
            if not n:
                return bytes(out)

    def build(self):
        hdr = 112
        off = hdr
        str_ids = off
        off += 4 * len(self.strings)
        type_ids = off
        off += 4 * len(self.types)
        proto_ids = off
        off += 12 * len(self.protos)
        meth_ids = off
        off += 8 * len(self.methods)
        class_defs = off
        off += 32 * len(self.classes)
        tail = bytearray()

        def place(b):
            nonlocal off
            o = off
            tail.extend(b)
            off += len(b)
            return o

        code_offs = {}
        for ci, methods in enumerate(self.classes):
            for meth in methods:
                midx, units, regs, outs = meth[:4]
                ins = meth[4] if len(meth) > 4 else 0
                if len(units) & 1:
                    units = list(units) + [0x0000]
                blk = struct.pack("<HHHHII", regs, ins, outs, 0, 0, len(units)) + \
                    struct.pack("<%dH" % len(units), *units)
                code_offs[(ci, midx)] = place(blk)
        class_data_offs = []
        for ci, methods in enumerate(self.classes):
            blk = bytearray()
            blk += self._uleb(0) + self._uleb(0) + self._uleb(len(methods)) + self._uleb(0)
            prev = 0
            for midx, *_rest in sorted(methods, key=lambda x: x[0]):
                blk += self._uleb(midx - prev)
                prev = midx
                blk += self._uleb(0) + self._uleb(code_offs[(ci, midx)])
            class_data_offs.append(place(bytes(blk)))
        str_data_offs = [place(self._uleb(len(t.encode())) + t.encode() + b"\x00") for t in self.strings]

        buf = bytearray(off)
        buf[0:8] = b"dex\n035\x00"
        struct.pack_into("<I", buf, 56, len(self.strings))
        struct.pack_into("<I", buf, 60, str_ids)
        struct.pack_into("<I", buf, 64, len(self.types))
        struct.pack_into("<I", buf, 68, type_ids)
        struct.pack_into("<I", buf, 72, len(self.protos))
        struct.pack_into("<I", buf, 76, proto_ids if self.protos else 0)
        struct.pack_into("<I", buf, 88, len(self.methods))
        struct.pack_into("<I", buf, 92, meth_ids)
        struct.pack_into("<I", buf, 96, len(self.classes))
        struct.pack_into("<I", buf, 100, class_defs)
        for i, o in enumerate(str_data_offs):
            struct.pack_into("<I", buf, str_ids + i * 4, o)
        for i, ts in enumerate(self.types):
            struct.pack_into("<I", buf, type_ids + i * 4, self.strings.index(ts))
        for i, shorty in enumerate(self.protos):
            struct.pack_into("<I", buf, proto_ids + i * 12, self.strings.index(shorty))
        for i, (cls, name, pidx) in enumerate(self.methods):
            struct.pack_into("<H", buf, meth_ids + i * 8, self.types.index(cls))
            struct.pack_into("<H", buf, meth_ids + i * 8 + 2, pidx or 0)
            struct.pack_into("<I", buf, meth_ids + i * 8 + 4, self.strings.index(name))
        for i in range(len(self.classes)):
            struct.pack_into("<I", buf, class_defs + i * 32 + 24, class_data_offs[i])
        head_end = hdr + 4 * len(self.strings) + 4 * len(self.types) + 12 * len(self.protos) + \
            8 * len(self.methods) + 32 * len(self.classes)
        buf[head_end:] = tail
        return bytes(buf)


def apk(members, codec="analysis", extra_doc=None):
    """A zip of `members` plus a puzzle document (schema v2, given codec, NO payload)."""
    doc = {"schema": "huntress.mobile.puzzle.v2", "codec": codec}
    if extra_doc:
        doc.update(extra_doc)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for k, v in members.items():
            zf.writestr(k, v)
        zf.writestr(PUZZLE, json.dumps(doc).encode())
    return buf.getvalue()


def member_map(blob):
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


# ------------------------------------------------------------------ chain tails (value -> code)
def emit_tail_format(a, d, vreg, fmtstr):
    """Assemble the code string with String.format(fmtstr, Long.valueOf(value)). fmtstr must
    produce 'ANS-'+16 hex (e.g. 'ANS-%016X'). Returns nothing; leaves the result in a fresh reg
    and returns-object it. Uses registers vreg(+1), and 10..14 as scratch."""
    arr, box, fmt, out, idx = 10, 12, 13, 14, 9
    lv = d.m(LONG, "valueOf", "LJ")           # Long.valueOf(long)->Long
    fmtm = d.m(STRING, "format", "LLL")       # String.format(String,Object[])->String
    tobj = d.t(OBJ_ARR)
    a.const4(idx, 1)
    a.new_array(arr, idx, tobj)               # Object[1]
    a.invoke(0x71, lv, [vreg, vreg + 1])      # invoke-static {v,v+1} Long.valueOf
    a.move_result_object(box)
    a.const4(idx, 0)
    a.aput(0x4d, box, arr, idx)               # aput-object box -> arr[0]
    a.const_string(fmt, d.s(fmtstr))
    a.invoke(0x71, fmtm, [fmt, arr])          # String.format
    a.move_result_object(out)
    a.return_object(out)


def emit_tail_sb_hexupper(a, d, vreg):
    """Assemble 'ANS-'+upper(Long.toHexString(value)) with a StringBuilder, value guaranteed 16
    nibbles by the caller. Exercises StringBuilder.append(String) and String.toUpperCase."""
    sb, pre, hexs, up, out = 4, 5, 6, 7, 8
    sbt = d.t(SB)
    init = d.m(SB, "<init>", "V")
    app = d.m(SB, "append", "LL")
    tostr = d.m(SB, "toString", "L")
    thx = d.m(LONG, "toHexString", "LJ")
    toupper = d.m(STRING, "toUpperCase", "L")
    a.new_instance(sb, sbt)
    a.invoke(0x70, init, [sb])
    a.const_string(pre, d.s("ANS-"))
    a.invoke(0x6e, app, [sb, pre])
    a.move_result_object(sb)
    a.invoke(0x71, thx, [vreg, vreg + 1])
    a.move_result_object(hexs)
    a.invoke(0x6e, app, [sb, hexs])
    a.move_result_object(sb)
    a.invoke(0x6e, tostr, [sb])
    a.move_result_object(out)
    a.invoke(0x6e, toupper, [out])
    a.move_result_object(up)
    a.return_object(up)


def ref_code_16hex(value):
    return "ANS-%016X" % (value & M64)


# ------------------------------------------------------------------ value chains (one 64-bit value in v0)
def value_dex(emit_value, regs=24, fmt="ANS-%016X"):
    """A one-class dex whose method computes a 64-bit value in v0 via emit_value, then assembles the
    code with String.format(fmt, Long.valueOf(v0))."""
    d = DexBuilder()
    a = Asm()
    emit_value(a, d)
    emit_tail_format(a, d, 0, fmt)
    units = a.finish()
    run = d.m("Lcom/huntress/C;", "run", "L")
    d.add_class([(run, units, regs, 5)])
    return d.build()


def string_dex(emit_full, regs=24):
    """A one-class dex whose method assembles and returns the whole code string itself."""
    d = DexBuilder()
    a = Asm()
    emit_full(a, d)
    units = a.finish()
    run = d.m("Lcom/huntress/C;", "run", "L")
    d.add_class([(run, units, regs, 5)])
    return d.build()


def int_to_long(a, dst_wide, src_int):
    a.unop(0x81, dst_wide, src_int)       # int-to-long


# ------- float/double reference (independent of the reader) -------
def f32_bits(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]


def f64_bits(x):
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def ref_cmp_long(a, b):
    xs, ys = _s64(a), _s64(b)
    return (xs > ys) - (xs < ys)


def ref_cmp_float(abits, bbits, bias):
    fa = struct.unpack("<f", struct.pack("<I", abits & M32))[0]
    fb = struct.unpack("<f", struct.pack("<I", bbits & M32))[0]
    if fa != fa or fb != fb:
        return bias
    return (fa > fb) - (fa < fb)


def ref_cmp_double(abits, bbits, bias):
    fa = struct.unpack("<d", struct.pack("<Q", abits & M64))[0]
    fb = struct.unpack("<d", struct.pack("<Q", bbits & M64))[0]
    if fa != fa or fb != fb:
        return bias
    return (fa > fb) - (fa < fb)
