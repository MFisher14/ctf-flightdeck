"""A small Dalvik assembler and dex writer for synthetic mobile fixtures (B-229).

The mobile opener's `analysis` cases (ctf.openers.fixtures) and the dex-chain tests need real
classes.dex files whose code computes an answer, built from code and never copied from a challenge.
This writes a dex the readers in solvers/mobile-android parse: a header with correct offsets and file
size, string, type, proto, field and method id tables, class definitions (with their own type), class
data and code items. Each proto carries its shorty and its return type; parameter lists are not
written (no reader here needs them).

    d = DexFile()
    m = d.method("Lcom/x/Release;", "code", "L")          # shorty: return type then parameters
    c = Code(regs=16, ins=0)
    c.const_string(0, d.string("ANS-"))
    ...
    d.define("Lcom/x/Release;", [(m, c)])
    blob = d.build()

The assembler emits only what the fixtures use. Branch targets are labels resolved by Code.units().
Nothing here runs or interprets the code: the reader under test does that, and each fixture computes
its expected answer independently in Python.
"""
from __future__ import annotations

import io
import struct
import zipfile

HEADER_SIZE = 0x70
ENDIAN_TAG = 0x12345678
MAGIC = b"dex\n035\x00"
ZIP_DATE = (2026, 10, 1, 0, 0, 0)    # fixed member dates: a fixture's bytes never depend on the clock


class DexAsmError(ValueError):
    """An instruction or table entry the assembler cannot encode (a register out of range, an unknown label)."""


def uleb(n: int) -> bytes:
    if n < 0:
        raise DexAsmError(f"uleb128 of a negative number {n}")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _reg(r: int, bits: int) -> int:
    if not 0 <= r < (1 << bits):
        raise DexAsmError(f"register v{r} does not fit in {bits} bits")
    return r


class Code:
    """One method body: 16-bit code units, labels, and fill-array-data payloads placed after the body."""

    def __init__(self, regs: int, ins: int = 0, outs: int = 5):
        self.regs, self.ins, self.outs = regs, ins, outs
        self.u: list[int] = []
        self.labels: dict[str, int] = {}
        self.fix: list[tuple[int, int, str, int]] = []      # (operand index, instruction start, label, units)
        self.arrays: list[tuple[str, int, list[int]]] = []  # (label, element width, values)

    def _op(self, op: int, a: int = 0) -> int:
        return (op & 0xFF) | ((a & 0xFF) << 8)

    def label(self, name: str) -> None:
        if name in self.labels:
            raise DexAsmError(f"label {name!r} defined twice")
        self.labels[name] = len(self.u)

    # constants
    def const4(self, dst: int, val: int) -> None:
        if not -8 <= val <= 7:
            raise DexAsmError(f"const/4 value {val} out of range")
        self.u.append(self._op(0x12, ((val & 0xF) << 4) | _reg(dst, 4)))

    def const16(self, dst: int, val: int) -> None:
        self.u += [self._op(0x13, _reg(dst, 8)), val & 0xFFFF]

    def const(self, dst: int, val: int) -> None:
        self.u += [self._op(0x14, _reg(dst, 8)), val & 0xFFFF, (val >> 16) & 0xFFFF]

    def const_wide(self, dst: int, val: int) -> None:
        self.u += [self._op(0x18, _reg(dst, 8))] + [(val >> s) & 0xFFFF for s in (0, 16, 32, 48)]

    def const_string(self, dst: int, sidx: int) -> None:
        self.u += [self._op(0x1A, _reg(dst, 8)), sidx & 0xFFFF]

    def const_class(self, dst: int, tidx: int) -> None:
        self.u += [self._op(0x1C, _reg(dst, 8)), tidx & 0xFFFF]

    # objects and arrays
    def new_instance(self, dst: int, tidx: int) -> None:
        self.u += [self._op(0x22, _reg(dst, 8)), tidx & 0xFFFF]

    def new_array(self, dst: int, size_reg: int, tidx: int) -> None:
        self.u += [self._op(0x23, (_reg(size_reg, 4) << 4) | _reg(dst, 4)), tidx & 0xFFFF]

    def fill_array_data(self, arr: int, width: int, values: list[int]) -> None:
        name = f"__array{len(self.arrays)}"
        start = len(self.u)
        self.u += [self._op(0x26, _reg(arr, 8)), 0, 0]
        self.fix.append((start + 1, start, name, 2))
        self.arrays.append((name, width, list(values)))

    def aget(self, op: int, dst: int, arr: int, idx: int) -> None:          # aget* 0x44..0x4a
        self.u += [self._op(op, _reg(dst, 8)), (_reg(idx, 8) << 8) | _reg(arr, 8)]

    def aput(self, op: int, src: int, arr: int, idx: int) -> None:          # aput* 0x4b..0x51
        self.u += [self._op(op, _reg(src, 8)), (_reg(idx, 8) << 8) | _reg(arr, 8)]

    # arithmetic
    def binop(self, op: int, dst: int, a: int, b: int) -> None:             # 23x: add-long 0x9b, xor-long 0xa2...
        self.u += [self._op(op, _reg(dst, 8)), (_reg(b, 8) << 8) | _reg(a, 8)]

    def binop_lit8(self, op: int, dst: int, src: int, lit: int) -> None:    # 22b: add-int/lit8 0xd8 ...
        self.u += [self._op(op, _reg(dst, 8)), ((lit & 0xFF) << 8) | _reg(src, 8)]

    def unop(self, op: int, dst: int, src: int) -> None:                    # 12x: int-to-long 0x81 ...
        self.u.append(self._op(op, (_reg(src, 4) << 4) | _reg(dst, 4)))

    # calls and results
    def invoke(self, op: int, midx: int, regs: list[int]) -> None:
        """invoke-virtual 0x6e, -super 0x6f, -direct 0x70, -static 0x71, -interface 0x72 (format 35c)."""
        if len(regs) > 5:
            raise DexAsmError("35c takes at most five registers")
        r = [_reg(x, 4) for x in regs] + [0] * (5 - len(regs))
        self.u += [self._op(op, (len(regs) << 4) | r[4]), midx & 0xFFFF,
                   (r[3] << 12) | (r[2] << 8) | (r[1] << 4) | r[0]]

    def move_result(self, dst: int) -> None:
        self.u.append(self._op(0x0A, _reg(dst, 8)))

    def move_result_wide(self, dst: int) -> None:
        self.u.append(self._op(0x0B, _reg(dst, 8)))

    def move_result_object(self, dst: int) -> None:
        self.u.append(self._op(0x0C, _reg(dst, 8)))

    def return_void(self) -> None:
        self.u.append(0x0E)

    def return_(self, src: int) -> None:
        self.u.append(self._op(0x0F, _reg(src, 8)))

    def return_wide(self, src: int) -> None:
        self.u.append(self._op(0x10, _reg(src, 8)))

    def return_object(self, src: int) -> None:
        self.u.append(self._op(0x11, _reg(src, 8)))

    # branches
    def goto16(self, label: str) -> None:
        start = len(self.u)
        self.u += [0x29, 0]
        self.fix.append((start + 1, start, label, 1))

    def if_z(self, op: int, reg: int, label: str) -> None:                  # if-eqz 0x38 ... (21t)
        start = len(self.u)
        self.u += [self._op(op, _reg(reg, 8)), 0]
        self.fix.append((start + 1, start, label, 1))

    def units(self) -> list[int]:
        """The finished body: payloads appended (4-byte aligned), every label resolved."""
        u = list(self.u)
        labels = dict(self.labels)
        for name, width, values in self.arrays:
            if len(u) % 2:
                u.append(0x0000)                     # nop: a payload starts on an even code unit
            labels[name] = len(u)
            raw = b"".join(int(v & ((1 << (8 * width)) - 1)).to_bytes(width, "little") for v in values)
            raw += b"\x00" * (-len(raw) % 2)
            u += [0x0300, width, len(values) & 0xFFFF, len(values) >> 16]
            u += list(struct.unpack("<%dH" % (len(raw) // 2), raw))
        for operand, start, label, n in self.fix:
            if label not in labels:
                raise DexAsmError(f"unknown label {label!r}")
            off = labels[label] - start
            u[operand] = off & 0xFFFF
            if n == 2:
                u[operand + 1] = (off >> 16) & 0xFFFF
        return u


_SHORTY_TYPE = {"V": "V", "Z": "Z", "B": "B", "S": "S", "C": "C", "I": "I", "J": "J", "F": "F", "D": "D",
                "L": "Ljava/lang/Object;"}


class DexFile:
    """The id tables and class definitions of one dex. Indices are handed out as items are first named."""

    def __init__(self):
        self.strings: list[str] = []
        self.types: list[str] = []
        self.protos: list[tuple[str, str]] = []           # (shorty, return type)
        self.fields: list[tuple[str, str, str]] = []      # (class, type, name)
        self.methods: list[tuple[str, int, str]] = []     # (class, proto index, name)
        self.classes: list[tuple[str, list[tuple[int, Code, bool]]]] = []

    def string(self, s: str) -> int:
        if s not in self.strings:
            self.strings.append(s)
        return self.strings.index(s)

    def type(self, desc: str) -> int:
        self.string(desc)
        if desc not in self.types:
            self.types.append(desc)
        return self.types.index(desc)

    def proto(self, shorty: str) -> int:
        ret = _SHORTY_TYPE.get(shorty[:1])
        if ret is None:
            raise DexAsmError(f"bad shorty {shorty!r}")
        self.string(shorty)
        self.type(ret)
        key = (shorty, ret)
        if key not in self.protos:
            self.protos.append(key)
        return self.protos.index(key)

    def field(self, cls: str, ftype: str, name: str) -> int:
        self.type(cls)
        self.type(ftype)
        self.string(name)
        key = (cls, ftype, name)
        if key not in self.fields:
            self.fields.append(key)
        return self.fields.index(key)

    def method(self, cls: str, name: str, shorty: str) -> int:
        self.type(cls)
        self.string(name)
        key = (cls, self.proto(shorty), name)
        if key not in self.methods:
            self.methods.append(key)
        return self.methods.index(key)

    def define(self, cls: str, methods: list[tuple[int, Code]], *, virtual: tuple[int, ...] = ()) -> None:
        """A class definition holding `methods` (direct methods, unless their index is in `virtual`)."""
        self.type(cls)
        self.classes.append((cls, [(m, c, m in virtual) for m, c in methods]))

    def build(self) -> bytes:
        """The dex bytes. The tables are written in the order the ids were handed out, not in the sorted order
        a d8-built dex uses: the readers here index the tables and never binary-search them."""
        ns, nt, np_, nf, nm, nc = (len(self.strings), len(self.types), len(self.protos), len(self.fields),
                                   len(self.methods), len(self.classes))
        off = HEADER_SIZE
        str_ids, off = off, off + 4 * ns
        type_ids, off = off, off + 4 * nt
        proto_ids, off = off, off + 12 * np_
        field_ids, off = off, off + 8 * nf
        meth_ids, off = off, off + 8 * nm
        class_defs, off = off, off + 32 * nc
        data_start = off
        data = bytearray()

        def place(blob: bytes, align: int = 1) -> int:
            nonlocal data
            while (data_start + len(data)) % align:
                data.append(0)
            at = data_start + len(data)
            data += blob
            return at

        code_offs: dict[tuple[int, int], int] = {}
        for ci, (_cls, methods) in enumerate(self.classes):
            for midx, code, _virtual in methods:
                units = code.units()
                body = struct.pack("<HHHHII", code.regs, code.ins, code.outs, 0, 0, len(units))
                body += struct.pack("<%dH" % len(units), *units)
                code_offs[(ci, midx)] = place(body, 4)
        class_data: list[int] = []
        for ci, (_cls, methods) in enumerate(self.classes):
            direct = sorted((m for m in methods if not m[2]), key=lambda m: m[0])
            virtual = sorted((m for m in methods if m[2]), key=lambda m: m[0])
            blob = bytearray(uleb(0) + uleb(0) + uleb(len(direct)) + uleb(len(virtual)))
            for group, flags in ((direct, 0x0009), (virtual, 0x0001)):          # public static / public
                prev = 0
                for midx, _code, _v in group:
                    blob += uleb(midx - prev) + uleb(flags) + uleb(code_offs[(ci, midx)])
                    prev = midx
            class_data.append(place(bytes(blob)))
        str_data = [place(uleb(len(s.encode("utf-8"))) + s.encode("utf-8") + b"\x00") for s in self.strings]

        head = bytearray(data_start)
        head[0:8] = MAGIC
        struct.pack_into("<II", head, 0x20, data_start + len(data), HEADER_SIZE)
        struct.pack_into("<I", head, 0x28, ENDIAN_TAG)
        for at, (n, o) in zip(range(0x38, 0x68, 8), ((ns, str_ids), (nt, type_ids), (np_, proto_ids),
                                                      (nf, field_ids), (nm, meth_ids), (nc, class_defs))):
            struct.pack_into("<II", head, at, n, o if n else 0)
        struct.pack_into("<II", head, 0x68, len(data), data_start)
        for i, o in enumerate(str_data):
            struct.pack_into("<I", head, str_ids + 4 * i, o)
        for i, t in enumerate(self.types):
            struct.pack_into("<I", head, type_ids + 4 * i, self.strings.index(t))
        for i, (shorty, ret) in enumerate(self.protos):
            struct.pack_into("<III", head, proto_ids + 12 * i, self.strings.index(shorty), self.types.index(ret), 0)
        for i, (cls, ftype, name) in enumerate(self.fields):
            struct.pack_into("<HHI", head, field_ids + 8 * i, self.types.index(cls), self.types.index(ftype),
                             self.strings.index(name))
        for i, (cls, pidx, name) in enumerate(self.methods):
            struct.pack_into("<HHI", head, meth_ids + 8 * i, self.types.index(cls), pidx, self.strings.index(name))
        for i, (cls, _methods) in enumerate(self.classes):
            struct.pack_into("<IIIIIIII", head, class_defs + 32 * i, self.types.index(cls), 0x0001, 0xFFFFFFFF,
                             0, 0xFFFFFFFF, 0, class_data[i], 0)
        return bytes(head) + bytes(data)


def apk(members: dict[str, bytes]) -> bytes:
    """A deterministic zip of `members` (fixed dates, deflated), in the order given."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in members.items():
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, body)
    return buf.getvalue()
