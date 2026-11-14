#!/usr/bin/env python3
"""Reference Dalvik interpreter for the Day 27 Mobile split look-ahead (backlog row 533).

It computes the TRUTH of a fixture whose answer is COMPUTED by the app's own dex chain, independently of the
shipped solver: it decodes the dex with androguard (a third-party reader) and runs the app's `Release.code(Context)`
on its own small model of the Android runtime, including what the Day 26 chain needs from a split bundle:

    Context.getApplicationInfo().splitSourceDirs   the paths of the NON-BASE splits, in the order given
    new ZipFile(path).getEntry("assets/<name>")    a member of one of those splits, or null
    ZipFile.getInputStream / InputStream.read      its bytes

It never imports anything from solvers/. Names are not special: whatever method the chain calls (`readSplit`, a
renamed reader) is interpreted from its own bytecode. An opcode or framework call it does not model raises
`Unsupported`, so a fixture is never given a guessed truth.
"""
import re

try:
    from loguru import logger as _logger
    _logger.remove()
except Exception:  # pragma: no cover
    pass

M32, M64 = 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF


class Unsupported(Exception):
    pass


class Thrown(Exception):
    pass


def s32(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def s64(x):
    x &= M64
    return x - (1 << 64) if x & (1 << 63) else x


def s8(x):
    x &= 0xFF
    return x - 256 if x & 0x80 else x


class Obj:
    def __init__(self, t, **kw):
        self.t = t
        self.__dict__.update(kw)


_ALU = re.compile(r"(add|sub|mul|div|rem|and|or|xor|shl|shr|ushr|rsub)-(int|long)(/2addr|/lit8|/lit16)?$")
_IF = re.compile(r"if-(eq|ne|lt|ge|gt|le)(z?)$")
_PARAM = re.compile(r"\[*(?:[ZBSCIJFD]|L[^;]*;)")


def _wrap(kind, x):
    return s64(x) if kind == "long" else s32(x)


def _alu(op, kind, a, b):
    bits = 64 if kind == "long" else 32
    mask = M64 if kind == "long" else M32
    if op == "add":
        r = a + b
    elif op == "sub":
        r = a - b
    elif op == "rsub":
        r = b - a
    elif op == "mul":
        r = a * b
    elif op in ("div", "rem"):
        if b == 0:
            raise Thrown("ArithmeticException")
        q = abs(a) // abs(b)
        q = q if (a < 0) == (b < 0) else -q
        r = q if op == "div" else a - q * b
    elif op == "and":
        r = a & b
    elif op == "or":
        r = a | b
    elif op == "xor":
        r = a ^ b
    elif op == "shl":
        r = a << (b & (bits - 1))
    elif op == "shr":
        r = a >> (b & (bits - 1))
    elif op == "ushr":
        r = (a & mask) >> (b & (bits - 1))
    else:
        raise Unsupported(op)
    return _wrap(kind, r)


def _params(desc):
    inner = desc[desc.index("(") + 1:desc.index(")")]
    return _PARAM.findall(inner)


class RefVM:
    def __init__(self, dex_bytes, splits):
        """splits: ordered [(path, {member: bytes})], the NON-BASE splits as ApplicationInfo.splitSourceDirs lists them."""
        from androguard.core.dex import DEX
        self.dex = DEX(dex_bytes)
        self.splits = list(splits)
        self.paths = {p: m for p, m in self.splits}
        self.methods = {}
        self.ans_methods = []
        for c in self.dex.get_classes():
            for m in c.get_methods():
                code = m.get_code()
                if code is None:
                    continue
                ins, addr = [], 0
                for i in code.get_bc().get_instructions():
                    ins.append((addr, i.get_name(), i.get_operands()))
                    addr += i.get_length() // 2
                pc = {a: k for k, (a, _, _) in enumerate(ins)}
                key = (c.get_name(), (m.get_name() + m.get_descriptor()).replace(" ", ""))
                self.methods[key] = (code, ins, pc)
                if any(n == "const-string" and ops[1][2] == "ANS-" for _, n, ops in ins):
                    self.ans_methods.append(key)
        self.statics = {}

    # ------------------------------------------------------------------ public
    def code(self):
        if len(self.ans_methods) != 1:
            raise Unsupported("expected exactly one method that builds the ANS- code, got %r" % (self.ans_methods,))
        cls, nd = self.ans_methods[0]
        out = self.call(cls, nd, [None])
        if not (isinstance(out, str) and re.fullmatch(r"ANS-[0-9A-F]{16}", out)):
            raise Unsupported("chain returned %r" % (out,))
        return out

    # ------------------------------------------------------------------ interpreter
    @staticmethod
    def _regs(ops):
        return [o[1] for o in ops if getattr(o[0], "name", "") == "REGISTER"]

    @staticmethod
    def _lit(ops):
        return next(o[1] for o in ops if getattr(o[0], "name", "") == "LITERAL")

    @staticmethod
    def _off(ops):
        return next(o[1] for o in ops if getattr(o[0], "name", "") == "OFFSET")

    def call(self, cls, nd, args, depth=0):
        if depth > 60:
            raise Unsupported("call depth")
        code, ins, pcmap = self.methods[(cls, nd)]
        R, I = code.get_registers_size(), code.get_ins_size()
        # the arguments sit in the last I registers; a wide (J, D) parameter takes two of them
        params = _params(nd)
        regs, r = {}, R - I
        it = iter(args)
        for p in params:
            regs[r] = next(it)
            r += 2 if p in ("J", "D") else 1
        pc, res = 0, None
        steps = 0
        while True:
            steps += 1
            if steps > 5_000_000:
                raise Unsupported("step limit")
            addr, name, ops = ins[pc]
            pc += 1
            rr = self._regs(ops)
            if name in ("const/4", "const/16", "const", "const/high16"):
                regs[rr[0]] = s32(self._lit(ops))
            elif name in ("const-wide/16", "const-wide/32", "const-wide", "const-wide/high16"):
                regs[rr[0]] = s64(self._lit(ops))
            elif name == "const-string":
                regs[rr[0]] = ops[1][2]
            elif name.startswith("move-result"):
                regs[rr[0]] = res
            elif name.startswith("move"):
                regs[rr[0]] = regs[rr[1]]
            elif name.startswith("return"):
                return None if name == "return-void" else regs[rr[0]]
            elif name == "goto" or name.startswith("goto/"):
                pc = pcmap[addr + self._off(ops)]
            elif _IF.match(name):
                m = _IF.match(name)
                cmp, z = m.group(1), m.group(2)
                a = regs[rr[0]]
                b = 0 if z else regs[rr[1]]
                if cmp in ("eq", "ne"):
                    same = (a is b) or (a == b if isinstance(a, int) and isinstance(b, int) else False)
                    if z:       # a null test: a reference is non-null, null/0 is zero
                        same = (a is None) or (isinstance(a, int) and a == 0)
                    ok = same if cmp == "eq" else not same
                else:
                    ok = {"lt": a < b, "ge": a >= b, "gt": a > b, "le": a <= b}[cmp]
                if ok:
                    pc = pcmap[addr + self._off(ops)]
            elif _ALU.match(name):
                m = _ALU.match(name)
                op, kind, form = m.group(1), m.group(2), m.group(3)
                if form == "/2addr":
                    regs[rr[0]] = _alu(op, kind, regs[rr[0]], regs[rr[1]])
                elif form in ("/lit8", "/lit16"):
                    regs[rr[0]] = _alu(op, kind, regs[rr[1]], self._lit(ops))
                else:
                    regs[rr[0]] = _alu(op, kind, regs[rr[1]], regs[rr[2]])
            elif name == "int-to-long":
                regs[rr[0]] = s64(regs[rr[1]])
            elif name == "long-to-int":
                regs[rr[0]] = s32(regs[rr[1]])
            elif name == "int-to-byte":
                regs[rr[0]] = s8(regs[rr[1]])
            elif name == "neg-int":
                regs[rr[0]] = s32(-regs[rr[1]])
            elif name == "neg-long":
                regs[rr[0]] = s64(-regs[rr[1]])
            elif name == "not-int":
                regs[rr[0]] = s32(~regs[rr[1]])
            elif name == "not-long":
                regs[rr[0]] = s64(~regs[rr[1]])
            elif name == "array-length":
                regs[rr[0]] = len(regs[rr[1]])
            elif name == "new-array":
                regs[rr[0]] = [0] * regs[rr[1]]
            elif name == "aget-byte":
                regs[rr[0]] = s8(regs[rr[1]][regs[rr[2]]])
            elif name in ("aget", "aget-object", "aget-wide"):
                regs[rr[0]] = regs[rr[1]][regs[rr[2]]]
            elif name in ("aput-byte", "aput", "aput-object", "aput-wide"):
                regs[rr[1]][regs[rr[2]]] = regs[rr[0]]
            elif name == "new-instance":
                regs[rr[0]] = Obj(ops[1][2])
            elif name == "throw":
                raise Thrown(getattr(regs[rr[0]], "t", "?"))
            elif name == "sget-object" or name == "sget":
                regs[rr[0]] = self.statics.get(ops[1][2], None)
            elif name == "sput-object" or name == "sput":
                self.statics[ops[1][2]] = regs[rr[0]]
            elif name == "iget-object":
                field = ops[-1][2]
                if "splitSourceDirs" in field:
                    regs[rr[0]] = [p for p, _ in self.splits]
                else:
                    raise Unsupported("iget " + field)
            elif name.startswith("invoke-"):
                desc = ops[-1][2]
                argregs = rr
                res = self._invoke(name, desc, [regs.get(x) for x in argregs], depth)
            elif name == "nop":
                pass
            else:
                raise Unsupported("opcode " + name)

    def _invoke(self, kind, desc, flat, depth):
        cls, rest = desc.split("->", 1)
        nd = rest.replace(" ", "")
        mname = nd[:nd.index("(")]
        params = _params(nd)
        # fold the flat register values into arguments: a wide parameter uses two registers
        recv = None
        vals = list(flat)
        if "static" not in kind:
            recv, vals = vals[0], vals[1:]
        args, k = [], 0
        for p in params:
            args.append(vals[k])
            k += 2 if p in ("J", "D") else 1
        if (cls, nd) in self.methods:
            return self.call(cls, nd, args, depth + 1)
        return self._framework(cls, mname, nd, recv, args)

    def _framework(self, cls, mname, nd, recv, a):
        key = cls + "->" + mname
        if key == "Landroid/content/Context;->getApplicationInfo":
            return Obj("ApplicationInfo")
        if key == "Ljava/util/zip/ZipFile;-><init>":
            if a[0] not in self.paths:
                raise Thrown("FileNotFoundException " + str(a[0]))
            recv.members = self.paths[a[0]]
            return None
        if key == "Ljava/util/zip/ZipFile;->getEntry":
            return Obj("ZipEntry", name=a[0]) if a[0] in recv.members else None
        if key == "Ljava/util/zip/ZipFile;->getInputStream":
            return Obj("InputStream", data=recv.members[a[0].name], pos=0)
        if key == "Ljava/util/zip/ZipFile;->close" or key == "Ljava/io/InputStream;->close":
            return None
        if key == "Ljava/io/InputStream;->read":
            buf, off, ln = a
            chunk = recv.data[recv.pos:recv.pos + ln]
            if not chunk:
                return -1
            for i, b in enumerate(chunk):
                buf[off + i] = s8(b)
            recv.pos += len(chunk)
            return len(chunk)
        if key == "Ljava/lang/StringBuilder;-><init>":
            recv.buf = []
            return None
        if key == "Ljava/lang/StringBuilder;->append":
            p = _params(nd)[0]
            recv.buf.append(a[0] if p == "Ljava/lang/String;" else chr(a[0]) if p == "C" else str(a[0]))
            return recv
        if key == "Ljava/lang/StringBuilder;->toString":
            return "".join(recv.buf)
        if key == "Ljava/lang/String;->charAt":
            return ord(recv[a[0]])
        if key == "Ljava/lang/Long;->toHexString":
            return "%x" % (a[0] & M64)
        if mname == "<init>" and re.fullmatch(r"Ljava/(?:io|lang)/\w*Exception;", cls) and not a:
            return None             # an exception's no-argument constructor: the `throw` that follows is Thrown
        raise Unsupported("framework call " + key + nd)


def chain_code(dex_bytes, splits):
    """The ANS code the app's own chain computes when the runtime's non-base splits are `splits`."""
    return RefVM(dex_bytes, splits).code()
