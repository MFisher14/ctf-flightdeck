"""A Python-source compiler for PURE leaf Dalvik methods, laid over dex_chain_codec.VM.run (speed solver only).

The shipped Mobile `analysis` reader (solvers/mobile-android/dex_chain_codec.py) interprets the app's dex. The
generated chains call small static methods that loop thousands of times over int/long arithmetic; the generic
interpreter spends about a microsecond per instruction there. This module compiles such a method (registers as
locals, one Python statement per instruction) the first time it is run, and runs the compiled form.

Exactness: only a method made solely of the ops below is compiled (no invoke, no field, no array, no object, no
float, no switch); such a method reads only its arguments and has no side effect, so its result is a pure
function of them. The step counter is kept exactly (self.steps grows by the instructions executed). Anything
unusual (an exception, the step budget reached, a register out of range) restores the counter and runs the
shipped interpreter on the same arguments, which then behaves exactly as without this module.
"""
from __future__ import annotations

import types

M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1

_PURE = set([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f, 0x10,
             0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x28, 0x29, 0x2a, 0x31,
             0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
             0x7b, 0x7c, 0x7d, 0x7e, 0x81, 0x84, 0x8d, 0x8e, 0x8f])
_PURE.update(range(0x90, 0xa6))
_PURE.update(range(0xb0, 0xc6))
_PURE.update(range(0xd0, 0xd8))
_PURE.update(range(0xd8, 0xe3))


def _s4(x):
    return x - 16 if x & 8 else x


def _s8(x):
    return x - 0x100 if x & 0x80 else x


def _s16(x):
    return x - 0x10000 if x & 0x8000 else x


def _s32c(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def S32(e):
    return "((((%s) & 0xFFFFFFFF) ^ 0x80000000) - 0x80000000)" % e


def S64(e):
    return "((((%s) & 0xFFFFFFFFFFFFFFFF) ^ 0x8000000000000000) - 0x8000000000000000)" % e


class _No(Exception):
    pass


class _Bail(Exception):
    pass


_INT2 = {0: "+", 1: "-", 2: "*", 5: "&", 6: "|", 7: "^"}
_LONG2 = {0: "+", 1: "-", 2: "*", 5: "&", 6: "|", 7: "^"}


def _int_expr(k, x, y):
    """int binop number k (0x90 + k) on source expressions x, y, as the VM computes it."""
    if k in _INT2:
        return S32("%s %s %s" % (x, _INT2[k], y))
    if k == 3:
        return "_idiv32(%s, %s)" % (x, y)
    if k == 4:
        return "_irem32(%s, %s)" % (x, y)
    if k == 8:
        return S32("(%s << (%s & 31)) & 0xFFFFFFFF" % (x, y))
    if k == 9:
        return "(%s >> (%s & 31))" % (S32(x), y)
    if k == 10:
        return S32("(%s & 0xFFFFFFFF) >> (%s & 31)" % (x, y))
    raise _No()


def _long_expr(k, x, y):
    """long binop number k (0x9b + k)."""
    if k in _LONG2:
        return "((%s %s %s) & 0xFFFFFFFFFFFFFFFF)" % (x, _LONG2[k], y)
    if k == 3:
        return "_ldiv64(%s, %s)" % (x, y)
    if k == 4:
        return "_lrem64(%s, %s)" % (x, y)
    if k == 8:
        return "((%s << (%s & 63)) & 0xFFFFFFFFFFFFFFFF)" % (x, y)
    if k == 9:
        return "((%s >> (%s & 63)) & 0xFFFFFFFFFFFFFFFF)" % (S64(x), y)
    if k == 10:
        return "((%s & 0xFFFFFFFFFFFFFFFF) >> (%s & 63))" % (x, y)
    raise _No()


def _decode(insns, W):
    """[(pc, op, b1, width)] of the method, or raise _No when it is not pure or does not decode."""
    out, pc, n = [], 0, len(insns)
    while pc < n:
        unit = insns[pc]
        op = unit & 0xFF
        if op == 0x00 and unit != 0:  # a payload pseudo-instruction: only reached by data ops (not pure)
            raise _No()
        if op not in _PURE:
            raise _No()
        w = W[op]
        if w <= 0 or pc + w > n:
            raise _No()
        out.append((pc, op, unit >> 8, w))
        pc += w
    return out


def compile_method(regs, ins_size, insns, W, helpers):
    """A function f(args, lim) -> (value, steps) for a pure method, or None. Raises _Bail at run time when the
    budget `lim` would be passed (the caller then reruns the shipped interpreter)."""
    try:
        code = _decode(insns, W)
    except _No:
        return None
    if not code or regs < 1 or regs > 250:
        return None
    at = {pc: i for i, (pc, _, _, _) in enumerate(code)}
    n = len(insns)

    def reg(i):
        if i < 0 or i >= regs:
            raise _No()
        return "r%d" % i

    # targets
    leaders = {0}
    targets = {}
    backward = False
    for i, (pc, op, b1, w) in enumerate(code):
        t = None
        if op == 0x28:
            off = _s8(b1)
            t = pc + (off if off else w)
        elif op == 0x29:
            t = pc + _s16(insns[pc + 1])
        elif op == 0x2a:
            t = pc + _s32c(insns[pc + 1] | (insns[pc + 2] << 16))
        elif 0x32 <= op <= 0x3d:
            t = pc + _s16(insns[pc + 1])
        if t is not None:
            if t not in at and t != n:
                return None
            if t <= pc:
                backward = True
            targets[pc] = t
            leaders.add(t)
            if pc + w < n:
                leaders.add(pc + w)
        elif op in (0x0e, 0x0f, 0x10) and pc + w < n:
            leaders.add(pc + w)
    leaders.discard(n)
    try:
        lines = ["def _f(args, lim):"]
        lines.append("    " + "; ".join("r%d = 0" % i for i in range(regs)))
        start = regs - ins_size
        lines.append("    _a = len(args)")
        for k in range(ins_size):
            pass
        lines.append("    if _a > %d: raise _Bail()" % ins_size)
        for k in range(ins_size):
            lines.append("    if _a > %d: r%d = args[%d]" % (k, start + k, k))
        lines.append("    st = 0")
        lines.append("    pc = 0")
        lines.append("    while True:")
        order = sorted(leaders)
        blocks = []
        for bi, lead in enumerate(order):
            i0 = at[lead]
            # block body: from lead until the next leader or a terminator
            body = []
            term = None
            cnt = 0
            i = i0
            ended = False
            while i < len(code):
                pc, op, b1, w = code[i]
                if pc != lead and pc in leaders:
                    break
                cnt += 1
                A = b1 & 0xF
                B = (b1 >> 4) & 0xF
                pre = "st += %d\n" % cnt   # steps up to and including this instruction, for exits
                if op == 0x00:
                    pass
                elif op in (0x01, 0x04, 0x07):
                    body.append("%s = %s" % (reg(A), reg(B)))
                    if op == 0x04:
                        body.append("%s = %s" % (reg(A + 1), reg(B + 1) if B + 1 < regs else "0"))
                elif op in (0x02, 0x05, 0x08):
                    src = insns[pc + 1]
                    body.append("%s = %s" % (reg(b1), reg(src)))
                    if op == 0x05:
                        body.append("%s = %s" % (reg(b1 + 1), reg(src + 1)))
                elif op in (0x03, 0x06, 0x09):
                    a, src = insns[pc + 1], insns[pc + 2]
                    body.append("%s = %s" % (reg(a), reg(src)))
                    if op == 0x06:
                        body.append("%s = %s" % (reg(a + 1), reg(src + 1) if src + 1 < regs else "0"))
                elif op == 0x0e:
                    body.append("return None, st + %d" % cnt)
                    term = ("ret",)
                    ended = True
                elif op in (0x0f, 0x10):
                    body.append("return %s, st + %d" % (reg(b1), cnt))
                    term = ("ret",)
                    ended = True
                elif op == 0x12:
                    body.append("%s = %d" % (reg(A), _s4(B)))
                elif op == 0x13:
                    body.append("%s = %d" % (reg(b1), _s16(insns[pc + 1])))
                elif op == 0x14:
                    body.append("%s = %d" % (reg(b1), _s32c(insns[pc + 1] | (insns[pc + 2] << 16))))
                elif op == 0x15:
                    body.append("%s = %d" % (reg(b1), _s32c((_s16(insns[pc + 1]) << 16) & M32)))
                elif op in (0x16, 0x17, 0x18, 0x19):
                    if op == 0x16:
                        v = _s16(insns[pc + 1]) & M64
                    elif op == 0x17:
                        v = _s32c(insns[pc + 1] | (insns[pc + 2] << 16)) & M64
                    elif op == 0x18:
                        v = (insns[pc + 1] | (insns[pc + 2] << 16) | (insns[pc + 3] << 32) | (insns[pc + 4] << 48)) & M64
                    else:
                        v = (_s16(insns[pc + 1]) << 48) & M64
                    body.append("%s = %d" % (reg(b1), v))
                    body.append("%s = 0" % reg(b1 + 1))
                elif op in (0x28, 0x29, 0x2a):
                    term = ("goto", targets[pc], cnt)
                    ended = True
                elif op == 0x31:
                    u2 = insns[pc + 1]
                    x, y = reg(u2 & 0xFF), reg((u2 >> 8) & 0xFF)
                    body.append("_x = %s; _y = %s" % (S64(x), S64(y)))
                    body.append("%s = (_x > _y) - (_x < _y)" % reg(b1))
                elif 0x32 <= op <= 0x37:
                    cmpop = {0x32: "==", 0x33: "!=", 0x34: "<", 0x35: ">=", 0x36: ">", 0x37: "<="}[op]
                    term = ("if", "%s %s %s" % (reg(A), cmpop, reg(B)), targets[pc], pc + w, cnt)
                    ended = True
                elif 0x38 <= op <= 0x3d:
                    cmpop = {0x38: "==", 0x39: "!=", 0x3a: "<", 0x3b: ">=", 0x3c: ">", 0x3d: "<="}[op]
                    term = ("if", "%s %s 0" % (reg(b1), cmpop), targets[pc], pc + w, cnt)
                    ended = True
                elif op == 0x81:
                    body.append("%s = %s & 0xFFFFFFFFFFFFFFFF" % (reg(A), S32(reg(B))))
                    body.append("%s = 0" % reg(A + 1))
                elif op == 0x84:
                    body.append("%s = %s" % (reg(A), S32(reg(B))))
                elif op == 0x7b:
                    body.append("%s = %s" % (reg(A), S32("-" + reg(B))))
                elif op == 0x7d:
                    body.append("%s = (-%s) & 0xFFFFFFFFFFFFFFFF" % (reg(A), reg(B)))
                    body.append("%s = 0" % reg(A + 1))
                elif op == 0x7c:
                    body.append("%s = %s" % (reg(A), S32("~" + reg(B))))
                elif op == 0x7e:
                    body.append("%s = (~%s) & 0xFFFFFFFFFFFFFFFF" % (reg(A), reg(B)))
                    body.append("%s = 0" % reg(A + 1))
                elif op == 0x8d:
                    body.append("_x = %s & 0xFF; %s = _x - 0x100 if _x & 0x80 else _x" % (reg(B), reg(A)))
                elif op == 0x8e:
                    body.append("%s = %s & 0xFFFF" % (reg(A), reg(B)))
                elif op == 0x8f:
                    body.append("_x = %s & 0xFFFF; %s = _x - 0x10000 if _x & 0x8000 else _x" % (reg(B), reg(A)))
                elif 0x90 <= op <= 0xa5:
                    u2 = insns[pc + 1]
                    x, y = reg(u2 & 0xFF), reg((u2 >> 8) & 0xFF)
                    if op <= 0x9a:
                        body.append("%s = %s" % (reg(b1), _int_expr(op - 0x90, x, y)))
                    else:
                        body.append("_x = %s; _y = %s" % (x, y))
                        body.append("%s = 0" % reg(b1 + 1))
                        body.append("%s = %s" % (reg(b1), _long_expr(op - 0x9b, "_x", "_y")))
                elif 0xb0 <= op <= 0xc5:
                    x, y = reg(A), reg(B)
                    if op <= 0xba:
                        body.append("%s = %s" % (x, _int_expr(op - 0xb0, x, y)))
                    else:
                        body.append("_x = %s; _y = %s" % (x, y))
                        body.append("%s = 0" % reg(A + 1))
                        body.append("%s = %s" % (x, _long_expr(op - 0xbb, "_x", "_y")))
                elif 0xd0 <= op <= 0xd7:
                    lit = _s16(insns[pc + 1])
                    x = reg(B)
                    k = op - 0xd0
                    if k in (3, 4) and not lit:
                        raise _No()
                    if k == 0:
                        e = S32("%s + %d" % (x, lit))
                    elif k == 1:
                        e = S32("%d - %s" % (lit, x))
                    elif k == 2:
                        e = S32("%s * %d" % (x, lit))
                    elif k == 3:
                        e = S32("int(%s / %d)" % (S32(x), lit))
                    elif k == 4:
                        e = "_rem_lit(%s, %d)" % (x, lit)
                    elif k == 5:
                        e = ("(%s & %d)" % (x, lit)) if lit >= 0 else S32("%s & %d" % (x, lit))
                    elif k == 6:
                        e = S32("%s | %d" % (x, lit))
                    else:
                        e = S32("%s ^ %d" % (x, lit))
                    body.append("%s = %s" % (reg(A), e))
                elif 0xd8 <= op <= 0xe2:
                    u2 = insns[pc + 1]
                    x = reg(u2 & 0xFF)
                    lit = _s8((u2 >> 8) & 0xFF)
                    k = op - 0xd8
                    if k in (3, 4) and not lit:
                        raise _No()
                    if k == 0:
                        e = S32("%s + %d" % (x, lit))
                    elif k == 1:
                        e = S32("%d - %s" % (lit, x))
                    elif k == 2:
                        e = S32("%s * %d" % (x, lit))
                    elif k == 3:
                        e = S32("int(%s / %d)" % (S32(x), lit))
                    elif k == 4:
                        e = "_rem_lit(%s, %d)" % (x, lit)
                    elif k == 5:
                        e = ("(%s & %d)" % (x, lit)) if lit >= 0 else S32("%s & %d" % (x, lit))
                    elif k == 6:
                        e = S32("%s | %d" % (x, lit))
                    elif k == 7:
                        e = S32("%s ^ %d" % (x, lit))
                    elif k == 8:
                        e = S32("(%s << %d) & 0xFFFFFFFF" % (x, lit & 31))
                    elif k == 9:
                        e = "(%s >> %d)" % (S32(x), lit & 31)
                    else:
                        e = S32("(%s & 0xFFFFFFFF) >> %d" % (x, lit & 31))
                    body.append("%s = %s" % (reg(b1), e))
                else:
                    raise _No()
                i += 1
                if ended:
                    break
            if not ended:
                # falls through into the next leader (or off the end: the VM then returns `result`, None)
                nxt = code[i][0] if i < len(code) else n
                if nxt >= n:
                    body.append("return None, st + %d" % cnt)
                    term = ("ret",)
                else:
                    term = ("goto", nxt, cnt)
            blocks.append((lead, cnt, body, term))
        bidx = {b[0]: k for k, b in enumerate(blocks)}
        loops = {}
        for k, (lead, cnt, body, term) in enumerate(blocks):
            # an innermost contiguous loop: blocks h..k, the last jumps back to blocks[h]
            for t in ((term[1],) if term[0] == "goto" else (term[2], term[3]) if term[0] == "if" else ()):
                if t <= lead and t in bidx:
                    h = bidx[t]
                    if h in loops and loops[h] <= k:
                        continue
                    loops[h] = k
        first = True
        for k, (lead, cnt, body, term) in enumerate(blocks):
            kw = "if" if first else "elif"
            first = False
            lines.append("        %s pc == %d:" % (kw, lead))
            if k in loops:
                h, e = k, loops[k]
                inside = {blocks[j][0] for j in range(h, e + 1)}
                lines.append("            while True:")
                # one conservative budget check an iteration (a bail only reruns the shipped interpreter)
                lines.append("                if st + %d > lim: raise _Bail()" % sum(blocks[j][1] for j in range(h, e + 1)))
                for j in range(h, e + 1):
                    nxt_lead = blocks[j + 1][0] if j + 1 <= e else None
                    _emit(lines, "                ", blocks[j], lead, nxt_lead, inside)
                lines.append("            continue")
            else:
                _emit(lines, "            ", blocks[k], None, None, ())
        lines.append("        else:")
        lines.append("            raise _Bail()")
    except _No:
        return None
    src = "\n".join(lines)
    ns = dict(helpers)
    ns["_Bail"] = _Bail
    try:
        exec(compile(src, "<dalvik-jit>", "exec"), ns)
    except Exception:
        return None
    f = ns["_f"]
    f.backward = backward
    f.src = src
    return f


def _emit(lines, ind, block, head, nxt, inside):
    """One block's code. In a loop (head given) a jump to the head is `continue`, to the next block of the loop a
    fall-through, to anywhere else `pc = X; break`; outside a loop every jump goes through the dispatcher."""
    lead, cnt, body, term = block
    if head is None:
        lines.append(ind + "if st + %d > lim: raise _Bail()" % cnt)
    for b in body:
        lines.append(ind + b)
    if term[0] == "ret":
        return
    lines.append(ind + "st += %d" % term[-1])

    def jump(t):
        if head is None:
            return "pc = %d; continue" % t
        if t == head:
            return "continue"
        if t == nxt:
            return "pass"
        return "pc = %d; break" % t

    if term[0] == "goto":
        j = jump(term[1])
        if j != "pass" or nxt is None:
            lines.append(ind + (j if j != "pass" else "pc = %d; break" % term[1]))
        return
    _, cond, t, f, _c = term
    lines.append(ind + "if %s: %s" % (cond, jump(t)))
    lines.append(ind + "else: %s" % jump(f))


_CACHE: dict = {}


def install(D):
    """Lay the compiler over D.VM.run (D is a privately loaded dex_chain_codec module). Idempotent."""
    if getattr(D.VM, "_speed_jit", False):
        return
    orig = D.VM.run
    W = D._W

    def _rem_lit(x, lit):
        xx = D._s32(x)
        return D._s32(xx - int(xx / lit) * lit)

    helpers = {"_idiv32": D._idiv32, "_irem32": D._irem32, "_ldiv64": D._ldiv64, "_lrem64": D._lrem64,
               "_rem_lit": _rem_lit}
    calls: dict = {}
    cache, has_back, comp = _CACHE, _has_back, compile_method

    def run(self, midx, args):
        dex = self.dex
        code = dex.code.get(midx)
        if code is None:
            return orig(self, midx, args)
        regs_size, ins_size, insns = code
        key = (regs_size, ins_size, tuple(insns))
        f = cache.get(key, False)
        if f is False:
            k2 = (id(dex), midx)
            c = calls.get(k2, 0) + 1
            calls[k2] = c
            if c < 3 and not has_back(insns, W):
                return orig(self, midx, args)
            f = comp(regs_size, ins_size, insns, W, helpers)
            cache[key] = f
        if f is None:
            return orig(self, midx, args)
        before = self.steps
        try:
            v, st = f(args, self.max_steps - before)
        except Exception:
            self.steps = before
            return orig(self, midx, args)
        self.steps = before + st
        return v

    # dex_float._G finds the interpreter's module by the globals of VM.run: give the replacement D's globals
    run = types.FunctionType(run.__code__, D.__dict__, "run", run.__defaults__, run.__closure__)
    D.VM.run = run
    D.VM._speed_jit = True


def _has_back(insns, W):
    pc, n = 0, len(insns)
    while pc < n:
        unit = insns[pc]
        op = unit & 0xFF
        if op == 0x28 and _s8(unit >> 8) < 0:
            return True
        if op == 0x29 and pc + 1 < n and _s16(insns[pc + 1]) < 0:
            return True
        if 0x32 <= op <= 0x3d and pc + 1 < n and _s16(insns[pc + 1]) < 0:
            return True
        w = W[op]
        if w <= 0:
            return False
        pc += w
    return False
