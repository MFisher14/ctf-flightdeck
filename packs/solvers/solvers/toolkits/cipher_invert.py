#!/usr/bin/env python3
"""Toolkit cipher_invert: run a handout's custom Python cipher backward with no model (B-110).

The "home-built scrambler, source and sealed bytes given, nothing that runs it backward" challenge:
the handout is a Python cipher (S-box, key schedule, rotations, add/xor rounds, a chained stream...)
and a target the cipher produced.  This engine recovers the input that produces the target.

How, in order, for each (forward function, target, input type, input length) it tries:

  1. TRACE.  The source is parsed and evaluated by a closed interpreter (``_cipher_vm.py``) with the
     secret input as symbols; the challenge code is never compiled, imported or run by CPython, and
     the interpreter has no file, network or process access.  The result is a DAG of the primitives
     the cipher applied to the secret.
  2. ALGEBRAIC.  Each primitive has a backward rule over known bits (xor, and, or, add/sub with
     carries, multiply by a constant, shifts, table lookup, mod/div on small values, select).
     Propagating the target back through the DAG to a fixpoint composes the inverse of every
     recognised primitive -- a rotation is a shift pair, an S-box a table whose preimage is unique,
     an xorshift resolves over a few rounds -- with no solver.  Every bit it sets is forced by the
     target, so a full solution is the only preimage.
  3. SMT FALLBACK.  Whatever propagation leaves open goes, with the bits already forced pinned, to
     ``symbolic.solve_bitvecs`` (z3): one model proved unique, a few enumerated, or none.
  A function that compares its result with a constant itself (``return encrypt(x) == TARGET``)
  states its own target: the comparison is traced to the pairs that must hold and inverted the same
  way, with no target to find.

  4. BLACK BOX.  When the trace itself is not possible (the cipher branches on the secret) the
     forward function is run concretely in the interpreter and the input recovered a position at a
     time, over a character set, using measured input/output dependence.

Never wrong: every value reported was re-run forward in a fresh interpreter and produced the target
exactly.  What cannot be modelled is named (``Unsupported``), never guessed around.

By hand:

    tools/ctfpy solvers/toolkits/cipher_invert.py lattice.py --target hex:c402fb... [--func enc]
    python -m ctf run toolkits.cipher_invert <challenge_dir> [--opt target=hex:..] [--opt func=enc]
        [--opt input=bytes|str|int] [--opt length=44] [--opt charset=printable]
        [--opt input_name=FLAG] [--opt output_name=ct] [--opt budget_s=20]
        [--opt source=recon/engines/binary.sandbox_recover/cipher.py]   # a source outside the handout
"""
from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import re
import sys
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:               # the lane is on sys.path under the engine boot and the tests
    sys.path.insert(1, str(HERE))

import _cipher_vm as cvm                    # noqa: E402  (flat import: the interpreter beside this file)
from _cipher_vm import (BudgetExceeded, Check, Encoded, Func, Inst, Klass, Mixed, Module,  # noqa: E402
                        Poison, Sym, SymBytes, SymStr, Unsupported, operands)

# ---------------------------------------------------------------------------- bounds (hard caps)
MAX_SOURCE_BYTES = 512 * 1024        # a Python source larger than this is not parsed
MAX_SOURCES = 6                      # handout sources tried by solve()
MAX_SIDE_FILES = 16                  # other handout files read for a target
MAX_SIDE_BYTES = 256 * 1024
MAX_FORWARDS = 12                    # forward functions / input variables tried per source
MAX_TARGETS = 16                     # targets tried per source
MAX_LENGTHS = 40                     # input lengths swept per (function, target, type)
MAX_INPUT = 4096                     # input bytes / characters
MAX_WIDTH = 8192                     # bits of one traced value
MAX_TABLE = 4096                     # entries of a lookup table enumerated backward or given to z3
MAX_ENUM_BITS = 12                   # a mod/div operand this narrow is inverted by enumeration
MAX_SMT_CALLS = 6                    # z3 solves per recover()
MAX_BLACKBOX = 4                     # black-box searches per recover()
MAX_RESULTS = 4                      # verified preimages kept by one recover()
BLACKBOX_BEAM = 32                   # prefixes kept per position
DEFAULT_BUDGET_S = 20.0              # recover()'s whole-run wall-clock budget
DEFAULT_TIMEOUT_MS = 8000            # one z3 solve (symbolic.py clamps it)
PRINTABLE = tuple(range(0x20, 0x7F))
_ENGINE = "toolkits.cipher_invert"


class InvertError(ValueError):
    """A bad argument or an unusable source (named in the message)."""


class _Conflict(Exception):
    """The target contradicts the traced computation: no input produces it."""


def _symbolic():
    """solvers/toolkits/symbolic.py (the z3 layer), or RuntimeError naming what is missing."""
    try:
        import symbolic
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"solvers/toolkits/symbolic.py is not importable ({exc})") from exc
    symbolic._require_z3()
    return symbolic


# ============================================================================ the bit-vector network

def _natural(v):
    return v.rng is not None and v.rng[0] >= 0


def _low_known(k):
    """How many low bits of the mask ``k`` are set without a gap."""
    return (k ^ (k + 1)).bit_length() - 1


class Net:
    """The traced computation behind some outputs, as fixed-width bit-vectors.

    ``pairs`` is [(Sym, wanted value)].  Each node gets a width: the bit length of its range when it
    is known non-negative, else (a value that may be negative or unbounded, meaningful only modulo a
    power of two) the widest slice any consumer reads.  ``propagate()`` then pushes known bits forward
    and backward through every node to a fixpoint; ``constraints()`` lowers the same network to z3.
    """

    def __init__(self, pairs, *, clock=None, deadline=None):
        self.pairs = [(a, int(b)) for a, b in pairs if isinstance(a, Sym)]
        self.clock, self.deadline = clock, deadline
        nodes = {}
        stack = [a for a, _ in self.pairs]
        while stack:
            n = stack.pop()
            if n.uid in nodes:
                continue
            nodes[n.uid] = n
            stack.extend(a for a in operands(n) if isinstance(a, Sym))
        self.nodes = nodes
        self.order = [nodes[u] for u in sorted(nodes)]
        self.inputs = {n.args[0]: n for n in self.order if n.op == "in"}
        self.users = {u: [] for u in nodes}
        for n in self.order:
            for a in operands(n):
                if isinstance(a, Sym):
                    self.users[a.uid].append(n.uid)
        self.W = self._widths()
        self.K = dict.fromkeys(nodes, 0)        # mask of known bits
        self.V = dict.fromkeys(nodes, 0)        # their values
        self._q: deque = deque()
        self._queued: set = set()

    def _widths(self):
        W, demand = {}, {}
        for n in reversed(self.order):
            if _natural(n):
                w = max(n.rng[1].bit_length(), 1)
            else:
                w = demand.get(n.uid)
                if w is None:
                    raise Unsupported("an output value may be negative or has no known range")
            if w > MAX_WIDTH:
                raise Unsupported(f"a traced value is wider than {MAX_WIDTH} bits")
            W[n.uid] = w
            op = n.op
            if op in ("xor", "and", "or", "add", "sub", "mul", "shl", "ite"):
                need = max(w - n.args[1], 1) if op == "shl" else w
                for a in operands(n):
                    if isinstance(a, Sym) and not _natural(a):
                        demand[a.uid] = max(demand.get(a.uid, 0), need)
            else:
                for a in operands(n):
                    if isinstance(a, Sym) and not _natural(a):
                        raise Unsupported(f"internal: {op} of a value with no known range")
        return W

    def primitives(self):
        """What the forward function applied to the secret, counted by primitive."""
        names = {"xor": "xor", "and": "mask", "or": "or", "add": "add", "sub": "subtract",
                 "mul": "multiply", "shl": "shift", "shr": "shift", "mod": "modulo", "div": "divide",
                 "cmp": "compare", "ite": "select"}
        out = Counter()
        for n in self.order:
            if n.op == "in":
                continue
            if n.op == "lookup":
                t = n.args[0]
                out["s-box" if len(set(t)) == len(t) else "table"] += 1
            else:
                out[names[n.op]] += 1
        return dict(out)

    # ------------------------------------------------------------------ known bits
    def _get(self, o, w):
        """(known mask, values) of operand ``o`` seen as ``w`` bits."""
        m = (1 << w) - 1
        if not isinstance(o, Sym):
            return m, o & m
        wo = self.W[o.uid]
        k, v = self.K[o.uid], self.V[o.uid]
        if wo >= w:
            return k & m, v & m
        return k | (m ^ ((1 << wo) - 1)), v          # a narrower non-negative value: zero above it

    def _learn(self, o, w, km, kv):
        """Record that bits ``km`` of ``o`` (seen as ``w`` bits) are ``kv``; a contradiction with
        what is already known, with a constant or with the node's range is a :class:`_Conflict`."""
        km &= (1 << w) - 1
        if not km:
            return
        kv &= km
        if not isinstance(o, Sym):
            if (o ^ kv) & km:
                raise _Conflict()
            return
        mo = (1 << self.W[o.uid]) - 1
        if kv & ~mo:
            raise _Conflict()                         # a bit above the value's width must be zero
        km &= mo
        k, v = self.K[o.uid], self.V[o.uid]
        if (v ^ kv) & k & km:
            raise _Conflict()
        new = km & ~k
        if new:
            self.K[o.uid] = k | new
            self.V[o.uid] = v | (kv & new)
            for uid in (o.uid, *self.users[o.uid]):
                if uid not in self._queued:
                    self._queued.add(uid)
                    self._q.append(uid)

    def propagate(self):
        """Run every rule to a fixpoint.  Raises :class:`_Conflict` when no input can produce the
        target.  Every bit set is implied by the target, so a fully known input is the only one."""
        self._q = deque(n.uid for n in self.order)
        self._queued = set(self._q)
        for a, want in self.pairs:
            w = self.W[a.uid]
            if want < 0 or want >> w:
                raise _Conflict()
            self._learn(a, w, (1 << w) - 1, want)
        work = 0
        while self._q:
            uid = self._q.popleft()
            self._queued.discard(uid)
            self._step(self.nodes[uid])
            work += 1
            if self.deadline is not None and not work & 0xFF and self.clock() > self.deadline:
                raise BudgetExceeded("time budget used up during propagation")

    def solved(self):
        """{input index: value} for the inputs whose every bit is known."""
        out = {}
        for i, n in self.inputs.items():
            if self.K[n.uid] == (1 << self.W[n.uid]) - 1:
                out[i] = self.V[n.uid]
        return out

    def _step(self, n):
        op = n.op
        if op == "in":
            return
        w = self.W[n.uid]
        M = (1 << w) - 1
        yk, yv = self.K[n.uid], self.V[n.uid]
        if op in ("xor", "and", "or"):
            a, b = n.args
            ak, av = self._get(a, w)
            bk, bv = self._get(b, w)
            if op == "xor":
                self._learn(n, w, ak & bk, av ^ bv)
                self._learn(a, w, yk & bk, yv ^ bv)
                self._learn(b, w, yk & ak, yv ^ av)
            elif op == "and":
                self._learn(n, w, (ak & bk) | (ak & ~av) | (bk & ~bv), av & bv)
                self._learn(a, w, (yk & yv) | (yk & ~yv & bk & bv), yv)
                self._learn(b, w, (yk & yv) | (yk & ~yv & ak & av), yv)
            else:
                self._learn(n, w, (ak & bk) | (ak & av) | (bk & bv), av | bv)
                self._learn(a, w, (yk & ~yv) | (yk & yv & bk & ~bv), yv & bk & ~bv)
                self._learn(b, w, (yk & ~yv) | (yk & yv & ak & ~av), yv & ak & ~av)
        elif op == "add":
            self._add(w, n.args[0], n.args[1], n)
        elif op == "sub":                             # n = a - b  <=>  a = n + b
            self._add(w, n, n.args[1], n.args[0])
        elif op == "mul":
            self._mul(w, n)
        elif op == "shl":
            a, k = n.args
            ak, av = self._get(a, w)
            self._learn(n, w, (ak << k) | ((1 << k) - 1), av << k)
            self._learn(a, w, yk >> k, yv >> k)
        elif op == "shr":
            a, k = n.args
            wa = self.W[a.uid]
            ak, av = self._get(a, wa)
            self._learn(n, w, ak >> k, av >> k)          # w <= wa - k: the range bounds the result
            self._learn(a, wa, yk << k, yv << k)
        elif op == "lookup":
            table, a = n.args
            self._table(n, a, w, table, 0, len(table) - 1)
        elif op in ("mod", "div"):
            a, m = n.args
            wa = self.W[a.uid]
            ak, av = self._get(a, wa)
            if ak == (1 << wa) - 1:
                self._learn(n, w, M, av % m if op == "mod" else av // m)
            elif wa <= MAX_ENUM_BITS and (ak or yk):
                f = (lambda i: i % m) if op == "mod" else (lambda i: i // m)
                self._table(n, a, w, f, a.rng[0], a.rng[1])
        elif op == "cmp":
            name, a, b = n.args
            wc = max(self.W[x.uid] if isinstance(x, Sym) else max(x.bit_length(), 1) for x in (a, b))
            ak, av = self._get(a, wc)
            bk, bv = self._get(b, wc)
            full = (1 << wc) - 1
            if ak == full and bk == full:
                self._learn(n, 1, 1, int(cvm._CMP[name](av, bv)))
        else:                                         # ite
            c, a, b = n.args
            ck, cv = self._get(c, 1)
            if ck:
                sel = a if cv else b
                sk, sv = self._get(sel, w)
                self._learn(n, w, sk, sv)
                self._learn(sel, w, yk, yv)
            else:
                ak, av = self._get(a, w)
                bk, bv = self._get(b, w)
                self._learn(n, w, ak & bk & ~(av ^ bv), av)

    def _add(self, w, a, b, s):
        """s = a + b (mod 2**w): learn every bit of the three that follows, bit-serially with the
        carry (which is known wherever two of its three inputs agree)."""
        M = (1 << w) - 1
        ak, av = self._get(a, w)
        bk, bv = self._get(b, w)
        sk, sv = self._get(s, w)
        if ak == M and bk == M:
            self._learn(s, w, M, av + bv)
            return
        if sk == M and bk == M:
            self._learn(a, w, M, sv - bv)
            return
        if sk == M and ak == M:
            self._learn(b, w, M, sv - av)
            return
        la = lb = ls = va = vb = vs = 0
        c = 0                                         # the carry into bit i: 0, 1 or None (unknown)
        for i in range(w):
            bit = 1 << i
            x = (av >> i) & 1 if ak & bit else None
            y = (bv >> i) & 1 if bk & bit else None
            z = (sv >> i) & 1 if sk & bit else None
            if c is None and x is not None and y is not None and z is not None:
                c = x ^ y ^ z
            if c is not None:
                if x is None and y is not None and z is not None:
                    x = y ^ z ^ c
                    la |= bit
                    va |= x << i
                elif y is None and x is not None and z is not None:
                    y = x ^ z ^ c
                    lb |= bit
                    vb |= y << i
                elif z is None and x is not None and y is not None:
                    z = x ^ y ^ c
                    ls |= bit
                    vs |= z << i
                elif x is not None and y is not None and z is not None and x ^ y ^ c != z:
                    raise _Conflict()
            known = [t for t in (x, y, c) if t is not None]
            if len(known) == 3:
                c = 1 if sum(known) >= 2 else 0
            elif len(known) == 2 and known[0] == known[1]:
                c = known[0]
            else:
                c = None
        self._learn(a, w, la, va)
        self._learn(b, w, lb, vb)
        self._learn(s, w, ls, vs)

    def _mul(self, w, n):
        """n = a * b (mod 2**w).  With one factor a known constant 2**t * odd, the low bits of the
        other factor and of the product determine each other through the odd part's inverse."""
        M = (1 << w) - 1
        a, b = n.args
        ak, av = self._get(a, w)
        bk, bv = self._get(b, w)
        if ak == M and bk == M:
            self._learn(n, w, M, av * bv)
            return
        yk, yv = self.K[n.uid], self.V[n.uid]
        for x, xk, xv, ck, c in ((a, ak, av, bk, bv), (b, bk, bv, ak, av)):
            if ck != M:
                continue
            if c == 0:
                self._learn(n, w, M, 0)
                continue
            t = (c & -c).bit_length() - 1
            j = min(_low_known(xk), w)
            fwd = min(w, j + t)
            if fwd:
                self._learn(n, w, (1 << fwd) - 1, (xv & ((1 << j) - 1)) * c)
            jy = min(_low_known(yk), w)
            if jy > t:                                # (a product whose low t bits are not zero is
                mod = 1 << (jy - t)                   # caught by the forward rule above)
                self._learn(x, w, mod - 1, ((yv >> t) * pow(c >> t, -1, mod)) % mod)

    def _table(self, n, a, w, table, lo, hi):
        """n = table[a] (a tuple, or a function of the index for mod/div): keep the indices that
        agree with what is known of ``a`` and of ``n``; the bits they all share become known."""
        wa = self.W[a.uid]
        Ma, M = (1 << wa) - 1, (1 << w) - 1
        ak, av = self._get(a, wa)
        yk, yv = self.K[n.uid], self.V[n.uid]
        get = table if callable(table) else table.__getitem__
        if ak == Ma:
            if not lo <= av <= hi:
                raise _Conflict()
            self._learn(n, w, M, get(av))
            return
        if not (ak or yk) or hi - lo >= MAX_TABLE:
            return
        and_i = and_t = -1
        or_i = or_t = 0
        found = False
        for i in range(lo, hi + 1):
            if (i & ak) != av:
                continue
            t = get(i)
            if (t & yk) != yv:
                continue
            found = True
            and_i &= i
            or_i |= i
            and_t &= t
            or_t |= t
        if not found:
            raise _Conflict()
        self._learn(a, wa, Ma & ~(and_i ^ or_i), and_i)
        self._learn(n, w, M & ~(and_t ^ or_t), and_t)

    # ------------------------------------------------------------------ z3
    def constraints(self, z3, variables):
        """z3 constraints equal to the network, over ``variables`` {input index: BitVec}.  A node
        propagation already pinned becomes a constant (its defining equation is asserted unless every
        operand is pinned too, which propagation has then already checked)."""
        E, cons = {}, []
        K, V, W = self.K, self.V, self.W

        def full(o):
            return not isinstance(o, Sym) or K[o.uid] == (1 << W[o.uid]) - 1

        def fetch(o, w):
            if not isinstance(o, Sym):
                return z3.BitVecVal(o & ((1 << w) - 1), w)
            e, wo = E[o.uid], W[o.uid]
            if wo > w:
                return z3.Extract(w - 1, 0, e)
            return z3.ZeroExt(w - wo, e) if wo < w else e

        def resize(e, wa, w):
            if wa > w:
                return z3.Extract(w - 1, 0, e)
            return z3.ZeroExt(w - wa, e) if wa < w else e

        for n in self.order:
            w, op = W[n.uid], n.op
            pinned = K[n.uid] == (1 << w) - 1
            if pinned and op != "in" and all(full(a) for a in operands(n)):
                E[n.uid] = z3.BitVecVal(V[n.uid], w)
                continue
            if op == "in":
                e = variables[n.args[0]]
                if K[n.uid] and not pinned:
                    cons.append(e & K[n.uid] == V[n.uid])
            elif op in ("xor", "and", "or", "add", "sub", "mul"):
                a, b = fetch(n.args[0], w), fetch(n.args[1], w)
                e = {"xor": lambda: a ^ b, "and": lambda: a & b, "or": lambda: a | b,
                     "add": lambda: a + b, "sub": lambda: a - b, "mul": lambda: a * b}[op]()
            elif op == "shl":
                e = fetch(n.args[0], w) << n.args[1] if n.args[1] < w else z3.BitVecVal(0, w)
            elif op == "shr":
                wa = W[n.args[0].uid]
                e = resize(z3.LShR(fetch(n.args[0], wa), n.args[1]), wa, w)
            elif op in ("mod", "div"):
                a, m = n.args
                wa = max(W[a.uid], m.bit_length())
                x, mv = fetch(a, wa), z3.BitVecVal(m, wa)
                e = resize(z3.URem(x, mv) if op == "mod" else z3.UDiv(x, mv), wa, w)
            elif op == "lookup":
                table, a = n.args
                if len(table) > MAX_TABLE:
                    raise Unsupported(f"a lookup table of {len(table)} entries is too large for z3")
                wa = W[a.uid]
                idx = fetch(a, wa)
                level = [z3.BitVecVal(t, w) for t in table] + \
                        [z3.BitVecVal(0, w)] * ((1 << wa) - len(table))
                for bit in range(wa):
                    sel = z3.Extract(bit, bit, idx) == 1
                    level = [z3.If(sel, level[j + 1], level[j]) for j in range(0, len(level), 2)]
                e = level[0]
            elif op == "cmp":
                name, a, b = n.args
                wc = max(W[x.uid] if isinstance(x, Sym) else max(x.bit_length(), 1) for x in (a, b))
                x, y = fetch(a, wc), fetch(b, wc)
                cond = {"eq": lambda: x == y, "ne": lambda: x != y, "lt": lambda: z3.ULT(x, y),
                        "le": lambda: z3.ULE(x, y), "gt": lambda: z3.UGT(x, y),
                        "ge": lambda: z3.UGE(x, y)}[name]()
                e = z3.If(cond, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
            else:                                     # ite
                c, a, b = n.args
                e = z3.If(fetch(c, 1) == 1, fetch(a, w), fetch(b, w))
            if pinned:
                cons.append(e == z3.BitVecVal(V[n.uid], w))
                E[n.uid] = z3.BitVecVal(V[n.uid], w)
            else:
                E[n.uid] = e
        for a, want in self.pairs:                    # the target itself (a no-op once propagated)
            w = W[a.uid]
            if want < 0 or want >> w:
                cons.append(z3.BoolVal(False))
            else:
                cons.append(E[a.uid] == z3.BitVecVal(want, w))
        return cons


# ============================================================================ forward functions

class Cipher:
    """A parsed cipher source.  ``fresh()`` evaluates the module in a new interpreter, so no state
    (a seeded generator, a counter) leaks from one forward run into the next."""

    def __init__(self, source, *, max_steps=cvm.DEFAULT_MAX_STEPS, deadline=None, clock=time.monotonic):
        if isinstance(source, bytes):
            source = source.decode("utf-8", "replace")
        if len(source) > MAX_SOURCE_BYTES:
            raise InvertError(f"source larger than {MAX_SOURCE_BYTES} bytes, not parsed")
        try:
            self.tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            raise InvertError(f"not parseable Python ({type(exc).__name__}: {exc})") from exc
        self.source = source
        self.max_steps, self.deadline, self.clock = max_steps, deadline, clock

    def fresh(self, inject=None):
        vm = cvm.VM(max_steps=self.max_steps, deadline=self.deadline, clock=self.clock,
                    inject=inject)
        return vm.run_module(self.tree)


@dataclass(frozen=True)
class Forward:
    """One way to run the cipher forward on a candidate secret: a function (``slot`` is the secret's
    parameter, ``bound`` names the module variables supplying the others) or the module itself with
    one variable replaced by the secret."""
    label: str
    kind: str                         # function | module
    name: str                         # function, instance.method, or the input variable
    slot: int = 0
    bound: tuple = ()
    output: str | None = None         # module: a variable also read as an output

    def run(self, cipher, x, vm=None):
        """The candidate outputs for secret ``x`` (a list: a module can print several values)."""
        if self.kind == "module":
            m = cipher.fresh(inject={self.name: x})
            outs = [v for args in m.printed for v in args] + list(m.written)
            if self.output is not None and self.output in m.root.vars:
                outs.append(m.root.vars[self.output])
            flat = []
            for v in outs:
                flat.extend(v.parts if isinstance(v, Mixed) else [v])
            return [v for v in flat if not isinstance(v, Poison)]
        m = vm if vm is not None else cipher.fresh()
        m.steps = 0
        fn = _resolve(m, self.name)
        if fn is None:
            raise InvertError(f"no function {self.name!r} in the source")
        args = [x if i == self.slot else m.live(m.root.vars[g]) for i, g in enumerate(self.bound)]
        return [fn(*args)]


def _resolve(m, name):
    g = m.root.vars
    if "." in name:
        inst, meth = name.split(".", 1)
        obj = g.get(inst)
        return m.getattr(obj, meth) if isinstance(obj, Inst) else None
    fn = g.get(name)
    return fn if isinstance(fn, Func) else None


_GOOD_FUNC = ("enc", "cipher", "scrambl", "seal", "obfus", "lock", "protect", "hide", "transform",
              "mix", "forward", "check")
_BAD_FUNC = ("dec", "unpad", "inv", "unscr", "rot", "pad", "sub", "lcg", "rand", "key", "gen",
             "main", "sbox", "perm")


def find_forwards(vm, *, func=None, input_name=None, output_name=None):
    """The ways to run the cipher forward, best first: module-level functions (and the methods of
    module-level instances) that can take the secret as one argument with every other required
    parameter supplied by a module variable of the same name, then the module itself for each
    variable it could not compute (a file read, an unknown import)."""
    g = vm.root.vars
    cands = []
    for name, v in g.items():
        if isinstance(v, Func):
            cands.append((name, v, 0))
        elif isinstance(v, Inst):
            for mname, mv in v.klass.attrs.items():
                if isinstance(mv, Func) and not mname.startswith("_") and not mv.static:
                    cands.append((f"{name}.{mname}", mv, 1))
    called = Counter()
    for _label, fn, _skip in cands:
        body = fn.node.body if isinstance(fn.node.body, list) else [fn.node.body]
        for st in body:
            for n in ast.walk(st):
                if isinstance(n, ast.Name):
                    called[n.id] += 1
                elif isinstance(n, ast.Attribute):
                    called[n.attr] += 1
    scored = []
    for order, (label, fn, skip) in enumerate(cands):
        short = label.split(".")[-1]
        if func is not None and func not in (label, short):
            continue
        a = fn.node.args
        params = [x.arg for x in a.posonlyargs + a.args][skip:]
        if not params or fn.is_gen:
            continue
        required = max(len(params) - len(fn.defaults), 0)
        low = short.lower()
        score = (3 if any(h in low for h in _GOOD_FUNC) else 0) \
            - (5 if any(h in low for h in _BAD_FUNC) else 0) + (2 if not called[short] else 0) \
            - (3 if short.startswith("_") else 0)
        for slot in range(max(required, 1)):
            bound, ok = [], True
            for i, q in enumerate(params[:max(required, slot + 1)]):
                if i == slot:
                    bound.append(None)
                    continue
                gname = next((k for k, val in g.items() if k.lower() == q.lower()
                              and not isinstance(val, (Func, Klass, Module, Poison))), None)
                if gname is None:
                    ok = False
                    break
                bound.append(gname)
            if ok:
                scored.append((-score, order, slot,
                               Forward(label if not slot else f"{label}[arg {slot}]", "function",
                                       label, slot, tuple(bound))))
    out = [f for *_k, f in sorted(scored, key=lambda t: t[:3])]
    names = [input_name] if input_name else list(vm.sources)
    mods = [Forward(f"module:{n}", "module", n, output=output_name) for n in names if n]
    if func is None:
        out = mods + out if input_name else out + mods
    return out


# ============================================================================ targets

@dataclass(frozen=True)
class Target:
    label: str
    value: object                     # bytes | str | int | list of ints | True (see TRUTH)


# "The function's own comparison holds": the target of a checker such as
# ``def check(x): return encrypt(x) == SEALED``.
TRUTH = Target("the function's own comparison", True)


_GOOD_TARGET = ("target", "ct", "cipher", "enc", "sealed", "out", "expect", "result", "token",
                "digest", "check", "flag", "secret")
_BAD_TARGET = ("box", "key", "rk", "perm", "table", "const", "alphabet", "iv", "seed", "round",
               "mask", "rot")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:0x)?((?:[0-9A-Fa-f]{2}){4,})(?![0-9A-Fa-f])")
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{12,}={0,2})(?![A-Za-z0-9+/=])")
_INT_RE = re.compile(r"(?<![0-9A-Za-z])(\d{10,})(?![0-9A-Za-z])")
_LIST_RE = re.compile(r"\[[^\[\]]{3,}\]")


def _is_int_list(v):
    return (isinstance(v, (list, tuple)) and len(v) >= 4
            and all(isinstance(x, int) and not isinstance(x, bool) for x in v))


def text_targets(text, label):
    """The values a piece of text may hold: itself, its hex runs (as bytes and as an integer), its
    base64 runs, its integer lists and its long decimal integers."""
    out = []
    for m in _HEX_RE.finditer(text):
        raw = bytes.fromhex(m.group(1))
        out.append(Target(f"{label} (hex)", raw))
        out.append(Target(f"{label} (hex integer)", int.from_bytes(raw, "big")))
    for m in _LIST_RE.finditer(text):
        try:
            v = ast.literal_eval(m.group(0))
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            continue
        if _is_int_list(v):
            out.append(Target(f"{label} (list)", list(v)))
    for m in _B64_RE.finditer(text):
        tok = m.group(1)
        if len(tok) % 4 or _HEX_RE.fullmatch(tok):
            continue
        try:
            out.append(Target(f"{label} (base64)", base64.b64decode(tok, validate=True)))
        except (binascii.Error, ValueError):
            continue
    for m in _INT_RE.finditer(text):
        out.append(Target(f"{label} (integer)", int(m.group(1))))
    stripped = text.strip()
    if (4 <= len(stripped) <= MAX_INPUT * 4 and "\n" not in stripped
            and not _HEX_RE.fullmatch(stripped)):       # hex text is read as the bytes it spells
        out.append(Target(f"{label} (text)", stripped))
    return out


def parse_target(spec):
    """An explicit target: bytes, an int, a list of ints, or text ``hex:..``, ``b64:..``, ``int:..``,
    ``str:..``, ``list:[..]``; bare text is read as hex when it is hex, else as itself."""
    if isinstance(spec, (bytes, bytearray)):
        return Target("given", bytes(spec))
    if isinstance(spec, bool) or spec is None:
        raise InvertError("target must be bytes, an integer, a list of integers or text")
    if isinstance(spec, int):
        return Target("given", spec)
    if isinstance(spec, (list, tuple)):
        if not all(isinstance(x, int) and not isinstance(x, bool) for x in spec):
            raise InvertError("a list target must hold integers only")
        return Target("given", list(spec))
    if not isinstance(spec, str):
        raise InvertError("target must be bytes, an integer, a list of integers or text")
    kind, _, rest = spec.partition(":")
    try:
        if kind == "hex":
            return Target("given", bytes.fromhex(rest))
        if kind == "b64":
            return Target("given", base64.b64decode(rest, validate=True))
        if kind == "int":
            return Target("given", int(rest, 0))
        if kind == "str":
            return Target("given", rest)
        if kind == "list":
            v = ast.literal_eval(rest)
            if not _is_int_list(v) and not (isinstance(v, (list, tuple)) and v
                                            and all(isinstance(x, int) for x in v)):
                raise ValueError("not a list of integers")
            return Target("given", list(v))
        if re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", spec):
            return Target("given", bytes.fromhex(spec))
    except (ValueError, SyntaxError, binascii.Error) as exc:
        raise InvertError(f"bad target {spec[:40]!r}: {exc}") from exc
    return Target("given", spec)


def find_targets(vm, cipher, side_texts=(), side_blobs=()):
    """Candidate targets, best first: module-level constants, constants and hex comments elsewhere
    in the source, and what the other handout files hold."""
    scored = []

    def add(score, t):
        scored.append((-score, len(scored), t))

    for name, v in vm.root.vars.items():
        if name.startswith("_"):
            continue
        low = name.lower()
        score = 4 + (3 if any(h in low for h in _GOOD_TARGET) else 0) \
            - (4 if any(h in low for h in _BAD_TARGET) else 0)
        if isinstance(v, bytes) and len(v) >= 4:
            add(score, Target(f"variable {name}", v))
        elif _is_int_list(v):
            add(score, Target(f"variable {name}", list(v)))
        elif isinstance(v, int) and not isinstance(v, bool) and v >= 1 << 32:
            add(score, Target(f"variable {name}", v))
        elif isinstance(v, str) and len(v) >= 8:
            for t in text_targets(v, f"variable {name}"):
                add(score, t)
    seen_nodes = set()
    for st in cipher.tree.body:
        for n in ast.walk(st):
            if isinstance(n, ast.Constant) and id(n) not in seen_nodes:
                seen_nodes.add(id(n))
                if isinstance(n.value, bytes) and len(n.value) >= 8:
                    add(1, Target(f"constant at line {n.lineno}", n.value))
                elif isinstance(n.value, str) and len(n.value) >= 16:
                    for t in text_targets(n.value, f"constant at line {n.lineno}"):
                        add(1, t)
    for i, line in enumerate(cipher.source.splitlines(), 1):
        if "#" in line:
            for t in text_targets(line.split("#", 1)[1], f"comment at line {i}"):
                if not isinstance(t.value, str):
                    add(2, t)
    for label, text in side_texts:                    # another handout file is the likeliest target
        for t in text_targets(text, label):
            add(8, t)
    for label, blob in side_blobs:
        if 4 <= len(blob) <= MAX_SIDE_BYTES:
            add(8, Target(label, blob))
    out, seen = [], set()
    for _s, _i, t in sorted(scored, key=lambda x: x[:2]):
        key = (type(t.value).__name__, repr(t.value))
        if key not in seen:
            seen.add(key)
            out.append(t)
    return out


# ============================================================================ output matching

def _flat(v):
    """A value as a flat list of numbers (ints and Syms), or None when it is not number-like."""
    if isinstance(v, (bytes, bytearray)):
        return list(v)
    if isinstance(v, SymBytes):
        return list(v.items)
    if isinstance(v, str):
        return [ord(c) for c in v]
    if isinstance(v, SymStr):
        return [ord(c) if isinstance(c, str) else c for c in v.items]
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, Sym)):
        return [v]
    if isinstance(v, (list, tuple)):
        out = []
        for x in v:
            sub = _flat(x)
            if sub is None:
                return None
            out.extend(sub)
        return out
    return None


def pairs_for(out, target, _depth=0):
    """[(output number, wanted integer)] when the output has the target's shape, else None."""
    want = target.value
    if want is True:                                  # TRUTH: the function's own comparison
        if isinstance(out, Check):
            return list(out.pairs)
        if out is True or out is False:
            return [(int(out), 1)]
        return None
    if isinstance(out, Encoded):
        raw = None
        if isinstance(want, (bytes, bytearray)) and len(want) == len(out.data):
            raw = bytes(want)
        else:
            text = want.decode("ascii", "replace") if isinstance(want, (bytes, bytearray)) else want
            if isinstance(text, str):
                try:
                    raw = (bytes.fromhex(text.strip()) if out.kind == "hex"
                           else base64.b64decode(text.strip(), validate=True))
                except (ValueError, binascii.Error):
                    raw = None
        if raw is None or len(raw) != len(out.data):
            return None
        return list(zip(_flat(out.data), raw))
    if isinstance(want, int) != (isinstance(out, (int, Sym)) and not isinstance(out, bool)):
        return _text_pairs(out, target) if isinstance(want, int) and _depth == 0 else None
    a, b = _flat(out), _flat(want)
    if a is None or b is None or not a:
        return None
    if len(a) != len(b):
        return _text_pairs(out, target) if _depth == 0 else None
    return list(zip(a, b))


def _text_pairs(out, target):
    """A concrete text output read the way a target file is read (its hex, base64 and list forms):
    the mirror of what the trace keeps opaque (``.hex()``, base64, an f-string around a value)."""
    if not isinstance(out, (str, bytes)):
        return None
    text = out.decode("latin-1") if isinstance(out, bytes) else out
    if len(text) > MAX_INPUT * 8:
        return None
    for t in text_targets(text, "output"):
        if type(t.value) is type(target.value) and t.value != text:
            pairs = pairs_for(t.value, target, _depth=1)
            if pairs is not None:
                return pairs
    return None


# ============================================================================ one inversion attempt

@dataclass
class Recovered:
    """A verified preimage: running ``func`` forward on each of ``values`` gives the target."""
    func: str
    target: str
    kind: str                          # bytes | str | int
    length: int                        # bytes / characters / bits of the input
    method: str                        # algebraic | smt | blackbox
    unique: bool                       # proved the only preimage of that type and length
    values: list
    primitives: dict = field(default_factory=dict)
    caveat: str = ""

    def text(self, value=None):
        v = self.values[0] if value is None else value
        if isinstance(v, bytes):
            return v.decode("latin-1")
        if isinstance(v, int):
            return v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big").decode("latin-1")
        return v


@dataclass
class Attempt:
    status: str                        # recovered | no-preimage | shape | error | unsolved
    reason: str = ""
    recovered: Recovered | None = None
    matched: bool = False              # an output had the target's shape (the pairing is plausible)
    fatal: bool = False                # the forward function cannot take this input type at all


def make_input(kind, n):
    """(symbols, value) for a secret of ``n`` bytes / characters / bits."""
    if kind == "bytes":
        syms = [Sym("in", (i,), (0, 255)) for i in range(n)]
        return syms, SymBytes(syms)
    if kind == "str":
        syms = [Sym("in", (i,), (0, 127)) for i in range(n)]
        return syms, SymStr(syms)
    if kind == "int":
        s = Sym("in", (0,), (0, (1 << n) - 1))
        return [s], s
    raise InvertError(f"input type must be bytes, str or int, not {kind!r}")


def concrete_input(kind, vals):
    if kind == "bytes":
        return bytes(vals)
    if kind == "str":
        return "".join(chr(v) for v in vals)
    return vals[0]


def verify(cipher, forward, x, target):
    """Whether running forward on the concrete ``x`` in a fresh interpreter gives the target."""
    for out in forward.run(cipher, x):
        pairs = pairs_for(out, target)
        if pairs is not None and all(not isinstance(a, Sym) and a == b for a, b in pairs):
            return True
    return False


def _why(exc):
    return str(exc) if isinstance(exc, (Unsupported, BudgetExceeded, InvertError)) \
        else f"{type(exc).__name__}: {exc}"


def parse_charset(spec):
    """A character set as a sorted tuple of code points, from a name, text, a (lo, hi) pair or ints."""
    if spec is None:
        return None
    named = {"printable": PRINTABLE, "ascii": tuple(range(128)), "all": tuple(range(256)),
             "hex": tuple(b"0123456789abcdef"), "digits": tuple(b"0123456789"),
             "lower": tuple(range(0x61, 0x7B)), "upper": tuple(range(0x41, 0x5B)),
             "alnum": tuple(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")}
    if isinstance(spec, str):
        vals = named.get(spec) or tuple(ord(c) for c in spec)
    elif isinstance(spec, bytes):
        vals = tuple(spec)
    elif (isinstance(spec, tuple) and len(spec) == 2 and all(isinstance(x, int) for x in spec)
          and spec[0] <= spec[1]):
        vals = tuple(range(spec[0], spec[1] + 1))
    else:
        vals = tuple(int(x) for x in spec)
    vals = tuple(sorted(set(vals)))
    if not vals or vals[0] < 0 or vals[-1] > 0x10FFFF:
        raise InvertError("charset must be a non-empty set of code points")
    return vals


class _Run:
    """Shared state of one recover(): the trace cache and the solver / search allowances."""

    def __init__(self, cipher, *, charset, timeout_ms, use_smt, use_blackbox, clock, deadline):
        self.cipher, self.charset, self.timeout_ms = cipher, charset, timeout_ms
        self.use_smt, self.use_blackbox = use_smt, use_blackbox
        self.clock, self.deadline = clock, deadline
        self.traces: dict = {}
        self.concrete: dict = {}
        self.smt_calls = 0
        self.blackbox_runs = 0
        self.blocked = ""

    def expired(self):
        return self.clock() > self.deadline

    def trace(self, forward, kind, n):
        key = (forward.label, kind, n)
        if key not in self.traces:
            syms, x = make_input(kind, n)
            try:
                self.traces[key] = (forward.run(self.cipher, x), None)
            except BudgetExceeded as exc:
                if self.expired():
                    raise
                self.traces[key] = (None, str(exc))
            except RecursionError:
                self.traces[key] = (None, "the source recurses too deeply to trace")
            except Exception as exc:  # noqa: BLE001 - the source is data; the reason is reported
                self.traces[key] = (None, _why(exc))
        return self.traces[key]


def attempt(run, forward, target, kind, n):
    """Try to invert ``forward`` on ``target`` for a secret of type ``kind`` and size ``n``."""
    cipher = run.cipher
    outs, err = run.trace(forward, kind, n)
    if err is not None:
        if kind == "int":
            return Attempt("error", err, fatal=True)
        return _blackbox(run, forward, target, kind, n, f"cannot trace ({err})")
    matched = False
    reason = ""
    for out in outs:
        pairs = pairs_for(out, target)
        if pairs is None:
            continue
        matched = True
        if any(not isinstance(a, Sym) and a != b for a, b in pairs):
            reason = "a constant part of the output differs from the target"
            continue
        if not any(isinstance(a, Sym) for a, _ in pairs):
            reason = "the output does not depend on the input"
            continue
        try:
            net = Net(pairs, clock=run.clock, deadline=run.deadline)
            net.propagate()
        except _Conflict:
            reason = "the target is outside what the function can produce at this length"
            continue
        except Unsupported as exc:
            return _blackbox(run, forward, target, kind, n, str(exc), matched=True)
        total = 1 if kind == "int" else n
        known = net.solved()
        free = total - len(net.inputs)
        caveat = (f"{free} input position(s) do not affect the output and were set to zero"
                  if free else "")
        if len(known) == len(net.inputs):
            vals = [known.get(i, 0) for i in range(total)]
            x = concrete_input(kind, vals)
            if verify(cipher, forward, x, target):
                return Attempt("recovered", matched=True, recovered=Recovered(
                    forward.label, target.label, kind, n, "algebraic", not free, [x],
                    net.primitives(), caveat))
            return Attempt("error", "internal: the propagated input does not reproduce the target",
                           matched=True)
        att = _smt(run, forward, target, kind, n, net, total, caveat)
        if att is not None:
            if att.status in ("recovered", "no-preimage"):
                if att.status == "recovered":
                    return att
                reason = att.reason
                continue
            return _blackbox(run, forward, target, kind, n, att.reason, matched=True)
        return _blackbox(run, forward, target, kind, n,
                         f"{len(net.inputs) - len(known)} of {len(net.inputs)} input symbol(s) are "
                         "not determined by propagation and the SMT fallback is off or used up",
                         matched=True)
    if matched:
        return Attempt("no-preimage", reason, matched=True)
    return Attempt("shape", "no output has the target's shape")


def _smt(run, forward, target, kind, n, net, total, caveat):
    """The z3 fallback over what propagation left open.  None when it is off or used up."""
    if not run.use_smt or run.smt_calls >= MAX_SMT_CALLS:
        return None
    try:
        symbolic = _symbolic()
    except RuntimeError as exc:
        run.blocked = f"the SMT fallback needs z3: {exc}"
        return Attempt("unsolved", run.blocked, matched=True)
    idxs = sorted(net.inputs)
    widths = [net.W[net.inputs[i].uid] for i in idxs]
    if len(idxs) > symbolic.MAX_VARS or max(widths) > symbolic.MAX_BITS:
        return Attempt("unsolved", "too many or too wide input symbols for the SMT fallback",
                       matched=True)
    tried_charsets = [run.charset] if run.charset is not None or kind == "int" else [None, PRINTABLE]
    note = ""
    for charset in tried_charsets:
        if run.smt_calls >= MAX_SMT_CALLS:
            break
        run.smt_calls += 1

        def build(vs, charset=charset):
            import z3
            cons = net.constraints(z3, dict(zip(idxs, vs)))
            if charset is not None and kind != "int":
                for v, w in zip(vs, widths):
                    ok = [c for c in charset if c >> w == 0]
                    cons.append(z3.Or([v == c for c in ok]) if ok else z3.BoolVal(False))
            return cons

        try:
            sol = symbolic.solve_bitvecs(widths, build, timeout_ms=run.timeout_ms)
        except Unsupported as exc:
            return Attempt("unsolved", str(exc), matched=True)
        if sol.status == symbolic.UNSAT:
            if charset is None or charset is run.charset:
                return Attempt("no-preimage", "z3 proved no input of this length gives the target"
                               + (" within the character set" if charset is not None else ""),
                               matched=True)
            break
        if sol.status in (symbolic.UNIQUE, symbolic.MULTIPLE):
            values = []
            for model in sol.models:
                by_idx = {i: int(model[f"v{j}"]) for j, i in enumerate(idxs)}
                x = concrete_input(kind, [by_idx.get(i, 0) for i in range(total)])
                if verify(run.cipher, forward, x, target):
                    values.append(x)
            if not values:
                return Attempt("error", "internal: a z3 model does not reproduce the target",
                               matched=True)
            unique = sol.status == symbolic.UNIQUE and not caveat and charset is None
            notes = [caveat] if caveat else []
            if charset is not None and charset is not run.charset:
                notes.append("unique only among printable-ASCII inputs" if len(values) == 1
                             else "restricted to printable-ASCII inputs")
            elif charset is not None:
                notes.append("restricted to the given character set")
            if len(values) > 1:
                notes.append(f"{len(values)} inputs give the target")
            return Attempt("recovered", matched=True, recovered=Recovered(
                forward.label, target.label, kind, n, "smt", unique, values, net.primitives(),
                "; ".join(notes)))
        note = f"z3: {sol.detail or sol.status}"
        if sol.status != symbolic.UNDERCONSTRAINED:
            break
    return Attempt("unsolved", note or "the SMT fallback did not finish", matched=True)


def _blackbox(run, forward, target, kind, n, why, matched=False):
    """Recover the input a position at a time by running the forward function concretely.

    Which output positions each input position influences is measured by changing that position.
    Positions are then fixed in the order the measurements allow: a position is next when some output
    depends only on it and on positions already fixed, and it is fixed by every such output.  Works
    for ciphers that are per-character or chained in one direction, whatever they branch on; anything
    it reports is re-run forward in a fresh interpreter first."""
    if kind == "int":
        return Attempt("unsolved", why, matched=matched)
    cipher = run.cipher
    charset = [c for c in (run.charset or PRINTABLE) if c < (256 if kind == "bytes" else 128)]
    vm = cipher.fresh() if forward.kind == "function" else None
    want = None

    def forward_run(vals):
        nonlocal want
        outs = forward.run(cipher, concrete_input(kind, vals), vm)
        for out in outs:
            pairs = pairs_for(out, target)
            if pairs is not None:
                want = [b for _a, b in pairs]
                return [a for a, _b in pairs]
        return None

    base = [charset[0] if charset else 0x41] * n
    key = (forward.label, kind, n, base[0])
    try:
        if key not in run.concrete:                  # the same base run serves every target
            try:
                run.concrete[key] = (forward.run(cipher, concrete_input(kind, base), vm), None)
            except BudgetExceeded:
                raise
            except Exception as exc:  # noqa: BLE001 - the source is data; the reason is reported
                run.concrete[key] = (None, exc)
        outs, failed = run.concrete[key]
        if failed is not None:
            raise failed
        ref = None
        for out in outs:
            pairs = pairs_for(out, target)
            if pairs is not None:
                want = [b for _a, b in pairs]
                ref = [a for a, _b in pairs]
                break
    except BudgetExceeded as exc:
        if run.expired():
            raise
        # the function does not finish inside the step budget on any input: stop trying this type
        return Attempt("error", f"{why}; and a concrete run does not finish ({exc})", fatal=True)
    except Exception as exc:  # noqa: BLE001 - the source is data; the reason is reported
        return Attempt("error", f"{why}; and it cannot run on a {kind} of {n} ({_why(exc)})",
                       matched=matched, fatal=not matched)
    if ref is None:
        if matched:
            return Attempt("unsolved", why, matched=True)
        return Attempt("shape", "no output has the target's shape")
    if target.value is True and not matched:
        return Attempt("shape", "a yes/no answer gives the black-box search nothing to follow")
    if not run.use_blackbox or len(charset) < 2 or target.value is True:
        return Attempt("unsolved", why, matched=True)
    if run.blackbox_runs >= MAX_BLACKBOX:
        return Attempt("unsolved", f"{why}; the black-box search allowance is used up", matched=True)
    run.blackbox_runs += 1
    try:
        feeds = [set() for _ in ref]                 # output position -> input positions it reads
        for i in range(n):
            for alt in (charset[1], charset[-1], charset[len(charset) // 2]):
                probe = list(base)
                probe[i] = alt
                got = forward_run(probe)
                if got is None:
                    return Attempt("unsolved", f"{why}; the output shape changes with the input",
                                   matched=True)
                for k, (p, q) in enumerate(zip(ref, got)):
                    if p != q:
                        feeds[k].add(i)
        todo = {i for i in range(n) if any(i in f for f in feeds)}
        if not todo:
            return Attempt("no-preimage", f"{why}; the output does not change with the input")
        free = n - len(todo)
        fixed: set = set()
        beam = [list(base)]
        while todo:
            ready = [i for i in sorted(todo) if any(i in f and f <= fixed | {i} for f in feeds)]
            i = ready[0] if ready else min(todo)
            checks = [k for k, f in enumerate(feeds) if f <= fixed | {i}]
            keep = []
            for vals in beam:
                for c in charset:
                    trial = list(vals)
                    trial[i] = c
                    got = forward_run(trial)
                    if got is not None and all(got[k] == want[k] for k in checks):
                        keep.append(trial)
                        if len(keep) > BLACKBOX_BEAM:
                            return Attempt("unsolved", f"{why}; black-box search: more than "
                                           f"{BLACKBOX_BEAM} candidates fit at position {i} (the "
                                           "cipher is not chained one position at a time)",
                                           matched=True)
            if not keep:
                return Attempt("unsolved", f"{why}; black-box search: no character of the set fits "
                               f"position {i}", matched=True)
            beam = keep
            todo.discard(i)
            fixed.add(i)
        values = [x for x in (concrete_input(kind, p) for p in beam)
                  if verify(cipher, forward, x, target)]
    except BudgetExceeded:
        raise
    except Exception as exc:  # noqa: BLE001 - the source is data; the reason is reported
        return Attempt("unsolved", f"{why}; black-box search stopped ({_why(exc)})", matched=True)
    if not values:
        return Attempt("unsolved", f"{why}; black-box search found no input that verifies",
                       matched=True)
    span = "the given character set" if run.charset is not None else "printable ASCII"
    notes = [f"searched over {span} only"]
    if free:
        notes.append(f"{free} input position(s) do not affect the output and were left as "
                     f"{chr(base[0])!r}")
    if len(values) > 1:
        notes.append(f"{len(values)} inputs give the target")
    return Attempt("recovered", matched=True, recovered=Recovered(
        forward.label, target.label, kind, n, "blackbox", False, values, {}, "; ".join(notes)))


# ============================================================================ the driver

@dataclass
class Report:
    recovered: list = field(default_factory=list)      # [Recovered]
    notes: list = field(default_factory=list)          # every reason something was not done, named
    promising: bool = False                            # a pairing fit but was not inverted
    incomplete: bool = False                           # the budget ran out or a cap was hit
    blocked: str = ""                                  # a missing dependency that stopped a step
    forwards: int = 0
    targets: int = 0
    attempts: int = 0


class _Enough(Exception):
    """recover() has what it was asked for."""


def _plausible(r):
    """Whether a recovered input reads as something a person chose: printable text, or a number.
    recover() stops at the first such result; a binary one may come from a wrong function/target
    pairing, so the sweep goes on (up to MAX_RESULTS) and plausible results are listed first."""
    for v in r.values:
        if isinstance(v, int):
            return True
        data = v.encode("latin-1", "replace") if isinstance(v, str) else v
        if data and all(0x20 <= c <= 0x7E for c in data):
            return True
    return False


def _trivial(r, target):
    """The recovered input is the target itself: the function passed it through unchanged (a
    conversion helper such as ``bytes(x)`` or ``x.strip()``), which inverts nothing."""
    if target.value is True:
        return False
    want = _flat(target.value)
    return all(_flat(v) == want for v in r.values)


def candidate_lengths(m):
    """Input sizes to try for a target of ``m`` elements: the same, shorter by up to a 16-byte
    padding block, a whole fraction (an expanding encoding), then shorter by up to 32."""
    cands = [m] + [m - d for d in range(1, 17)] + [m // q for q in (2, 3, 4, 8) if m % q == 0] \
        + [m - d for d in range(17, 33)]
    out = []
    for c in cands:
        if 1 <= c <= MAX_INPUT and c not in out:
            out.append(c)
    return out[:MAX_LENGTHS]


def _sizes(kind, target, length, hint=()):
    v = target.value
    if length is not None:
        return list(length)
    if v is True:                                     # no size of its own: the other targets' sizes
        if kind == "int":
            return [64, 32, 128, 16, 8, 256]
        out = []
        for m in hint:
            out.extend(c for c in candidate_lengths(m) if c not in out)
        return out[:MAX_LENGTHS]
    if kind == "int":
        bits = v.bit_length() if isinstance(v, int) else 8 * len(v)
        return [w for w in (8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096) if w >= bits][:2]
    if length is not None:
        return list(length)
    m = (v.bit_length() + 7) // 8 if isinstance(v, int) else len(v)
    return candidate_lengths(max(m, 1))


def recover(source, *, target=None, func=None, kind=None, length=None, charset=None,
            input_name=None, output_name=None, side_texts=(), side_blobs=(),
            timeout_ms=DEFAULT_TIMEOUT_MS, budget_s=DEFAULT_BUDGET_S,
            max_steps=cvm.DEFAULT_MAX_STEPS, use_smt=True, use_blackbox=True, find_all=False,
            clock=time.monotonic):
    """Invert the cipher in ``source`` and return a :class:`Report`.

    target       bytes / int / list / text (see :func:`parse_target`), or a list of them; default:
                 every candidate found in the source and in ``side_texts`` / ``side_blobs``
                 ([(label, text)] / [(label, bytes)], the other handout files).
    func         the forward function (``name`` or ``instance.method``); default: every candidate.
    kind         ``bytes`` | ``str`` | ``int``; default: each in turn.
    length       input size(s) (bytes, characters, or bits for ``int``); default: a sweep.
    charset      restrict the input (z3 and the black-box search); a name, text, (lo, hi) or ints.
    input_name / output_name   module mode: the variable holding the secret, a variable to read as
                 the output (what the module prints or writes is always read).
    find_all     keep going after the first plausible verified preimage.
    Stops at the first verified preimage that is printable text or a number (a binary one may come
    from a wrong function/target pairing, so the sweep goes on) unless ``find_all``, and at
    ``MAX_RESULTS`` in any case; printable results are listed first.  ``budget_s`` bounds the whole
    run on ``clock``, ``max_steps`` each interpreter.
    """
    rep = Report()
    budget_s = float(budget_s)
    if budget_s < 0:
        raise InvertError("budget_s must be >= 0 seconds")
    if kind is not None and kind not in ("bytes", "str", "int"):
        raise InvertError(f"input type must be bytes, str or int, not {kind!r}")
    if isinstance(length, int) and not isinstance(length, bool):
        length = [length]
    elif isinstance(length, str):
        length = [int(x) for x in length.replace(",", " ").split()]
    if length is not None:
        length = [int(x) for x in length]
        if not length or any(not 1 <= x <= MAX_INPUT * 8 for x in length):
            raise InvertError(f"length must be between 1 and {MAX_INPUT * 8}")
    charset = parse_charset(charset)
    deadline = clock() + budget_s
    cipher = Cipher(source, max_steps=max_steps, deadline=deadline, clock=clock)
    run = _Run(cipher, charset=charset, timeout_ms=timeout_ms, use_smt=use_smt,
               use_blackbox=use_blackbox, clock=clock, deadline=deadline)
    try:
        base = cipher.fresh()
    except BudgetExceeded as exc:
        rep.incomplete = True
        rep.notes.append(f"the module's own top level did not finish: {exc}")
        return rep
    rep.notes.extend(f"not evaluated: {s}" for s in base.skipped[:6])
    if len(base.skipped) > 6:
        rep.notes.append(f"... and {len(base.skipped) - 6} more top-level statement(s) not evaluated")
    forwards = find_forwards(base, func=func, input_name=input_name, output_name=output_name)
    if target is not None:
        specs = target if isinstance(target, list) and target and not isinstance(target[0], int) \
            else [target]
        targets = [t if isinstance(t, Target) else parse_target(t) for t in specs]
    else:
        targets = find_targets(base, cipher, side_texts, side_blobs)
    hint = list(dict.fromkeys(len(t.value) for t in targets
                              if isinstance(t.value, (bytes, str, list))))
    if target is None and (targets or length is not None):
        targets = [TRUTH] + targets                   # a checker function states its own target
    rep.forwards, rep.targets = len(forwards), len(targets)
    if not forwards:
        rep.notes.append("no forward function found" + (f" named {func!r}" if func else "")
                         + ": no module-level function takes the secret as one argument, and no "
                           "module variable is an unavailable input (pass func= or input_name=)")
        return rep
    if not targets:
        rep.notes.append("no target found in the source or beside it (pass target=)")
        return rep
    if len(forwards) > MAX_FORWARDS:
        rep.incomplete = True
        rep.notes.append(f"{len(forwards) - MAX_FORWARDS} forward function(s) beyond the cap of "
                         f"{MAX_FORWARDS} not tried")
    if len(targets) > MAX_TARGETS:
        rep.incomplete = True
        rep.notes.append(f"{len(targets) - MAX_TARGETS} target candidate(s) beyond the cap of "
                         f"{MAX_TARGETS} not tried")
    kinds = [kind] if kind else ["bytes", "str", "int"]
    seen_reasons = set()

    def note(fwd, tgt, k, n, why):
        key = (fwd.label, k, why)
        if why and key not in seen_reasons and len(seen_reasons) < 24:
            seen_reasons.add(key)
            rep.notes.append(f"{fwd.label} on {tgt.label} as {k}[{n}]: {why}")

    try:
        for fwd in forwards[:MAX_FORWARDS]:
            dead_kinds = set()
            for tgt in targets[:MAX_TARGETS]:
                done = False
                if tgt is TRUTH and fwd.kind != "function":
                    continue
                for k in kinds:
                    if k in dead_kinds or done:
                        continue
                    for n in _sizes(k, tgt, length, hint):
                        if clock() > deadline:
                            raise BudgetExceeded(f"time budget of {budget_s:g} s used up")
                        rep.attempts += 1
                        try:
                            att = attempt(run, fwd, tgt, k, n)
                        except BudgetExceeded as exc:
                            if run.expired():
                                raise
                            rep.incomplete = True
                            note(fwd, tgt, k, n, str(exc))
                            continue
                        except Exception as exc:  # noqa: BLE001 - the source is data: named, not fatal
                            rep.incomplete = True
                            note(fwd, tgt, k, n, f"stopped on an error ({_why(exc)})")
                            continue
                        rep.promising = rep.promising or att.status == "unsolved" \
                            or (att.status == "error" and att.matched)
                        if att.status == "recovered" and _trivial(att.recovered, tgt):
                            note(fwd, tgt, k, n, "the function returns this target unchanged: a "
                                                 "conversion, not a cipher to invert")
                            break
                        if att.status == "recovered":
                            done = True
                            if any(r.func == att.recovered.func and r.values == att.recovered.values
                                   for r in rep.recovered):
                                break                 # the same input again, through another reading
                            rep.recovered.append(att.recovered)
                            if (not find_all and _plausible(att.recovered)) \
                                    or len(rep.recovered) >= MAX_RESULTS:
                                raise _Enough()
                            break
                        if att.status != "shape":
                            note(fwd, tgt, k, n, att.reason)
                        if att.fatal:
                            dead_kinds.add(k)
                            break
    except _Enough:
        pass
    except BudgetExceeded as exc:
        rep.incomplete = True
        rep.notes.append(f"stopped: {exc}")
    rep.recovered.sort(key=lambda r: not _plausible(r))
    rep.blocked = run.blocked
    return rep


# ============================================================================ engine entry

_SKIP_DIRS = {"recon"}


def _handout(challenge_dir: Path):
    """``(sources, others, over)``: the Python sources and the other small files under ``files/``,
    ``unpacked/`` and the challenge root (intake's ``recon/`` and symlinks skipped), each once by
    content; ``over`` counts sources beyond the cap."""
    import os
    sources, others, seen = [], [], set()
    over = 0
    for root in (challenge_dir / "files", challenge_dir / "unpacked", challenge_dir):
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames
                                 if not (here == challenge_dir and d in _SKIP_DIRS)
                                 and not d.startswith(".") and not (here / d).is_symlink())
            for nm in sorted(filenames):
                f = here / nm
                if f.is_symlink() or not f.is_file() or nm.startswith("."):
                    continue
                try:
                    size = f.stat().st_size
                    if size > max(MAX_SOURCE_BYTES, MAX_SIDE_BYTES) or size == 0:
                        continue
                    blob = f.read_bytes()
                except OSError:
                    continue
                digest = hashlib.sha256(blob).digest()
                if digest in seen:
                    continue
                seen.add(digest)
                if nm.endswith(".py"):
                    if len(sources) < MAX_SOURCES:
                        sources.append((f, blob))
                    else:
                        over += 1
                elif (len(blob) <= MAX_SIDE_BYTES and len(others) < MAX_SIDE_FILES
                      and nm not in ("challenge.json", "notes.md")):
                    others.append((f, blob))
    return sources, others, over


def _side(others, challenge_dir):
    texts, blobs = [], []
    for f, blob in others:
        rel = str(f.relative_to(challenge_dir))
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            blobs.append((f"file {rel}", blob))
            continue
        if all(c.isprintable() or c.isspace() for c in text):
            texts.append((f"file {rel}", text))
            if 4 <= len(blob) <= 4096 and not _HEX_RE.fullmatch(text.strip()):
                blobs.append((f"file {rel} (raw)", blob.strip()))
        else:
            blobs.append((f"file {rel}", blob))
    return texts, blobs


def _show(v):
    return repr(v) if not isinstance(v, int) else hex(v)


def solve(challenge_dir, profile, *, target=None, func=None, input=None, length=None,  # noqa: A002
          charset=None, input_name=None, output_name=None, source=None,
          timeout_ms=DEFAULT_TIMEOUT_MS, budget_s=DEFAULT_BUDGET_S, clock=time.monotonic, **_opts):
    """Engine entry: invert the custom Python cipher in the handout and report the recovered input.

    ``solved`` when a verified, unique preimage is itself in the event flag format; ``candidate``
    when a verified preimage holds a flag but is not proved unique; ``unsure`` when an input was
    recovered that is not a flag (the usual case: a passphrase to give to a service -- it is in the
    notes and the evidence), or when a function and a target fit but the inversion did not finish
    (each reason named); ``blocked`` when the only thing missing was z3 for the SMT fallback;
    ``none`` when the handout has no Python source, or no function/target pairing fits.
    ``source`` names one source file to use instead of the handout's (relative to the challenge
    folder, or absolute): a recovered or hand-fixed copy, for instance under ``recon/``; an
    unreadable one is ``blocked``, named.
    The challenge code is never executed: it is parsed and evaluated by the closed interpreter.
    """
    from ctf.result import SolverResult, Evidence
    from ctf import flagfmt

    challenge_dir = Path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    sources, others, over = _handout(challenge_dir)
    if source is not None:
        path = Path(str(source))
        path = path if path.is_absolute() else challenge_dir / path
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                raise OSError("too large")
            sources, over = [(path, path.read_bytes())], 0
        except OSError as exc:
            return SolverResult(status="blocked", engine=_ENGINE,
                                notes=f"the source given ({source}) cannot be read "
                                      f"({type(exc).__name__}: {exc})")
    if not sources:
        return SolverResult(status="none", engine=_ENGINE,
                            notes="no Python source in the handout to invert")
    texts, blobs = _side(others, challenge_dir)
    started = clock()
    budget_s = float(budget_s)
    evidence, flags, found, notes = [], [], [], []
    unique_flag = False
    promising = incomplete = False
    blocked = ""
    if over:
        incomplete = True
        notes.append(f"{over} more Python source(s) beyond the cap of {MAX_SOURCES} not tried")
    for i, (f, blob) in enumerate(sources):
        inside = f.is_relative_to(challenge_dir)
        rel = str(f.relative_to(challenge_dir)) if inside else f.name
        left = budget_s - (clock() - started)
        if left <= 0:
            incomplete = True
            notes.append(f"{rel}: not tried, time budget of {budget_s:g} s used up")
            continue
        try:
            # an even share of what is left, so one large unrelated source cannot starve the rest
            rep = recover(blob, target=target, func=func, kind=input, length=length,
                          charset=charset, input_name=input_name, output_name=output_name,
                          side_texts=texts, side_blobs=blobs, timeout_ms=timeout_ms,
                          budget_s=left / (len(sources) - i), clock=clock)
        except InvertError as exc:
            notes.append(f"{rel}: {exc}")
            continue
        promising = promising or rep.promising
        incomplete = incomplete or rep.incomplete
        blocked = blocked or rep.blocked
        notes.extend(f"{rel}: {n}" for n in rep.notes)
        for r in rep.recovered:
            prims = ", ".join(f"{k} x{v}" for k, v in sorted(r.primitives.items()))
            for v in r.values:
                detail = (f"{rel}: {r.func}({_show(v)}) reproduces {r.target} "
                          f"[{r.method}, {r.kind} of {r.length}"
                          + (", proved the only preimage" if r.unique else "")
                          + (f"; {r.caveat}" if r.caveat else "")
                          + (f"; primitives: {prims}" if prims else "") + "]")
                evidence.append(Evidence(kind="recovered-input", detail=detail,
                                         path=rel if inside else None))
                found.append(f"{rel}: {r.func} <- {_show(v)} ({r.method}"
                             + (", unique" if r.unique else "") + ")")
                for fl in ff.find_flags(r.text(v)):
                    if fl not in flags:
                        flags.append(fl)
                        unique_flag = unique_flag or (r.unique and len(r.values) == 1)
        if rep.recovered:
            break
    tail = ("; " + "; ".join(notes)) if notes else ""
    if flags:
        status = "solved" if unique_flag and len(flags) == 1 else "candidate"
        return SolverResult(status=status, flags=tuple(flags), evidence=tuple(evidence),
                            engine=_ENGINE,
                            notes="recovered input is in the flag format (re-run forward, matches "
                                  "the target): " + "; ".join(found) + tail)
    if found:
        return SolverResult(status="unsure", evidence=tuple(evidence), engine=_ENGINE,
                            notes="recovered the cipher's input (re-run forward, matches the "
                                  "target; not itself a flag -- give it to whatever checks it): "
                                  + "; ".join(found) + tail)
    if blocked:                       # set only when a pairing fit and needed the missing solver
        return SolverResult(status="blocked", engine=_ENGINE, notes=blocked + tail)
    if promising or incomplete:
        head = ("a cipher function and a target fit but nothing was recovered" if promising
                else "nothing recovered, but the sweep did not complete")
        return SolverResult(status="unsure", engine=_ENGINE, notes=head + tail)
    return SolverResult(status="none", engine=_ENGINE,
                        notes="no function/target pairing in the handout's Python source inverted"
                              + tail)


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(description="Invert a custom Python cipher (static, no execution).")
    ap.add_argument("source", help="the cipher's Python source file")
    ap.add_argument("--target", help="hex:.. | b64:.. | int:.. | str:.. | list:[..] (default: found)")
    ap.add_argument("--func")
    ap.add_argument("--input", choices=("bytes", "str", "int"))
    ap.add_argument("--length")
    ap.add_argument("--charset")
    ap.add_argument("--input-name")
    ap.add_argument("--output-name")
    ap.add_argument("--budget-s", type=float, default=DEFAULT_BUDGET_S)
    a = ap.parse_args(argv)
    rep = recover(Path(a.source).read_bytes(), target=a.target, func=a.func, kind=a.input,
                  length=a.length, charset=a.charset, input_name=a.input_name,
                  output_name=a.output_name, budget_s=a.budget_s)
    print(json.dumps({"recovered": [{"func": r.func, "target": r.target, "input": r.kind,
                                     "length": r.length, "method": r.method, "unique": r.unique,
                                     "values": [_show(v) for v in r.values], "caveat": r.caveat,
                                     "primitives": r.primitives} for r in rep.recovered],
                      "notes": rep.notes, "incomplete": rep.incomplete, "blocked": rep.blocked},
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
