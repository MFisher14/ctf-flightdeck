"""The static interpreter behind cipher_invert (B-110).

A handout's cipher source is DATA here: it is parsed with ``ast`` and evaluated by this closed
interpreter, never compiled, imported or run by CPython.  The interpreter knows a subset of Python
(functions, generators, simple classes, loops, comprehensions, integer/bytes/str/list/dict work) and a
fixed whitelist of builtins and module stand-ins (hashlib, seeded random, struct, base64, binascii,
itertools, functools, operator, math, string, three Crypto.Util helpers).  There is no file, network,
process or import access: ``open`` for reading, ``input``, ``os`` and every unknown module raise
:class:`Unsupported` naming what was asked for, and attribute access is limited to listed methods (no
underscore names), so the source cannot reach the host interpreter's objects.

The secret input is a set of :class:`Sym` leaves.  Arithmetic on a Sym builds a DAG node carrying the
exact Python-integer semantics of the operation and a conservative value range; anything the DAG cannot
express (a branch on a secret, a secret shift count, a secret-dependent table) raises Unsupported with
the reason.  Concrete values stay ordinary Python objects, so one interpreter serves the symbolic trace,
the concrete re-check of a recovered input and the black-box search.
"""
from __future__ import annotations

import ast
import collections.abc
import itertools
import operator
import types

MAX_BITS = 8192                 # widest value a secret-dependent node may reach
MAX_SEQ = 1 << 22               # elements of one sequence the interpreter will build in one step
MAX_CONCRETE_BITS = 1 << 20     # bits of one concrete integer a single << or ** may produce
MAX_DEPTH = 40                  # nested interpreted calls
DEFAULT_MAX_STEPS = 3_000_000   # expression/statement evaluations in one interpreter


class Unsupported(Exception):
    """The source uses something the interpreter does not model; the message names it."""


class BudgetExceeded(Exception):
    """The step or time budget of an interpreter ran out."""


class _StopIter(Exception):
    """StopIteration as the interpreted source sees it (a real one cannot cross a generator frame)."""


_MISSING = object()


class _Return(Exception):
    def __init__(self, value):
        self.value = value


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


# ============================================================================ symbolic integers

_UID = itertools.count()
_PYOP = {"add": operator.add, "sub": operator.sub, "mul": operator.mul, "xor": operator.xor,
         "and": operator.and_, "or": operator.or_}
_CMP = {"eq": operator.eq, "ne": operator.ne, "lt": operator.lt, "le": operator.le,
        "gt": operator.gt, "ge": operator.ge}
_TABLES: dict = {}


class Sym:
    """One secret-dependent Python integer: a DAG node.

    ``op``/``args``: ``in`` (index,), ``add sub mul xor and or`` (a, b), ``shl shr`` (a, count),
    ``mod div`` (a, modulus), ``lookup`` (table, index), ``cmp`` (name, a, b), ``ite`` (cond, a, b).
    ``rng`` is an inclusive (lo, hi) bound on the value, or None when nothing is known (then only the
    low bits are meaningful, and the value must be masked before its magnitude is used).
    """
    __slots__ = ("op", "args", "rng", "uid")

    def __init__(self, op, args, rng):
        if rng is not None and max(abs(rng[0]), abs(rng[1])).bit_length() > MAX_BITS:
            raise Unsupported(f"a secret-dependent value grows past {MAX_BITS} bits")
        self.op, self.args, self.rng, self.uid = op, args, rng, next(_UID)

    __hash__ = object.__hash__

    def __repr__(self):
        return f"<secret {self.op}#{self.uid}>"

    def __bool__(self):
        raise Unsupported("a branch or truth test depends on the secret input")

    def __index__(self):
        raise Unsupported("a secret-dependent value is used as an index, count or size")

    def __add__(self, o): return _arith("add", self, o)
    def __radd__(self, o): return _arith("add", o, self)
    def __sub__(self, o): return _arith("sub", self, o)
    def __rsub__(self, o): return _arith("sub", o, self)
    def __mul__(self, o): return _arith("mul", self, o)
    def __rmul__(self, o): return _arith("mul", o, self)
    def __xor__(self, o): return _arith("xor", self, o)
    def __rxor__(self, o): return _arith("xor", o, self)
    def __and__(self, o): return _arith("and", self, o)
    def __rand__(self, o): return _arith("and", o, self)
    def __or__(self, o): return _arith("or", self, o)
    def __ror__(self, o): return _arith("or", o, self)
    def __lshift__(self, o): return _shift("shl", self, o)
    def __rshift__(self, o): return _shift("shr", self, o)
    def __mod__(self, o): return _divmod("mod", self, o)
    def __floordiv__(self, o): return _divmod("div", self, o)
    def __divmod__(self, o): return _divmod("div", self, o), _divmod("mod", self, o)
    def __neg__(self): return _arith("sub", 0, self)
    def __pos__(self): return self
    def __invert__(self): return _arith("sub", -1, self)
    def __eq__(self, o): return _compare("eq", self, o)
    def __ne__(self, o): return _compare("ne", self, o)
    def __lt__(self, o): return _compare("lt", self, o)
    def __le__(self, o): return _compare("le", self, o)
    def __gt__(self, o): return _compare("gt", self, o)
    def __ge__(self, o): return _compare("ge", self, o)

    def _secret_operand(self, *_a):
        raise Unsupported("a shift count, modulus, divisor or exponent depends on the secret input, "
                          "or a secret-dependent value is divided or raised to a power")

    __rlshift__ = __rrshift__ = __rmod__ = __rfloordiv__ = __rdivmod__ = _secret_operand
    __truediv__ = __rtruediv__ = __pow__ = __rpow__ = _secret_operand

    def to_bytes(self, length=1, byteorder="big", *, signed=False):
        if signed:
            raise Unsupported("signed to_bytes of a secret-dependent value")
        if byteorder not in ("big", "little"):
            raise ValueError("byteorder must be either 'little' or 'big'")
        if length > MAX_SEQ:
            raise Unsupported(f"to_bytes({length}) past the size limit")
        r = self.rng
        if r is None or r[0] < 0 or r[1] >= 1 << (8 * length):
            raise Unsupported(f"to_bytes({length}) of a secret-dependent value that may not fit "
                              "(mask it first)")
        items = [(self >> (8 * i)) & 0xFF for i in range(length)]
        if byteorder == "big":
            items.reverse()
        return mkbytes(items)


def _num(v):
    return isinstance(v, (int, Sym))


def _rng(v):
    return v.rng if isinstance(v, Sym) else (v, v)


def _bits(r):
    """Bit length of a range known to be non-negative, else None."""
    return r[1].bit_length() if r is not None and r[0] >= 0 else None


def _arith(op, a, b):
    if not (_num(a) and _num(b)):
        return NotImplemented
    if type(a) is bool:
        a = int(a)
    if type(b) is bool:
        b = int(b)
    ca, cb = not isinstance(a, Sym), not isinstance(b, Sym)
    if ca and cb:
        return _PYOP[op](a, b)
    ra, rb = _rng(a), _rng(b)
    if op == "add":
        if cb and b == 0:
            return a
        if ca and a == 0:
            return b
        rng = (ra[0] + rb[0], ra[1] + rb[1]) if ra and rb else None
    elif op == "sub":
        if cb and b == 0:
            return a
        rng = (ra[0] - rb[1], ra[1] - rb[0]) if ra and rb else None
    elif op == "mul":
        for c, isc, other in ((a, ca, b), (b, cb, a)):
            if isc and c == 0:
                return 0
            if isc and c == 1:
                return other
        if ra and rb:
            corners = [x * y for x in ra for y in rb]
            rng = (min(corners), max(corners))
        else:
            rng = None
    elif op in ("xor", "or"):
        if cb and b == 0:
            return a
        if ca and a == 0:
            return b
        na, nb = _bits(ra), _bits(rb)
        rng = (0, (1 << max(na, nb)) - 1) if na is not None and nb is not None else None
    else:                                           # and
        if (cb and b == 0) or (ca and a == 0):
            return 0
        if cb and b == -1:
            return a
        if ca and a == -1:
            return b
        na, nb = _bits(ra), _bits(rb)
        for x, nx, c, isc in ((a, na, b, cb), (b, nb, a, ca)):
            if isc and c >= 0 and nx is not None and c & ((1 << nx) - 1) == (1 << nx) - 1:
                return x                            # the mask keeps every bit the value can have
        his = [r[1] for r, n in ((ra, na), (rb, nb)) if n is not None]
        rng = (0, min(his)) if his else None
    return Sym(op, (a, b), rng)


def _shift(op, a, k):
    if isinstance(k, Sym):
        raise Unsupported("a shift count depends on the secret input")
    if not isinstance(k, int):
        return NotImplemented
    k = int(k)
    if k < 0:
        raise ValueError("negative shift count")
    if k == 0:
        return a
    r = a.rng
    if op == "shl":
        if k > MAX_BITS:
            raise Unsupported(f"a secret-dependent value is shifted left by {k} bits")
        return Sym("shl", (a, k), (r[0] << k, r[1] << k) if r else None)
    if r is None or r[0] < 0:
        raise Unsupported("right shift of a secret-dependent value that may be negative or has no "
                          "known range (mask it first)")
    if r[1] >> k == 0:
        return 0
    return Sym("shr", (a, k), (r[0] >> k, r[1] >> k))


def _divmod(op, a, m):
    if isinstance(m, Sym):
        raise Unsupported("a modulus or divisor depends on the secret input")
    if not isinstance(m, int):
        return NotImplemented
    m = int(m)
    if m == 0:
        raise ZeroDivisionError("integer division or modulo by zero")
    if m < 0:
        raise Unsupported("a negative modulus or divisor on a secret-dependent value")
    pow2 = m & (m - 1) == 0
    r = a.rng
    if op == "mod":
        if pow2:
            return _arith("and", a, m - 1)
        if r is None:
            raise Unsupported(f"modulo {m} of a secret-dependent value with no known range")
        if r[0] < 0:                                # shift into the non-negative range first
            a = _arith("add", a, m * (-r[0] // m + 1))
            r = a.rng
        if r[1] < m:
            return a
        return Sym("mod", (a, m), (0, m - 1))
    if r is None or r[0] < 0:
        raise Unsupported("floor division of a secret-dependent value that may be negative or has "
                          "no known range")
    if pow2:
        return _shift("shr", a, m.bit_length() - 1)
    if r[1] < m:
        return 0
    return Sym("div", (a, m), (r[0] // m, r[1] // m))


def _compare(op, a, b):
    if not (_num(a) and _num(b)):
        if op == "eq":
            return False
        if op == "ne":
            return True
        return NotImplemented
    if type(a) is bool:
        a = int(a)
    if type(b) is bool:
        b = int(b)
    ra, rb = _rng(a), _rng(b)
    if ra is None or rb is None:
        raise Unsupported("comparison of a secret-dependent value with no known range (mask it first)")
    if ra[1] < rb[0]:                               # decided by the ranges alone
        return op in ("lt", "le", "ne")
    if ra[0] > rb[1]:
        return op in ("gt", "ge", "ne")
    if (op == "le" and ra[1] <= rb[0]) or (op == "ge" and ra[0] >= rb[1]):
        return True
    if (op == "lt" and ra[0] >= rb[1]) or (op == "gt" and ra[1] <= rb[0]):
        return False
    off = -min(ra[0], rb[0])
    if off > 0:                                     # compare as non-negative numbers
        a, b = _arith("add", a, off), _arith("add", b, off)
    return Sym("cmp", (op, a, b), (0, 1))


def ite(c, a, b):
    """``a if c else b`` for a secret-dependent condition (both sides integers)."""
    if not isinstance(c, Sym):
        return a if c else b
    if not (_num(a) and _num(b)):
        raise Unsupported("a secret-dependent choice between values that are not integers")
    if a is b:
        return a
    if type(a) is bool:
        a = int(a)
    if type(b) is bool:
        b = int(b)
    if c.rng != (0, 1):
        c = _compare("ne", c, 0)
        if not isinstance(c, Sym):
            return a if c else b
    ra, rb = _rng(a), _rng(b)
    rng = (min(ra[0], rb[0]), max(ra[1], rb[1])) if ra and rb else None
    return Sym("ite", (c, a, b), rng)


def lookup(table, idx):
    """``table[idx]`` for a secret-dependent index into a table of non-negative integer constants."""
    n = len(table)
    r = idx.rng
    if r is None or r[0] < 0 or r[1] >= n:
        raise Unsupported(f"a secret-dependent index may fall outside its table of {n} entries "
                          "(mask it first)")
    key = tuple(table)
    hit = _TABLES.get(key)                           # a table checked before: (entries, range)
    if hit is None:
        if not all(isinstance(v, int) for v in key):
            raise Unsupported("a secret-dependent index into a table that holds secret-dependent "
                              "or non-integer values")
        vals = tuple(int(v) for v in key)
        if min(vals) < 0:
            raise Unsupported("a secret-dependent index into a table with negative entries")
        if len(_TABLES) > 1024:
            _TABLES.clear()
        hit = _TABLES[key] = (vals, (min(vals), max(vals)))
    return Sym("lookup", (hit[0], idx), hit[1])


def operands(n):
    """The Sym/int operands of a node (constants of the operation itself left out)."""
    op = n.op
    if op == "in":
        return ()
    if op == "lookup":
        return (n.args[1],)
    if op == "cmp":
        return n.args[1:]
    if op in ("shl", "shr", "mod", "div"):
        return (n.args[0],)
    return n.args


def evaluate(roots, inputs):
    """Concrete values of ``roots`` (Syms or ints) given ``inputs`` {index: int}: plain Python integer
    arithmetic, no widths.  Iterative, so a deep DAG cannot hit the recursion limit."""
    nodes = {}
    stack = [r for r in roots if isinstance(r, Sym)]
    while stack:
        n = stack.pop()
        if n.uid in nodes:
            continue
        nodes[n.uid] = n
        stack.extend(a for a in operands(n) if isinstance(a, Sym))
    val = {}

    def get(a):
        return val[a.uid] if isinstance(a, Sym) else a

    for uid in sorted(nodes):
        n = nodes[uid]
        op = n.op
        if op == "in":
            v = inputs[n.args[0]]
        elif op in _PYOP:
            v = _PYOP[op](get(n.args[0]), get(n.args[1]))
        elif op == "shl":
            v = get(n.args[0]) << n.args[1]
        elif op == "shr":
            v = get(n.args[0]) >> n.args[1]
        elif op == "mod":
            v = get(n.args[0]) % n.args[1]
        elif op == "div":
            v = get(n.args[0]) // n.args[1]
        elif op == "lookup":
            v = n.args[0][get(n.args[1])]
        elif op == "cmp":
            v = int(_CMP[n.args[0]](get(n.args[1]), get(n.args[2])))
        else:                                       # ite
            v = get(n.args[1]) if get(n.args[0]) else get(n.args[2])
        val[uid] = v
    return [get(r) for r in roots]


# ============================================================================ symbolic bytes / text

def _byte(v):
    if isinstance(v, Sym):
        r = v.rng
        if r is None or r[0] < 0:
            raise Unsupported("a secret-dependent byte may be negative or has no known range "
                              "(mask it first)")
        if r[1] > 255:
            # CPython raises ValueError when the value really exceeds 255, so the true input keeps
            # it in range and the low 8 bits are the value.  Masking only widens the set of inputs
            # the trace accepts; every reported input is re-run forward, where the source's own
            # error would show.
            return v & 0xFF
        return v
    if isinstance(v, int):
        if not 0 <= v <= 255:
            raise ValueError("bytes must be in range(0, 256)")
        return int(v)
    raise TypeError(f"'{type(v).__name__}' object cannot be interpreted as a byte")


def byte_items(v):
    """The elements of a bytes-like value (bytes, bytearray, SymBytes)."""
    if isinstance(v, SymBytes):
        return v.items
    if isinstance(v, (bytes, bytearray)):
        return list(v)
    raise TypeError(f"a bytes-like object is required, not '{type(v).__name__}'")


def mkbytes(items, mutable=False):
    """bytes from elements that may be secret: real ``bytes`` when every element is concrete and the
    value is immutable, else a :class:`SymBytes`."""
    items = [_byte(x) for x in items]
    if not mutable and not any(isinstance(x, Sym) for x in items):
        return bytes(items)
    return SymBytes(items, mutable)


class SymBytes:
    """bytes or bytearray whose elements may be secret.  Every bytearray is one (``mutable``), so a
    secret byte can be stored into it later."""
    __slots__ = ("items", "mutable")
    EXPOSED = frozenset({"hex", "decode", "append", "extend", "reverse", "copy", "pop"})

    def __init__(self, items, mutable=False):
        self.items = list(items)
        self.mutable = mutable

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        return iter(self.items)

    def __repr__(self):
        return f"<{'bytearray' if self.mutable else 'bytes'} of {len(self.items)}, secret-dependent>"

    def concrete(self):
        return not any(isinstance(x, Sym) for x in self.items)

    def __getitem__(self, i):
        if isinstance(i, slice):
            return mkbytes(self.items[i], self.mutable)
        return self.items[i]

    def __setitem__(self, i, v):
        if not self.mutable:
            raise TypeError("'bytes' object does not support item assignment")
        if isinstance(i, slice):
            self.items[i] = [_byte(x) for x in byte_items(v)]
        else:
            self.items[i] = _byte(v)

    def __add__(self, o):
        return mkbytes(self.items + list(byte_items(o)), self.mutable)

    def __radd__(self, o):
        return mkbytes(list(byte_items(o)) + self.items, isinstance(o, bytearray))

    def __iadd__(self, o):
        if not self.mutable:
            return self + o
        self.items.extend(_byte(x) for x in byte_items(o))
        return self

    def __mul__(self, n):
        if not isinstance(n, int):
            return NotImplemented
        if len(self.items) * n > MAX_SEQ:
            raise Unsupported("a byte string is repeated past the size limit")
        return mkbytes(self.items * n, self.mutable)

    __rmul__ = __mul__

    def __eq__(self, o):
        if not isinstance(o, (bytes, bytearray, SymBytes)):
            return False
        other = list(byte_items(o))
        if self.concrete() and not any(isinstance(x, Sym) for x in other):
            return self.items == other
        raise Unsupported("a comparison of secret-dependent bytes")

    def __ne__(self, o):
        return not self.__eq__(o)

    __hash__ = None

    # ---- the methods the interpreter exposes
    def hex(self, *args):
        if self.concrete():
            return bytes(self.items).hex(*args)
        if args:
            raise Unsupported("hex() with a separator on secret-dependent bytes")
        return Encoded("hex", mkbytes(self.items))

    def decode(self, encoding="utf-8", errors="strict"):
        if self.concrete():
            return bytes(self.items).decode(encoding, errors)
        top = 255 if encoding.lower().replace("-", "").replace("_", "") in ("latin1", "iso88591") else 127
        out = []
        for x in self.items:
            if isinstance(x, Sym):
                if x.rng[1] > top:
                    raise Unsupported(f"decode({encoding!r}) of secret-dependent bytes that may be "
                                      f"above {top}")
                out.append(x)
            else:
                out.append(bytes([x]).decode(encoding, errors))
        return mkstr(out)

    def append(self, v):
        self._need_mutable("append")
        self.items.append(_byte(v))

    def extend(self, vs):
        self._need_mutable("extend")
        self.items.extend(_byte(x) for x in vs)

    def reverse(self):
        self._need_mutable("reverse")
        self.items.reverse()

    def pop(self, i=-1):
        self._need_mutable("pop")
        return self.items.pop(i)

    def copy(self):
        return SymBytes(self.items, self.mutable)

    def _need_mutable(self, what):
        if not self.mutable:
            raise AttributeError(f"'bytes' object has no attribute '{what}'")


class SymStr:
    """str whose characters may be secret code points: items are 1-character strs or Syms."""
    __slots__ = ("items",)
    EXPOSED = frozenset({"encode"})

    def __init__(self, items):
        self.items = list(items)

    def __len__(self):
        return len(self.items)

    def __repr__(self):
        return f"<str of {len(self.items)}, secret-dependent>"

    def _one(self, x):
        return x if isinstance(x, str) else SymStr([x])

    def __iter__(self):
        return (self._one(x) for x in self.items)

    def __getitem__(self, i):
        if isinstance(i, slice):
            return mkstr(self.items[i])
        return self._one(self.items[i])

    def __add__(self, o):
        return mkstr(self.items + str_items(o))

    def __radd__(self, o):
        return mkstr(str_items(o) + self.items)

    def __mul__(self, n):
        if not isinstance(n, int):
            return NotImplemented
        if len(self.items) * n > MAX_SEQ:
            raise Unsupported("a string is repeated past the size limit")
        return mkstr(self.items * n)

    __rmul__ = __mul__

    def __eq__(self, o):
        if not isinstance(o, (str, SymStr)):
            return False
        raise Unsupported("a comparison of secret-dependent text")

    def __ne__(self, o):
        return not self.__eq__(o)

    __hash__ = None

    def encode(self, encoding="utf-8", errors="strict"):
        top = 255 if encoding.lower().replace("-", "").replace("_", "") in ("latin1", "iso88591") else 127
        out = []
        for x in self.items:
            if isinstance(x, Sym):
                if x.rng is None or x.rng[0] < 0 or x.rng[1] > top:
                    raise Unsupported(f"encode({encoding!r}) of a secret-dependent character that "
                                      f"may be above {top}")
                out.append(x)
            else:
                out.extend(x.encode(encoding, errors))
        return mkbytes(out)


def str_items(v):
    if isinstance(v, SymStr):
        return v.items
    if isinstance(v, str):
        return list(v)
    raise TypeError(f"can only concatenate str (not '{type(v).__name__}') to str")


def mkstr(items):
    items = list(items)
    if all(isinstance(x, str) for x in items):
        return "".join(items)
    return SymStr(items)


class Encoded:
    """The hex or base64 text of secret-dependent bytes, carried opaque until it meets the target."""
    __slots__ = ("kind", "data")
    EXPOSED = frozenset({"encode", "decode", "lower", "upper", "strip"})

    def __init__(self, kind, data):
        self.kind, self.data = kind, data

    def _same(self, *_a, **_k):
        return self

    encode = decode = lower = upper = strip = _same


class Check:
    """The outcome of comparing secret-dependent data with something for equality: the pairs
    (secret-dependent number, value it must equal) under which the comparison holds.  A function
    that returns one states its own target; branching on one is a branch on the secret."""
    __slots__ = ("pairs",)

    def __init__(self, pairs):
        self.pairs = list(pairs)

    def __bool__(self):
        raise Unsupported("a branch or truth test depends on a comparison of secret-dependent data")


def _numbers(v):
    """(kind, numbers) of a bytes-, str-, list- or tuple-like value, for an equality test."""
    if isinstance(v, (bytes, bytearray, SymBytes)):
        return "bytes", list(byte_items(v))
    if isinstance(v, (str, SymStr)):
        return "str", [ord(c) if isinstance(c, str) else c for c in str_items(v)]
    if isinstance(v, (list, tuple)):
        if not all(_num(x) for x in v):
            raise Unsupported("a comparison of nested secret-dependent sequences")
        return type(v).__name__, [int(x) if isinstance(x, bool) else x for x in v]
    return None, None


def sequence_equal(a, b):
    """``a == b`` for sequences of which at least one holds secret data: False when they cannot be
    equal, True when they always are, else a :class:`Check`."""
    ka, xs = _numbers(a)
    kb, ys = _numbers(b)
    if ka is None or ka != kb or len(xs) != len(ys):
        return False
    pairs = []
    for x, y in zip(xs, ys):
        sx, sy = isinstance(x, Sym), isinstance(y, Sym)
        if not sx and not sy:
            if x != y:
                return False
        elif sx and sy:
            if x is not y:
                pairs.append((x ^ y, 0))
        else:
            pairs.append((x, y) if sx else (y, x))
    return Check(pairs) if pairs else True


class Mixed:
    """Formatted text with secret-dependent parts (an f-string): only its parts are kept."""
    __slots__ = ("parts",)

    def __init__(self, parts):
        self.parts = list(parts)


class Poison:
    """A value the interpreter could not compute (a file read, an unknown module...): using it
    raises Unsupported with the reason."""
    __slots__ = ("reason",)

    def __init__(self, reason):
        self.reason = reason

    def __repr__(self):
        return f"<unavailable: {self.reason}>"


def is_secret(v):
    """Whether a value is, or directly holds, secret-dependent data."""
    if isinstance(v, (Sym, SymStr, Encoded, Mixed, Check)):
        return True
    if isinstance(v, SymBytes):
        return not v.concrete()
    if isinstance(v, (list, tuple)):
        return any(is_secret(x) for x in v)
    return False


def int_from_bytes(data, byteorder="big", *, signed=False):
    items = [_byte(x) for x in (data.items if isinstance(data, SymBytes) else data)]
    if not any(isinstance(x, Sym) for x in items):
        return int.from_bytes(bytes(items), byteorder, signed=signed)
    if signed:
        raise Unsupported("signed from_bytes of secret-dependent bytes")
    if byteorder not in ("big", "little"):
        raise ValueError("byteorder must be either 'little' or 'big'")
    if byteorder == "big":
        items.reverse()
    acc = 0
    for i, it in enumerate(items):
        acc = acc | (it << (8 * i))
    return acc


def _join_bytes(sep, parts):
    parts = list(parts)
    if all(isinstance(p, (bytes, bytearray)) for p in parts) and isinstance(sep, bytes):
        return sep.join(parts)
    out = []
    for i, p in enumerate(parts):
        if i:
            out.extend(byte_items(sep))
        out.extend(byte_items(p))
    return mkbytes(out)


def _join_str(sep, parts):
    parts = list(parts)
    if all(isinstance(p, str) for p in parts) and isinstance(sep, str):
        return sep.join(parts)
    out = []
    for i, p in enumerate(parts):
        if i:
            out.extend(str_items(sep))
        out.extend(str_items(p))
    return mkstr(out)


# ============================================================================ interpreter objects

class Scope:
    __slots__ = ("vars", "parent", "globs", "nonloc", "is_class")

    def __init__(self, vars_, parent, globs=(), nonloc=(), is_class=False):
        self.vars, self.parent = vars_, parent
        self.globs, self.nonloc, self.is_class = globs, nonloc, is_class


class Func:
    """An interpreted function or lambda: calling it runs the interpreter, so real builtins such as
    ``map``, ``sorted(key=...)`` and ``functools.reduce`` can take one."""

    def __init__(self, vm, node, scope, name):
        self.vm, self.node, self.scope, self.name = vm, node, scope, name
        a = node.args
        self.defaults = [vm.eval(d, scope) for d in a.defaults]
        self.kw_defaults = [_MISSING if d is None else vm.eval(d, scope) for d in a.kw_defaults]
        self.static = False
        if isinstance(node, ast.Lambda):
            self.is_gen, self.globs, self.nonloc = False, (), ()
        else:
            inner = [n for st in node.body for n in _walk_own(st)]
            self.is_gen = any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in inner)
            self.globs = frozenset(x for n in inner if isinstance(n, ast.Global) for x in n.names)
            self.nonloc = frozenset(x for n in inner if isinstance(n, ast.Nonlocal) for x in n.names)

    def __call__(self, *args, **kwargs):
        return self.vm.call(self, args, kwargs)

    def __repr__(self):
        return f"<function {self.name}>"


class Klass:
    def __init__(self, vm, name, attrs):
        self.vm, self.name, self.attrs = vm, name, attrs

    def __call__(self, *args, **kwargs):
        inst = Inst(self)
        init = self.attrs.get("__init__")
        if init is not None:
            init(inst, *args, **kwargs)
        elif args or kwargs:
            raise TypeError(f"{self.name}() takes no arguments")
        return inst


class Inst:
    __slots__ = ("klass", "attrs")

    def __init__(self, klass):
        self.klass, self.attrs = klass, {}


class Module:
    __slots__ = ("name", "ns")

    def __init__(self, name, ns):
        self.name, self.ns = name, ns


class _Type:
    """A builtin type name (``int``, ``bytes``...): its constructor plus its class methods."""

    def __init__(self, name, ctor, real, attrs=None):
        self.name, self.ctor, self.real, self.attrs = name, ctor, real, attrs or {}

    def __call__(self, *args, **kwargs):
        return self.ctor(*args, **kwargs)


class Sink:
    """A file opened for writing: what is written is kept as a candidate output, nothing is stored."""
    EXPOSED = frozenset({"write", "close", "flush"})

    def __init__(self, vm, name):
        self.vm, self.name = vm, name

    def write(self, data):
        self.vm.written.append(data)
        return 0

    def close(self):
        return None

    flush = close


class _Hash:
    EXPOSED = frozenset({"update", "digest", "hexdigest", "copy"})

    def __init__(self, h):
        self._h = h

    def update(self, data):
        self._h.update(_concrete_bytes(data, "a hash"))

    def digest(self):
        return self._h.digest()

    def hexdigest(self):
        return self._h.hexdigest()

    def copy(self):
        return _Hash(self._h.copy())


class _Random:
    """``random`` with the handout's seed.  Unseeded use is refused: the stream could not be the
    author's."""
    EXPOSED = frozenset({"seed", "randint", "randrange", "getrandbits", "random", "choice", "shuffle",
                         "sample", "randbytes", "choices", "Random"})

    def __init__(self, seed=_MISSING):
        import random
        self._r = random.Random()
        self._seeded = False
        if seed is not _MISSING:
            self.seed(seed)

    def seed(self, a=None, version=2):
        if a is None or is_secret(a) or isinstance(a, Poison):
            self._seeded = False
            raise Unsupported("random is seeded from the clock or from a secret: the stream cannot "
                              "be reproduced")
        if not isinstance(a, (int, str, bytes, float)):
            raise Unsupported("random.seed() with an argument that is not an int, str or bytes")
        self._r.seed(a, version)
        self._seeded = True

    def _use(self, name, *args, **kwargs):
        if not self._seeded:
            raise Unsupported(f"random.{name}() without a seed: the stream cannot be reproduced")
        if any(is_secret(a) for a in args):
            raise Unsupported(f"random.{name}() on secret-dependent data")
        return getattr(self._r, name)(*args, **kwargs)

    @staticmethod
    def _sized(name, n, limit):
        # the stream is drawn in C: a size past the limit is refused before it is drawn
        if isinstance(n, int) and n > limit:
            raise Unsupported(f"random.{name}() of {n} (over {limit})")
        return n

    def randint(self, a, b): return self._use("randint", a, b)
    def randrange(self, *a): return self._use("randrange", *a)
    def getrandbits(self, k):
        return self._use("getrandbits", self._sized("getrandbits", k, MAX_CONCRETE_BITS))
    def random(self): return self._use("random")
    def choice(self, seq): return self._use("choice", seq)
    def shuffle(self, x): return self._use("shuffle", x)
    def sample(self, pop, k): return self._use("sample", pop, self._sized("sample", k, MAX_SEQ))
    def randbytes(self, n): return self._use("randbytes", self._sized("randbytes", n, MAX_SEQ))
    def choices(self, pop, weights=None, *, k=1):
        return self._use("choices", pop, weights, k=self._sized("choices", k, MAX_SEQ))

    def Random(self, seed=_MISSING):                    # random.Random(seed): an independent generator
        return _Random(seed)


def _walk_own(node):
    """ast.walk that does not descend into function, lambda or class bodies (a nested one is
    yielded itself, its inside is another scope)."""
    yield node
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
        return
    for child in ast.iter_child_nodes(node):
        yield from _walk_own(child)


def assigned_names(st):
    """The names a statement binds in its own scope."""
    out = []
    for n in _walk_own(st):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            out.append(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.ClassDef)):
            out.append(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            out.extend((a.asname or a.name).split(".")[0] for a in n.names if a.name != "*")
    return list(dict.fromkeys(out))


def _concrete_bytes(data, what):
    if isinstance(data, SymBytes):
        if not data.concrete():
            raise Unsupported(f"{what} of secret-dependent data (not invertible here)")
        return bytes(data.items)
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if is_secret(data):
        raise Unsupported(f"{what} of secret-dependent data (not invertible here)")
    raise TypeError(f"a bytes-like object is required, not '{type(data).__name__}'")


# ---------------------------------------------------------------------------- method whitelist

_METHODS = {
    str: frozenset("encode lower upper strip lstrip rstrip split rsplit splitlines replace index find "
                   "rfind count startswith endswith isalpha isdigit isalnum isupper islower isspace "
                   "isascii isprintable zfill ljust rjust center title swapcase capitalize translate "
                   "partition removeprefix removesuffix".split()),
    bytes: frozenset("hex decode index find rfind count startswith endswith replace strip lstrip "
                     "rstrip split ljust rjust zfill translate lower upper isalpha isdigit "
                     "removeprefix removesuffix".split()),
    int: frozenset("to_bytes bit_length bit_count".split()),
    list: frozenset("append extend pop insert index count reverse sort copy remove clear".split()),
    tuple: frozenset("index count".split()),
    dict: frozenset("get items keys values pop setdefault update copy clear".split()),
    set: frozenset("add remove discard union intersection difference update copy pop clear issubset "
                   "issuperset".split()),
    frozenset: frozenset("union intersection difference copy issubset issuperset".split()),
}
_METHODS[bool] = _METHODS[int]
# whitelisted methods that pull an iterable argument in C, and those that pad to a width argument
_CONSUMING_METHODS = frozenset("extend update union intersection difference issubset issuperset".split())
_WIDTH_METHODS = frozenset("ljust rjust center zfill".split())


_PERCENT_DIRECTIVE = None


def _check_format_sizes(fmt, args=(), percent=False):
    """Refuse a format whose width or precision (``f"{x:>99999999}"``, ``"%.99999999f" % x``) would
    build a value past MAX_SEQ: CPython allocates it in one C call.  ``fmt`` is an f-string spec, or
    with ``percent`` the left operand of ``%`` (only its directives are looked at, and a ``*`` width
    is checked against the integer arguments)."""
    import re
    global _PERCENT_DIRECTIVE
    if isinstance(fmt, bytes):
        fmt = fmt.decode("latin-1")
    if not isinstance(fmt, str):
        return
    if percent:
        if _PERCENT_DIRECTIVE is None:
            _PERCENT_DIRECTIVE = re.compile(r"%%|%(?:\([^)]*\))?[#0\- +]*(\*|\d+)?(?:\.(\*|\d+))?")
        sizes = [g for m in _PERCENT_DIRECTIVE.finditer(fmt) for g in m.groups() if g]
    else:
        sizes = re.findall(r"\d+", fmt)
    for n in sizes:
        if n == "*":
            for a in (args if isinstance(args, tuple) else (args,)):
                if isinstance(a, int) and a > MAX_SEQ:
                    raise Unsupported(f"a format width or precision of {a} past the size limit")
        elif len(n) > 7 or int(n) > MAX_SEQ:
            raise Unsupported(f"a format width or precision of {n} past the size limit")


_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.BitXor: operator.xor, ast.BitAnd: operator.and_, ast.BitOr: operator.or_,
        ast.LShift: operator.lshift, ast.RShift: operator.rshift, ast.Mod: operator.mod,
        ast.FloorDiv: operator.floordiv, ast.Div: operator.truediv, ast.Pow: operator.pow}
_IBIN = {ast.Add: operator.iadd, ast.Sub: operator.isub, ast.Mult: operator.imul,
         ast.BitXor: operator.ixor, ast.BitAnd: operator.iand, ast.BitOr: operator.ior,
         ast.LShift: operator.ilshift, ast.RShift: operator.irshift, ast.Mod: operator.imod,
         ast.FloorDiv: operator.ifloordiv, ast.Div: operator.itruediv, ast.Pow: operator.ipow}
_CMPOPS = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le,
           ast.Gt: operator.gt, ast.GtE: operator.ge}
_HANDOUT_ERRORS = (ArithmeticError, LookupError, TypeError, ValueError, AssertionError, _StopIter)
_SEQ_TYPES = (list, tuple, str, bytes, SymBytes, SymStr)
_EQ_SEQS = (list, tuple, str, bytes, bytearray, SymBytes, SymStr)


# ============================================================================ the interpreter

class VM:
    """One interpreter: module globals, a step budget, and what the source printed or wrote."""

    def __init__(self, *, max_steps=DEFAULT_MAX_STEPS, deadline=None, clock=None, inject=None):
        self.max_steps, self.deadline, self.clock = max_steps, deadline, clock
        self.steps = 0
        self.depth = 0
        self.line = 0
        self.inject = dict(inject or {})   # module-level name -> value bound instead of what it computes
        self.skipped: list[str] = []       # top-level statements that could not be evaluated, with why
        self.sources: list[str] = []       # names left unavailable by a statement that failed
        self.printed: list = []
        self.written: list = []
        self.root = Scope({"__name__": "__main__"}, None)
        self.builtins = self._make_builtins()
        self._modules: dict = {}
        self._ev = {
            ast.Constant: self.e_constant, ast.Name: self.e_name, ast.BinOp: self.e_binop,
            ast.UnaryOp: self.e_unary, ast.BoolOp: self.e_boolop, ast.Compare: self.e_compare,
            ast.IfExp: self.e_ifexp, ast.Call: self.e_call, ast.Attribute: self.e_attribute,
            ast.Subscript: self.e_subscript, ast.List: self.e_list, ast.Tuple: self.e_tuple,
            ast.Dict: self.e_dict, ast.Set: self.e_set, ast.ListComp: self.e_listcomp,
            ast.GeneratorExp: self.e_genexp, ast.SetComp: self.e_setcomp,
            ast.DictComp: self.e_dictcomp, ast.Lambda: self.e_lambda,
            ast.JoinedStr: self.e_joined, ast.NamedExpr: self.e_named,
        }

    # ------------------------------------------------------------------ budget
    def _tick(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise BudgetExceeded(f"step budget of {self.max_steps} used up")
        if self.deadline is not None and not self.steps & 0x3FF and self.clock() > self.deadline:
            raise BudgetExceeded("time budget used up")

    # ------------------------------------------------------------------ module
    def run_module(self, tree):
        """Evaluate the module's top-level statements.  One that cannot be evaluated (a file read, an
        unknown import, an error) is recorded in ``skipped`` and the names it binds become unavailable
        (or take their ``inject`` value); the rest of the module still runs."""
        self._tolerant(tree.body)
        return self

    def _tolerant(self, stmts):
        root = self.root
        for st in stmts:
            if isinstance(st, ast.If):
                try:
                    taken = self.truth(self.eval(st.test, root))
                except BudgetExceeded:
                    raise
                except Exception as exc:  # noqa: BLE001 - the source is data; the failure is recorded
                    self._skip(st, exc)
                    continue
                self._tolerant(st.body if taken else st.orelse)
                continue
            try:
                for _ in self._stmt(st, root):
                    raise Unsupported("yield outside a function")
            except BudgetExceeded:
                raise
            except Exception as exc:  # noqa: BLE001 - the source is data; the failure is recorded
                self._skip(st, exc)

    def _skip(self, st, exc):
        why = str(exc) if isinstance(exc, Unsupported) else f"{type(exc).__name__}: {exc}"
        reason = f"line {getattr(st, 'lineno', '?')}: {why}"
        self.skipped.append(reason)
        for name in assigned_names(st):
            if name in self.inject:
                self.root.vars[name] = self.inject[name]
            else:
                self.root.vars[name] = Poison(reason)
                if name not in self.sources:
                    self.sources.append(name)

    # ------------------------------------------------------------------ names
    def lookup_name(self, name, sc):
        s = sc
        while s is not None:
            if name in s.vars:
                return s.vars[name]
            s = s.parent
        try:
            return self.builtins[name]
        except KeyError:
            raise Unsupported(f"name {name!r} is not defined or not modelled") from None

    def store(self, name, value, sc):
        if name in sc.globs:
            sc = self.root
        elif name in sc.nonloc:
            s = sc.parent
            while s is not None and name not in s.vars:
                s = s.parent
            if s is None:
                raise Unsupported(f"nonlocal {name!r} has no binding")
            sc = s
        if sc is self.root and name in self.inject:
            value = self.inject[name]
        sc.vars[name] = value

    def live(self, v):
        if type(v) is Poison:
            raise Unsupported(f"uses a value that is not available ({v.reason})")
        return v

    def truth(self, v):
        self.live(v)
        if isinstance(v, (Encoded, Mixed)):
            return True
        return bool(v)                               # a Sym or a Check raises: a branch on the secret

    def iterate(self, v):
        self.live(v)
        if isinstance(v, Sym):
            raise Unsupported("iteration over a secret-dependent integer")
        if isinstance(v, (Encoded, Mixed)):
            raise Unsupported("iteration over the hex/base64/formatted text of secret-dependent data")
        return iter(v)

    def consume(self, v):
        """``iterate`` charging one step per element.  Everything that hands an iterable to a C-level
        consumer (sum, max, list(), dict.fromkeys, itertools.product, ...) goes through this, so a
        handout line like ``max(range(10 ** 11))`` or ``list(itertools.count())`` runs into the step
        and time budget instead of running unbounded inside CPython.  Iterator builders that pull in
        C (filter, islice, chain, cycle, ...) get their sources through it too: ``next(filter(None,
        itertools.repeat(0)))`` skips elements inside CPython, so the charge has to sit on the source.
        The non-iterable / secret-dependent check runs now, the per-element charge as items are
        pulled."""
        return self._charged(self.iterate(v))

    def _charged(self, it):
        for item in it:
            self._tick()
            yield item

    # ------------------------------------------------------------------ calls
    def call(self, fn, args, kwargs):
        self.depth += 1
        try:
            if self.depth > MAX_DEPTH:
                raise Unsupported(f"calls nested deeper than {MAX_DEPTH}")
            sc = Scope(self._bind(fn, args, kwargs), fn.scope, fn.globs, fn.nonloc)
            if isinstance(fn.node, ast.Lambda):
                return self.eval(fn.node.body, sc)
            if fn.is_gen:
                return self._generator(fn, sc)
            try:
                for _ in self._block(fn.node.body, sc):
                    raise Unsupported("yield outside a generator")
            except _Return as r:
                return r.value
            return None
        finally:
            self.depth -= 1

    def _generator(self, fn, sc):
        try:
            yield from self._block(fn.node.body, sc)
        except _Return:
            return

    def _bind(self, fn, args, kwargs):
        a = fn.node.args
        names = [x.arg for x in a.posonlyargs + a.args]
        kwonly = [x.arg for x in a.kwonlyargs]
        local = {}
        if len(args) > len(names) and not a.vararg:
            raise TypeError(f"{fn.name}() takes {len(names)} positional arguments but "
                            f"{len(args)} were given")
        for n, v in zip(names, args):
            local[n] = v
        if a.vararg:
            local[a.vararg.arg] = tuple(args[len(names):])
        extra = {}
        for k, v in kwargs.items():
            if k in local:
                raise TypeError(f"{fn.name}() got multiple values for argument {k!r}")
            if k in names or k in kwonly:
                local[k] = v
            elif a.kwarg:
                extra[k] = v
            else:
                raise TypeError(f"{fn.name}() got an unexpected keyword argument {k!r}")
        if a.kwarg:
            local[a.kwarg.arg] = extra
        first_default = len(names) - len(fn.defaults)
        for i, n in enumerate(names):
            if n not in local:
                if i < first_default:
                    raise TypeError(f"{fn.name}() missing required argument {n!r}")
                local[n] = fn.defaults[i - first_default]
        for n, d in zip(kwonly, fn.kw_defaults):
            if n not in local:
                if d is _MISSING:
                    raise TypeError(f"{fn.name}() missing required keyword argument {n!r}")
                local[n] = d
        return local

    # ------------------------------------------------------------------ statements
    def _block(self, stmts, sc):
        for st in stmts:
            yield from self._stmt(st, sc)

    def _stmt(self, st, sc):
        self._tick()
        self.line = getattr(st, "lineno", self.line)
        t = type(st)
        if t is ast.Expr:
            v = st.value
            if isinstance(v, ast.Yield):
                yield (self.eval(v.value, sc) if v.value is not None else None)
            elif isinstance(v, ast.YieldFrom):
                yield from self.consume(self.eval(v.value, sc))
            else:
                self.eval(v, sc)
        elif t is ast.Assign:
            if isinstance(st.value, ast.Yield):
                yield (self.eval(st.value.value, sc) if st.value.value is not None else None)
                val = None
            else:
                val = self.eval(st.value, sc)
            for tg in st.targets:
                self.assign(tg, val, sc)
        elif t is ast.AugAssign:
            tg = st.target
            if isinstance(tg, ast.Name):
                cur = self.live(self.lookup_name(tg.id, sc))
                self.store(tg.id, self._binop(type(st.op), cur, self.live(self.eval(st.value, sc)),
                                              True), sc)
            elif isinstance(tg, ast.Subscript):
                obj = self.live(self.eval(tg.value, sc))
                idx = self._index(tg.slice, sc)
                cur = self.live(self.getitem(obj, idx))
                self.setitem(obj, idx, self._binop(type(st.op), cur,
                                                   self.live(self.eval(st.value, sc)), True))
            elif isinstance(tg, ast.Attribute):
                obj = self.live(self.eval(tg.value, sc))
                cur = self.live(self.getattr(obj, tg.attr))
                self.setattr(obj, tg.attr, self._binop(type(st.op), cur,
                                                       self.live(self.eval(st.value, sc)), True))
            else:
                raise Unsupported("augmented assignment to this kind of target")
        elif t is ast.AnnAssign:
            if st.value is not None:
                self.assign(st.target, self.eval(st.value, sc), sc)
        elif t is ast.Return:
            raise _Return(self.eval(st.value, sc) if st.value is not None else None)
        elif t is ast.If:
            if self.truth(self.eval(st.test, sc)):
                yield from self._block(st.body, sc)
            else:
                yield from self._block(st.orelse, sc)
        elif t is ast.For:
            broke = False
            for item in self.iterate(self.eval(st.iter, sc)):
                self._tick()
                self.assign(st.target, item, sc)
                try:
                    yield from self._block(st.body, sc)
                except _Break:
                    broke = True
                    break
                except _Continue:
                    continue
            if not broke:
                yield from self._block(st.orelse, sc)
        elif t is ast.While:
            broke = False
            while self.truth(self.eval(st.test, sc)):
                self._tick()
                try:
                    yield from self._block(st.body, sc)
                except _Break:
                    broke = True
                    break
                except _Continue:
                    continue
            if not broke:
                yield from self._block(st.orelse, sc)
        elif t is ast.Break:
            raise _Break()
        elif t is ast.Continue:
            raise _Continue()
        elif t in (ast.Pass, ast.Global, ast.Nonlocal):
            pass
        elif t is ast.FunctionDef:
            fn = Func(self, st, sc.parent if sc.is_class else sc, st.name)
            for d in st.decorator_list:
                if isinstance(d, ast.Name) and d.id == "staticmethod":
                    fn.static = True
                else:
                    raise Unsupported(f"decorator on {st.name}() is not modelled")
            self.store(st.name, fn, sc)
        elif t is ast.ClassDef:
            for b in st.bases:
                if not (isinstance(b, ast.Name) and b.id == "object"):
                    raise Unsupported(f"class {st.name} inherits from another class")
            if st.decorator_list or st.keywords:
                raise Unsupported(f"class {st.name} has decorators or keywords")
            body = Scope({}, sc, is_class=True)
            for _ in self._block(st.body, body):
                raise Unsupported("yield in a class body")
            self.store(st.name, Klass(self, st.name, body.vars), sc)
        elif t is ast.Import:
            for a in st.names:
                if a.asname:
                    self.store(a.asname, self._import(a.name), sc)
                else:
                    top = a.name.split(".")[0]
                    self.store(top, self._import(top), sc)
        elif t is ast.ImportFrom:
            if st.module == "__future__":
                return
            mod = self._import(st.module or "") if not st.level else Poison("a relative import")
            for a in st.names:
                if a.name == "*":
                    if isinstance(mod, Module):
                        for k, v in mod.ns.items():
                            self.store(k, v, sc)
                        continue
                    raise Unsupported(f"from {st.module} import *: the module is not modelled")
                if isinstance(mod, Module) and a.name in mod.ns:
                    val = mod.ns[a.name]
                elif isinstance(mod, Module) and self._import(f"{st.module}.{a.name}", quiet=True):
                    val = self._import(f"{st.module}.{a.name}")
                else:
                    val = Poison(f"{st.module}.{a.name} is not modelled")
                    if sc is self.root and (a.asname or a.name) not in self.sources:
                        self.sources.append(a.asname or a.name)
                self.store(a.asname or a.name, val, sc)
        elif t is ast.Assert:
            if not self.truth(self.eval(st.test, sc)):
                raise AssertionError("the source's own assert failed")
        elif t is ast.Raise:
            exc = self.live(self.eval(st.exc, sc)) if st.exc is not None else ValueError("re-raise")
            if isinstance(exc, type) and issubclass(exc, Exception):
                exc = exc()
            if not isinstance(exc, Exception):
                raise Unsupported("raise of something that is not an exception")
            raise exc
        elif t is ast.Try:
            try:
                try:
                    yield from self._block(st.body, sc)
                except _HANDOUT_ERRORS as exc:
                    for h in st.handlers:
                        if h.type is None or isinstance(exc, self._exc_types(h.type, sc)):
                            if h.name:
                                self.store(h.name, exc, sc)
                            yield from self._block(h.body, sc)
                            break
                    else:
                        raise
                else:
                    yield from self._block(st.orelse, sc)
            finally:
                for _ in self._block(st.finalbody, sc):
                    raise Unsupported("yield in a finally block")
        elif t is ast.With:
            for item in st.items:
                ctx = self.live(self.eval(item.context_expr, sc))
                if not isinstance(ctx, Sink):
                    raise Unsupported("a with-statement on something other than a file opened for "
                                      "writing")
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, ctx, sc)
            yield from self._block(st.body, sc)
        elif t is ast.Delete:
            for tg in st.targets:
                if isinstance(tg, ast.Name):
                    sc.vars.pop(tg.id, None)
                elif isinstance(tg, ast.Subscript):
                    obj = self.live(self.eval(tg.value, sc))
                    idx = self._index(tg.slice, sc)
                    if not isinstance(obj, (list, dict)) or is_secret(idx):
                        raise Unsupported("del on this kind of target")
                    del obj[idx]
                else:
                    raise Unsupported("del on this kind of target")
        else:
            raise Unsupported(f"{t.__name__} statements are not modelled")

    def _exc_types(self, node, sc):
        v = self.eval(node, sc)
        vs = v if isinstance(v, tuple) else (v,)
        out = []
        for x in vs:
            if x is _StopIter or (isinstance(x, type) and issubclass(x, Exception)):
                out.append(x)
            else:
                raise Unsupported("an except clause names something that is not an exception")
        return tuple(out)

    def assign(self, tg, val, sc):
        t = type(tg)
        if t is ast.Name:
            self.store(tg.id, val, sc)
        elif t in (ast.Tuple, ast.List):
            vals = list(self.consume(val))
            star = [i for i, e in enumerate(tg.elts) if isinstance(e, ast.Starred)]
            if star:
                i = star[0]
                tail = len(tg.elts) - i - 1
                if len(star) > 1 or len(vals) < len(tg.elts) - 1:
                    raise ValueError("cannot unpack")
                vals = vals[:i] + [vals[i:len(vals) - tail]] + vals[len(vals) - tail:]
                targets = [e.value if isinstance(e, ast.Starred) else e for e in tg.elts]
            else:
                targets = tg.elts
                if len(vals) != len(targets):
                    raise ValueError(f"cannot unpack {len(vals)} values into {len(targets)} names")
            for e, v in zip(targets, vals):
                self.assign(e, v, sc)
        elif t is ast.Subscript:
            self.setitem(self.live(self.eval(tg.value, sc)), self._index(tg.slice, sc), val)
        elif t is ast.Attribute:
            self.setattr(self.live(self.eval(tg.value, sc)), tg.attr, val)
        else:
            raise Unsupported(f"assignment to a {t.__name__}")

    # ------------------------------------------------------------------ containers and attributes
    def _index(self, sl, sc):
        if isinstance(sl, ast.Slice):
            return slice(*(None if p is None else self.live(self.eval(p, sc))
                           for p in (sl.lower, sl.upper, sl.step)))
        return self.live(self.eval(sl, sc))

    def getitem(self, obj, idx):
        if isinstance(idx, Sym):
            if isinstance(obj, (list, tuple, bytes)):
                return lookup(obj, idx)
            if isinstance(obj, SymBytes):
                return lookup(obj.items, idx)
            if isinstance(obj, str):
                return SymStr([lookup([ord(c) for c in obj], idx)])
            raise Unsupported(f"a secret-dependent index into a {type(obj).__name__}")
        if isinstance(obj, dict):
            if is_secret(idx):
                raise Unsupported("a secret-dependent value is used as a dict key")
            return obj[idx]
        if isinstance(obj, _SEQ_TYPES) or isinstance(obj, range):
            return obj[idx]
        raise Unsupported(f"subscript of a {type(obj).__name__}")

    def setitem(self, obj, idx, val):
        if is_secret(idx):
            raise Unsupported("a store at a secret-dependent index or key")
        if isinstance(obj, (list, dict, SymBytes)):
            obj[idx] = val
        else:
            raise Unsupported(f"item assignment on a {type(obj).__name__}")

    def getattr(self, obj, name):
        if name.startswith("_"):
            raise Unsupported(f"attribute {name!r} is not modelled")
        t = type(obj)
        if t is Module:
            if name in obj.ns:
                return obj.ns[name]
            sub = self._import(f"{obj.name}.{name}", quiet=True)
            if sub:
                return sub
            raise Unsupported(f"{obj.name}.{name} is not modelled")
        if t is Inst:
            if name in obj.attrs:
                return obj.attrs[name]
            if name not in obj.klass.attrs:
                raise AttributeError(f"'{obj.klass.name}' object has no attribute '{name}'")
            v = obj.klass.attrs[name]
            if isinstance(v, Func) and not v.static:
                return lambda *a, **k: v(obj, *a, **k)
            return v
        if t is Klass:
            if name not in obj.attrs:
                raise AttributeError(f"class {obj.name} has no attribute '{name}'")
            return obj.attrs[name]
        if t is _Type:
            if name in obj.attrs:
                return obj.attrs[name]
            raise Unsupported(f"{obj.name}.{name} is not modelled")
        if t is Sym:
            if name == "to_bytes":
                return obj.to_bytes
            raise Unsupported(f"int.{name}() of a secret-dependent value")
        if t in (SymBytes, SymStr, Encoded, Sink, _Hash, _Random):
            if t is SymBytes and name == "extend":   # it pulls its argument: charge each pull
                return lambda vs: obj.extend(list(self.consume(vs)))
            if name in t.EXPOSED:
                return getattr(obj, name)
            if t is SymBytes and obj.concrete() and name in _METHODS[bytes]:
                return self._guarded(bytes(obj.items), name)
            raise Unsupported(f".{name}() on {t.__name__} is not modelled")
        if t is str and name == "join":
            return lambda parts: _join_str(obj, self.consume(parts))
        if t is bytes and name == "join":
            return lambda parts: _join_bytes(obj, self.consume(parts))
        allowed = _METHODS.get(t)
        if allowed is not None and name in allowed:
            return self._guarded(obj, name)
        raise Unsupported(f"attribute {name!r} of a {t.__name__} is not modelled")

    def _guarded(self, obj, name):
        """A whitelisted method of a concrete value, with the two ways hostile source could make it
        run unbounded inside CPython closed: an iterable argument (list.extend, set.update, ...) is
        pulled through ``consume`` first, and a size argument (ljust, zfill, to_bytes, ...) or a
        result size (replace, translate) past MAX_SEQ is refused before anything is allocated."""
        m = getattr(obj, name)
        if name in _CONSUMING_METHODS:
            def run(*args, **kwargs):
                return m(*[a if isinstance(a, dict) else list(self.consume(a)) for a in args],
                         **kwargs)
            return run
        if name in _WIDTH_METHODS or name == "to_bytes":
            def run(*args, **kwargs):
                n = args[0] if args else kwargs.get("length" if name == "to_bytes" else "width", 1)
                if isinstance(n, int) and n > MAX_SEQ:
                    raise Unsupported(f".{name}({n}) past the size limit")
                return m(*args, **kwargs)
            return run
        if name == "replace":
            def run(old, new, count=-1):
                if isinstance(old, (str, bytes)) and isinstance(new, (str, bytes)) \
                        and len(new) > len(old):
                    hits = obj.count(old)
                    if isinstance(count, int) and count >= 0:
                        hits = min(hits, count)
                    if len(obj) + hits * (len(new) - len(old)) > MAX_SEQ:
                        raise Unsupported(".replace() would grow the value past the size limit")
                return m(old, new, count)
            return run
        if name == "translate" and isinstance(obj, str):
            def run(table):
                if isinstance(table, dict):
                    widest = max((len(v) for v in table.values() if isinstance(v, str)), default=1)
                    if len(obj) * widest > MAX_SEQ:
                        raise Unsupported(".translate() could grow the value past the size limit")
                return m(table)
            return run
        return m

    def setattr(self, obj, name, val):
        if name.startswith("__") or not isinstance(obj, (Inst, Klass)):
            raise Unsupported(f"attribute assignment .{name} on a {type(obj).__name__}")
        obj.attrs[name] = val

    # ------------------------------------------------------------------ expressions
    def eval(self, node, sc):
        self._tick()
        try:
            fn = self._ev[type(node)]
        except KeyError:
            raise Unsupported(f"{type(node).__name__} expressions are not modelled") from None
        return fn(node, sc)

    def e_constant(self, node, sc):
        return node.value

    def e_name(self, node, sc):
        return self.lookup_name(node.id, sc)

    def _binop(self, opt, a, b, inplace):
        fn = (_IBIN if inplace else _BIN).get(opt)
        if fn is None:
            raise Unsupported(f"operator {opt.__name__} is not modelled")
        if isinstance(a, (Encoded, Mixed)) or isinstance(b, (Encoded, Mixed)):
            raise Unsupported("arithmetic or concatenation on the hex/base64/formatted text of "
                              "secret-dependent data")
        if opt is ast.LShift:
            if isinstance(a, int) and isinstance(b, int) and b > MAX_CONCRETE_BITS:
                raise Unsupported(f"a left shift by {b} bits")
        elif opt is ast.Mod:
            if isinstance(a, (str, bytes)):
                _check_format_sizes(a, b, percent=True)
        elif opt is ast.Pow:
            if (isinstance(a, int) and isinstance(b, int) and b > 0
                    and a.bit_length() * b > MAX_CONCRETE_BITS):
                raise Unsupported("a power too large to evaluate")
        elif opt is ast.Mult:
            for x, n in ((a, b), (b, a)):
                if isinstance(x, _SEQ_TYPES) and isinstance(n, int) and len(x) * n > MAX_SEQ:
                    raise Unsupported("a sequence is repeated past the size limit")
            if (isinstance(a, int) and isinstance(b, int)
                    and a.bit_length() + b.bit_length() > 8 * MAX_CONCRETE_BITS):
                raise Unsupported("a product too large to evaluate")
        return fn(a, b)

    def e_binop(self, node, sc):
        a = self.live(self.eval(node.left, sc))
        b = self.live(self.eval(node.right, sc))
        return self._binop(type(node.op), a, b, False)

    def e_unary(self, node, sc):
        v = self.live(self.eval(node.operand, sc))
        t = type(node.op)
        if t is ast.Not:
            return not self.truth(v)
        if t is ast.USub:
            return -v
        if t is ast.Invert:
            return ~v
        return +v

    def e_boolop(self, node, sc):
        is_and = isinstance(node.op, ast.And)
        v = None
        for i, sub in enumerate(node.values):
            v = self.eval(sub, sc)
            if i == len(node.values) - 1 or self.truth(v) != is_and:
                return v                             # the last operand is the value, untested
        return v

    def e_compare(self, node, sc):
        left = self.live(self.eval(node.left, sc))
        result = True
        for i, (op, rn) in enumerate(zip(node.ops, node.comparators)):
            right = self.live(self.eval(rn, sc))
            result = self._compare(type(op), left, right)
            if i < len(node.ops) - 1 and not self.truth(result):
                return False
            left = right
        return result

    def _compare(self, t, a, b):
        if t is ast.Is:
            return a is b
        if t is ast.IsNot:
            return a is not b
        if t in (ast.In, ast.NotIn):
            if isinstance(b, (dict, set, frozenset)) and is_secret(a):
                raise Unsupported("a membership test of a secret-dependent value in a dict or set")
            if isinstance(a, SymStr) or isinstance(b, (SymStr, Sym, Encoded, Mixed)):
                raise Unsupported("a membership test on secret-dependent text")
            if isinstance(b, collections.abc.Iterator):   # an iterator is searched element by element
                found = any(x is a or x == a for x in self.consume(b))
            else:
                found = operator.contains(b, a)
            return found if t is ast.In else not found
        if t in (ast.Eq, ast.NotEq) and (is_secret(a) or is_secret(b)) \
                and isinstance(a, _EQ_SEQS) and isinstance(b, _EQ_SEQS):
            same = sequence_equal(a, b)
            if t is ast.Eq:
                return same
            if isinstance(same, Check):
                raise Unsupported("an inequality test on secret-dependent data")
            return not same
        return _CMPOPS[t](a, b)

    def e_ifexp(self, node, sc):
        c = self.live(self.eval(node.test, sc))
        if isinstance(c, Sym):
            return ite(c, self.live(self.eval(node.body, sc)), self.live(self.eval(node.orelse, sc)))
        return self.eval(node.body if self.truth(c) else node.orelse, sc)

    def e_call(self, node, sc):
        fn = self.live(self.eval(node.func, sc))
        args = []
        for a in node.args:
            if isinstance(a, ast.Starred):
                args.extend(self.consume(self.eval(a.value, sc)))
            else:
                args.append(self.live(self.eval(a, sc)))
        kwargs = {}
        for k in node.keywords:
            v = self.live(self.eval(k.value, sc))
            if k.arg is None:
                if not isinstance(v, dict):
                    raise TypeError("argument after ** must be a dict")
                kwargs.update(v)
            else:
                kwargs[k.arg] = v
        if not callable(fn):
            raise TypeError(f"'{type(fn).__name__}' object is not callable")
        if isinstance(fn, types.BuiltinMethodType):
            owner = getattr(fn, "__self__", None)
            if isinstance(owner, (dict, set, frozenset)) and any(is_secret(a) for a in args):
                raise Unsupported("a secret-dependent value is used as a dict key or set member")
        return fn(*args, **kwargs)

    def e_attribute(self, node, sc):
        return self.getattr(self.live(self.eval(node.value, sc)), node.attr)

    def e_subscript(self, node, sc):
        obj = self.live(self.eval(node.value, sc))
        return self.getitem(obj, self._index(node.slice, sc))

    def _elts(self, elts, sc):
        out = []
        for e in elts:
            if isinstance(e, ast.Starred):
                out.extend(self.consume(self.eval(e.value, sc)))
            else:
                out.append(self.eval(e, sc))
        return out

    def e_list(self, node, sc):
        return self._elts(node.elts, sc)

    def e_tuple(self, node, sc):
        return tuple(self._elts(node.elts, sc))

    def e_set(self, node, sc):
        vals = self._elts(node.elts, sc)
        if any(is_secret(v) for v in vals):
            raise Unsupported("a secret-dependent value is used as a set member")
        return set(vals)

    def e_dict(self, node, sc):
        out = {}
        for k, v in zip(node.keys, node.values):
            if k is None:
                out.update(self.live(self.eval(v, sc)))
                continue
            key = self.live(self.eval(k, sc))
            if is_secret(key):
                raise Unsupported("a secret-dependent value is used as a dict key")
            out[key] = self.eval(v, sc)
        return out

    def _comp(self, gens, sc, emit):
        inner = Scope({}, sc)

        def rec(i):
            if i == len(gens):
                emit(inner)
                return
            g = gens[i]
            for item in self.iterate(self.eval(g.iter, inner)):
                self._tick()
                self.assign(g.target, item, inner)
                if all(self.truth(self.eval(c, inner)) for c in g.ifs):
                    rec(i + 1)

        rec(0)

    def e_listcomp(self, node, sc):
        out = []
        self._comp(node.generators, sc, lambda s: out.append(self.eval(node.elt, s)))
        return out

    def e_genexp(self, node, sc):                    # evaluated eagerly: the source is pure
        return iter(self.e_listcomp(node, sc))

    def e_setcomp(self, node, sc):
        vals = self.e_listcomp(node, sc)
        if any(is_secret(v) for v in vals):
            raise Unsupported("a secret-dependent value is used as a set member")
        return set(vals)

    def e_dictcomp(self, node, sc):
        out = {}

        def emit(s):
            key = self.live(self.eval(node.key, s))
            if is_secret(key):
                raise Unsupported("a secret-dependent value is used as a dict key")
            out[key] = self.eval(node.value, s)

        self._comp(node.generators, sc, emit)
        return out

    def e_lambda(self, node, sc):
        return Func(self, node, sc, "<lambda>")

    def e_named(self, node, sc):
        v = self.eval(node.value, sc)
        self.store(node.target.id, v, sc)
        return v

    def e_joined(self, node, sc):
        text, secret = [], []
        for part in node.values:
            if isinstance(part, ast.Constant):
                text.append(str(part.value))
                continue
            v = self.live(self.eval(part.value, sc))
            if is_secret(v):
                secret.append(v)
                continue
            spec = self.e_joined(part.format_spec, sc) if part.format_spec is not None else ""
            if isinstance(spec, Mixed):
                raise Unsupported("a secret-dependent format specification")
            _check_format_sizes(spec)
            if part.conversion == ord("r"):
                v = repr(v)
            elif part.conversion == ord("s"):
                v = str(v)
            if not isinstance(v, (int, float, str, bytes, bool, type(None), list, tuple, dict)):
                raise Unsupported(f"formatting a {type(v).__name__}")
            text.append(format(v, spec))
        return Mixed(secret) if secret else "".join(text)

    # ------------------------------------------------------------------ imports
    def _import(self, dotted, quiet=False):
        if dotted in self._modules:
            return self._modules[dotted]
        shims = self._shims()
        if dotted in shims:
            mod = Module(dotted, shims[dotted])
        elif any(k.startswith(dotted + ".") for k in shims):
            mod = Module(dotted, {})                 # a package: its modelled sub-modules resolve lazily
        elif quiet:
            return None
        else:
            mod = Poison(f"module {dotted!r} is not modelled")
        self._modules[dotted] = mod
        return mod

    def _shims(self):
        if hasattr(self, "_shim_table"):
            return self._shim_table
        import base64
        import binascii
        import functools
        import hashlib
        import math
        import string
        import struct

        def hasher(name):
            def make(data=b""):
                return _Hash(hashlib.new(name, _concrete_bytes(data, "a hash")))
            return make

        def concrete_only(fn, what):
            def run(*args, **kwargs):
                if any(is_secret(a) for a in args):
                    raise Unsupported(f"{what} of secret-dependent data is not modelled")
                args = [bytes(a.items) if isinstance(a, SymBytes) else a for a in args]
                return fn(*args, **kwargs)
            return run

        def encoder(real, kind):
            def run(data, *args, **kwargs):
                if isinstance(data, SymBytes) and not data.concrete():
                    if args or kwargs:
                        raise Unsupported(f"{kind} encoding options on secret-dependent bytes")
                    return Encoded(kind, mkbytes(data.items))
                return real(bytes(byte_items(data)), *args, **kwargs)
            return run

        def struct_parse(fmt):
            order = "little"
            if not fmt or fmt[0] not in "<>!=":
                raise Unsupported("struct format without an explicit byte order on secret-dependent "
                                  "data")
            if fmt[0] in ">!":
                order = "big"
            sizes, count = [], ""
            for ch in fmt[1:]:
                if ch.isdigit():
                    count += ch
                    continue
                if ch not in "BHILQ":
                    raise Unsupported(f"struct code {ch!r} on secret-dependent data")
                sizes.extend([{"B": 1, "H": 2, "I": 4, "L": 4, "Q": 8}[ch]] * int(count or 1))
                count = ""
            return order, sizes

        def s_pack(fmt, *vals):
            if not any(is_secret(v) for v in vals):
                return struct.pack(fmt, *vals)
            order, sizes = struct_parse(fmt)
            if len(sizes) != len(vals):
                raise ValueError("struct.pack: wrong number of values")
            out = []
            for size, v in zip(sizes, vals):
                out.extend(byte_items(v.to_bytes(size, order)))
            return mkbytes(out)

        def s_unpack(fmt, data):
            if not is_secret(data):
                return struct.unpack(fmt, bytes(byte_items(data)))
            order, sizes = struct_parse(fmt)
            items = byte_items(data)
            if sum(sizes) != len(items):
                raise ValueError("struct.unpack: wrong buffer size")
            out, pos = [], 0
            for size in sizes:
                out.append(int_from_bytes(items[pos:pos + size], order))
                pos += size
            return tuple(out)

        def long_to_bytes(n, blocksize=0):
            if isinstance(n, Sym):
                need = (n.rng[1].bit_length() + 7) // 8 if n.rng and n.rng[0] >= 0 else None
                if not blocksize or need is None or need > blocksize:
                    raise Unsupported("long_to_bytes of a secret-dependent value without a "
                                      "blocksize that fixes its length")
                return n.to_bytes(blocksize, "big")
            raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
            if blocksize and len(raw) % blocksize:
                raw = b"\x00" * (blocksize - len(raw) % blocksize) + raw
            return raw

        def pad(data, block_size, style="pkcs7"):
            if style != "pkcs7":
                raise Unsupported(f"padding style {style!r}")
            n = block_size - len(data) % block_size
            return data + bytes([n]) * n

        def strxor(a, b):
            if len(a) != len(b):
                raise ValueError("strxor: length mismatch")
            return mkbytes([x ^ y for x, y in zip(byte_items(a), byte_items(b))])

        def reduce(fn, seq, *init):
            return functools.reduce(fn, self.consume(seq), *init)

        def pooled(fn, n_iterables):
            # product/permutations/combinations copy their input(s) into a tuple in C when built;
            # product takes any number of iterables, the other two one iterable and then r
            def run(*args, **kwargs):
                k = len(args) if n_iterables is None else min(n_iterables, len(args))
                return fn(*[tuple(self.consume(it)) for it in args[:k]], *args[k:], **kwargs)
            run.__name__ = fn.__name__
            return run

        def charged(fn, n_iterables):
            # lazy builders (islice skips, cycle copies, chain/zip_longest advance) pull their
            # sources in C: hand each source over through consume() so every pull is charged
            def run(*args, **kwargs):
                k = len(args) if n_iterables is None else min(n_iterables, len(args))
                return fn(*[self.consume(it) for it in args[:k]], *args[k:], **kwargs)
            run.__name__ = fn.__name__
            return run

        rnd = _Random()
        self._shim_table = {
            "hashlib": {**{n: hasher(n) for n in ("md5", "sha1", "sha224", "sha256", "sha384",
                                                  "sha512", "sha3_256", "blake2b", "blake2s")},
                        "new": lambda name, data=b"": hasher(name)(data)},
            "random": {n: getattr(rnd, n) for n in _Random.EXPOSED},
            "struct": {"pack": s_pack, "unpack": s_unpack, "calcsize": struct.calcsize},
            "base64": {"b64encode": encoder(base64.b64encode, "base64"),
                       "b64decode": concrete_only(base64.b64decode, "base64 decoding"),
                       "b16encode": concrete_only(base64.b16encode, "base16 encoding"),
                       "b16decode": concrete_only(base64.b16decode, "base16 decoding"),
                       "b32encode": concrete_only(base64.b32encode, "base32 encoding"),
                       "b32decode": concrete_only(base64.b32decode, "base32 decoding"),
                       "urlsafe_b64encode": concrete_only(base64.urlsafe_b64encode, "base64 encoding"),
                       "urlsafe_b64decode": concrete_only(base64.urlsafe_b64decode, "base64 decoding")},
            "binascii": {"hexlify": encoder(binascii.hexlify, "hex"),
                         "b2a_hex": encoder(binascii.b2a_hex, "hex"),
                         "unhexlify": concrete_only(binascii.unhexlify, "hex decoding"),
                         "a2b_hex": concrete_only(binascii.a2b_hex, "hex decoding"),
                         "crc32": concrete_only(binascii.crc32, "a CRC")},
            "itertools": {"count": itertools.count, "repeat": itertools.repeat,
                          **{n: charged(getattr(itertools, n), None) for n in ("chain", "zip_longest")},
                          **{n: charged(getattr(itertools, n), 1) for n in
                             ("cycle", "islice", "accumulate")},
                          "product": pooled(itertools.product, None),
                          "permutations": pooled(itertools.permutations, 1),
                          "combinations": pooled(itertools.combinations, 1)},
            "functools": {"reduce": reduce},
            "operator": {n: getattr(operator, n) for n in
                         ("xor", "add", "sub", "mul", "and_", "or_", "lshift", "rshift", "mod",
                          "floordiv", "neg", "invert", "eq", "ne", "lt", "le", "gt", "ge")},
            "math": {**{n: getattr(math, n) for n in
                        ("gcd", "lcm", "isqrt", "ceil", "floor", "log2", "log", "sqrt", "pi")},
                     "prod": self._prod},
            "string": {n: getattr(string, n) for n in
                       ("ascii_lowercase", "ascii_uppercase", "ascii_letters", "digits", "hexdigits",
                        "punctuation", "printable", "whitespace", "octdigits")},
            "Crypto.Util.number": {"bytes_to_long": lambda b: int_from_bytes(b, "big"),
                                   "long_to_bytes": long_to_bytes},
            "Crypto.Util.Padding": {"pad": pad},
            "Crypto.Util.strxor": {"strxor": strxor},
        }
        return self._shim_table

    # ------------------------------------------------------------------ builtins
    def _make_builtins(self):
        vm = self
        import math
        math_prod = math.prod

        def sized(v):
            if isinstance(v, range) and len(v) > MAX_SEQ:
                raise Unsupported(f"a sequence of {len(v)} elements")
            return v

        def b_int(x=0, base=None):
            if isinstance(x, Sym):
                return x
            if is_secret(x):
                raise Unsupported("int() of secret-dependent text or bytes")
            return int(x) if base is None else int(x, base)

        def b_bytes(x=b"", encoding=None, errors="strict", *, _mutable=False):
            if isinstance(x, Sym):
                raise Unsupported("bytes() sized by a secret-dependent value")
            if isinstance(x, bool) or isinstance(x, int):
                if x > MAX_SEQ:
                    raise Unsupported(f"bytes({x})")
                return mkbytes([0] * x, _mutable)
            if isinstance(x, (str, SymStr)):
                if encoding is None:
                    raise TypeError("string argument without an encoding")
                return mkbytes(byte_items(x.encode(encoding, errors)), _mutable)
            return mkbytes(vm.consume(sized(x)), _mutable)

        def b_bytearray(x=b"", encoding=None, errors="strict"):
            return b_bytes(x, encoding, errors, _mutable=True)

        def b_str(x="", *args):
            if isinstance(x, (SymStr, Encoded)):
                return x
            if is_secret(x):
                raise Unsupported("str() of a secret-dependent value")
            if isinstance(x, SymBytes):
                x = bytes(x.items)
            if not isinstance(x, (int, float, str, bytes, bool, type(None), list, tuple, dict,
                                  Exception)):
                raise Unsupported(f"str() of a {type(x).__name__}")
            return str(x, *args)

        def b_ord(c):
            if isinstance(c, SymStr):
                if len(c.items) != 1:
                    raise TypeError("ord() expected a character")
                x = c.items[0]
                return x if isinstance(x, Sym) else ord(x)
            if isinstance(c, Sym):
                raise TypeError("ord() expected a character, but an integer was found")
            return ord(c)

        def b_chr(v):
            if isinstance(v, Sym):
                if v.rng is None or v.rng[0] < 0 or v.rng[1] > 0x10FFFF:
                    raise Unsupported("chr() of a secret-dependent value that may be out of range "
                                      "(mask it first)")
                return SymStr([v])
            return chr(v)

        def b_set(x=()):
            vals = list(vm.consume(sized(x)))
            if any(is_secret(v) for v in vals):
                raise Unsupported("a secret-dependent value is used as a set member")
            return set(vals)

        def reduction(fn):
            # sum/min/max/any/all/math.prod consume their argument in C: feed it through consume()
            def run(*args, **kwargs):
                if len(args) == 1:
                    args = (vm.consume(args[0]),)
                elif fn in (sum, math_prod) and args:
                    args = (vm.consume(args[0]),) + args[1:]
                return fn(*args, **kwargs)
            run.__name__ = fn.__name__
            return run

        vm._prod = reduction(math_prod)

        def b_dict(*args, **kwargs):
            if args and not isinstance(args[0], dict):
                args = (list(vm.consume(args[0])),) + args[1:]
            d = dict(*args, **kwargs)
            if any(is_secret(k) for k in d):
                raise Unsupported("a secret-dependent value is used as a dict key")
            return d

        def b_pow(a, b, m=None):
            if is_secret(a) or is_secret(b) or is_secret(m):
                raise Unsupported("pow() on a secret-dependent value")
            if m is None:
                return vm._binop(ast.Pow, a, b, False)
            return pow(a, b, m)

        def b_next(it, *default):
            try:
                return next(it)
            except StopIteration:
                if default:
                    return default[0]
                raise _StopIter("iterator exhausted") from None

        def b_isinstance(x, t):
            ts = t if isinstance(t, tuple) else (t,)
            for one in ts:
                if isinstance(one, Klass):
                    if isinstance(x, Inst) and x.klass is one:
                        return True
                elif isinstance(one, _Type):
                    if one.name == "bytearray":
                        if isinstance(x, SymBytes) and x.mutable:
                            return True
                    elif one.name == "bytes":
                        if isinstance(x, bytes) or (isinstance(x, SymBytes) and not x.mutable):
                            return True
                    elif isinstance(x, one.real):
                        return True
                else:
                    raise Unsupported("isinstance() against something that is not a modelled type")
            return False

        def b_print(*args, **_kwargs):
            vm.printed.append(args)

        def b_open(name="", mode="r", *_a, **_k):
            if isinstance(mode, str) and any(c in mode for c in "wax"):
                return Sink(vm, name)
            raise Unsupported(f"reads the file {name!r}")

        def b_input(*_a):
            raise Unsupported("reads standard input")

        def b_sorted(x, **kw):
            return sorted(vm.consume(sized(x)), **kw)

        def b_abs(x):
            if isinstance(x, Sym):
                if x.rng is not None and x.rng[0] >= 0:
                    return x
                raise Unsupported("abs() of a secret-dependent value that may be negative")
            return abs(x)

        def b_hex(x):
            return hex(x)

        # lazy iterator builders: CPython pulls their sources in C (filter skips, zip/map advance
        # every source), so each source goes through consume() and every pull is charged.
        # reversed() takes no iterator (only a sequence, which it walks lazily) and is left as is.
        def b_enumerate(it, start=0):
            return enumerate(vm.consume(it), start)

        def b_zip(*its, strict=False):
            return zip(*[vm.consume(i) for i in its], strict=strict)

        def b_map(fn, *its):
            return map(fn, *[vm.consume(i) for i in its])

        def b_filter(fn, it):
            return filter(fn, vm.consume(it))

        b = {
            "len": len, "range": range, "enumerate": b_enumerate, "zip": b_zip, "reversed": reversed,
            "sum": reduction(sum), "min": reduction(min), "max": reduction(max),
            "any": reduction(any), "all": reduction(all), "map": b_map, "filter": b_filter,
            "divmod": divmod, "round": round, "iter": iter, "hex": b_hex, "bin": bin, "oct": oct,
            "repr": b_str, "abs": b_abs, "sorted": b_sorted, "ord": b_ord, "chr": b_chr,
            "pow": b_pow, "next": b_next, "isinstance": b_isinstance, "print": b_print,
            "open": b_open, "input": b_input,
            "int": _Type("int", b_int, (int, Sym), {"from_bytes": int_from_bytes}),
            "bool": _Type("bool", lambda x=False: vm.truth(x), bool),
            "float": _Type("float", float, float),
            "str": _Type("str", b_str, (str, SymStr),
                         {"join": lambda sep, parts: _join_str(sep, vm.consume(parts)),
                          "maketrans": str.maketrans}),
            "bytes": _Type("bytes", b_bytes, bytes,
                           {"fromhex": bytes.fromhex, "maketrans": bytes.maketrans}),
            "bytearray": _Type("bytearray", b_bytearray, SymBytes,
                               {"fromhex": lambda s: SymBytes(bytes.fromhex(s), True)}),
            "list": _Type("list", lambda x=(): list(vm.consume(sized(x))), list),
            "tuple": _Type("tuple", lambda x=(): tuple(vm.consume(sized(x))), tuple),
            "set": _Type("set", b_set, set),
            "frozenset": _Type("frozenset", lambda x=(): frozenset(b_set(x)), frozenset),
            "dict": _Type("dict", b_dict, dict,
                          {"fromkeys": lambda keys, *v: b_dict(dict.fromkeys(vm.consume(keys), *v))}),
            "object": _Type("object", object, object),
            "True": True, "False": False, "None": None,
            "StopIteration": _StopIter,
        }
        for exc in (Exception, ValueError, TypeError, KeyError, IndexError, AssertionError,
                    ZeroDivisionError, RuntimeError, NotImplementedError, ArithmeticError,
                    LookupError, OverflowError):
            b[exc.__name__] = exc
        return b
