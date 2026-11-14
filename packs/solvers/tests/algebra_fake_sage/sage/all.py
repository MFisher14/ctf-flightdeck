"""A fake `sage.all` for the B-157 tests: the slice of Sage's API that _algebra_sage_worker.py calls.

It stands in for the external tool, the way the stub docker stands in for Docker: the worker's own
code (wire parsing, dispatch, result building, error reporting) runs for real against it. It does not
prove that real Sage answers to these names and signatures: that is the human smoke step
(`algebra_service.py selftest --backend sage-image`). The mathematics comes from the repo's own exact
code; BKZ here is the exact LLL and only records that it was called, with what.
"""
import json
import os
import time
from fractions import Fraction

import algebra_service as alg
import rsa_lattice


def _log(entry):
    path = os.environ.get("FAKE_SAGE_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


class _Elem:
    """A base-ring element: a Fraction over QQ, an int in [0, n) otherwise."""

    def __init__(self, ring, value):
        self.ring, self.value = ring, ring.coerce(value)

    def __truediv__(self, other):
        if self.ring.kind == "QQ":
            return _Elem(self.ring, self.value / other.value)
        return _Elem(self.ring, self.value * pow(other.value, -1, self.ring.modulus))

    def __mul__(self, other):
        if isinstance(other, _Elem):
            return _Elem(self.ring, self.value * other.value)
        return NotImplemented

    def numerator(self):
        return self.value.numerator

    def denominator(self):
        return self.value.denominator

    def __int__(self):
        return int(self.value)


class _Base:
    def __init__(self, ring):
        self.ring = ring

    def __call__(self, value):
        return _Elem(self.ring, value)


class _Integers:
    def __call__(self, value):
        fr = Fraction(value.value if isinstance(value, _Elem) else value)
        if fr.denominator != 1:
            raise TypeError("no conversion of this rational to integer")
        return int(fr)


ZZ = _Integers()
QQ = _Base(alg.Ring("QQ"))


def GF(p):
    from sympy import isprime
    if not isprime(p):
        raise ValueError("the order of a finite field must be a prime power")
    return _Base(alg.Ring("GF", int(p)))


def Zmod(n):
    return _Base(alg.Ring("Zmod", int(n)))


class _Poly:
    def __init__(self, parent, data):
        self.parent, self.data = parent, data

    def _ring(self):
        return self.parent.base.ring

    def __add__(self, other):
        return _Poly(self.parent, alg.poly_add(self._ring(), self.data, other.data))

    def __mul__(self, other):
        return _Poly(self.parent, alg.poly_mul(self._ring(), self.data, other.data))

    def __rmul__(self, elem):
        zero = tuple([0] * self.parent.n)
        scalar = {zero: elem.value} if elem.value else {}
        return _Poly(self.parent, alg.poly_mul(self._ring(), scalar, self.data))

    def __pow__(self, k):
        out = self.parent.one()
        for _ in range(int(k)):
            out = out * self
        return out

    def __eq__(self, other):
        return isinstance(other, _Poly) and self.data == other.data

    def __hash__(self):
        return hash(tuple(sorted(self.data)))

    def __str__(self):
        return alg.poly_text(self._ring(), self.data, self.parent.names)

    def dict(self):
        return {e: _Elem(self._ring(), c) for e, c in self.data.items()}

    def resultant(self, other, variable):
        var = self.parent.gens().index(variable)
        return _Poly(self.parent, alg._py_resultant(self._ring(), self.parent.n, self.data, other.data, var))


class _MRing:
    def __init__(self, base, n, names, order):
        if order not in ("lex", "deglex", "degrevlex"):
            raise ValueError("unknown term order")
        self.base, self.n, self.names, self.order = base, int(n), list(names), order
        self._gens = tuple(_Poly(self, {tuple(1 if i == j else 0 for i in range(self.n)): base.ring.coerce(1)})
                           for j in range(self.n))

    def base_ring(self):
        return self.base

    def gens(self):
        return self._gens

    def gen(self, i):
        return self._gens[i]

    def zero(self):
        return _Poly(self, {})

    def one(self):
        return _Poly(self, {tuple([0] * self.n): self.base.ring.coerce(1)})

    def __call__(self, value):
        return value

    def ideal(self, gens):
        return _Ideal(self, list(gens))


class _Ideal:
    def __init__(self, parent, gens):
        self.parent, self._gens = parent, gens

    def gens(self):
        return self._gens

    def _data(self):
        return [g.data for g in self._gens]

    def groebner_basis(self):
        R = self.parent
        return [_Poly(R, g) for g in alg._py_groebner(R.base.ring, R.n, R.order, self._data())]

    def dimension(self):
        R = self.parent
        basis = alg._py_groebner(R.base.ring, R.n, "lex", self._data())
        if any(set(g) == {tuple([0] * R.n)} for g in basis):
            return -1
        leads = [max(g) for g in basis]
        pure = {i for lead in leads for i in range(R.n) if lead[i] and sum(lead) == lead[i]}
        return 0 if len(pure) == R.n else 1

    def variety(self):
        R = self.parent
        if self.dimension() != 0:                # the worker must check the dimension before it asks
            raise AssertionError("fake sage: variety() called on an ideal of dimension %d" % self.dimension())
        return [{g: _Elem(R.base.ring, c) for g, c in zip(R.gens(), pt)}
                for pt in alg._py_variety(R.base.ring, R.n, self._data())]

    def elimination_ideal(self, variables):
        R = self.parent
        gone = sorted(R.gens().index(v) for v in variables)
        return _Ideal(R, [_Poly(R, g) for g in alg._py_eliminate(R.base.ring, R.n, self._data(), gone)])


class _UPoly:
    def __init__(self, base, coeffs):
        self.base, self.coeffs = base, [c.value if isinstance(c, _Elem) else base.ring.coerce(c) for c in coeffs]

    def roots(self, multiplicities=True):
        if multiplicities:
            raise NotImplementedError("the fake only lists roots")
        return [_Elem(self.base.ring, r) for r in alg._py_univariate_roots(self.base.ring, self.coeffs)]

    def monic(self):
        n = self.base.ring.modulus
        inv = pow(self.coeffs[-1], -1, n)
        return _UPoly(self.base, [c * inv % n for c in self.coeffs])

    def small_roots(self, X=None, beta=1.0, epsilon=None):
        _log({"call": "small_roots", "X": X, "beta": beta, "epsilon": epsilon})
        n = self.base.ring.modulus
        return [_Elem(self.base.ring, r) for r in rsa_lattice.coppersmith_roots(self.coeffs, n, X, beta=beta)]


class _URing:
    def __init__(self, base):
        self.base = base

    def __call__(self, coeffs):
        return _UPoly(self.base, list(coeffs))


def PolynomialRing(base, *args, order="lex"):
    if len(args) == 1 and isinstance(args[0], str):
        return _URing(base)
    n, names = args
    if len(names) != n:
        raise ValueError("the number of names must equal the number of generators")
    return _MRing(base, n, names, order)


class _Matrix:
    def __init__(self, rows):
        self._rows = [list(r) for r in rows]

    def rows(self):
        return [list(r) for r in self._rows]

    def nrows(self):
        return len(self._rows)

    def rank(self):
        from sympy import Matrix
        return int(Matrix(self._rows).rank())

    def LLL(self):
        _log({"call": "LLL", "rows": len(self._rows)})
        if os.environ.get("FAKE_SAGE_MODE") == "slow_lll":   # a reduction that outlives the job's limit
            time.sleep(float(os.environ.get("FAKE_SAGE_HANG", "30")))
        reduced = rsa_lattice.lll(self._rows)
        if reduced is None:
            raise ValueError("dependent rows")
        return _Matrix(reduced)

    def BKZ(self, block_size=10, **kw):
        _log({"call": "BKZ", "block_size": block_size, "kw": kw})
        if not 2 <= block_size <= len(self._rows):
            raise ValueError("block size out of range")
        return _Matrix(rsa_lattice.lll(self._rows))

    def solve_left(self, target):
        got = alg.solve_left(self._rows, target._rows)
        if got is None:
            raise ValueError("matrix equation has no solutions")
        return _Matrix([[Fraction(x) for x in row] for row in got])


def matrix(ring, rows):
    if ring is not ZZ:
        raise TypeError("the fake only builds integer matrices")
    return _Matrix(rows)
