#!/usr/bin/env python3
"""General lattice and polynomial-ideal solving service (B-157): one JSON job, a named backend, a checked result.

    import algebra_service as alg
    res = alg.execute({"op": "variety", "ring": "GF(101)", "vars": ["x", "y"],
                       "polys": ["x*y - 1", "x - y"]})            # ServiceResult
    res.require()["points"]                                        # [{"x": 1, "y": 1}, {"x": 100, "y": 100}]
    alg.reduce_basis(rows, method="bkz", block_size=20, backend="sage-image")   # verified rows, or it raises

Operations (`OPS`): `lll`, `bkz` (integer row bases); `groebner`, `variety`, `eliminate`, `resultant`,
`roots` (polynomials over `QQ`, `GF(p)` or `Zmod(n)`); `small_roots` (univariate Coppersmith mod N).

Backends (`BACKENDS`), always named in the result:

    python       in-repo exact LLL, BKZ through a local fpylll (`lattice_backends`, the one local
                 reduction seam), SymPy for ideals over QQ and GF(p). No Zmod(n) ideals.
    sage-local   a `sage` on PATH.
    sage-image   the pinned `ctf-sage:<version>` image of tools/images.toml (B-188), run with no network
                 and never pulled; it must be built and fresh (`python -m ctf toolchain status`).
    sage         sage-local when there is one and no version was asked for, else sage-image.
    auto         python when the job fits it (`AUTO_*` limits), else sage.

Nothing is installed, pulled or built here, and no algorithm is swapped for a weaker one: BKZ without
fpylll or Sage is `blocked` with `needs_tool` naming what is missing, never a quiet LLL. A backend that
is absent, stale or the wrong release is `blocked`; a backend that ran and failed is `error`; one that
ran out of time is `timeout`.

What the result proves (`proof`):

    exact     lll/bkz: the backend's transforms U and V are checked here over the integers (U·B = R and
              V·R = B), so the reduced rows span exactly the input lattice. variety/roots/small_roots:
              every returned point is substituted into the input polynomials here.
    partial   eliminate/resultant: only "the eliminated variables are absent" is checked.
    none      groebner: a basis cannot be checked by substitution. Take roots with `variety`.

A point that fails its substitution, or a transform that does not multiply out, turns the whole result
into `error`: an unchecked value never comes back as an answer. Completeness (that a variety lists
every solution) is the backend's claim.

Polynomials are never evaluated as code. A polynomial is a string parsed by the small parser below
(integers, variable names, `+ - * / ^ **`, parentheses; `/` only by an integer constant) or a term list
`[[coeff, [e0, e1, ...]], ...]`. The Sage worker (`_algebra_sage_worker.py`) receives exponent tuples
and integers only, under the variable names x0..xN it makes itself.

CLI (JSON on stdout; exit 0 ok, 1 error/timeout, 2 bad job, 3 blocked):

    algebra_service.py status
    algebra_service.py run JOB.json [--backend B] [--sage-version V] [--timeout S]
    algebra_service.py selftest [--backend B] [--sage-version V] [--timeout S]
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

SCHEMA = 1
SENTINEL = "CTF-ALGEBRA-RESULT "
LATTICE_OPS = ("lll", "bkz")
IDEAL_OPS = ("groebner", "variety", "eliminate", "resultant", "roots")
OPS = LATTICE_OPS + IDEAL_OPS + ("small_roots",)
BACKENDS = ("auto", "python", "sage", "sage-local", "sage-image")
ORDERS = ("lex", "deglex", "degrevlex")
RING_KINDS = ("QQ", "GF", "Zmod")
STATUSES = ("ok", "blocked", "error", "timeout")
WORKER_NAME = "_algebra_sage_worker.py"

MAX_JSON = 16 * 1024 * 1024
MAX_ROWS = 1024
MAX_COLUMNS = 2048
MAX_BITS = 65_536
MAX_VARS = 64
MAX_POLYS = 512
MAX_TERMS = 50_000
MAX_EXPONENT = 100_000
MAX_INT_DIGITS = 25_000
# Parsing a polynomial string runs in the calling process, before any worker or timeout exists, so it
# is bounded by work, not time. MAX_NESTING caps parentheses (the parser recurses on them); unary signs
# are read in a loop. MAX_PARSE_WORK caps the multiplication work of one job's polynomials in
# `_Meter` units: each coefficient product costs PARSE_PRODUCT_COST plus its 64-bit limb product (twice
# that in GF/Zmod, for the reduction). Measured at about 4e7 units per CPU second for small and
# 4096-bit coefficients, so the cap is 2-3 s of CPU; schoolbook limb counting over-charges very large
# coefficients (Python multiplies them by Karatsuba), which only makes the cap stricter. A bigger
# expansion is a JobError: send it as a term list, which is read in linear time.
MAX_NESTING = 64
MAX_PARSE_WORK = 100_000_000
PARSE_PRODUCT_COST = 32
DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 86_400
# Seconds a worker gets on top of the job's timeout before it is killed from outside: interpreter
# start for the python child, Sage start-up, container start (amd64 Sage is emulated on Apple Silicon).
PYTHON_GRACE = 10
SAGE_LOCAL_GRACE = 60
IMAGE_START_GRACE = 180
DOCKER_KILL_TIMEOUT = 60
CONTAINER_PREFIX = "ctf-algebra-"

# What `auto` hands to the python backend; a larger job goes to Sage (or is blocked, never shrunk).
AUTO_LATTICE_ROWS = 48
AUTO_IDEAL_VARS = 6
AUTO_IDEAL_TERMS = 400
AUTO_IDEAL_DEGREE = 12
AUTO_SMALL_ROOTS_DEGREE = 6

_INT_RE = re.compile(r"[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)")
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RING_RE = re.compile(r"\s*(QQ|GF|Zmod)\s*(?:\(\s*([+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))\s*\))?\s*")
_TOKEN_RE = re.compile(r"\s*(?:(0[xX][0-9a-fA-F]+|[0-9]+)|([A-Za-z_][A-Za-z0-9_]*)|(\*\*|[-+*/^()]))")
_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)*")


class JobError(ValueError):
    """The job itself is malformed or over a cap (CLI exit 2)."""


class ServiceError(RuntimeError):
    """A backend ran and did not produce a checked result (`ServiceResult.require`)."""


class BackendUnavailable(RuntimeError):
    """No backend can run the job as asked. `needs_tool` uses the needs_tool marker names
    (`sage`, `py:fpylll`, `image:ctf-sage:10.7`); `fix` is the command or step that provides it."""

    def __init__(self, reason: str, needs_tool: Sequence[str] = (), fix: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.needs_tool = tuple(needs_tool)
        self.fix = fix


class _Meter:
    """The parse-work budget of one job (see MAX_PARSE_WORK); spend() raises before the work is done."""

    def __init__(self, cap: int | None = None):
        self.cap, self.used = (MAX_PARSE_WORK if cap is None else cap), 0

    def spend(self, units: int) -> None:
        if self.used + units > self.cap:
            raise JobError(f"expanding the polynomials would exceed the parse-work cap of {self.cap} units "
                           f"(MAX_PARSE_WORK): pass a large expansion as a term list instead")
        self.used += units


def _limbs(c) -> int:
    if isinstance(c, Fraction):
        return (c.numerator.bit_length() + c.denominator.bit_length()) // 64 + 1
    return int(c).bit_length() // 64 + 1


@contextlib.contextmanager
def _bigints():
    """Lift Python's decimal-conversion cap for the block: lattice entries pass 4300 digits."""
    get, put = getattr(sys, "get_int_max_str_digits", None), getattr(sys, "set_int_max_str_digits", None)
    if get is None or put is None:
        yield
        return
    old = get()
    if old == 0 or old >= MAX_INT_DIGITS:
        yield
        return
    put(MAX_INT_DIGITS)
    try:
        yield
    finally:
        put(old)


# --------------------------------------------------------------------------------------- integers

def parse_int(value, name: str = "value", *, bits: int = MAX_BITS) -> int:
    """An int, or a decimal / 0x string of one, under the bit cap. JobError otherwise."""
    if isinstance(value, bool):
        raise JobError(f"{name} must be an integer, not a boolean")
    if isinstance(value, str):
        text = value.strip().replace("_", "")
        if not _INT_RE.fullmatch(text):
            raise JobError(f"{name} is not an integer: {value[:40]!r}")
        sign = -1 if text.startswith("-") else 1
        digits = text.lstrip("+-")
        value = sign * (int(digits, 16) if digits[:2].lower() == "0x" else int(digits))
    if not isinstance(value, int):
        raise JobError(f"{name} must be an integer")
    if value.bit_length() > bits:
        raise JobError(f"{name} exceeds the {bits}-bit cap")
    return value


_int = parse_int


def _basis(value) -> list[list[int]]:
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= MAX_ROWS:
        raise JobError(f"basis must hold 1..{MAX_ROWS} rows")
    first = value[0]
    width = len(first) if isinstance(first, (list, tuple)) else 0
    if not 1 <= width <= MAX_COLUMNS:
        raise JobError(f"basis rows must hold 1..{MAX_COLUMNS} integers")
    if len(value) > width:
        raise JobError("basis has more rows than columns: its rows cannot be independent")
    rows = []
    for i, row in enumerate(value):
        if not isinstance(row, (list, tuple)) or len(row) != width:
            raise JobError(f"basis row {i} does not have {width} entries")
        rows.append([_int(x, f"basis[{i}]") for x in row])
    return rows


# ------------------------------------------------------------------------------------------ rings

@dataclass(frozen=True)
class Ring:
    """QQ, GF(p) or Zmod(n). Coefficients are Fractions over QQ and ints in [0, modulus) otherwise."""
    kind: str
    modulus: int | None = None

    def coerce(self, value):
        fr = Fraction(value)
        if self.kind == "QQ":
            return fr
        num, den = fr.numerator % self.modulus, fr.denominator % self.modulus
        if den == 1:
            return num
        try:
            return num * pow(den, -1, self.modulus) % self.modulus
        except ValueError:
            raise JobError(f"denominator {fr.denominator} is not invertible in {self.text()}") from None

    def encode(self, c):
        """Wire form: an int, or [numerator, denominator] for a non-integer rational."""
        if self.kind == "QQ" and c.denominator != 1:
            return [c.numerator, c.denominator]
        return int(c)

    def decode(self, c, name: str = "coefficient"):
        if isinstance(c, (list, tuple)):
            if self.kind != "QQ" or len(c) != 2:
                raise JobError(f"{name}: a [numerator, denominator] pair is only a QQ coefficient")
            den = _int(c[1], name)
            if den == 0:
                raise JobError(f"{name}: zero denominator")
            return Fraction(_int(c[0], name), den)
        if isinstance(c, str) and "/" in c:
            num, _, den = c.partition("/")
            return self.decode([num, den], name) if self.kind == "QQ" else self.coerce(
                Fraction(_int(num, name), _nonzero(_int(den, name), name)))
        return self.coerce(_int(c, name))

    def show(self, c):
        """Result form: an int, or "n/d" for a non-integer rational."""
        if self.kind == "QQ" and c.denominator != 1:
            return f"{c.numerator}/{c.denominator}"
        return int(c)

    def spec(self) -> dict:
        return {"kind": self.kind, "modulus": self.modulus}

    def text(self) -> str:
        return "QQ" if self.kind == "QQ" else f"{self.kind}({self.modulus})"


def _nonzero(value: int, name: str) -> int:
    if value == 0:
        raise JobError(f"{name}: zero denominator")
    return value


def parse_ring(value) -> Ring:
    """"QQ", "GF(p)", "Zmod(n)" or {"kind": ..., "modulus": ...}. GF needs a prime (checked by the
    backend that runs the job), Zmod any modulus above 1."""
    if isinstance(value, str):
        m = _RING_RE.fullmatch(value)
        if not m:
            raise JobError(f"ring {value[:40]!r} is not QQ, GF(<p>) or Zmod(<n>)")
        kind, modulus = m.group(1), m.group(2)
    elif isinstance(value, Mapping):
        if set(value) - {"kind", "modulus"}:
            raise JobError(f"ring has unknown keys: {sorted(set(value) - {'kind', 'modulus'})}")
        kind, modulus = value.get("kind"), value.get("modulus")
    else:
        raise JobError("ring must be a string or an object")
    if kind not in RING_KINDS:
        raise JobError(f"ring kind must be one of {RING_KINDS}")
    if kind == "QQ":
        if modulus is not None:
            raise JobError("QQ takes no modulus")
        return Ring("QQ")
    if modulus is None:
        raise JobError(f"{kind} needs a modulus")
    n = _int(modulus, "ring modulus")
    if n < 2:
        raise JobError("ring modulus must be at least 2")
    return Ring(kind, n)


# ------------------------------------------------------------------------------ sparse polynomials
# A polynomial is {exponent tuple: coefficient}, zero coefficients removed.

Poly = dict


def poly_add(ring: Ring, a: Poly, b: Poly) -> Poly:
    return _add_into(ring, dict(a), b)


def _add_into(ring: Ring, out: Poly, b: Poly) -> Poly:
    for e, c in b.items():
        s = ring.coerce(out.get(e, 0) + c)
        if s:
            out[e] = s
        else:
            out.pop(e, None)
    return out


def poly_mul(ring: Ring, a: Poly, b: Poly, *, cap: int = MAX_TERMS, meter: _Meter | None = None) -> Poly:
    """a·b; with a meter, each row of the product is paid for before it is computed."""
    out: Poly = {}
    if meter is not None:
        b_limbs = sum(_limbs(c) for c in b.values())
        if ring.kind != "QQ":
            b_limbs *= 2                                    # and the reduction mod the modulus
        row_base = PARSE_PRODUCT_COST * len(b)
    for ea, ca in a.items():
        if meter is not None:
            meter.spend(row_base + _limbs(ca) * b_limbs)
        for eb, cb in b.items():
            e = tuple(x + y for x, y in zip(ea, eb))
            if max(e, default=0) > MAX_EXPONENT:
                raise JobError(f"an exponent exceeds the cap of {MAX_EXPONENT}")
            s = ring.coerce(out.get(e, 0) + ca * cb)
            if s:
                out[e] = s
            else:
                out.pop(e, None)
        if len(out) > cap:
            raise JobError(f"a polynomial exceeds the cap of {cap} terms")
    return out


def poly_eval(ring: Ring, f: Poly, point: Sequence) -> Any:
    """f at a point (one ring element per variable), reduced in the ring."""
    total = Fraction(0) if ring.kind == "QQ" else 0
    for e, c in f.items():
        term = c
        for v, k in zip(point, e):
            if k:
                term = term * (pow(v, k, ring.modulus) if ring.kind != "QQ" else v ** k)
        total = total + term
        if ring.kind != "QQ":
            total %= ring.modulus
    return total


def poly_text(ring: Ring, f: Poly, names: Sequence[str]) -> str:
    """A string the parser reads back to the same polynomial."""
    if not f:
        return "0"
    parts = []
    for e in sorted(f, reverse=True):
        c = f[e]
        mono = "*".join(n if k == 1 else f"{n}^{k}" for n, k in zip(names, e) if k)
        neg = ring.kind == "QQ" and c < 0
        mag = -c if neg else c
        if ring.kind == "QQ" and mag.denominator != 1:
            ctext = f"{mag.numerator}/{mag.denominator}"
            body = f"{mag.numerator}*{mono}/{mag.denominator}" if mono else ctext
        else:
            ctext = str(int(mag))
            body = mono if (mono and mag == 1) else (f"{ctext}*{mono}" if mono else ctext)
        parts.append(("- " if neg else "+ ") + body)
    text = " ".join(parts)
    return text[2:] if text.startswith("+ ") else "-" + text[2:]


def parse_polynomial(text: str, names: Sequence[str], ring: Ring, *, meter: _Meter | None = None) -> Poly:
    """Parse `x^2 + 3*x*y - 7/2` over the ring. No evaluation: a tokenizer and a recursive descent over
    integers, the given names, + - * / ^ ** and parentheses; `/` divides by an integer constant only.
    Parentheses nest at most MAX_NESTING deep and the expansion work is charged to `meter` (a fresh
    MAX_PARSE_WORK budget when none is given): past either cap it is JobError, never a crash."""
    meter = _Meter() if meter is None else meter
    if not isinstance(text, str) or len(text) > MAX_JSON:
        raise JobError("a polynomial string is required")
    tokens, pos = [], 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            if text[pos:].strip() == "":
                break
            raise JobError(f"polynomial: unexpected character at offset {pos}: {text[pos:pos + 12]!r}")
        tokens.append(m)
        pos = m.end()
    index = {n: i for i, n in enumerate(names)}
    n = len(names)
    zero = tuple([0] * n)
    at = [0]
    depth = [0]

    def mul(a: Poly, b: Poly) -> Poly:
        return poly_mul(ring, a, b, meter=meter)

    def peek():
        return tokens[at[0]].group(3) if at[0] < len(tokens) else None

    def const(value) -> Poly:
        c = ring.coerce(value)
        return {zero: c} if c else {}

    def atom() -> Poly:
        if at[0] >= len(tokens):
            raise JobError("polynomial: unexpected end")
        tok = tokens[at[0]]
        at[0] += 1
        if tok.group(1) is not None:
            return const(_int(tok.group(1), "polynomial constant"))
        if tok.group(2) is not None:
            name = tok.group(2)
            if name not in index:
                raise JobError(f"polynomial: unknown variable {name!r} (vars: {list(names)})")
            return {tuple(1 if i == index[name] else 0 for i in range(n)): ring.coerce(1)}
        if tok.group(3) == "(":
            if depth[0] >= MAX_NESTING:
                raise JobError(f"polynomial: parentheses nest deeper than the cap of {MAX_NESTING}")
            depth[0] += 1
            inner = expr()
            depth[0] -= 1
            if peek() != ")":
                raise JobError("polynomial: missing ')'")
            at[0] += 1
            return inner
        raise JobError(f"polynomial: unexpected {tok.group(3)!r}")

    def power() -> Poly:
        base = atom()
        if peek() in ("^", "**"):
            at[0] += 1
            if at[0] >= len(tokens) or tokens[at[0]].group(1) is None:
                raise JobError("polynomial: an exponent must be a non-negative integer constant")
            k = _int(tokens[at[0]].group(1), "exponent")
            at[0] += 1
            if k > MAX_EXPONENT:
                raise JobError(f"an exponent exceeds the cap of {MAX_EXPONENT}")
            out, sq = const(1), base
            while k:
                if k & 1:
                    out = mul(out, sq)
                k >>= 1
                if k:
                    sq = mul(sq, sq)
            return out
        return base

    def unary() -> Poly:
        negate = False
        while peek() in ("-", "+"):                         # a loop, not recursion: any run of signs
            negate ^= peek() == "-"
            at[0] += 1
        out = power()
        return mul(const(-1), out) if negate else out

    def term() -> Poly:
        out = unary()
        while peek() in ("*", "/"):
            op = peek()
            at[0] += 1
            if op == "*":
                out = mul(out, unary())
                continue
            if at[0] >= len(tokens) or tokens[at[0]].group(1) is None:
                raise JobError("polynomial: '/' takes an integer constant only")
            d = _nonzero(_int(tokens[at[0]].group(1), "divisor"), "polynomial")
            at[0] += 1
            out = mul(out, const(Fraction(1, d)))
        return out

    def expr() -> Poly:
        out = term()                                         # a fresh dict on every path: safe to add into
        while peek() in ("+", "-"):
            op = peek()
            at[0] += 1
            rhs = term()
            meter.spend(len(rhs))
            _add_into(ring, out, rhs if op == "+" else mul(const(-1), rhs))   # in place: linear in the terms
            if len(out) > MAX_TERMS:
                raise JobError(f"a polynomial exceeds the cap of {MAX_TERMS} terms")
        return out

    result = expr()
    if at[0] != len(tokens):
        tok = tokens[at[0]]
        raise JobError(f"polynomial: unexpected {tok.group(0).strip()!r}")
    return result


def _poly_from_terms(value, nvars: int, ring: Ring, name: str) -> Poly:
    out: Poly = {}
    if not isinstance(value, (list, tuple)) or len(value) > MAX_TERMS:
        raise JobError(f"{name} must be a string or a term list of at most {MAX_TERMS} terms")
    for term in value:
        if not isinstance(term, (list, tuple)) or len(term) != 2:
            raise JobError(f"{name}: a term is [coefficient, [exponents]]")
        exps = term[1]
        if not isinstance(exps, (list, tuple)) or len(exps) != nvars:
            raise JobError(f"{name}: a term needs {nvars} exponents")
        key = []
        for e in exps:
            if isinstance(e, bool) or not isinstance(e, int) or not 0 <= e <= MAX_EXPONENT:
                raise JobError(f"{name}: exponents are integers in 0..{MAX_EXPONENT}")
            key.append(e)
        out = poly_add(ring, out, {tuple(key): c} if (c := ring.decode(term[0], name)) else {})
    return out


def _poly_in(value, names: Sequence[str], ring: Ring, name: str, meter: _Meter) -> Poly:
    return (parse_polynomial(value, names, ring, meter=meter) if isinstance(value, str)
            else _poly_from_terms(value, len(names), ring, name))


def _wire(ring: Ring, f: Poly) -> list:
    return [[ring.encode(f[e]), list(e)] for e in sorted(f, reverse=True)]


def _unwire(ring: Ring, value, nvars: int, name: str) -> Poly:
    try:
        return _poly_from_terms(value, nvars, ring, name)
    except JobError as ex:
        raise ServiceError(f"the backend returned a malformed polynomial: {ex}") from None


# ------------------------------------------------------------------------------------ job parsing

@dataclass(frozen=True)
class Job:
    """A validated job: `wire` is what a worker receives (integers and exponent lists only)."""
    op: str
    wire: dict
    ring: Ring | None = None
    names: tuple[str, ...] = ()
    polys: tuple = ()
    basis: tuple = ()


def _keys(job: Mapping, allowed: Sequence[str]) -> None:
    extra = sorted(set(job) - set(allowed) - {"op", "schema"})
    if extra:
        raise JobError(f"unknown job keys for op {job.get('op')!r}: {extra}")


def _names(value) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= MAX_VARS:
        raise JobError(f"vars must list 1..{MAX_VARS} names")
    for n in value:
        if not isinstance(n, str) or not _NAME_RE.fullmatch(n):
            raise JobError(f"variable name {n!r} is not an identifier")
    if len(set(value)) != len(value):
        raise JobError("vars must be distinct")
    return tuple(value)


def parse_job(job: Mapping) -> Job:
    """Validate a job and build its wire form. JobError names what is wrong."""
    if not isinstance(job, Mapping):
        raise JobError("a job is a JSON object")
    if job.get("schema", SCHEMA) != SCHEMA:
        raise JobError(f"job schema must be {SCHEMA}")
    op = job.get("op")
    if op not in OPS:
        raise JobError(f"op must be one of {OPS}")
    if op in LATTICE_OPS:
        _keys(job, ("basis", "block_size", "tours"))
        basis = _basis(job.get("basis"))
        wire: dict = {"schema": SCHEMA, "op": op, "basis": basis}
        if op == "bkz":
            block = job.get("block_size", 20)
            if isinstance(block, bool) or not isinstance(block, int) or not 2 <= block <= len(basis):
                raise JobError("bkz block_size must be an integer in 2..number-of-rows")
            wire["block_size"] = block
            tours = job.get("tours")
            if tours is not None and (isinstance(tours, bool) or not isinstance(tours, int)
                                      or not 1 <= tours <= 64):
                raise JobError("bkz tours must be an integer in 1..64")
            wire["tours"] = tours
        elif "block_size" in job or "tours" in job:
            raise JobError("block_size and tours belong to op bkz")
        return Job(op, wire, basis=tuple(tuple(r) for r in basis))
    if op == "small_roots":
        _keys(job, ("modulus", "poly", "vars", "bound", "beta", "epsilon"))
        modulus = _int(job.get("modulus"), "modulus")
        if modulus < 2:
            raise JobError("modulus must be at least 2")
        ring = Ring("Zmod", modulus)
        names = _names(job.get("vars", ["x"]))
        if len(names) != 1:
            raise JobError("small_roots is univariate: one variable")
        f = _poly_in(job.get("poly"), names, ring, "poly", _Meter())
        degree = max((e[0] for e in f), default=0)
        if degree < 1:
            raise JobError("small_roots needs a polynomial of degree 1 or more")
        if math.gcd(f[(degree,)], modulus) != 1:
            raise JobError("small_roots needs a leading coefficient invertible mod the modulus")
        bound = _int(job.get("bound"), "bound")
        if bound < 1:
            raise JobError("bound must be positive")
        beta = job.get("beta", 1.0)
        if isinstance(beta, bool) or not isinstance(beta, (int, float)) or not 0 < beta <= 1:
            raise JobError("beta must be a number in (0, 1]")
        eps = job.get("epsilon")
        if eps is not None and (isinstance(eps, bool) or not isinstance(eps, (int, float)) or not 0 < eps < 1):
            raise JobError("epsilon must be a number in (0, 1)")
        dense = [int(f.get((k,), 0)) for k in range(degree + 1)]
        wire = {"schema": SCHEMA, "op": op, "modulus": modulus, "poly": dense, "bound": bound,
                "beta": float(beta), "epsilon": None if eps is None else float(eps)}
        return Job(op, wire, ring, names, (f,))
    _keys(job, ("ring", "vars", "polys", "order", "eliminate", "var"))
    ring = parse_ring(job.get("ring"))
    names = _names(job.get("vars"))
    raw = job.get("polys")
    if not isinstance(raw, (list, tuple)) or not 1 <= len(raw) <= MAX_POLYS:
        raise JobError(f"polys must list 1..{MAX_POLYS} polynomials")
    meter = _Meter()                                         # one parse-work budget for the whole job
    polys = tuple(_poly_in(p, names, ring, f"polys[{i}]", meter) for i, p in enumerate(raw))
    order = job.get("order", "lex")
    if order not in ORDERS:
        raise JobError(f"order must be one of {ORDERS}")
    wire = {"schema": SCHEMA, "op": op, "ring": ring.spec(), "nvars": len(names), "order": order,
            "polys": [_wire(ring, f) for f in polys]}
    if op != "eliminate" and "eliminate" in job:
        raise JobError("eliminate belongs to op eliminate")
    if op != "resultant" and "var" in job:
        raise JobError("var belongs to op resultant")
    if op == "eliminate":
        elim = job.get("eliminate")
        if (not isinstance(elim, (list, tuple)) or not elim or len(set(elim)) != len(elim)
                or any(v not in names for v in elim)):
            raise JobError("eliminate must list distinct names from vars")
        if len(elim) == len(names):
            raise JobError("eliminate must leave at least one variable")
        wire["eliminate"] = sorted(names.index(v) for v in elim)
    elif op == "resultant":
        if len(polys) != 2 or job.get("var") not in names:
            raise JobError("resultant takes exactly two polys and var, one of vars")
        if any(not f for f in polys):
            raise JobError("resultant of the zero polynomial is not defined here")
        wire["var"] = names.index(job["var"])
    elif op == "roots":
        if len(names) != 1 or len(polys) != 1 or not polys[0]:
            raise JobError("roots takes one variable and one non-zero polynomial")
        if ring.kind == "Zmod":
            raise JobError("roots works over QQ or GF(p); for a composite modulus use small_roots or factor it")
    if op == "variety" and ring.kind == "Zmod":
        raise JobError("variety needs a field: QQ or GF(p)")
    return Job(op, wire, ring, names, polys)


# ----------------------------------------------------------------------------- lattice certificates

def _matmul(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]]) -> list[list[int]]:
    cols = list(zip(*b))
    return [[sum(x * y for x, y in zip(row, col)) for col in cols] for row in a]


def _int_matrix(value, rows: int, cols: int) -> list[list[int]] | None:
    if not isinstance(value, list) or len(value) != rows:
        return None
    out = []
    for row in value:
        if not isinstance(row, list) or len(row) != cols:
            return None
        if any(isinstance(x, bool) or not isinstance(x, int) for x in row):
            return None
        out.append(row)
    return out


def same_lattice(before, after, u, v) -> bool:
    """True when U·before == after and V·after == before over the integers: each row set is an integer
    combination of the other, so both span one lattice. Anything malformed is False."""
    n = len(before)
    width = len(before[0]) if n else 0
    r = _int_matrix(after, n, width)
    uu, vv = _int_matrix(u, n, n), _int_matrix(v, n, n)
    if r is None or uu is None or vv is None:
        return False
    return _matmul(uu, before) == r and _matmul(vv, r) == [list(x) for x in before]


def solve_left(m: Sequence[Sequence[int]], t: Sequence[Sequence[int]]) -> list[list[int]] | None:
    """The integer matrix X with X·M == T for independent rows M, or None when there is none (T is
    outside the lattice of M, or M's rows are dependent). Exact rational elimination."""
    n = len(m)
    if n == 0 or len(t) == 0:
        return None
    cols, k = len(m[0]), len(t)
    aug = [[Fraction(m[i][c]) for i in range(n)] + [Fraction(t[j][c]) for j in range(k)] for c in range(cols)]
    rank = 0
    for col in range(n):
        piv = next((r for r in range(rank, cols) if aug[r][col] != 0), None)
        if piv is None:
            return None
        aug[rank], aug[piv] = aug[piv], aug[rank]
        inv = 1 / aug[rank][col]
        aug[rank] = [x * inv for x in aug[rank]]
        for r in range(cols):
            if r != rank and aug[r][col] != 0:
                f = aug[r][col]
                aug[r] = [x - f * y for x, y in zip(aug[r], aug[rank])]
        rank += 1
    if any(x != 0 for r in range(rank, cols) for x in aug[r][n:]):
        return None
    out = []
    for j in range(k):
        row = [aug[i][n + j] for i in range(n)]
        if any(x.denominator != 1 for x in row):
            return None
        out.append([int(x) for x in row])
    return out


# ------------------------------------------------------------------------------ the python backend
# Runs in a child process (`algebra_service.py __worker__ job.json`) so a Groebner blow-up is killed
# at the timeout. Every function below takes and returns wire forms.

_SYMPY_ORDER = {"lex": "lex", "deglex": "grlex", "degrevlex": "grevlex"}


def _py_gens(nvars: int):
    from sympy import symbols
    return symbols(" ".join(f"x{i}" for i in range(nvars)), seq=True)


def _py_domain_kw(ring: Ring) -> dict:
    from sympy import QQ, isprime
    if ring.kind == "QQ":
        return {"domain": QQ}
    if ring.kind == "GF":
        if not isprime(ring.modulus):
            raise ValueError(f"GF({ring.modulus}): the modulus is not prime (use Zmod with a Sage backend)")
        return {"modulus": ring.modulus}
    raise ValueError("the python backend has no Zmod(n) ideals: use a Sage backend")


def _py_poly(ring: Ring, f: Poly, gens, where: Sequence[int] | None = None):
    """A SymPy Poly over `gens`; `where[k]` is the variable index that generator k stands for."""
    from sympy import Poly as SPoly, Rational
    where = list(range(len(gens))) if where is None else list(where)
    data = {tuple(e[i] for i in where): (Rational(c.numerator, c.denominator) if ring.kind == "QQ" else int(c))
            for e, c in f.items()}
    return SPoly.from_dict(data, tuple(gens), **_py_domain_kw(ring))


def _py_unpoly(ring: Ring, sp, gens) -> Poly:
    """A SymPy Poly (maybe over fewer generators) back to a sparse polynomial over all of `gens`."""
    where = [gens.index(g) for g in sp.gens]
    out: Poly = {}
    for e, c in sp.as_dict().items():
        full = [0] * len(gens)
        for i, k in zip(where, e):
            full[i] = int(k)
        value = ring.coerce(Fraction(int(c.p), int(c.q)) if ring.kind == "QQ" else int(c))
        if value:
            out[tuple(full)] = value
    return out


def _py_groebner(ring: Ring, nvars: int, order: str, polys: Sequence[Poly],
                 first: Sequence[int] = ()) -> list[Poly]:
    """The reduced Groebner basis; `first` lists variable indices to rank above the others."""
    from sympy import groebner
    all_gens = tuple(_py_gens(nvars))
    where = list(first) + [i for i in range(nvars) if i not in first]
    gens = tuple(all_gens[i] for i in where)
    live = [_py_poly(ring, f, gens, where) for f in polys if f]
    if not live:
        return []
    basis = groebner(live, *gens, order=_SYMPY_ORDER[order], **_py_domain_kw(ring))
    return [g for g in (_py_unpoly(ring, sp, all_gens) for sp in basis.polys) if g]


def _py_univariate_roots(ring: Ring, dense: Sequence) -> list:
    """Roots in the ring of a univariate polynomial given lowest degree first (not all zero)."""
    from sympy import ZZ, Poly as SPoly, Rational, symbols
    coeffs = list(dense)
    while coeffs and coeffs[-1] == 0:
        coeffs.pop()
    if len(coeffs) < 2:
        return []
    if ring.kind == "QQ":
        x = symbols("x0")
        sp = SPoly([Rational(c.numerator, c.denominator) for c in reversed(coeffs)], x, domain="QQ")
        return sorted(Fraction(int(r.p), int(r.q)) for r in sp.ground_roots())
    from sympy.polys.galoistools import gf_factor
    _py_domain_kw(ring)
    p = ring.modulus
    _, factors = gf_factor([ZZ(int(c) % p) for c in reversed(coeffs)], p, ZZ)
    return sorted({int(-f[1]) % p for f, _ in factors if len(f) == 2})


def _py_variety(ring: Ring, nvars: int, polys: Sequence[Poly]) -> list[tuple]:
    """Every point of the ring's field that all polynomials vanish on, for a zero-dimensional ideal.
    Lex Groebner basis, then back-substitution from the last variable: at each level the basis
    polynomials that involve only the variables fixed so far and the next one become univariate, and
    the next coordinate is a common root of them. A level with no such polynomial is a free variable:
    ValueError (the ideal is not zero-dimensional)."""
    basis = _py_groebner(ring, nvars, "lex", polys)
    if any(set(g) == {tuple([0] * nvars)} for g in basis):
        return []
    if not basis:
        raise ValueError("the ideal is zero: every point is a solution (not zero-dimensional)")
    points: list[tuple] = []

    def descend(level: int, tail: tuple) -> None:
        if level < 0:
            points.append(tail)
            return
        common = None
        for g in basis:
            if any(e[i] for e in g for i in range(level)):
                continue
            dense: dict[int, Any] = {}
            for e, c in g.items():
                term = c
                for value, k in zip(tail, e[level + 1:]):
                    if k:
                        term = term * (pow(value, k, ring.modulus) if ring.kind != "QQ" else value ** k)
                dense[e[level]] = ring.coerce(dense.get(e[level], 0) + term)
            coeffs = [dense.get(k, 0) for k in range(max(dense, default=0) + 1)]
            if not any(coeffs):
                continue
            roots = set(_py_univariate_roots(ring, coeffs))      # a non-zero constant has none
            common = roots if common is None else common & roots
            if not common:
                return
        if common is None:
            raise ValueError(f"the ideal is not zero-dimensional: variable {level} is free")
        for value in sorted(common):
            descend(level - 1, (value,) + tail)

    descend(nvars - 1, ())
    return sorted(set(points))


def _py_eliminate(ring: Ring, nvars: int, polys: Sequence[Poly], elim: Sequence[int]) -> list[Poly]:
    """Generators of the elimination ideal: a lex basis with the eliminated variables first, keeping
    the members free of them."""
    basis = _py_groebner(ring, nvars, "lex", polys, first=elim)
    return [g for g in basis if not any(e[i] for e in g for i in elim)]


def _py_resultant(ring: Ring, nvars: int, f: Poly, g: Poly, var: int) -> Poly:
    gens = tuple(_py_gens(nvars))
    where = [var] + [i for i in range(nvars) if i != var]
    ordered = tuple(gens[i] for i in where)
    sf, sg = _py_poly(ring, f, ordered, where), _py_poly(ring, g, ordered, where)
    res = sf.resultant(sg)
    if not hasattr(res, "as_dict"):
        return {tuple([0] * nvars): c} if (c := ring.coerce(Fraction(str(res)))) else {}
    return _py_unpoly(ring, res, gens)


def _python_run(wire: dict, deadline: float | None = None) -> dict:
    """One wire job on the python backend: {"status": "ok", "engine", "data"} or blocked/error."""
    op = wire["op"]
    if op in LATTICE_OPS:
        import lattice_backends
        if op == "bkz" and not lattice_backends.backend_status()["bkz"]:
            return {"status": "blocked", "needs_tool": ["py:fpylll"],
                    "error": "BKZ on the python backend needs a local fpylll, which is not importable"}
        got = lattice_backends.reduce_lattice(wire["basis"], method=op, block_size=wire.get("block_size", 20),
                                              tours=wire.get("tours") or 8, deadline=deadline)
        if got is None:
            return {"status": "error", "error": "the reduction declined: dependent rows, the deadline, or a "
                                                "reduced basis that is not the same lattice"}
        reduced = [list(r) for r in got.basis]
        u, v = solve_left(wire["basis"], reduced), solve_left(reduced, wire["basis"])
        if u is None or v is None:
            return {"status": "error", "error": "no integer transform between the input and the reduced basis"}
        return {"status": "ok", "engine": got.backend, "data": {"basis": reduced, "u": u, "v": v}}
    if op == "small_roots":
        import rsa_lattice
        roots = rsa_lattice.coppersmith_roots(wire["poly"], wire["modulus"], wire["bound"],
                                              beta=wire["beta"], deadline=deadline)
        return {"status": "ok", "engine": "in-repo Howgrave-Graham (rsa_lattice.coppersmith_roots)",
                "data": {"roots": [int(r) for r in roots]}}
    import sympy
    ring = Ring(wire["ring"]["kind"], wire["ring"]["modulus"])
    n = wire["nvars"]
    polys = [_poly_from_terms(p, n, ring, "poly") for p in wire["polys"]]
    engine = f"SymPy {sympy.__version__}"
    if op == "groebner":
        data = {"basis": [_wire(ring, g) for g in _py_groebner(ring, n, wire["order"], polys)]}
    elif op == "variety":
        data = {"points": [[ring.encode(c) for c in pt] for pt in _py_variety(ring, n, polys)]}
    elif op == "eliminate":
        data = {"basis": [_wire(ring, g) for g in _py_eliminate(ring, n, polys, wire["eliminate"])]}
    elif op == "resultant":
        data = {"poly": _wire(ring, _py_resultant(ring, n, polys[0], polys[1], wire["var"]))}
    else:
        f = polys[0]
        dense = [f.get((k,), 0) for k in range(max(e[0] for e in f) + 1)]
        data = {"roots": [ring.encode(r) for r in _py_univariate_roots(ring, dense)]}
    return {"status": "ok", "engine": engine, "data": data}


def _worker_main(path: str) -> int:
    """The python backend's child: read a wire job, print the sentinel line."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    put = getattr(sys, "set_int_max_str_digits", None)
    if put is not None:
        put(0)
    try:
        wire = json.loads(Path(path).read_text(encoding="utf-8"))
        budget = wire.get("timeout")
        out = _python_run(wire, None if budget is None else time.monotonic() + budget)
    except Exception as ex:                                  # the child reports, the parent decides
        out = {"status": "error", "error": f"{type(ex).__name__}: {ex}"[:2000]}
    sys.stdout.write("\n" + SENTINEL + json.dumps(out, sort_keys=True) + "\n")
    return 0


# ---------------------------------------------------------------------------------------- backends

@dataclass(frozen=True)
class _Plan:
    backend: str                  # python | sage-local | sage-image
    detail: str
    sage: str | None = None       # sage-local: the binary
    image: Any = None             # sage-image: the images.Image
    want_version: str | None = None


def _has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _python_reason(job: Job, *, auto: bool) -> BackendUnavailable | None:
    """Why the python backend cannot (or, for auto, should not) run the job; None when it can."""
    if job.op == "bkz":
        if not _has_module("fpylll"):
            return BackendUnavailable("BKZ on the python backend needs a local fpylll, which is not importable",
                                      ["py:fpylll"], "build fpylll into the venv (B-244), or use a Sage backend")
    if job.op in IDEAL_OPS:
        if not _has_module("sympy"):
            return BackendUnavailable("the python backend's ideal operations need SymPy", ["py:sympy"],
                                      "install the pinned requirements")
        if job.ring.kind == "Zmod":
            return BackendUnavailable(f"the python backend has no ideals over {job.ring.text()}: only QQ and GF(p)")
    if not auto:
        return None
    if job.op in LATTICE_OPS and len(job.basis) > AUTO_LATTICE_ROWS:
        return BackendUnavailable(f"{len(job.basis)} rows is above the {AUTO_LATTICE_ROWS}-row limit auto gives "
                                  "the pure-Python reducer")
    if job.op in IDEAL_OPS:
        terms = sum(len(f) for f in job.polys)
        degree = max((sum(e) for f in job.polys for e in f), default=0)
        if len(job.names) > AUTO_IDEAL_VARS or terms > AUTO_IDEAL_TERMS or degree > AUTO_IDEAL_DEGREE:
            return BackendUnavailable(
                f"{len(job.names)} variables, {terms} terms, degree {degree} is above what auto gives SymPy "
                f"({AUTO_IDEAL_VARS} variables, {AUTO_IDEAL_TERMS} terms, degree {AUTO_IDEAL_DEGREE})")
    if job.op == "small_roots" and len(job.wire["poly"]) - 1 > AUTO_SMALL_ROOTS_DEGREE:
        return BackendUnavailable(f"degree {len(job.wire['poly']) - 1} is above the degree-"
                                  f"{AUTO_SMALL_ROOTS_DEGREE} limit auto gives the pure-Python Coppersmith")
    return None


def _version_matches(wanted: str, provided: str) -> bool:
    """10.5 and 10.5.1 are served by a 10.5 Sage (the rule of ctf.toolchain.versions)."""
    return wanted == provided or wanted.startswith(provided + ".")


def sage_images(root: Path | None = None) -> list:
    """The Sage images of tools/images.toml (those declaring a `sage` version)."""
    from ctf.toolchain import images
    return [im for im in images.load(images.manifest_path(root)) if im.version_of("sage")]


def _plan_sage_local(env: Mapping[str, str], sage_version: str | None) -> _Plan:
    exe = shutil.which("sage", path=env.get("PATH"))
    if exe is None:
        raise BackendUnavailable("no `sage` on PATH", ["sage"],
                                 "use --backend sage-image, or install SageMath (a human step)")
    return _Plan("sage-local", exe, sage=exe, want_version=sage_version)


def _plan_sage_image(env: Mapping[str, str], sage_version: str | None, root: Path | None) -> _Plan:
    from ctf.toolchain import images
    try:
        known = sage_images(root)
    except (images.ImagesError, OSError) as ex:
        raise BackendUnavailable(f"the image manifest is unusable: {ex}", ["image:ctf-sage"]) from None
    if sage_version is None:
        chosen = [im for im in known if "sage" in im.default_for]
    else:
        chosen = [im for im in known if _version_matches(sage_version, im.version_of("sage"))]
    if len(chosen) != 1:
        have = ", ".join(f"{im.version_of('sage')} ({im.tag})" for im in known) or "none"
        what = "a default Sage image" if sage_version is None else f"a Sage {sage_version} image"
        raise BackendUnavailable(f"tools/images.toml has no single entry for {what}; it lists: {have}",
                                 ["image:ctf-sage"], "add the tag to tools/images.toml and build it")
    im = chosen[0]
    try:
        st = images.status([im], root=root, environ=env)[0]
    except images.ImagesError as ex:
        raise BackendUnavailable(str(ex), [f"image:{im.tag}"]) from None
    if not st.ok:
        raise BackendUnavailable(f"image {im.tag} is {st.state}: {st.detail}", [f"image:{im.tag}"], st.fix)
    return _Plan("sage-image", im.tag, image=im, want_version=im.version_of("sage"))


def plan_backend(job: Job, backend: str = "auto", *, sage_version: str | None = None,
                 environ: Mapping[str, str] | None = None, root: Path | None = None) -> _Plan:
    """Pick the one backend that runs the job, or raise BackendUnavailable naming what is missing."""
    if backend not in BACKENDS:
        raise JobError(f"backend must be one of {BACKENDS}")
    if sage_version is not None and (not isinstance(sage_version, str) or not _VERSION_RE.fullmatch(sage_version)):
        raise JobError("sage_version must look like 10.5")
    env = dict(os.environ if environ is None else environ)
    if backend == "python":
        if sage_version is not None:
            raise JobError("sage_version makes no sense with the python backend")
        why = _python_reason(job, auto=False)
        if why is not None:
            raise why
        return _Plan("python", "in-repo LLL / fpylll / SymPy")
    if backend == "sage-local":
        return _plan_sage_local(env, sage_version)
    if backend == "sage-image":
        return _plan_sage_image(env, sage_version, root)
    # auto and sage: one backend is chosen by what the job needs and what is here; a named release
    # only ever comes from its pinned image.
    tried: list[tuple[str, BackendUnavailable]] = []
    if backend == "auto" and sage_version is None:
        why = _python_reason(job, auto=True)
        if why is None:
            return _Plan("python", "in-repo LLL / fpylll / SymPy")
        tried.append(("python", why))
    if sage_version is None:
        try:
            return _plan_sage_local(env, None)
        except BackendUnavailable as ex:
            tried.append(("sage-local", ex))
    try:
        return _plan_sage_image(env, sage_version, root)
    except BackendUnavailable as ex:
        tried.append(("sage-image", ex))
    needs = sorted({t for _, r in tried for t in r.needs_tool})
    raise BackendUnavailable("no backend can run this job: " + "; ".join(f"{n}: {r.reason}" for n, r in tried),
                             needs, "; or ".join(r.fix for _, r in tried if r.fix))


def backend_status(*, environ: Mapping[str, str] | None = None, root: Path | None = None) -> dict:
    """What each backend can do here, with the missing piece and its fix named. Reads only
    (`docker image inspect`); nothing is started."""
    env = dict(os.environ if environ is None else environ)
    fpylll, sympy = _has_module("fpylll"), _has_module("sympy")
    out: dict[str, Any] = {"schema": SCHEMA, "python": {
        "available": True, "lll": True, "bkz": fpylll, "ideals": sympy, "rings": ["QQ", "GF"],
        "needs_tool": ([] if fpylll else ["py:fpylll"]) + ([] if sympy else ["py:sympy"])}}
    exe = shutil.which("sage", path=env.get("PATH"))
    out["sage-local"] = {"available": exe is not None, "path": exe,
                         "needs_tool": [] if exe else ["sage"]}
    entry: dict[str, Any] = {"available": False, "images": [], "default": None, "needs_tool": []}
    try:
        from ctf.toolchain import images
        known = sage_images(root)
        report = images.status(known, root=root, environ=env) if known else []
        for im, st in zip(known, report):
            entry["images"].append({"tag": im.tag, "sage": im.version_of("sage"), "state": st.state,
                                    "detail": st.detail, "fix": st.fix, "default": "sage" in im.default_for})
            if "sage" in im.default_for:
                entry["default"] = im.tag
            if not st.ok:
                entry["needs_tool"].append(f"image:{im.tag}")
        entry["available"] = any(i["state"] == "ok" for i in entry["images"])
        if not known:
            entry["reason"] = "tools/images.toml lists no Sage image"
    except Exception as ex:                                  # ImagesError, a refused docker, a bad manifest
        entry["reason"] = f"{type(ex).__name__}: {ex}"
        entry["needs_tool"] = ["image:ctf-sage"]
    out["sage-image"] = entry
    return out


# ----------------------------------------------------------------------------------- running a job

@dataclass(frozen=True)
class ServiceResult:
    op: str
    status: str                              # ok | blocked | error | timeout
    backend: str = ""
    detail: str = ""                         # the engine that answered, or the image tag / binary
    proof: str = "none"                      # exact | partial | none
    checks: tuple[str, ...] = ()
    result: Mapping[str, Any] | None = None
    seconds: float = 0.0
    reason: str = ""
    needs_tool: tuple[str, ...] = ()
    fix: str = ""

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"status {self.status!r} is not one of {STATUSES}")

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def require(self) -> Mapping[str, Any]:
        """The result of an ok run; BackendUnavailable when blocked, ServiceError otherwise."""
        if self.status == "blocked":
            raise BackendUnavailable(self.reason, self.needs_tool, self.fix)
        if not self.ok or self.result is None:
            raise ServiceError(f"{self.op} on {self.backend or 'no backend'}: {self.status}: {self.reason}")
        return self.result

    def to_dict(self) -> dict:
        return {"schema": SCHEMA, "op": self.op, "status": self.status, "backend": self.backend,
                "detail": self.detail, "proof": self.proof, "checks": list(self.checks),
                "result": self.result, "seconds": round(self.seconds, 3), "reason": self.reason,
                "needs_tool": list(self.needs_tool), "fix": self.fix}


def _tail(text: str, limit: int = 400) -> str:
    text = (text or "").strip()
    return text[-limit:]


def _spawn(argv: Sequence[str], env: Mapping[str, str], limit: float,
           on_timeout: Callable[[], str] | None = None) -> tuple[str, dict | None, str]:
    """Run a worker; (state, parsed sentinel object, message). state: ran | timeout | failed. The
    worker gets its own process group, and at the limit the whole group is killed, so a wrapper script
    cannot leave its interpreter running. `on_timeout` then stops what lives outside that group (the
    sage-image container) and returns a note for the message."""
    try:
        proc = subprocess.Popen(list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=dict(env), stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError as ex:
        return "failed", None, f"could not start {argv[0]}: {ex}"
    try:
        stdout, stderr = proc.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.wait()
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()
        note = on_timeout() if on_timeout is not None else ""
        return "timeout", None, f"no answer within {limit:.0f} s{note}"
    p = subprocess.CompletedProcess(list(argv), proc.returncode, stdout, stderr)
    for line in reversed((p.stdout or "").splitlines()):
        if line.startswith(SENTINEL):
            try:
                obj = json.loads(line[len(SENTINEL):])
            except ValueError as ex:
                return "failed", None, f"unreadable worker result: {ex}"
            if isinstance(obj, dict):
                return "ran", obj, ""
            return "failed", None, "the worker result is not an object"
    if p.returncode == 124:
        return "timeout", None, "the worker was stopped at its time limit"
    return "failed", None, (f"the worker exited {p.returncode} without a result: "
                            f"{_tail(p.stderr) or _tail(p.stdout) or 'no output'}")


def _run_plan(plan: _Plan, job: Job, timeout: int, env: Mapping[str, str]) -> tuple[str, dict | None, str]:
    wire = dict(job.wire, timeout=timeout)
    with tempfile.TemporaryDirectory(prefix="ctf-algebra-") as tmp:
        work = Path(tmp)
        (work / "job.json").write_text(json.dumps(wire), encoding="utf-8")
        if plan.backend == "python":
            argv = [sys.executable, "-I", str(Path(__file__).resolve()), "__worker__", str(work / "job.json")]
            return _spawn(argv, env, timeout + PYTHON_GRACE)
        shutil.copyfile(Path(__file__).resolve().with_name(WORKER_NAME), work / "worker.py")
        if plan.backend == "sage-local":
            return _spawn([plan.sage, "-python", str(work / "worker.py"), str(work / "job.json")], env,
                          timeout + SAGE_LOCAL_GRACE)
        from ctf.toolchain import images
        docker = images.docker_path(env)
        if docker is None:
            return "failed", None, "docker is not on PATH"
        os.chmod(work, 0o755)
        inner = ["timeout", "-k", "10", str(timeout), "sage", "-python", "/work/worker.py", "/work/job.json"]
        base = images.run_argv(plan.image, inner, workdir=work)
        if base[1] != "run":
            raise ServiceError(f"images.run_argv no longer starts with `docker run`: {base[:2]}")
        # A name of this job's own: killing the docker CLI does not stop its container, so on the outer
        # timeout exactly this container (and nothing else) is killed by name.
        name = f"{CONTAINER_PREFIX}{uuid.uuid4().hex}"
        argv = [docker, "run", "--name", name, *base[2:]]
        return _spawn(argv, env, timeout + IMAGE_START_GRACE, lambda: _kill_container(docker, name, env))


def _kill_container(docker: str, name: str, env: Mapping[str, str]) -> str:
    """`docker kill <name>` for the container this job started; the note says how that went."""
    try:
        p = subprocess.run([docker, "kill", name], capture_output=True, text=True, env=dict(env),
                           stdin=subprocess.DEVNULL, timeout=DOCKER_KILL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as ex:
        return f"; `docker kill {name}` failed: {ex}"
    if p.returncode == 0:
        return f"; container {name} killed"
    err = _tail(p.stderr) or _tail(p.stdout) or "no output"
    if "No such container" in err:
        return f"; container {name} had already ended"
    return f"; `docker kill {name}` exited {p.returncode}: {err}"


def _show_points(job: Job, raw, width: int) -> list[tuple]:
    if not isinstance(raw, list):
        raise ServiceError("the backend returned no point list")
    points = []
    for pt in raw:
        if not isinstance(pt, list) or len(pt) != width:
            raise ServiceError("the backend returned a malformed point")
        try:
            points.append(tuple(job.ring.decode(c, "point") for c in pt))
        except JobError as ex:
            raise ServiceError(f"the backend returned a malformed point: {ex}") from None
    return sorted(set(points))


def _check(job: Job, data: Mapping[str, Any]) -> tuple[str, list[str], dict]:
    """Check a backend's raw data against the job: (proof, checks, result). ServiceError when a value
    fails its check or the data is malformed."""
    if not isinstance(data, Mapping):
        raise ServiceError("the backend returned no data object")
    op, ring, names = job.op, job.ring, job.names
    if op in LATTICE_OPS:
        before = [list(r) for r in job.basis]
        if not same_lattice(before, data.get("basis"), data.get("u"), data.get("v")):
            raise ServiceError("the reduced basis failed the lattice check: U·B = R and V·R = B do not both "
                               "hold over the integers")
        return "exact", ["same lattice: U·B = R and V·R = B over the integers"], {
            "basis": data["basis"], "transform": data["u"]}
    if op == "small_roots":
        raw = data.get("roots")
        if not isinstance(raw, list) or any(isinstance(r, bool) or not isinstance(r, int) for r in raw):
            raise ServiceError("the backend returned no integer root list")
        n, bound, f = job.wire["modulus"], job.wire["bound"], job.polys[0]
        exact = job.wire["beta"] >= 1.0
        found = []
        for r in sorted({(x % n) - n if (x % n) > n // 2 else x % n for x in raw}):
            g = math.gcd(int(poly_eval(ring, f, (r % n,))), n)
            if abs(r) > bound or (g != n if exact else g <= 1):
                raise ServiceError(f"the backend returned {r}, which is not a root within the bound")
            found.append({"root": r, "divisor": g})
        what = "f(root) = 0 mod N" if exact else "gcd(f(root), N) > 1"
        return "exact", [f"every root substituted: |root| <= bound and {what}"], {"roots": found}
    n = len(names)
    if op == "groebner":
        basis = [g for g in (_unwire(ring, t, n, "basis") for t in _list(data.get("basis"))) if g]
        return "none", [], {"basis": [poly_text(ring, g, names) for g in basis],
                            "basis_terms": [_wire(ring, g) for g in basis], "order": job.wire["order"]}
    if op == "variety":
        points = _show_points(job, data.get("points"), n)
        for pt in points:
            if any(poly_eval(ring, f, pt) != 0 for f in job.polys):
                raise ServiceError("the backend returned a point that is not a common root of the input")
        return "exact", ["every point substituted into every input polynomial"], {
            "points": [{name: ring.show(c) for name, c in zip(names, pt)} for pt in points],
            "complete": "claimed by the backend"}
    if op == "roots":
        points = _show_points(job, [[r] for r in _list(data.get("roots"))], 1)
        for pt in points:
            if poly_eval(ring, job.polys[0], pt) != 0:
                raise ServiceError("the backend returned a value that is not a root of the input")
        return "exact", ["every root substituted into the input polynomial"], {
            "roots": [ring.show(pt[0]) for pt in points], "complete": "claimed by the backend"}
    gone = job.wire["eliminate"] if op == "eliminate" else [job.wire["var"]]
    # A zero generator (Sage lists one for the zero ideal) says nothing: it is dropped.
    polys = ([g for g in (_unwire(ring, t, n, "basis") for t in _list(data.get("basis"))) if g]
             if op == "eliminate" else [_unwire(ring, data.get("poly"), n, "poly")])
    if any(e[i] for g in polys for e in g for i in gone):
        raise ServiceError("the backend returned a polynomial that still holds an eliminated variable")
    checks = ["the eliminated variables are absent"]
    if op == "eliminate":
        return "partial", checks, {"basis": [poly_text(ring, g, names) for g in polys],
                                   "basis_terms": [_wire(ring, g) for g in polys]}
    return "partial", checks, {"poly": poly_text(ring, polys[0], names), "poly_terms": _wire(ring, polys[0])}


def _list(value) -> list:
    if not isinstance(value, list):
        raise ServiceError("the backend returned no list where one is required")
    return value


def execute(job: Mapping, *, backend: str = "auto", sage_version: str | None = None,
            timeout: int = DEFAULT_TIMEOUT, environ: Mapping[str, str] | None = None,
            root: Path | None = None) -> ServiceResult:
    """Run one job. A malformed job is JobError; everything else comes back as a ServiceResult whose
    status says what happened (ok, blocked, error, timeout)."""
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT:
        raise JobError(f"timeout must be an integer number of seconds in 1..{MAX_TIMEOUT}")
    with _bigints():
        parsed = parse_job(job)
        env = dict(os.environ if environ is None else environ)
        try:
            plan = plan_backend(parsed, backend, sage_version=sage_version, environ=env, root=root)
        except BackendUnavailable as ex:
            return ServiceResult(parsed.op, "blocked", backend if backend not in ("auto", "sage") else "",
                                 reason=ex.reason, needs_tool=ex.needs_tool, fix=ex.fix)
        started = time.monotonic()
        state, obj, message = _run_plan(plan, parsed, timeout, env)
        seconds = time.monotonic() - started

        def done(status, **kw):
            return ServiceResult(parsed.op, status, plan.backend, kw.pop("detail", plan.detail),
                                 seconds=seconds, **kw)

        if state == "timeout":
            return done("timeout", reason=message)
        if state != "ran":
            return done("error", reason=message)
        status = obj.get("status")
        engine = str(obj.get("engine") or plan.detail)[:200]
        if status == "timeout":
            return done("timeout", reason=str(obj.get("error") or "the worker ran out of time")[:2000])
        if status == "blocked":
            needs = obj.get("needs_tool")
            return done("blocked", reason=str(obj.get("error") or "")[:2000],
                        needs_tool=tuple(str(x) for x in needs) if isinstance(needs, list) else ())
        if status != "ok":
            return done("error", reason=str(obj.get("error") or "the worker reported no status")[:2000])
        if plan.backend != "python":
            got = str(obj.get("sage_version") or "")
            if not got:
                return done("error", reason="the Sage worker did not report its release")
            if plan.want_version is not None and not _version_matches(got, plan.want_version):
                return done("blocked", reason=f"Sage {plan.want_version} was asked for but {plan.detail} is "
                                              f"Sage {got}", needs_tool=("sage",),
                            fix="pass the release you have, or use --backend sage-image")
            engine = f"SageMath {got} ({plan.detail})"
            if obj.get("soft_timeout") is False:
                engine += "; no cysignals alarm in this Sage: only the outside kill enforces the timeout"
        try:
            proof, checks, result = _check(parsed, obj.get("data"))
        except ServiceError as ex:
            return done("error", detail=engine, reason=str(ex))
        return done("ok", detail=engine, proof=proof, checks=tuple(checks), result=result)


def reduce_basis(basis, *, method: str = "lll", block_size: int = 20, tours: int | None = None,
                 backend: str = "auto", sage_version: str | None = None, timeout: int = DEFAULT_TIMEOUT,
                 environ: Mapping[str, str] | None = None, root: Path | None = None) -> list[list[int]]:
    """The reduced basis of the same lattice (proof exact), or it raises: BackendUnavailable when the
    backend for `method` is missing (BKZ is never downgraded to LLL), ServiceError otherwise."""
    if method not in LATTICE_OPS:
        raise JobError(f"method must be one of {LATTICE_OPS}")
    job: dict[str, Any] = {"op": method, "basis": [list(r) for r in basis]}
    if method == "bkz":
        job["block_size"] = block_size
        if tours is not None:
            job["tours"] = tours
    res = execute(job, backend=backend, sage_version=sage_version, timeout=timeout, environ=environ, root=root)
    return [list(r) for r in res.require()["basis"]]


# ---------------------------------------------------------------------------------------- selftest

_SELFTEST_P = (1 << 127) - 1
_SELFTEST_N = 18446744073709551629 * 18446744073709551653        # two primes just above 2^64


def _selftest_cases() -> list[tuple[str, dict, Any]]:
    """(name, job, check(result) -> bool): known-answer jobs, one or more per operation."""
    short = [[2, 0, 0], [0, 3, 0], [0, 0, 5]]
    mix = [[1, 0, 0], [977, 1, 0], [-613, 359, 1]]
    basis = _matmul(mix, short)

    def norms(res):
        return sorted(sum(x * x for x in row) for row in res["basis"]) == [4, 9, 25]

    a, b = 0x1234567890abcdef, 0xfedcba9876543
    p = _SELFTEST_P
    x0, m0 = 0xbeef, 0xc0ffee << 64
    c = pow(m0 + x0, 3, _SELFTEST_N)
    return [
        ("lll", {"op": "lll", "basis": basis}, norms),
        ("bkz", {"op": "bkz", "basis": basis, "block_size": 3}, norms),
        ("groebner", {"op": "groebner", "ring": "GF(101)", "vars": ["x", "y"], "polys": ["x*y - 1", "x - y"]},
         lambda r: sorted(r["basis"]) == ["x + 100*y", "y^2 + 100"]),
        ("variety", {"op": "variety", "ring": f"GF({p})", "vars": ["x", "y"],
                     "polys": [f"x + y - {a + b}", f"x*y - {a * b}"]},
         lambda r: sorted((pt["x"], pt["y"]) for pt in r["points"]) == sorted([(a, b), (b, a)])),
        ("eliminate", {"op": "eliminate", "ring": "QQ", "vars": ["x", "y"],
                       "polys": ["x^2 + y^2 - 5", "x - y - 1"], "eliminate": ["x"]},
         lambda r: [_monic_text(t) for t in r["basis_terms"]] == ["y^2 + y - 2"]),
        ("resultant", {"op": "resultant", "ring": "QQ", "vars": ["x", "y"],
                       "polys": ["x^2 + y^2 - 5", "x - y - 1"], "var": "x"},
         lambda r: r["poly"] == "2*y^2 + 2*y - 4"),
        ("roots", {"op": "roots", "ring": f"GF({p})", "vars": ["x"], "polys": ["x^3 - 7*x + 6"]},
         lambda r: r["roots"] == [1, 2, p - 3]),
        ("small_roots", {"op": "small_roots", "modulus": _SELFTEST_N, "poly": f"(x + {m0})^3 - {c}",
                         "bound": 1 << 20},
         lambda r: [x["root"] for x in r["roots"]] == [x0]),
    ]


def _monic_text(terms) -> str:
    ring = Ring("QQ")
    f = _poly_from_terms(terms, 2, ring, "poly")
    lead = f[max(f)]
    return poly_text(ring, {e: c / lead for e, c in f.items()}, ("x", "y"))


def selftest(*, backend: str = "auto", sage_version: str | None = None, timeout: int = DEFAULT_TIMEOUT,
             environ: Mapping[str, str] | None = None, root: Path | None = None) -> dict:
    """Run a known-answer job per operation on one backend. `passed` only when every job came back ok
    with the expected answer; a blocked job is `blocked`, never a pass."""
    rows = []
    for name, job, check in _selftest_cases():
        res = execute(job, backend=backend, sage_version=sage_version, timeout=timeout, environ=environ,
                      root=root)
        if res.status == "blocked":
            verdict, why = "blocked", res.reason
        elif not res.ok:
            verdict, why = "failed", f"{res.status}: {res.reason}"
        elif not check(res.result):
            verdict, why = "failed", "the answer differs from the known one"
        else:
            verdict, why = "passed", ""
        rows.append({"case": name, "verdict": verdict, "backend": res.backend, "detail": res.detail,
                     "reason": why, "needs_tool": list(res.needs_tool), "seconds": round(res.seconds, 3)})
    count = {v: sum(1 for r in rows if r["verdict"] == v) for v in ("passed", "failed", "blocked")}
    status = "failed" if count["failed"] else ("blocked" if count["blocked"] else "passed")
    return {"schema": SCHEMA, "status": status, "counts": count, "cases": rows}


# --------------------------------------------------------------------------------------------- CLI

class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise JobError(message)


def load_job(path_value: str) -> dict:
    path = Path(path_value)
    if not path.is_file():
        raise JobError(f"job file not found: {path}")
    if path.stat().st_size > MAX_JSON:
        raise JobError(f"job file is over the {MAX_JSON}-byte cap")
    try:
        with _bigints():
            value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, ValueError) as ex:
        raise JobError(f"job file is not JSON: {ex}") from None
    except RecursionError:
        raise JobError("job file nests JSON arrays or objects too deeply to read") from None
    if not isinstance(value, dict):
        raise JobError("a job is a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["__worker__"] and len(argv) == 2:
        return _worker_main(argv[1])
    parser = _Parser(prog="algebra_service.py", description="lattice and polynomial-ideal jobs on a named backend")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("status")
    for name in ("run", "selftest"):
        sp = sub.add_parser(name)
        if name == "run":
            sp.add_argument("job")
        sp.add_argument("--backend", default="auto", choices=BACKENDS)
        sp.add_argument("--sage-version")
        sp.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    try:
        args = parser.parse_args(argv)
        if args.command is None:
            raise JobError("a command is required: status, run or selftest")
        with _bigints():
            if args.command == "status":
                print(json.dumps(backend_status(), indent=2, sort_keys=True))
                return 0
            if args.command == "selftest":
                rep = selftest(backend=args.backend, sage_version=args.sage_version, timeout=args.timeout)
                print(json.dumps(rep, indent=2, sort_keys=True))
                return {"passed": 0, "failed": 1, "blocked": 3}[rep["status"]]
            res = execute(load_job(args.job), backend=args.backend, sage_version=args.sage_version,
                          timeout=args.timeout)
            print(json.dumps(res.to_dict(), sort_keys=True))
            return {"ok": 0, "blocked": 3}.get(res.status, 1)
    except JobError as ex:
        print(f"algebra_service: {ex}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
