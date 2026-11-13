#!/usr/bin/env python3
"""Template lattice constructions for the common cases (B-157): build the basis, reduce it on a named
backend, read the answers back and check each one exactly.

    import lattice_templates as lt
    t = lt.hidden_number(q, samples, bound)        # Template(name, basis, extract, notes)
    lt.solve(t)                                    # LLL on the auto backend -> checked solutions
    lt.solve(t, method="bkz", block_size=20, backend="sage-image")   # the same lattice, a stronger reduction

Choosing the lattice for a new challenge is the solver's reasoning; these are the starting points:

    bounded_linear(matrix, rhs, moduli, bounds)    x with lo <= x_j <= hi and A·x = b (mod m_r, or over
                                                   the integers where m_r is None): the general form
    short_kernel(matrix, moduli, widths)           a non-zero x with |x_j| <= w_j and A·x = 0 (mod m_r)
    hidden_number(modulus, samples, bound)         x with (a_i + t_i·x) mod q < bound for every sample
    truncated_lcg(multiplier, increment, modulus, highs, unknown_bits)   the first full state
    subset_sum(values, target)                     0/1 choices with the exact sum (CJLOSS embedding)
    modular_ratio(h, modulus, f_bound, g_bound)    small f, g with f·h = g (mod q): NTRU-style keys
    integer_relation(values, bound)                small c with sum c_i·v_i = 0

Every builder returns a `Template`: `basis` is the integer row basis, `extract(reduced_rows)` returns
only values that pass the template's own exact check (the bounds and every equation, the regenerated
LCG outputs, the exact sum). An empty list means this reduction did not expose a solution: raise the
method (`bkz`), the block size, or rethink the lattice. `solve` reduces through
`algebra_service.reduce_basis`, so the backend is named, a missing one is BackendUnavailable with its
`needs_tool`, and BKZ is never swapped for LLL.

CLI (JSON on stdout; exit 0 ran, 1 error, 2 bad job, 3 blocked):

    lattice_templates.py list
    lattice_templates.py basis JOB.json            # {"template": "hidden_number", "args": {...}}
    lattice_templates.py solve JOB.json [--method lll|bkz] [--block-size N] [--backend B]
                                        [--sage-version V] [--timeout S]
"""
from __future__ import annotations

import argparse
import inspect
import json
import math
import sys
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

import algebra_service as alg
from algebra_service import BackendUnavailable, JobError, ServiceError

MAX_UNKNOWNS = 512
MAX_EQUATIONS = 512


@dataclass(frozen=True)
class Template:
    name: str
    basis: tuple[tuple[int, ...], ...]
    extract: Callable[[Sequence[Sequence[int]]], list]
    notes: str = ""

    @property
    def dimension(self) -> int:
        return len(self.basis)


def _i(value, name: str) -> int:
    return alg.parse_int(value, name)


def _freeze(rows) -> tuple[tuple[int, ...], ...]:
    return tuple(tuple(r) for r in rows)


def _system(matrix, moduli) -> tuple[list[list[int]], list[int | None]]:
    if not isinstance(matrix, (list, tuple)) or not 1 <= len(matrix) <= MAX_EQUATIONS:
        raise JobError(f"matrix must hold 1..{MAX_EQUATIONS} equation rows")
    width = len(matrix[0]) if isinstance(matrix[0], (list, tuple)) else 0
    if not 1 <= width <= MAX_UNKNOWNS:
        raise JobError(f"an equation must hold 1..{MAX_UNKNOWNS} coefficients")
    rows = []
    for r, row in enumerate(matrix):
        if not isinstance(row, (list, tuple)) or len(row) != width:
            raise JobError(f"matrix row {r} does not have {width} coefficients")
        rows.append([_i(x, f"matrix[{r}]") for x in row])
    if moduli is None or isinstance(moduli, (int, str)):
        moduli = [moduli] * len(rows)
    if not isinstance(moduli, (list, tuple)) or len(moduli) != len(rows):
        raise JobError("moduli must be one modulus, null, or one entry per equation")
    mods: list[int | None] = []
    for r, m in enumerate(moduli):
        if m is None:
            mods.append(None)
            continue
        value = _i(m, f"moduli[{r}]")
        if value < 2:
            raise JobError("a modulus must be at least 2 (use null for an equation over the integers)")
        mods.append(value)
    return rows, mods


def _residue(value: int, modulus: int | None) -> int:
    return value if modulus is None else value % modulus


def _weights(widths: Sequence[int]) -> tuple[int, list[int]]:
    """The common size every scaled coordinate stays under, and the per-unknown scale."""
    top = max(max(widths), 1)
    return top, [top // max(w, 1) for w in widths]


def bounded_linear(matrix, rhs, moduli, bounds) -> Template:
    """x with bounds[j][0] <= x_j <= bounds[j][1] and, per row r, sum_j matrix[r][j]·x_j = rhs[r]
    (mod moduli[r]; over the integers where it is None). `moduli` is one modulus for all rows, null,
    or a list.

    Lattice (Kannan embedding, rows): the unknowns are recentred to y_j = x_j - centre_j, each scaled
    so every |y_j|·scale_j stays under one size W; a block of columns weighted K carries the equations
    (so a short vector has them exactly zero); the last row holds the right-hand side and W. The short
    vector (y_1·s_1, ..., y_n·s_n, 0, ..., 0, ±W) is the solution."""
    a, mods = _system(matrix, moduli)
    k, n = len(a), len(a[0])
    if not isinstance(rhs, (list, tuple)) or len(rhs) != k:
        raise JobError("rhs must hold one value per equation")
    b = [_i(x, f"rhs[{r}]") for r, x in enumerate(rhs)]
    if not isinstance(bounds, (list, tuple)) or len(bounds) != n:
        raise JobError("bounds must hold one [low, high] pair per unknown")
    lows, highs = [], []
    for j, pair in enumerate(bounds):
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise JobError(f"bounds[{j}] must be [low, high]")
        lo, hi = _i(pair[0], f"bounds[{j}]"), _i(pair[1], f"bounds[{j}]")
        if lo > hi:
            raise JobError(f"bounds[{j}]: low is above high")
        lows.append(lo)
        highs.append(hi)
    centres = [(lo + hi) // 2 for lo, hi in zip(lows, highs)]
    top, scale = _weights([max(hi - c, c - lo) for lo, hi, c in zip(lows, highs, centres)])
    shifted = [_residue(b[r] - sum(a[r][j] * centres[j] for j in range(n)), mods[r]) for r in range(k)]
    dim = n + sum(1 for m in mods if m is not None) + 1
    heavy = top * (n + 1) << (dim // 2 + 1)
    rows = []
    for j in range(n):
        row = [0] * (n + k + 1)
        row[j] = scale[j]
        for r in range(k):
            row[n + r] = heavy * a[r][j]
        rows.append(row)
    for r, m in enumerate(mods):
        if m is not None:
            row = [0] * (n + k + 1)
            row[n + r] = heavy * m
            rows.append(row)
    last = [0] * (n + k + 1)
    for r in range(k):
        last[n + r] = -heavy * shifted[r]
    last[-1] = top
    rows.append(last)

    def holds(x: Sequence[int]) -> bool:
        if any(not lo <= v <= hi for v, lo, hi in zip(x, lows, highs)):
            return False
        return all(_residue(sum(c * v for c, v in zip(a[r], x)) - b[r], mods[r]) == 0 for r in range(k))

    def extract(reduced) -> list:
        found: list[tuple[int, ...]] = []
        candidates = [tuple(centres)]
        for row in reduced:
            if len(row) != n + k + 1 or any(row[n:n + k]) or abs(row[-1]) != top:
                continue
            sign = 1 if row[-1] == top else -1               # a lattice row's column j is a multiple of scale[j]
            candidates.append(tuple(centres[j] + sign * row[j] // scale[j] for j in range(n)))
        for x in candidates:
            if x not in found and holds(x):
                found.append(x)
        return [list(x) for x in found]

    return Template("bounded_linear", _freeze(rows), extract,
                    f"{n} unknowns, {k} equations, dimension {len(rows)}")


def short_kernel(matrix, moduli, widths) -> Template:
    """Non-zero x with |x_j| <= widths[j] and sum_j matrix[r][j]·x_j = 0 (mod moduli[r]; over the
    integers where it is None). The homogeneous form of `bounded_linear`: the same scaled unknowns and
    weighted equation columns, no right-hand-side row. Each solution is returned once, with its first
    non-zero entry positive."""
    a, mods = _system(matrix, moduli)
    k, n = len(a), len(a[0])
    if not isinstance(widths, (list, tuple)) or len(widths) != n:
        raise JobError("widths must hold one positive bound per unknown")
    w = [_i(x, f"widths[{j}]") for j, x in enumerate(widths)]
    if any(x < 1 for x in w):
        raise JobError("widths must be positive")
    top, scale = _weights(w)
    dim = n + sum(1 for m in mods if m is not None)
    heavy = top * (n + 1) << (dim // 2 + 1)
    rows = []
    for j in range(n):
        row = [0] * (n + k)
        row[j] = scale[j]
        for r in range(k):
            row[n + r] = heavy * a[r][j]
        rows.append(row)
    for r, m in enumerate(mods):
        if m is not None:
            row = [0] * (n + k)
            row[n + r] = heavy * m
            rows.append(row)

    def extract(reduced) -> list:
        found: list[tuple[int, ...]] = []
        for row in reduced:
            if len(row) != n + k or any(row[n:]):
                continue
            x = [row[j] // scale[j] for j in range(n)]
            lead = next((v for v in x if v), 0)
            if lead == 0 or any(abs(v) > bound for v, bound in zip(x, w)):
                continue
            if lead < 0:
                x = [-v for v in x]
            if any(_residue(sum(c * v for c, v in zip(a[r], x)), mods[r]) != 0 for r in range(k)):
                continue
            if tuple(x) not in found:
                found.append(tuple(x))
        return [list(x) for x in found]

    return Template("short_kernel", _freeze(rows), extract,
                    f"{n} unknowns, {k} equations, dimension {len(rows)}")


def _hnp_samples(modulus, samples, bound, secret_bound):
    q = _i(modulus, "modulus")
    if q < 2:
        raise JobError("modulus must be at least 2")
    if not isinstance(samples, (list, tuple)) or not 1 <= len(samples) <= MAX_EQUATIONS:
        raise JobError(f"samples must hold 1..{MAX_EQUATIONS} [t, a] pairs")
    pairs = []
    for i, pair in enumerate(samples):
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise JobError(f"samples[{i}] must be [t, a]")
        pairs.append((_i(pair[0], f"samples[{i}]") % q, _i(pair[1], f"samples[{i}]") % q))
    limit = _i(bound, "bound")
    if not 1 <= limit <= q:
        raise JobError("bound must be in 1..modulus")
    secret = q if secret_bound is None else _i(secret_bound, "secret_bound")
    if not 1 <= secret <= q:
        raise JobError("secret_bound must be in 1..modulus")
    return q, pairs, limit, secret


def _hnp_basis(q: int, pairs, limit: int, secret: int):
    """The (m + 2)-row hidden-number lattice, recentred: rows q·e_i, then (t_1..t_m | 1 | 0), then
    (a'_1..a'_m | 0 | 1), with the k columns scaled by the secret's half-width and the secret column
    by the k half-width, so every coordinate of the target stays under their product."""
    m = len(pairs)
    cx, ck = secret // 2, limit // 2
    wx, wk = max(secret - cx, 1), max(limit - ck, 1)
    top = wx * wk
    rows = []
    for i in range(m):
        row = [0] * (m + 2)
        row[i] = wx * q
        rows.append(row)
    rows.append([wx * t for t, _ in pairs] + [wk, 0])
    rows.append([wx * ((a + t * cx - ck) % q) for t, a in pairs] + [0, top])

    def secrets(reduced) -> list[int]:
        out = []
        for row in reduced:
            if len(row) != m + 2 or abs(row[-1]) != top:
                continue
            sign = 1 if row[-1] == top else -1
            x = cx + sign * row[m] // wk
            if 0 <= x < secret and x not in out and all((a + t * x) % q < limit for t, a in pairs):
                out.append(x)
        return out

    return rows, secrets


def hidden_number(modulus, samples, bound, secret_bound=None) -> Template:
    """x in [0, secret_bound) (default: the modulus) with (a_i + t_i·x) mod modulus < bound for every
    sample [t_i, a_i]: biased or truncated nonces, leaked top bits, any "k = a + t·x is small" leak.
    Returns each x that satisfies every inequality; the caller checks it against the public key."""
    q, pairs, limit, secret = _hnp_samples(modulus, samples, bound, secret_bound)
    rows, secrets = _hnp_basis(q, pairs, limit, secret)
    return Template("hidden_number", _freeze(rows), secrets,
                    f"{len(pairs)} samples, dimension {len(rows)}")


def truncated_lcg(multiplier, increment, modulus, highs, unknown_bits) -> Template:
    """The first state s_0 of s_{i+1} = multiplier·s_i + increment (mod modulus), from the outputs
    highs[i] = s_i >> unknown_bits. Each s_i is affine in the unknown low bits of s_0, so this is the
    hidden-number lattice with the secret bounded by 2^unknown_bits. A state is returned only when
    regenerating the sequence from it reproduces every output."""
    a, c, m = _i(multiplier, "multiplier"), _i(increment, "increment"), _i(modulus, "modulus")
    u = _i(unknown_bits, "unknown_bits")
    if m < 2 or not 1 <= u < m.bit_length() + 1:
        raise JobError("modulus must be at least 2 and unknown_bits in 1..its bit length")
    if not isinstance(highs, (list, tuple)) or not 2 <= len(highs) <= MAX_EQUATIONS:
        raise JobError(f"highs must hold 2..{MAX_EQUATIONS} outputs")
    hs = [_i(h, f"highs[{i}]") for i, h in enumerate(highs)]
    if any(h < 0 for h in hs):
        raise JobError("highs must be non-negative")
    step = 1 << u
    pairs, coeff, const = [], 1, 0
    for h in hs[1:]:
        coeff, const = a * coeff % m, (a * const + c) % m
        pairs.append((coeff, (coeff * hs[0] * step + const - h * step) % m))
    rows, secrets = _hnp_basis(m, pairs, min(step, m), min(step, m))

    def extract(reduced) -> list:
        out = []
        for low in secrets(reduced):
            state = seed = hs[0] * step + low
            if seed >= m:
                continue
            good = True
            for h in hs[1:]:
                state = (a * state + c) % m
                if state >> u != h:
                    good = False
                    break
            if good:
                out.append(seed)
        return out

    return Template("truncated_lcg", _freeze(rows), extract, f"{len(hs)} outputs, dimension {len(rows)}")


def subset_sum(values, target) -> Template:
    """0/1 choices x with sum x_i·values[i] == target (the CJLOSS low-density embedding): rows
    (2·e_i | N·v_i) and (1, ..., 1 | N·target). A reduced row (±1, ..., ±1 | 0) is a solution."""
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= MAX_UNKNOWNS:
        raise JobError(f"values must hold 1..{MAX_UNKNOWNS} integers")
    vs = [_i(v, f"values[{i}]") for i, v in enumerate(values)]
    goal = _i(target, "target")
    n = len(vs)
    weight = max(2, math.isqrt(n) + 1)
    rows = []
    for i, v in enumerate(vs):
        row = [0] * (n + 1)
        row[i] = 2
        row[-1] = weight * v
        rows.append(row)
    rows.append([1] * n + [weight * goal])

    def extract(reduced) -> list:
        found = []
        for row in reduced:
            if len(row) != n + 1 or row[-1] != 0 or any(abs(x) != 1 for x in row[:-1]):
                continue
            for sign in (1, -1):
                bits = [(1 - sign * x) // 2 for x in row[:-1]]
                if sum(v * bit for v, bit in zip(vs, bits)) == goal and bits not in found:
                    found.append(bits)
        return found

    return Template("subset_sum", _freeze(rows), extract, f"{n} items, dimension {len(rows)}")


def modular_ratio(h, modulus, f_bound, g_bound) -> Template:
    """Small f, g with f·h = g (mod modulus), |f| <= f_bound, |g| <= g_bound and f > 0: the two-row
    lattice behind NTRU-style keys h = g/f and rational reconstruction. Returns [f, g] pairs."""
    t = short_kernel([[_i(h, "h"), -1]], [_i(modulus, "modulus")], [f_bound, g_bound])
    return Template("modular_ratio", t.basis, t.extract, t.notes)


def integer_relation(values, bound) -> Template:
    """Small integers c, |c_i| <= bound, not all zero, with sum c_i·values[i] == 0: integer relations
    between scaled constants, minimal polynomials of a scaled root's powers."""
    if not isinstance(values, (list, tuple)) or len(values) < 2:
        raise JobError("values must hold at least two integers")
    t = short_kernel([list(values)], None, [bound] * len(values))
    return Template("integer_relation", t.basis, t.extract, t.notes)


TEMPLATES: dict[str, Callable[..., Template]] = {
    "bounded_linear": bounded_linear, "short_kernel": short_kernel, "hidden_number": hidden_number,
    "truncated_lcg": truncated_lcg, "subset_sum": subset_sum, "modular_ratio": modular_ratio,
    "integer_relation": integer_relation,
}


def build(name: str, args: Mapping[str, Any]) -> Template:
    """The named template from keyword arguments (the CLI's job form). JobError on a bad name or args."""
    if name not in TEMPLATES:
        raise JobError(f"template must be one of {sorted(TEMPLATES)}")
    if not isinstance(args, Mapping):
        raise JobError("args must be an object")
    fn = TEMPLATES[name]
    params = inspect.signature(fn).parameters
    unknown = sorted(set(args) - set(params))
    missing = sorted(p for p, spec in params.items() if spec.default is inspect.Parameter.empty and p not in args)
    if unknown or missing:
        raise JobError(f"{name} takes {list(params)}: unknown {unknown}, missing {missing}")
    return fn(**args)


def solve_detailed(template: Template, *, method: str = "lll", block_size: int = 20, tours: int | None = None,
                   backend: str = "auto", sage_version: str | None = None,
                   timeout: int = alg.DEFAULT_TIMEOUT, environ: Mapping[str, str] | None = None,
                   root=None) -> tuple[list, alg.ServiceResult]:
    """Reduce the template's basis and extract: (checked solutions, the reduction's ServiceResult).
    The solutions are empty when the reduction did not run (see the result's status). A block size
    above the dimension is taken as the dimension."""
    if method not in alg.LATTICE_OPS:
        raise JobError(f"method must be one of {alg.LATTICE_OPS}")
    job: dict[str, Any] = {"op": method, "basis": [list(r) for r in template.basis]}
    if method == "bkz":
        if isinstance(block_size, bool) or not isinstance(block_size, int) or block_size < 2:
            raise JobError("block_size must be an integer of 2 or more")
        job["block_size"] = min(block_size, len(template.basis))
        if tours is not None:
            job["tours"] = tours
    res = alg.execute(job, backend=backend, sage_version=sage_version, timeout=timeout, environ=environ,
                      root=root)
    return (template.extract(res.result["basis"]) if res.ok else []), res


def solve(template: Template, **kw) -> list:
    """The template's checked solutions after one reduction (keywords of `solve_detailed`). Raises
    BackendUnavailable when the backend for the method is missing and ServiceError when it failed;
    an empty list means the reduction ran and exposed nothing."""
    found, res = solve_detailed(template, **kw)
    res.require()
    return found


# --------------------------------------------------------------------------------------------- CLI

class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise JobError(message)


def _job_template(path: str) -> Template:
    job = alg.load_job(path)
    if set(job) - {"template", "args"}:
        raise JobError(f"unknown job keys: {sorted(set(job) - {'template', 'args'})}")
    return build(job.get("template"), job.get("args", {}))


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="lattice_templates.py", description="template lattices: build, reduce, check")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list")
    sub.add_parser("basis").add_argument("job")
    sp = sub.add_parser("solve")
    sp.add_argument("job")
    sp.add_argument("--method", default="lll", choices=alg.LATTICE_OPS)
    sp.add_argument("--block-size", type=int, default=20)
    sp.add_argument("--backend", default="auto", choices=alg.BACKENDS)
    sp.add_argument("--sage-version")
    sp.add_argument("--timeout", type=int, default=alg.DEFAULT_TIMEOUT)
    try:
        args = parser.parse_args(argv)
        if args.command is None:
            raise JobError("a command is required: list, basis or solve")
        if args.command == "list":
            print(json.dumps({name: {"args": list(inspect.signature(fn).parameters),
                                     "what": (fn.__doc__ or "").strip().split("\n\n")[0].replace("\n    ", " ")}
                              for name, fn in sorted(TEMPLATES.items())}, indent=2))
            return 0
        with alg._bigints():
            template = _job_template(args.job)
            if args.command == "basis":
                print(json.dumps({"template": template.name, "dimension": template.dimension,
                                  "notes": template.notes, "basis": [list(r) for r in template.basis]}))
                return 0
            found, res = solve_detailed(template, method=args.method, block_size=args.block_size,
                                        backend=args.backend, sage_version=args.sage_version,
                                        timeout=args.timeout)
            print(json.dumps({"template": template.name, "dimension": template.dimension,
                              "method": args.method, "status": res.status, "backend": res.backend,
                              "detail": res.detail, "proof": "exact" if res.ok else "none",
                              "solutions": found, "reason": res.reason, "needs_tool": list(res.needs_tool),
                              "fix": res.fix, "seconds": round(res.seconds, 3)}, sort_keys=True))
            return {"ok": 0, "blocked": 3}.get(res.status, 1)
    except JobError as ex:
        print(f"lattice_templates: {ex}", file=sys.stderr)
        return 2


__all__ = ["BackendUnavailable", "JobError", "ServiceError", "TEMPLATES", "Template", "bounded_linear",
           "build", "hidden_number", "integer_relation", "modular_ratio", "short_kernel", "solve",
           "solve_detailed", "subset_sum", "truncated_lcg"]

if __name__ == "__main__":
    raise SystemExit(main())
