#!/usr/bin/env python3
"""Bounded LLL/BKZ reduction harness with exact lattice-equivalence checks.

The repository's pure-Python LLL is always available.  BKZ is dispatched only to a locally installed
``fpylll``; this module never installs a package or contacts a service.  A reduced basis is labelled
verified only when its row lattice has the same exact Hermite normal form as the input.  If the
optional backend or the independent SymPy verifier is absent, the API declines rather than treating
an unchecked basis as a recovered value.

LLL backends (B-244), fastest first:

* ``fpylll``  -- floating-point L2 (fplll).  Optional: not in the pinned venv, it needs a build on the
  target platform (B-188's toolkit image, or a human install).  Asking for it by name without it
  raises :class:`BackendUnavailable` naming ``py:fpylll``; nothing is installed from here.
* ``gmpy2``   -- the in-repo exact LLL on GMP integers: bit-identical output, about 10x faster than
  Python ints on Coppersmith / Boneh-Durfee lattices (gmpy2 is pinned in requirements.in).
* ``python``  -- the in-repo exact LLL on Python ints.

``make_reducer("auto")`` takes the fastest one present and says which in ``.backend``; every run
records the backend it used, so a slower path is never taken silently.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from rsa_lattice import lll


MAX_JSON = 2 * 1024 * 1024
MAX_ROWS = 128
MAX_COLUMNS = 256
MAX_BITS = 16_384


LLL_BACKENDS = ("fpylll", "gmpy2", "python")
FPYLLL_REMEDY = ("py:fpylll is not importable here; it needs a build on the target platform: use the "
                 "B-188 toolkit image, or install it into the venv as a human step and pin it in "
                 "requirements.in")


class BackendUnavailable(RuntimeError):
    """A lattice backend asked for by name is not present. ``tool`` is the needs_tool name."""

    def __init__(self, backend: str, tool: str, reason: str):
        super().__init__(f"lattice backend {backend!r} unavailable (needs_tool {tool}): {reason}")
        self.backend, self.tool = backend, tool


def _has(module: str) -> bool:
    try:
        __import__(module)
        return True
    except ImportError:
        return False


def lll_backends() -> dict[str, bool]:
    """Which LLL backends can run in this interpreter."""
    return {"fpylll": _has("fpylll"), "gmpy2": _has("gmpy2"), "python": True}


def resolve_backend(name: str = "auto") -> str:
    """The backend ``name`` stands for. "auto" is the fastest present; an explicit name that is not
    present raises BackendUnavailable (never a quiet downgrade)."""
    have = lll_backends()
    if name == "auto":
        return next(b for b in LLL_BACKENDS if have[b])
    if name not in LLL_BACKENDS:
        raise ValueError(f"LLL backend must be 'auto' or one of {LLL_BACKENDS}, got {name!r}")
    if not have[name]:
        if name == "fpylll":
            raise BackendUnavailable("fpylll", "py:fpylll", FPYLLL_REMEDY)
        raise BackendUnavailable(name, f"py:{name}", f"py:{name} does not import (it is pinned in "
                                 f"requirements.in: the venv is incomplete)")
    return name


def _fpylll_lll(rows) -> list[list[int]]:
    from fpylll import LLL, IntegerMatrix
    matrix = IntegerMatrix.from_matrix([[int(x) for x in row] for row in rows], int_type="mpz")
    LLL.reduction(matrix)
    out = [[int(matrix[i, j]) for j in range(matrix.ncols)] for i in range(matrix.nrows)]
    # fplll puts the zero vectors of a dependent basis first; the in-repo callers read the shortest
    # vectors from the top, so zero rows move to the end.
    return [r for r in out if any(r)] + [r for r in out if not any(r)]


class Reducer:
    """``reducer(rows, deadline) -> rows | None`` for rsa_lattice and roca (their ``reducer=`` hook).

    ``calls`` counts reductions; ``backend`` names what runs.  fpylll cannot be interrupted, so its
    deadline is checked before each call only."""

    def __init__(self, backend: str = "auto"):
        self.backend = resolve_backend(backend)
        self.calls = 0

    def __call__(self, rows, deadline: float | None = None):
        self.calls += 1
        if deadline is not None and time.monotonic() > deadline:
            return None
        if self.backend == "fpylll":
            return _fpylll_lll(rows)
        return lll(rows, deadline=deadline, arith="gmpy2" if self.backend == "gmpy2" else "python-int")

    def __repr__(self) -> str:
        return f"Reducer({self.backend!r})"


def make_reducer(backend: str = "auto") -> Reducer:
    return Reducer(backend)


@dataclass(frozen=True)
class ReductionResult:
    basis: tuple[tuple[int, ...], ...]
    method: str
    block_size: int | None
    tours: int | None
    lattice_verified: bool
    backend: str


def _basis(value) -> list[list[int]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ROWS:
        raise ValueError(f"basis must contain 1..{MAX_ROWS} rows")
    width = len(value[0]) if isinstance(value[0], list) else 0
    if not 1 <= width <= MAX_COLUMNS or len(value) > width:
        raise ValueError("basis must be bounded and have no more rows than columns")
    rows = []
    for row in value:
        if not isinstance(row, list) or len(row) != width:
            raise ValueError("basis must be rectangular")
        parsed = []
        for coordinate in row:
            if isinstance(coordinate, bool) or not isinstance(coordinate, int):
                raise ValueError("basis coordinates must be integers")
            if coordinate.bit_length() > MAX_BITS:
                raise ValueError(f"basis coordinate exceeds {MAX_BITS}-bit cap")
            parsed.append(coordinate)
        rows.append(parsed)
    return rows


def _same_row_lattice(before: list[list[int]], after: list[list[int]]) -> bool:
    """Compare canonical column HNFs of the transposed row bases."""
    try:
        from sympy import Matrix
        from sympy.matrices.normalforms import hermite_normal_form
        return hermite_normal_form(Matrix(before).T) == hermite_normal_form(Matrix(after).T)
    except Exception:
        return False


def reduce_lattice(basis, *, method: str = "lll", block_size: int = 20, tours: int = 4,
                   deadline: float | None = None, backend: str = "python") -> ReductionResult | None:
    """Reduce a row basis and return it only after an independent exact lattice check.

    ``None`` means deadline, unavailable BKZ backend, dependent input, or failed verification.  No
    silent BKZ-to-LLL downgrade occurs: callers can distinguish algorithmic coverage honestly.
    ``backend`` picks the LLL backend ("python", "gmpy2", "fpylll" or "auto"); an explicit backend
    that is absent raises BackendUnavailable.
    """
    rows = _basis(basis)
    if method not in ("lll", "bkz"):
        raise ValueError("method must be 'lll' or 'bkz'")
    if deadline is not None and time.monotonic() > deadline:
        return None
    if method == "lll":
        reducer = Reducer(backend)
        reduced = reducer(rows, deadline)
        backend = {"python": "in-repo exact integer LLL", "gmpy2": "in-repo exact integer LLL (gmpy2)",
                   "fpylll": "local fpylll LLL"}[reducer.backend]
        block = loops = None
    else:
        if (isinstance(block_size, bool) or not isinstance(block_size, int)
                or not 2 <= block_size <= min(MAX_ROWS, len(rows))):
            raise ValueError("BKZ block_size must be in 2..number-of-rows")
        if isinstance(tours, bool) or not isinstance(tours, int) or not 1 <= tours <= 64:
            raise ValueError("BKZ tours must be in 1..64")
        try:
            from fpylll import BKZ, IntegerMatrix
        except ImportError:
            return None
        matrix = IntegerMatrix.from_matrix(rows)
        try:
            BKZ.reduction(matrix, BKZ.Param(block_size=block_size, max_loops=tours))
        except Exception:
            return None
        reduced = [[int(matrix[i, j]) for j in range(matrix.ncols)]
                   for i in range(matrix.nrows)]
        backend, block, loops = "local fpylll", block_size, tours
    if reduced is None or not _same_row_lattice(rows, reduced):
        return None
    return ReductionResult(tuple(tuple(row) for row in reduced), method, block, loops, True, backend)


def backend_status() -> dict[str, Any]:
    try:
        import fpylll  # noqa: F401
        bkz = True
    except ImportError:
        bkz = False
    try:
        import sympy  # noqa: F401
        verifier = True
    except ImportError:
        verifier = False
    return {"lll": True, "bkz": bkz, "exact_hnf_verifier": verifier,
            "lll_backends": lll_backends(), "lll_auto": resolve_backend("auto"),
            "offline": True, "requests_sent": 0}


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON member {key!r}")
        out[key] = value
    return out


def parse_json_document(raw: bytes) -> dict[str, Any]:
    """Parse one bounded strict JSON object without evaluating any expression."""
    if not isinstance(raw, bytes) or len(raw) > MAX_JSON:
        raise ValueError("input JSON must be bounded bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError(
                               f"non-finite JSON value {value!r}")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("input is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("input JSON must be an object")
    return value


def _load(path_value: str) -> dict[str, Any]:
    path = Path(path_value)
    if not path.is_file() or path.stat().st_size > MAX_JSON:
        raise ValueError("input JSON is absent or over cap")
    return parse_json_document(path.read_bytes())


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="lattice_backends.py")
    parser.add_argument("operation", choices=("status", "reduce"))
    parser.add_argument("input", nargs="?")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.operation == "status":
            if args.input is not None:
                raise ValueError("status takes no input")
            output = backend_status()
        else:
            if args.input is None:
                raise ValueError("reduce requires a JSON input")
            data = _load(args.input)
            result = reduce_lattice(data["basis"], method=data.get("method", "lll"),
                                    block_size=data.get("block_size", 20), tours=data.get("tours", 4),
                                    backend=data.get("backend", "python"))
            if result is None:
                raise ValueError("backend unavailable, deadline expired, or exact verification failed")
            output = asdict(result)
        print(json.dumps(output, sort_keys=True, indent=2 if args.json else None))
        return 0
    except BackendUnavailable as exc:
        print(f"lattice_backends: {exc}", file=sys.stderr)
        return 3
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"lattice_backends: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
