"""Tabular change points + exact linear fit + quantize-and-hash fingerprint (B-093).

The shape this closes: a handout ships a numeric *history* (feature columns plus a target
score) that was produced by an exact linear rule ``score = intercept + sum(w_i * x_i)``
whose coefficients changed at one or more unknown rows, plus a batch of *probe* rows with
the features only.  The ask is to reconstruct the current (latest) rule, score the probes
with it, and turn the scores into a fingerprint the README defines (quantize, join, hash).

No model, no floats in the fit:

* Every cell is parsed to an exact :class:`fractions.Fraction` (``"0.125"`` is 1/8, never a
  binary float).  NPZ arrays load with ``allow_pickle=False``; an NPZ float goes through its
  shortest ``repr`` (the decimal the author wrote), an integer stays an integer.
* Change points are found by residual: rows are added newest first to an incremental exact
  system (Gauss-Jordan over the rationals); the first row whose residual against the rule
  so far is non-zero ends the segment.  The remaining older rows are refitted the same way,
  per split, so every segment has its own exact coefficients and a zero residual on every
  one of its rows.  More than ``max_segments`` segments means the data is not piecewise
  exactly linear in these columns (noise, rounding, a non-linear rule): that is a ``none``
  with the reason, never a near fit.
* A segment whose rows only just determine the unknowns (no spare row to check against) is
  reported as unverified, and a rank-deficient segment says which probes it cannot score.
* The fingerprint form is the README's to define, so it is parameters, not a guess:
  ``decimals``, ``rounding``, ``render`` (scaled integer or fixed decimal string), ``join``,
  ``trailing`` newline, ``hash`` and hex case.  Parameters the caller fixes are used as
  given; the rest are enumerated, ranked (README hints first, then common forms) and all
  returned as ``candidate`` values.  One is never picked silently.

Contract entry: ``solve(challenge_dir, profile, **opts) -> SolverResult`` (CONTRACTS 6-7).
Script: ``tabular_fit.py <challenge dir | data file> [--event SLUG] [--opt key=value]...``.
"""

from __future__ import annotations

import csv
import hashlib
import io
import math
import re
import sys
import time
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Iterable, Sequence

# ctf package import (a script run, as triage suggests it, needs the checkout root on sys.path)
try:
    from ctf.result import Cost, Evidence, SolverResult
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf.result import Cost, Evidence, SolverResult

ENGINE = "toolkits.tabular_fit"

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ROWS = 200_000
MAX_COLS = 512
MAX_TEXT_BYTES = 64 * 1024          # a README read for fingerprint hints
DEFAULT_MAX_SEGMENTS = 8
DEFAULT_MIN_CHECK_ROWS = 2          # spare rows a segment needs before its zero residual means anything
DEFAULT_MAX_CANDIDATES = 8

TABLE_EXTS = (".csv", ".tsv", ".npz")
SKIP_DIRS = {"recon", ".git", "__pycache__", "__MACOSX"}
SKIP_ROOT_FILES = {"notes.md", "triage.md", "challenge.json"}   # our own brief/triage text, not the handout

# Column names that order the history (time-like) and names that only identify a row.  Both are
# kept out of the features unless the fit fails without them.
ORDER_NAMES = ("timestamp", "time", "datetime", "date", "ts", "t", "step", "seq", "sequence",
               "epoch", "tick", "day", "period")
ID_NAMES = ("id", "idx", "index", "row", "row_id", "rowid", "record_id", "probe_id", "case_id", "uid",
            "sample_id")
TARGET_NAMES = ("score", "target", "y", "risk", "risk_score", "output", "response", "result",
                "value", "prediction", "label", "outcome")

ROUNDINGS = ("half_up", "half_even", "floor", "trunc", "half_away", "ceil")
RENDERS = ("int", "fixed")
HASHES = ("sha256", "md5", "sha1", "sha512", "sha224", "sha384", "sha3_256", "sha3_512",
          "blake2b", "blake2s")
DEFAULT_GRID = {
    "decimals": (3, 2, 4, 0, 6, 1, 5),
    "rounding": ROUNDINGS,
    "render": RENDERS,
    "join": ("\n", ",", "", " "),
    "trailing": (False, True),
    "hash": ("sha256", "md5", "sha1", "sha512"),
    "hexcase": ("lower",),
}
PARAMS = ("decimals", "rounding", "render", "join", "trailing", "hash", "hexcase")


class TabularError(ValueError):
    """A data file exists but cannot be read as a numeric table (the message says why)."""


class NoExactFit(ValueError):
    """The rows are not piecewise exactly linear within the segment budget."""


# ---------------------------------------------------------------------------- exact numbers


def to_fraction(cell) -> Fraction | None:
    """An exact rational for a cell, or ``None`` when it is empty or not a finite number.

    Strings parse as written (``"0.1"`` is 1/10, ``"3/4"`` and ``"1e-3"`` work); a Python or
    NumPy float goes through its shortest ``repr`` so the decimal the author wrote survives;
    ``nan`` and ``inf`` are not numbers here.
    """
    if cell is None:
        return None
    if isinstance(cell, Fraction):
        return cell
    if isinstance(cell, bool):
        return Fraction(int(cell))
    if isinstance(cell, int):
        return Fraction(cell)
    if hasattr(cell, "item") and not isinstance(cell, (str, bytes)):   # a NumPy scalar
        dtype = getattr(cell, "dtype", None)
        if dtype is not None and dtype.kind == "f" and dtype.itemsize != 8:
            # float32/float16 (and long double): numpy's str() is the shortest repr *for that
            # dtype*, so a float32 0.1 stays 0.1.  .item() would widen it to float64 first and
            # give 0.10000000149011612, which no exact fit of the written decimals reproduces.
            text = str(cell).strip()
            try:
                value = Fraction(text)
            except (ValueError, ZeroDivisionError):
                return None                              # nan, inf
            return value
        cell = cell.item()
        if isinstance(cell, (int, bool)):
            return Fraction(int(cell))
    if isinstance(cell, float):
        if not math.isfinite(cell):
            return None
        return Fraction(repr(cell))
    if isinstance(cell, bytes):
        cell = cell.decode("utf-8", "replace")
    text = str(cell).strip().replace("_", "")
    if not text:
        return None
    try:
        value = Fraction(text)
    except (ValueError, ZeroDivisionError):
        return None
    return value


def fmt_fraction(v: Fraction) -> str:
    """``3``, ``-7/4`` -- exact, the way a human checks it."""
    return str(v.numerator) if v.denominator == 1 else f"{v.numerator}/{v.denominator}"


def fmt_decimal(v: Fraction, places: int = 12) -> str:
    """A terminating decimal exactly when it terminates within ``places``, else ``~`` and rounded."""
    d = v.denominator
    for p in (2, 5):
        while d % p == 0:
            d //= p
    scaled = v * 10 ** places
    if d == 1 and scaled.denominator == 1:
        text = _fixed(int(scaled), places).rstrip("0").rstrip(".")
        return text or "0"
    return "~" + _fixed(round(scaled), places).rstrip("0").rstrip(".")


# ---------------------------------------------------------------------------- exact solver


class ExactSystem:
    """An incremental exact linear system ``A w = b`` over the rationals, kept in RREF.

    ``add(row, rhs)`` reduces the new equation against the pivots so far.  What is left of
    its right-hand side when no unknown is left is its residual: zero means the row is
    consistent with every row before it, non-zero means it is not (the system is unchanged).
    """

    def __init__(self, unknowns: int):
        if unknowns < 1:
            raise ValueError("an exact system needs at least one unknown")
        self.n = unknowns
        self.pivots: dict[int, list[Fraction]] = {}   # pivot column -> its row (n coefficients + rhs)
        self.rows = 0

    @property
    def rank(self) -> int:
        return len(self.pivots)

    def _reduce(self, row: Sequence[Fraction], rhs: Fraction) -> list[Fraction]:
        r = [Fraction(x) for x in row] + [Fraction(rhs)]
        if len(r) != self.n + 1:
            raise ValueError(f"row has {len(row)} coefficients, the system {self.n}")
        for col, prow in self.pivots.items():
            c = r[col]
            if c:
                for j in range(self.n + 1):
                    if prow[j]:
                        r[j] -= c * prow[j]
        return r

    def residual(self, row: Sequence[Fraction], rhs: Fraction) -> Fraction | None:
        """The residual of a row against the system, or ``None`` when the row adds a new pivot."""
        r = self._reduce(row, rhs)
        if any(r[: self.n]):
            return None
        return r[self.n]

    def add(self, row: Sequence[Fraction], rhs: Fraction) -> Fraction:
        """Add an equation; return its residual (0 when consistent).  An inconsistent row is not kept."""
        if len(self.pivots) == self.n:                  # unique already: the residual is rhs - w.x
            if len(row) != self.n:
                raise ValueError(f"row has {len(row)} coefficients, the system {self.n}")
            res = Fraction(rhs) - sum((Fraction(a) * p[self.n] for a, p in
                                       ((row[c], prow) for c, prow in self.pivots.items())), Fraction(0))
            if not res:
                self.rows += 1
            return res
        r = self._reduce(row, rhs)
        lead = next((j for j in range(self.n) if r[j]), None)
        if lead is None:
            if r[self.n]:
                return r[self.n]
            self.rows += 1
            return Fraction(0)
        inv = 1 / r[lead]
        r = [x * inv for x in r]
        for prow in self.pivots.values():               # keep it fully reduced (RREF)
            c = prow[lead]
            if c:
                for j in range(self.n + 1):
                    if r[j]:
                        prow[j] -= c * r[j]
        self.pivots[lead] = r
        self.rows += 1
        return Fraction(0)

    def solution(self) -> list[Fraction]:
        """One exact solution: free unknowns 0, pivot unknowns from their rows."""
        w = [Fraction(0)] * self.n
        for col, prow in self.pivots.items():
            w[col] = prow[self.n]
        return w

    def nullspace(self) -> list[list[Fraction]]:
        """A basis of the directions the rows leave undetermined (empty when the fit is unique)."""
        free = [j for j in range(self.n) if j not in self.pivots]
        basis = []
        for f in free:
            v = [Fraction(0)] * self.n
            v[f] = Fraction(1)
            for col, prow in self.pivots.items():
                v[col] = -prow[f]
            basis.append(v)
        return basis


@dataclass(frozen=True)
class Fit:
    """Exact coefficients of one segment: ``coef[0]`` is the intercept when ``intercept``."""

    coef: tuple[Fraction, ...]
    intercept: bool
    rank: int
    unknowns: int
    rows: int
    null: tuple[tuple[Fraction, ...], ...] = ()

    @property
    def unique(self) -> bool:
        return self.rank == self.unknowns

    @property
    def spare(self) -> int:
        """Rows beyond the ones that pin the unknowns: each one is an independent zero-residual check."""
        return self.rows - self.rank

    def design(self, x: Sequence[Fraction]) -> list[Fraction]:
        return ([Fraction(1)] if self.intercept else []) + [Fraction(v) for v in x]

    def predict(self, x: Sequence[Fraction]) -> tuple[Fraction, bool]:
        """(score, determined): ``determined`` is False when the segment's rows do not fix this row's score."""
        d = self.design(x)
        if len(d) != self.unknowns:
            raise ValueError(f"probe row has {len(x)} features, the fit {self.unknowns - int(self.intercept)}")
        value = sum((c * v for c, v in zip(self.coef, d)), Fraction(0))
        determined = all(sum((a * b for a, b in zip(nv, d)), Fraction(0)) == 0 for nv in self.null)
        return value, determined

    def residual(self, x: Sequence[Fraction], y: Fraction) -> Fraction:
        return Fraction(y) - self.predict(x)[0]


def _fit_from(system: ExactSystem, intercept: bool) -> Fit:
    return Fit(coef=tuple(system.solution()), intercept=intercept, rank=system.rank,
               unknowns=system.n, rows=system.rows, null=tuple(tuple(v) for v in system.nullspace()))


def exact_fit(X: Sequence[Sequence[Fraction]], y: Sequence[Fraction], *, intercept: bool = True) -> Fit:
    """The exact linear fit of every row, or :class:`NoExactFit` naming the first row that breaks it."""
    if len(X) != len(y):
        raise ValueError(f"{len(X)} feature rows but {len(y)} targets")
    if not X:
        raise NoExactFit("no rows to fit")
    n = len(X[0]) + int(intercept)
    system = ExactSystem(n)
    for i, (x, t) in enumerate(zip(X, y)):
        d = ([Fraction(1)] if intercept else []) + [Fraction(v) for v in x]
        res = system.add(d, Fraction(t))
        if res:
            raise NoExactFit(f"row {i} has residual {fmt_fraction(res)} against the rows before it")
    return _fit_from(system, intercept)


@dataclass(frozen=True)
class Segment:
    """Rows ``[start, end)`` of the ordered history and their exact fit.

    ``slack`` rows at the start of the segment also fit the previous segment's rule, so the
    change point lies somewhere in ``[start, start + slack]``.
    """

    start: int
    end: int
    fit: Fit
    slack: int = 0

    @property
    def rows(self) -> int:
        return self.end - self.start


def find_segments(X: Sequence[Sequence[Fraction]], y: Sequence[Fraction], *, intercept: bool = True,
                  max_segments: int = DEFAULT_MAX_SEGMENTS) -> list[Segment]:
    """Split the ordered rows into maximal exactly-linear runs, newest first, refitting per split.

    Rows are added from the newest backwards; the first older row whose residual against the
    newer rows is non-zero is the change point, and the rows before it are fitted afresh.
    Returns the segments oldest first.  :class:`NoExactFit` when more than ``max_segments``
    are needed.
    """
    if len(X) != len(y):
        raise ValueError(f"{len(X)} feature rows but {len(y)} targets")
    if not X:
        raise NoExactFit("no history rows")
    n = len(X[0]) + int(intercept)
    design = [([Fraction(1)] if intercept else []) + [Fraction(v) for v in x] for x in X]
    segs: list[Segment] = []
    end = len(X)
    while end > 0:
        if len(segs) >= max_segments:
            raise NoExactFit(f"more than {max_segments} exactly-linear segments needed "
                             f"(rows 0..{end - 1} still unexplained): the data is noisy, rounded or "
                             f"not linear in these columns")
        system = ExactSystem(n)
        i = end - 1
        while i >= 0:
            if system.add(design[i], Fraction(y[i])):
                break
            i -= 1
        segs.append(Segment(start=i + 1, end=end, fit=_fit_from(system, intercept)))
        end = i + 1
    segs.reverse()
    # Boundary slack: rows at the start of a newer segment that the older rule also explains.
    out = [segs[0]]
    for prev, seg in zip(segs, segs[1:]):
        slack = 0
        if prev.fit.unique:
            for j in range(seg.start, seg.end - 1):
                if prev.fit.residual(X[j], y[j]) != 0:
                    break
                slack += 1
        out.append(Segment(seg.start, seg.end, seg.fit, slack))
    return out


# ---------------------------------------------------------------------------- quantize + hash


def _fixed(q: int, decimals: int) -> str:
    """The scaled integer ``q`` (value * 10**decimals) as a decimal string with ``decimals`` places."""
    if decimals <= 0:
        return str(q)
    sign = "-" if q < 0 else ""
    digits = str(abs(q)).rjust(decimals + 1, "0")
    return f"{sign}{digits[:-decimals]}.{digits[-decimals:]}"


def quantize(value: Fraction, decimals: int, rounding: str = "half_up") -> int:
    """``value * 10**decimals`` rounded to an integer by ``rounding``.

    ``half_up`` is ``floor(x + 1/2)`` (ties toward +inf, the README ``floor(1000*s+0.5)`` form);
    ``half_even`` is banker's rounding (Python ``round``); ``half_away`` rounds ties away from
    zero; ``floor``, ``ceil`` and ``trunc`` are what they say.
    """
    if decimals < 0:
        raise ValueError("decimals must be >= 0")
    x = Fraction(value) * 10 ** decimals
    half = Fraction(1, 2)
    if rounding == "half_up":
        return math.floor(x + half)
    if rounding == "half_even":
        return round(x)
    if rounding == "half_away":
        return math.floor(x + half) if x >= 0 else -math.floor(-x + half)
    if rounding == "floor":
        return math.floor(x)
    if rounding == "ceil":
        return math.ceil(x)
    if rounding == "trunc":
        return math.trunc(x)
    raise ValueError(f"rounding {rounding!r}: use one of {', '.join(ROUNDINGS)}")


def render_values(values: Iterable[Fraction], decimals: int, rounding: str = "half_up",
                  render: str = "int") -> list[str]:
    """Each value quantized and written as the scaled integer (``int``) or a fixed decimal (``fixed``)."""
    if render not in RENDERS:
        raise ValueError(f"render {render!r}: use one of {', '.join(RENDERS)}")
    out = []
    for v in values:
        q = quantize(v, decimals, rounding)
        out.append(str(q) if render == "int" else _fixed(q, decimals))
    return out


def fingerprint_text(values: Iterable[Fraction], *, decimals: int, rounding: str = "half_up",
                     render: str = "int", join: str = "\n", trailing: bool = False) -> str:
    text = join.join(render_values(values, decimals, rounding, render))
    return text + join if trailing and join else text


def _hasher(name: str):
    if name not in HASHES:
        raise ValueError(f"hash {name!r}: use one of {', '.join(HASHES)}")
    return hashlib.new(name)


def fingerprint(values: Iterable[Fraction], *, decimals: int, rounding: str = "half_up",
                render: str = "int", join: str = "\n", trailing: bool = False, hash: str = "sha256",
                hexcase: str = "lower") -> str:
    """The hex digest of the quantized, rendered, joined values -- exactly the form given."""
    text = fingerprint_text(values, decimals=decimals, rounding=rounding, render=render, join=join,
                            trailing=trailing)
    h = _hasher(hash)
    h.update(text.encode("utf-8"))
    digest = h.hexdigest()
    if hexcase not in ("lower", "upper"):
        raise ValueError(f"hexcase {hexcase!r}: use lower or upper")
    return digest.upper() if hexcase == "upper" else digest


@dataclass(frozen=True)
class Hint:
    value: object
    snippet: str


def readme_hints(text: str) -> dict[str, Hint]:
    """What a README says about the fingerprint form, as hints (never a decision).

    Recognised: the hash name (SHA-256, MD5, ...), the scale or decimal places
    (``floor(1000*score+0.5)``, ``3 decimal places``, ``%.3f``, ``round(x, 3)``, ``nearest 0.001``),
    the rounding (``+ 0.5`` inside a floor, half to even, truncate, floor, ceil), the separator
    (newline / one per line, comma, space, tab), a trailing newline (with or without), and
    upper-case hex.  The text is data: it is only matched, never followed.
    """
    hints: dict[str, Hint] = {}
    if not text:
        return hints
    low = text.lower()

    def snip(m) -> str:
        a, b = max(0, m.start() - 20), min(len(text), m.end() + 20)
        return " ".join(text[a:b].split())

    m = re.search(r"\b(sha-?256|sha-?1|sha-?512|sha-?384|sha-?224|sha3-?256|sha3-?512|md5|blake2b|blake2s)\b", low)
    if m:
        name = m.group(1).replace("-", "")
        name = {"sha3256": "sha3_256", "sha3512": "sha3_512"}.get(name, name)
        hints["hash"] = Hint(name, snip(m))

    scale = (re.search(r"\b(1(?:0){1,9})\s*[*x×]\s*\(?\s*(?:the\s+)?[a-z_]", low)
             or re.search(r"[a-z_)]\s*[*×]\s*(1(?:0){1,9})\b", low)
             or re.search(r"(?:multipl\w*|scal\w*)\s+(?:\w+\s+){0,4}by\s+(1(?:0){1,9})\b", low))
    if scale:
        hints["decimals"] = Hint(len(scale.group(1)) - 1, snip(scale))
        hints["render"] = Hint("int", snip(scale))
    else:
        places = (re.search(r"\b(\d{1,2})\s+(?:decimal\s+places|decimals|decimal\s+digits|digits\s+after)", low)
                  or re.search(r"%\.(\d{1,2})f", low) or re.search(r"\{:\.(\d{1,2})f\}", low)
                  or re.search(r"round\([^,()]*,\s*(\d{1,2})\s*\)", low))
        nearest = re.search(r"nearest\s+0\.(0*)1\b", low)
        if places:
            hints["decimals"] = Hint(int(places.group(1)), snip(places))
            hints["render"] = Hint("fixed", snip(places))
        elif nearest:
            hints["decimals"] = Hint(len(nearest.group(1)) + 1, snip(nearest))
            hints["render"] = Hint("fixed", snip(nearest))

    r = (re.search(r"floor\s*\([^()]*(?:\([^()]*\)[^()]*)*\+\s*0?\.5\s*\)", low)
         or re.search(r"round(?:ing)?\s+half[\s-]+up|half[\s-]+up", low))
    if r:
        hints["rounding"] = Hint("half_up", snip(r))
    elif r := re.search(r"half[\s-]+(?:to[\s-]+)?even|banker", low):
        hints["rounding"] = Hint("half_even", snip(r))
    elif r := re.search(r"half[\s-]+away", low):
        hints["rounding"] = Hint("half_away", snip(r))
    elif r := re.search(r"\btrunc\w*", low):
        hints["rounding"] = Hint("trunc", snip(r))
    elif r := re.search(r"\bfloor\b", low):
        hints["rounding"] = Hint("floor", snip(r))
    elif r := re.search(r"\bceil\w*", low):
        hints["rounding"] = Hint("ceil", snip(r))

    # A "trailing newline" phrase says nothing about the separator: blank it out (same length, so
    # the match offsets still point into the original text) before looking for one.
    sep_low = re.sub(r"(?:final|trailing)\s+newline|newline[\s-]+terminated",
                     lambda m: " " * len(m.group(0)), low)
    j = re.search(r"newline|new-line|line\s*feed|per\s+line|own\s+line|\\n|separate\s+lines|line\s+break", sep_low)
    if j:
        hints["join"] = Hint("\n", snip(j))
    elif j := re.search(r"comma", sep_low):
        hints["join"] = Hint(",", snip(j))
    elif j := re.search(r"\btab[\s-]+separated|\btabs?\b", sep_low):
        hints["join"] = Hint("\t", snip(j))
    elif j := re.search(r"space[\s-]+separated|single\s+spaces?", sep_low):
        hints["join"] = Hint(" ", snip(j))

    t = re.search(r"(?:no|without|not\s+followed\s+by\s+a|omit\w*\s+the|no\s+final)\s+(?:a\s+)?(?:final\s+|trailing\s+)newline", low)
    if t:
        hints["trailing"] = Hint(False, snip(t))
    elif t := re.search(r"(?:final|trailing|terminat\w+)\s+newline|newline[\s-]+terminated", low):
        hints["trailing"] = Hint(True, snip(t))

    u = re.search(r"upper[\s-]*case\s+hex|hex\w*\s+(?:in\s+)?upper[\s-]*case", low)
    if u:
        hints["hexcase"] = Hint("upper", snip(u))
    return hints


@dataclass(frozen=True)
class Candidate:
    digest: str
    params: dict
    hinted: tuple[str, ...]          # params whose value the README hinted
    misses: tuple[str, ...]          # params where this candidate goes against a README hint
    preview: str                     # the first rendered value, as hashed
    also: int = 0                    # other parameter sets giving the same digest

    def describe(self) -> str:
        p = self.params
        sep = {"\n": "newline", ",": "comma", "": "nothing", " ": "space", "\t": "tab"}.get(p["join"], repr(p["join"]))
        form = (f"floor({10 ** p['decimals']}*s+1/2)" if p["rounding"] == "half_up" and p["render"] == "int"
                else f"{p['rounding']}({10 ** p['decimals']}*s)" if p["render"] == "int"
                else f"{p['rounding']} to {p['decimals']} places")
        tail = ", trailing newline" if p["trailing"] else ""
        case = ", upper-case hex" if p["hexcase"] == "upper" else ""
        bits = [f"{p['hash']} of {sep}-joined {form}{tail}{case}"]
        if self.hinted:
            bits.append("README: " + ",".join(self.hinted))
        if self.misses:
            bits.append("against README: " + ",".join(self.misses))
        if self.also:
            bits.append(f"+{self.also} equal form(s)")
        return "; ".join(bits)


def fingerprint_candidates(values: Sequence[Fraction], *, fixed: dict | None = None,
                           hints: dict[str, Hint] | None = None, limit: int | None = None) -> list[Candidate]:
    """Every fingerprint form, ranked: README-consistent first, then the common forms first.

    ``fixed`` pins parameters (the caller knows them); the others range over README hints plus
    :data:`DEFAULT_GRID`.  Forms that produce the same digest are merged (the best-ranked one is
    kept and counts the others).  Nothing is chosen: the caller gets the ranked list.
    """
    fixed = dict(fixed or {})
    hints = dict(hints or {})
    unknown = set(fixed) - set(PARAMS)
    if unknown:
        raise ValueError(f"unknown fingerprint parameter(s): {', '.join(sorted(unknown))}")
    choices: dict[str, list] = {}
    for p in PARAMS:
        if p in fixed:
            choices[p] = [fixed[p]]
            continue
        seq = list(DEFAULT_GRID[p])
        if p in hints and hints[p].value in seq:
            seq.remove(hints[p].value)
        if p in hints:
            seq.insert(0, hints[p].value)
        choices[p] = seq
    rendered: dict[tuple, list[str]] = {}
    ranked = []
    import itertools

    for combo in itertools.product(*(choices[p] for p in PARAMS)):
        params = dict(zip(PARAMS, combo))
        key = (params["decimals"], params["rounding"], params["render"])
        if key not in rendered:
            rendered[key] = render_values(values, params["decimals"], params["rounding"], params["render"])
        text = params["join"].join(rendered[key])
        if params["trailing"]:
            text += params["join"]             # with join "" this is the plain text again (merged below)
        h = _hasher(params["hash"])
        h.update(text.encode("utf-8"))
        digest = h.hexdigest().upper() if params["hexcase"] == "upper" else h.hexdigest()
        hinted = tuple(p for p in PARAMS if p in hints and p not in fixed and params[p] == hints[p].value)
        misses = tuple(p for p in PARAMS if p in hints and p not in fixed and params[p] != hints[p].value)
        prior = sum(choices[p].index(params[p]) for p in PARAMS)
        ranked.append(((len(misses), prior), digest, params, hinted, misses,
                       rendered[key][0] if rendered[key] else ""))
    ranked.sort(key=lambda r: r[0])
    seen: dict[str, int] = {}
    out: list[Candidate] = []
    for _rank, digest, params, hinted, misses, preview in ranked:
        if digest in seen:
            i = seen[digest]
            c = out[i]
            out[i] = Candidate(c.digest, c.params, c.hinted, c.misses, c.preview, c.also + 1)
            continue
        seen[digest] = len(out)
        out.append(Candidate(digest, params, hinted, misses, preview))
    return out[:limit] if limit else out


# ---------------------------------------------------------------------------- tables


@dataclass
class Table:
    """A named table: lower-cased column names and rows of raw cells (str, number or None)."""

    name: str
    columns: list[str]
    rows: list[list] = field(default_factory=list)
    shown: list[str] = field(default_factory=list)   # column names as written
    notes: list[str] = field(default_factory=list)   # how the reader built it, when it had a choice

    def col(self, name: str) -> int:
        return self.columns.index(name)

    def numeric_columns(self) -> list[str]:
        """Columns whose every non-empty cell is a finite number (and that have at least one)."""
        out = []
        for j, c in enumerate(self.columns):
            seen = False
            for r in self.rows:
                cell = r[j] if j < len(r) else None
                if cell is None or (isinstance(cell, str) and not cell.strip()):
                    continue
                if to_fraction(cell) is None:
                    break
                seen = True
            else:
                if seen:
                    out.append(c)
        return out


def _norm(name: str) -> str:
    return str(name).strip().lower()


def _is_number_text(cell: str) -> bool:
    return to_fraction(cell) is not None


def read_csv(path: Path) -> Table:
    """A CSV/TSV as a :class:`Table`; a first row with a non-numeric cell is the header."""
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise TabularError(f"{path.name}: over {MAX_FILE_BYTES} bytes")
    raw = path.read_bytes()
    text = raw.decode("utf-8-sig", errors="replace")
    sample = text[:16384]
    if path.suffix.lower() == ".tsv":
        delim = "\t"
    else:
        try:
            delim = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
        except csv.Error:
            delim = ","
    rows = [r for r in csv.reader(io.StringIO(text), delimiter=delim) if any(c.strip() for c in r)]
    if not rows:
        raise TabularError(f"{path.name}: no rows")
    if len(rows) > MAX_ROWS + 1:
        raise TabularError(f"{path.name}: over {MAX_ROWS} rows")
    width = max(len(r) for r in rows)
    if width > MAX_COLS:
        raise TabularError(f"{path.name}: over {MAX_COLS} columns")
    first = rows[0]
    header = any(c.strip() and not _is_number_text(c) for c in first)
    if header:
        shown = [c.strip() or f"c{j}" for j, c in enumerate(first)] + [f"c{j}" for j in range(len(first), width)]
        body = rows[1:]
    else:
        shown = [f"c{j}" for j in range(width)]
        body = rows
    cols = [_norm(c) for c in shown]
    if len(set(cols)) != len(cols):
        dup = sorted({c for c in cols if cols.count(c) > 1})
        raise TabularError(f"{path.name}: duplicate column name(s) {', '.join(dup)}")
    body = [r + [None] * (width - len(r)) for r in body]
    return Table(name=path.name, columns=cols, rows=body, shown=shown)


def _require_numpy():
    try:
        import numpy as np
    except ImportError as exc:                       # no silent fallback
        raise TabularError("numpy is required to read .npz tables (pip install numpy); "
                           "CSV/TSV input needs nothing") from exc
    return np


# Array names in an NPZ that say "these rows are the probes" / "these rows are the history".  Used
# only to decide which 2-D array a 1-D target belongs to when more than one has its length.
PROBE_ARRAY_WORDS = ("probe", "test", "query", "queries", "eval", "audit", "predict", "unlabel",
                     "unknown", "holdout", "challenge")
HISTORY_ARRAY_WORDS = ("hist", "train", "past", "log", "known", "label", "fit", "obs")
HISTORY_ARRAY_NAMES = ("x", "data", "features", "feats", "inputs")


def _array_role(name: str) -> int:
    """0 history-like, 1 neutral, 2 probe-like -- by the words in an NPZ array's name."""
    # words split on separators and camel case: X_test, XTest -> x, test; "latest" stays one word
    tokens = [t.lower() for t in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", str(name))]
    if any(t.startswith(w) for t in tokens for w in PROBE_ARRAY_WORDS) or any("probe" in t for t in tokens):
        return 2
    if any(t.startswith(w) for t in tokens for w in HISTORY_ARRAY_WORDS) or \
            any(t in HISTORY_ARRAY_NAMES for t in tokens):
        return 0
    return 1


def _cells(a) -> list:
    """An array's cells for :func:`to_fraction`: Python numbers, except narrow floats.

    ``tolist()`` widens float32/float16 to float64, whose repr is not the decimal written; those
    stay NumPy scalars so :func:`to_fraction` takes the dtype's own shortest repr.
    """
    if a.dtype.kind == "f" and a.dtype.itemsize != 8:
        return [list(r) for r in a] if a.ndim == 2 else list(a)
    return a.tolist()


def _pairing_fit(a, v) -> tuple[int, int] | None:
    """How well the rows of 2-D array ``a`` explain 1-D array ``v`` exactly: (segments, -spare rows).

    Smaller is better; ``None`` when a cell is not a finite number or no exact piecewise fit
    exists within :data:`DEFAULT_MAX_SEGMENTS`.  The intercept is always on (a rule without one
    fits with it too).  A wrong pairing (probes against the history's target) needs a new
    segment every few rows, each with no spare row, or fails outright.
    """
    X = [[to_fraction(c) for c in r] for r in _cells(a)]
    y = [to_fraction(c) for c in _cells(v)]
    if any(c is None for r in X for c in r) or any(c is None for c in y):
        return None
    try:
        segs = find_segments(X, y, intercept=True)
    except NoExactFit:
        return None
    return len(segs), -sum(s.fit.spare for s in segs)


def read_npz(path: Path) -> list[Table]:
    """Tables from an NPZ (``allow_pickle=False``: an object array is refused, never unpickled).

    * a structured array is one table (its field names are the columns);
    * each 2-D array is a table with columns ``f0..f{k-1}``; a 1-D array whose length equals
      its row count is added as a column under the 1-D array's name (the target, usually).
      When several 2-D arrays have that row count, the one whose name reads as the history
      (``X``, ``train``, ``history``) wins over a neutral name, and a neutral name over a
      probe-like one (``probes``, ``X_test``, ``audit``).  When the names tie, each tied pairing
      is fitted (:func:`_pairing_fit`) and the one that explains the 1-D array with the fewest
      exactly-linear segments wins; only when that also ties does array order decide.  The
      table's notes say a choice was made and how;
    * the remaining 1-D arrays are grouped by length, one table per length, one column each.
    """
    np = _require_numpy()
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise TabularError(f"{path.name}: over {MAX_FILE_BYTES} bytes")
    try:
        with np.load(path, allow_pickle=False) as z:
            arrays = {k: np.asarray(z[k]) for k in z.files}
    except ValueError as exc:
        raise TabularError(f"{path.name}: {exc} (object arrays are refused: allow_pickle=False)") from exc
    except (OSError, EOFError) as exc:
        raise TabularError(f"{path.name}: not a readable NPZ ({exc})") from exc
    tables: list[Table] = []
    one_d = {k: a for k, a in arrays.items() if a.ndim == 1 and a.dtype.names is None}
    two_d = [k for k, a in arrays.items() if a.dtype.names is None and a.ndim == 2]
    for k in two_d:
        a = arrays[k]
        if a.shape[0] > MAX_ROWS or a.shape[1] > MAX_COLS:
            raise TabularError(f"{path.name}:{k}: shape {a.shape} over the {MAX_ROWS}x{MAX_COLS} cap")
    # Which 2-D array each 1-D array joins (by row count, then by the arrays' names).
    shown_of = {k: [f"f{j}" for j in range(arrays[k].shape[1])] for k in two_d}
    attach: dict[str, list[str]] = {k: [] for k in two_d}
    notes_of: dict[str, list[str]] = {k: [] for k in two_d}
    used: set[str] = set()
    for k1, v in one_d.items():
        fits = [k for k in two_d if arrays[k].shape[0] == v.shape[0] and _norm(k1) not in
                [_norm(c) for c in shown_of[k]]]
        if not fits:
            continue
        best = min(fits, key=lambda k: (_array_role(k), two_d.index(k)))
        tied = [k for k in fits if _array_role(k) == _array_role(best)]
        how = "by the array names"
        if len(tied) > 1:
            # The names do not decide: the pairing whose rows explain v exactly wins.
            score = {k: _pairing_fit(arrays[k], v) for k in tied}
            ok = sorted((sc, two_d.index(k), k) for k, sc in score.items() if sc is not None)
            if ok and (len(ok) == 1 or ok[0][0] < ok[1][0]):
                best = ok[0][2]
                segs_n = ok[0][0][0]
                how = (f"by exact fit (the names do not say which is the history; {segs_n} exactly-linear "
                       f"segment(s) with {best!r}, " +
                       ", ".join(f"{score[k][0]} with {k!r}" if score[k] else f"no exact fit with {k!r}"
                                 for k in tied if k != best) + ")")
            else:
                best = tied[0]
                how = ("by array order (the names do not say which is the history, and the "
                       + ("fits tie" if ok else "rows fit neither exactly") + ")")
        shown_of[best].append(k1)
        attach[best].append(k1)
        used.add(k1)
        others = [k for k in fits if k != best]
        if others:
            notes_of[best].append(f"{path.name}: {k1!r} joined to {best!r}, not {', '.join(map(repr, others))} "
                                  f"(same {v.shape[0]} rows), {how}")
    for k, a in arrays.items():
        if a.dtype.names:
            names = list(a.dtype.names)
            flat = a.reshape(-1)
            tables.append(Table(name=f"{path.name}:{k}", columns=[_norm(n) for n in names],
                                rows=[[row[n] for n in names] for row in flat], shown=names))
        elif a.ndim == 2:
            shown = shown_of[k]
            rows = [list(r) for r in _cells(a)]
            for k1 in attach[k]:
                for r, cell in zip(rows, _cells(one_d[k1])):
                    r.append(cell)
            tables.append(Table(name=f"{path.name}:{k}", columns=[_norm(c) for c in shown], rows=rows,
                                shown=shown, notes=notes_of[k]))
    groups: dict[int, list[str]] = {}
    for k, v in one_d.items():
        if k not in used:
            groups.setdefault(v.shape[0], []).append(k)
    for length, names in sorted(groups.items()):
        if length > MAX_ROWS:
            raise TabularError(f"{path.name}: 1-D arrays of length {length} over the {MAX_ROWS} cap")
        cols = [_cells(one_d[n]) for n in names]
        tables.append(Table(name=f"{path.name}:{','.join(names)}", columns=[_norm(n) for n in names],
                            rows=[list(r) for r in zip(*cols)], shown=list(names)))
    return [t for t in tables if t.rows]


def find_files(challenge_dir: Path, exts: Sequence[str]) -> list[Path]:
    """Handout files with these extensions under the challenge folder, de-duplicated by content.

    ``recon/`` (engine output) and the brief files at the challenge root are left out; the
    same file reached twice (``files/`` and its unpacked copy) is read once.
    """
    root = Path(challenge_dir)
    if root.is_file():
        return [root] if root.suffix.lower() in exts else []
    found, seen = [], set()
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]) or p.is_symlink() or not p.is_file():
            continue
        if len(rel.parts) == 1 and p.name in SKIP_ROOT_FILES:
            continue
        if p.suffix.lower() not in exts:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            continue
        if digest in seen:
            continue
        seen.add(digest)
        found.append(p)
    return found


# ---------------------------------------------------------------------------- dataset assembly


@dataclass
class Dataset:
    features: list[str]
    target: str
    X: list[list[Fraction]]
    y: list[Fraction]
    row_labels: list[str]
    probes: list[list[Fraction]]
    probe_labels: list[str]
    history_from: list[str]
    probes_from: list[str]
    order_by: str | None
    notes: list[str] = field(default_factory=list)


def _cell(t: Table, r: list, c: str):
    j = t.col(c)
    return r[j] if j < len(r) else None


def _blank(cell) -> bool:
    return cell is None or (isinstance(cell, str) and not cell.strip())


def _guess_target(tables: list[Table], numeric: dict[str, list[str]]) -> tuple[str | None, str]:
    """The target column: in a history table but not in the probe table that has the rest."""
    skip = set(ORDER_NAMES) | set(ID_NAMES)
    found = []
    for a in tables:
        for b in tables:
            if a is b:
                continue
            nb = set(numeric[b.name]) - skip
            if not nb or not nb <= set(a.columns):
                continue
            extra = [c for c in numeric[a.name] if c not in b.columns and c not in skip]
            for c in extra:
                if c not in found:
                    found.append(c)
    if len(found) == 1:
        return found[0], f"target {found[0]!r}: the one numeric column the history has and the probes lack"
    if len(found) > 1:
        named = [c for c in found if c in TARGET_NAMES]
        if len(named) == 1:
            return named[0], (f"target {named[0]!r}: the score-like name among the history-only columns "
                              + ", ".join(found))
        return None, ("several columns could be the target (" + ", ".join(found) +
                      "): pass --opt target=COLUMN")
    for t in tables:
        for c in t.columns:
            if c in TARGET_NAMES and c in numeric[t.name]:
                # a target-named column that is blank in some rows or absent from another table
                return c, f"target {c!r}: by its name"
    return None, "no target column found (no history/probe pair, no score-like name): pass --opt target=COLUMN"


def _sort_key(cell):
    v = to_fraction(cell)
    return (0, v, "") if v is not None else (1, Fraction(0), "" if cell is None else str(cell))


def assemble(tables: list[Table], *, target: str | None = None, features: Sequence[str] | None = None,
             exclude: Sequence[str] = (), order: str | None = None, keep_id_columns: bool = False) -> Dataset:
    """Pick the target, the feature columns, the ordered history rows and the probe rows.

    History rows are the rows with a numeric target; probe rows are rows of a table without
    the target column, or with it blank.  ``order`` is a column to sort the history by,
    ``"file"`` for file order, ``None`` to sort by a time-like column when there is exactly one.
    """
    if not tables:
        raise TabularError("no tables")
    numeric = {t.name: t.numeric_columns() for t in tables}
    notes = []
    if target:
        target = _norm(target)
        if not any(target in t.columns for t in tables):
            raise TabularError(f"target column {target!r} is in no table")
        why = f"target {target!r}: given"
    else:
        target, why = _guess_target(tables, numeric)
        if target is None:
            raise TabularError(why)
    notes.append(why)
    hist = [t for t in tables if target in t.columns and any(not _blank(_cell(t, r, target)) for r in t.rows)]
    if not hist:
        raise TabularError(f"no table has values in the target column {target!r}")
    for t in hist:
        if target not in numeric[t.name]:
            raise TabularError(f"{t.name}: target column {target!r} is not numeric")
    excl = {_norm(c) for c in exclude}
    if features:
        feats = [_norm(c) for c in features]
        for t in hist:
            missing = [c for c in feats if c not in numeric[t.name]]
            if missing:
                raise TabularError(f"{t.name}: feature column(s) {', '.join(missing)} missing or not numeric")
    else:
        common = [c for c in numeric[hist[0].name] if all(c in numeric[t.name] for t in hist[1:])]
        skip = excl | {target} | (set() if keep_id_columns else set(ORDER_NAMES) | set(ID_NAMES))
        feats = [c for c in common if c not in skip]
    others = [t for t in tables if t not in hist and set(feats) & set(t.columns)]
    if not features and others:
        narrowed = [c for c in feats if all(c in numeric[t.name] for t in others)]
        if narrowed != feats:
            notes.append("features narrowed to the columns the probes carry: dropped " +
                          ", ".join(c for c in feats if c not in narrowed))
            feats = narrowed
    probe_tables = [t for t in others if all(c in t.columns for c in feats)]
    probe_tables += [t for t in hist if any(_blank(_cell(t, r, target)) for r in t.rows)]
    if not feats:
        raise TabularError("no numeric feature columns besides the target")

    # Order the history.
    order_col = None
    if order and order != "file":
        order_col = _norm(order)
        if not all(order_col in t.columns for t in hist):
            raise TabularError(f"order column {order_col!r} is not in every history table")
    elif order is None:
        timeish = [c for c in hist[0].columns if c in ORDER_NAMES and all(c in t.columns for t in hist)]
        if len(timeish) == 1:
            order_col = timeish[0]
        elif len(timeish) > 1:
            notes.append("several time-like columns (" + ", ".join(timeish) +
                         "): history kept in file order; pass --opt order=COLUMN")
    rows = []
    for t in hist:
        for i, r in enumerate(t.rows):
            yv = _cell(t, r, target)
            if _blank(yv):
                continue
            xs = [to_fraction(_cell(t, r, c)) for c in feats]
            if any(v is None for v in xs):
                bad = [c for c, v in zip(feats, xs) if v is None]
                raise TabularError(f"{t.name} row {i + 1}: blank feature(s) {', '.join(bad)} in a history row")
            label = f"{t.name}#{i + 1}"
            idc = next((c for c in t.columns if c in ID_NAMES or c in ORDER_NAMES), None)
            if idc is not None and not _blank(_cell(t, r, idc)):
                label += f" ({idc}={_cell(t, r, idc)})"
            key = _sort_key(_cell(t, r, order_col)) if order_col else None
            rows.append((key, xs, to_fraction(yv), label))
    if order_col:
        rows.sort(key=lambda r: r[0])                # stable: ties keep file order
        notes.append(f"history ordered by {order_col!r}")
    if len(hist) > 1:
        notes.append("history concatenated from " + ", ".join(t.name for t in hist))

    probes, plabels, pfrom = [], [], []
    for t in probe_tables:
        took = 0
        for i, r in enumerate(t.rows):
            if target in t.columns and not _blank(_cell(t, r, target)):
                continue
            xs = [to_fraction(_cell(t, r, c)) for c in feats]
            if any(v is None for v in xs):
                if all(v is None for v in xs):
                    continue
                bad = [c for c, v in zip(feats, xs) if v is None]
                raise TabularError(f"{t.name} row {i + 1}: blank feature(s) {', '.join(bad)} in a probe row")
            probes.append(xs)
            plabels.append(f"{t.name}#{i + 1}")
            took += 1
        if took:
            pfrom.append(t.name)
    if len(pfrom) > 1:
        notes.append("probes concatenated in name order from " + ", ".join(pfrom))
    return Dataset(features=feats, target=target, X=[r[1] for r in rows], y=[r[2] for r in rows],
                   row_labels=[r[3] for r in rows], probes=probes, probe_labels=plabels,
                   history_from=[t.name for t in hist], probes_from=pfrom, order_by=order_col, notes=notes)


def load_tables(challenge_dir: Path) -> tuple[list[Table], list[str]]:
    """Every CSV/TSV/NPZ table in the challenge, plus a note per file that could not be read."""
    tables, notes = [], []
    for p in find_files(challenge_dir, TABLE_EXTS):
        try:
            if p.suffix.lower() == ".npz":
                got = read_npz(p)
                tables.extend(got)
                notes.extend(n for t in got for n in t.notes)
            else:
                tables.append(read_csv(p))
        except TabularError as exc:
            notes.append(f"skipped {exc}")
    return tables, notes


def load_readme_text(challenge_dir: Path) -> tuple[str, list[str]]:
    """README* files first, then the other handout .txt/.md files (each cut at 64 KiB)."""
    files = find_files(challenge_dir, (".txt", ".md", ".rst", ""))
    files = [p for p in files if p.suffix.lower() in (".txt", ".md", ".rst") or p.name.lower().startswith("readme")]
    readmes = [p for p in files if p.name.lower().startswith("readme")]
    files = readmes or files          # a README, when there is one, is the only hint source
    parts, names = [], []
    for p in files:
        try:
            with open(p, "rb") as fh:
                parts.append(fh.read(MAX_TEXT_BYTES).decode("utf-8", "replace"))
            names.append(p.name)
        except OSError:
            continue
    return "\n".join(parts), names


# ---------------------------------------------------------------------------- solve


def _parse_join(value: str) -> str:
    v = str(value)
    named = {"newline": "\n", "lf": "\n", "\\n": "\n", "crlf": "\r\n", "\\r\\n": "\r\n", "comma": ",",
             "space": " ", "tab": "\t", "\\t": "\t", "none": "", "empty": "", "nothing": ""}
    return named.get(v.lower(), v)


def _parse_bool(value, name: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} option {value!r}: expected true or false")


def _parse_int(value, name: str, lo: int = 0) -> int:
    try:
        v = int(str(value).strip())
    except ValueError:
        raise ValueError(f"{name} option {value!r}: expected an integer") from None
    if v < lo:
        raise ValueError(f"{name} option {value!r}: must be >= {lo}")
    return v


def fixed_params(opts: dict) -> dict:
    """The fingerprint parameters the caller pinned (``decimals``, ``rounding``, ...), validated."""
    out = {}
    if "decimals" in opts:
        out["decimals"] = _parse_int(opts["decimals"], "decimals")
    if "rounding" in opts:
        if opts["rounding"] not in ROUNDINGS:
            raise ValueError(f"rounding option {opts['rounding']!r}: use one of {', '.join(ROUNDINGS)}")
        out["rounding"] = opts["rounding"]
    if "render" in opts:
        if opts["render"] not in RENDERS:
            raise ValueError(f"render option {opts['render']!r}: use one of {', '.join(RENDERS)}")
        out["render"] = opts["render"]
    if "join" in opts:
        out["join"] = _parse_join(opts["join"])
    if "trailing" in opts:
        out["trailing"] = _parse_bool(opts["trailing"], "trailing")
    if "hash" in opts:
        h = str(opts["hash"]).lower().replace("-", "")
        h = {"sha3256": "sha3_256", "sha3512": "sha3_512"}.get(h, h)
        if h not in HASHES:
            raise ValueError(f"hash option {opts['hash']!r}: use one of {', '.join(HASHES)}")
        out["hash"] = h
    if "hexcase" in opts:
        if opts["hexcase"] not in ("lower", "upper"):
            raise ValueError(f"hexcase option {opts['hexcase']!r}: use lower or upper")
        out["hexcase"] = opts["hexcase"]
    return out


def _split_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [v for v in (s.strip() for s in str(value).split(",")) if v]


def solve(challenge_dir, profile, **opts) -> SolverResult:
    """Fit the history piecewise exactly, score the probes with the latest rule, rank fingerprints.

    Options (all strings work, as ``ctf run --opt`` passes them): ``target``, ``features`` and
    ``exclude`` (comma lists), ``order`` (a column, or ``file``), ``intercept`` (default true),
    ``max_segments`` (8), ``changes`` (the change-point count the README states: a mismatch is
    ``unsure``), ``min_check_rows`` (2), ``max_candidates`` (8), and the fingerprint parameters
    ``decimals``, ``rounding``, ``render``, ``join``, ``trailing``, ``hash``, ``hexcase``.

    Status: ``candidate`` with the ranked fingerprints (best first) when every probe is scored
    by a verified latest rule; ``unsure`` when the rule is found but cannot be trusted or applied
    (too few spare rows, an undetermined probe, a change count that disagrees, no probes);
    ``none`` when there is no history/probe table or no exact piecewise fit; ``blocked`` when an
    option is malformed or a needed reader (numpy, for NPZ) is missing.  The ``profile`` is not
    used to wrap the digest: the README, not the event, defines the answer form.
    """
    t0 = time.process_time()
    cid = opts.get("challenge_id")

    def result(status, **kw):
        return SolverResult(status, engine=ENGINE, challenge_id=cid,
                            cost=Cost(seconds=round(time.process_time() - t0, 3)), **kw)

    try:
        fixed = fixed_params(opts)
        intercept = _parse_bool(opts.get("intercept", True), "intercept")
        max_segments = _parse_int(opts.get("max_segments", DEFAULT_MAX_SEGMENTS), "max_segments", 1)
        min_check = _parse_int(opts.get("min_check_rows", DEFAULT_MIN_CHECK_ROWS), "min_check_rows")
        max_cands = _parse_int(opts.get("max_candidates", DEFAULT_MAX_CANDIDATES), "max_candidates", 1)
        changes = _parse_int(opts["changes"], "changes") if "changes" in opts else None
    except ValueError as exc:
        return result("blocked", notes=str(exc))

    challenge_dir = Path(challenge_dir)
    tables, notes = load_tables(challenge_dir)
    blocked_numpy = [n for n in notes if "numpy is required" in n]
    if not tables:
        if blocked_numpy:
            return result("blocked", notes="; ".join(notes))
        return result("none", notes="; ".join(["no CSV/TSV/NPZ table in the challenge files"] + notes))

    user_feats = _split_list(opts.get("features"))
    try:
        ds = assemble(tables, target=opts.get("target"), features=user_feats or None,
                      exclude=_split_list(opts.get("exclude")), order=opts.get("order"))
    except TabularError as exc:
        return result("none", notes="; ".join(notes + [f"no fit problem: {exc}"]))
    notes += ds.notes

    try:
        segs = find_segments(ds.X, ds.y, intercept=intercept, max_segments=max_segments)
    except NoExactFit as exc:
        if user_feats:
            return result("none", notes="; ".join(notes + [str(exc)]))
        # The id/time-like columns were left out on a guess; try once with them, and say so.
        try:
            ds2 = assemble(tables, target=opts.get("target"), exclude=_split_list(opts.get("exclude")),
                           order=opts.get("order"), keep_id_columns=True)
        except TabularError:
            ds2 = None
        if ds2 is None or ds2.features == ds.features:
            return result("none", notes="; ".join(notes + [str(exc)]))
        try:
            segs = find_segments(ds2.X, ds2.y, intercept=intercept, max_segments=max_segments)
        except NoExactFit as exc2:
            return result("none", notes="; ".join(notes + [str(exc), f"with id/time columns as features too: {exc2}"]))
        notes.append("no exact fit without the id/time-like columns; they are features here")
        ds = ds2

    names = (["intercept"] if intercept else []) + ds.features
    evidence = []
    rel = ",".join(ds.history_from)
    for k, s in enumerate(segs):
        coef = ", ".join(f"{n}={fmt_fraction(c)}" for n, c in zip(names, s.fit.coef))
        where = (f"rows {s.start}..{s.end - 1} ({ds.row_labels[s.start]} .. {ds.row_labels[s.end - 1]})")
        extra = []
        if k and s.slack:
            extra.append(f"change point anywhere in rows {s.start}..{s.start + s.slack}: "
                         f"{s.slack} row(s) fit both rules")
        if not s.fit.unique:
            extra.append(f"underdetermined: rank {s.fit.rank} of {s.fit.unknowns}")
        evidence.append(Evidence("fit", f"segment {k + 1}/{len(segs)} {where}, zero residual on all "
                                        f"{s.rows} rows ({s.fit.spare} spare): {coef}"
                                        + ("; " + "; ".join(extra) if extra else ""), path=rel))
    latest = segs[-1]
    notes.append(f"{len(segs)} segment(s), {len(segs) - 1} change point(s) at row(s) "
                 + (", ".join(str(s.start) for s in segs[1:]) or "-")
                 + f"; features {', '.join(ds.features)}; target {ds.target}")
    doubts = []
    if latest.fit.spare < min_check:
        doubts.append(f"latest rule unverified: {latest.rows} rows for {latest.fit.rank} unknowns leave "
                      f"{latest.fit.spare} spare row(s) (< {min_check}), so a zero residual proves nothing "
                      f"and the change point may sit later")
    if len(segs) > 1 and all(s.fit.spare == 0 for s in segs):
        doubts.append(f"every one of the {len(segs)} segments has exactly as many rows as unknowns "
                      f"(0 spare): that is what noisy or rounded data looks like on a short history, "
                      f"not a sequence of rule changes")
    if changes is not None and changes != len(segs) - 1:
        doubts.append(f"found {len(segs) - 1} change point(s), the brief says {changes}")

    if not ds.probes:
        return result("unsure", evidence=tuple(evidence),
                      notes="; ".join(notes + doubts + ["no probe rows to score (a table without the "
                                                         "target, or rows with it blank)"]))
    scored = [latest.fit.predict(x) for x in ds.probes]
    undetermined = [ds.probe_labels[i] for i, (_, ok) in enumerate(scored) if not ok]
    if undetermined:
        doubts.append(f"{len(undetermined)} probe(s) not determined by the latest rows "
                      f"(rank-deficient fit): {', '.join(undetermined[:5])}")
    values = [v for v, _ in scored]
    shown = ", ".join(fmt_decimal(v) for v in values[:12]) + (" ..." if len(values) > 12 else "")
    evidence.append(Evidence("score", f"latest rule on {len(values)} probe row(s) from "
                                      f"{', '.join(ds.probes_from)}: {shown}", path=",".join(ds.probes_from)))
    if doubts:
        return result("unsure", evidence=tuple(evidence), notes="; ".join(notes + doubts))

    text, readmes = load_readme_text(challenge_dir)
    hints = readme_hints(text)
    if hints:
        notes.append("README hints (" + ", ".join(readmes[:3]) + "): " +
                     ", ".join(f"{k}={v.value!r}" for k, v in hints.items()))
    try:
        cands = fingerprint_candidates(values, fixed=fixed, hints=hints)
    except ValueError as exc:
        return result("blocked", notes="; ".join(notes + [str(exc)]))
    top = cands[:max_cands]
    for i, c in enumerate(top):
        evidence.append(Evidence("fingerprint", f"rank {i + 1}: {c.digest} = {c.describe()} "
                                                f"(first value hashed: {c.preview!r})"))
    pinned = len(fixed)
    notes.append(f"{len(cands)} distinct fingerprint form(s), top {len(top)} returned ranked; "
                 + ("all parameters pinned by options" if pinned == len(PARAMS) else
                    f"{pinned} of {len(PARAMS)} parameters pinned, the rest ranked by README hints "
                    f"then common forms -- read the README and pin them (--opt decimals=3 ...); "
                    f"none is picked"))
    return result("candidate", flags=tuple(c.digest for c in top), evidence=tuple(evidence),
                  notes="; ".join(notes))


__all__ = [
    "ExactSystem", "Fit", "Segment", "Table", "Dataset", "Candidate", "Hint",
    "TabularError", "NoExactFit",
    "to_fraction", "exact_fit", "find_segments", "quantize", "render_values", "fingerprint",
    "fingerprint_text", "fingerprint_candidates", "readme_hints", "read_csv", "read_npz",
    "find_files", "load_tables", "assemble", "fixed_params", "solve", "main",
]

_USAGE = "usage: tabular_fit.py <challenge dir | data file> [--event <slug>] [--opt key=value]..."


def main(argv) -> int:
    """Script entry: run :func:`solve` and print the SolverResult JSON (exit 0 candidate, 1 otherwise,
    2 on a usage or event error).  A data-file argument means its folder."""
    from ctf import event

    args = list(argv)
    target = slug = None
    opts: dict[str, str] = {}
    while args:
        a = args.pop(0)
        if a in ("--event", "--opt"):
            if not args:
                print(f"tabular_fit.py: {a} needs a value\n{_USAGE}", file=sys.stderr)
                return 2
            val = args.pop(0)
            if a == "--event":
                slug = val
            elif "=" not in val:
                print(f"tabular_fit.py: --opt {val!r} is not key=value\n{_USAGE}", file=sys.stderr)
                return 2
            else:
                k, v = val.split("=", 1)
                opts[k] = v
        elif a.startswith("-") or target is not None:
            print(f"tabular_fit.py: unexpected argument {a!r}\n{_USAGE}", file=sys.stderr)
            return 2
        else:
            target = a
    if target is None:
        print(_USAGE, file=sys.stderr)
        return 2
    path = Path(target)
    if not path.exists():
        print(f"tabular_fit.py: {target}: no such file or folder", file=sys.stderr)
        return 2
    challenge_dir = path.parent if path.is_file() else path
    try:
        profile = event.load(slug) if slug else event.current()
    except Exception as exc:   # noqa: BLE001 -- any profile failure is a named usage error
        print(f"tabular_fit.py: no event profile ({exc}); pass --event <slug>", file=sys.stderr)
        return 2
    res = solve(challenge_dir, profile, **opts)
    print(res.to_json())
    return 0 if res.status in ("solved", "candidate") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
