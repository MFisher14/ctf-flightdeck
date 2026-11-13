#!/usr/bin/env python3
"""Gradient-inversion solver: the training input behind a single-sample federated update in an .npz (B-092).

A federated client sends back an update computed on its own data. For a dense first layer
z = W x + b and ONE training sample, the update of that layer is dW = delta (outer) x and
db = delta, so every unit i with db[i] != 0 gives the input in closed form:

    x = dW[i] / db[i]

and all live units must give the same x. This engine finds such a pair in a NumPy archive without
trusting array names (they change per challenge), checks the units agree, and turns x into text.

  .venv/bin/python solvers/toolkits/federated_leakage.py <challenge dir | file.npz> [--event SLUG] [--opt k=v]...
  python -m ctf run toolkits.federated_leakage <challenge dir> [--opt k=v]...

What it does, in order:

1. Detect, statically: solvers/common/ai_model_files.read_npz reads the member headers (names,
   shapes, dtypes) with nothing loaded. An object array is refused by name and never loaded; the
   numeric arrays are then loaded with numpy.load(allow_pickle=False), so the file is data, never code.
2. Candidate (W, b) pairs by shape: every 2-D array against every 1-D array as long as one of its
   sides, read both ways (out x in, PyTorch; in x out, Keras). An update may be shipped as the
   gradient or step itself, or as old and new weights: same-shape arrays are also differenced
   (later minus earlier) and a weight difference is paired with a bias difference.
3. Ratio and agreement: W[i] / b[i] over the live units (|b[i]| >= LIVE_REL of the largest), the
   median as consensus, each unit within `tol` of it, at least `min_share` of them agreeing. Model
   weights, a batch of several samples and unrelated arrays fail here and are declined by name.
4. Rank by shape: the first layer is the agreeing pair whose input side is no other pair's output
   side; then the wider input, then archive order. Later layers recover hidden activations, not x.
5. Byte-scale decodes of x: x*255, x*256, x, x*127, x*128, (x+1)*127.5, x*128+128, each rounded and
   kept only when every value is within BYTE_TOL of an integer in 0..255 and the bytes (trailing
   NUL padding dropped) are printable text; failing those, a fitted scale (the largest value mapped
   to each printable byte in turn).
6. No bias update at all: the update matrix is still rank one, so the direction of x is closed
   form and only one scale is unknown. That scale is the one thing optimised (`match_scale`): the
   model in the archive (weights matched to updates by shape; ReLU hidden layers and softmax
   cross-entropy assumed, `--opt activation=`) is run at x = c * direction for every label and the
   c whose own gradient is a multiple of the observed update is kept, only when the fit is tight
   and the residual rises either side of it (a saturated model fits a range of scales: x then stays
   a direction). With no usable model the fitted byte scale still reads text.

Result: `solved` when the decoded text holds one value in the event flag format; `candidate` for
printable text that is not in the format (or several flags); `unsure` when an input was recovered
but is not text (it is saved as <out>/<file>.input.npy, with a PGM/PPM preview when its length is
a square image); `none` when no pair agrees (the best near-miss is named); `blocked` when numpy is
missing or every archive was refused. Nothing is submitted and nothing is executed.

Not covered (declined, never guessed): a convolutional or embedding first layer, a batch of more
than one sample, and a bias-free model whose layers cannot be told apart by shape.
"""
from __future__ import annotations

import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"

# ctf package import (a script run, as triage suggests it, needs the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(HERE.parents[1]))
    from ctf import flagfmt
from ctf.result import Cost, Evidence, SolverResult

ENGINE = "toolkits.federated_leakage"
MAX_FILE = 64 * 1024 * 1024       # bytes of one archive
MAX_FILES = 8                     # archives read per challenge
MAX_ARRAYS = 256                  # arrays read per archive
MAX_ELEMENTS = 4_000_000          # elements of one array
MAX_TOTAL_ELEMENTS = 16_000_000   # elements of one archive: arrays loaded plus differences made (128 MB of float64)
MAX_GROUP = 4                     # same-shape arrays differenced pairwise, at most
MAX_PAIRS = 2000                  # (W, b) candidates tried per archive
LIVE_REL = 1e-4                   # a unit is live when |b[i]| >= LIVE_REL * max|b|
AGREE_TOL = 1e-2                  # a unit agrees when its ratio is within this of the consensus (relative to max|x|)
MIN_SHARE = 0.8                   # share of the live units that must agree
RANK1_TOL = 1e-3                  # rank-one residual, relative to the largest entry
BYTE_TOL = 0.25                   # distance from an integer a named byte scale may leave
FIT_TOL = 0.1                     # the same for a fitted scale (tighter: the scale is a free parameter)
MIN_TEXT = 4                      # shortest text a named scale may report
MIN_FIT_TEXT = 6                  # shortest text a fitted scale may report ...
MIN_FIT_DISTINCT = 3              # ... with at least this many different byte values
MATCH_TOL = 1e-3                  # gradient matching: largest relative residual accepted
MAX_LABELS = 256                  # gradient matching: classes enumerated at most
MAX_MATCH_WORK = 2_000_000_000    # gradient matching: weight elements x labels x scales touched at most
MATCH_GRID = 161                  # gradient matching: scales tried per sign, log-spaced over 1e-4 .. 1e4
SCALES = (("x*255", 255.0, 0.0), ("x*256", 256.0, 0.0), ("x", 1.0, 0.0), ("x*127", 127.0, 0.0),
          ("x*128", 128.0, 0.0), ("(x+1)*127.5", 127.5, 127.5), ("x*128+128", 128.0, 128.0))
SKIP_DIRS = {"recon", ".git"}
_NUMERIC = re.compile(r"[<>|=]?[fiub]\d+$")


class Refused(ValueError):
    """The archive (or the run) cannot be used at all; the message names why."""


class NoLeak(ValueError):
    """These arrays are not a single-sample dense-layer update; the message names why. `share` is
    the share of live units that did agree, when the ratio got that far."""

    def __init__(self, message: str, share: float = -1.0):
        super().__init__(message)
        self.share = share


def _np():
    try:
        import numpy as np
    except ImportError as exc:                       # no silent fallback
        raise Refused("numpy is required (needs_tools py:numpy)") from exc
    return np


def _reader():
    """solvers/common/ai_model_files.py by file: the toolkits module of that name wins a flat import."""
    if str(COMMON) not in sys.path:
        sys.path.insert(1, str(COMMON))
    from _shadowed import common_module
    return common_module("ai_model_files")


# ---- reading the archive ----------------------------------------------------------------------------

def inspect_archive(data: bytes) -> list:
    """The arrays of an .npz, read statically (headers only, nothing loaded), in archive order:
    [{"name", "shape", "dtype", "numeric", "object"}]. Raises Refused when it is not an .npz."""
    rep = _reader().read_npz(data)
    if rep is None:
        raise Refused("not a NumPy .npz archive (a zip whose members are all readable .npy arrays)")
    out = []
    for a in rep["arrays"]:
        dtype = a["dtype"] if isinstance(a["dtype"], str) else str(a["dtype"])
        out.append({"name": a["name"], "shape": a["shape"], "dtype": dtype, "object": bool(a["object_array"]),
                    "numeric": not a["object_array"] and bool(_NUMERIC.match(dtype)) and a["shape"] is not None})
    return out


def load_arrays(path) -> tuple:
    """({name: float64 array, 1-D or 2-D}, notes, refused) of the numeric arrays in an .npz.

    `refused` names every array that was not loaded because loading it is not safe or not possible:
    an object array (never loaded; numpy.load runs with allow_pickle=False, so one the static reader
    missed is refused by numpy instead) or a member numpy cannot read. Vector-shaped arrays ((n,),
    (n, 1), (1, n)) come back 1-D, matrices 2-D; anything else is left out with a note. Raises
    Refused when the file is not a readable .npz."""
    np = _np()
    path = Path(path)
    try:
        size = path.stat().st_size
        if size > MAX_FILE:
            raise Refused(f"{size} bytes is over the {MAX_FILE} byte limit")
        data = path.read_bytes()
    except OSError as exc:
        raise Refused(f"unreadable: {type(exc).__name__}: {exc}") from exc
    listed = inspect_archive(data)
    arrays, notes = {}, []
    refused = [f"{a['name']} (object array: it would need allow_pickle)" for a in listed if a["object"]]
    skipped = [f"{a['name']} ({a['dtype']})" for a in listed if not a["numeric"] and not a["object"]]
    if len(listed) > MAX_ARRAYS:
        notes.append(f"only the first {MAX_ARRAYS} of {len(listed)} arrays were read")
    try:
        store = np.load(path, allow_pickle=False)
    except (ValueError, OSError, EOFError) as exc:
        raise Refused(f"numpy could not open it: {type(exc).__name__}: {exc}") from exc
    total = 0
    with store:
        for a in listed[:MAX_ARRAYS]:
            if not a["numeric"]:
                continue
            count = 1
            for d in a["shape"]:
                count *= int(d)
            if count > MAX_ELEMENTS:
                notes.append(f"{a['name']}: {count} elements is over the {MAX_ELEMENTS} limit, not read")
                continue
            if total + count > MAX_TOTAL_ELEMENTS:          # a hostile archive of compressible arrays
                notes.append(f"{a['name']}: not read, it would bring the archive to {total + count} elements, "
                             f"over the {MAX_TOTAL_ELEMENTS} total limit")
                continue
            try:
                arr = np.asarray(store[a["name"]])
            except (ValueError, KeyError, OSError, EOFError) as exc:     # incl. "Object arrays cannot be loaded"
                refused.append(f"{a['name']} (numpy refused it: {type(exc).__name__}: {str(exc)[:80]})")
                continue
            arr = arr.astype(np.float64)
            total += count
            if not np.all(np.isfinite(arr)):
                notes.append(f"{a['name']}: holds a non-finite value, left out")
                continue
            wide = tuple(d for d in arr.shape if d != 1)
            if len(wide) == 1 and wide[0] >= 2:
                arrays[a["name"]] = arr.reshape(-1)
            elif len(wide) == 2 and min(wide) >= 2:
                arrays[a["name"]] = arr.reshape(wide)
            else:
                notes.append(f"{a['name']}: shape {tuple(arr.shape)} is neither a dense-layer matrix nor a vector, left out")
    if refused:
        notes.insert(0, "refused, never loaded: " + ", ".join(refused))
    if skipped:
        notes.append("not numeric, left out: " + ", ".join(skipped))
    return arrays, notes, refused


# ---- the closed form ---------------------------------------------------------------------------------

@dataclass
class RatioFit:
    x: object                # the recovered input, one value per input feature
    live: int                # units with a usable bias update
    agree: int               # of those, units whose ratio matches the consensus
    spread: float            # largest deviation among the agreeing units, relative to max|x|


def ratio_recover(W, b, *, tol: float = AGREE_TOL, min_share: float = MIN_SHARE) -> RatioFit:
    """x from one dense layer's single-sample update: W[i] / b[i] over every unit with b[i] != 0.

    W is (units, inputs), b is (units,). The consensus is the median ratio; a unit agrees when its
    whole row is within `tol` of it (relative to max|x|). Raises NoLeak when the bias update is all
    zero, the ratio is all zero, or fewer than two units / `min_share` of the live units agree. A
    single live unit has nothing to agree with: it is returned with live == agree == 1 for the
    caller to mark unconfirmed. The returned x is the least-squares fit over the agreeing units."""
    np = _np()
    W = np.asarray(W, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64).reshape(-1)
    if W.ndim != 2 or W.shape[0] != b.shape[0]:
        raise NoLeak(f"shapes {W.shape} and {b.shape} are not a (units, inputs) matrix and its bias")
    peak = float(np.abs(b).max()) if b.size else 0.0
    if peak == 0.0:
        raise NoLeak("the bias update is all zero")
    live = np.flatnonzero(np.abs(b) >= LIVE_REL * peak)
    ratios = W[live] / b[live, None]
    consensus = np.median(ratios, axis=0)
    top = float(np.abs(consensus).max()) if consensus.size else 0.0
    if top == 0.0:
        raise NoLeak("the ratio is zero for every input")
    dev = np.abs(ratios - consensus).max(axis=1) / top
    ok = dev <= tol
    agree = int(ok.sum())
    if live.size >= 2 and (agree < 2 or agree < min_share * live.size):
        raise NoLeak(f"ratios disagree ({agree} of {live.size} live units within {tol:g})", share=agree / live.size)
    keep = live[ok]
    x = (b[keep] @ W[keep]) / float(b[keep] @ b[keep])
    return RatioFit(x=x, live=int(live.size), agree=agree, spread=float(dev[ok].max()))


def rank_one(M, *, tol: float = RANK1_TOL):
    """(u, r, live) with M = outer(u, r) to within `tol` of its largest entry, or None.

    A single-sample dense update is exactly this (u = delta, r = x) whether or not a bias was sent.
    None when M is not rank one, or when fewer than two rows or two columns carry it (one row or
    column is rank one by construction and proves nothing)."""
    np = _np()
    M = np.asarray(M, dtype=np.float64)
    if M.ndim != 2 or not M.size:
        return None
    peak = float(np.abs(M).max())
    if peak == 0.0:
        return None
    r = M[int(np.argmax((M * M).sum(axis=1)))]
    u = M @ r / float(r @ r)
    if float(np.abs(M - np.outer(u, r)).max()) > tol * peak:
        return None
    rows = int((np.abs(u) >= LIVE_REL * np.abs(u).max()).sum())
    cols = int((np.abs(r) >= LIVE_REL * np.abs(r).max()).sum())
    if rows < 2 or cols < 2:
        return None
    return u, r, rows


# ---- decoding x ---------------------------------------------------------------------------------------

def _as_text(np, y, tol: float):
    """The text of a vector of byte values, or None: every value within `tol` of an integer in
    0..255, trailing NUL padding dropped, the rest UTF-8 and printable."""
    r = np.rint(y)
    if not y.size or not np.all(np.isfinite(y)) or float(np.abs(y - r).max()) > tol or r.min() < 0 or r.max() > 255:
        return None
    raw = bytes(int(v) for v in r).rstrip(b"\x00")
    if len(raw) < MIN_TEXT:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if all(ch.isprintable() or ch in "\t\n\r" for ch in text) else None


def decode_bytes(x) -> list:
    """[(label, text)] for each named byte scale (SCALES) under which x is printable text."""
    np = _np()
    x = np.asarray(x, dtype=np.float64).reshape(-1)
    out = []
    for label, scale, offset in SCALES:
        text = _as_text(np, x * scale + offset, BYTE_TOL)
        if text is not None:
            out.append((label, text))
    return out


def fit_decode(x) -> list:
    """[(label, text)] for a vector whose scale is unknown: the largest value is mapped to each
    printable byte in turn and the scale kept when every value lands on a printable byte. Several
    hits are several readings (a text of digits also reads at twice the scale); smallest first.
    A text under MIN_FIT_TEXT characters or MIN_FIT_DISTINCT different bytes is too easy to fit."""
    np = _np()
    x = np.asarray(x, dtype=np.float64).reshape(-1)
    top = float(x.max()) if x.size else 0.0
    if top <= 0.0:
        return []
    out = []
    for c in range(32, 127):
        y = x * (c / top)
        text = _as_text(np, y, FIT_TOL)
        if text is None or len(text) < MIN_FIT_TEXT or len(set(text)) < MIN_FIT_DISTINCT:
            continue
        out.append((f"fitted scale x*{c / top:.6g}", text))
    return out


# ---- the no-bias case: one scale, found by gradient matching ---------------------------------------

_ACTIVATIONS = {
    "relu": (lambda np, z: np.maximum(z, 0.0), lambda np, z: (z > 0).astype(np.float64)),
    "tanh": (lambda np, z: np.tanh(z), lambda np, z: 1.0 - np.tanh(z) ** 2),
    "sigmoid": (lambda np, z: 0.5 * (1.0 + np.tanh(0.5 * z)),            # the logistic function, overflow-free
                lambda np, z: (s := 0.5 * (1.0 + np.tanh(0.5 * z))) * (1.0 - s)),
    "linear": (lambda np, z: z, lambda np, z: np.ones_like(z)),
}


def _forward(np, x, layers, act):
    acts, zs = [x], []
    for W, b in layers:
        zs.append(W @ acts[-1] + (b if b is not None else 0.0))
        acts.append(act(np, zs[-1]))                          # the last one is never used: the output layer is linear
    z = zs[-1] - zs[-1].max()
    p = np.exp(z)
    return acts, zs, p / p.sum()


def model_gradients(x, layers, label: int, activation: str = "relu") -> list:
    """The weight gradient of every layer (units x inputs) for ONE sample (x, label): a dense chain
    [(W, b or None), ...], `activation` between layers, softmax cross-entropy on the last."""
    np = _np()
    act, dact = _ACTIVATIONS[activation]
    acts, zs, p = _forward(np, np.asarray(x, dtype=np.float64), layers, act)
    delta = p.copy()
    delta[label] -= 1.0
    out = [None] * len(layers)
    for k in range(len(layers) - 1, -1, -1):
        out[k] = np.outer(delta, acts[k])
        if k:
            delta = (layers[k][0].T @ delta) * dact(np, zs[k - 1])
    return out


def _golden(f, lo: float, hi: float, steps: int = 80) -> float:
    """The t in [lo, hi] golden-section search settles on for f (a minimum when f is unimodal there)."""
    phi = (5 ** 0.5 - 1) / 2
    a, b = hi - phi * (hi - lo), lo + phi * (hi - lo)
    fa, fb = f(a), f(b)
    for _ in range(steps):
        if fa < fb:
            hi, b, fb = b, a, fa
            a = hi - phi * (hi - lo)
            fa = f(a)
        else:
            lo, a, fa = a, b, fb
            b = lo + phi * (hi - lo)
            fb = f(b)
    return a if fa < fb else b


@dataclass
class Match:
    scale: float             # x = scale * direction
    label: int
    factor: float            # update = factor * gradient (1: the gradient; -lr: a step)
    residual: float          # |factor * gradient - update| / |update| at the match
    sharp: bool              # the residual rises clearly 2 % either side: the scale is pinned


def match_scale(direction, layers, updates, *, activation: str = "relu") -> Match:
    """The one free parameter of a bias-free single-sample update: the scale c of x = c * direction.

    `layers` is the model [(W, b or None)] from the updated layer on, `updates` the observed update
    of each layer (units x inputs) or None. For every label and both signs, c runs over a log grid
    (1e-4 .. 1e4 times the direction) and is refined by golden section; the residual is the distance
    between the observed updates and the best multiple of the model's own gradient at x. Raises
    NoLeak when `activation` is unknown, there are too many classes, the search would touch more
    than MAX_MATCH_WORK weight elements, or no c brings the residual under MATCH_TOL (the model, the
    activation or the loss is not the one that made the update)."""
    np = _np()
    if activation not in _ACTIVATIONS:
        raise NoLeak(f"unknown activation {activation!r} (known: {', '.join(sorted(_ACTIVATIONS))})")
    d = np.asarray(direction, dtype=np.float64)
    used = [k for k, u in enumerate(updates) if u is not None]
    if not used:
        raise NoLeak("no update to match")
    classes = layers[-1][0].shape[0]
    if classes > MAX_LABELS:
        raise NoLeak(f"{classes} classes is over the {MAX_LABELS} enumerated")
    work = (2 * MATCH_GRID + 100) * (1 + classes) * sum(int(W.size) for W, _ in layers)
    if work > MAX_MATCH_WORK:
        raise NoLeak(f"the model is too large to search ({work} weight elements to touch, limit {MAX_MATCH_WORK})")
    target = np.concatenate([np.asarray(updates[k], dtype=np.float64).ravel() for k in used])
    norm = float(np.linalg.norm(target))
    if norm == 0.0:
        raise NoLeak("the update is all zero")
    act, dact = _ACTIVATIONS[activation]

    def residuals(c):
        """(residual, factor) for every label at x = c * d: one forward pass, one backward per label."""
        acts, zs, p = _forward(np, c * d, layers, act)
        res = []
        for label in range(classes):
            delta = p.copy()
            delta[label] -= 1.0
            parts = {}
            for k in range(len(layers) - 1, used[0] - 1, -1):
                if k in used:
                    parts[k] = np.outer(delta, acts[k]).ravel()
                if k:
                    delta = (layers[k][0].T @ delta) * dact(np, zs[k - 1])
            g = np.concatenate([parts[k] for k in used])
            gg = float(g @ g)
            if gg == 0.0:
                res.append((1.0, 0.0))
                continue
            factor = float(g @ target) / gg
            res.append((float(np.linalg.norm(factor * g - target)) / norm, factor))
        return res

    grid = np.logspace(-4.0, 4.0, MATCH_GRID)
    best = (float("inf"), 0.0, 0, 0)                          # residual, signed c, label, grid index
    for sign in (1.0, -1.0):
        for i, c in enumerate(grid):
            for label, (res, _) in enumerate(residuals(sign * c)):
                if res < best[0]:
                    best = (res, sign * float(c), label, i)
    _, c0, label, i = best
    sign = 1.0 if c0 > 0 else -1.0
    lo, hi = np.log(grid[max(i - 1, 0)]), np.log(grid[min(i + 1, len(grid) - 1)])
    t = _golden(lambda t: residuals(sign * float(np.exp(t)))[label][0], lo, hi)
    c = sign * float(np.exp(t))
    res, factor = residuals(c)[label]
    if res > best[0]:                     # the refinement never makes it worse: ReLU kinks make the residual
        c, (res, factor) = c0, residuals(c0)[label]           # non-unimodal inside the bracket
    if res > MATCH_TOL:
        raise NoLeak(f"the model's own gradient never lines up with the update (best residual {res:.2g} at "
                     f"scale {c:.4g}, label {label}; assumed {activation} hidden layers and softmax cross-entropy)")
    floor = max(20.0 * res, 1e-6)
    sharp = residuals(c * 1.02)[label][0] >= floor and residuals(c / 1.02)[label][0] >= floor
    return Match(scale=c, label=label, factor=factor, residual=res, sharp=sharp)


# ---- candidates, ranking -------------------------------------------------------------------------------

@dataclass
class Source:
    name: str                # an array name, or "new - old" for a difference
    value: object
    parts: tuple             # the array name(s) it is made of; (later, earlier) for a difference
    order: int

    @property
    def diff(self) -> bool:
        return len(self.parts) == 2


@dataclass
class Recovery:
    w: Source
    b: Source | None
    layout: str              # "rows": W is units x inputs; "columns": inputs x units
    x: object
    out_dim: int
    live: int
    agree: int
    spread: float
    method: str = "W/b ratio"
    scale_known: bool = True
    sign_known: bool = True
    confirmed: bool = True   # False: one live unit only, so nothing agreed with it
    head: bool = False       # its input side is no other update's output side: the first layer
    decodes: list = field(default_factory=list)      # [(label, text, flags)]
    notes: list = field(default_factory=list)

    @property
    def in_dim(self) -> int:
        return int(self.x.shape[0])

    def describe(self) -> str:
        pair = f"{self.w.name} / {self.b.name}" if self.b is not None else self.w.name
        how = (f"{self.agree}/{self.live} live units agree (spread {self.spread:.1e})" if self.b is not None
               else f"rank one across {self.live} live units")
        return f"{pair} ({self.layout}, {self.in_dim} inputs, {self.out_dim} units): {self.method}, {how}"


def _sources(arrays, ndim: int, notes: list, budget: list) -> list:
    """Every array of that rank, then every difference (later minus earlier) of two same-shape ones,
    while budget[0] (elements left under MAX_TOTAL_ELEMENTS) covers it; each difference spends it."""
    names = [n for n, a in arrays.items() if a.ndim == ndim]
    out = [Source(n, arrays[n], (n,), i) for i, n in enumerate(names)]
    groups = {}
    for n in names:
        groups.setdefault(arrays[n].shape, []).append(n)
    for shape, members in groups.items():
        if len(members) > MAX_GROUP:
            notes.append(f"{len(members)} arrays of shape {shape}: over {MAX_GROUP}, their differences were not tried")
            continue
        size = int(arrays[members[0]].size)
        pairs = [(old, new) for i, old in enumerate(members) for new in members[i + 1:]]
        for k, (old, new) in enumerate(pairs):
            if size > budget[0]:
                notes.append(f"{len(pairs) - k} of {len(pairs)} differences of shape {shape} not tried: "
                             f"over the {MAX_TOTAL_ELEMENTS} element total")
                break
            budget[0] -= size
            out.append(Source(f"{new} - {old}", arrays[new] - arrays[old], (new, old), len(out)))
    return out


def _model_chain(np, arrays, mats, rank1, rec, taken_vectors) -> tuple:
    """(layers, updates, bias names, weight names) for gradient matching from the layer `rec` updates
    on, by shape alone.

    Weights are the 2-D arrays that are not rank one; each layer's update is the rank-one array (or
    difference of two weights) of its shape. The chain follows the one shape whose input side is the
    previous output side. A layer's bias is the one unused vector of its width, when only one layer
    has that width. Raises NoLeak when a layer has no weights or the shapes do not decide."""
    orient = (lambda a: a) if rec.layout == "rows" else (lambda a: a.T)
    dims = (lambda s: s) if rec.layout == "rows" else (lambda s: s[::-1])
    singles = {s.name for s in mats if not s.diff}
    weights = [n for n in singles if n not in rank1]
    weights.sort(key=list(arrays).index)

    def layer(shape):
        ws = [n for n in weights if arrays[n].shape == shape]
        if not ws:
            raise NoLeak(f"no model weights of shape {shape} beside the update")
        ups = [s for s in mats if s.name in rank1 and s.value.shape == shape and (not s.diff or set(s.parts) <= set(ws))]
        if len(ups) > 1:
            raise NoLeak(f"{len(ups)} candidate updates of shape {shape}: " + ", ".join(s.name for s in ups))
        up = ups[0] if ups else None
        if up is not None and up.diff:
            model = up.parts[1]
        elif len(ws) == 1:
            model = ws[0]
        else:
            raise NoLeak(f"{len(ws)} weight arrays of shape {shape} ({', '.join(ws)}): which one the update was computed on is not decided")
        return model, up

    shape = rec.w.value.shape
    chain, seen = [], set()
    while True:
        model, up = layer(shape)
        chain.append((model, up))
        seen.add(shape)
        width = dims(shape)[0]
        nxt = sorted({arrays[n].shape for n in weights if arrays[n].shape not in seen and dims(arrays[n].shape)[1] == width})
        if not nxt:
            break
        if len(nxt) > 1:
            raise NoLeak(f"the model chain is ambiguous after {model}: shapes {nxt} all take {width} inputs")
        shape = nxt[0]
    widths = [dims(arrays[m].shape)[0] for m, _ in chain]
    vectors = [n for n, a in arrays.items() if a.ndim == 1 and n not in taken_vectors]
    layers, updates, biased = [], [], []
    for (model, up), width in zip(chain, widths):
        cands = [n for n in vectors if arrays[n].shape[0] == width]
        bias = cands[0] if len(cands) == 1 and widths.count(width) == 1 else None
        if bias:
            biased.append(bias)
        layers.append((orient(arrays[model]), arrays[bias] if bias else None))
        updates.append(orient(up.value) if up is not None else None)
    return layers, updates, biased, [m for m, _ in chain]


def recover(arrays: dict, *, tol: float = AGREE_TOL, min_share: float = MIN_SHARE, activation: str = "relu",
            match: bool = True) -> tuple:
    """(recoveries, notes) for the arrays of one archive: every agreeing (W, b) pair, and every
    rank-one update with no bias, ranked first layer first. See the module docstring."""
    np = _np()
    notes = []
    budget = [MAX_TOTAL_ELEMENTS - sum(int(a.size) for a in arrays.values())]
    mats = _sources(arrays, 2, notes, budget)
    vecs = _sources(arrays, 1, notes, budget)
    recs, tried, near = [], 0, None
    for M in mats:
        for v in vecs:
            if M.diff != v.diff:                              # a gradient with a step would agree at the wrong scale
                continue
            for layout, W in (("rows", M.value), ("columns", M.value.T)):
                if W.shape[0] != v.value.shape[0]:
                    continue
                if tried >= MAX_PAIRS:
                    continue
                tried += 1
                try:
                    fit = ratio_recover(W, v.value, tol=tol, min_share=min_share)
                except NoLeak as exc:
                    if near is None or exc.share > near[0]:
                        near = (exc.share, f"{M.name} / {v.name}: {exc}")
                    continue
                rec = Recovery(w=M, b=v, layout=layout, x=fit.x, out_dim=int(W.shape[0]), live=fit.live,
                               agree=fit.agree, spread=fit.spread, sign_known=not M.diff, confirmed=fit.live >= 2)
                if not rec.confirmed:
                    rec.notes.append("one live unit only: nothing to agree with, unconfirmed")
                if M.diff:
                    rec.notes.append("update taken as the later array minus the earlier one; the sign is right "
                                     "when weights and biases are stored in the same order")
                recs.append(rec)
    if tried >= MAX_PAIRS:
        notes.append(f"stopped after {MAX_PAIRS} (W, b) candidates")

    rank1 = {}
    for M in mats:
        fac = rank_one(M.value)
        if fac is not None:
            rank1[M.name] = fac
    taken = {p for r in recs for p in r.w.parts}
    taken_vectors = {p for r in recs for p in r.b.parts}
    layouts = [lay for lay in ("rows", "columns") if not recs or any(r.layout == lay for r in recs)]
    bare = []
    for M in mats:
        if M.name not in rank1 or set(M.parts) & taken:
            continue
        u, r, live = rank1[M.name]
        for layout in layouts:
            x = r if layout == "rows" else u
            x = x / x[int(np.argmax(np.abs(x)))]              # largest entry +1: the scale is not known yet
            bare.append(Recovery(w=M, b=None, layout=layout, x=x, out_dim=int(M.value.shape[0 if layout == "rows" else 1]),
                                 live=live, agree=live, spread=0.0, method="no bias: rank-one direction",
                                 scale_known=False, sign_known=False))
    recs += bare
    for r in recs:
        r.head = not any(o.w is not r.w and o.layout == r.layout and o.out_dim == r.in_dim for o in recs)
    for r in bare:
        if not (match and r.head):
            continue
        try:
            layers, updates, biased, models = _model_chain(np, arrays, mats, rank1, r, taken_vectors)
            tries = [(layers, biased)] + ([([(W, None) for W, _ in layers], [])] if biased else [])
            found, why = None, None
            for ls, bs in tries:
                try:
                    m = match_scale(r.x, ls, updates, activation=activation)
                except NoLeak as exc:
                    why = why or exc
                    continue
                if found is None or m.residual < found[0].residual:
                    found = (m, bs)
            if found is None:
                raise why
        except NoLeak as exc:
            r.notes.append(f"scale not fixed by gradient matching: {exc}")
            continue
        m, bs = found
        said = (f"gradient matching on model {' -> '.join(models)}" + (f" with bias {', '.join(bs)}" if bs else " (no bias)")
                + f": scale {m.scale:.6g}, label {m.label}, update = {m.factor:.4g} x gradient, residual {m.residual:.1e}")
        if not m.sharp:                                       # a saturated model fits a whole range of scales
            r.notes.append(said + "; the residual is flat around that scale, so the scale is NOT pinned and x stays a direction")
            continue
        r.x = r.x * m.scale
        r.scale_known = r.sign_known = True
        r.method = "no bias: rank-one direction + gradient matching"
        r.notes.append(said)
    recs.sort(key=lambda r: (not r.head, -r.in_dim, r.w.order))       # stable: ratio pairs stay ahead of bare ones
    if not recs and near is not None:
        notes.append("no (W, b) pair agreed; nearest: " + near[1])
    elif not recs:
        notes.append("no dense-layer (W, b) pair by shape" if mats else "no 2-D numeric array: not a model update")
    return recs, notes


def decode(rec: Recovery, ff) -> None:
    """Fill rec.decodes [(label, text, flags)]: the named byte scales, failing them a fitted one (the
    only one that can read a direction whose scale is unknown); x and -x when the sign is not known."""
    out = []
    for sign in ((1.0,) if rec.sign_known else (1.0, -1.0)):
        v = rec.x * sign
        hits = decode_bytes(v) or fit_decode(v)
        out += [(label + (" of -x" if sign < 0 else ""), text, tuple(ff.find_flags(text))) for label, text in hits]
    rec.decodes = out


# ---- one archive, one challenge -------------------------------------------------------------------------

@dataclass
class Report:
    file: str
    recoveries: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    refused: str | None = None
    written: list = field(default_factory=list)


def analyse(path, ff, *, name: str | None = None, **opts) -> Report:
    """Read one .npz and recover what it leaks. A refusal (not an .npz, numpy missing) is rep.refused."""
    rep = Report(file=name or Path(path).name)
    try:
        arrays, rep.notes, refused = load_arrays(path)
        if not arrays:
            if refused:                                       # nothing was loaded, and not for lack of arrays
                rep.refused = "nothing loadable: " + ", ".join(refused)
            else:
                rep.notes.append("no numeric dense-layer arrays")
            return rep
        recs, notes = recover(arrays, tol=float(opts.get("tol", AGREE_TOL)), min_share=float(opts.get("min_share", MIN_SHARE)),
                              activation=str(opts.get("activation", "relu")),
                              match=str(opts.get("match", "true")).lower() not in ("0", "false", "no", "off"))
    except Refused as exc:
        rep.refused = str(exc)
        return rep
    rep.notes += notes
    for r in recs:
        decode(r, ff)
    rep.recoveries = recs
    return rep


def _preview(np, x):
    """(suffix, bytes) of a PGM/PPM picture of x when its length is a square image (grey or RGB), else None."""
    n = int(x.shape[0])
    for channels, magic, suffix in ((1, b"P5", "pgm"), (3, b"P6", "ppm")):
        side = int(round((n / channels) ** 0.5))
        if side >= 8 and side * side * channels == n:
            lo, hi = float(x.min()), float(x.max())
            pix = np.zeros(n) if hi == lo else (x - lo) / (hi - lo) * 255.0
            if channels == 3:                                 # channel-first (3, h, w) is the usual layout
                pix = pix.reshape(3, side, side).transpose(1, 2, 0).reshape(-1)
            return suffix, magic + f"\n{side} {side}\n255\n".encode() + bytes(int(v) for v in np.rint(pix))
    return None


def save(rep: Report, out_dir: Path) -> None:
    """Write the best recovery of a report as <file>.input.npy (and a picture when it is image-sized)."""
    np = _np()
    if not rep.recoveries:
        return
    x = rep.recoveries[0].x
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", rep.file)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        p = out_dir / f"{stem}.input.npy"
        np.save(p, x, allow_pickle=False)
        rep.written.append(p)
        pic = _preview(np, x)
        if pic:
            q = out_dir / f"{stem}.input.{pic[0]}"
            q.write_bytes(pic[1])
            rep.written.append(q)
    except OSError as exc:
        rep.notes.append(f"recovered input not saved: {type(exc).__name__}: {exc}")


def result_of(reports: list, *, seconds: float = 0.0, challenge_id=None, root: Path | None = None) -> SolverResult:
    """The SolverResult of a set of reports (module docstring, "Result")."""
    def shown(p):
        try:
            return str(Path(p).relative_to(root)) if root else str(p)
        except ValueError:
            return str(p)

    cost = Cost(seconds=round(seconds, 3))
    flags, texts, evidence, notes = [], [], [], []
    recovered = False
    for rep in reports:
        if rep.refused:
            notes.append(f"{rep.file}: refused: {rep.refused}")
            continue
        notes += [f"{rep.file}: {n}" for n in rep.notes]
        for i, r in enumerate(rep.recoveries):
            recovered = True
            for label, text, found in r.decodes:
                evidence.append(Evidence("ratio" if r.b is not None else "rank-one",
                                         f"{r.describe()}; {label} -> {text.strip()!r}", path=rep.file))
                flags += [f for f in found if f not in flags]
                if text.strip() and text.strip() not in texts:
                    texts.append(text.strip())
            if i == 0 or r.decodes:
                notes.append(f"{rep.file}: {r.describe()}" + ("" if r.decodes else
                             f"; no byte-scale text (values {float(r.x.min()):.4g} .. {float(r.x.max()):.4g}"
                             + ("" if r.scale_known else ", scale unknown") + ")"))
                notes += [f"{rep.file}: {n}" for n in r.notes]
        notes += [f"{rep.file}: wrote {shown(p)}" for p in rep.written]
    note = "; ".join(notes)
    if flags:
        status = "solved" if len(flags) == 1 else "candidate"
        return SolverResult(status, flags=tuple(flags), evidence=tuple(evidence[:8]), engine=ENGINE,
                            challenge_id=challenge_id, cost=cost,
                            notes=note + ("" if len(flags) == 1 else "; several flags decoded: pick by the evidence"))
    if texts:
        return SolverResult("candidate", flags=tuple(texts[:3]), evidence=tuple(evidence[:8]), engine=ENGINE,
                            challenge_id=challenge_id, cost=cost,
                            notes=note + "; decoded text is not in the event flag format")
    if recovered:
        first = next(rep for rep in reports if rep.recoveries)
        ev = Evidence("ratio" if first.recoveries[0].b is not None else "rank-one", first.recoveries[0].describe(), path=first.file)
        return SolverResult("unsure", evidence=(ev,), engine=ENGINE, challenge_id=challenge_id, cost=cost,
                            notes=note + "; an input was recovered but it is not byte-scaled text: read the saved array")
    if reports and all(rep.refused for rep in reports):
        return SolverResult("blocked", engine=ENGINE, challenge_id=challenge_id, cost=cost, notes=note)
    return SolverResult("none", engine=ENGINE, challenge_id=challenge_id, cost=cost,
                        notes=note or "no .npz archive in the challenge files")


def find_archives(challenge_dir: Path) -> list:
    """The .npz files of a challenge: the sweep's scratch copy (`unpacked/`) when there is one, else
    `files/`, else the folder itself; recon output and links left out; sorted, at most MAX_FILES."""
    challenge_dir = Path(challenge_dir)
    if not challenge_dir.is_dir():
        raise FileNotFoundError(f"no such challenge folder: {challenge_dir}")
    root = next((challenge_dir / d for d in ("unpacked", "files") if (challenge_dir / d).is_dir()), challenge_dir)
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (here / d).is_symlink())
        for n in sorted(filenames):
            p = here / n
            if n.lower().endswith(".npz") and not p.is_symlink() and p.is_file():
                out.append(p)
    return out


def solve(challenge_dir: Path, profile, **opts) -> SolverResult:
    """Engine contract. opts: tol (unit agreement, default 1e-2), min_share (default 0.8), activation
    (relu | tanh | sigmoid | linear, the no-bias model), match (false: skip gradient matching), out
    (folder for the recovered input; default <challenge>/recon/federated_leakage), challenge_id."""
    t0 = time.monotonic()
    cid = opts.get("challenge_id")
    challenge_dir = Path(challenge_dir)
    try:
        _np()
    except Refused as exc:
        return SolverResult("blocked", engine=ENGINE, challenge_id=cid, notes=str(exc))
    ff = flagfmt.for_profile(profile)
    files = find_archives(challenge_dir)
    out_dir = Path(opts["out"]) if opts.get("out") else challenge_dir / "recon" / "federated_leakage"
    reports = []
    for p in files[:MAX_FILES]:
        rep = analyse(p, ff, name=str(p.relative_to(challenge_dir)), **opts)
        save(rep, out_dir)
        reports.append(rep)
    res = result_of(reports, seconds=time.monotonic() - t0, challenge_id=cid, root=challenge_dir)
    if len(files) > MAX_FILES:
        res = SolverResult(res.status, flags=res.flags, evidence=res.evidence, cost=res.cost, engine=ENGINE, challenge_id=cid,
                           notes=res.notes + f"; only the first {MAX_FILES} of {len(files)} .npz files were read")
    return res


_USAGE = "usage: federated_leakage.py <challenge dir | file.npz> [--event <slug>] [--out DIR] [--opt key=value]..."


def main(argv=None) -> int:
    """Script entry: a readable summary, then the SolverResult JSON as the last line. A file argument
    is read alone (nothing is written unless --out is given); a folder is solve(). Exit 0 for any
    result, 2 for a usage or event error."""
    from ctf import event

    args = list(sys.argv[1:] if argv is None else argv)
    target = slug = None
    opts = {}
    while args:
        a = args.pop(0)
        if a in ("--event", "--opt", "--out"):
            if not args:
                print(f"federated_leakage.py: {a} needs a value\n{_USAGE}", file=sys.stderr)
                return 2
            val = args.pop(0)
            if a == "--event":
                slug = val
            elif a == "--out":
                opts["out"] = val
            elif "=" not in val:
                print(f"federated_leakage.py: --opt {val!r} is not key=value\n{_USAGE}", file=sys.stderr)
                return 2
            else:
                k, v = val.split("=", 1)
                opts[k] = v
        elif a.startswith("-") or target is not None:
            print(f"federated_leakage.py: unexpected argument {a!r}\n{_USAGE}", file=sys.stderr)
            return 2
        else:
            target = Path(a)
    if target is None:
        print(_USAGE, file=sys.stderr)
        return 2
    if not target.exists():
        print(f"federated_leakage.py: {target} does not exist", file=sys.stderr)
        return 2
    try:
        profile = event.load(slug) if slug else event.current()
    except event.EventError as exc:
        print(f"federated_leakage.py: no event profile ({exc}); pass --event <slug>", file=sys.stderr)
        return 2
    if target.is_dir():
        res = solve(target, profile, **opts)
    else:
        t0 = time.monotonic()
        try:
            _np()
        except Refused as exc:
            res = SolverResult("blocked", engine=ENGINE, notes=str(exc))
        else:
            rep = analyse(target, flagfmt.for_profile(profile), **opts)
            if opts.get("out"):
                save(rep, Path(opts["out"]))
            res = result_of([rep], seconds=time.monotonic() - t0)
    for e in res.evidence:
        print(f"[{e.kind}] {e.path}: {e.detail}")
    for line in res.notes.split("; "):
        if line:
            print(f"note: {line}")
    print(res.to_json())
    return 0


__all__ = ["ENGINE", "Refused", "NoLeak", "RatioFit", "Match", "Recovery", "Report", "inspect_archive", "load_arrays",
           "ratio_recover", "rank_one", "decode_bytes", "fit_decode", "model_gradients", "match_scale", "recover",
           "analyse", "find_archives", "result_of", "solve", "main"]

if __name__ == "__main__":
    sys.exit(main())
