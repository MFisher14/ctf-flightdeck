"""Backdoored small-net trigger extractor: rebuild a saved MLP, flag its odd units, find the input it accepts (B-116).

The task: a challenge ships a small saved network (an "authenticator", a tampered classifier) and the
flag is the one input it was built or trained to accept. This engine does that without a model:

1. **Load** the weights with `_model_tensors` (safetensors, npz, npy, the PyTorch zip, JSON number
   lists). Nothing is unpickled or executed; a file is data.
2. **Rebuild** the dense layer chain from the tensor names and shapes (`build_mlp`): layer order,
   `(out, in)` or `(in, out)` orientation, biases, and the activation (ReLU unless a hint or
   `--opt activation=` says otherwise; with no hint tanh and sigmoid are tried after ReLU).
3. **Flag anomalous units** (`unit_anomalies`): units whose weight norm, peak weight, bias or outgoing
   weight is a robust outlier among the units of their layer, corroborated by
   `model_integrity_forensics.weight_outlier_report` run on the real per-unit numbers.
4. **Search** for the input that flips the classifier (`search`): for each way the input could
   encode text (bits as 0/1 or -1/+1, one value per character at the common scales, one-hot per
   character) and each output the net could be pushed to, coordinate ascent over the input under a
   leaky stand-in for the activation that is annealed to the real one. A detector net is flat almost
   everywhere under its real activation (dead ReLUs), which is why a plain search or gradient fails;
   the leaky stage lets every unit pull the input toward what it checks, the last stage is the real
   net.
5. **Read the units** (`unit_readoffs`): a tampered detector unit carries its trigger in the signs of
   its weights, so each first-layer unit is also read directly (per position, the value it weighs
   highest or lowest) and decoded.
6. **Verify and decode** (`extract`): every input found either way is run through the real forward
   pass, decoded (8/7-bit, MSB/LSB first, characters, one-hot alphabet) and scanned with the event
   flag format. A trigger is proof (`proven`) when the whole decoded input is one flag and the forward
   pass puts it on a side that at most RARE of random inputs reach.

Statuses: `solved` when exactly one flag is proven and it is pinned down: a unit's weights spell it,
or no single-position change of it is another accepted flag. `candidate` when the net also accepts
neighbouring flags and no unit decides, when several different flags are proven, when a flag is
spelled but the forward pass does not accept it, or while the event flag format is unknown (the
proven one first). `unsure` when an accepted rare input reads as text outside the flag format.
`none` when there is no small MLP or no such input. `blocked` when numpy is missing or a named
option is wrong. Never submits.

Not covered (named in the result, never guessed): convolutional or recurrent layers, embedding
layers, legacy torch pickles, Keras HDF5, and inputs that are images rather than text. A net that
was trained to accept a loose region around a string, rather than built or tampered to detect it,
is not inverted to that string: its best-scoring input need not be the one it was trained on.

Contract entry: `solve(challenge_dir, profile, **opts) -> SolverResult` (CONTRACTS 6-7). Options:
`activation` (relu | leaky_relu | tanh | sigmoid | identity), `alphabet` (the characters of a custom
one-hot alphabet, in index order), `budget_s` (CPU seconds, default 20), `seed` (of the random inputs
the acceptance rate is measured on), `max_inputs`.
"""
from __future__ import annotations

import hashlib
import importlib
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:                     # a direct script run: put the checkout root on sys.path
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt
from ctf.result import Cost, Evidence, SolverResult

# By their dotted names, so this engine, its sibling and the tests share one module object each
# whichever way they were imported first (a flat import of the same file would be a second object).
tensors_mod = importlib.import_module("solvers.toolkits._model_tensors")
integrity = importlib.import_module("solvers.toolkits.model_integrity_forensics")

ENGINE = "toolkits.model_trigger"
ACTIVATIONS = ("relu", "leaky_relu", "tanh", "sigmoid", "identity")
AUTO_ACTIVATIONS = ("relu", "tanh", "sigmoid")     # tried in this order when nothing names the activation
MODEL_SUFFIXES = (".npz", ".npy", ".safetensors", ".pt", ".pth", ".ckpt", ".bin", ".json")
SKIP_DIRS = {"recon", ".git", "__pycache__", "node_modules"}
MAX_LAYERS = 8
MAX_INPUTS = 16_384                 # input coordinates of a net this engine searches
MAX_CONTRIB = 40_000_000            # groups x choices x first-layer units held for one input encoding
MAX_TARGETS = 16
MAX_FILES = 24
MAX_CHALLENGE_BYTES = 768 * 1024 * 1024   # file bytes plus tensor bytes kept from one challenge's model files
DEFAULT_BUDGET = 20.0               # CPU seconds for one challenge
SCHEDULE = (1.0, 0.5, 0.25, 0.1, 0.03, 0.01, 0.0)   # leaky slope of the stand-in activation, annealed to the real one
MAX_SWEEPS = 24
RANDOM_SAMPLES = 512
RARE = 0.05                         # an input is "accepted" on a side at most this share of random inputs reach
ANOMALY_Z = 6.0                    # robust z (median/MAD) at which a unit statistic is an outlier
PRINTABLE = set(range(0x20, 0x7F))
CHAR_CODES = (0,) + tuple(range(0x20, 0x7F))        # one value per character: NUL padding, then printable ASCII
CHAR_SCALES = (("code/255", 1 / 255), ("code/256", 1 / 256), ("code/127", 1 / 127), ("code/128", 1 / 128),
               ("code", 1.0))
ONEHOT_ALPHABETS = {95: "".join(map(chr, range(0x20, 0x7F))), 128: "".join(map(chr, range(128))),
                    256: "".join(map(chr, range(256)))}

_BIAS_NAME = re.compile(r"bias|intercept|(?:^|[._/])b(?:[._]?\d+|[._][a-z]+)?(?::\d+)?$")
_WEIGHT_NAME = re.compile(r"weight|kernel|coef|(?:^|[._/])w(?:[._]?\d+|[._][a-z]+)?(?::\d+)?$")


class NetError(ValueError):
    """The tensors are not a dense layer chain this engine rebuilds; the message says why."""


class OptionError(ValueError):
    """A named option has a value the engine does not accept."""


def _np():
    import numpy
    return numpy


# ---- 1. the network ------------------------------------------------------------------------------------

@dataclass
class Layer:
    name: str
    W: object                       # (out, in) float64
    b: object                       # (out,) float64
    bias_name: str | None = None


@dataclass
class Net:
    layers: list
    activation: str = "relu"
    source: str = ""
    notes: list = field(default_factory=list)

    @property
    def n_in(self) -> int:
        return int(self.layers[0].W.shape[1])

    @property
    def n_out(self) -> int:
        return int(self.layers[-1].W.shape[0])

    @property
    def shape(self) -> str:
        return "-".join(str(d) for d in [self.n_in] + [int(l.W.shape[0]) for l in self.layers])

    def tail(self, Z1, alpha: float = 0.0):
        """Logits (N, out) from first-layer pre-activations Z1 (N, h1). `alpha` is the slope a ReLU
        lets through below zero: 0 is the real net, above 0 the leaky stand-in used while searching."""
        a = Z1
        for layer in self.layers[1:]:
            a = _activate(a, self.activation, alpha) @ layer.W.T + layer.b
        return a

    def forward(self, X):
        """Logits (N, out) of inputs X (N, n_in): the real forward pass."""
        np = _np()
        X = np.atleast_2d(np.asarray(X, dtype=np.float64))
        return self.tail(X @ self.layers[0].W.T + self.layers[0].b, 0.0)


def _activate(z, kind: str, alpha: float):
    np = _np()
    if kind == "relu":
        return np.where(z > 0, z, alpha * z)
    if kind == "leaky_relu":
        return np.where(z > 0, z, max(alpha, 0.01) * z)
    if kind == "tanh":
        return np.tanh(z)
    if kind == "sigmoid":
        return 1.0 / (1.0 + np.exp(-np.clip(z, -60, 60)))
    return z                                         # identity


def _natural(name: str):
    return [int(p) if p.isdigit() else p.lower() for p in re.split(r"(\d+)", name)]


def _is_bias_name(name: str) -> bool:
    return bool(_BIAS_NAME.search(name.lower()))


def _is_weight_name(name: str) -> bool:
    low = name.lower()
    return bool(_WEIGHT_NAME.search(low)) and not _is_bias_name(name)


def _stem(name: str) -> str:
    """The layer part of a tensor name: fc1.weight and fc1.bias, W2 and b2, share one."""
    low = re.sub(r":\d+$", "", name.lower())
    low = re.sub(r"weights?|kernel|coefs?_?|bias(?:es)?|intercepts?_?", "", low)
    low = re.sub(r"(?:^|(?<=[._/]))[wb](?=[._]?\d|[._]|$)", "", low)
    return re.sub(r"[._/]+", ".", low).strip(".")


def build_mlp(tensors: dict, activation: str = "relu", source: str = "") -> Net:
    """The dense chain in `tensors` ({name: ndarray}). NetError when there is none, or more than one
    reading fits and nothing in the names or biases decides."""
    np = _np()
    if activation not in ACTIVATIONS:
        raise OptionError(f"activation {activation!r} is not one of {', '.join(ACTIVATIONS)}")
    mats, vecs, notes = [], [], []
    for name in sorted(tensors, key=_natural):
        arr = np.asarray(tensors[name])
        if arr.dtype.kind not in "biuf":
            continue
        arr = arr.astype(np.float64)
        if arr.ndim >= 3 and arr.size:
            if _is_weight_name(name) or arr.ndim == 4:
                raise NetError(f"tensor {name!r} has shape {list(arr.shape)}: convolution or recurrent "
                               "layers are not rebuilt here")
            continue
        if arr.ndim == 2 and 1 in arr.shape and _is_bias_name(name):
            vecs.append((name, arr.reshape(-1)))
        elif arr.ndim == 2 and arr.size:
            mats.append((name, arr))
        elif arr.ndim == 1 and arr.size and _is_weight_name(name):
            mats.append((name, arr.reshape(1, -1)))             # an output weight vector
            notes.append(f"{name} is a vector with a weight name: read as a 1 x {arr.size} output layer")
        elif arr.ndim <= 1 and arr.size:
            vecs.append((name, arr.reshape(-1)))
    if not mats:
        raise NetError("no 2-D weight matrix among the tensors")
    if len(mats) > MAX_LAYERS:
        raise NetError(f"{len(mats)} weight matrices: more than the {MAX_LAYERS} dense layers this engine chains")
    named = all(_is_weight_name(n) for n, _ in mats)
    bias_for = {}                                                # matrix name -> (bias name, vector) by shared stem
    for bname, vec in vecs:
        for mname, _ in mats:
            if _stem(mname) == _stem(bname) and mname not in bias_for:
                bias_for[mname] = (bname, vec)
                break

    def orientations(order):
        """Every (out, in) orientation of the matrices in `order` whose dimensions chain."""
        found = []

        def walk(i, prev_out, picked):
            if i == len(order):
                found.append(list(picked))
                return
            name, m = order[i]
            for flip in ((False, True) if m.shape[0] != m.shape[1] else (False,)):
                w = m.T if flip else m
                if prev_out is not None and w.shape[1] != prev_out:
                    continue
                bias = bias_for.get(name)
                if bias is not None and bias[1].size != w.shape[0]:
                    continue                                     # its own bias says the other side is `out`
                picked.append((name, w, flip))
                walk(i + 1, w.shape[0], picked)
                picked.pop()

        walk(0, None, [])
        return found

    readings = orientations(mats)
    if not readings and len(mats) <= 6:                          # the names do not sort into layer order
        import itertools
        for perm in itertools.permutations(mats):
            got = orientations(list(perm))
            if got:
                readings.extend(got)
                notes.append("layer order taken from the shapes: the tensor names do not sort into a chain")
            if len(readings) > 8:
                break
    if not readings:
        raise NetError("the weight matrices do not chain into layers: " +
                       ", ".join(f"{n}{list(m.shape)}" for n, m in mats))

    def rank(reading):
        widths = [w.shape[1] for _n, w, _f in reading] + [reading[-1][1].shape[0]]
        return (widths[-1] > widths[0],                          # a net narrows from input to output
                any(f for _n, _w, f in reading))                 # then (out, in), the torch layout
    readings.sort(key=rank)
    if len(readings) > 1 and rank(readings[0]) == rank(readings[1]):
        raise NetError("more than one layer reading fits the shapes and nothing in the names or biases decides: " +
                       ", ".join(f"{n}{list(m.shape)}" for n, m in mats))
    if len(readings) > 1:
        notes.append("the shapes allow another orientation; taken: narrowing toward the output, else (out, in)")
    chosen = readings[0]
    free = [(n, v) for n, v in vecs if n not in {b[0] for b in bias_for.values()}]
    layers = []
    for name, w, flip in chosen:
        bias = bias_for.get(name)
        if bias is None:                                         # no shared stem: the next unused vector that fits
            hit = next((fv for fv in free if fv[1].size == w.shape[0]), None)
            if hit is not None:
                free.remove(hit)
                bias = hit
        if bias is None:
            notes.append(f"{name}: no bias vector of length {w.shape[0]} found; zero bias assumed")
            layers.append(Layer(name, np.ascontiguousarray(w), np.zeros(w.shape[0])))
        else:
            layers.append(Layer(name, np.ascontiguousarray(w), bias[1].astype(np.float64), bias[0]))
        if flip:
            notes.append(f"{name} is stored (in, out)")
        elif w.shape[0] == w.shape[1]:
            notes.append(f"{name} is square: (out, in) assumed")
    if not named and not any(l.bias_name for l in layers):
        raise NetError("matrices that chain, but no tensor is named like a weight and none has a bias: "
                       "not taken as a network")
    for name, _v in free:
        notes.append(f"{name}: not part of the dense chain, ignored")
    return Net(layers, activation, source, notes)


def activation_hint(tensor_set) -> str | None:
    """An activation the file itself names (a metadata value or a tensor name), else None."""
    words = [str(v) for v in (tensor_set.metadata or {}).values() if isinstance(v, str)] + list(tensor_set.tensors)
    text = " ".join(words).lower()
    for kind in ("leaky_relu", "sigmoid", "tanh", "relu"):
        if kind in text or kind.replace("_", "") in text:
            return kind
    return None


# ---- 2. anomalous units --------------------------------------------------------------------------------

def unit_anomalies(net: Net) -> dict:
    """Units whose statistics are robust outliers among the units of their layer.

    {"units": [{layer, layer_name, unit, stat, value, robust_z}], "integrity": weight_outlier_report over
    the same per-unit numbers}. A statistic is compared across one layer's units by median/MAD; a layer
    with fewer than 8 units, or no spread, is not judged. An outlier is a lead, not proof of tampering."""
    np = _np()
    units, rows = [], []
    for li, layer in enumerate(net.layers):
        w = layer.W
        stats = {"weight_norm": np.linalg.norm(w, axis=1), "peak_weight": np.abs(w).max(axis=1),
                 "bias": layer.b.copy()}
        if li + 1 < len(net.layers):
            stats["outgoing_norm"] = np.linalg.norm(net.layers[li + 1].W, axis=0)
        for stat, values in stats.items():
            if values.size <= integrity.MAX_DIMENSIONS:
                rows.append({"name": f"{layer.name}.{stat}", "values": [float(v) for v in values]})
            if values.size < 8:
                continue
            med = float(np.median(values))
            mad = float(np.median(np.abs(values - med)))
            if mad == 0:
                continue
            z = (values - med) / (1.4826 * mad)
            for unit in np.flatnonzero(np.abs(z) >= ANOMALY_Z):
                units.append({"layer": li, "layer_name": layer.name, "unit": int(unit), "stat": stat,
                              "value": float(values[unit]), "robust_z": float(z[unit])})
    units.sort(key=lambda u: -abs(u["robust_z"]))
    report = integrity.weight_outlier_report(rows) if rows else None
    return {"units": units, "integrity": report}


# ---- 3. input encodings --------------------------------------------------------------------------------

@dataclass
class Encoding:
    """One way the net's input could carry text: `groups` positions, each taking one of `choices`
    values. contrib[g, c] is what position g adds to the first layer's pre-activation under choice c."""
    name: str
    kind: str                       # bits | chars | onehot
    contrib: object                 # (groups, choices, h1)
    values: object = None           # bits: (lo, hi); chars: the scale; onehot: the alphabet string

    @property
    def groups(self) -> int:
        return int(self.contrib.shape[0])

    @property
    def choices(self) -> int:
        return int(self.contrib.shape[1])

    def z1(self, net: Net, choice):
        np = _np()
        return net.layers[0].b + self.contrib[np.arange(self.groups), choice].sum(axis=0)

    def vector(self, choice):
        """The input vector (n_in,) this choice stands for."""
        np = _np()
        choice = np.asarray(choice)
        if self.kind == "bits":
            return np.where(choice == 1, self.values[1], self.values[0]).astype(np.float64)
        if self.kind == "chars":
            return np.array([CHAR_CODES[c] for c in choice], dtype=np.float64) * self.values
        out = np.zeros(self.groups * self.choices)
        out[np.arange(self.groups) * self.choices + choice] = 1.0
        return out

    def decodes(self, choice) -> list:
        """[(decoder name, text)]: every reading of this choice as text."""
        np = _np()
        choice = np.asarray(choice)
        if self.kind == "chars":
            return [("one value per character", "".join(chr(CHAR_CODES[c]) for c in choice))]
        if self.kind == "onehot":
            return [(f"one-hot over {len(self.values)} characters", "".join(self.values[c] for c in choice))]
        out = []
        bits = choice.astype(np.uint8)
        for width in (8, 7):
            if bits.size % width or bits.size < width:
                continue
            rows = bits.reshape(-1, width)
            weights_msb = 1 << np.arange(width - 1, -1, -1)
            for label, weights in (("MSB first", weights_msb), ("LSB first", weights_msb[::-1])):
                out.append((f"{width}-bit {label}", "".join(chr(int(v)) for v in rows @ weights)))
        return out


def encodings_for(net: Net, alphabet: str | None = None) -> tuple:
    """([Encoding], [skipped reason]) for the net's input width, most common first."""
    np = _np()
    w1 = net.layers[0].W                                        # (h1, n)
    h1, n = w1.shape
    out, skipped = [], []

    def room(groups, choices, name):
        if groups * choices * h1 > MAX_CONTRIB:
            skipped.append(f"{name}: {groups} x {choices} x {h1} values is over the search table cap")
            return False
        return True

    if n % 8 == 0 or n % 7 == 0:
        for name, lo, hi in (("bits 0/1", 0.0, 1.0), ("bits -1/+1", -1.0, 1.0)):
            if room(n, 2, name):
                contrib = np.stack([lo * w1.T, hi * w1.T], axis=1)       # (n, 2, h1)
                out.append(Encoding(name, "bits", contrib, (lo, hi)))
    else:
        skipped.append(f"bits: {n} inputs is not a multiple of 8 or 7")
    alphabets = dict(ONEHOT_ALPHABETS)
    if alphabet:
        alphabets = {len(alphabet): alphabet, **{k: v for k, v in alphabets.items() if k != len(alphabet)}}
    for size, chars in alphabets.items():
        if n % size == 0 and n // size >= 2:
            name = f"one-hot x{size}"
            if room(n // size, size, name):
                out.append(Encoding(name, "onehot", np.ascontiguousarray(w1.T.reshape(n // size, size, h1)), chars))
    codes = np.array(CHAR_CODES, dtype=np.float64)
    for label, scale in CHAR_SCALES:
        name = f"characters ({label})"
        if room(n, len(CHAR_CODES), name):
            out.append(Encoding(name, "chars", w1.T[:, None, :] * (codes * scale)[None, :, None], scale))
    return out, skipped


# ---- 4. the search -------------------------------------------------------------------------------------

def _score(logits, target, strict: bool):
    """(N,) how far each row is on the target's side. A single output is pushed high or low; a class
    is scored against the best other class (strict, the real decision) or their mean (the stand-in)."""
    np = _np()
    side, index = target
    if logits.shape[1] == 1:
        return logits[:, 0] if side == "high" else -logits[:, 0]
    others = np.delete(logits, index, axis=1)
    return logits[:, index] - (others.max(axis=1) if strict else others.mean(axis=1))


def targets_for(net: Net) -> list:
    if net.n_out == 1:
        return [("high", 0), ("low", 0)]
    return [("class", c) for c in range(net.n_out)]


def _ascend(net: Net, enc: Encoding, target, choice, alpha: float, spent) -> tuple:
    """Coordinate ascent on the target score under leaky slope `alpha`: each position takes its best
    value with the others held, until a whole sweep changes nothing. Returns (choice, sweeps)."""
    np = _np()
    strict = alpha == 0.0
    contrib = enc.contrib
    z1 = enc.z1(net, choice)
    sweeps = 0
    for sweeps in range(1, MAX_SWEEPS + 1):
        changed = False
        for g in range(enc.groups):
            cand = (z1 - contrib[g, choice[g]])[None, :] + contrib[g]
            s = _score(net.tail(cand, alpha), target, strict)
            best = int(np.argmax(s))
            if best != choice[g] and s[best] > s[choice[g]] + 1e-12 * (1.0 + abs(float(s[choice[g]]))):
                choice[g] = best
                z1 = cand[best]
                changed = True
        if not changed or spent():
            break
        z1 = enc.z1(net, choice)                                 # drop the accumulated rounding
    return choice, sweeps


def search(net: Net, enc: Encoding, target, *, schedule=None, spent=lambda: False) -> dict:
    """The input (as a choice per position) the real net scores highest for `target`, by coordinate
    ascent from the all-first-choice input through `schedule` (default SCHEDULE): leaky slopes that
    end at 0, the real net. {"choice", "score"}: score is the real net's margin, > 0 on the target's
    side. Deterministic."""
    np = _np()
    schedule = SCHEDULE if schedule is None else tuple(schedule)
    choice = np.zeros(enc.groups, dtype=np.int64)
    for alpha in schedule:
        if net.activation not in ("relu", "leaky_relu") and alpha not in (schedule[0], 0.0):
            continue                                             # only a ReLU has a leak to anneal
        choice, _ = _ascend(net, enc, target, choice, alpha, spent)
    return {"choice": choice, "score": float(_score(net.tail(enc.z1(net, choice)[None, :], 0.0), target, True)[0])}


def random_rate(net: Net, enc: Encoding, target, *, seed: int = 0, samples: int = RANDOM_SAMPLES) -> float:
    """The share of random inputs of this encoding the real net already puts on the target's side."""
    np = _np()
    rng = np.random.default_rng(seed + 7919)
    hits = 0
    step = max(1, min(samples, 4_000_000 // max(1, enc.groups * enc.contrib.shape[2])))
    for at in range(0, samples, step):
        k = min(step, samples - at)
        pick = rng.integers(0, enc.choices, size=(k, enc.groups))
        z1 = net.layers[0].b + enc.contrib[np.arange(enc.groups)[None, :], pick].sum(axis=1)
        hits += int((_score(net.tail(z1, 0.0), target, True) > 0).sum())
    return hits / samples


# ---- 5. decode, verify, report -------------------------------------------------------------------------

def _printable(text: str) -> bool:
    return bool(text) and all(ord(ch) in PRINTABLE for ch in text)


def _flags_in(text: str, ff) -> list:
    """Printable flags of the event format in a decoded input (NUL padding dropped). While the
    event's prefixes are unknown the format itself matches any word prefix; the result is then capped
    at `candidate` by the caller."""
    return [f for f in ff.find_flags(text.replace("\x00", "")) if _printable(f)]


def _clean(text: str, flag: str) -> bool:
    """The decoded input is the flag and nothing else (padding aside): a flag-shaped run inside
    other characters is a partial reading, never proof."""
    return text.replace("\x00", "").strip() == flag


def _alternatives(net: Net, enc: Encoding, target, choice, decoder: str, flag: str, ff, cap: int = 4) -> list:
    """Other flags one position away that the real net also accepts, strongest first: when there is
    one, the net does not pin the string down and the result is a candidate."""
    np = _np()
    z1 = enc.z1(net, choice)
    found = {}
    for g in range(enc.groups):
        cand = (z1 - enc.contrib[g, choice[g]])[None, :] + enc.contrib[g]
        s = _score(net.tail(cand, 0.0), target, True)
        for c in np.flatnonzero(s > 0):
            if c == choice[g]:
                continue
            other = choice.copy()
            other[g] = c
            text = dict(enc.decodes(other)).get(decoder, "")
            for alt in _flags_in(text, ff):
                if alt != flag and _clean(text, alt) and s[c] > found.get(alt, -np.inf):
                    found[alt] = float(s[c])
    return [f for f, _s in sorted(found.items(), key=lambda kv: -kv[1])][:cap]


def _pinned(net: Net, enc: Encoding, target, choice) -> bool:
    """No single-position change of this input is also accepted: the net pins the input down."""
    np = _np()
    z1 = enc.z1(net, choice)
    for g in range(enc.groups):
        cand = (z1 - enc.contrib[g, choice[g]])[None, :] + enc.contrib[g]
        s = _score(net.tail(cand, 0.0), target, True)
        s[choice[g]] = -np.inf
        if (s > 0).any():
            return False
    return True


def proven(trigger: dict) -> bool:
    """A trigger entry that is proof of a flag: the whole decoded input is one flag, and the real
    forward pass puts that input on a side random inputs rarely reach."""
    return bool(trigger["flags"]) and trigger["clean"] and trigger["accepted"]


def _landing(net: Net, vector) -> tuple:
    """(target, margin) of the side the real forward pass puts one input vector on."""
    np = _np()
    logits = net.forward(vector)
    if net.n_out == 1:
        target = ("high", 0) if logits[0, 0] > 0 else ("low", 0)
    else:
        target = ("class", int(np.argmax(logits[0])))
    return target, float(_score(logits, target, True)[0])


def unit_readoffs(net: Net, enc: Encoding, ff, rate_of, anomalous=frozenset()) -> list:
    """Flags spelled by single first-layer units: per position, the value a unit weighs highest (or
    lowest). A tampered detector unit carries its trigger in the signs of its weights, whatever the
    rest of the net does with it. Each is run through the real forward pass: `accepted` means it
    lands on a side that at most RARE of random inputs reach. `rate_of(target)` gives that share."""
    np = _np()
    if enc.kind == "chars":
        return []                               # a per-character value has no sign pattern to read off
    out, seen = [], set()
    most = np.argmax(enc.contrib, axis=1)       # (groups, h1)
    least = np.argmin(enc.contrib, axis=1)
    for unit in range(most.shape[1]):
        if not np.any(net.layers[0].W[unit]):
            continue
        for polarity, table in (("highest", most), ("lowest", least)):
            choice = table[:, unit]
            for decoder, text in enc.decodes(choice):
                flags = _flags_in(text, ff)
                if not flags or (unit, flags[0]) in seen:
                    continue
                seen.add((unit, flags[0]))
                target, margin = _landing(net, enc.vector(choice))
                rate = rate_of(target)
                out.append({"source": "read-off", "unit": unit, "anomalous": unit in anomalous,
                            "polarity": polarity, "encoding": enc.name, "target": f"{target[0]} {target[1]}",
                            "decoder": decoder, "text": text, "flags": flags, "score": margin,
                            "clean": _clean(text, flags[0]),
                            "accepted": margin > 0 and rate <= RARE, "random_rate": rate,
                            "alternatives": []})
    return out


def extract(net: Net, ff, *, seed: int = 0, alphabet: str | None = None, spent=lambda: False,
            anomalies: list | None = None) -> dict:
    """Search every input encoding and target of `net`; decode and verify what is found.

    {"triggers": [...], "skipped": [...], "complete": bool}. A trigger is {source (search | read-off),
    unit, encoding, target, decoder, text, flags, clean, score, accepted, random_rate,
    alternatives}. `score` and `accepted` come from the real forward pass of the rebuilt input vector, not from
    the search's own bookkeeping; `accepted` also needs the side to be rare (at most RARE of random
    inputs); `clean` says the decoded input is the flag and nothing else. `proven(t)` is all three."""
    encs, skipped = encodings_for(net, alphabet)
    targets = targets_for(net)
    if len(targets) > MAX_TARGETS:
        skipped.append(f"{len(targets)} classes: only the first {MAX_TARGETS} were searched")
        targets = targets[:MAX_TARGETS]
    anomalous = frozenset(a["unit"] for a in (anomalies or []) if a["layer"] == 0)
    triggers, complete = [], True
    for index, enc in enumerate(encs):
        rates = {}

        def rate_of(target, enc=enc, rates=rates):
            if target not in rates:
                rates[target] = random_rate(net, enc, target, seed=seed)
            return rates[target]

        if spent():
            complete = False
            skipped.append(f"{enc.name}: CPU budget spent before it was searched")
            continue
        triggers.extend(unit_readoffs(net, enc, ff, rate_of, anomalous))
        for target in targets:
            if spent():
                complete = False
                skipped.append(f"{enc.name}, target {target[0]} {target[1]}: CPU budget spent before it was searched")
                continue
            found = search(net, enc, target, spent=spent)
            choice = found["choice"]
            real = float(_score(net.forward(enc.vector(choice)), target, True)[0])
            entry = {"source": "search", "unit": None, "anomalous": False, "encoding": enc.name,
                     "target": f"{target[0]} {target[1]}", "score": real, "accepted": False,
                     "decoder": None, "text": None, "flags": [], "alternatives": [],
                     "random_rate": None, "clean": False}
            readings = enc.decodes(choice)
            for decoder, text in readings:
                flags = _flags_in(text, ff)
                if flags:
                    entry.update(decoder=decoder, text=text, flags=flags, clean=_clean(text, flags[0]))
                    break
            else:
                clean = [(d, t.replace("\x00", "")) for d, t in readings]
                clean = [(d, t) for d, t in clean if len(t) >= 4 and _printable(t)]
                if clean:
                    entry.update(decoder=clean[0][0], text=clean[0][1])
            if real > 0 and entry["text"] is not None:
                entry["random_rate"] = rate_of(target)
                entry["accepted"] = entry["random_rate"] <= RARE
                if entry["accepted"] and not entry["flags"] and enc.kind != "bits" \
                        and not _pinned(net, enc, target, choice):
                    # every input of a per-character encoding is printable, so text alone says nothing:
                    # it counts only when the net pins that exact text down
                    entry.update(text=None, decoder=None)
                if entry["clean"] and entry["accepted"]:
                    entry["alternatives"] = _alternatives(net, enc, target, choice, entry["decoder"],
                                                          entry["flags"][0], ff)
            triggers.append(entry)
        if any(proven(t) and (t["source"] == "read-off" or not t["alternatives"]) for t in triggers):
            rest = [e.name for e in encs[index + 1:]]
            if rest:
                skipped.append("not searched after an accepted flag was found: " + ", ".join(rest))
            break
    triggers.sort(key=lambda t: (not proven(t), not bool(t["flags"]), not t["accepted"],
                                 t["source"] != "read-off", -t["score"]))
    return {"triggers": triggers, "skipped": skipped, "complete": complete}


# ---- 6. files and the contract entry -------------------------------------------------------------------

def find_model_sets(challenge_dir) -> tuple:
    """([TensorSet], [note]) for the small model files under a challenge folder. Loose .npy files in
    one folder are one set (W1.npy, b1.npy, ...). Copies of one file (files/ and unpacked/) are read once.
    A symlink is never followed (it could point outside the challenge folder). What is kept is capped at
    MAX_CHALLENGE_BYTES (each file's bytes plus its tensors'): a file past it is dropped with a note."""
    root = Path(challenge_dir)
    sets, notes, seen, loose = [], [], set(), {}
    kept = 0
    paths = []
    if root.is_file():
        paths = [root]
    else:
        for p in sorted(root.rglob("*")):
            if p.suffix.lower() not in MODEL_SUFFIXES or set(p.relative_to(root).parts[:-1]) & SKIP_DIRS:
                continue
            if p.is_symlink():                                   # rglob itself never enters a linked folder
                notes.append(f"{p.relative_to(root).as_posix()}: a symlink, not followed")
                continue
            if p.is_file():
                paths.append(p)
    for p in paths[:MAX_FILES * 8]:
        try:
            size = p.stat().st_size
            if size > tensors_mod.MAX_FILE:
                notes.append(f"{p.name}: {size} bytes is too large to be a small net (see model_prefix_probe "
                             "for a language model)")
                continue
            if kept + size > MAX_CHALLENGE_BYTES:
                notes.append(f"{p.name}: not read, the {MAX_CHALLENGE_BYTES} byte model-file budget of the "
                             "challenge is spent")
                continue
            data = p.read_bytes()
        except OSError as exc:
            notes.append(f"{p.name}: unreadable ({type(exc).__name__})")
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        try:
            ts = tensors_mod.load_bytes(data, p.name)
        except tensors_mod.TensorError as exc:
            if p.suffix.lower() != ".json":                      # most JSON files are not weights: no note
                notes.append(str(exc))
            continue
        cost = len(data) + sum(int(a.nbytes) for a in ts.tensors.values())
        if kept + cost > MAX_CHALLENGE_BYTES:
            notes.append(f"{p.name}: not kept, its {cost} bytes of file and tensors would pass the "
                         f"{MAX_CHALLENGE_BYTES} byte model-file budget of the challenge")
            continue
        kept += cost
        if not root.is_file():
            ts.source = p.relative_to(root).as_posix()
        for _key, why in ts.skipped:
            notes.append(why)
        if ts.kind == "npy":
            folder = p.parent.name if root.is_file() else p.parent.relative_to(root).as_posix()
            group = loose.setdefault(p.parent, tensors_mod.TensorSet("npy", f"{folder}/*.npy"))
            group.tensors.update(ts.tensors)
        elif ts.tensors:
            sets.append(ts)
        if len(sets) >= MAX_FILES:
            notes.append(f"more than {MAX_FILES} model files: the rest were not read")
            break
    sets.extend(g for g in loose.values() if g.tensors)
    return sets, notes


def _opt_float(opts, key, default):
    value = opts.get(key, default)
    if isinstance(value, bool):
        raise OptionError(f"option {key}={value!r} is not a number")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise OptionError(f"option {key}={value!r} is not a number") from None
    if not number > 0:
        raise OptionError(f"option {key}={value!r} must be positive")
    return number


def _has_proof(report: dict) -> bool:
    return any(proven(t) for t in report["triggers"])


def analyze_set(ts, ff, *, activation: str | None = None, seed: int = 0, alphabet: str | None = None,
                spent=lambda: False, max_inputs: int = MAX_INPUTS) -> dict:
    """One model file end to end: {"source", "net", "activation", "anomalies", "extract", "notes",
    "error"}. `error` names why the file was not searched (not an MLP, too wide)."""
    out = {"source": ts.source, "net": None, "activation": None, "anomalies": None, "extract": None,
           "notes": [], "error": None}
    hint = activation or activation_hint(ts)
    kinds = (hint,) if hint else AUTO_ACTIVATIONS
    tried = []
    for kind in kinds:
        try:
            net = build_mlp(ts.tensors, kind, ts.source)
        except NetError as exc:
            out["error"] = f"{ts.source}: {exc}"
            return out
        if net.n_in > max_inputs:
            out["error"] = f"{ts.source}: {net.n_in} inputs is over the {max_inputs} input search cap"
            return out
        if out["anomalies"] is None:
            out["anomalies"] = unit_anomalies(net)
        got = extract(net, ff, seed=seed, alphabet=alphabet, spent=spent, anomalies=out["anomalies"]["units"])
        tried.append(kind)
        if out["extract"] is None or (_has_proof(got) and not _has_proof(out["extract"])):
            out.update(net=net, activation=kind, extract=got)
        if _has_proof(got) or spent():
            break
    if not hint:
        out["notes"].append(f"activation not named by the file: tried {', '.join(tried)}; "
                            f"the result is under {out['activation']}")
    out["notes"].extend(out["net"].notes)
    return out


def _describe(source: str, net: Net, activation: str, t: dict) -> str:
    """One evidence line a human can check for a trigger entry."""
    rate = "" if t["random_rate"] is None else f" ({t['random_rate']:.1%} of random inputs are there)"
    how = f"input read as {t['encoding']}, {t['decoder']}"
    if t["source"] == "read-off":
        odd = "an outlier unit" if t["anomalous"] else "a unit"
        lead = (f"{source} rebuilt as a {net.shape} {activation} MLP: {odd}, {net.layers[0].name}[{t['unit']}], "
                f"spells it when each position takes the value the unit weighs {t['polarity']}")
    else:
        lead = f"{source} rebuilt as a {net.shape} {activation} MLP: the search's best input for {t['target']}"
    side = (f"the forward pass puts that input on the {t['target']} side by {t['score']:.4g}{rate}" if t["score"] > 0
            else f"the forward pass does not put that input on the {t['target']} side (margin {t['score']:.4g})")
    return f"{lead}; {side}; {how}"


def solve(challenge_dir, profile, **opts) -> SolverResult:
    """Recover the input a small saved net is backdoored to accept, as a flag. See the module docstring."""
    t0 = time.process_time()
    cid = opts.get("challenge_id")
    clock = opts.get("clock") or time.process_time

    def result(status, **kw):
        return SolverResult(status, engine=ENGINE, challenge_id=cid,
                            cost=Cost(seconds=round(max(0.0, time.process_time() - t0), 3)), **kw)

    try:
        _np()
    except ImportError:
        return result("blocked", notes="numpy is not installed (py:numpy): the forward pass cannot run")
    try:
        budget = _opt_float(opts, "budget_s", DEFAULT_BUDGET)
        max_inputs = int(_opt_float(opts, "max_inputs", MAX_INPUTS))
        seed = opts.get("seed", 0)
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise OptionError(f"option seed={seed!r} is not a non-negative integer")
        activation = opts.get("activation")
        if activation is not None and activation not in ACTIVATIONS:
            raise OptionError(f"option activation={activation!r} is not one of {', '.join(ACTIVATIONS)}")
        alphabet = opts.get("alphabet")
        if alphabet is not None and (not isinstance(alphabet, str) or len(set(alphabet)) != len(alphabet)
                                     or len(alphabet) < 2):
            raise OptionError("option alphabet must be a string of two or more distinct characters")
    except OptionError as exc:
        return result("blocked", notes=str(exc))

    start = clock()
    spent = lambda: clock() - start >= budget                    # noqa: E731
    ff = flagfmt.for_profile(profile)
    sets, notes = find_model_sets(challenge_dir)
    if not sets:
        return result("none", notes="; ".join(["no small model file (npz, npy, safetensors, PyTorch zip, "
                                               "JSON weights) in the challenge files"] + notes[:6]))
    evidence, strong, weak, alts, texts, errors = [], {}, [], [], [], []
    incomplete = False
    for ts in sets:
        if spent():
            incomplete = True
            notes.append(f"{ts.source}: CPU budget of {budget:g} s spent before it was read")
            continue
        rep = analyze_set(ts, ff, activation=activation, seed=seed, alphabet=alphabet, spent=spent,
                          max_inputs=max_inputs)
        if rep["error"]:
            errors.append(rep["error"])
            continue
        net, ex = rep["net"], rep["extract"]
        incomplete |= not ex["complete"]
        notes.extend(rep["notes"])
        notes.extend(ex["skipped"])
        units = rep["anomalies"]["units"]
        if units:
            top = ", ".join(f"{u['layer_name']}[{u['unit']}] {u['stat']} z={u['robust_z']:+.1f}" for u in units[:5])
            evidence.append(Evidence("anomaly", f"{ts.source}: {len({(u['layer'], u['unit']) for u in units})} "
                                                f"outlier unit(s) by median/MAD: {top}", path=ts.source))
        report = rep["anomalies"]["integrity"] or {}
        if report.get("findings"):
            seen_in = ", ".join(f"{f['tensor']} (top 1% of units carry {f['fraction']:.0%} of the squared "
                                f"magnitude)" for f in report["findings"][:4])
            evidence.append(Evidence("anomaly", f"{ts.source}: model_integrity_forensics.weight_outlier_report "
                                                f"on the per-unit numbers: {seen_in}", path=ts.source))
        shown = 0
        for t in ex["triggers"]:
            if t["flags"]:
                flag = t["flags"][0]
                if proven(t):
                    # pinned: a unit's weights spell it, or no accepted neighbour is another flag
                    pinned = t["source"] == "read-off" or not t["alternatives"]
                    strong[flag] = strong.get(flag, False) or pinned
                    alts.extend(a for a in t["alternatives"] if a not in alts)
                elif flag not in weak:
                    weak.append(flag)
                if shown < 6:
                    line = _describe(ts.source, net, rep["activation"], t)
                    if not t["clean"]:
                        line += "; the flag is only part of the decoded input"
                    if t["alternatives"]:
                        line += f"; {len(t['alternatives'])} other accepted flag(s) one position away"
                    evidence.append(Evidence("forward-pass" if proven(t) else "decode", line, path=ts.source))
                    shown += 1
            elif t["accepted"] and t["text"] is not None and len(texts) < 3:
                texts.append(t["text"])
                evidence.append(Evidence("forward-pass", _describe(ts.source, net, rep["activation"], t)
                                         + f"; text {t['text'][:80]!r} is not in the event flag format",
                                         path=ts.source))
    notes.extend(errors)
    note = "; ".join(dict.fromkeys(notes))[:1500]
    others = [f for f in alts + weak if f not in strong]
    if len(strong) == 1 and all(strong.values()) and ff.known:
        flag = next(iter(strong))
        if others:
            note = (f"{len(others)} weaker reading(s) not returned (a neighbour of the flag the net also accepts, or "
                    f"a partial decode): {', '.join(repr(o) for o in others[:4])}. " + note)
        return result("solved", flags=(flag,), evidence=tuple(evidence), notes=note.strip())
    flags = list(strong) + others
    if flags:
        why = ("several different flags were recovered; those the forward pass accepts come first" if len(flags) > 1
               else "the forward pass does not accept the decoded input as a rare one, or the flag is only part of it"
               if not strong else "the event flag format is not known yet")
        return result("candidate", flags=tuple(flags), evidence=tuple(evidence), notes=f"{why}. {note}".strip())
    if texts:
        return result("unsure", evidence=tuple(evidence),
                      notes=("an accepted rare input reads as text outside the flag format: "
                             + " | ".join(repr(t[:80]) for t in texts) + ". " + note).strip())
    tail = " (search cut by the CPU budget: raise --opt budget_s=)" if incomplete else ""
    return result("none", notes=("no input that the rebuilt net accepts decodes to a flag" + tail + ". " + note).strip())


__all__ = ["solve", "build_mlp", "unit_anomalies", "encodings_for", "search", "extract", "unit_readoffs",
           "analyze_set", "find_model_sets", "random_rate", "targets_for", "activation_hint", "Net", "Layer",
           "Encoding", "NetError", "OptionError", "ENGINE", "RARE", "proven"]
