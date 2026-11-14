"""Side-channel CPA over NPZ/NPY trace corpora (aligned, masked, 2nd-order), B-028.

A no-model adapter from a captured ``traces.npz`` / ``*.npy`` corpus to a recovered
AES key, and, when a sealed blob ships with the corpus, to the flag it opens.

This is the input side ``solvers/common/sidechannel_offline`` never had: that module
holds the bounded pure-Python CPA/DPA/fault primitives but caps at 4096 traces, takes
only the built-in AES S-box, and has no loader.  Here NumPy does the heavy correlation,
the trace cap is raised past the 8000-trace corpora seen in the wild, the leakage S-box
is taken from the file when the author ships one, and three capture shapes are handled:

* **first-order, aligned** -- ``HW(sbox[p ^ k])`` against every sample, per key byte,
  for any key length (the ``recover_aes_sbox_byte_cpa`` model, vectorised and uncapped);
* **desynchronised** -- per-trace alignment on the argmax of a leading trigger window
  before the correlation;
* **first-order masked (second-order)** -- variance-based leak-point discovery, then a
  centered-product combine of a mask sample with each later sample, CPA on the product.

All inputs are already-captured observations loaded from disk: no acquisition, no
hardware, no network, no submission.  Arrays load with ``allow_pickle=False`` so a
corpus file is data, never code.  A recovered key is replayed against the model and,
if a sealed blob is present, used to open it; the flag is returned only when it is
found in the event format with evidence.  Missing NumPy, a missing/ambiguous corpus or
a failed model declines loudly (``blocked`` / ``none``), never silently.

Contract entry: ``solve(challenge_dir, profile, **opts) -> SolverResult`` (CONTRACTS 6-7).
"""

from __future__ import annotations

import binascii
import re
import sys
from pathlib import Path
from typing import Sequence

# ctf package import (a script run, as triage suggests it, needs the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt
from ctf.result import Cost, Evidence, SolverResult

MAX_TRACES = 200_000
MAX_SAMPLES = 100_000
MAX_CELLS = 200_000_000           # traces * samples ceiling, to bound work and memory
MAX_KEY_BYTES = 64
MAX_LEAK_POINTS = 48              # second-order: candidate mask samples kept by variance
MAX_SECOND_ORDER_TARGETS = 256    # second-order: partner samples per mask sample (all when S <= this)
MAX_CORPUS_BYTES = 256 * 1024 * 1024
MAX_BLOB_BYTES = 1 << 20

_AES_SBOX = tuple(
    bytes.fromhex(
        "637c777bf26b6fc53001672bfed7ab76"
        "ca82c97dfa5947f0add4a2af9ca472c0"
        "b7fd9326363ff7cc34a5e5f171d83115"
        "04c723c31896059a071280e2eb27b275"
        "09832c1a1b6e5aa0523bd6b329e32f84"
        "53d100ed20fcb15b6acbbe394a4c58cf"
        "d0efaafb434d338545f9027f503c9fa8"
        "51a3408f929d38f5bcb6da2110fff3d2"
        "cd0c13ec5f974417c4a77e3d645d1973"
        "60814fdc222a908846eeb814de5e0bdb"
        "e0323a0a4906245cc2d3ac629195e479"
        "e7c8376d8dd54ea96c56f4ea657aae08"
        "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
        "703eb5664803f60e613557b986c11d9e"
        "e1f8981169d98e949b1e87e9ce5528df"
        "8ca1890dbfe6426841992d0fb054bb16"
    )
)

_TRACE_NAMES = ("traces", "trace", "leakage", "power", "waves", "t", "l")
# One plaintext-name list for the NPZ keys and the sibling .npy stems.  ``data`` is
# ambiguous (authors use it for traces too), so a name match alone never decides: an
# NPZ plaintext must be integer-valued, and a lone .npy is chosen as traces by dtype.
_PLAIN_NAMES = ("plaintexts", "plaintext", "plains", "pts", "pt", "inputs",
                "messages", "msgs", "data", "p")
_SBOX_NAMES = ("sbox", "s_box", "aes_sbox", "s")
_CIPHER_EXTS = (".hex", ".bin", ".ct", ".enc", ".cipher", ".dat")


class CorpusError(ValueError):
    """The corpus file exists but is not a usable (traces, plaintexts) pair."""


class MissingTool(RuntimeError):
    """A tool the requested step needs is absent (named in the message)."""


def _require_numpy():
    try:
        import numpy as np
    except ImportError as exc:                       # no silent fallback
        raise CorpusError("numpy is required for CPA over NPZ corpora; pip install numpy") from exc
    return np


def _hw_table(np):
    return np.array([bin(i).count("1") for i in range(256)], dtype=np.float64)


# --------------------------------------------------------------------------- loading


def _named(np, store, names, *, integer=False):
    """First array in ``store`` whose key (case-folded) is one of ``names``.

    With ``integer`` only an integer-valued array qualifies (a float array named ``data``
    is traces, not plaintexts).
    """
    lowered = {k.lower(): k for k in store.files} if hasattr(store, "files") else {}
    for want in names:
        if want in lowered:
            arr = np.asarray(store[lowered[want]])
            if integer and not np.issubdtype(arr.dtype, np.integer):
                continue
            return arr
    return None


def _coerce_sbox(np, arr):
    if arr is None:
        return None
    flat = np.asarray(arr).reshape(-1)
    if flat.shape[0] != 256:
        return None
    try:
        vals = flat.astype(np.int64)
    except (TypeError, ValueError):
        return None
    if np.any(vals < 0) or np.any(vals > 255):
        return None
    if np.unique(vals).shape[0] != 256:              # a real S-box is a permutation
        return None
    return tuple(int(v) for v in vals)


def load_corpus(path):
    """Load a side-channel corpus from one ``.npz`` or one/two ``.npy`` file(s).

    Returns ``(traces, plaintexts, sbox_or_None)`` as NumPy arrays: ``traces`` float
    ``(N, S)``, ``plaintexts`` uint8 ``(N, B)``, ``sbox`` the carried S-box tuple or
    ``None``.  Array names are detected case-insensitively, then by shape.  Raises
    ``CorpusError`` with a named reason for anything unusable.  ``allow_pickle`` is
    never enabled, so the file cannot execute code.
    """
    np = _require_numpy()
    path = Path(path)
    if not path.is_file():
        raise CorpusError(f"corpus not found: {path}")
    if path.stat().st_size > MAX_CORPUS_BYTES:
        raise CorpusError(f"corpus {path.name} exceeds {MAX_CORPUS_BYTES} bytes")

    traces = plains = sbox = None
    if path.suffix.lower() == ".npz":
        with np.load(path, allow_pickle=False) as store:
            traces = _named(np, store, _TRACE_NAMES)
            plains = _named(np, store, _PLAIN_NAMES, integer=True)
            sbox = _coerce_sbox(np, _named(np, store, _SBOX_NAMES))
            arrays = {name: np.asarray(store[name]) for name in store.files}
        if traces is None or plains is None:         # fall back to shape detection
            t2, p2 = _detect_by_shape(np, arrays)
            traces = traces if traces is not None else t2
            plains = plains if plains is not None else p2
        if sbox is None:
            for name, arr in arrays.items():
                if name.lower() not in _TRACE_NAMES + _PLAIN_NAMES:
                    sbox = _coerce_sbox(np, arr)
                    if sbox is not None:
                        break
    elif path.suffix.lower() == ".npy":
        arr = np.load(path, allow_pickle=False)
        # a lone .npy is the traces; its plaintexts sit beside it
        traces = np.asarray(arr)
        plains = _sibling_plaintexts(np, path)
    else:
        raise CorpusError(f"unsupported corpus type {path.suffix!r}: expected .npz or .npy")

    if traces is None:
        raise CorpusError(f"{path.name}: no trace array found (names tried: {', '.join(_TRACE_NAMES)})")
    if plains is None:
        raise CorpusError(f"{path.name}: no plaintext array found (names tried: {', '.join(_PLAIN_NAMES)})")
    return _finish(np, traces, plains, sbox, path.name)


def _sibling_plaintexts(np, trace_path):
    """Plaintexts beside a lone traces ``.npy``: the first integer ``<plaintext name>.npy``
    that is not the traces file itself."""
    folder = trace_path.parent
    for name in _PLAIN_NAMES:
        cand = folder / f"{name}.npy"
        if not cand.is_file() or cand.resolve() == trace_path.resolve():
            continue
        arr = np.load(cand, allow_pickle=False)
        if np.issubdtype(arr.dtype, np.integer):
            return arr
    return None


def _detect_by_shape(np, arrays):
    """Pick (traces, plaintexts) from unnamed arrays: widest float 2-D vs integer 2-D."""
    traces = plains = None
    best_width = -1
    for arr in arrays.values():
        a = np.asarray(arr)
        if a.ndim != 2:
            continue
        if np.issubdtype(a.dtype, np.floating):
            if a.shape[1] > best_width:
                traces, best_width = a, a.shape[1]
    for arr in arrays.values():
        a = np.asarray(arr)
        if a.ndim == 2 and np.issubdtype(a.dtype, np.integer) and a.max() <= 255 and a.min() >= 0:
            plains = a
            break
    return traces, plains


def _finish(np, traces, plains, sbox, name):
    traces = np.asarray(traces)
    if traces.ndim == 1:
        traces = traces.reshape(traces.shape[0], 1)
    if traces.ndim != 2:
        raise CorpusError(f"{name}: trace array is {traces.ndim}-D, expected 2-D (N, samples)")
    try:
        traces = traces.astype(np.float64)
    except (TypeError, ValueError) as exc:
        raise CorpusError(f"{name}: trace array is not numeric") from exc
    if not np.all(np.isfinite(traces)):
        raise CorpusError(f"{name}: trace array holds a non-finite sample")

    plains = np.asarray(plains)
    if plains.ndim == 1:
        plains = plains.reshape(plains.shape[0], 1)
    if plains.ndim != 2:
        raise CorpusError(f"{name}: plaintext array is {plains.ndim}-D, expected 2-D (N, bytes)")
    if not np.issubdtype(plains.dtype, np.integer):
        raise CorpusError(f"{name}: plaintext array is not integer-valued")
    plains = plains.astype(np.int64)
    if plains.min() < 0 or plains.max() > 255:
        raise CorpusError(f"{name}: plaintext bytes outside 0..255")
    plains = plains.astype(np.uint8)

    n, s = traces.shape
    if traces.shape[0] != plains.shape[0]:
        raise CorpusError(f"{name}: {traces.shape[0]} traces but {plains.shape[0]} plaintexts")
    if not 2 <= n <= MAX_TRACES:
        raise CorpusError(f"{name}: {n} traces outside 2..{MAX_TRACES}")
    if not 1 <= s <= MAX_SAMPLES:
        raise CorpusError(f"{name}: {s} samples outside 1..{MAX_SAMPLES}")
    if n * s > MAX_CELLS:
        raise CorpusError(f"{name}: {n}x{s} cells exceeds {MAX_CELLS}")
    if not 1 <= plains.shape[1] <= MAX_KEY_BYTES:
        raise CorpusError(f"{name}: {plains.shape[1]} key bytes outside 1..{MAX_KEY_BYTES}")
    return traces, plains, sbox


# ----------------------------------------------------------------------- correlation


def _corr_matrix(np, hyp, traces):
    """Pearson correlation of every hypothesis column against every sample column.

    ``hyp`` is ``(N, K)``, ``traces`` is ``(N, S)``; result is ``(K, S)``.  A constant
    hypothesis or sample column yields 0 (no leakage), never a divide-by-zero.
    """
    hc = hyp - hyp.mean(axis=0, keepdims=True)
    tc = traces - traces.mean(axis=0, keepdims=True)
    num = hc.T @ tc                                      # (K, S)
    hn = np.sqrt((hc * hc).sum(axis=0))                  # (K,)
    tn = np.sqrt((tc * tc).sum(axis=0))                  # (S,)
    denom = np.outer(hn, tn)
    with np.errstate(divide="ignore", invalid="ignore"):
        corr = np.where(denom > 0, num / denom, 0.0)
    return corr


def _hypotheses(np, plain_col, sbox, hw):
    """``(N, 256)`` leakage HW(sbox[p ^ k]) for every key guess k."""
    sbox_arr = np.array(sbox, dtype=np.int64)
    guesses = np.arange(256, dtype=np.int64)
    idx = np.bitwise_xor(plain_col.astype(np.int64)[:, None], guesses[None, :])   # (N, 256)
    return hw[sbox_arr[idx]]


def _rank_byte(np, corr):
    """Best key guess from a ``(256, S)`` correlation matrix: (key, score, runner_up)."""
    per_key = np.abs(corr).max(axis=1)                   # (256,)
    order = np.argsort(per_key)[::-1]
    best = int(order[0])
    second = float(per_key[order[1]]) if per_key.shape[0] > 1 else 0.0
    return best, float(per_key[best]), second


def cpa_first_order(traces, plaintexts, sbox=None, *, min_correlation=0.2, margin=0.03):
    """First-order CPA for every key byte.  Returns ``(key_bytes, per_byte)``.

    ``key_bytes`` is ``bytes`` only when every byte clears ``min_correlation`` and beats
    its runner-up by at least ``margin``; otherwise ``None`` with the per-byte detail so
    the caller can fall back to the masked path.  ``sbox`` defaults to the AES S-box.
    """
    np = _require_numpy()
    traces = np.asarray(traces, dtype=np.float64)
    plaintexts = np.asarray(plaintexts, dtype=np.int64)
    box = tuple(sbox) if sbox is not None else _AES_SBOX
    hw = _hw_table(np)
    per_byte = []
    recovered = []
    clean = True
    for b in range(plaintexts.shape[1]):
        hyp = _hypotheses(np, plaintexts[:, b], box, hw)
        corr = _corr_matrix(np, hyp, traces)
        key, score, runner = _rank_byte(np, corr)
        sep = score - runner
        ok = score >= min_correlation and sep >= margin
        clean = clean and ok
        per_byte.append({"byte": b, "key": key, "score": round(score, 6),
                         "runner_up": round(runner, 6), "margin": round(sep, 6), "clean": ok})
        recovered.append(key)
    return (bytes(recovered) if clean else None), per_byte


# ------------------------------------------------------------------- alignment & 2nd order


def has_trigger(traces, *, window=17, share=0.8):
    """True when most traces carry one dominant spike in the leading ``window``.

    A trace has a spike when its window maximum beats the runner-up by at least half the
    maximum's height above the window median: a trigger pulse does, the top of plain noise or
    of data-dependent samples does not.  ``share`` of the traces must have one.  Aligning on
    the argmax of a window with no spike shifts rows at random and destroys an aligned
    corpus, so :func:`solve` uses this to choose which variant to try first.
    """
    np = _require_numpy()
    traces = np.asarray(traces, dtype=np.float64)
    n, s = traces.shape
    window = max(1, min(int(window), s))
    if window < 3:
        return False
    w = np.sort(traces[:, :window], axis=1)
    peak, second = w[:, -1], w[:, -2]
    median = np.median(w, axis=1)
    height = peak - median
    spiky = (height > 0) & ((peak - second) >= 0.5 * height)
    return bool(spiky.mean() >= float(share))


def align_traces(traces, *, window=17, max_shift=None):
    """Shift each trace so its leading-window argmax lands at a common column.

    The classic random-delay countermeasure fires a trigger spike within the first
    ``window`` samples; aligning on its argmax removes the desynchronisation before
    correlation.  Returns a new ``(N, S)`` array (rows rolled, vacated ends zero-filled).
    """
    np = _require_numpy()
    traces = np.asarray(traces, dtype=np.float64)
    n, s = traces.shape
    window = max(1, min(int(window), s))
    peaks = np.argmax(traces[:, :window], axis=1)
    target = int(np.median(peaks))
    cap = s if max_shift is None else int(max_shift)
    out = np.zeros_like(traces)
    for i in range(n):
        shift = target - int(peaks[i])
        if shift > cap or -shift > cap:
            shift = max(-cap, min(cap, shift))
        if shift == 0:
            out[i] = traces[i]
        elif shift > 0:
            out[i, shift:] = traces[i, : s - shift]
        else:
            out[i, : s + shift] = traces[i, -shift:]
    return out


def leak_points(traces, *, limit=MAX_LEAK_POINTS):
    """Sample indices most likely to carry leakage, ranked by variance (highest first).

    A masked, data-dependent sample varies across traces; a constant or idle sample does
    not.  Returns at most ``limit`` column indices.
    """
    np = _require_numpy()
    traces = np.asarray(traces, dtype=np.float64)
    var = traces.var(axis=0)
    order = np.argsort(var)[::-1]
    keep = min(int(limit), traces.shape[1])
    return [int(i) for i in order[:keep]]


def cpa_second_order(traces, plaintexts, sbox=None, *, min_correlation=0.08, margin=0.02,
                     points=None, targets=None):
    """Second-order CPA against a first-order Boolean mask.

    For each candidate mask sample ``m`` the traces are preprocessed by the centered
    product ``(T[:,m]-mean) * (T[:,j]-mean)`` over the partner samples ``j``; first-order
    CPA on that product recovers ``HW(sbox[p ^ k])`` that the mask hid.  The mask sample and
    the key are searched jointly over the highest-variance leak points (``points``).  The
    partners ``targets`` default to every sample when the trace has at most
    ``MAX_SECOND_ORDER_TARGETS`` samples, else to that many highest-variance samples, so the
    cost stays ``points x targets`` rather than ``points x samples``.  Each product is built
    once per mask sample and reused for every key byte.  Returns ``(key_bytes, per_byte)``
    like :func:`cpa_first_order`; ``key_bytes`` is ``None`` when any byte fails the thresholds.
    """
    np = _require_numpy()
    traces = np.asarray(traces, dtype=np.float64)
    plaintexts = np.asarray(plaintexts, dtype=np.int64)
    box = tuple(sbox) if sbox is not None else _AES_SBOX
    hw = _hw_table(np)
    cand = points if points is not None else leak_points(traces)
    if not cand:
        return None, []
    if targets is None:
        if traces.shape[1] <= MAX_SECOND_ORDER_TARGETS:
            targets = list(range(traces.shape[1]))
        else:
            targets = leak_points(traces, limit=MAX_SECOND_ORDER_TARGETS)
    targets = np.asarray(list(targets), dtype=np.int64)
    centered = traces - traces.mean(axis=0, keepdims=True)
    partners = centered[:, targets]                                    # (N, T)
    n_bytes = plaintexts.shape[1]
    best = [{"key": 0, "score": -1.0, "runner_up": 0.0, "mask": -1} for _ in range(n_bytes)]
    for m in cand:
        combined = partners * centered[:, m][:, None]                  # (N, T), key-independent
        for b in range(n_bytes):
            hyp = _hypotheses(np, plaintexts[:, b], box, hw)          # (N, 256)
            corr = _corr_matrix(np, hyp, combined)
            key, score, runner = _rank_byte(np, corr)
            if score > best[b]["score"]:
                best[b] = {"key": key, "score": score, "runner_up": runner, "mask": int(m)}
    per_byte = []
    recovered = []
    clean = True
    for b, bb in enumerate(best):
        sep = bb["score"] - bb["runner_up"]
        ok = bb["score"] >= min_correlation and sep >= margin
        clean = clean and ok
        per_byte.append({"byte": b, "key": bb["key"], "score": round(bb["score"], 6),
                         "runner_up": round(bb["runner_up"], 6), "margin": round(sep, 6),
                         "mask_sample": bb["mask"], "partners": int(targets.shape[0]), "clean": ok})
        recovered.append(bb["key"])
    return (bytes(recovered) if clean else None), per_byte


# ------------------------------------------------------------------------- flag recovery


def _read_blobs(challenge_dir, limit=MAX_BLOB_BYTES):
    """Candidate sealed ciphertexts beside the corpus: (name, bytes) for small side files."""
    out = []
    for p in sorted(Path(challenge_dir).rglob("*")):
        if not p.is_file() or p.suffix.lower() not in _CIPHER_EXTS:
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if len(raw) > limit:
            continue
        out.append((p.name, _maybe_unhex(raw)))
        if len(out) >= 8:
            break
    return out


def _maybe_unhex(raw):
    text = raw.strip()
    compact = bytes(c for c in text if c not in b" \t\r\n")
    if compact and len(compact) % 2 == 0 and re.fullmatch(rb"[0-9A-Fa-f]+", compact):
        try:
            return binascii.unhexlify(compact)
        except binascii.Error:
            return raw
    return raw


def _require_crypto():
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
    except ImportError as exc:                       # no silent fallback
        raise MissingTool("py:Crypto (pycryptodome) is required to open the sealed blob "
                          "with the recovered key") from exc
    return AES, Counter


def _decrypt_candidates(key, blob):
    """Plaintext candidates for ``blob`` under ``key``: AES-CTR (zero counter), ECB, CBC(zero IV).

    Raises :class:`MissingTool` when pycryptodome is absent.
    """
    AES, Counter = _require_crypto()
    if len(key) not in (16, 24, 32):
        return []
    outs = []
    try:
        ctr = Counter.new(128, initial_value=0)
        outs.append(("aes-ctr", AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(blob)))
    except (ValueError, TypeError):
        pass
    if len(blob) % 16 == 0 and blob:
        try:
            outs.append(("aes-ecb", AES.new(key, AES.MODE_ECB).decrypt(blob)))
        except (ValueError, TypeError):
            pass
        try:
            outs.append(("aes-cbc", AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(blob)))
        except (ValueError, TypeError):
            pass
    return outs


def open_with_key(challenge_dir, key, profile):
    """Try the recovered key against every sealed blob; return (flag, evidence) or (None, None).

    Raises :class:`MissingTool` (named) when a sealed blob exists but pycryptodome is absent.
    """
    ff = flagfmt.for_profile(profile)
    blobs = _read_blobs(challenge_dir)
    if blobs:
        _require_crypto()
    for name, blob in blobs:
        for mode, plain in _decrypt_candidates(key, blob):
            flags = ff.find_flags(plain)
            if flags:
                ev = Evidence("decrypt", f"{mode} of {name} under recovered key -> {flags[0]}", path=name)
                return flags[0], ev
    return None, None


# --------------------------------------------------------------------------- the engine


def _npy_header(np, path):
    """(dtype, shape) of a ``.npy`` read from its header only, or ``None`` when unreadable."""
    try:
        with open(path, "rb") as fh:
            version = np.lib.format.read_magic(fh)
            if version == (1, 0):
                shape, _, dtype = np.lib.format.read_array_header_1_0(fh)
            elif version == (2, 0):
                shape, _, dtype = np.lib.format.read_array_header_2_0(fh)
            else:
                return None
    except (OSError, ValueError):
        return None
    return dtype, shape


def _find_corpus(challenge_dir):
    """The corpus file: the first ``.npz``, else the ``.npy`` holding the traces.

    A ``.npy`` is taken as traces when its stem is exactly a trace name (never a substring:
    ``plaintexts.npy`` contains ``t``).  Failing that the names are ambiguous, so the dtype
    decides: the widest floating-point 2-D ``.npy`` that is not an S-box (plaintexts are
    integers, so a float ``data.npy`` is traces), preferring stems that are not plaintext
    names; then the first ``.npy`` whose stem is not a plaintext or S-box name.  ``None``
    when no candidate trace file exists.
    """
    np = _require_numpy()
    npz = sorted(Path(challenge_dir).rglob("*.npz"))
    if npz:
        return npz[0]
    npy = sorted(Path(challenge_dir).rglob("*.npy"))
    for p in npy:
        if p.stem.lower() in _TRACE_NAMES:
            return p
    floats = []
    for p in npy:
        if p.stem.lower() in _SBOX_NAMES:
            continue
        head = _npy_header(np, p)
        if head and np.issubdtype(head[0], np.floating) and len(head[1]) == 2:
            floats.append((p.stem.lower() in _PLAIN_NAMES, -int(head[1][1]), str(p), p))
    if floats:
        return min(floats)[3]
    for p in npy:
        if p.stem.lower() not in _PLAIN_NAMES + _SBOX_NAMES:
            return p
    return None


def _align_mode(value):
    """``"auto"`` | ``True`` | ``False`` from an option (``ctf run --opt align=false`` is a string)."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text == "auto":
        return "auto"
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"align option {value!r}: expected auto, true or false")


def _second_order_variants(traces, mode, window, notes):
    """Yield ``(label, traces)`` in the order second order should try them.

    ``mode`` False: raw only.  True: aligned only.  ``"auto"``: aligned first when a leading
    trigger spike is present, else raw first; the other variant follows as the fallback
    (skipped when alignment changed nothing).
    """
    np = _require_numpy()
    if mode is False:
        yield "raw", traces
        return
    aligned = align_traces(traces, window=window)
    if mode is True:
        yield "aligned", aligned
        return
    spike = has_trigger(traces, window=window)
    notes.append("leading trigger spike " + ("found: aligned first" if spike else "absent: raw first"))
    first, second = (("aligned", aligned), ("raw", traces)) if spike else (("raw", traces), ("aligned", aligned))
    yield first
    if not np.array_equal(aligned, traces):
        yield second


def _opt_float(opts, key, default):
    try:
        return float(opts.get(key, default))
    except (TypeError, ValueError):
        return default


def solve(challenge_dir, profile, **opts) -> SolverResult:
    """Recover an AES key by CPA over the NPZ/NPY corpus, and the flag it seals.

    Options: ``order`` (``auto`` | ``first`` | ``second``), ``min_correlation``,
    ``margin``, ``align`` (``auto`` | true | false, second-order path only), ``window``.

    With ``align=auto`` second order runs on the trigger-aligned traces first only when
    :func:`has_trigger` sees a leading spike, else on the raw traces first; when that variant
    finds no clean key the other one is tried.  ``align=true`` / ``false`` forces one variant.
    """
    import time

    t0 = time.monotonic()
    cid = opts.get("challenge_id")
    me = "common.cpa_npz"
    try:
        _require_numpy()
    except CorpusError as exc:
        return SolverResult("blocked", engine=me, challenge_id=cid, notes=str(exc),
                            cost=Cost(seconds=round(time.monotonic() - t0, 3)))

    corpus = _find_corpus(challenge_dir)
    if corpus is None:
        return SolverResult("none", engine=me, challenge_id=cid,
                            notes="no .npz/.npy trace corpus in challenge files "
                                  "(a .npy named only as plaintexts or S-box is not traces)",
                            cost=Cost(seconds=round(time.monotonic() - t0, 3)))
    try:
        traces, plains, sbox = load_corpus(corpus)
    except CorpusError as exc:
        return SolverResult("blocked", engine=me, challenge_id=cid, notes=str(exc),
                            cost=Cost(seconds=round(time.monotonic() - t0, 3)))

    order = str(opts.get("order", "auto"))
    min_corr = _opt_float(opts, "min_correlation", 0.2)
    margin = _opt_float(opts, "margin", 0.03)
    window = int(_opt_float(opts, "window", 17))
    try:
        align_mode = _align_mode(opts.get("align", "auto"))
    except ValueError as exc:                        # a bad option is named, never guessed
        return SolverResult("blocked", engine=me, challenge_id=cid, notes=str(exc),
                            cost=Cost(seconds=round(time.monotonic() - t0, 3)))
    rel = corpus.name
    notes = [f"corpus {rel}: {traces.shape[0]} traces x {traces.shape[1]} samples, "
             f"{plains.shape[1]} key bytes, sbox {'from file' if sbox else 'AES default'}"]

    key = None
    method = None
    detail = None
    if order in ("auto", "first"):
        key, detail = cpa_first_order(traces, plains, sbox, min_correlation=min_corr, margin=margin)
        if key is not None:
            method = "first-order"
    if key is None and order in ("auto", "second"):
        s_min = _opt_float(opts, "min_correlation", 0.08) if order == "second" else 0.08
        s_margin = _opt_float(opts, "margin", 0.02) if order == "second" else 0.02
        for label, variant in _second_order_variants(traces, align_mode, window, notes):
            key, detail = cpa_second_order(variant, plains, sbox, min_correlation=s_min, margin=s_margin)
            if detail and detail[0]["partners"] < variant.shape[1]:
                notes.append(f"second order ({label}) combined the top {detail[0]['partners']} of "
                             f"{variant.shape[1]} samples by variance")
            if key is not None:
                method = f"second-order ({label}, masked)"
                break

    if key is None:
        best = max((d.get("score", 0.0) for d in (detail or [])), default=0.0)
        return SolverResult("none", engine=me, challenge_id=cid,
                            notes="; ".join(notes) + f"; no clean key (best |corr| {best})",
                            cost=Cost(seconds=round(time.monotonic() - t0, 3)))

    notes.append(f"{method} recovered key {key.hex()}")
    evidence = [Evidence("cpa", f"{method} CPA key byte ranks: " +
                         ", ".join(f"b{d['byte']}=0x{d['key']:02x}@{d['score']}" for d in detail[:4]) +
                         ("..." if len(detail) > 4 else ""), path=rel)]

    try:
        flag, ev = open_with_key(challenge_dir, key, profile)
    except MissingTool as exc:
        return SolverResult("candidate", flags=(key.hex(),), evidence=tuple(evidence), engine=me,
                            challenge_id=cid,
                            notes="; ".join(notes) + f"; key recovered, sealed blob not tried: {exc}",
                            cost=Cost(seconds=round(time.monotonic() - t0, 3)))
    seconds = round(time.monotonic() - t0, 3)
    if flag is not None:
        evidence.append(ev)
        return SolverResult("solved", flags=(flag,), evidence=tuple(evidence), engine=me,
                            challenge_id=cid, notes="; ".join(notes) + "; sealed blob opened",
                            cost=Cost(seconds=seconds))

    # key recovered but no sealed blob opened: the bytes may themselves be the answer.
    printable = all(32 <= c < 127 for c in key)
    ff = flagfmt.for_profile(profile)
    as_text = key.decode("latin-1")
    if printable and ff.find_flags(as_text):
        return SolverResult("solved", flags=(ff.find_flags(as_text)[0],), evidence=tuple(evidence),
                            engine=me, challenge_id=cid, notes="; ".join(notes) + "; key bytes are the flag",
                            cost=Cost(seconds=seconds))
    candidate = as_text if printable else key.hex()
    return SolverResult("candidate", flags=(candidate,), evidence=tuple(evidence), engine=me,
                        challenge_id=cid,
                        notes="; ".join(notes) + "; key recovered, no sealed blob opened (needs the decrypt mode)",
                        cost=Cost(seconds=seconds))


__all__ = [
    "CorpusError",
    "MissingTool",
    "load_corpus",
    "cpa_first_order",
    "cpa_second_order",
    "align_traces",
    "has_trigger",
    "leak_points",
    "open_with_key",
    "solve",
    "main",
]

_USAGE = "usage: cpa_npz.py <challenge dir | corpus .npz/.npy> [--event <slug>] [--opt key=value]..."


def main(argv) -> int:
    """Script entry (what triage prints): run :func:`solve` and print the SolverResult JSON.

    A corpus file argument means its folder.  The event profile comes from ``--event`` or the
    current event; none resolvable is an error that names why.  Exit 0 for solved/candidate,
    1 for none/blocked, 2 for a usage or event error.
    """
    from ctf import event

    args = list(argv)
    target = slug = None
    opts = {}
    while args:
        a = args.pop(0)
        if a in ("--event", "--opt"):
            if not args:
                print(f"cpa_npz.py: {a} needs a value\n{_USAGE}", file=sys.stderr)
                return 2
            val = args.pop(0)
            if a == "--event":
                slug = val
            elif "=" not in val:
                print(f"cpa_npz.py: --opt {val!r} is not key=value\n{_USAGE}", file=sys.stderr)
                return 2
            else:
                k, v = val.split("=", 1)
                opts[k] = v
        elif a.startswith("-") or target is not None:
            print(f"cpa_npz.py: unexpected argument {a!r}\n{_USAGE}", file=sys.stderr)
            return 2
        else:
            target = Path(a)
    if target is None:
        print(_USAGE, file=sys.stderr)
        return 2
    if not target.exists():
        print(f"cpa_npz.py: {target} does not exist", file=sys.stderr)
        return 2
    challenge_dir = target if target.is_dir() else target.parent
    try:
        profile = event.load(slug) if slug else event.current()
    except event.EventError as exc:
        print(f"cpa_npz.py: no event profile ({exc}); pass --event <slug>", file=sys.stderr)
        return 2
    res = solve(challenge_dir, profile, **opts)
    print(res.to_json())
    return 0 if res.status in ("solved", "candidate") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
