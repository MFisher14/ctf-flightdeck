#!/usr/bin/env python3
"""DSP tone-decoder for the CyberSonics family (CSCTF audio / misc lane).

The 2025 "CyberSonics" challenges hide text in a sequence of fixed-duration tone blocks whose
FFT peak frequency maps to a character:

  CyberSonics-1   each block is a pure tone; freq = base + step*code (code is the ASCII value),
                  so the text is read straight off the peak-frequency ladder.
  CyberSonics-2   two tone streams separated by a long silence; each decodes to a byte sequence
                  (often base64), and the two sequences are XORed together to give the flag.
  CyberSonics-3   fine 35-155 Hz clustering: the tones sit in a narrow band and only the ORDER
                  of the distinct frequency clusters matters -> chr(offset + cluster_index).

This engine is offline and static. It loads wav/flac/ogg via soundfile (numpy FFT, no scipy),
segments the recording into tone blocks (fixed --block-ms, or auto via silence gaps), measures
each block's peak frequency with a Hann window + parabolic interpolation, and maps frequency to
a symbol by either the linear freq=base+step*code rule (base/step given or auto-fit) or by
nearest-cluster -> chr(offset+index). It never submits; it prints decoded text as CANDIDATES for
the player to read and highlights any CSCTF{...} / CTF{...} hit.

Other container formats (mp3/m4a/...): transcode to wav first with ffmpeg INSIDE the sandbox
(`tools/sandbox.py`), then point this at the wav.

  load_audio(path)                      -> (mono float samples in [-1,1], samplerate)
  detect_segments(samples, sr, ...)     -> [(start,end)] tone blocks (fixed or silence-gap)
  peak_freq(block, sr)                  -> float Hz (Hann + parabolic)
  block_freqs(samples, sr, ...)         -> [float] one peak freq per block
  autofit_linear(freqs)                 -> (base, step) best printable linear fit
  freqs_to_codes_linear(freqs,base,step)-> [int]
  freqs_to_codes_cluster(freqs, offset) -> ([int], [cluster_centers])
  split_streams(samples, sr, ...)       -> [(start,end)] streams split by the longest silence
  decode(path, ...)                     -> dict with codes/text/streams/xor candidates

CLI:
  audio_tones.py <audiofile> [--block-ms N] [--base HZ --step HZ | --cluster] [--offset 33]
                 [--xor] [--silence FRAC] [--json]
"""
import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

try:
    import soundfile as sf
except Exception:  # pragma: no cover - soundfile is a venv dependency
    sf = None

FLAG_RE = flagfmt.TEXT

MAX_SAMPLES = 32 * 1024 * 1024     # bound on frames read from one recording
DEFAULT_SILENCE = 0.10             # silence = RMS below this fraction of the loudest window


# ---- loading ---------------------------------------------------------------------------------

def load_audio(path):
    """Read an audio file to a mono float array in [-1, 1] and its samplerate.

    soundfile handles wav/flac/ogg natively. Other formats must be transcoded to wav with
    ffmpeg inside the Docker sandbox first.
    """
    if sf is None:
        raise RuntimeError("soundfile is required (pip install soundfile)")
    try:
        data, sr = sf.read(str(path), always_2d=True, frames=MAX_SAMPLES)
    except sf.LibsndfileError:
        return np.zeros(0, dtype=np.float64), 0
    data = np.asarray(data, dtype=np.float64)
    if data.shape[0] > MAX_SAMPLES:
        data = data[:MAX_SAMPLES]
    mono = data.mean(axis=1)           # mix channels down; streams are split by silence, not channel
    peak = np.max(np.abs(mono)) if mono.size else 0.0
    if peak > 0:
        mono = mono / peak
    return mono, int(sr)


# ---- envelope / segmentation ------------------------------------------------------------------

def _rms_envelope(samples, win):
    """Per-window RMS envelope; returns (centers_in_samples, rms) arrays."""
    win = max(1, int(win))
    n = len(samples)
    if n == 0:
        return np.array([]), np.array([])
    nwin = n // win
    if nwin == 0:
        return np.array([win // 2]), np.array([float(np.sqrt(np.mean(samples ** 2)))])
    trimmed = samples[: nwin * win].reshape(nwin, win)
    rms = np.sqrt(np.mean(trimmed ** 2, axis=1))
    centers = (np.arange(nwin) * win + win // 2)
    return centers, rms


def _silent_mask(samples, sr, silence_frac):
    """Boolean per-window mask: True where the window is 'loud' (part of a tone)."""
    win = max(1, int(sr * 0.005))                    # 5 ms analysis windows
    centers, rms = _rms_envelope(samples, win)
    if rms.size == 0:
        return win, np.array([]), np.array([], dtype=bool)
    thresh = silence_frac * float(np.max(rms))
    loud = rms > thresh
    return win, centers, loud


def detect_segments(samples, sr, block_ms=None, silence_frac=DEFAULT_SILENCE, min_ms=5.0):
    """Return [(start,end)] sample ranges, one per tone block.

    block_ms given  -> partition the signal into equal fixed-length blocks.
    block_ms None   -> auto-detect: contiguous 'loud' runs separated by silence gaps.
    """
    n = len(samples)
    if n == 0:
        return []
    if block_ms:
        scaled = sr * block_ms / 1000.0
        if not math.isfinite(scaled):
            return [(0, n)]
        blk = max(1, int(round(scaled)))
        segs = []
        for start in range(0, n - blk + 1, blk):
            segs.append((start, start + blk))
        # include a trailing partial block if it is at least half a block long
        rem = n - (len(segs) * blk)
        if segs and rem >= blk // 2:
            segs.append((len(segs) * blk, n))
        elif not segs and n >= 1:
            segs.append((0, n))
        return segs

    win, centers, loud = _silent_mask(samples, sr, silence_frac)
    if loud.size == 0:
        return []
    segs = []
    i = 0
    min_win = max(1, int((min_ms / 1000.0) * sr / win))
    while i < len(loud):
        if loud[i]:
            j = i
            while j < len(loud) and loud[j]:
                j += 1
            if (j - i) >= min_win:
                start = int(centers[i] - win // 2)
                end = int(centers[j - 1] + win // 2) if j - 1 < len(centers) else n
                segs.append((max(0, start), min(n, end)))
            i = j
        else:
            i += 1
    return segs


# ---- frequency measurement --------------------------------------------------------------------

def peak_freq(block, sr):
    """Peak frequency (Hz) of a block via Hann-windowed rFFT with parabolic interpolation."""
    block = np.asarray(block, dtype=np.float64)
    n = len(block)
    if n < 4:
        return 0.0
    # trim transients at the block edges (take the central 80%)
    lo = int(n * 0.10)
    hi = int(n * 0.90)
    if hi - lo >= 4:
        block = block[lo:hi]
        n = len(block)
    block = block - np.mean(block)
    win = np.hanning(n)
    spec = np.abs(np.fft.rfft(block * win))
    if spec.size < 2:
        return 0.0
    spec[0] = 0.0                                   # drop DC
    k = int(np.argmax(spec))
    if k <= 0 or k >= len(spec) - 1:
        delta = 0.0
    else:
        a, b, c = spec[k - 1], spec[k], spec[k + 1]
        denom = (a - 2 * b + c)
        delta = 0.5 * (a - c) / denom if denom != 0 else 0.0
        delta = float(np.clip(delta, -0.5, 0.5))
    return (k + delta) * sr / n


def block_freqs(samples, sr, block_ms=None, silence_frac=DEFAULT_SILENCE):
    segs = detect_segments(samples, sr, block_ms=block_ms, silence_frac=silence_frac)
    return [peak_freq(samples[s:e], sr) for (s, e) in segs]


# ---- frequency -> symbol ----------------------------------------------------------------------

def freqs_to_codes_linear(freqs, base, step):
    """code = round((freq - base) / step) under the linear rule freq = base + step*code."""
    if step == 0:
        return [0 for _ in freqs]
    codes = []
    for f in freqs:
        v = (f - base) / step
        codes.append(int(round(v)) if math.isfinite(v) else 0)
    return codes


def _printable_score(codes):
    """Score a code list by how text-like it is (printable + letters + flag punctuation)."""
    if not codes:
        return -1e9
    pr = sum(1 for c in codes if 32 <= c <= 126)
    if pr != len(codes):
        return -1e9 + pr                            # any non-printable is heavily penalised
    letters = sum(1 for c in codes if chr(c).isalnum())
    brace = sum(1 for c in codes if chr(c) in "{}")
    return letters + 3 * brace


def _estimate_step(freqs):
    """Robust per-code spacing: the measured tones sit on a lattice freq = base + step*code.

    The smallest inter-frequency gap is step*(smallest code gap); larger gaps are integer
    multiples of step. Dividing each gap by its nearest integer multiple of the seed spacing and
    taking the median averages out the per-tone FFT jitter, recovering the true step.
    """
    fr = sorted({round(float(f), 3) for f in freqs})
    diffs = [b - a for a, b in zip(fr, fr[1:]) if (b - a) > 1e-6]
    if not diffs:
        return 1.0
    seed = min(diffs)
    ratios = []
    for d in diffs:
        m = int(round(d / seed))
        if m >= 1:
            ratios.append(d / m)
    if not ratios:
        return seed
    return float(np.median(ratios))


def autofit_linear(freqs):
    """Best (base, step) for freq = base + step*code yielding a printable ASCII decode.

    step is refined from the inter-frequency lattice; the integer offset is searched so the
    decode lands in printable ASCII, scored toward text. Iterated so the step estimate is
    re-fit from the recovered codes by least squares.
    """
    freqs = [float(f) for f in freqs]
    if not freqs:
        return 0.0, 1.0
    step = _estimate_step(freqs)
    fmin = min(freqs)
    for _ in range(3):
        rel = [int(round((f - fmin) / step)) for f in freqs]   # 0-based lattice indices
        best = None
        for c0 in range(0, 127):                               # absolute code of the lowest tone
            codes = [c0 + r for r in rel]
            score = _printable_score(codes)
            if best is None or score > best[0]:
                best = (score, c0)
        c0 = best[1]
        codes = [c0 + r for r in rel]
        # least-squares re-fit freq = base + step*code from the recovered integer codes
        cs = np.array(codes, dtype=np.float64)
        fs = np.array(freqs, dtype=np.float64)
        if np.ptp(cs) > 0:
            A = np.vstack([cs, np.ones_like(cs)]).T
            (slope, intercept), *_ = np.linalg.lstsq(A, fs, rcond=None)
            if slope > 1e-9:
                step = float(slope)
                fmin = float(intercept)            # base; rel is recomputed against it next loop
                base = float(intercept)
                return base, step
        base = fmin - step * c0
        return base, step
    return fmin - step * c0, step


def _cluster_centers(freqs, tol_frac=0.25):
    """Group near-equal frequencies into clusters; return sorted cluster centers."""
    fr = sorted(float(f) for f in freqs)
    if not fr:
        return []
    diffs = [b - a for a, b in zip(fr, fr[1:]) if (b - a) > 1e-9]
    gap = (min(diffs) * 0.5) if diffs else 1.0      # anything closer than half the min gap = same cluster
    tol = max(gap, tol_frac * min(diffs) if diffs else 1.0)
    centers = []
    group = [fr[0]]
    for f in fr[1:]:
        if f - group[-1] <= tol:
            group.append(f)
        else:
            centers.append(sum(group) / len(group))
            group = [f]
    centers.append(sum(group) / len(group))
    return centers


def freqs_to_codes_cluster(freqs, offset=33):
    """Map each freq to chr(offset + cluster_index) by the rank of its frequency cluster."""
    centers = _cluster_centers(freqs)
    if not centers:
        return [], []
    codes = []
    for f in freqs:
        idx = int(np.argmin([abs(f - c) for c in centers]))
        codes.append(offset + idx)
    return codes, centers


def codes_to_text(codes):
    return "".join(chr(c) if 0 <= c <= 0x10FFFF else "?" for c in codes)


# ---- dual-stream split + XOR ------------------------------------------------------------------

def split_streams(samples, sr, silence_frac=DEFAULT_SILENCE, min_gap_ms=120.0):
    """Split the recording into streams at the LONGEST interior silence gap.

    Returns [(start,end)] stream ranges. If no gap is longer than min_gap_ms, returns one range.
    """
    n = len(samples)
    if n == 0:
        return []
    win, centers, loud = _silent_mask(samples, sr, silence_frac)
    if loud.size == 0:
        return [(0, n)]
    # find silent runs (not loud) and pick the longest interior one
    runs = []
    i = 0
    while i < len(loud):
        if not loud[i]:
            j = i
            while j < len(loud) and not loud[j]:
                j += 1
            runs.append((i, j))
            i = j
        else:
            i += 1
    min_gap_win = max(1, int((min_gap_ms / 1000.0) * sr / win))
    interior = [(a, b) for (a, b) in runs if a > 0 and b < len(loud) and (b - a) >= min_gap_win]
    if not interior:
        return [(0, n)]
    a, b = max(interior, key=lambda r: r[1] - r[0])
    mid = int(centers[(a + b) // 2]) if (a + b) // 2 < len(centers) else n // 2
    return [(0, mid), (mid, n)]


def _decode_stream(samples, sr, block_ms, mode, base, step, offset, silence_frac):
    freqs = block_freqs(samples, sr, block_ms=block_ms, silence_frac=silence_frac)
    if mode == "cluster":
        codes, _ = freqs_to_codes_cluster(freqs, offset=offset)
    elif mode == "linear":
        codes = freqs_to_codes_linear(freqs, base, step)
    else:  # auto-fit
        b, s = autofit_linear(freqs)
        base, step = b, s
        codes = freqs_to_codes_linear(freqs, base, step)
    return freqs, codes, (base, step)


def _xor_bytes(a, b):
    m = min(len(a), len(b))
    return bytes((a[i] ^ b[i]) & 0xFF for i in range(m))


def _maybe_b64(text):
    import base64
    try:
        s = text.strip()
        pad = (-len(s)) % 4
        return base64.b64decode(s + "=" * pad, validate=False)
    except Exception:
        return None


# ---- high-level decode ------------------------------------------------------------------------

def decode(path, block_ms=None, mode="auto", base=0.0, step=1.0, offset=33,
           xor=False, silence_frac=DEFAULT_SILENCE):
    """Decode one recording. Returns a dict of candidates; never submits."""
    samples, sr = load_audio(path)
    result = {
        "file": str(path),
        "samplerate": sr,
        "mode": mode,
        "candidates": [],
    }

    if xor:
        streams = split_streams(samples, sr, silence_frac=silence_frac)
        result["n_streams"] = len(streams)
        decoded = []
        for (s, e) in streams:
            freqs, codes, (b, st) = _decode_stream(
                samples[s:e], sr, block_ms, mode, base, step, offset, silence_frac)
            decoded.append({"range": [int(s), int(e)], "freqs": [round(f, 3) for f in freqs],
                            "codes": codes, "text": codes_to_text(codes), "base": b, "step": st})
        result["streams"] = decoded
        if len(decoded) >= 2:
            c0, c1 = decoded[0]["codes"], decoded[1]["codes"]
            b0 = bytes(c & 0xFF for c in c0)
            b1 = bytes(c & 0xFF for c in c1)
            # (1) XOR the raw per-block codes
            raw_xor = _xor_bytes(b0, b1)
            result["candidates"].append(("xor(codes)", _safe_text(raw_xor)))
            # (2) base64-decode each stream's text, then XOR the bytes
            d0, d1 = _maybe_b64(decoded[0]["text"]), _maybe_b64(decoded[1]["text"])
            if d0 is not None and d1 is not None:
                result["candidates"].append(("xor(b64(stream0),b64(stream1))",
                                             _safe_text(_xor_bytes(d0, d1))))
        return result

    freqs = block_freqs(samples, sr, block_ms=block_ms, silence_frac=silence_frac)
    result["n_blocks"] = len(freqs)
    result["freqs"] = [round(f, 3) for f in freqs]
    if mode == "cluster":
        codes, centers = freqs_to_codes_cluster(freqs, offset=offset)
        result["clusters"] = [round(c, 3) for c in centers]
        result["offset"] = offset
    elif mode == "linear":
        codes = freqs_to_codes_linear(freqs, base, step)
        result["base"], result["step"] = base, step
    else:
        base, step = autofit_linear(freqs)
        codes = freqs_to_codes_linear(freqs, base, step)
        result["base"], result["step"] = round(base, 4), round(step, 4)
    result["codes"] = codes
    text = codes_to_text(codes)
    result["candidates"].append((mode, text))
    return result


def _safe_text(b):
    try:
        return b.decode("latin-1")
    except Exception:
        return b.hex()


def find_flags(result):
    """Event-format flags in the decoded candidates and stream texts. Every value is bytes decoded
    from tone codes (one code per block, or two streams XORed), so a flag can follow a stray code
    with no separator: scanned with flagfmt.PACKED_TEXT (no left boundary, R-16)."""
    rx = flagfmt.PACKED_TEXT
    hits = []
    for _name, val in result.get("candidates", []):
        if isinstance(val, str):
            hits += rx.findall(val)
    for st in result.get("streams", []):
        hits += rx.findall(st.get("text", ""))
    # de-dup preserving order
    seen, out = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


# ---- CLI ---------------------------------------------------------------------------------------

def report(result):
    lines = []
    lines.append(f"file: {result['file']}  sr={result['samplerate']}Hz  mode={result['mode']}")
    if "n_blocks" in result:
        lines.append(f"blocks: {result['n_blocks']}")
        if "base" in result:
            lines.append(f"linear fit: base={result['base']} step={result['step']}")
        if "clusters" in result:
            lines.append(f"clusters ({len(result['clusters'])}): {result['clusters']}  offset={result['offset']}")
        lines.append(f"freqs: {result['freqs']}")
    if "n_streams" in result:
        lines.append(f"streams: {result['n_streams']}")
        for i, st in enumerate(result.get("streams", [])):
            lines.append(f"  stream{i}: text={st['text']!r} (base={round(st['base'],3)} step={round(st['step'],3)})")
    for name, val in result.get("candidates", []):
        lines.append(f"[{name}] {val!r}")
    flags = find_flags(result)
    for f in flags:
        lines.append(f"  >>> FLAG: {f}")
    if not flags:
        lines.append("  (no flag in the event's format; read the candidate text above)")
    return "\n".join(lines)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    ap = argparse.ArgumentParser(description="CyberSonics tone decoder (offline).")
    ap.add_argument("audiofile")
    ap.add_argument("--block-ms", type=float, default=None,
                    help="fixed block duration in ms (default: auto-detect via silence gaps)")
    ap.add_argument("--base", type=float, default=None, help="linear rule base frequency (Hz)")
    ap.add_argument("--step", type=float, default=None, help="linear rule step (Hz per code)")
    ap.add_argument("--cluster", action="store_true", help="nearest-cluster -> chr(offset+index)")
    ap.add_argument("--offset", type=int, default=33, help="ASCII offset for cluster mode (default 33)")
    ap.add_argument("--xor", action="store_true", help="split two streams by silence and XOR them")
    ap.add_argument("--silence", type=float, default=DEFAULT_SILENCE,
                    help="silence threshold as a fraction of peak RMS (default 0.10)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 2)

    p = Path(args.audiofile)
    if not p.is_file():
        print(f"audio_tones.py: {args.audiofile} is not a file", file=sys.stderr)
        return 2

    if args.cluster:
        mode = "cluster"
    elif args.base is not None and args.step is not None:
        mode = "linear"
    else:
        mode = "auto"

    try:
        result = decode(p, block_ms=args.block_ms, mode=mode,
                        base=args.base or 0.0, step=args.step or 1.0, offset=args.offset,
                        xor=args.xor, silence_frac=args.silence)
    except (OSError, ValueError, TypeError, RuntimeError, OverflowError, EOFError) as exc:
        print(f"audio_tones.py: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, ensure_ascii=False))
    else:
        print(report(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
