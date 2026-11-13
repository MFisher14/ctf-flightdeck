#!/usr/bin/env python3
"""Audio stego carriers with no key on hand (B-245): spread spectrum, echo hiding, phase coding,
parity coding and silence-interval coding, swept over bounded parameter sets. Offline; numpy;
nothing is executed. Reads integer-PCM WAV, G.711 (mu-law / A-law) WAV, AIFF/AIFF-C PCM and Sun .au.

stegodepth_spread.extract_dsss and stegodepth_echo.extract_echo decode only when they are told the
parameters (the PN chips, the two echo delays, the window). This module finds those parameters in the
signal, then hands them to those two decoders for the reading. It adds the classic carriers the tree
had no reader for: phase coding, parity coding and silence-interval coding (the matrix row F8 audio
algorithms), and the G.711 code-byte LSB.

  symbol_periods the symbol length of a repeating-PN spread spectrum, found blind: the mean |local
                 correlation| at lag L peaks at the symbol length and its multiples although the bit
                 signs flip; the lag most peaks are multiples of is the symbol. The symbol's own lag
                 often scores under its multiples, so a divisor of two or more peaks is admitted at a
                 lower gate.
  dsss_sweep     blind direct-sequence spread spectrum with a PN sequence that repeats for every bit
                 (the model stegodepth_spread decodes). For each symbol length L (the detected periods,
                 their exact divisors p/2 .. p/8 and pairwise gcds, and a bounded set) the signal is cut
                 into L-sample rows; the matrix of rows is
                 (bit sign) x (PN) + cover, so
                 its top singular vector pair is (the bits, the PN). A fit counts only when the top
                 component carries far more energy than a random matrix of that shape would
                 (STRUCTURE) and the per-row loadings are two-valued (BIMODALITY). The PN is then
                 re-estimated on the raw rows, its chip width read from the run lengths, and
                 stegodepth_spread.extract_dsss reads the bits with those chips.
  echo_sweep     echo hiding with two delays. For each window length in a bounded set every window's
                 real cepstrum is taken; the two lags that most often hold a window's cepstral peak are
                 the delays. stegodepth_echo.extract_echo reads the bits with them; the cepstral
                 comparison is a second reading.
  phase_read     phase coding (Bender et al.): the first segment's phase spectrum holds the bits as
                 +pi/2 (0) and -pi/2 (1) over a run of bins. For each power-of-two segment length the
                 bins whose phase sits at +-pi/2 are found; a long dense run of them is the message.
                 Its ragged ends (chance +-pi/2 cover bins chained on, an edge bin rounded off) are
                 trimmed to solid hits and each end is moved by up to PHASE_EDGE bins.
  parity_read    parity coding: one bit per region of R samples, the XOR of the regions' sample LSBs
                 (R = 1 is plain sample LSB). On a G.711 recording, the LSB of the stored code byte.
  silence_read   silence-interval coding: each silent gap's length mod 2^k carries k bits.

Never-wrong: every reading goes through _carrier_judge (stego_containers.validate_container plus
jpeg_stego._provable). A value is PLAIN only when a stored length + CRC-32, or a checksum-carrying
gzip/zip, proves it and it is the one distinct proven payload of the survey. A fit that is
structurally strong but unproven is a note with its parameters (and a candidate when it reads as
text). Which carrier an author meant cannot be proven from the audio alone (B-245 blocker), so nothing
here is ever PLAIN without a container.

DECLINED, said out loud: a spread-spectrum PN stream that never repeats (a keyed generator) cannot be
estimated blind; supply the chips to stegodepth_spread. Echo hiding with a key-hopped delay set, and
phase coding of segments other than the first, are not read.

Bounded: frames read, matrix elements per fit, bits per reading, fits decoded, and an optional
deadline checked between stages.
"""
from __future__ import annotations

import argparse
import json
import math
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))

import _carrier_judge as cj          # noqa: E402
import stegodepth_echo as se         # noqa: E402
import stegodepth_spread as ss       # noqa: E402

MAX_FRAMES = 4_000_000          # frames read from one recording
MAX_CHANNELS = 2                # channels swept (left, right)
DEFAULT_MAX_BITS = 4096         # bits per reading (512 bytes): a container header + a flag fits easily
MIN_BITS = 16

DSSS_LENGTHS = (64, 100, 128, 200, 250, 256, 400, 500, 512, 1000, 1024, 2000, 2048, 4000, 4096, 8000, 8192)
DSSS_MAX_ELEMENTS = 1 << 21     # samples in one fit matrix
DSSS_ITERATIONS = 30            # power iterations for the top singular pair
DSSS_MIN_STRUCTURE = 2.0        # top-component energy over a random matrix's (Marchenko-Pastur edge)
DSSS_MIN_BIMODALITY = 0.80      # mean(|u|)^2 / mean(u^2): 1 for +-a, 2/pi = 0.64 for Gaussian loadings
DSSS_TOP = 4                    # fits decoded
EXPLICIT_MAX_SAMPLES = 1 << 20  # samples the pure-Python explicit decoders are asked to read
PERIOD_MAX_LAG = 4096           # the longest symbol the period detector looks for
PERIOD_WINDOW = 32              # samples per local correlation window
PERIOD_MAX_SAMPLES = 1 << 16    # samples the period detector reads
PERIOD_MIN_Z = 8.0              # a lag is a period when its score sits this many MADs over the median
PERIOD_TOP = 4                  # detected periods added to the sweep
PERIOD_SCAN = 256               # highest-scoring lags looked at for peaks
PERIOD_MAX_PEAKS = 24           # peaks kept
PERIOD_DIVISOR_Z = 4.0          # the gate for a divisor of two or more peaks (the symbol under its multiples)
PERIOD_DIVISOR_PEAKS = 8        # strongest peaks whose divisors are tried
PERIOD_MAX_DIVISOR = 8          # divisors p/2 .. p/8 of each

ECHO_WINDOWS = (256, 500, 512, 1000, 1024, 1500, 2000, 2048, 4000, 4096, 8000, 8192)
ECHO_MIN_DELAY = 2
ECHO_MAX_DELAY = 2048
ECHO_MAX_ELEMENTS = 1 << 21
ECHO_MIN_DOMINANCE = 0.5        # share of windows whose cepstral peak is one of the two delays
ECHO_TOP = 12                   # fits whose cepstral reading is judged (vectorised, cheap)
ECHO_EXPLICIT = 3               # of those, the ones also read by the pure-Python stegodepth_echo

PHASE_MIN_LOG2, PHASE_MAX_LOG2 = 6, 16
PHASE_TOL = 0.1                 # radians from +-pi/2
PHASE_MIN_RUN = 16              # bins
PHASE_DENSITY = 0.9
PHASE_GAP = 2                   # misses bridged inside a run
PHASE_EDGE = 4                  # bins each end of a run is moved by when the message is read
PHASE_SOLID = 3                 # hits in a row that mark where a run's ragged end is trimmed to

PARITY_REGIONS = (1, 2, 3, 4, 5, 8, 10, 16, 32, 64, 100, 128, 256)
PARITY_MAX_BITS = 1 << 16


class AudioCarrierError(ValueError):
    """A parameter a caller gave is out of range (never raised for bad audio: that is a note)."""


@dataclass
class Pcm:
    rate: int
    bits: int
    ints: np.ndarray            # (frames, channels) int64, signed
    floats: np.ndarray          # (frames, channels) float64 in [-1, 1)
    raw: bytes                  # a PCM WAV of these samples (the input itself when it was one) for the
    #                             explicit decoders
    container: str = "wav"      # wav | aiff | au | wav-g711 | au-g711
    codes: np.ndarray | None = None   # G.711 code bytes as stored (frames * channels), else None
    codec: str = ""             # 'mu-law' | 'a-law' for a G.711 recording

    @property
    def channels(self) -> int:
        return self.ints.shape[1]

    @property
    def frames(self) -> int:
        return self.ints.shape[0]


def pcm_wav(rate: int, bits: int, ints: np.ndarray) -> bytes:
    """A canonical PCM WAV (16/24/32-bit signed, 8-bit unsigned) of a (frames, channels) int array."""
    frames, channels = ints.shape
    width = bits // 8
    if width == 1:
        body = (np.clip(ints, -128, 127) + 128).astype(np.uint8).tobytes()
    elif width == 2:
        body = np.clip(ints, -32768, 32767).astype("<i2").tobytes()
    elif width == 3:
        v = np.clip(ints, -(1 << 23), (1 << 23) - 1).astype(np.int64).reshape(-1) & 0xFFFFFF
        body = np.stack([v & 255, (v >> 8) & 255, v >> 16], axis=1).astype(np.uint8).tobytes()
    else:
        body = np.clip(ints, -(1 << 31), (1 << 31) - 1).astype("<i4").tobytes()
    fmt = struct.pack("<HHIIHH", 1, channels, rate, rate * channels * width, channels * width, bits)
    chunks = b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", len(body)) + body
    if len(body) & 1:
        chunks += b"\x00"
    return b"RIFF" + struct.pack("<I", 4 + len(chunks)) + b"WAVE" + chunks


def mulaw_decode(codes: np.ndarray) -> np.ndarray:
    """G.711 mu-law code bytes to 16-bit linear (ITU-T G.711, the usual 14-bit table scaled by 4)."""
    u = ~codes.astype(np.int64) & 0xFF
    t = (((u & 0x0F) << 3) + 0x84) << ((u & 0x70) >> 4)
    return np.where(u & 0x80, 0x84 - t, t - 0x84)


def alaw_decode(codes: np.ndarray) -> np.ndarray:
    """G.711 A-law code bytes to 16-bit linear."""
    a = codes.astype(np.int64) ^ 0x55
    seg = (a & 0x70) >> 4
    t = (a & 0x0F) << 4
    t = np.where(seg == 0, t + 8, np.where(seg == 1, t + 0x108, (t + 0x108) << np.maximum(seg - 1, 0)))
    return np.where(a & 0x80, t, -t)


def _riff_chunks(data: bytes):
    i, n = 12, len(data)
    while i + 8 <= n:
        cid = data[i:i + 4]
        size = struct.unpack_from("<I", data, i + 4)[0]
        yield cid, data[i + 8:i + 8 + size]
        i += 8 + size + (size & 1)


def _g711_wav(data: bytes):
    """(rate, channels, codec, code bytes) of a G.711 WAV (format tag 6 A-law, 7 mu-law), or None."""
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return None
    fmt = body = None
    for cid, chunk in _riff_chunks(data):
        if cid == b"fmt " and fmt is None:
            fmt = chunk
        elif cid == b"data" and body is None:
            body = chunk
    if fmt is None or body is None or len(fmt) < 16:
        return None
    tag, channels, rate, _br, _align, bits = struct.unpack_from("<HHIIHH", fmt, 0)
    if tag not in (6, 7) or bits != 8 or not 1 <= channels <= 32:
        return None
    return rate, channels, "a-law" if tag == 6 else "mu-law", body


def _au(data: bytes):
    """(rate, channels, encoding, body) of a Sun/NeXT .au, or None."""
    if data[:4] != b".snd" or len(data) < 24:
        return None
    off, size, enc, rate, channels = struct.unpack_from(">IIIII", data, 4)
    if off < 24 or off > len(data) or not 1 <= channels <= 32:
        return None
    body = data[off:] if size in (0xFFFFFFFF, 0) else data[off:off + size]
    return rate, channels, enc, body


def _aiff(data: bytes):
    """(rate, bits, (frames, channels) int array) of an AIFF / AIFF-C PCM recording, or None."""
    if data[:4] != b"FORM" or data[8:12] not in (b"AIFF", b"AIFC"):
        return None
    comm = ssnd = None
    i, n = 12, len(data)
    while i + 8 <= n:
        cid = data[i:i + 4]
        size = struct.unpack_from(">I", data, i + 4)[0]
        if cid == b"COMM" and comm is None:
            comm = data[i + 8:i + 8 + size]
        elif cid == b"SSND" and ssnd is None:
            ssnd = data[i + 8:i + 8 + size]
        i += 8 + size + (size & 1)
    if not comm or ssnd is None or len(comm) < 18 or len(ssnd) < 8:
        return None
    channels, _frames, bits = struct.unpack_from(">HIH", comm, 0)
    if data[8:12] == b"AIFC" and len(comm) >= 22 and comm[18:22] not in (b"NONE", b"twos"):
        return None
    rate = _extended80(comm[8:18])
    if not 1 <= channels <= 32 or bits not in (8, 16, 24, 32):
        return None
    offset = struct.unpack_from(">I", ssnd, 0)[0]
    return rate, bits, _be_ints(ssnd[8 + offset:], bits, channels)


def _extended80(b: bytes) -> int:
    exp = ((b[0] & 0x7F) << 8) | b[1]
    mant = int.from_bytes(b[2:10], "big")
    if not mant or exp == 0x7FFF:
        return 0
    return max(0, int(round(mant * 2.0 ** (exp - 16383 - 63))))


def _be_ints(raw: bytes, bits: int, channels: int) -> np.ndarray:
    width = bits // 8
    frames = min(len(raw) // (width * channels), MAX_FRAMES)
    a = np.frombuffer(raw, dtype=np.uint8, count=frames * width * channels)
    if width == 1:
        v = a.view(np.int8).astype(np.int64)
    elif width == 2:
        v = a.view(">i2").astype(np.int64)
    elif width == 3:
        b = a.reshape(-1, 3).astype(np.int64)
        v = (b[:, 0] << 16) | (b[:, 1] << 8) | b[:, 2]
        v = np.where(v & 0x800000, v - (1 << 24), v)
    else:
        v = a.view(">i4").astype(np.int64)
    return v.reshape(frames, channels)


def _from_ints(rate, bits, ints, container, codes=None, codec="") -> Pcm | None:
    if ints.shape[0] < 1 or not rate:
        return None
    floats = ints.astype(np.float64) / float(1 << (bits - 1))
    return Pcm(int(rate), bits, ints, floats, pcm_wav(int(rate), bits, ints), container, codes, codec)


def load_pcm(data) -> Pcm | None:
    """A bounded recording as numpy arrays, or None: integer-PCM WAV (stegodepth_echo.parse_pcm_wav),
    AIFF/AIFF-C PCM, Sun .au (linear 8/16/24/32, mu-law, A-law) and G.711 WAV (format 6/7). A G.711
    recording is decoded to 16-bit linear for the sweeps and keeps its code bytes for the LSB read."""
    data = bytes(data) if isinstance(data, (bytearray, memoryview)) else data
    if not isinstance(data, bytes):
        return None
    info = se.parse_pcm_wav(data)
    if info is None or info.frames < 1:
        g = _g711_wav(data)
        if g is not None:
            rate, channels, codec, body = g
            n = min(len(body) // channels, MAX_FRAMES) * channels
            codes = np.frombuffer(body, dtype=np.uint8, count=n)
            lin = (mulaw_decode if codec == "mu-law" else alaw_decode)(codes).reshape(-1, channels)
            return _from_ints(rate, 16, lin, "wav-g711", codes, codec)
        au = _au(data)
        if au is not None:
            rate, channels, enc, body = au
            if enc in (1, 27):
                n = min(len(body) // channels, MAX_FRAMES) * channels
                codes = np.frombuffer(body, dtype=np.uint8, count=n)
                codec = "mu-law" if enc == 1 else "a-law"
                lin = (mulaw_decode if enc == 1 else alaw_decode)(codes).reshape(-1, channels)
                return _from_ints(rate, 16, lin, "au-g711", codes, codec)
            if enc in (2, 3, 4, 5):
                bits = 8 * (enc - 1)
                return _from_ints(rate, bits, _be_ints(body, bits, channels), "au")
            return None
        aiff = _aiff(data)
        if aiff is not None:
            rate, bits, ints = aiff
            return _from_ints(rate, bits, ints, "aiff")
        return None
    frames = min(info.frames, MAX_FRAMES)
    width = info.bits_per_sample // 8
    raw = np.frombuffer(info.samples, dtype=np.uint8, count=frames * info.block_align)
    if width == 1:
        ints = raw.astype(np.int64) - 128
    elif width == 2:
        ints = raw.view("<i2").astype(np.int64)
    elif width == 3:
        b = raw.reshape(-1, 3).astype(np.int64)
        v = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)
        ints = np.where(v & 0x800000, v - (1 << 24), v)
    else:
        ints = raw.view("<i4").astype(np.int64)
    ints = ints.reshape(frames, info.channels)
    floats = ints.astype(np.float64) / float(1 << (info.bits_per_sample - 1))
    return Pcm(info.rate, info.bits_per_sample, ints, floats, bytes(data))


def _late(deadline) -> bool:
    return deadline is not None and time.monotonic() > deadline


def _positive_ints(values, name, low, high):
    out = []
    for v in values or ():
        if type(v) is not int or not low <= v <= high:
            raise AudioCarrierError(f"{name} must be integers in {low}..{high}; got {v!r}")
        out.append(v)
    return tuple(out)


# ---- spread spectrum ---------------------------------------------------------------------------------

@dataclass
class DsssFit:
    channel: int
    length: int
    offset: int
    rows: int
    view: str                   # 'raw' (row-centred) or 'diff' (first difference: a white PN survives it)
    structure: float
    bimodality: float
    ones: float
    loadings: np.ndarray = field(repr=False)

    @property
    def score(self) -> float:
        if self.structure < DSSS_MIN_STRUCTURE or not 0.05 <= self.ones <= 0.95:
            return 0.0
        return self.bimodality


def _top_pair(M: np.ndarray):
    rng = np.random.default_rng(0)
    v = rng.standard_normal(M.shape[1])
    v /= np.linalg.norm(v)
    for _ in range(DSSS_ITERATIONS):
        v = M.T @ (M @ v)
        norm = np.linalg.norm(v)
        if not norm or not math.isfinite(norm):
            return None
        v /= norm
    u = M @ v
    return u, v, float(u @ u)


def dsss_fit(x: np.ndarray, length: int, offset: int = 0, max_bits: int = DEFAULT_MAX_BITS, channel: int = 0):
    """The best rank-1 fit (raw or differenced view) of `x` cut into `length`-sample rows, or None."""
    rows = min((len(x) - offset) // length, max_bits, DSSS_MAX_ELEMENTS // length)
    if rows < MIN_BITS:
        return None
    seg = x[offset:offset + rows * length]
    best = None
    for view in ("raw", "diff"):
        if view == "raw":
            M = seg.reshape(rows, length)
            M = M - M.mean(axis=1, keepdims=True)
        else:
            M = np.diff(seg, prepend=seg[0]).reshape(rows, length)
        total = float(np.sum(M * M))
        if total <= 0.0 or not math.isfinite(total):
            continue
        pair = _top_pair(M)
        if pair is None:
            continue
        u, _v, s1 = pair
        null = (math.sqrt(rows) + math.sqrt(length)) ** 2 * total / (rows * length)
        mu2 = float(np.mean(u * u))
        bimodality = float(np.mean(np.abs(u))) ** 2 / mu2 if mu2 > 0 else 0.0
        fit = DsssFit(channel, length, offset, rows, view, s1 / null, bimodality, float(np.mean(u > 0)), u)
        if best is None or fit.score > best.score or (fit.score == best.score and fit.structure > best.structure):
            best = fit
    return best


def _chip_width(signs: np.ndarray) -> int:
    """The chip width of a +-1 per-sample PN estimate: the gcd of its run lengths."""
    change = np.flatnonzero(np.diff(signs)) + 1
    edges = np.concatenate(([0], change, [len(signs)]))
    runs = np.diff(edges)
    return int(np.gcd.reduce(runs)) if len(runs) else len(signs)


def _dsss_read(pcm: Pcm, fit: DsssFit, S: cj.Survey):
    x = pcm.floats[:, fit.channel]
    tag = f"dsss ch{fit.channel} L{fit.length} off{fit.offset} {fit.view}"
    rows = x[fit.offset:fit.offset + fit.rows * fit.length].reshape(fit.rows, fit.length)
    sign = np.where(fit.loadings >= 0, 1.0, -1.0)
    pn = sign @ rows / fit.rows
    chips_per_sample = np.where(pn >= 0, 1, -1).astype(np.int64)
    spc = _chip_width(chips_per_sample)
    readings = []
    if fit.length % spc == 0 and 4 <= fit.length // spc <= ss.MAX_CHIPS \
            and fit.rows * fit.length <= EXPLICIT_MAX_SAMPLES:
        chips = tuple(int(c) for c in chips_per_sample[::spc])
        res = ss.extract_dsss(pcm.raw, chips=chips, samples_per_chip=spc, channel=fit.channel,
                              offset_samples=fit.offset, max_bits=fit.rows, min_correlation=0.1)
        if res is not None:
            readings.append((f"{tag} stegodepth_spread chips={len(chips)}x{spc}", np.asarray(res.bits, np.uint8)))
            S.notes.append(f"{tag}: PN of {len(chips)} chips x {spc} samples, "
                           f"{res.confident}/{len(res.bits)} bits over |corr| 0.1")
    if not readings:
        readings.append((f"{tag} rank-1 loadings", (fit.loadings > 0).astype(np.uint8)))
        S.notes.append(f"{tag}: read from the rank-1 loadings (chip width {spc} does not give "
                       f"4..{ss.MAX_CHIPS} chips within {EXPLICIT_MAX_SAMPLES} samples for stegodepth_spread)")
    best = "none"
    for name, bits in readings:
        for pol, b in (("", bits), (" inverted", 1 - bits)):
            v = S.judge_bits(b, name + pol)
            if v == "plain" or (v == "candidate" and best == "none"):
                best = v
    return best


def symbol_periods(x: np.ndarray, *, max_lag: int = PERIOD_MAX_LAG, window: int = PERIOD_WINDOW,
                   max_samples: int = PERIOD_MAX_SAMPLES, top: int = PERIOD_TOP, min_z: float = PERIOD_MIN_Z,
                   divisor_z: float = PERIOD_DIVISOR_Z):
    """[(lag, z)] of the lags at which a signal repeats up to a sign flip, strongest first.

    A PN that repeats every symbol (times the symbol's bit sign) makes the local correlation
    c_w(lag) = sum over a short window w of x[t] * x[t + lag] about +-alpha^2 * |w| at lag = the symbol
    length, for every window that does not straddle a symbol edge; the sign flips from symbol to symbol,
    so a plain autocorrelation averages it away, but the mean of |c_w(lag)| does not. The score is that
    mean, normalised by the local energies; a period is a lag whose score sits `min_z` MADs above the
    median score (on the raw signal or its first difference, which takes most of a tonal cover out).
    Bounded: `max_samples` samples, lags 2 .. `max_lag`."""
    seg = np.asarray(x[:max_samples], dtype=np.float64)
    n = (len(seg) - max_lag) // window
    if n < MIN_BITS:
        return []
    size = 1 << int(math.ceil(math.log2(window + max_lag)))
    best = np.zeros(max_lag + 1)
    for view in (seg - seg.mean(), np.diff(seg, prepend=seg[0])):
        total = np.zeros(max_lag + 1)
        energy = 0.0
        for start in range(0, n, 128):
            rows = range(start, min(n, start + 128))
            A = np.zeros((len(rows), size))
            B = np.zeros((len(rows), size))
            for i, w in enumerate(rows):
                a = view[w * window:(w + 1) * window]
                A[i, :window] = a
                B[i, :window + max_lag] = view[w * window:w * window + window + max_lag]
                energy += float(a @ a)
            c = np.fft.irfft(np.conj(np.fft.rfft(A, axis=1)) * np.fft.rfft(B, axis=1), n=size, axis=1)
            total += np.abs(c[:, :max_lag + 1]).sum(axis=0)
        if energy <= 0.0 or not math.isfinite(energy):
            continue
        score = total / energy
        body = score[2:]
        med = float(np.median(body))
        mad = float(np.median(np.abs(body - med))) or 1e-12
        z = (score - med) / mad
        z[:2] = 0.0
        best = np.maximum(best, z)
    best[:4] = 0.0                                      # a lag under 4 is a chip, not a symbol
    order = np.argsort(-best, kind="stable")
    peaks = []

    def shoulder(lag):
        return any(abs(lag - o) <= max(1, o // 64) for o in peaks)

    for lag in order[:PERIOD_SCAN]:
        lag = int(lag)
        if best[lag] < min_z:
            break
        if shoulder(lag):
            continue                                    # the shoulder of a peak already taken
        peaks.append(lag)
        if len(peaks) >= PERIOD_MAX_PEAKS:
            break
    # every multiple of the symbol length is a peak too; the symbol is the lag most peaks are multiples of

    def multiples(p):
        tol = max(1, p // 64)
        return sum(1 for q in peaks if q != p and min(q % p, p - q % p) <= tol)

    # The symbol's own lag often scores a little under its multiples (z 7-9 against 10-12 on a tonal
    # cover), so it can miss the gate or the peak cap while the multiples clear both. Each divisor
    # p/k of a strong peak is tried: it is admitted when it scores `divisor_z` and at least two peaks
    # are its multiples (a clean cover has no peak over `min_z`, so nothing is admitted there).
    for p in list(peaks[:PERIOD_DIVISOR_PEAKS]):
        for k in range(2, PERIOD_MAX_DIVISOR + 1):
            d0 = int(round(p / k))
            if d0 < 4:
                break
            tol = max(1, d0 // 64)
            lo, hi = max(4, d0 - tol), min(max_lag, d0 + tol)
            d = lo + int(np.argmax(best[lo:hi + 1]))
            if shoulder(d) or best[d] < divisor_z or multiples(d) < 2:
                continue
            peaks.append(d)

    ranked = sorted(peaks, key=lambda p: (-multiples(p), p))
    return [(p, float(best[p])) for p in ranked[:top]]


def period_divisors(found) -> list[int]:
    """The exact divisors p/2 .. p/PERIOD_MAX_DIVISOR (at least 4) of each detected period, and the gcd
    of every pair, that are not themselves detected: when a short PN with wide chips leaves only the
    multiples of its symbol over the gate (window-local correlation is weak when a window holds only a
    few chips), the symbol is one of these, and the rank-1 fit gates decide."""
    lags = [lag for lag, _ in found]
    out = []
    for i, p in enumerate(lags):
        out += [p // k for k in range(2, PERIOD_MAX_DIVISOR + 1) if p % k == 0]
        out += [math.gcd(p, q) for q in lags[i + 1:]]
    return [d for d in dict.fromkeys(out) if d >= 4 and d not in lags]


def dsss_sweep(pcm: Pcm, S: cj.Survey, *, lengths=(), offsets=(0,), max_bits=DEFAULT_MAX_BITS, deadline=None):
    """Fit every (channel, length, offset); decode the DSSS_TOP best that pass the gates. With no
    lengths given, the sweep is the symbol periods symbol_periods() finds, their divisors
    (period_divisors) and DSSS_LENGTHS."""
    given = _positive_ints(lengths, "dsss lengths", 4, ss.MAX_SYMBOL_SAMPLES)
    fits = []
    for ch in range(min(pcm.channels, MAX_CHANNELS)):
        x = pcm.floats[:, ch]
        if given:
            lengths = given
        else:
            found = symbol_periods(x)
            if found:
                S.notes.append(f"dsss ch{ch}: repeating-symbol periods " +
                               ", ".join(f"{lag} (z {z:.0f})" for lag, z in found))
            lengths = tuple(dict.fromkeys([lag for lag, _ in found if lag >= 4] + period_divisors(found)
                                          + list(DSSS_LENGTHS)))
        for L in lengths:
            for off in offsets:
                if _late(deadline):
                    S.notes.append("dsss: out of time")
                    return fits
                fit = dsss_fit(x, L, off, max_bits, ch)
                if fit is not None:
                    fits.append(fit)
    good = sorted((f for f in fits if f.score >= DSSS_MIN_BIMODALITY), key=lambda f: (-f.score, -f.structure))
    for fit in good[:DSSS_TOP]:
        if _late(deadline):
            S.notes.append("dsss: out of time")
            break
        S.notes.append(f"dsss fit: ch{fit.channel} L={fit.length} off={fit.offset} view={fit.view} "
                       f"structure={fit.structure:.1f} bimodality={fit.bimodality:.3f} ones={fit.ones:.2f}")
        _dsss_read(pcm, fit, S)
    if not good:
        S.notes.append(f"dsss: no rank-1 fit over {len(fits)} (channel, length, offset) cuts")
    return fits


# ---- echo hiding -------------------------------------------------------------------------------------

@dataclass
class EchoFit:
    channel: int
    window: int
    offset: int
    windows: int
    delay_zero: int
    delay_one: int
    dominance: float
    balance: float
    cepstral_bits: np.ndarray = field(repr=False)

    @property
    def score(self) -> float:
        return self.dominance if self.balance >= 0.05 else 0.0


def echo_fit(x: np.ndarray, window: int, offset: int = 0, max_bits: int = DEFAULT_MAX_BITS, channel: int = 0):
    """The two delays that most often hold a window's cepstral peak, or None."""
    n = min((len(x) - offset) // window, max_bits, ECHO_MAX_ELEMENTS // window)
    hi = min(window // 4, ECHO_MAX_DELAY)
    if n < MIN_BITS or hi - ECHO_MIN_DELAY < 4:
        return None
    X = x[offset:offset + n * window].reshape(n, window)
    X = X - X.mean(axis=1, keepdims=True)
    spec = np.abs(np.fft.rfft(X, axis=1))
    cep = np.fft.irfft(np.log(spec + 1e-12), n=window, axis=1)
    band = cep[:, ECHO_MIN_DELAY:hi]
    peaks = ECHO_MIN_DELAY + np.argmax(band, axis=1)
    counts = np.bincount(peaks, minlength=hi)
    order = np.argsort(-counts, kind="stable")
    a = int(order[0])
    b = next((int(o) for o in order[1:] if abs(int(o) - a) > 1), None)
    if b is None or counts[b] == 0:
        return None
    d0, d1 = sorted((a, b))
    ca, cb = int(counts[d0]), int(counts[d1])
    bits = (cep[:, d1] > cep[:, d0]).astype(np.uint8)
    return EchoFit(channel, window, offset, n, d0, d1, (ca + cb) / n, min(ca, cb) / max(ca, cb), bits)


def _echo_read(pcm: Pcm, fit: EchoFit, S: cj.Survey, explicit: bool = True):
    tag = f"echo ch{fit.channel} W{fit.window} off{fit.offset} d{fit.delay_zero}/{fit.delay_one}"
    readings = [(f"{tag} cepstrum", fit.cepstral_bits)]
    if not explicit:
        pass
    elif fit.windows * fit.window <= EXPLICIT_MAX_SAMPLES:
        res = se.extract_echo(pcm.raw, delay_zero=fit.delay_zero, delay_one=fit.delay_one,
                              window_samples=fit.window, channel=fit.channel, offset_samples=fit.offset,
                              max_bits=fit.windows)
        if res is not None:
            auto = np.asarray(res.bits, np.uint8)
            readings.insert(0, (f"{tag} stegodepth_echo", auto))
            S.notes.append(f"{tag}: stegodepth_echo {res.confident}/{len(res.bits)} windows over margin, "
                           f"{int(np.sum(auto != fit.cepstral_bits))} differ from the cepstral reading")
    else:
        S.notes.append(f"{tag}: over {EXPLICIT_MAX_SAMPLES} samples, read by the cepstrum only")
    seen = set()
    for name, bits in readings:
        for pol, b in (("", bits), (" swapped", 1 - bits)):
            key = b.tobytes()
            if key in seen:
                continue
            seen.add(key)
            S.judge_bits(b, name + pol)


def echo_sweep(pcm: Pcm, S: cj.Survey, *, windows=(), offsets=(0,), max_bits=DEFAULT_MAX_BITS, deadline=None):
    windows = _positive_ints(windows, "echo windows", 16, se.MAX_WINDOW_SAMPLES) or ECHO_WINDOWS
    fits = []
    for ch in range(min(pcm.channels, MAX_CHANNELS)):
        x = pcm.floats[:, ch]
        for W in windows:
            for off in offsets:
                if _late(deadline):
                    S.notes.append("echo: out of time")
                    return fits
                fit = echo_fit(x, W, off, max_bits, ch)
                if fit is not None:
                    fits.append(fit)
    good = sorted((f for f in fits if f.score >= ECHO_MIN_DOMINANCE), key=lambda f: (-f.score, -f.balance))
    for rank, fit in enumerate(good[:ECHO_TOP]):
        if _late(deadline):
            S.notes.append("echo: out of time")
            break
        S.notes.append(f"echo fit: ch{fit.channel} W={fit.window} off={fit.offset} delays {fit.delay_zero}/"
                       f"{fit.delay_one} dominance={fit.dominance:.2f} balance={fit.balance:.2f}")
        _echo_read(pcm, fit, S, explicit=rank < ECHO_EXPLICIT)
    if not good:
        S.notes.append(f"echo: no two-delay cepstral fit over {len(fits)} (channel, window, offset) cuts")
    return fits


# ---- phase coding ------------------------------------------------------------------------------------

def phase_runs(hit: np.ndarray, min_run: int = PHASE_MIN_RUN):
    """[(start, length)] of runs of True in `hit` that bridge gaps of up to PHASE_GAP misses and keep a
    density of at least PHASE_DENSITY, longest first."""
    runs = []
    idx = np.flatnonzero(hit)
    if not len(idx):
        return runs
    start = prev = int(idx[0])
    for i in idx[1:]:
        i = int(i)
        if i - prev - 1 > PHASE_GAP:
            runs.append((start, prev - start + 1))
            start = i
        prev = i
    runs.append((start, prev - start + 1))
    out = []
    for s, n in runs:
        if n >= min_run and hit[s:s + n].mean() >= PHASE_DENSITY:
            out.append((s, n))
    return sorted(out, key=lambda r: -r[1])


def phase_spectrum(x: np.ndarray, length: int, offset: int = 0):
    """Phases and magnitudes of bins 1 .. length/2 - 1 of the segment at `offset`, or None."""
    seg = x[offset:offset + length]
    if len(seg) < length:
        return None
    F = np.fft.rfft(seg)[1:length // 2]
    return np.angle(F), np.abs(F)


def phase_core(hit: np.ndarray, s: int, n: int, solid: int = PHASE_SOLID):
    """(start, end) of a run with its ragged ends trimmed: the first and last places where `solid` bins
    in a row are hits. A cover bin sits within PHASE_TOL of +-pi/2 by chance about 6% of the time, so
    the gap bridging can chain a few isolated chance hits onto either end of the message; `solid`
    chance hits in a row are rare (0.064^3). Falls back to the run itself when no such place exists."""
    e = s + n
    a = next((i for i in range(s, e - solid + 1) if hit[i:i + solid].all()), s)
    b = next((i for i in range(e, s + solid - 1, -1) if hit[i - solid:i].all()), e)
    return (a, b) if a < b else (s, e)


def phase_variants(ph: np.ndarray, hit: np.ndarray, s: int, n: int):
    """[(label, bits)] to judge for the run (s, n): bits are 1 where the phase is -pi/2. The message
    starts (ascending order) or ends (descending) at the trimmed run's end give or take PHASE_EDGE
    bins: a chance hit next to a solid stretch still extends it, a message bin that rounding pushed
    off +-pi/2 shortens it. Each end is moved over that range; the far end is read long, since a
    stored length ignores the tail."""
    a0, e0 = phase_core(hit, s, n)
    lo, hi = max(0, min(s, a0 - PHASE_EDGE)), min(len(ph), max(s + n, e0 + PHASE_EDGE))
    out = [(f"start{a - a0:+d} asc", (ph[a:hi] < 0).astype(np.uint8))
           for a in range(max(0, a0 - PHASE_EDGE), min(a0 + PHASE_EDGE, e0 - 1) + 1)]
    out += [(f"end{e - e0:+d} desc", (ph[lo:e] < 0).astype(np.uint8)[::-1])
            for e in range(max(e0 - PHASE_EDGE, a0 + 1), min(len(ph), e0 + PHASE_EDGE) + 1)]
    return out


def phase_read(pcm: Pcm, S: cj.Survey, *, offsets=(0,), deadline=None):
    """Find phase-coded runs in the first segment for each power-of-two segment length; judge them."""
    found = []
    for ch in range(min(pcm.channels, MAX_CHANNELS)):
        x = pcm.floats[:, ch]
        for k in range(PHASE_MIN_LOG2, PHASE_MAX_LOG2 + 1):
            L = 1 << k
            for off in offsets:
                if _late(deadline):
                    S.notes.append("phase: out of time")
                    return found
                got = phase_spectrum(x, L, off)
                if got is None:
                    continue
                ph, mag = got
                floor = float(np.max(mag)) * 1e-9
                hit = (np.abs(np.abs(ph) - math.pi / 2) < PHASE_TOL) & (mag > floor)
                runs = phase_runs(hit)
                if not runs:
                    continue
                s, n = runs[0]
                found.append((ch, L, off, s, n))
                tag = f"phase ch{ch} L{L} off{off} bins {s + 1}..{s + n}"
                S.notes.append(f"phase fit: {tag} ({n} bins at +-pi/2, density {hit[s:s + n].mean():.2f})")
                proven = False
                for label, bits in phase_variants(ph, hit, s, n):
                    for pol, bb in (("", bits), (" inverted", 1 - bits)):
                        if S.judge_bits(bb, f"{tag} {label}{pol}") == "plain":
                            proven = True
                if not proven:
                    S.notes.append(f"{tag}: not proven by a container (bits as -pi/2 = 1, ascending: "
                                   f"{cj.pack_bits((ph[s:s + n] < 0).astype(np.uint8)).hex()[:64]})")
    if not found:
        S.notes.append("phase: no run of +-pi/2 bins in any first segment")
    return found


# ---- parity coding -----------------------------------------------------------------------------------

def parity_bits(lsb: np.ndarray, region: int, max_bits: int = PARITY_MAX_BITS) -> np.ndarray:
    n = min(len(lsb) // region, max_bits)
    if n <= 0:
        return np.zeros(0, np.uint8)
    return (lsb[:n * region].reshape(n, region).sum(axis=1) & 1).astype(np.uint8)


def parity_read(pcm: Pcm, S: cj.Survey, *, regions=(), deadline=None):
    regions = _positive_ints(regions, "parity regions", 1, 1 << 16) or PARITY_REGIONS
    if pcm.codes is not None:
        # a G.711 tool flips the LSB of the stored code byte, not of the decoded linear sample
        streams = [(f"{pcm.codec} code", pcm.codes.astype(np.int64) & 1)]
    else:
        streams = [(f"ch{c}", pcm.ints[:, c] & 1) for c in range(min(pcm.channels, MAX_CHANNELS))]
        if pcm.channels > 1:
            streams.append(("interleaved", pcm.ints.reshape(-1) & 1))
    for name, lsb in streams:
        for R in regions:
            if _late(deadline):
                S.notes.append("parity: out of time")
                return
            bits = parity_bits(lsb, R)
            if len(bits) >= 64:
                S.judge_bits(bits, f"parity {name} R{R}" if R > 1 else f"lsb {name}")


# ---- silence-interval coding ---------------------------------------------------------------------------

SILENCE_THRESHOLDS = (0, 1, 2, 4, 8, 16, 32)    # |sample| at or under this is silent (integer units)
SILENCE_MIN_RUN = 8                              # samples: a shorter quiet stretch is a zero crossing
SILENCE_BITS = (1, 2, 3, 4)                      # bits per interval: the run length mod 2^k
SILENCE_MIN_INTERVALS = 16


def silence_runs(samples: np.ndarray, threshold: int, min_run: int = SILENCE_MIN_RUN) -> np.ndarray:
    """Lengths of the runs of |sample| <= threshold that are at least `min_run` long, in order; a run
    touching either end of the recording is lead-in or tail, not an interval, and is left out."""
    quiet = np.abs(samples) <= threshold
    if not quiet.any():
        return np.zeros(0, np.int64)
    edges = np.flatnonzero(np.diff(np.concatenate(([0], quiet.astype(np.int8), [0]))))
    starts, ends = edges[0::2], edges[1::2]
    keep = (ends - starts >= min_run) & (starts > 0) & (ends < len(samples))
    return (ends - starts)[keep].astype(np.int64)


def interval_bits(runs: np.ndarray, k: int) -> np.ndarray:
    """k bits (MSB first) of each run length mod 2^k."""
    vals = runs % (1 << k)
    return ((vals[:, None] >> np.arange(k - 1, -1, -1)) & 1).astype(np.uint8).reshape(-1)


def silence_read(pcm: Pcm, S: cj.Survey, *, deadline=None):
    """Silence-interval coding: the message sits in the lengths of the silent gaps (each gap's length
    mod 2^k carries k bits). Every (channel, threshold, k) reading is judged."""
    seen = set()
    for ch in range(min(pcm.channels, MAX_CHANNELS)):
        x = pcm.ints[:, ch]
        for thr in SILENCE_THRESHOLDS:
            if _late(deadline):
                S.notes.append("silence: out of time")
                return
            runs = silence_runs(x, thr)
            key = runs.tobytes()
            if len(runs) < SILENCE_MIN_INTERVALS or key in seen:
                continue
            seen.add(key)
            S.notes.append(f"silence ch{ch} |x|<={thr}: {len(runs)} intervals")
            for k in SILENCE_BITS:
                S.judge_bits(interval_bits(runs, k), f"silence ch{ch} thr{thr} k{k}")


# ---- the survey --------------------------------------------------------------------------------------

METHODS = ("parity", "silence", "phase", "echo", "dsss")


def survey(data, *, methods=METHODS, dsss_lengths=(), echo_windows=(), offsets=(0,), max_bits=DEFAULT_MAX_BITS,
           deadline=None) -> dict:
    """Every carrier over one WAV. {plain, method, channel: 'audio', candidates, readings, notes, judged}."""
    unknown = set(methods) - set(METHODS)
    if unknown:
        raise AudioCarrierError(f"unknown audio methods: {sorted(unknown)} (known: {', '.join(METHODS)})")
    offsets = _positive_ints(offsets, "offsets", 0, MAX_FRAMES) or (0,)
    if type(max_bits) is not int or not MIN_BITS <= max_bits <= se.MAX_BITS:
        raise AudioCarrierError(f"max_bits must be an integer in {MIN_BITS}..{se.MAX_BITS}")
    S = cj.Survey("audio")
    pcm = load_pcm(data)
    if pcm is None:
        S.notes.append("not a recording this reader parses (integer-PCM or G.711 WAV, AIFF, Sun .au)")
        return S.result()
    S.notes.append(f"{pcm.container}{' ' + pcm.codec if pcm.codec else ''}: {pcm.rate} Hz, {pcm.bits}-bit, "
                   f"{pcm.channels} ch, {pcm.frames} frames")
    if "parity" in methods:
        parity_read(pcm, S, deadline=deadline)
    if "silence" in methods:
        silence_read(pcm, S, deadline=deadline)
    if "phase" in methods:
        phase_read(pcm, S, offsets=offsets, deadline=deadline)
    if "echo" in methods:
        echo_sweep(pcm, S, windows=echo_windows, offsets=offsets, max_bits=max_bits, deadline=deadline)
    if "dsss" in methods:
        dsss_sweep(pcm, S, lengths=dsss_lengths, offsets=offsets, max_bits=max_bits, deadline=deadline)
    return S.result()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="audio_carriers.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--method", action="append", choices=METHODS, help="only these carriers (default: all)")
    ap.add_argument("--dsss-length", type=int, action="append", default=[], help="a DSSS symbol length to fit")
    ap.add_argument("--echo-window", type=int, action="append", default=[], help="an echo window length")
    ap.add_argument("--offset", type=int, action="append", default=[], help="a start offset in frames")
    ap.add_argument("--max-bits", type=int, default=DEFAULT_MAX_BITS)
    a = ap.parse_args(argv)
    rc = 0
    for path in a.files:
        try:
            data = path.read_bytes()
            res = survey(data, methods=tuple(a.method or METHODS), dsss_lengths=a.dsss_length,
                         echo_windows=a.echo_window, offsets=a.offset or (0,), max_bits=a.max_bits)
        except (OSError, AudioCarrierError) as e:
            print(f"audio_carriers.py: {path}: {e}", file=sys.stderr)
            rc = 2
            continue
        print(json.dumps({"input": str(path), **cj.jsonable(res)}, sort_keys=True))
    return rc


__all__ = ["AudioCarrierError", "Pcm", "load_pcm", "pcm_wav", "mulaw_decode", "alaw_decode", "symbol_periods",
           "dsss_fit", "dsss_sweep", "echo_fit", "echo_sweep", "phase_runs", "phase_spectrum", "phase_read",
           "parity_bits", "parity_read", "silence_runs", "interval_bits", "silence_read", "survey", "METHODS"]


if __name__ == "__main__":
    sys.exit(main())
