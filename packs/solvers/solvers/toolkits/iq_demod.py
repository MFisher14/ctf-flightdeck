#!/usr/bin/env python3
"""IQ capture -> frames, for the radio protocols a CTF hands out as a saved capture (B-158).

One dispatcher over six demodulators. It reads a saved IQ file (never a radio), runs each
demodulator the capture allows, hands the recovered bits to the bit-level parsers already in the
tree, and chooses among every reading by crib: a frame whose bytes carry a flag in the event format
(ctf.flagfmt) wins.

    .venv/bin/python solvers/toolkits/iq_demod.py <capture> [--rate HZ] [--format cu8|cs8|cs16|cf32]
                                                  [--proto a,b] [--out DIR] [--json] [--centre-hz HZ]
                                                  [--lora-os N] [--lora-implicit LEN,CR,CRC]
    prints a triage, then a SolverResult JSON line.

  protocol  from IQ (this module)                               then (already in the tree)
  --------  --------------------------------------------------  ------------------------------------
  tetra     pi/4-DQPSK: RRC matched filter, symbol timing and   sec_lmr_tetra.parse_air_burst
            carrier by the 4th-power law, burst search on the
            ETSI training sequences
  p25       C4FM: discriminator, integrate-and-dump, frame      sec_lmr_p25.parse_phase1_frame
            sync correlation, 4-level slicing scaled by the sync
  lora      unaligned capture: preamble run, timing and CFO     rf2_lora_phy.decode_symbols
            from the SFD downchirps, sync word, symbol bins
  gfsk      discriminator, baud from run lengths (no rate       wav_linecode line codes, framings and
            needed), bit-slip and PN9 readings                  crib ranking (B-083)
  pocsag    discriminator at 512/1200/2400 baud with fractional sdr_protocols.decode_pocsag_bits
            samples per symbol
  sstv      FM demodulation to audio, header search (the        signal_stego_depth.detect_sstv_vis,
            leader anywhere in the capture), clock (slant)      rf2_sstv_modes.decode_sstv,
            correction from the line sync pulses                signal_stego_depth.decode_sstv_martin

What it never does: open an SDR, a sound device or a socket; run GNU Radio, rtl_sdr or any other
program; install anything. A live-radio source or a flowgraph as input is refused with a named
reason. A protocol that cannot be attempted (no sample rate, too few samples per symbol, a missing
sibling module) is listed with its reason, never skipped silently.

What a "frame" is here: the air-interface unit the bit-level parser takes. TETRA bursts stay
scrambled and FEC-coded, P25 frames stay FEC-coded beyond the NID; channel decoding is not in this
module (docs/build-log/B-158.md, gaps).

Inputs: raw interleaved IQ (.cu8 .cs8 .cs16 .cf32 .cfile, or --format), SigMF (.sigmf-data beside
its .sigmf-meta), a stereo PCM WAV (left = I, right = Q), and a mono PCM WAV (audio that is already
FM-demodulated: SSTV only). The sample rate comes from --rate, the SigMF meta, the WAV header or an
rtl_433-style file name (x_433.92M_250k.cu8), in that order.

Public functions (each a plain step an operator can call):

  load_capture(path, fmt=None, rate=None)  -> Capture
  iq_from_bytes(data, fmt)                 -> complex samples
  discriminator(iq)                        phase step per sample (radians): the FM demodulator
  bursts(iq)                               [(start, end)] of the keyed stretches of a capture
  coarse_offset(iq)                        the centre of the occupied spectrum (cycles per sample)
  gfsk_bits(iq)                            bits + samples-per-bit estimate of a 2-level FSK burst
  demod_gfsk / demod_pocsag / demod_p25 / demod_tetra / demod_lora / demod_sstv   -> ProtoResult
  p25_dibits / p25_strip_status / tetra_symbols / tetra_dibits / tetra_bursts / lora_dechirp /
  lora_acquire / fractional_shift / fm_audio / inst_freq / sstv_headers / sstv_clock_error
  crib_bits(bits, ff)                      every bit-slip reading of a bit string, searched for a flag
  demodulate(capture, protocols=None, ff=None, ...) -> Report
"""
from __future__ import annotations

import argparse
import io
import json
import math
import stat
import sys
import time
import wave
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import rf  # noqa: E402  (sibling toolkit: iq_format, name_hints, te_estimate)
import wav_linecode as wl  # noqa: E402  (B-083: line codes, framings, crib ranking)

ENGINE = "toolkits.iq_demod"
PROTOCOLS = ("pocsag", "gfsk", "lora", "p25", "tetra", "sstv")
MAX_SAMPLES = 8_000_000             # complex samples kept; a longer capture is cut and says so
MAX_FRAMES = 64                     # frames kept per protocol
DEFAULT_BUDGET = 120.0              # CPU seconds (time.process_time) for one capture
SAMPLE_BYTES = {"cu8": 2, "cs8": 2, "cs16": 4, "cf32": 8}
SIGMF_TYPES = {"cu8": "cu8", "ci8": "cs8", "ci16_le": "cs16", "cf32_le": "cf32"}
LIVE_PREFIXES = ("rtl", "rtl_tcp", "rtlsdr", "hackrf", "soapy", "uhd", "airspy", "bladerf", "plutosdr",
                 "sdrplay", "osmosdr", "audio", "alsa", "pulse", "udp", "tcp", "zmq")
FLOWGRAPH_EXT = (".grc",)
POCSAG_BAUDS = (512, 1200, 2400)
P25_SYMBOL_RATE = 4800.0
TETRA_SYMBOL_RATE = 18000.0
TETRA_MIN_LOCK = 0.25               # 4th-power coherence of the symbol steps: noise is a few hundredths
LORA_BANDWIDTHS = (125000.0, 250000.0, 500000.0, 62500.0, 41666.667, 31250.0, 20833.333, 15625.0,
                   10416.667, 7812.5)       # Hz, likeliest first
LORA_SFS = (7, 8, 9, 10, 11, 12)
LORA_MIN_SHARE = 0.25               # share of a symbol's energy in one FFT bin that counts as a chirp
LORA_MAX_SYMBOLS = 1024             # data symbols read after an SFD (the longest packet is about 600)
AUDIO_RATE = 48000                  # the rate FM-demodulated audio is brought to for SSTV
# One scan line (ms) of each SSTV mode, by VIS code: sync + porches + colour scans (N7CXI mode
# specifications). PD and Robot 36 carry two picture rows in one such period.
SSTV_LINE_MS = {
    44: 4.862 + 0.572 + 3 * (146.432 + 0.572),      # Martin M1
    40: 4.862 + 0.572 + 3 * (73.216 + 0.572),       # Martin M2
    60: 9.0 + 3 * 1.5 + 3 * 138.240,                # Scottie S1
    56: 9.0 + 3 * 1.5 + 3 * 88.064,                 # Scottie S2
    76: 9.0 + 3 * 1.5 + 3 * 345.600,                # Scottie DX
    8: 9.0 + 3.0 + 88.0 + 4.5 + 1.5 + 44.0,         # Robot 36
    12: 9.0 + 3.0 + 138.0 + 2 * (4.5 + 1.5 + 69.0),  # Robot 72
    93: 20.0 + 2.08 + 4 * 91.520,                   # PD50
    99: 20.0 + 2.08 + 4 * 170.240,                  # PD90
    95: 20.0 + 2.08 + 4 * 121.600,                  # PD120
}


class IQDemodError(ValueError):
    """A capture or a protocol attempt that cannot proceed; the message is the named reason."""


# ---- result types ----------------------------------------------------------------------------------

@dataclass
class Capture:
    name: str
    fmt: str                        # cu8 | cs8 | cs16 | cf32 | wav-iq | wav-audio
    rate: float | None              # Hz; None when nothing states it
    rate_source: str                # option | sigmf | wav | name | none
    iq: np.ndarray | None = None    # complex baseband, or None for a mono (audio) WAV
    audio: np.ndarray | None = None  # mono audio of a mono WAV
    total_samples: int = 0          # samples in the file (before the cap)
    notes: list = field(default_factory=list)

    @property
    def samples(self):
        return int(self.iq.size if self.iq is not None else (self.audio.size if self.audio is not None else 0))


@dataclass
class Frame:
    proto: str
    summary: str                    # one line a human can check
    data: bytes = b""               # the bytes searched for a flag
    text: str = ""                  # decoded text when the protocol carries text (shown, not searched)
    fields: dict = field(default_factory=dict)
    validated: str = ""             # the protocol check that vouches for the frame ("" = none)
    flags: tuple = ()
    lead: bool = False


@dataclass
class ProtoResult:
    proto: str
    frames: list = field(default_factory=list)
    params: dict = field(default_factory=dict)
    error: str = ""                 # the named reason this protocol was not attempted or failed
    note: str = ""

    @property
    def flags(self):
        return tuple(dict.fromkeys(f for fr in self.frames for f in fr.flags))


@dataclass
class Report:
    capture: Capture
    results: list = field(default_factory=list)
    flags: tuple = ()
    best: Frame | None = None
    files: list = field(default_factory=list)   # pictures written with --out

    def result(self, proto):
        for r in self.results:
            if r.proto == proto:
                return r
        return None


# ---- loading ---------------------------------------------------------------------------------------

def iq_from_bytes(data, fmt):
    """Complex samples (complex64, about unit scale) of raw interleaved IQ in `fmt` (cu8, cs8, cs16
    little-endian, cf32 little-endian). A ragged tail (not a whole I/Q pair) is an IQDemodError: the
    caller decides whether to cut it. Non-finite floats are an IQDemodError."""
    width = SAMPLE_BYTES.get(fmt)
    if width is None:
        raise IQDemodError(f"unsupported IQ format {fmt!r} (have {', '.join(SAMPLE_BYTES)})")
    if len(data) % width:
        raise IQDemodError(f"{fmt} data is {len(data)} bytes: not whole I/Q pairs of {width} bytes")
    if fmt == "cu8":
        a = (np.frombuffer(data, dtype=np.uint8).astype(np.float32) - 127.5) / 127.5
    elif fmt == "cs8":
        a = np.frombuffer(data, dtype=np.int8).astype(np.float32) / 128.0
    elif fmt == "cs16":
        a = np.frombuffer(data, dtype="<i2").astype(np.float32) / 32768.0
    else:
        a = np.frombuffer(data, dtype="<f4").astype(np.float32)
        if not np.all(np.isfinite(a)):
            raise IQDemodError("cf32 capture contains a non-finite sample")
    return (a[0::2] + 1j * a[1::2]).astype(np.complex64)


def _wav_channels(path, skip=0, max_samples=None):
    """(rate, float32 array of shape (frames, channels), true frame count) of a PCM WAV. The file
    is streamed: `skip` frames are passed over with a seek and at most `max_samples` (capped at
    MAX_SAMPLES) are read, so a long WAV is never loaded whole and --skip reaches past the cap."""
    limit = MAX_SAMPLES if max_samples is None else min(int(max_samples), MAX_SAMPLES)
    try:
        with open(path, "rb") as fh, wave.open(fh, "rb") as w:
            if w.getcomptype() != "NONE":
                raise IQDemodError("WAV is compressed: only PCM is read")
            ch, sw, rate, total = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
            if rate <= 0 or ch < 1 or sw not in (1, 2, 3, 4):
                raise IQDemodError(f"unsupported WAV layout ({ch} channels, {sw} bytes per sample, {rate} Hz)")
            # setpos past the end is a wave.Error, but setpos(total) is legal and reads nothing,
            # so a skip at or past the end becomes "no samples" (load_capture names that)
            w.setpos(min(int(skip), total))
            raw = w.readframes(limit)           # stops at the end of the data
    except IQDemodError:
        raise
    except (wave.Error, EOFError, ValueError) as e:
        raise IQDemodError(f"not a PCM WAV this reads: {e}") from e
    raw = raw[:len(raw) // (sw * ch) * (sw * ch)]
    if sw == 1:
        a = (np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128.0) / 128.0
    elif sw == 2:
        a = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
    elif sw == 3:
        b = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3).astype(np.int32)
        v = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)
        a = (v - (v >= (1 << 23)) * (1 << 24)).astype(np.float32) / float(1 << 23)
    else:
        a = (np.frombuffer(raw, dtype="<i4").astype(np.float64) / float(1 << 31)).astype(np.float32)
    return rate, a.reshape(-1, ch), total


SIGMF_META_MAX = 4 << 20            # bytes of .sigmf-meta read; a larger meta is refused unread


def _sigmf(meta_path):
    """(format, rate or None) a .sigmf-meta states. The meta is untrusted data: only its datatype
    and sample rate are read, and both are checked."""
    try:
        if meta_path.stat().st_size > SIGMF_META_MAX:     # checked before a byte is read
            raise IQDemodError(f"{meta_path.name} is over 4 MiB: not read")
        with meta_path.open("rb") as fh:
            raw = fh.read(SIGMF_META_MAX + 1)
        if len(raw) > SIGMF_META_MAX:                     # it grew between the stat and the read
            raise IQDemodError(f"{meta_path.name} is over 4 MiB: not read")
        meta = json.loads(raw.decode("utf-8", "replace"))
        glob = meta["global"]
        dtype = str(glob["core:datatype"])
    except IQDemodError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise IQDemodError(f"cannot read the SigMF meta {meta_path.name}: {type(e).__name__}: {e}") from e
    fmt = SIGMF_TYPES.get(dtype)
    if fmt is None:
        raise IQDemodError(f"SigMF datatype {dtype!r} is not read (have {', '.join(SIGMF_TYPES)})")
    rate = glob.get("core:sample_rate")
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate <= 0:
        rate = None
    return fmt, (float(rate) if rate else None)


def refuse_live(source):
    """Raise IQDemodError when `source` names a live radio, a device, a pipe or a flowgraph rather
    than a saved capture. This engine reads files; it never opens an SDR and never runs GNU Radio."""
    text = str(source)
    head = text.split(":", 1)[0].split("=", 1)[0].lower()
    if text == "-" or ((":" in text or "=" in text) and head in LIVE_PREFIXES and not Path(text).exists()):
        raise IQDemodError(f"{text!r} names a live source: this engine reads saved captures only and "
                           "never opens an SDR, a sound device or a socket (record to a file first)")
    p = Path(text)
    if p.suffix.lower() in FLOWGRAPH_EXT:
        raise IQDemodError(f"{p.name} is a GNU Radio flowgraph: it is not run (gnuradio is not used or "
                           "installed here); pass the IQ file it reads")
    try:
        mode = p.stat().st_mode
    except OSError as e:
        raise IQDemodError(f"{text}: {e.strerror or e}") from e
    if not stat.S_ISREG(mode):
        raise IQDemodError(f"{text} is not a regular file (a device or pipe is a live source: this "
                           "engine reads saved captures only)")


def _require_samples(name, count):
    """IQDemodError when a capture holds no samples: every demodulator would otherwise report a
    plain 'nothing found' (or trip on an empty array) and hide that there was nothing to read."""
    if count <= 0:
        raise IQDemodError(f"{name}: the capture holds no samples (empty file, or --skip past its end)")


def load_capture(path, fmt=None, rate=None, skip=0, max_samples=MAX_SAMPLES):
    """Read a saved capture into a Capture. IQDemodError with the reason when it is a live source,
    an unknown format or unreadable. `skip` complex samples are passed over first; at most
    `max_samples` are kept, and a cut capture says so in its notes."""
    refuse_live(path)
    p = Path(path)
    notes = []
    if rate is not None and (not math.isfinite(rate) or rate <= 0):
        raise IQDemodError(f"--rate must be a positive number of Hz, not {rate!r}")
    if skip < 0 or max_samples < 1:
        raise IQDemodError("--skip must be >= 0 and --max-samples >= 1")
    max_samples = min(int(max_samples), MAX_SAMPLES)
    rate_source = "option" if rate is not None else "none"
    with p.open("rb") as fh:
        head = fh.read(12)
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE" and fmt is None:
        wav_rate, chans, total = _wav_channels(p, skip, max_samples)
        if rate is None:
            rate, rate_source = float(wav_rate), "wav"
        _require_samples(p.name, chans.shape[0])
        if total - skip > chans.shape[0]:
            notes.append(f"capture cut to {chans.shape[0]} of {total} frames (--skip / --max-samples)")
        if chans.shape[1] == 1:
            cap = Capture(p.name, "wav-audio", rate, rate_source, audio=chans[:, 0].astype(np.float64),
                          total_samples=total, notes=notes)
            notes.append("mono WAV: read as already-demodulated audio (SSTV only); IQ needs two channels")
            return cap
        if chans.shape[1] > 2:
            notes.append(f"WAV has {chans.shape[1]} channels: the first two are read as I and Q")
        iq = (chans[:, 0] + 1j * chans[:, 1]).astype(np.complex64)
        return Capture(p.name, "wav-iq", rate, rate_source, iq=iq, total_samples=total, notes=notes)
    if fmt is None and p.name.lower().endswith(".sigmf-data"):
        meta = p.with_name(p.name[:-len(".sigmf-data")] + ".sigmf-meta")
        if not meta.is_file():
            raise IQDemodError(f"{p.name} has no {meta.name} beside it: pass --format and --rate")
        fmt, meta_rate = _sigmf(meta)
        if rate is None and meta_rate:
            rate, rate_source = meta_rate, "sigmf"
    if fmt is None:
        fmt = rf.iq_format(p.name)
    if fmt is None:
        raise IQDemodError(f"{p.name}: the IQ sample format is not stated by the extension "
                           f"(.cu8 .cs8 .cs16 .cf32 .cfile .sigmf-data, or a WAV): pass --format")
    fmt = {"cs16le": "cs16", "cf32le": "cf32", "u8": "cu8", "s8": "cs8"}.get(fmt.lower(), fmt.lower())
    width = SAMPLE_BYTES.get(fmt)
    if width is None:
        raise IQDemodError(f"unsupported IQ format {fmt!r} (have {', '.join(SAMPLE_BYTES)})")
    size = p.stat().st_size
    total = size // width
    if size % width:
        notes.append(f"{size % width} trailing byte(s) dropped: not a whole {fmt} I/Q pair")
    with p.open("rb") as fh:
        fh.seek(skip * width)
        data = fh.read(max_samples * width)
    data = data[:len(data) // width * width]
    iq = iq_from_bytes(data, fmt)
    _require_samples(p.name, iq.size)
    if total - skip > iq.size:
        notes.append(f"capture cut to {iq.size} of {total} samples (--skip / --max-samples)")
    if rate is None:
        hint = rf.name_hints(p.name)[1]
        if hint:
            rate, rate_source = float(hint), "name"
    return Capture(p.name, fmt, rate, rate_source, iq=iq, total_samples=total, notes=notes)


# ---- signal helpers --------------------------------------------------------------------------------

def discriminator(iq):
    """The phase step between consecutive samples, in radians (-pi, pi]: the FM demodulator. One
    sample shorter than the input. Multiply by rate / (2 pi) for Hz."""
    x = np.asarray(iq)
    if x.size < 2:
        return np.zeros(0)
    return np.angle(x[1:] * np.conj(x[:-1])).astype(np.float64)


def boxcar(x, w):
    """The centred w-sample moving average of x (same length; the window shrinks at the edges)."""
    x = np.asarray(x)
    w = int(w)
    if w <= 1 or x.size == 0:
        return x.astype(np.float64) if not np.iscomplexobj(x) else x
    c = np.concatenate(([0], np.cumsum(x, dtype=np.complex128 if np.iscomplexobj(x) else np.float64)))
    i = np.arange(x.size)
    a = np.clip(i - w // 2, 0, x.size)
    b = np.clip(i - w // 2 + w, 0, x.size)
    return (c[b] - c[a]) / np.maximum(b - a, 1)


def sample_at(x, start, step, count=None):
    """x read at start, start + step, ... by linear interpolation (a fractional samples-per-symbol
    clock). At most `count` values; it stops before the end of x."""
    x = np.asarray(x)
    if x.size < 2 or step <= 0:
        return x[:0]
    n = int(math.floor((x.size - 1 - start) / step)) + 1 if start <= x.size - 1 else 0
    if count is not None:
        n = min(n, int(count))
    if n <= 0:
        return x[:0]
    pos = start + step * np.arange(n)
    i = np.clip(np.floor(pos).astype(np.int64), 0, x.size - 2)
    frac = pos - i
    return x[i] * (1.0 - frac) + x[i + 1] * frac


def bursts(iq, min_len=64, max_bursts=16):
    """[(start, end)] of the keyed stretches of a capture, in order (the max_bursts longest): where
    a 64-sample amplitude envelope rises above twice the noise floor (its 10th percentile) and above a
    quarter of its peak. The peak is the envelope's maximum, so one short burst in a long quiet capture
    (a key-fob press) is found. A capture with no on/off contrast, the peak under twice the floor (a
    continuous carrier, or a signal under 6 dB above the noise), is one stretch, the whole of it.
    Edges are good to about 16 samples."""
    x = np.asarray(iq)
    if x.size < min_len:
        return []
    env = boxcar(np.abs(x), 64)
    floor, peak = float(np.percentile(env, 10)), float(np.max(env))
    if peak <= floor * 2.0 + 1e-9:
        return [(0, int(x.size))]
    on = env > max(2.0 * floor, 0.25 * peak)
    edges = np.flatnonzero(np.diff(on.astype(np.int8)))
    starts = list(edges[on[edges + 1]] + 1) if edges.size else []
    ends = list(edges[~on[edges + 1]] + 1) if edges.size else []
    if on[0]:
        starts.insert(0, 0)
    if on[-1]:
        ends.append(int(x.size))
    spans = [[int(a), int(b)] for a, b in zip(starts, ends)]
    merged = []
    for a, b in spans:                      # a short dropout inside a burst does not split it
        if merged and a - merged[-1][1] < min_len:
            merged[-1][1] = b
        else:
            merged.append([a, b])
    out = [(a, b) for a, b in merged if b - a >= min_len]
    out.sort(key=lambda s: s[0] - s[1])
    return sorted(out[:max_bursts])


def coarse_offset(iq, nfft=1024, max_segments=512):
    """The centre of a capture's occupied spectrum, in cycles per sample (-0.5 to 0.5): the power
    spectrum averaged over up to max_segments stretches spread across the capture, then its centroid
    taken round the circle, so a signal at the band edge does not average to the middle and a flat
    noise floor pulls nowhere. For a modulation with a symmetric spectrum this is the carrier offset,
    good to a small part of the bandwidth. 0.0 when the capture is shorter than one stretch."""
    x = np.asarray(iq)
    count = min(max_segments, x.size // nfft)
    if count < 1:
        return 0.0
    starts = np.linspace(0, x.size - nfft, count).astype(np.int64)
    window = np.hanning(nfft)
    power = np.zeros(nfft)
    for a in starts:
        power += np.abs(np.fft.fft(x[a:a + nfft] * window)) ** 2
    turn = np.sum(power * np.exp(2j * np.pi * np.fft.fftfreq(nfft)))
    return float(np.angle(turn) / (2 * np.pi))


def run_lengths(levels):
    """Signed run lengths of a 0/1 array: +n for n ones, -n for n zeros (rf.runs, vectorised)."""
    lv = np.asarray(levels).astype(np.int8)
    if lv.size == 0:
        return []
    cuts = np.flatnonzero(np.diff(lv)) + 1
    bounds = np.concatenate(([0], cuts, [lv.size]))
    lens = np.diff(bounds)
    signs = np.where(lv[bounds[:-1]] > 0, 1, -1)
    return (lens * signs).tolist()


def pack_bits(bits, msb_first=True):
    """Whole bytes of a 0/1 numpy array or bit string (a ragged tail is dropped)."""
    a = _bit_array(bits)
    a = a[:a.size // 8 * 8]
    return np.packbits(a, bitorder="big" if msb_first else "little").tobytes()


def _bit_array(bits):
    if isinstance(bits, str):
        return (np.frombuffer(bits.encode("ascii"), dtype=np.uint8) - 48).astype(np.uint8)
    return np.asarray(bits, dtype=np.uint8)


def _bit_string(bits):
    return bits if isinstance(bits, str) else (np.asarray(bits, dtype=np.uint8) + 48).tobytes().decode("ascii")


# ---- crib selection --------------------------------------------------------------------------------

def crib_bits(bits, ff):
    """Every bit-slip reading of a bit string searched for a flag: 8 bit offsets x both polarities x
    both bit orders. Returns [(label, bytes, flags, lead)] for the readings that carry a flag or the
    flag lead (`PREFIX{`), flags first. A flag in a demodulated stream sits at whatever bit offset the
    frame put it; this finds it without knowing the framing."""
    a = _bit_array(bits)
    out = []
    for inv in (False, True):
        b = (1 - a) if inv else a
        for off in range(8):
            for order in ("msb", "lsb"):
                blob = pack_bits(b[off:], order == "msb")
                if not blob:
                    continue
                flags = tuple(dict.fromkeys(ff.find_flags(blob)))
                lead = bool(flags) or bool(ff.lead_bregex.search(blob))
                if lead:
                    label = f"bit offset {off}, {order}-first{', inverted' if inv else ''}"
                    out.append((label, blob, flags, lead))
    out.sort(key=lambda r: (not r[2], len(r[1])))
    return out


def _mark(frame, ff):
    """Fill a frame's flags and lead from its bytes."""
    frame.flags = tuple(dict.fromkeys(ff.find_flags(frame.data))) if frame.data else ()
    frame.lead = bool(frame.flags) or bool(frame.data and ff.lead_bregex.search(frame.data))
    return frame


def _slip_frames(proto, bits, ff, what):
    """Frames for the bit-slip readings of a whole demodulated stream that carry a flag or its lead."""
    out = []
    for label, blob, _flags, _lead in crib_bits(bits, ff)[:4]:
        i = blob.find(b"{")
        preview = "".join(chr(c) if 32 <= c < 127 else "." for c in blob[max(0, i - 16):i + 80])
        out.append(_mark(Frame(proto, f"{what}, {label}: {preview!r}", data=blob), ff))
    return out


def _preview(data, n=60):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in data[:n])


# ---- GFSK / 2-FSK ----------------------------------------------------------------------------------

PN9_SYNC_WORDS = (b"\xd3\x91", b"\x2d\xd4", b"\x93\x0b\x51\xde")   # CC1101 / RFM69-Si446x / CC1200 defaults
GFSK_MIN_RUN_FIT = 0.8              # share of runs that are a whole number of bit times (noise: under 0.5)


def gfsk_bits(iq):
    """Bits of one 2-level FSK / GFSK burst without being told the baud: the discriminator is
    smoothed, sliced at the midpoint of its two levels, and the run lengths give the samples per bit
    (rf.te_estimate, refined by a least-squares fit over all runs), as in the B-083 WAV front end.
    The smoothing window is tried at 3, 5, 9, ... samples and the widest-eyed reading whose runs fit a
    bit clock is kept (a slow burst sampled fast needs the longer window to rise out of the
    discriminator noise; a window as long as a bit erases the bits, and its runs no longer fit).
    Returns {'bits', 'sps', 'eye', 'run_fit', 'deviation', 'smoothing'} or None when the burst has no
    two-level structure. eye is the level separation over the spread within a level, read at the
    middle of each run that lasts most of a bit; run_fit the fraction of runs that are a whole number
    of bit times; deviation is in radians per sample (x rate / 2 pi = Hz)."""
    d = discriminator(iq)
    if d.size < 64:
        return None
    best = None
    for w in (3, 5, 9, 17, 33, 65, 129):
        got = _gfsk_reading(d, w)
        if got is None:
            continue
        score = (got["run_fit"] >= GFSK_MIN_RUN_FIT, got["eye"])
        if best is None or score > best[0]:
            best = (score, got)
    return best[1] if best else None


def _gfsk_reading(d, w):
    """gfsk_bits at one smoothing window (samples)."""
    sm = boxcar(d, w)
    lo, hi = np.percentile(sm, [10, 90])
    if hi - lo < 1e-4:
        return None
    centre = (lo + hi) / 2.0
    # a Schmitt trigger: the level changes only once the stream is 15 % of the swing past the centre,
    # so noise at a crossing does not chatter into one-sample runs (which would set the bit time)
    margin = 0.15 * (hi - lo)
    state = np.where(sm > centre + margin, 1, np.where(sm < centre - margin, -1, 0))
    last = np.where(state != 0, np.arange(state.size), 0)
    np.maximum.accumulate(last, out=last)
    levels = state[last] > 0
    timings = run_lengths(levels)
    unit = rf.te_estimate(timings)
    if not unit or unit < 2:
        return None
    t = np.abs(np.asarray(timings, dtype=np.float64))
    n = np.rint(t / unit)
    ok = (n >= 1) & (np.abs(t / unit - n) < 0.3)
    if ok.sum() < 8:
        return None
    sps = float(t[ok].sum() / n[ok].sum())
    n = np.rint(t / sps)
    run_fit = float(np.mean((n >= 1) & (np.abs(t / sps - n) < 0.3)))
    symbols = wl.symbols_from_runs(timings, sps)
    # the eye, read where a receiver would: at the middle of each run that lasts most of a bit
    ends = np.cumsum(t).astype(np.int64)
    mids = (ends - (t // 2).astype(np.int64) - 1)[t >= 0.6 * sps]
    vals = sm[np.clip(mids, 0, sm.size - 1)]
    high, low = vals[vals > centre], vals[vals <= centre]
    if high.size < 4 or low.size < 4:
        return None
    spread = math.sqrt((float(np.var(high)) * high.size + float(np.var(low)) * low.size) / vals.size) + 1e-12
    eye = float((np.mean(high) - np.mean(low)) / spread)
    top, bottom = np.percentile(sm, [95, 5])       # the settled levels: shaping rounds off alternating bits
    return {"bits": np.asarray(symbols, dtype=np.uint8), "sps": sps, "eye": eye, "run_fit": run_fit,
            "deviation": float((top - bottom) / 2.0), "smoothing": w}


def _pn9_frames(bits, ff, scheme):
    """Readings that are PN9-whitened after a known sync word (the CC1101-family packet format):
    for each sync word found in the bit stream, the bytes after it de-whitened."""
    import rf_demod_full as rfd
    text = _bit_string(bits)
    out = []
    for sync in PN9_SYNC_WORDS:
        pat = "".join(f"{b:08b}" for b in sync)
        at = text.find(pat)
        seen = 0
        while at >= 0 and seen < 8:
            body = pack_bits(text[at + len(pat):at + len(pat) + 8 * 4096])
            if body:
                plain = rfd.pn9(body)
                fr = _mark(Frame("gfsk", f"{scheme}, sync {sync.hex()} + PN9 de-whitening: {_preview(plain)!r}",
                                 data=plain, fields={"sync_word": sync.hex(), "whitening": "pn9"}), ff)
                if fr.lead:
                    out.append(fr)
            seen += 1
            at = text.find(pat, at + 1)
    return out


def demod_gfsk(cap, ff):
    """2-level FSK / GFSK bursts to candidate frames. Needs no sample rate. Each burst is read as
    NRZ (both polarities), NRZ-I and Manchester under the B-083 framings (raw, 0x7E sync word, HDLC),
    at every bit offset, and PN9-de-whitened after the common sync words; the crib picks."""
    res = ProtoResult("gfsk")
    if cap.iq is None:
        res.error = "gfsk: needs IQ (this capture is mono audio)"
        return res
    spans = bursts(cap.iq)
    best_q = None
    for a, b in spans:
        got = gfsk_bits(cap.iq[a:b])
        if got is None:
            continue
        q = (got["run_fit"], got["eye"])
        if best_q is None or q > best_q[0]:
            best_q = (q, got, a)
        if got["run_fit"] < GFSK_MIN_RUN_FIT:
            continue                        # the runs fit no bit clock: not a two-level keyed signal
        sym = got["bits"].tolist()
        scheme = f"burst@{a} {got['sps']:.2f} samples/bit"
        if cap.rate:
            scheme += f" ({cap.rate / got['sps']:.0f} baud)"
        sources = {f"{scheme}:nrz": wl.nrz_bits(sym, False), f"{scheme}:nrz_inv": wl.nrz_bits(sym, True),
                   f"{scheme}:nrzi1": wl.nrzi_bits(sym, True), f"{scheme}:nrzi0": wl.nrzi_bits(sym, False)}
        for conv in ("ieee", "thomas"):
            mb, _bad = wl.manchester_bits(sym, conv)
            if mb:
                sources[f"{scheme}:manchester_{conv}"] = mb
        cands = wl.rank_candidates(wl.stream_candidates(sources, ff))
        for c in cands[:3]:
            if c.flags or c.lead or (wl._printable_ratio(c.data) >= 0.9 and len(c.data) >= 8):
                res.frames.append(Frame("gfsk", f"{c.scheme}, {c.bit_order}-first, framing {c.framing}: {c.text[:60]!r}",
                                        data=c.data, flags=c.flags, lead=c.lead,
                                        fields={"scheme": c.scheme, "framing": c.framing, "bit_order": c.bit_order}))
        if not any(f.flags for f in res.frames):
            for code in ("nrz", "nrzi1"):                   # the bit-slip crib tries both polarities itself
                res.frames += _slip_frames("gfsk", sources[f"{scheme}:{code}"], ff, f"{scheme}:{code}")
            for code in ("nrz", "nrz_inv", "nrzi1", "nrzi0"):
                res.frames += _pn9_frames(sources[f"{scheme}:{code}"], ff, f"{scheme}:{code}")
        if len(res.frames) >= MAX_FRAMES:
            break
    if best_q is not None:
        _q, got, a = best_q
        res.params = {"bursts": len(spans), "samples_per_bit": round(got["sps"], 3), "eye": round(got["eye"], 2),
                      "run_fit": round(got["run_fit"], 3), "bits": int(got["bits"].size)}
        if cap.rate:
            res.params["baud"] = round(cap.rate / got["sps"], 1)
            res.params["deviation_hz"] = round(abs(got["deviation"]) * cap.rate / (2 * math.pi), 1)
    if not res.frames:
        res.note = ("no two-level FSK burst found"
                    if best_q is None or best_q[0][0] < GFSK_MIN_RUN_FIT
                    else "two-level FSK bits recovered, but no reading carries the flag or readable text")
    res.frames = res.frames[:MAX_FRAMES]
    return res


# ---- POCSAG ----------------------------------------------------------------------------------------

def fsk_symbols(d, sps, phases=16):
    """Binary symbols of a discriminator stream at a known (fractional) samples-per-symbol: the
    stream is averaged over one symbol and read at the timing phase with the widest eye. `d` must
    already be centred on the decision level. Returns (bits as uint8, eye) with eye = mean |symbol|
    over its standard deviation; (empty, 0.0) for too short a stream."""
    if d.size < 4 * sps:
        return np.zeros(0, dtype=np.uint8), 0.0
    y = boxcar(d, max(1, int(round(sps))))
    best = None
    for k in range(phases):
        s = sample_at(y, sps / 2.0 + k * sps / phases, sps)
        if s.size < 4:
            continue
        mag = np.abs(s)
        eye = float(np.mean(mag) / (np.std(mag) + 1e-12))
        if best is None or eye > best[0]:
            best = (eye, s)
    if best is None:
        return np.zeros(0, dtype=np.uint8), 0.0
    return (best[1] > 0).astype(np.uint8), best[0]


def demod_pocsag(cap, ff):
    """POCSAG pager bursts: the discriminator is read at 512, 1200 and 2400 baud (fractional samples
    per symbol, so any capture rate works), in both polarities, and the bits go to
    sdr_protocols.decode_pocsag_bits (sync word, BCH(31,21) correction, message text). A frame is one
    message."""
    res = ProtoResult("pocsag")
    if cap.iq is None:
        res.error = "pocsag: needs IQ (for a mono discriminator WAV use rf_demod_full.py pocsag --format wav)"
        return res
    if not cap.rate:
        res.error = "pocsag: the sample rate is unknown (pass --rate)"
        return res
    import sdr_protocols as sdr
    tried = []
    best = None
    for a, b in bursts(cap.iq, min_len=int(cap.rate * 0.05)):
        d = discriminator(cap.iq[a:b])
        if d.size < 64:
            continue
        lo, hi = np.percentile(boxcar(d, 3), [10, 90])
        d = d - (lo + hi) / 2.0
        for baud in POCSAG_BAUDS:
            sps = cap.rate / baud
            if sps < 2.0:
                tried.append(f"{baud} baud needs >= {2 * baud} Hz")
                continue
            bits, eye = fsk_symbols(d, sps)
            if bits.size < 64 or bits.size > sdr.MAX_BITS:
                continue
            # POCSAG keys a 1 as the lower frequency; a spectrum-inverted capture has it the other way
            for sense, stream in (("1 = lower frequency (standard)", 1 - bits), ("1 = higher frequency (inverted)", bits)):
                msgs = sdr.decode_pocsag_bits(_bit_string(stream))
                if not msgs:
                    continue
                score = (len(msgs), eye)
                if best is None or score > best[0]:
                    best = (score, baud, sense, msgs, a, eye)
    if tried:
        res.params["not_tried"] = "; ".join(sorted(set(tried)))
    if best is None:
        res.note = "no POCSAG sync word (0x7CD215D8) at 512, 1200 or 2400 baud in either polarity"
        if tried:
            res.note += f" ({res.params['not_tried']})"
        return res
    _score, baud, sense, msgs, start, eye = best
    res.params.update({"baud": baud, "polarity": sense, "burst_start": int(start), "eye": round(eye, 2),
                       "messages": len(msgs)})
    for m in msgs[:MAX_FRAMES]:
        alnum, numeric = m.get("alphanumeric", ""), m.get("numeric", "")
        fr = Frame("pocsag", f"address {m['address']} function {m['function']}: {alnum[:60]!r} "
                             f"(numeric reading {numeric[:24]!r})",
                   text=alnum + "\n" + numeric, data=alnum.encode("latin-1", "replace"),
                   fields={k: v for k, v in m.items()}, validated="sync word + BCH(31,21) codewords")
        res.frames.append(_mark(fr, ff))
    return res


# ---- P25 phase 1 (C4FM) ----------------------------------------------------------------------------

def _p25_sync_levels():
    import sec_lmr_p25 as p25
    bits = f"{p25.PHASE1_SYNC:048b}"
    level = {"01": 3.0, "00": 1.0, "10": -1.0, "11": -3.0}
    return np.array([level[bits[i:i + 2]] for i in range(0, 48, 2)])


def p25_dibits(iq, rate, threshold=0.85, max_symbols=864):
    """C4FM symbols after each P25 phase-1 frame sync in a capture. The discriminator (Hz) is
    integrated over one symbol (4800 symbols/s), correlated against the 24-symbol frame sync
    (0x5575F5FF77FF: only the outer +-1800 Hz levels), and at every correlation peak the sync itself
    gives the scale and the carrier offset for the 4-level slicer (+3 -> 01, +1 -> 00, -1 -> 10,
    -3 -> 11). Returns [{'sample', 'correlation', 'inverted', 'deviation_hz', 'offset_hz', 'bits'}]:
    bits is a uint8 array, two per symbol, starting with the sync, up to max_symbols symbols (the
    longest data unit, an LDU, is 864). A negative correlation is a spectrum-inverted capture."""
    sps = rate / P25_SYMBOL_RATE
    if sps < 2.0:
        raise IQDemodError(f"p25: {rate:g} Hz is under 2 samples per C4FM symbol (needs >= 9600 Hz)")
    hz = discriminator(iq) * (rate / (2.0 * math.pi))
    y = boxcar(hz, max(1, int(round(sps))))
    pattern = _p25_sync_levels()
    shifts = np.rint(np.arange(pattern.size) * sps).astype(np.int64)
    span = int(shifts[-1]) + 1
    n = y.size - span
    if n <= 0:
        return []
    p0 = pattern - pattern.mean()
    cov = np.zeros(n)
    s1 = np.zeros(n)
    s2 = np.zeros(n)
    for j, sh in enumerate(shifts):
        seg = y[sh:sh + n]
        cov += p0[j] * seg
        s1 += seg
        s2 += seg * seg
    var = np.maximum(s2 - s1 * s1 / pattern.size, 1e-18)
    r = cov / np.sqrt(float(np.sum(p0 * p0)) * var)
    hot = np.flatnonzero(np.abs(r) >= threshold)
    out = []
    if hot.size == 0:
        return out
    groups = np.split(hot, np.flatnonzero(np.diff(hot) > sps) + 1)
    for g in groups:
        n0 = int(g[np.argmax(np.abs(r[g]))])
        s = sample_at(y, float(n0), sps, max_symbols)
        if s.size < pattern.size:
            continue
        head = s[:pattern.size]
        gain = float(np.sum(p0 * (head - head.mean())) / np.sum(p0 * p0))   # Hz per level unit, signed
        if abs(gain) < 1e-9:
            continue
        offset = float(head.mean() - gain * pattern.mean())
        u = (s - offset) / gain
        first = (u < 0).astype(np.uint8)            # 10 and 11 are the negative levels
        second = (np.abs(u) > 2.0).astype(np.uint8)  # the outer levels end in 1
        bits = np.empty(s.size * 2, dtype=np.uint8)
        bits[0::2], bits[1::2] = first, second
        out.append({"sample": n0, "correlation": float(r[n0]), "inverted": gain < 0,
                    "deviation_hz": abs(gain) * 3.0, "offset_hz": offset, "bits": bits})
    return out


def p25_strip_status(bits):
    """The structural bits of a transmitted P25 frame: the status symbol (2 bits) after every 70
    bits removed. The regions sec_lmr_p25 reports, and any payload, are offsets in this stream."""
    a = _bit_array(bits)
    keep = (np.arange(a.size) % 72) < 70
    return a[keep]


def demod_p25(cap, ff):
    """P25 phase-1 frames: C4FM symbols from each frame sync (p25_dibits), cut at the data-unit
    length the NID names (a packet data unit, which has none, runs to the next frame sync or the end
    of the symbols), parsed by sec_lmr_p25.parse_phase1_frame (frame sync, NID BCH, status symbols,
    regions). Phase 2 (TDMA) is not demodulated."""
    res = ProtoResult("p25")
    if cap.iq is None:
        res.error = "p25: needs IQ (this capture is mono audio)"
        return res
    if not cap.rate:
        res.error = "p25: the sample rate is unknown (pass --rate)"
        return res
    import sec_lmr_p25 as p25
    hits = p25_dibits(cap.iq, cap.rate)
    sps = cap.rate / P25_SYMBOL_RATE
    (phase1_lengths,) = _parser_tables("p25", p25, ("_PHASE1_LENGTHS",))
    lengths = sorted({v for v in phase1_lengths.values() if v})
    bad_nid = 0
    for i, hit in enumerate(hits):
        bits = hit["bits"]
        nxt = hits[i + 1]["sample"] if i + 1 < len(hits) else None
        to_next = int(round((nxt - hit["sample"]) / sps)) * 2 if nxt is not None else bits.size
        parsed = None
        for length in lengths:
            if length > bits.size:
                continue
            chunk = bits[:length]
            try:
                parsed = p25.parse_phase1_frame(pack_bits(np.concatenate((chunk, np.zeros(-length % 8, np.uint8)))), length)
                break
            except p25.SecLmrP25Error as e:
                if "NID" in str(e):     # the NID does not decode: no length will parse this sync
                    bad_nid += 1
                    break
        if parsed is None:
            continue
        if parsed["expected_transmitted_bits"] is None:      # a packet data unit: it runs to the next sync
            length = min(bits.size, to_next) // 2 * 2
            try:
                parsed = p25.parse_phase1_frame(pack_bits(np.concatenate((bits[:length], np.zeros(-length % 8, np.uint8)))),
                                                length)
            except p25.SecLmrP25Error:
                pass                                         # keep the shortest reading that parsed
        length = parsed["transmitted_bit_length"]
        logical = p25_strip_status(bits[:length])
        fr = Frame("p25", f"{parsed['data_unit']} NAC 0x{parsed['nac_hex']} at sample {hit['sample']} "
                          f"({length} bits, NID corrected {parsed['nid_corrected_bits']} bit(s))",
                   data=pack_bits(logical[112:]), validated="frame sync + NID BCH(63,16,23)",
                   fields={"sample": hit["sample"], "correlation": round(hit["correlation"], 3),
                           "inverted": hit["inverted"], "deviation_hz": round(hit["deviation_hz"], 1),
                           "offset_hz": round(hit["offset_hz"], 1), "nac": parsed["nac"],
                           "duid": parsed["duid"], "data_unit": parsed["data_unit"],
                           "bit_length": length, "regions": parsed["regions"],
                           "status_symbols": len(parsed["status_symbols"])})
        res.frames.append(_mark(fr, ff))
        if not fr.flags:
            res.frames += _slip_frames("p25", logical[112:], ff,
                                       f"{parsed['data_unit']} at sample {hit['sample']}, status symbols removed")
        if len(res.frames) >= MAX_FRAMES:
            break
    res.params = {"samples_per_symbol": round(sps, 3), "frame_syncs": len(hits), "nid_failures": bad_nid}
    if not hits:
        res.note = "no P25 phase-1 frame sync (0x5575F5FF77FF) in the C4FM symbol stream"
    elif not res.frames:
        res.note = f"{len(hits)} frame sync(s) found but no NID decoded"
    else:
        res.note = "payload beyond the NID stays FEC-coded (not decoded here)"
    return res


# ---- TETRA (pi/4-DQPSK) ----------------------------------------------------------------------------

def rrc_taps(sps, alpha=0.35, span=8):
    """Root-raised-cosine taps for a (fractional) samples-per-symbol, unit energy, `span` symbols
    long. alpha 0.35 is the TETRA modulation filter (ETSI EN 300 392-2 clause 5)."""
    half = int(math.ceil(span * sps / 2.0))
    t = np.arange(-half, half + 1) / float(sps)
    taps = np.empty(t.size)
    for i, x in enumerate(t):
        if abs(x) < 1e-9:
            taps[i] = 1.0 - alpha + 4.0 * alpha / math.pi
        elif abs(abs(4.0 * alpha * x) - 1.0) < 1e-9:
            taps[i] = (alpha / math.sqrt(2.0)) * ((1 + 2 / math.pi) * math.sin(math.pi / (4 * alpha))
                                                  + (1 - 2 / math.pi) * math.cos(math.pi / (4 * alpha)))
        else:
            taps[i] = ((math.sin(math.pi * x * (1 - alpha)) + 4 * alpha * x * math.cos(math.pi * x * (1 + alpha)))
                       / (math.pi * x * (1 - (4 * alpha * x) ** 2)))
    return taps / math.sqrt(float(np.sum(taps * taps)))


def tetra_symbols(iq, rate, phases=16, centre_hz=None):
    """Differential pi/4-DQPSK symbols of a capture at 18000 symbols/s. The capture is moved to
    the centre of its spectrum (coarse_offset: a receiver tuned kilohertz off would otherwise lose the
    signal in the filters), brought to 4-8 samples per symbol, matched-filtered (RRC 0.35), and read
    at the timing phase where the differential symbols d[k] = z[k] conj(z[k-1]) are most coherent
    under the 4th-power law (a pi/4-DQPSK step raised to the 4th power is always -1). The same law
    gives what is left of the carrier offset per symbol, up to a multiple of pi/2 (demod_tetra tries
    the four). centre_hz states the carrier offset instead of estimating it. Returns {'d', 'lock',
    'coarse_step', 'cfo_step', 'sps'}: d are the offset-corrected
    differential symbols; lock is how far the steps' 4th powers agree, each weighted by its strength
    (1 for a clean signal, a few hundredths for noise); coarse_step and cfo_step are the two carrier
    corrections in radians per symbol."""
    sps = rate / TETRA_SYMBOL_RATE
    if sps < 2.0:
        raise IQDemodError(f"tetra: {rate:g} Hz is under 2 samples per symbol (needs >= 36000 Hz)")
    x = np.asarray(iq)
    centre = coarse_offset(x) if centre_hz is None else centre_hz / rate
    coarse_step = 2.0 * math.pi * centre * sps
    if centre:
        x = x * np.exp(-2j * np.pi * centre * np.arange(x.size))
    dec = int(sps // 4) if sps >= 8 else 1
    if dec > 1:
        x = x[:x.size // dec * dec].reshape(-1, dec).mean(axis=1)
        sps /= dec
    x = x - np.mean(x)
    mf = np.convolve(x, rrc_taps(sps), mode="same")
    best = None
    for k in range(phases):
        z = sample_at(mf, k * sps / phases, sps)
        if z.size < 32:
            continue
        d = z[1:] * np.conj(z[:-1])
        mag = np.abs(d)
        m4 = np.sum(mag * (d / (mag + 1e-30)) ** 4)     # each step's 4th power, weighted by its strength
        lock = float(abs(m4) / (np.sum(mag) + 1e-30))
        if best is None or lock > best[0]:
            best = (lock, d, m4)
    if best is None:
        return {"d": np.zeros(0, dtype=np.complex128), "lock": 0.0, "coarse_step": coarse_step,
                "cfo_step": 0.0, "sps": sps}
    lock, d, m4 = best
    step = float(np.angle(-m4)) / 4.0           # carrier phase advance per symbol, modulo pi/2
    return {"d": d * np.exp(-1j * step), "lock": lock, "coarse_step": coarse_step, "cfo_step": step, "sps": sps}


def tetra_dibits(d, quarter_turns=0, inverted=False):
    """Bits (uint8, two per symbol) of differential pi/4-DQPSK symbols, by the ETSI EN 300 392-2
    clause 5 mapping of the phase step: +pi/4 -> 00, +3pi/4 -> 01, -3pi/4 -> 11, -pi/4 -> 10.
    quarter_turns removes a residual k * pi/2 carrier step; inverted reads a spectrum-inverted
    (I/Q swapped) capture."""
    z = d * np.exp(-1j * (math.pi / 2.0) * quarter_turns)
    if inverted:
        z = np.conj(z)
    phase = np.angle(z)
    bits = np.empty(phase.size * 2, dtype=np.uint8)
    bits[0::2] = phase < 0
    bits[1::2] = np.abs(phase) > math.pi / 2.0
    return bits


def _parser_tables(proto, module, names):
    """The named tables of a bit-level parser module this engine reads rather than copies (one
    source for the ETSI / TIA layouts). They are underscore names there, so a rename would surface as
    a bare AttributeError deep in a demodulator: this names the protocol, the module and the table."""
    missing = [n for n in names if not hasattr(module, n)]
    if missing:
        raise IQDemodError(f"{proto}: {module.__name__} no longer has {', '.join(missing)} (renamed?): "
                           "this engine reads its layout tables, so it cannot frame bursts until "
                           "iq_demod is updated to the new names")
    return [getattr(module, n) for n in names]


def _tetra_layouts():
    """{training kind: (sequences, [(burst_type, burst_bits, training_offset)])} for the pi/4 bursts,
    from sec_lmr_tetra's ETSI layout table (one source for the offsets and the sequences)."""
    import sec_lmr_tetra as tetra
    n1, n2, sync, ext, layouts, layout_length = _parser_tables(
        "tetra", tetra, ("_NORMAL_1", "_NORMAL_2", "_SYNC", "_EXTENDED", "_LAYOUTS", "_layout_length"))
    seqs = {"normal_training": (n1, n2), "sync_training": (sync,), "extended_training": (ext,)}
    table = {k: (v, []) for k, v in seqs.items()}
    for (btype, mod), layout in layouts.items():
        if mod != "pi/4":
            continue
        off = 0
        for name, width, _kind in layout:
            if name in table:
                table[name][1].append((btype, layout_length(layout), off))
            off += width
    return table


def _sequence_hits(bits, seq, max_errors):
    """Even (symbol-aligned) bit offsets where `seq` occurs in a 0/1 array with at most max_errors
    wrong bits: [(offset, errors)]."""
    t = _bit_array(seq).astype(np.int16) * 2 - 1
    if bits.size < t.size:
        return []
    corr = np.correlate(bits.astype(np.int16) * 2 - 1, t, mode="valid")
    errors = (t.size - corr) // 2
    at = np.flatnonzero(errors <= max_errors)
    return [(int(i), int(errors[i])) for i in at if i % 2 == 0]


def tetra_bursts(bits, max_frames=MAX_FRAMES):
    """TETRA bursts in a demodulated bit stream: every training sequence occurrence (normal 1/2 with
    at most 1 wrong bit, extended with 2, synchronisation with 3) is tried under each burst layout
    that puts that sequence there, sec_lmr_tetra.parse_air_burst splits the burst, and a layout whose
    every ETSI sequence check is exact is kept over one that has a wrong check, however many more checks
    the latter gets right; then the most checks valid wins. Returns [{'bit', 'training_bit', 'training_errors',
    'bits', 'report'}], in stream order."""
    import sec_lmr_tetra as tetra
    found = {}
    tolerance = {"normal_training": 1, "extended_training": 2, "sync_training": 3}
    for kind, (seqs, layouts) in _tetra_layouts().items():
        for seq in seqs:
            for at, errors in _sequence_hits(bits, seq, tolerance[kind]):
                best = None
                for btype, length, off in layouts:
                    start = at - off
                    if start < 0 or start + length > bits.size:
                        continue
                    chunk = bits[start:start + length]
                    packed = pack_bits(np.concatenate((chunk, np.zeros(-length % 8, np.uint8))))
                    try:
                        rep = tetra.parse_air_burst(packed, length, burst_type=btype, modulation="pi/4")
                    except tetra.SecLmrTetraError:
                        continue
                    valid = sum(1 for row in rep["sequence_checks"] if row["valid"])
                    score = (bool(rep["training_valid"]), valid, -len(rep["sequence_checks"]))
                    if best is None or score > best[0]:
                        best = (score, start, chunk, rep)
                if best is None:
                    continue
                score, start, chunk, rep = best
                prev = found.get(start)
                if prev is None or score > prev[0]:
                    found[start] = (score, {"bit": start, "training_bit": at, "training_errors": errors,
                                            "bits": chunk, "report": rep})
    ordered = [row for _start, (_score, row) in sorted(found.items())]
    kept, end = [], -1
    for row in ordered:                     # one burst per stretch of the stream
        if row["bit"] < end:
            if kept and row["report"]["training_valid"] and not kept[-1]["report"]["training_valid"]:
                kept[-1] = row
                end = row["bit"] + row["bits"].size
            continue
        kept.append(row)
        end = row["bit"] + row["bits"].size
    return kept[:max_frames]


def demod_tetra(cap, ff, centre_hz=None):
    """TETRA pi/4-DQPSK bursts: tetra_symbols recovers the differential symbols, the four residual
    carrier quadrants and both spectrum senses are tried, and the reading with the most training
    sequences is split into bursts (tetra_bursts -> sec_lmr_tetra.parse_air_burst). Without symbol lock
    (TETRA_MIN_LOCK) nothing is searched. A burst whose every ETSI sequence is exact (30 to 44 known
    bits) proves the capture is TETRA; bursts with a wrong training bit are reported only beside one,
    because a 22-bit training sequence with one error allowed also turns up by chance in any long
    bit stream. centre_hz states where the carrier sits in the capture (Hz from its centre) when
    the spectrum's own centre would mislead, as with a second signal in the band; the capture is
    otherwise taken to hold one channel. pi/8-D8PSK and TEDS QAM are not demodulated."""
    res = ProtoResult("tetra")
    if cap.iq is None:
        res.error = "tetra: needs IQ (this capture is mono audio)"
        return res
    if not cap.rate:
        res.error = "tetra: the sample rate is unknown (pass --rate)"
        return res
    sym = tetra_symbols(cap.iq, cap.rate, centre_hz=centre_hz)
    res.params = {"samples_per_symbol": round(sym["sps"], 3), "lock": round(sym["lock"], 3),
                  "symbols": int(sym["d"].size),
                  "centre": "stated (--centre-hz)" if centre_hz is not None else "centre of the spectrum"}
    if sym["d"].size < 64:
        res.note = "capture too short for a TETRA burst"
        return res
    if sym["lock"] < TETRA_MIN_LOCK:
        res.note = "no pi/4-DQPSK symbol lock at 18000 symbols/s"
        return res
    best = None
    for inverted in (False, True):
        for turns in range(4):
            bits = tetra_dibits(sym["d"], turns, inverted)
            found = tetra_bursts(bits)
            score = (sum(1 for b in found if b["report"]["training_valid"]), len(found))
            if best is None or score > best[0]:
                best = (score, turns, inverted, bits, found)
    _score, turns, inverted, bits, found = best
    chance = 0
    if not any(b["report"]["training_valid"] for b in found):
        chance, found = len(found), []
    step = sym["cfo_step"] + turns * math.pi / 2.0
    step = sym["coarse_step"] + (step + math.pi) % (2 * math.pi) - math.pi
    res.params.update({"carrier_offset_hz": round(step * TETRA_SYMBOL_RATE / (2 * math.pi), 1),
                       "inverted": inverted, "bursts": len(found)})
    for b in found:
        rep = b["report"]
        checks = rep["sequence_checks"]
        ok = sum(1 for row in checks if row["valid"])
        fr = Frame("tetra", f"{rep['burst_type']} ({rep['burst_name']}) at bit {b['bit']}: "
                            f"{ok}/{len(checks)} ETSI sequences valid, training {rep['training']}",
                   data=pack_bits(b["bits"]),
                   validated="all ETSI training sequences" if rep["training_valid"] else "training sequence",
                   fields={"bit": b["bit"], "symbol": b["bit"] // 2, "burst_type": rep["burst_type"],
                           "bit_length": rep["bit_length"], "training": rep["training"],
                           "training_valid": rep["training_valid"], "training_errors": b["training_errors"],
                           "fields": {k: {"offset": v["offset"], "length": v["length"], "hex": v["hex"]}
                                      for k, v in rep["fields"].items()}})
        res.frames.append(_mark(fr, ff))
    if not any(f.flags for f in res.frames):
        res.frames += _slip_frames("tetra", bits, ff, "demodulated pi/4-DQPSK stream")
    if not found:
        res.note = "pi/4-DQPSK symbol lock but no TETRA burst with its training sequences intact"
        if chance:
            res.note += f" ({chance} lone training-sequence match(es) with a wrong bit: not reported)"
    else:
        res.note = "burst blocks stay scrambled and FEC-coded (not decoded here)"
    res.frames = res.frames[:MAX_FRAMES]
    return res


# ---- LoRa ------------------------------------------------------------------------------------------

def _lora_chirp(n):
    k = np.arange(n, dtype=np.float64)
    return np.exp(2j * np.pi * (k * k / (2.0 * n) - k / 2.0))


def lora_dechirp(iq, start, sf, os=1, count=None, down=False, shift=0.0, pad=1):
    """Dechirp `count` consecutive LoRa symbols starting at sample `start`: each is averaged to one
    sample per chip (os = samples per chip), multiplied by the conjugate upchirp (the upchirp when
    down=True, to read downchirps), rotated by -shift bins, and transformed. Returns (bins, peak
    fraction): the strongest FFT bin of each symbol (a float, in units of 1/pad bin when pad > 1
    zero-pads the transform) and the share of the symbol's energy in that bin: 1.0 for a pure chirp
    at one sample per chip, about 0.64 when oversampled (the per-chip average rolls off toward the band
    edges), a few percent for noise."""
    n = 1 << sf
    width = n * os
    start = int(start)
    avail = (len(iq) - start) // width if start >= 0 else 0
    count = avail if count is None else min(int(count), avail)
    if count <= 0:
        return np.zeros(0), np.zeros(0)
    block = np.asarray(iq[start:start + count * width]).reshape(count, n, os).mean(axis=2)
    ref = _lora_chirp(n)
    k = np.arange(n)
    mix = (ref if down else np.conj(ref)) * np.exp(-2j * np.pi * shift * k / n)
    spec = np.abs(np.fft.fft(block * mix, n * pad, axis=1)) ** 2
    idx = np.argmax(spec, axis=1)
    energy = np.sum(np.abs(block) ** 2, axis=1) * n + 1e-30
    return idx / float(pad), spec[np.arange(count), idx] / energy


def fractional_shift(x, delta):
    """x re-read `delta` samples later (a fraction of a sample), by a linear phase across its
    spectrum: out[n] = x(n + delta) for a band-limited x. The ends wrap, so shift a stretch with room
    to spare."""
    x = np.asarray(x)
    if x.size == 0:
        return x
    return np.fft.ifft(np.fft.fft(x) * np.exp(2j * np.pi * np.fft.fftfreq(x.size) * delta))


def _circ_mean(values, modulus):
    ang = np.asarray(values, dtype=np.float64) * (2 * np.pi / modulus)
    return float(np.angle(np.mean(np.exp(1j * ang))) % (2 * np.pi)) * modulus / (2 * np.pi)


def lora_acquire(iq, sf, os=1, min_preamble=5, max_packets=8):
    """Find LoRa packets in an unaligned capture at one spreading factor and oversampling.

    1. On an arbitrary symbol grid a preamble is a run of windows with the same upchirp bin u = timing
       + carrier offset; the SFD downchirps read on the same grid give d = carrier offset - timing. So
       the timing is (u - d) / 2 chips and the carrier offset (u + d) / 2 bins (taken within a quarter
       of the bandwidth), and the grid is moved to the symbol boundary, to the nearest sample.
    2. On that grid the preamble and the downchirps no longer straddle a frequency wrap, so their
       bins read to an eighth of a bin, and half their difference is what is left of the timing (up
       to half a chip: a window that straddles a wrap reads a whole bin). The grid moves again; at one sample per chip, where it cannot move by a fraction of a
       chip, the packet's stretch is shifted by the fraction instead (fractional_shift).
    3. The two sync-word symbols and the 2.25 downchirps are located, and the data symbols after them
       are read with the carrier offset removed. (Only the carrier: what timing is left after step 2,
       under half a sample, shifts a preamble's bin but breaks a data symbol's phase at its wrap, and
       taking the preamble's whole residual out of the data reads worse, not better.)

    Returns [{'start', 'data_start', 'cfo_bins', 'preamble_symbols', 'sync_symbols', 'sync_word',
    'symbols', 'symbol_quality'}] (start, data_start: the sample where the first preamble symbol and
    the first data symbol begin, to within a sample; symbols: raw FFT bins, the rf2_lora_phy input;
    symbol_quality: the median share of a data symbol's energy in its bin)."""
    n = 1 << sf
    width = n * os
    x = np.asarray(iq)
    if x.size < 14 * width:
        return []

    def signed(v):
        return (np.asarray(v, dtype=np.float64) + n / 2.0) % n - n / 2.0

    bins, frac = lora_dechirp(x, 0, sf, os)
    good = frac > LORA_MIN_SHARE
    packets, k, total = [], 0, bins.size
    while k < total and len(packets) < max_packets:
        if not good[k]:
            k += 1
            continue
        j = k + 1
        while j < total and good[j] and min((bins[j] - bins[k]) % n, (bins[k] - bins[j]) % n) <= 1:
            j += 1
        run = j - k
        if run < min_preamble:
            k = j
            continue
        # 1. timing and carrier from the run and the downchirps after it, on the grid as found
        fine, _ = lora_dechirp(x, k * width, sf, os, count=run - 1, pad=8)
        u = _circ_mean(fine, n)
        dn_bins, dn_frac = lora_dechirp(x, j * width, sf, os, count=5, down=True, pad=8)
        pick = [i for i in range(dn_bins.size) if dn_frac[i] > LORA_MIN_SHARE]
        k = j
        if not pick:
            continue
        d = float(dn_bins[max(pick, key=lambda i: dn_frac[i])])
        cfo = float(signed(u + d)) / 2.0
        start = int(round((k - run) * width - ((u - cfo) % n) * os))
        while start < 0:
            start += width
        # 2. on the aligned grid: the preamble windows, then the first downchirp
        pre_bins, pre_frac = lora_dechirp(x, start, sf, os, count=run + 6, shift=cfo, pad=8)
        off = signed(pre_bins)
        up_ok = [i for i in range(off.size) if pre_frac[i] > LORA_MIN_SHARE and abs(off[i]) < 1.5]
        if len(up_ok) < min_preamble - 1:
            continue
        start += up_ok[0] * width           # the run may have begun on a window that was only partly preamble
        left_up = float(np.mean([off[i] for i in up_ok]))
        look = len(up_ok) + 8
        _b, up_f = lora_dechirp(x, start, sf, os, count=look, shift=cfo + left_up)
        dn_b, dn_f = lora_dechirp(x, start, sf, os, count=look, down=True, shift=cfo, pad=8)
        first_down = next((i for i in range(2, min(up_f.size, dn_f.size))
                           if dn_f[i] > LORA_MIN_SHARE and dn_f[i] > up_f[i]), None)
        if first_down is None:
            continue
        downs = [i for i in (first_down, first_down + 1) if i < dn_f.size and dn_f[i] > LORA_MIN_SHARE]
        left_down = float(np.mean(signed(dn_b[downs])))
        late = (left_up - left_down) / 2.0              # chips the grid still starts into each symbol
        seg, base = x, 0
        if os == 1 and abs(late) > 0.1:
            base = max(0, start - width)
            seg = fractional_shift(x[base:start + (look + 3 + LORA_MAX_SYMBOLS) * width], -late)
        else:
            start -= int(round(late * os))
            if start < 0:
                continue
        # 3. sync word, then the data symbols, with the carrier offset removed
        up_b, _f = lora_dechirp(seg, start - base, sf, os, count=first_down, shift=cfo)
        sync = (int(up_b[first_down - 2]) % n, int(up_b[first_down - 1]) % n)
        data_start = start + first_down * width + (9 * width) // 4
        sym, sym_frac = lora_dechirp(seg, data_start - base, sf, os, count=LORA_MAX_SYMBOLS, shift=cfo)
        if sym.size < 8:
            continue
        # averaging os samples into a chip reads each chip (os - 1) / 2 samples late, so the grid
        # that reads clean sits that much before the symbol boundary: report the boundary
        edge = (os - 1) // 2
        packets.append({"start": start + edge, "data_start": data_start + edge, "cfo_bins": round(cfo, 3),
                        "preamble_symbols": first_down - 2, "sync_symbols": sync,
                        "sync_word": ((sync[0] // 8) & 0xF) << 4 | ((sync[1] // 8) & 0xF),
                        "symbols": [int(v) % n for v in sym], "symbol_quality": float(np.median(sym_frac))})
        k = max(k, (data_start + 8 * width) // width)
    return packets


def lora_oversamplings(rate):
    """Samples per chip to try, likeliest first. With a known rate: every standard LoRa bandwidth
    the rate is a whole multiple of, in the order 125, 250, 500 kHz, then the narrow ones. With no
    rate: 1, 2, 4, 8."""
    if not rate:
        return [1, 2, 4, 8]
    out = []
    for bw in LORA_BANDWIDTHS:
        ratio = rate / bw
        if 1 <= round(ratio) <= 64 and abs(ratio - round(ratio)) < 1e-3 and int(round(ratio)) not in out:
            out.append(int(round(ratio)))
    return out


def demod_lora(cap, ff, sfs=LORA_SFS, oversamplings=None, implicit=None):
    """LoRa packets from an unaligned capture: for each spreading factor and oversampling,
    lora_acquire finds preamble + SFD and reads the symbol bins, and rf2_lora_phy.decode_symbols
    recovers the payload (explicit header, Hamming, de-whitening, CRC), with and without low-data-rate
    optimisation. A packet counts only when its header checksum holds (and its CRC, when it has one).
    implicit = (payload_length, coding_rate, crc_present) reads implicit-header packets (with no CRC
    nothing vouches for such a packet, and it is marked unchecked). The search
    stops at the first oversampling (bandwidth) that yields a packet; a capture with I and Q swapped
    is tried when nothing decodes."""
    res = ProtoResult("lora")
    if cap.iq is None:
        res.error = "lora: needs IQ (this capture is mono audio)"
        return res
    os_list = list(oversamplings) if oversamplings else lora_oversamplings(cap.rate)
    if not os_list:
        res.error = (f"lora: {cap.rate:g} Hz is not a whole multiple of a LoRa bandwidth "
                     "(125/250/500 kHz and the narrow ones): pass --lora-os SAMPLES_PER_CHIP")
        return res
    import rf2_lora_phy as phy
    acquired = 0
    for swapped in (False, True):
        x = np.conj(cap.iq) if swapped else cap.iq
        for os in os_list:
            for sf in sfs:
                for pkt in lora_acquire(x, sf, os):
                    acquired += 1
                    for ldro in (False, True):
                        kw = {"ldro": ldro, "allow_trailing": True}
                        if implicit:
                            kw.update(implicit=True, payload_length=implicit[0], coding_rate=implicit[1],
                                      crc_present=bool(implicit[2]))
                        try:
                            packet = phy.decode_symbols(pkt["symbols"], sf, **kw)
                        except phy.RF2LoRaError:
                            continue
                        # an implicit header with no CRC checks nothing: such a packet is a reading, not a proof
                        check = "payload CRC-16" if packet.crc_present else ("" if implicit else "explicit header checksum")
                        fr = Frame("lora", f"SF{sf} CR4/{4 + packet.coding_rate} {len(packet.payload)} bytes, "
                                           f"{check or 'unchecked (implicit header, no CRC)'}: {_preview(packet.payload)!r}",
                                   data=packet.payload, validated=check,
                                   fields={**packet.as_dict(), "samples_per_chip": os, "start_sample": pkt["start"],
                                           "data_start_sample": pkt["data_start"], "cfo_bins": pkt["cfo_bins"],
                                           "preamble_symbols": pkt["preamble_symbols"],
                                           "sync_word": f"0x{pkt['sync_word']:02x}", "iq_swapped": swapped,
                                           "bandwidth_hz": (cap.rate / os) if cap.rate else None})
                        res.frames.append(_mark(fr, ff))
                        break
            if res.frames:
                break
        if res.frames:
            break
    res.params = {"spreading_factors": list(sfs), "samples_per_chip": os_list, "preambles": acquired,
                  "packets": len(res.frames)}
    if not res.frames:
        res.note = ("no LoRa preamble + SFD found" if not acquired else
                    f"{acquired} preamble(s) acquired but no packet passed its header checksum "
                    "(implicit header? pass --lora-implicit LEN,CR,CRC)")
    res.frames = res.frames[:MAX_FRAMES]
    return res


# ---- SSTV ------------------------------------------------------------------------------------------

def _lowpass_taps(cutoff, rate, width=8.0):
    n = int(width * rate / cutoff) | 1
    k = np.arange(n) - n // 2
    taps = np.sinc(2.0 * cutoff / rate * k) * np.hamming(n)
    return taps / taps.sum()


def fm_audio(iq, rate, audio_rate=AUDIO_RATE):
    """FM-demodulate IQ to audio: discriminator, a boxcar decimation to 48-96 kHz, a 6 kHz
    low-pass (wide enough to keep SSTV's tone steps sharp), then linear resampling to `audio_rate`
    (the capture rate itself when that is lower).
    Returns (audio scaled to about +-1, integer rate). The DC term (a carrier offset) is removed."""
    if rate < 8000:
        raise IQDemodError(f"sstv: {rate:g} Hz is too low for SSTV audio (needs >= 8000 Hz)")
    d = discriminator(iq)
    dec = max(1, int(rate // 48000))
    if dec > 1:
        d = d[:d.size // dec * dec].reshape(-1, dec).mean(axis=1)
    r1 = rate / dec
    d = d - np.mean(d) if d.size else d
    if r1 > 2.5 * 6000:
        d = np.convolve(d, _lowpass_taps(6000.0, r1), mode="same")
    out_rate = int(audio_rate) if r1 >= audio_rate else int(round(r1))
    if abs(r1 - out_rate) > 1e-9:
        t = np.arange(int(d.size * out_rate / r1)) * (r1 / out_rate)
        d = np.interp(t, np.arange(d.size), d)
    peak = float(np.percentile(np.abs(d), 99.9)) if d.size else 0.0
    return (d / peak * 0.7 if peak > 0 else d), out_rate


def inst_freq(audio, rate, smooth_ms=1.0):
    """Instantaneous frequency (Hz) of real audio, per sample, from the analytic signal, smoothed
    over smooth_ms. SSTV is a frequency-modulated tone, so this is its video and sync signal."""
    n = audio.size
    if n < 8:
        return np.zeros(n)
    spec = np.fft.fft(audio)
    h = np.zeros(n)
    h[0] = 1.0
    h[1:(n + 1) // 2] = 2.0
    if n % 2 == 0:
        h[n // 2] = 1.0
    analytic = np.fft.ifft(spec * h)
    f = np.angle(analytic[1:] * np.conj(analytic[:-1])) * (rate / (2 * np.pi))
    f = np.concatenate((f, f[-1:]))
    return boxcar(f, max(1, int(round(rate * smooth_ms / 1000.0))))


def sstv_headers(audio, rate, max_headers=8):
    """Sample offsets where an SSTV calibration header starts (the 300 ms 1900 Hz leader, 10 ms
    1200 Hz break, 300 ms leader, then the VIS start bit), anywhere in the audio. Found on the
    instantaneous frequency: a score of how much of each header segment sits on its tone, then the
    break's two edges place the start within a millisecond, then a least-squares fit of the header's
    tone schedule (1900 / 1200 / 1900 / 1200 Hz) over the offsets around it places it to the sample.
    The existing decoders need the header at sample 0; this is the offset to cut at."""
    f = inst_freq(audio, rate, 2.0)
    lead = np.concatenate(([0], np.cumsum(np.abs(f - 1900.0) < 100.0)))
    brk = np.concatenate(([0], np.cumsum(np.abs(f - 1200.0) < 100.0)))
    n300, n10, n30 = int(round(rate * 0.3)), int(round(rate * 0.01)), int(round(rate * 0.03))
    m = f.size - (2 * n300 + n10 + n30)
    if m <= 0:
        return []
    t = np.arange(m)
    guard = int(rate * 0.004)
    a = (lead[t + n300 - guard] - lead[t + guard]) / float(n300 - 2 * guard)
    b = (lead[t + 2 * n300 + n10 - guard] - lead[t + n300 + n10 + guard]) / float(n300 - 2 * guard)
    c = (brk[t + 2 * n300 + n10 + n30 - guard] - brk[t + 2 * n300 + n10 + guard]) / float(n30 - 2 * guard)
    score = (a + b + c) / 3.0
    hot = np.flatnonzero(score > 0.85)
    if hot.size == 0:
        return []
    fine = inst_freq(audio, rate, 0.5)
    miss_1900, miss_1200 = _tone_misfit(audio, rate, 1900.0), _tone_misfit(audio, rate, 1200.0)
    edges = (0, n300, n300 + n10, 2 * n300 + n10, 2 * n300 + n10 + n30)
    out = []
    for g in np.split(hot, np.flatnonzero(np.diff(hot) > n300) + 1):
        t0 = int(g[np.argmax(score[g])])
        lo, hi = max(0, t0 + n300 - 2 * n10), min(fine.size - 1, t0 + n300 + 3 * n10)
        low = np.flatnonzero(fine[lo:hi] < 1550.0)
        if low.size:
            down, up = lo + int(low[0]), lo + int(low[-1]) + 1
            t0 = int(round(((down - n300) + (up - n300 - n10)) / 2.0))
        # last step: the offset at which the header's tone schedule fits the samples best
        reach = max(3, int(rate * 0.0015))
        cand = np.arange(max(0, t0 - reach), min(t0 + reach, audio.size - edges[-1] - 1) + 1)
        if cand.size:
            cost = np.zeros(cand.size)
            for k, miss in enumerate((miss_1900, miss_1200, miss_1900, miss_1200)):
                cost += miss[cand + edges[k + 1]] - miss[cand + edges[k] + 1]
            best = np.flatnonzero(cost <= cost.min() + 1e-9 * (cost.max() + 1e-30))
            t0 = int(cand[best[best.size // 2]])
        out.append(t0)
        if len(out) >= max_headers:
            break
    return out


def _tone_misfit(audio, rate, frequency):
    """Running sum of how badly each sample fits a steady tone of `frequency`: a sinusoid obeys
    x[n+1] + x[n-1] = 2 cos(w) x[n] whatever its phase and amplitude, so the squared remainder is zero
    inside a stretch of that tone and not inside any other. out[b] - out[a] is the misfit of the
    samples a..b-1."""
    r = np.zeros(audio.size)
    r[1:-1] = audio[2:] + audio[:-2] - 2.0 * math.cos(2.0 * math.pi * frequency / rate) * audio[1:-1]
    return np.concatenate(([0.0], np.cumsum(r * r)))


def sstv_clock_error(audio, rate, start, line_ms, min_pulses=6):
    """The sample-clock error of an SSTV transmission, from its line sync pulses: the 1200 Hz pulses
    after the header (which starts at sample `start`) should come every line_ms; the fitted period
    over all of them, divided by the nominal one, minus 1, is the error (0.01 = the recording runs 1 %
    slow, so the picture slants). None with fewer than min_pulses pulses. Returns (error, pulses)."""
    f = inst_freq(audio, rate, 1.0)
    a = start + int(rate * 0.91)
    sync = f[a:] < 1350.0
    runs = run_lengths(sync)
    pos, at = [], a
    for r in runs:
        if r > 0 and r >= rate * 0.003:
            pos.append(at)
        at += abs(r)
    if len(pos) < min_pulses:
        return None, len(pos)
    pos = np.asarray(pos, dtype=np.float64)
    nominal = line_ms * rate / 1000.0
    gaps = np.diff(pos)
    near = gaps[np.abs(gaps / nominal - 1.0) < 0.05]
    if near.size < min_pulses - 2:
        return None, len(pos)
    period = float(np.median(near))
    anchor = pos[int(np.flatnonzero(np.abs(gaps / nominal - 1.0) < 0.05)[0])]   # a pulse on the line grid
    k = np.rint((pos - anchor) / period)
    keep = np.abs((pos - anchor) - k * period) < 0.2 * period
    if keep.sum() < min_pulses:
        return None, int(keep.sum())
    slope = float(np.polyfit(k[keep], pos[keep], 1)[0])
    return slope / nominal - 1.0, int(keep.sum())


def _resample_clock(audio, error):
    """The audio re-read on a clock (1 + error) times faster, so a period that measured (1 + error)
    times nominal becomes nominal."""
    t = np.arange(int(audio.size / (1.0 + error))) * (1.0 + error)
    return np.interp(t, np.arange(audio.size), audio)


def demod_sstv(cap, ff, out_dir=None, max_lines=512, min_drift_ms=1.0):
    """SSTV pictures: IQ is FM-demodulated to audio (a mono WAV is the audio already), every
    calibration header in it is located (sstv_headers), the VIS code names the mode, the line sync
    pulses give the clock error, the audio is re-clocked when that error moves the last sync pulse by
    min_drift_ms or more (the decoders step through the picture on a fixed schedule, so a drifting
    recording loses sync part-way down), and the aligned audio goes to the existing decoders
    (rf2_sstv_modes for Scottie / Robot / PD, signal_stego_depth for Martin). A frame is one picture; with out_dir it is written there as PNG (PPM without Pillow). The flag is in
    the picture: it is not read here (no OCR), so a picture alone is never `solved`."""
    res = ProtoResult("sstv")
    if not cap.rate:
        res.error = "sstv: the sample rate is unknown (pass --rate)"
        return res
    import rf2_sstv_modes as modes
    import signal_stego_depth as ssd
    if cap.iq is not None:
        audio, rate = fm_audio(cap.iq, cap.rate)
        res.params["audio"] = f"FM-demodulated to {rate} Hz"
    else:
        audio, rate = np.asarray(cap.audio, dtype=np.float64), int(round(cap.rate))
        res.params["audio"] = f"mono WAV at {rate} Hz"
    if rate < 8000:
        res.error = f"sstv: {rate} Hz audio is too low (needs >= 8000 Hz)"
        return res
    if audio.size > ssd.MAX_SAMPLES:
        res.note = f"audio cut to {ssd.MAX_SAMPLES} samples"
        audio = audio[:ssd.MAX_SAMPLES]
    starts = sstv_headers(audio, rate)
    res.params["headers"] = len(starts)
    if not starts:
        res.note = (res.note + "; " if res.note else "") + "no SSTV calibration header (1900/1200/1900 Hz leader)"
        return res
    for index, start in enumerate(starts):
        clip = audio[start:]
        vis = _sstv_vis(ssd, clip, rate)
        if vis is None:
            res.frames.append(Frame("sstv", f"leader at {start / rate:.3f} s but the VIS code failed its check",
                                    fields={"start_s": round(start / rate, 4)}))
            continue
        code, name = vis["vis"], vis["mode"]
        fields = {"start_s": round(start / rate, 4), "vis": code, "mode": name}
        line_ms = SSTV_LINE_MS.get(code)
        if line_ms:
            err, pulses = sstv_clock_error(audio, rate, start, line_ms)
            fields["sync_pulses"] = pulses
            if err is not None:
                fields["clock_error_ppm"] = round(err * 1e6, 1)
                if abs(err) * pulses * line_ms >= min_drift_ms:
                    fixed = _resample_clock(audio, err)
                    s2 = int(round(start / (1.0 + err)))
                    near = [s for s in sstv_headers(fixed[max(0, s2 - rate // 10):s2 + 2 * rate], rate)]
                    if near:
                        s2 = max(0, s2 - rate // 10) + near[0]
                    if _sstv_vis(ssd, fixed[s2:], rate) is not None:
                        clip = fixed[s2:]
                        fields["reclocked"] = True
        ppm, why = _sstv_picture(modes, ssd, clip, rate, code, max_lines)
        if ppm is None:
            res.frames.append(Frame("sstv", f"{name} (VIS {code}) at {start / rate:.3f} s: {why}", fields=fields,
                                    validated="leader + VIS parity"))
            continue
        width, height = _ppm_size(ppm)
        fields.update({"width": width, "height": height})
        fr = Frame("sstv", f"{name} (VIS {code}) picture {width}x{height} at {start / rate:.3f} s"
                           + (f", clock error {fields['clock_error_ppm']:+.0f} ppm"
                              + (" corrected" if fields.get("reclocked") else "") if "clock_error_ppm" in fields else "")
                           + (f" ({why})" if why else ""),
                   data=ppm, fields=fields, validated="leader + VIS parity + line syncs")
        if out_dir is not None:
            fields["file"] = _write_picture(Path(out_dir), f"{Path(cap.name).stem}.sstv{index}", ppm)
        res.frames.append(fr)
    return res


def _sstv_vis(ssd, clip, rate):
    if clip.size < int(rate * 0.91) or clip.size > ssd.MAX_SAMPLES:
        return None
    return ssd.detect_sstv_vis(ssd.Audio(rate, np.ascontiguousarray(clip)))


def _sstv_picture(modes, ssd, clip, rate, code, max_lines):
    """(binary PPM, note) of the picture, or (None, the named reason). The mode decoders stop with
    an error at the first line they cannot check and at a capture cut mid-line, so the number of
    lines asked for is what the audio holds, and when a line still fails the longest prefix of lines
    that decodes is kept (the note then says where the picture ends and why)."""
    audio = ssd.Audio(rate, np.ascontiguousarray(clip))
    if code in modes.MODES:
        spec = modes.MODES[code]
        rows = 2 if spec.family == "pd" else 1                      # picture rows in one scan period
        per = 2 if spec.family in ("pd", "robot36") else 1          # rows the decoder takes at a time
        avail_ms = clip.size * 1000.0 / rate - modes.HEADER_MS
        top = min(max_lines, modes.MAX_LINES, spec.height, int((avail_ms + 1.0) // SSTV_LINE_MS[code]) * rows)
        top -= top % per
        if top < per:
            return None, "the capture ends before one complete scan line"
        last = [""]

        def attempt(rows):
            try:
                return modes.decode_sstv(audio, max_lines=rows)
            except modes.RF2SSTVError as e:
                last[0] = str(e)
                return None

        frame = attempt(top)
        if frame is None:
            lo, hi = 0, top // per - 1                              # row units that decode
            while lo < hi:
                mid = (lo + hi + 1) // 2
                got = attempt(mid * per)
                if got is not None:
                    frame, lo = got, mid
                else:
                    hi = mid - 1
            if frame is None:
                return None, f"picture not decoded: {last[0]}"
            return frame.ppm(), f"picture ends after {frame.height} of {top} rows: {last[0]}"
        return frame.ppm(), ""
    if code in (44, 40):
        ppm = ssd.decode_sstv_martin(audio, max_lines=min(max_lines, 256))
        return (ppm, "") if ppm else (None, "picture not decoded: no complete Martin scan line after the header")
    return None, "no pixel decoder for this mode in the tree (Scottie, Robot 36/72, PD50/90/120, Martin M1/M2)"


def _ppm_size(ppm):
    parts = ppm.split(b"\n", 3)
    w, h = parts[1].split()
    return int(w), int(h)


def _write_picture(folder, stem, ppm):
    folder.mkdir(parents=True, exist_ok=True)
    try:
        from PIL import Image
    except ImportError:
        path = folder / f"{stem}.ppm"
        path.write_bytes(ppm)
        return str(path)
    path = folder / f"{stem}.png"
    Image.open(io.BytesIO(ppm)).save(path)
    return str(path)


# ---- dispatcher ------------------------------------------------------------------------------------

DEMODS = {"pocsag": demod_pocsag, "gfsk": demod_gfsk, "lora": demod_lora, "p25": demod_p25,
          "tetra": demod_tetra, "sstv": demod_sstv}


def parse_protocols(text):
    """The protocol list of --proto ('all' or comma-separated names). An unknown name is an
    IQDemodError naming what exists: there is no demodulator to fall back to."""
    if text is None or text.strip().lower() in ("", "all", "auto"):
        return list(PROTOCOLS)
    names = [t.strip().lower() for t in text.split(",") if t.strip()]
    unknown = [n for n in names if n not in DEMODS]
    if unknown:
        raise IQDemodError(f"no demodulator for {', '.join(unknown)} (have {', '.join(PROTOCOLS)}); "
                           "nothing is installed or run in its place")
    return list(dict.fromkeys(names))


def _rank(frame):
    return (bool(frame.flags), frame.lead, bool(frame.validated), wl._printable_ratio(frame.data), -len(frame.data))


def demodulate(cap, protocols=None, ff=None, out_dir=None, budget=DEFAULT_BUDGET, clock=time.process_time,
               lora_os=None, lora_implicit=None, centre_hz=None):
    """Run each requested demodulator over a Capture and choose by crib. Every protocol gets a
    ProtoResult: frames, what was estimated, or the named reason it was not attempted. `budget` is
    CPU seconds on `clock`: a protocol that would start after it is spent is listed as not run.
    Report.flags are the flags in the event format (`ff`, default the active event's); Report.best is
    the frame the crib ranks first (a flag, then the flag lead, then a protocol-validated frame)."""
    if ff is None:
        ff = flagfmt.current()
    names = list(PROTOCOLS) if protocols is None else list(protocols)
    _require_samples(cap.name, cap.samples)
    report = Report(cap)
    began = clock()
    for name in names:
        fn = DEMODS.get(name)
        if fn is None:
            raise IQDemodError(f"no demodulator for {name} (have {', '.join(PROTOCOLS)})")
        if clock() - began >= budget:
            report.results.append(ProtoResult(name, error=f"{name}: not run, the {budget:g} s CPU budget was "
                                                          "spent by the protocols before it (--budget)"))
            continue
        try:
            if name == "sstv":
                res = fn(cap, ff, out_dir=out_dir)
            elif name == "lora":
                res = fn(cap, ff, oversamplings=lora_os, implicit=lora_implicit)
            elif name == "tetra":
                res = fn(cap, ff, centre_hz=centre_hz)
            else:
                res = fn(cap, ff)
        except IQDemodError as e:
            res = ProtoResult(name, error=str(e))
        except ImportError as e:
            res = ProtoResult(name, error=f"{name}: a module it builds on does not import: {e}")
        except Exception as e:      # one demodulator failing must not hide what the others find
            res = ProtoResult(name, error=f"{name}: failed on this capture: {type(e).__name__}: {e}")
        report.results.append(res)
        report.files += [f.fields["file"] for f in res.frames if f.fields.get("file")]
    frames = [f for r in report.results for f in r.frames]
    report.flags = tuple(dict.fromkeys(fl for f in frames for fl in f.flags))
    report.best = max(frames, key=_rank) if frames else None
    return report


# ---- CLI -------------------------------------------------------------------------------------------

def solver_result(path, report):
    """The SolverResult of a Report: solved with the flag-bearing frames as evidence; unsure when a
    protocol decoded frames (or the flag lead shows) but no flag is in them; none when every
    attempted protocol found nothing; blocked when nothing could be attempted."""
    from ctf.result import Evidence, SolverResult
    frames = [f for r in report.results for f in r.frames]
    why = "; ".join([r.error or f"{r.proto}: {r.note}" for r in report.results if r.error or (r.note and not r.frames)]
                    + list(report.capture.notes))
    if report.flags:
        ev = [Evidence("decode", f"{f.proto}: {f.summary}"[:300], path=path) for f in frames if f.flags][:8]
        return SolverResult(status="solved", flags=list(report.flags), evidence=ev, engine=ENGINE)
    attempted = [r for r in report.results if not r.error]
    if not attempted:
        return SolverResult(status="blocked", engine=ENGINE, notes=why or "no protocol could be attempted")
    solid = [f for f in frames if f.validated or f.lead]
    if solid:
        by = {}
        for f in solid:
            by[f.proto] = by.get(f.proto, 0) + 1
        what = ", ".join(f"{n} {p} frame(s)" for p, n in by.items())
        extra = f"; pictures: {', '.join(report.files)}" if report.files else ""
        return SolverResult(status="unsure", engine=ENGINE,
                            notes=f"decoded {what} but no flag in the event format: read them (--json){extra}. "
                                  f"best: {report.best.summary[:200]}"
                                  + "".join(f"; {n}" for n in report.capture.notes))
    return SolverResult(status="none", engine=ENGINE, notes=why or "no protocol found a frame")


def report_dict(report):
    cap = report.capture
    return {"capture": {"name": cap.name, "format": cap.fmt, "rate": cap.rate, "rate_source": cap.rate_source,
                        "samples": cap.samples, "total_samples": cap.total_samples, "notes": cap.notes},
            "flags": list(report.flags),
            "protocols": [{"proto": r.proto, "error": r.error, "note": r.note, "params": r.params,
                           "frames": [{"summary": f.summary, "validated": f.validated, "flags": list(f.flags),
                                       "lead": f.lead, "text": f.text,
                                       "data_hex": f.data[:512].hex() if f.proto != "sstv" else "",
                                       "fields": f.fields} for f in r.frames]}
                          for r in report.results]}


def triage(report):
    cap = report.capture
    rate = f"{cap.rate:g} Hz ({cap.rate_source})" if cap.rate else "rate unknown"
    lines = [f"== {cap.name}: {cap.fmt}, {cap.samples} samples, {rate}"]
    lines += [f"  note: {n}" for n in cap.notes]
    for r in report.results:
        if r.error:
            lines.append(f"  {r.proto}: NOT RUN: {r.error}")
            continue
        params = ", ".join(f"{k}={v}" for k, v in r.params.items())
        lines.append(f"  {r.proto}: {len(r.frames)} frame(s)" + (f" [{params}]" if params else "")
                     + (f" - {r.note}" if r.note else ""))
        for f in r.frames[:6]:
            tag = f"FLAG {list(f.flags)}" if f.flags else ("lead" if f.lead else (f.validated or "unvalidated"))
            lines.append(f"    {f.summary[:160]}  [{tag}]")
    if report.flags:
        lines.append(f"  FLAG(S): {list(report.flags)}")
    return "\n".join(lines)


def _implicit(text):
    try:
        length, cr, crc = (int(v) for v in text.split(","))
    except ValueError as e:
        raise argparse.ArgumentTypeError("--lora-implicit takes LEN,CR,CRC (e.g. 16,1,1)") from e
    return length, cr, crc


def main(argv=None):
    ap = argparse.ArgumentParser(prog="iq_demod.py", description="saved IQ capture -> frames, crib-selected")
    ap.add_argument("capture", nargs="+")
    ap.add_argument("--rate", type=float, help="sample rate in Hz (else SigMF meta, WAV header, file name)")
    ap.add_argument("--format", help="cu8 | cs8 | cs16 | cf32 (else the extension)")
    ap.add_argument("--proto", help=f"comma-separated subset of {','.join(PROTOCOLS)} (default all)")
    ap.add_argument("--out", help="folder for report.json and decoded SSTV pictures")
    ap.add_argument("--skip", type=int, default=0, help="complex samples to pass over first")
    ap.add_argument("--max-samples", type=int, default=MAX_SAMPLES)
    ap.add_argument("--budget", type=float, default=DEFAULT_BUDGET, help="CPU seconds per capture")
    ap.add_argument("--lora-os", type=int, action="append", help="LoRa samples per chip (repeatable)")
    ap.add_argument("--lora-implicit", type=_implicit, help="LEN,CR,CRC of implicit-header LoRa packets")
    ap.add_argument("--centre-hz", type=float, help="TETRA: the carrier's offset from the capture centre, in Hz "
                                                    "(else the centre of the spectrum)")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON instead of the triage")
    args = ap.parse_args(argv)
    from ctf.result import SolverResult
    rc = 0
    for path in args.capture:
        try:
            protocols = parse_protocols(args.proto)
            cap = load_capture(path, fmt=args.format, rate=args.rate, skip=args.skip, max_samples=args.max_samples)
            report = demodulate(cap, protocols, out_dir=args.out, budget=args.budget, lora_os=args.lora_os,
                                lora_implicit=args.lora_implicit, centre_hz=args.centre_hz)
        except IQDemodError as e:
            print(f"iq_demod.py: {e}", file=sys.stderr)
            print(SolverResult(status="blocked", engine=ENGINE, notes=str(e)).to_json())
            rc = 1
            continue
        if args.out:
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{Path(path).name}.report.json").write_text(json.dumps(report_dict(report), indent=1, default=str))
        print(json.dumps(report_dict(report), default=str) if args.json else triage(report))
        print(solver_result(path, report).to_json())
    return rc


if __name__ == "__main__":
    sys.exit(main())
