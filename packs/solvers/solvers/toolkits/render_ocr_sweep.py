#!/usr/bin/env python3
"""Toolkit `render_ocr_sweep` (B-126): text that is drawn, not serialized, read with no model.

Two readings that were hand jobs at Spooky 2026, both of a message stored as a picture:

  spectrogram   a PCM WAV's spectrogram from 0 Hz to Nyquist, in pure numpy (no Docker, no sox):
                the whole band, then overlapping 8 kHz and 4 kHz bands, each about a hundred rows
                tall, both polarities, each read by tesseract (image_carve.ocr_text). The carried
                reader (stego_tools.spectrogram_text) stops at 8 kHz, so writing at 8 to 11 kHz was
                never read. Each frequency row is levelled on its own floor (the 20th percentile
                of its level over time), so a steady tone is not ink, and a picture with next to
                no ink is `blank` and not sent to OCR. A long recording is read in 20 s windows.
                Exact 5x7 glyphs drawn as seven tones are read without OCR: the tone rows, the
                column length and the start are measured from the spectrogram, anywhere up to
                Nyquist, and handed to signal_stego_depth.decode_spectrogram_text, which accepts
                only a text whose every glyph matches.
  bit planes    bits 0 to 2 of every channel of a PNG, BMP, TIFF or PPM, each scored for spatial
                structure: how far the agreement of neighbouring bits is above what the plane's
                own density explains, so the sparse plane of a few letters on black counts
                (steganalysis.lsb_plane_score damps a biased plane and rejects it; its verdict is
                kept on record beside ours). The structured planes are rendered, the rarer value
                dark on white, and read by tesseract at up to three sizes. carve_stego renders
                planes for barcodes only and the survey OCRs only the cover.

Every text read is searched for the event's flag as it stands, then under a letter rotation with
the slips OCR makes of ciphertext mended (a brace read as i or (, one wrong letter in the prefix:
with the prefix `spooky`, `febbxli...}` is `fcbbxl{...}` is ROT13 of the flag), then through
crib_decode's keyless readings (rotations, atbash, reversals, the base families). The reading most
sizes agree on comes first. Key hints found in sibling files (a number in another image's LSB note,
B-068's evidence-ledger candidates, keys the caller gives) are applied to the texts: the cross-file
join.

After a rejected flag, `checklist(report, rejected=FLAG)` is the fixed list of what this sweep ruled
out, and `file_checklist` writes it to the hypothesis ledger (ctf.hypothesis, B-181) as negatives, the
rejected reading as a false positive (`python -m ctf render-sweep rejected DIR --flag FLAG`).

  solve(challenge_dir, profile, **opts) -> SolverResult      the engine contract (python -m ctf run)
  examine(files, ff, ...) -> Report                          the same over {name: bytes}
  bands(nyquist, top_hz=None) -> [(lo, hi, nfft)]            the band plan of one recording
  renderings(audio, top_hz=None) -> [Rendering]              band pictures, light then dark
  glyph_text(audio, deadline=None, stopped=None) -> [(text, how)]   exact 5x7 glyphs, measured not assumed
  plane_structure(bits) -> dict                              density, agreement score, flat tiles
  text_flags(text, ff, prefixes, deadline) -> [(flag, chain)]
  checklist(report, rejected=None) -> [dict]; file_checklist(cid, items, ...) -> [records]
  run_options(...) -> dict; load_report(out_dir, files, options=None, seconds=None) -> Report | None

  .venv/bin/python solvers/toolkits/render_ocr_sweep.py FILE... [--event SLUG] [--out DIR]
        [--ocr auto|on|off] [--seconds S] [--top-hz HZ] [--key K]...

Status: a flag read by OCR, or reached through a guessed rotation or a key, is `candidate`; one flag
read as it stands by the exact glyph reader is `solved`. Renderings with something drawn in them but
no flag are `unsure`, written as PNG for a human or model read. tesseract missing while a rendering
needed it is `blocked`, naming it. Nothing is executed; tesseract is the only program run.

A probe that did not run to the end (out of time, no tesseract, OCR off, a picture that does not open)
is never filed as ruled out: its checklist line is `error` or `inconclusive`, and so are the two
delivery-wide lines (keyless decode, cross-file keys) while any reading they depend on is missing. A
plane read at fewer sizes than it was due (the clock or a tesseract fault stopped it part way) counts
as missing too. A file probe that ran to the end but did not look at the whole file (the glyph reader
past its first 60 s, a spectrogram cut by top_hz) is `inconclusive` with the limit in its evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common", HERE.parent / "warmups"):
    if str(_p) not in sys.path:
        sys.path.append(str(_p))

import numpy as np                  # noqa: E402

import image_carve as ic            # noqa: E402
import signal_stego_depth as sd     # noqa: E402
import steganalysis as sa           # noqa: E402

ENGINE = "toolkits.render_ocr_sweep"
REPORT_NAME = "report.json"
REPORT_SCHEMA = 1
DEFAULT_SECONDS = 40.0                # under the manifest's intake timeout (60 s) with room to write the report
MAX_FILE = ic.MAX_FILE
MAX_PIXELS = 40_000_000

# ---- spectrogram ----
HOP = 256                             # samples between spectrogram columns, every band
BAND_PLAN = ((8000.0, 512), (4000.0, 1024))   # (band width in Hz, FFT size): about 93 rows each at 44.1 kHz
WHOLE_NFFT = 256                      # the whole band in one picture: 129 rows
WINDOW_S = 20.0                       # a long recording is read in windows this long ...
WINDOW_STEP_S = 10.0                  # ... starting this far apart, so writing up to 10 s long is whole in one
FLOOR_PCT = 20.0                      # a row's floor: this percentile of its level over time
INK_DB = 15.0                         # dB over the row's own floor at which a cell is ink
RAMP_DB = (20.0, 6.0)                 # a rendering's grey ramp: from this far under its strong level to this far
RAMP_MIN_DB = 9.0                     # ... and never starting lower than this over the floor
BLANK = 0.001                         # share of ink under which (or over 1 - this) a rendering is blank ...
BLANK_CELLS = 200                     # ... and it is blank under this many ink cells too (a glyph is more)
MARGIN = 12                           # white pixels around a rendering
OCR_SCALE_BAND = 2
GLYPH_NFFT, GLYPH_HOP = 1024, 128
GLYPH_SECONDS = 60.0                  # the exact glyph reader looks at this much from the start
GLYPH_MAX_PEAKS = 24
# ---- bit planes ----
PLANE_BITS = (0, 1, 2)
STRUCTURE_MIN = 0.20                  # agreement beyond what the plane's own density explains
TILE = 32
FLAT_TILES_MIN = 0.05                 # share of flat 32x32 tiles from which a plane is structured
PLANE_FORMATS = ("PNG", "BMP", "TIFF", "PPM")     # stored samples survive decoding exactly
# ---- text ----
MAX_TEXT = 4000                       # characters of one reading kept
MAX_LINES = 40                        # lines of one reading sent to the decoder on their own
DECODE_SECONDS = 1.0                  # crib_decode's budget for one text or line
MAX_KEYED = 24                        # keyed readings listed
MAX_NOTE_KEYS = 6                     # shifts taken from one sibling note
LEDGER_MAX_BYTES = 64 << 20           # deliveries larger than this are not given to the evidence ledger

PROBE_SPEC, PROBE_GLYPH, PROBE_PLANE = "spectrogram-ocr", "spectrogram-5x7", "bitplane-ocr"
PROBE_DECODE, PROBE_KEYS = "keyless-decode", "cross-file-keys"
READ, BLANK_STATE, NOT_READ = "read", "blank", "not-read"
OUT_OF_TIME = "out of time"           # the reason of everything the deadline stopped

NOT_COVERED = (
    "a message only in the difference of the stereo channels (channels are averaged before the read)",
    "speech or tones meant to be heard (multimon-ng, SSTV, Morse: stego_tools, signal_stego)",
    "audio that is not PCM WAV (convert it first)",
    "bit planes 3 to 7, planes combined or XORed with each other, and the index planes of a paletted picture",
    "pictures with samples wider than 8 bits, and JPEG (its stored bits are coefficients: jpeg_stego)",
    "LSB payloads stored as bytes (carve_stego.lsb_scan, zsteg) and passphrase tools (steghide, outguess)",
    "writing OCR cannot read: a rendering with something drawn is written as PNG for a human or model",
)

ToolMissing = ic.ToolMissing


class OptionError(ValueError):
    """An option of the sweep has a value it cannot take; the message names it."""


# ---- the spectrogram -------------------------------------------------------------------------------

def stft_power(samples: np.ndarray, nfft: int, hop: int = HOP):
    """Power spectrogram [nfft/2+1 bins, columns] (Hann window), float32; None for less than one window."""
    if samples.size < nfft:
        return None
    view = np.lib.stride_tricks.sliding_window_view(samples, nfft)[::hop]
    win = np.hanning(nfft)
    out = np.empty((nfft // 2 + 1, view.shape[0]), dtype=np.float32)
    for a in range(0, view.shape[0], 2048):
        spec = np.fft.rfft(view[a:a + 2048] * win, axis=1)
        out[:, a:a + spec.shape[0]] = (spec.real ** 2 + spec.imag ** 2).T
    return out


def ink_map(power: np.ndarray):
    """(rel, hard) of a power spectrogram: `rel` is each cell's level in dB over its own row's floor
    (the FLOOR_PCT percentile of that row over time), after a 3x3 mean, which takes the long tail off
    noise; `hard` is True where that is INK_DB or more. A steady tone and a flat noise floor are not
    ink; writing is, and so is a noise band with writing cut out of it (the dark rendering reads it)."""
    from scipy.ndimage import uniform_filter
    smooth = uniform_filter(power.astype(np.float64), size=3, mode="nearest")
    top = float(smooth.max())
    if not top > 0.0:
        z = np.zeros(power.shape)
        return z, z.astype(bool)
    db = 10.0 * np.log10(np.maximum(smooth, top * 1e-9))          # nothing counts below -90 dB of the peak
    rel = np.maximum(db - np.percentile(db, FLOOR_PCT, axis=1, keepdims=True), 0.0)
    return rel, rel >= INK_DB


def ramp(rel: np.ndarray) -> np.ndarray:
    """A picture's cells on its grey ramp, 0..1: white up to RAMP_DB[0] under the picture's strong
    level (the 99th percentile of its cells), black from RAMP_DB[1] under it, so the splatter around
    loud writing stays white; the ramp never starts under RAMP_MIN_DB over the floor."""
    strong = float(np.percentile(rel, 99.0)) if rel.size else 0.0
    lo = max(RAMP_MIN_DB, strong - RAMP_DB[0])
    hi = max(lo + 3.0, strong - RAMP_DB[1])
    return np.clip((rel - lo) / (hi - lo), 0.0, 1.0)


def bands(nyquist: float, top_hz: float | None = None) -> list:
    """[(lo, hi, nfft)]: the whole band 0..top, then overlapping bands of each BAND_PLAN width, half a
    width apart, the last one always ending at top. top is Nyquist unless `top_hz` cuts it lower."""
    top = float(nyquist) if not top_hz else min(float(nyquist), float(top_hz))
    out = [(0.0, top, WHOLE_NFFT)]
    for width, nfft in BAND_PLAN:
        if top <= width * 1.25:
            continue
        los = list(np.arange(0.0, top - width, width / 2.0))
        if top - width - los[-1] > width / 8.0:
            los.append(top - width)
        elif len(los) > 1:
            los[-1] = top - width                     # the last band is moved up a little rather than repeated
        out += [(float(lo), float(lo + width), nfft) for lo in los]
    return out


def windows(n_samples: int, rate: int) -> list:
    """[(start, stop)] in samples: the whole recording up to 1.25 windows, else WINDOW_S windows
    WINDOW_STEP_S apart, the last one ending at the end."""
    if n_samples <= int(1.25 * WINDOW_S * rate):
        return [(0, n_samples)]
    size, step = int(WINDOW_S * rate), int(WINDOW_STEP_S * rate)
    starts = list(range(0, n_samples - size, step))
    if n_samples - size - starts[-1] > step // 8:
        starts.append(n_samples - size)
    elif len(starts) > 1:
        starts[-1] = n_samples - size                 # the last window is moved on a little rather than repeated
    return [(s, s + size) for s in starts]


def _png(gray: np.ndarray) -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.fromarray(np.ascontiguousarray(gray, dtype=np.uint8), "L").save(buf, "PNG")
    return buf.getvalue()


def _framed(dark_ink: np.ndarray, light: bool) -> bytes:
    """A PNG of a 0..1 ink picture inside a MARGIN of background: light = dark ink on white."""
    body = np.pad(dark_ink, MARGIN, constant_values=0.0)
    return _png(np.round((1.0 - body if light else body) * 255.0))


@dataclass
class Rendering:
    where: str                 # '8000-12000 Hz, 0.0-18.9 s, light'
    png: bytes | None          # None when blank
    ink: float                 # share of ink cells
    blank: bool
    light: bool
    lo: float = 0.0
    hi: float = 0.0


def renderings(audio, top_hz: float | None = None) -> list:
    """Every band picture of a recording, per time window and band, light (dark ink on white) and
    dark. A band with no ink (or nothing but ink) is one blank Rendering with no picture."""
    rate, nyq = int(audio.rate), audio.rate / 2.0
    plan = bands(nyq, top_hz)
    out = []
    for start, stop in windows(audio.samples.size, rate):
        chunk = audio.samples[start:stop]
        maps = {}
        for lo, hi, nfft in plan:
            if nfft not in maps:
                power = stft_power(chunk, nfft)
                maps[nfft] = None if power is None else ink_map(power)
            span = f"{lo:.0f}-{hi:.0f} Hz, {start / rate:.1f}-{stop / rate:.1f} s"
            if maps[nfft] is None:
                out.append(Rendering(span, None, 0.0, True, True, lo, hi))
                continue
            rel, hard = maps[nfft]
            b0 = int(math.floor(lo * nfft / rate))
            b1 = min(hard.shape[0], int(math.ceil(hi * nfft / rate)) + 1)
            cut = hard[b0:b1]
            ink = float(cut.mean()) if cut.size else 0.0
            least = max(BLANK, BLANK_CELLS / max(1, cut.size))  # a share, so a short line in a long window still counts
            if not least <= ink <= 1.0 - least:
                out.append(Rendering(span, None, ink, True, True, lo, hi))
                continue
            cols = np.flatnonzero(cut.any(axis=0) if ink < 0.5 else (~cut).any(axis=0))
            c0, c1 = max(0, int(cols[0]) - 16), min(cut.shape[1], int(cols[-1]) + 17)
            picture = ramp(rel[b0:b1, c0:c1])[::-1]                 # high frequencies on top
            for light in (True, False):
                out.append(Rendering(f"{span}, {'light' if light else 'dark'}", _framed(picture, light), ink, False,
                                     light, lo, hi))
    return out


# ---- exact 5x7 glyphs, measured ---------------------------------------------------------------------

def _tone_rows(power: np.ndarray, rate: int, nfft: int):
    """(base_hz, step_hz) of seven equally spaced tone rows in a spectrogram, or None: the strongest
    seven-term progression among the peaks of the time-averaged spectrum."""
    prof = power.mean(axis=1).astype(np.float64)
    if prof.size < 16 or not prof.max() > 0:
        return None
    peaks = [k for k in range(1, prof.size - 1)
             if prof[k] >= prof[k - 1] and prof[k] > prof[k + 1] and prof[k] >= 0.02 * prof.max()]
    if not 7 <= len(peaks) <= GLYPH_MAX_PEAKS:
        return None
    freqs = []
    for k in peaks:                                   # parabolic fit of the log power around the peak
        a, b, c = (math.log(max(prof[j], 1e-300)) for j in (k - 1, k, k + 1))
        d = a - 2 * b + c
        freqs.append((k + (0.5 * (a - c) / d if d else 0.0)) * rate / nfft)
    best = None
    for i in range(len(freqs)):
        for j in range(i + 6, len(freqs)):
            step = (freqs[j] - freqs[i]) / 6.0
            if step < 3.0 * rate / nfft:
                continue
            total, ok = prof[peaks[i]] + prof[peaks[j]], True
            for m in range(1, 6):
                want = freqs[i] + m * step
                near = min(range(i + 1, j), key=lambda q: abs(freqs[q] - want))
                if abs(freqs[near] - want) > 0.2 * step:
                    ok = False
                    break
                total += prof[peaks[near]]
            if ok and (best is None or total > best[0]):
                best = (total, freqs[i], step)
    return None if best is None else (best[1], best[2])


def _column_grid(edges: np.ndarray, least: float):
    """(origin, period) of the grid the rising edges lie on, in spectrogram columns, or None. The
    period starts as the smallest gap between two edges that is not jitter, then a line is fitted to
    a growing span of edges so an error in the first guess cannot build up."""
    e = np.unique(edges.astype(np.float64))
    if e.size < 6:
        return None
    gaps = np.diff(e)
    real = gaps[gaps >= max(3.0, least)]
    if real.size < 3:
        return None
    period = float(np.median(real[real <= 1.3 * real.min()]))
    origin, span = float(e[0]), 8.0
    while True:
        use = e[e - e[0] <= span * period]
        k = np.round((use - origin) / period)
        if np.unique(k).size >= 2:
            period, origin = (float(v) for v in np.polyfit(k, use, 1))
        if use.size == e.size:
            break
        span *= 2.0
    resid = (e - origin) / period
    if period < least or float(np.sqrt(np.mean((resid - np.round(resid)) ** 2))) > 0.15:
        return None
    return origin, period


def glyph_text(audio, deadline=None, stopped: list | None = None) -> list:
    """[(text, how)]: text drawn as exact 5x7 glyphs on seven tones, wherever in the band they sit.
    The tone rows, the column length and the start are measured here; the reading itself is
    signal_stego_depth.decode_spectrogram_text, which returns a text only when every glyph matches
    its font and every separator column is silent. Both row orders are tried (the font's top row as
    the lowest tone, and as the highest). [] when the recording holds no such writing. When
    `deadline` (time.monotonic()) ends the search before every arrangement was tried, `stopped` is
    given 'out of time': what is returned then is not the whole answer, and [] is not a no."""
    def late() -> bool:
        return deadline is not None and time.monotonic() > deadline

    def stop() -> None:
        if stopped is not None and OUT_OF_TIME not in stopped:
            stopped.append(OUT_OF_TIME)

    if late():
        stop()
        return []
    rate = int(audio.rate)
    quiet = np.zeros(GLYPH_NFFT)                      # so writing that starts at sample 0 still has a rising edge
    samples = np.concatenate([quiet, audio.samples[:int(GLYPH_SECONDS * rate)], quiet])
    power = stft_power(samples, GLYPH_NFFT, GLYPH_HOP)
    if power is None:
        return []
    rows = _tone_rows(power, rate, GLYPH_NFFT)
    if rows is None:
        return []
    base, step = rows
    bins = [int(round((base + m * step) * GLYPH_NFFT / rate)) for m in range(7)]
    if bins[0] < 1 or bins[-1] + 2 > power.shape[0]:
        return []
    energy = np.stack([power[b - 1:b + 2].sum(axis=0) for b in bins]).astype(np.float64)
    on = energy > 0.05 * energy.max(axis=1, keepdims=True)
    rising = on & ~np.concatenate([np.zeros((7, 1), dtype=bool), on[:, :-1]], axis=1)
    grid = _column_grid(np.nonzero(rising)[1], least=0.010 * rate / GLYPH_HOP)
    if grid is None:
        return []
    origin, period = grid
    last_on = int(np.flatnonzero(on.any(axis=0))[-1])
    columns = int(math.floor((last_on - origin) / period)) + 1
    width0 = int(round(period * GLYPH_HOP))
    found, cut = {}, False
    for sign, tag in ((1, "top row lowest"), (-1, "top row highest")):
        b_hz, s_hz = (base, step) if sign > 0 else (base + 6 * step, -step)
        for width in (width0, width0 - 1, width0 + 1):
            for shift in (0, 1):                     # the first glyph's first column may be empty
                glyphs = int(math.ceil((columns + shift) / 6.0))
                for off in (GLYPH_NFFT // 2, GLYPH_NFFT // 4, 3 * GLYPH_NFFT // 4, 0, GLYPH_NFFT):
                    if tag in found:
                        break
                    if late():
                        cut = True
                        break
                    need = glyphs * 6 * width
                    s0 = int(round(origin * GLYPH_HOP)) + off - shift * width
                    a, b = max(0, s0), min(samples.size, s0 + need)
                    seg = np.zeros(need)
                    if b > a:
                        seg[a - s0:b - s0] = samples[a:b]
                    got = sd.decode_spectrogram_text(sd.Audio(rate, seg), column_ms=width * 1000.0 / rate,
                                                     base_hz=b_hz, row_step_hz=s_hz)
                    if got:
                        found[tag] = got.decode("ascii")
    if cut:
        stop()
    how = (f"exact 5x7 glyphs on tones {base:.0f} Hz + {step:.0f} Hz x 0..6, "
           f"{period * GLYPH_HOP * 1000.0 / rate:.1f} ms columns")
    return [(text, f"{how}, {tag}") for tag, text in found.items()]


# ---- bit planes ------------------------------------------------------------------------------------

def claimed_format(data: bytes) -> str | None:
    """The picture format a file's first bytes claim, asked of a file Pillow does not open: PNG and
    TIFF by their signatures; BMP and PPM, whose magic is two letters, only when the file is not plain
    text (notes that begin 'BM' are not a damaged bitmap)."""
    if data.startswith(ic.PNG_SIG):
        return "PNG"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "TIFF"
    if ic.cs.sniff(data) == "text":
        return None
    if data[:2] == b"BM":
        return "BMP"
    if data[:2] in (b"P5", b"P6") and data[2:3].isspace():
        return "PPM"
    return None


def _open_picture(data: bytes):
    """The opened, not yet decoded, Pillow image of a PLANE_FORMATS picture; None for anything else;
    ValueError when the file carries a picture's magic (claimed_format) but does not open."""
    from PIL import Image
    try:
        im = Image.open(io.BytesIO(data))
    except Exception as e:
        claimed = claimed_format(data)
        if claimed is None:
            return None
        raise ValueError(f"{claimed} magic, but the picture does not open ({type(e).__name__}): repair its header "
                         "and run again") from e
    return im if im.format in PLANE_FORMATS else None


def image_array(data: bytes):
    """(samples [h, w, channels] uint8, band names) of a picture whose stored samples survive decoding
    (PLANE_FORMATS), or None for anything else. A paletted picture is read as its colours. ValueError
    (with the reason) when it is one of those but cannot be read here: over MAX_PIXELS, samples wider
    than 8 bits, damaged, or carrying the magic of one (claimed_format) without opening as a picture:
    a damaged header is a stego trick of its own, so the file is named, not dropped."""
    im = _open_picture(data)
    if im is None:
        return None
    if im.width * im.height > MAX_PIXELS:
        raise ValueError(f"{im.width}x{im.height} is over {MAX_PIXELS} pixels")
    if im.mode.startswith(("I", "F")):
        raise ValueError(f"{im.format} mode {im.mode}: samples wider than 8 bits, whose low planes are not read here")
    try:
        if im.mode not in ("L", "LA", "RGB", "RGBA"):
            im = im.convert("RGBA" if (im.mode == "P" and "transparency" in im.info) else
                            "L" if im.mode == "1" else "RGB")
        arr = np.asarray(im, dtype=np.uint8)
    except Exception as e:
        raise ValueError(f"{im.format} does not decode: {e}") from e
    if arr.ndim == 2:
        arr = arr[:, :, None]
    return arr, im.getbands()


def plane_structure(bits: np.ndarray) -> dict:
    """What a bit plane [h, w] of 0/1 looks like: `density` (share of ones), `score` (how far the
    agreement of neighbouring cells is above what independent bits of that density would give, 0..1:
    0 for noise whatever its density, near 1 for a drawing, however sparse), `flat` (share of TILE x
    TILE tiles that are all but one value: a region overwritten with a drawing inside a noise plane),
    `blank` (one value throughout) and `structured` (score or flat share over its threshold)."""
    h, w = bits.shape
    density = float(bits.mean())
    if density in (0.0, 1.0) or h < 8 or w < 8:                # one value throughout, or too small to hold writing
        return {"density": density, "score": 0.0, "flat": 0.0, "blank": True, "structured": False}
    agree = (float(np.mean(bits[:, 1:] == bits[:, :-1])) + float(np.mean(bits[1:, :] == bits[:-1, :]))) / 2.0
    chance = density * density + (1.0 - density) * (1.0 - density)
    score = max(0.0, (agree - chance) / (1.0 - chance))
    flat = 0.0
    th, tw = h // TILE, w // TILE
    if th * tw >= 16:
        tiles = bits[:th * TILE, :tw * TILE].reshape(th, TILE, tw, TILE).mean(axis=(1, 3))
        flat = float(np.mean((tiles <= 0.02) | (tiles >= 0.98)))
    return {"density": density, "score": score, "flat": flat, "blank": False,
            "structured": score >= STRUCTURE_MIN or flat >= FLAT_TILES_MIN}


def render_plane(bits: np.ndarray) -> bytes:
    """A bit plane as PNG, the rarer value dark on white (what OCR reads best), inside a margin."""
    ink = bits.astype(bool) if bits.mean() <= 0.5 else ~bits.astype(bool)
    return _framed(ink.astype(np.float64), True)


def plane_ocr_scales(h: int, w: int) -> tuple:
    """The upscalings a plane is read at. OCR of ciphertext is a coin toss per letter (no word helps
    it), and the toss falls differently at each size, so a small plane is read at three."""
    side = max(h, w)
    return (1, 2, 3) if side < 1000 else (1, 2) if side < 2500 else (1,)


# ---- text to flags ---------------------------------------------------------------------------------

def text_lines(text: str) -> list:
    """The lines of a reading that could be writing: four or more letters, digits, braces or
    underscores, making up at least 60% of the line."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        word = sum(1 for c in line if c.isalnum() or c in "{}_")
        if word >= 4 and word >= 0.6 * len(line):
            out.append(line)
    return list(dict.fromkeys(out))


def _crib():
    """The warmups decoder, loaded on first use. ImportError names what is missing."""
    try:
        import crib_decode
    except Exception as e:
        raise ImportError(f"crib_decode (solvers/warmups) is not importable: {type(e).__name__}: {e}") from e
    return crib_decode


def keyless_readings(payload: bytes, seconds: float) -> dict:
    """crib_decode's {text: chain} of one payload (strict chains, one loose step), given `seconds`
    (at least 0.05): crib_decode.readings_within, its entry point for a caller outside it."""
    return _crib().readings_within(payload, max(0.05, seconds))


MENDED = "prefix mended"
DECODE_CUT = f"keyless decode: {OUT_OF_TIME} before every line was read"
NO_PREFIX = "the event's flag prefix is not known, so a rotation proves nothing"
# image_carve.ocr_flags' brace slips; a letter or digit read for the brace only right after the prefix
_OPEN, _CLOSE = r"(?:\s*[\{\(\[]|[il|1])", r"[\}\)\]]"


def rotation_name(k: int) -> str:
    return "rot13" if k % 26 == 13 else f"caesar+{k % 26}"


def rotated_flags(text: str, ff, prefixes) -> dict:
    """{flag: chain} of the flags written under a letter rotation and then read by OCR, which
    crib_decode cannot reach once OCR has slipped: for each stated prefix and each rotation, the
    rotated prefix on a word start (one of its characters may be misread when it has four or more),
    an opening brace or what OCR makes of one (( [ i l | 1), a body, a closing brace () ]). The body
    is rotated back and kept only when prefix{body} is one flag in the event format. The chain names
    the rotation, and MENDED when the prefix needed it."""
    out = {}
    for pre in prefixes:
        for k in range(26):
            enc = caesar(pre, -k)
            alts = [re.escape(enc)]
            if len(enc) >= 4:
                alts += [re.escape(enc[:j]) + "[A-Za-z0-9]" + re.escape(enc[j + 1:]) for j in range(len(enc))]
            rx = r"(?<![A-Za-z0-9_])(" + "|".join(alts) + r")" + _OPEN + r"([^\n\{\}\(\)\[\]]{1,200})" + _CLOSE
            for m in re.finditer(rx, text):
                chain = ((rotation_name(k),) if k else ()) + (() if m.group(1) == enc else (MENDED,))
                for f in ic.ocr_flags(f"{pre}{{{caesar(m.group(2).strip(), k)}}}", ff, (pre,)):
                    if f not in out or len(chain) < len(out[f]):
                        out[f] = chain
    return out


def text_flags(text: str, ff, prefixes=(), deadline=None, skipped: list | None = None) -> list:
    """[(flag, chain)] of one reading: the event's flag as it stands (chain ()), with the usual OCR
    slips of the braces mended (image_carve.ocr_flags); the same under a letter rotation
    (rotated_flags); then in every keyless reading crib_decode reaches from the whole text and from
    each line; a decoded flag with a control or non-ASCII character in it is noise and dropped. Of
    flags that differ only in letter case the one with the shortest chain is kept. With
    no known flag prefix neither search is made: every rotation of `word{...}` has the any-word shape,
    so it would prove nothing."""
    found = {f: () for f in ic.ocr_flags(text, ff, prefixes)}
    if not ff.known:
        if skipped is not None and "{" in text:
            skipped.append(f"keyless decode not run: {NO_PREFIX}")
        return list(found.items())
    for f, chain in rotated_flags(text, ff, prefixes).items():
        if f not in found or len(chain) < len(found[f]):
            found[f] = chain
    payloads = [text.strip()] + [x for x in text_lines(text)[:MAX_LINES] if x != text.strip()]
    for p in payloads:
        if not p:
            continue
        left = DECODE_SECONDS if deadline is None else min(DECODE_SECONDS, deadline - time.monotonic())
        if left <= 0:
            if skipped is not None:
                skipped.append(DECODE_CUT)
            break
        for reading, chain in keyless_readings(p.encode("utf-8", "replace"), left).items():
            for f in ic.ocr_flags(reading, ff, prefixes):
                if not all(32 <= ord(c) < 127 for c in f):
                    continue                          # a one-byte xor's flag shape with a control character in it: noise
                if f not in found or len(chain) < len(found[f]):
                    found[f] = tuple(chain)
    best = {}                                        # the decoder also offers the text upper-cased, swap-cased, ...:
    for f, chain in found.items():                   # of flags that differ only in case, the shortest chain stands
        if f.lower() not in best or len(chain) < len(best[f.lower()][1]):
            best[f.lower()] = (f, chain)
    return list(best.values())


# ---- keys from sibling files ------------------------------------------------------------------------

_SHIFT = re.compile(r"(?<![\w.])([1-9]|1[0-9]|2[0-5])(?![\w.])")


def caesar(text: str, k: int) -> str:
    def one(c):
        if "a" <= c <= "z":
            return chr((ord(c) - 97 + k) % 26 + 97)
        if "A" <= c <= "Z":
            return chr((ord(c) - 65 + k) % 26 + 65)
        return c
    return "".join(one(c) for c in text)


def vigenere(text: str, key: str, sign: int = -1) -> str:
    """Vigenere over the letters (case kept, the key stepping on letters only); sign -1 decrypts."""
    ks = [ord(c) - 97 for c in key.lower() if "a" <= c <= "z"]
    if not ks:
        return text
    out, i = [], 0
    for c in text:
        if c.isascii() and c.isalpha():
            out.append(caesar(c, sign * ks[i % len(ks)]))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def mask(value: str) -> str:
    """A key as it may be printed: its first character and its length."""
    return f"{value[:1]}***({len(value)})"


@dataclass
class Key:
    value: object              # int: a Caesar shift; str: a Vigenere key
    source: str                # where it came from, printable
    listed: bool = True        # False: its readings are reported only when they hold a flag
    file: str | None = None    # the file it was read from (its own texts are not keyed with it)


def note_keys(files: dict, ff, deadline=None, skipped: list | None = None) -> list:
    """Shifts named in the text notes other pictures carry (an LSB text, a text chunk, data after the
    end): every standalone number 1..25 in a note, at most MAX_NOTE_KEYS a note."""
    keys = []
    for name in sorted(files):
        data = files[name]
        if ic.cs.sniff(data) not in ("png", "bmp"):
            continue
        for h in ic.image_payloads(name, data, ff, deadline, skipped if skipped is not None else []):
            note = (h.data.decode("latin-1") if h.data else h.preview)[:400]
            for m in list(_SHIFT.finditer(note))[:MAX_NOTE_KEYS]:
                keys.append(Key(int(m.group(1)), f"the number {m.group(1)} in {name} ({h.channel}: {h.method[:60]})",
                                file=name))
    return keys


def ledger_keys(files: dict, deadline=None) -> list:
    """B-068's cross-file candidates (evidence_ledger.harvest_candidates: passwords, keys and GUIDs
    joined across LNK, registry, pcap, pax and history files) that are words, as Vigenere keys. Their
    values are never listed: a reading under one is reported only when it holds the event's flag."""
    if sum(len(v) for v in files.values()) > LEDGER_MAX_BYTES:
        raise ValueError(f"the delivery is over {LEDGER_MAX_BYTES} bytes")
    try:
        import evidence_ledger
    except Exception as e:
        raise ImportError(f"evidence_ledger (solvers/common, B-068) is not importable: {type(e).__name__}: {e}") from e
    index = evidence_ledger.collect(dict(files), deadline=deadline)
    return [Key(v, f"evidence-ledger candidate {mask(v)}", listed=False)
            for v in evidence_ledger.candidates(index) if re.fullmatch(r"[A-Za-z]{3,32}", v)]


def given_keys(values) -> list:
    """Keys the caller states: a number 1..25 is a shift, a word a Vigenere key. OptionError otherwise."""
    out = []
    for v in values or ():
        s = str(v).strip()
        if re.fullmatch(r"-?\d+", s) and 1 <= int(s) % 26:
            out.append(Key(int(s) % 26, f"the given shift {s}"))
        elif re.fullmatch(r"[A-Za-z]{2,64}", s):
            out.append(Key(s, f"the given key {s}"))
        else:
            raise OptionError(f"key {s!r} is neither a shift (a number that is not a multiple of 26) nor a word")
    return out


def apply_key(text: str, key: Key) -> list:
    """[(what, text)]: a shift both ways, a word as a Vigenere key decrypting and encrypting."""
    if isinstance(key.value, int):
        return [(f"caesar +{key.value}", caesar(text, key.value)), (f"caesar -{key.value}", caesar(text, -key.value))]
    return [("vigenere decrypt", vigenere(text, key.value, -1)), ("vigenere encrypt", vigenere(text, key.value, 1))]


# ---- one delivery ----------------------------------------------------------------------------------

@dataclass
class Reading:
    file: str
    probe: str                 # PROBE_SPEC | PROBE_GLYPH | PROBE_PLANE
    where: str                 # '8000-12000 Hz, 0.0-18.9 s, light' | 'B bit 0'
    state: str = READ          # READ | BLANK_STATE | NOT_READ
    why: str = ""              # the reason of a NOT_READ
    note: str = ""             # how a plane scored: the sweep's own score and steganalysis's verdict
    text: str = ""
    exact: bool = False        # read by an exact reader (every glyph matched), not by OCR
    score: float | None = None
    flags: list = field(default_factory=list)       # [(flag, chain)], the flag most readings agree on first
    votes: dict = field(default_factory=dict)       # flag -> how many of this picture's readings gave it
    png: bytes | None = field(default=None, repr=False)
    scales: tuple = (OCR_SCALE_BAND,)               # the upscalings it is read at
    parts: list = field(default_factory=list)       # the text of each of those readings
    partial: str = ""          # READ, but not at every size: '1 of 3 sizes read: <why the rest were not>'
    order: tuple = (0,)

    def to_dict(self) -> dict:
        return {"file": self.file, "probe": self.probe, "where": self.where, "state": self.state, "why": self.why,
                "note": self.note, "text": self.text, "exact": self.exact, "score": self.score,
                "partial": self.partial, "flags": [[f, list(c), self.votes.get(f, 1)] for f, c in self.flags]}

    @classmethod
    def from_dict(cls, d: dict) -> "Reading":
        return cls(file=d["file"], probe=d["probe"], where=d["where"], state=d["state"], why=d.get("why", ""),
                   note=d.get("note", ""), text=d.get("text", ""), exact=bool(d.get("exact")), score=d.get("score"),
                   partial=d.get("partial", ""),
                   flags=[(f, tuple(c)) for f, c, _n in d.get("flags", [])],
                   votes={f: int(n) for f, _c, n in d.get("flags", [])}, parts=[d.get("text", "")])

    def decode(self, ff, prefixes, deadline, skipped) -> None:
        """Fill .flags and .votes from each reading of the picture (text_flags)."""
        chains, self.votes = {}, {}
        for part in self.parts or [self.text]:
            for f, chain in text_flags(part, ff, prefixes, deadline, skipped):
                self.votes[f] = self.votes.get(f, 0) + 1
                if f not in chains or len(chain) < len(chains[f]):
                    chains[f] = tuple(chain)
        self.flags = sorted(chains.items(), key=lambda fc: -self.votes[fc[0]])


@dataclass
class Report:
    files: dict = field(default_factory=dict)       # name -> {kind, sha256, detail[, limits: {probe: what it left unseen}]}
    readings: list = field(default_factory=list)    # [Reading]
    keyed: list = field(default_factory=list)       # [{file, where, key, how, text, flags}]
    keys: list = field(default_factory=list)        # the printable source of every key tried
    key_notes: list = field(default_factory=list)   # why a key source was not read
    skipped: list = field(default_factory=list)
    written: list = field(default_factory=list)     # [Path]
    ocr: str = "not needed"                         # not needed | run | off | not run: <why>
    decode: str = "not needed"                      # not needed | run | cut: <why> | not run: <why>
    options: dict | None = None                     # run_options() of the run that made it (None: not recorded)
    seconds: float | None = None                    # the budget of that run (sweep)
    out_of_time: bool = False                       # the deadline stopped something in it

    def to_dict(self) -> dict:
        return {"schema": REPORT_SCHEMA, "engine": ENGINE, "files": self.files,
                "readings": [r.to_dict() for r in self.readings], "keyed": self.keyed, "keys": self.keys,
                "key_notes": self.key_notes, "skipped": self.skipped, "written": [str(p) for p in self.written],
                "ocr": self.ocr, "decode": self.decode, "options": self.options, "seconds": self.seconds,
                "out_of_time": self.out_of_time}

    @classmethod
    def from_dict(cls, d: dict) -> "Report":
        if d.get("schema") != REPORT_SCHEMA or d.get("engine") != ENGINE:
            raise ValueError(f"not a {ENGINE} report of schema {REPORT_SCHEMA}")
        return cls(files=dict(d["files"]), readings=[Reading.from_dict(r) for r in d["readings"]],
                   keyed=list(d.get("keyed", [])), keys=list(d.get("keys", [])), key_notes=list(d.get("key_notes", [])),
                   skipped=list(d.get("skipped", [])), written=[Path(p) for p in d.get("written", [])],
                   ocr=d.get("ocr", "not needed"), decode=d.get("decode", "not needed"), options=d.get("options"),
                   seconds=d.get("seconds"), out_of_time=bool(d.get("out_of_time", False)))

    def flags(self) -> dict:
        """{flag: (Reading | keyed dict, chain)} of every flag, the shortest chain kept, the flag the
        most readings agree on first (a misread differs from reading to reading; the text does not)."""
        out, votes = {}, {}
        for r in self.readings:
            for f, chain in r.flags:
                votes[f] = votes.get(f, 0) + r.votes.get(f, 1)
                if f not in out or len(chain) < len(out[f][1]):
                    out[f] = (r, tuple(chain))
        for k in self.keyed:
            for f in k.get("flags", []):
                votes[f] = votes.get(f, 0) + 1
                out.setdefault(f, (k, (k["how"],)))
        return {f: out[f] for f in sorted(out, key=lambda f: -votes[f])}


_OTHER_AUDIO = ((b"fLaC", "FLAC"), (b"OggS", "Ogg"), (b"ID3", "MP3"), (b"\xff\xfb", "MP3"), (b"FORM", "AIFF"))


def _audio_readings(name: str, data: bytes, rep: Report, top_hz, deadline) -> None:
    audio = sd.read_audio(data)
    if audio is None:
        rep.files[name]["detail"] = "RIFF, but not PCM WAV this reader takes"
        rep.skipped.append(f"{name}: a RIFF file that is not PCM WAV (1 to 4 channels, 8 to 32 bit, at most "
                           f"{sd.MAX_SAMPLES} frames): spectrogram not read; convert it to 16-bit PCM first")
        for probe in (PROBE_SPEC, PROBE_GLYPH):
            rep.readings.append(Reading(name, probe, "0 Hz to Nyquist", NOT_READ, "not PCM WAV this reader takes"))
        return
    nyq = audio.rate / 2.0
    top = nyq if not top_hz else min(nyq, float(top_hz))
    rep.files[name].update(detail=f"{audio.samples.size / audio.rate:.2f} s at {audio.rate} Hz, read 0 to {top:.0f} Hz "
                                  f"of {nyq:.0f} Hz (Nyquist)", nyquist=nyq, top=top)
    limits = {}                                       # what a probe that ran to the end still did not look at
    if top < nyq:
        rep.skipped.append(f"{name}: read only to {top:.0f} Hz (top_hz); {top:.0f} to {nyq:.0f} Hz was not looked at")
        limits[PROBE_SPEC] = f"{top:.0f} to {nyq:.0f} Hz was not looked at (top_hz)"
    stopped = []
    got = glyph_text(audio, deadline, stopped)
    if audio.samples.size > GLYPH_SECONDS * audio.rate:
        rep.skipped.append(f"{name}: the exact 5x7 glyph reader looked at the first {GLYPH_SECONDS:.0f} s only")
        limits[PROBE_GLYPH] = (f"only the first {GLYPH_SECONDS:.0f} s of {audio.samples.size / audio.rate:.1f} s "
                               "was looked at")
    if limits:
        rep.files[name]["limits"] = limits
    for text, how in got:
        rep.readings.append(Reading(name, PROBE_GLYPH, how, READ, text=text, exact=True))
    if stopped:                                       # not a no: the search did not get to the end
        rep.skipped.append(f"{name}: exact 5x7 glyph read: {stopped[0]} before every arrangement was tried")
        rep.readings.append(Reading(name, PROBE_GLYPH, "0 Hz to Nyquist", NOT_READ, stopped[0]))
    elif not got:
        rep.readings.append(Reading(name, PROBE_GLYPH, "0 Hz to Nyquist", BLANK_STATE))
    for k, r in enumerate(renderings(audio, top_hz)):
        rep.readings.append(Reading(name, PROBE_SPEC, r.where, BLANK_STATE if r.blank else NOT_READ, png=r.png,
                                    score=round(r.ink, 5), order=(0 if r.light else 1, 1, k)))


def _plane_readings(name: str, data: bytes, rep: Report) -> None:
    try:
        got = image_array(data)
    except ValueError as e:
        rep.skipped.append(f"{name}: bit planes not read: {e}")
        rep.readings.append(Reading(name, PROBE_PLANE, "bits 0-2 of every channel", NOT_READ, str(e)))
        return
    if got is None:                                   # two letters of magic on a file that is no picture (plain text)
        del rep.files[name]
        return
    arr, labels = got
    rep.files[name]["detail"] = f"{arr.shape[1]}x{arr.shape[0]} {''.join(labels)}, bits {PLANE_BITS[0]}-{PLANE_BITS[-1]}"
    for ci, label in enumerate(labels):
        for bit in PLANE_BITS:
            bits = (arr[:, :, ci] >> bit) & 1
            st = plane_structure(bits)
            structured, score = st["structured"], st["score"]
            r = Reading(name, PROBE_PLANE, f"{label} bit {bit}", NOT_READ if structured else BLANK_STATE,
                        score=round(score, 4), scales=plane_ocr_scales(*bits.shape), order=(0, 0, bit, -score, ci))
            if structured:
                # steganalysis's visual-structure test as a second opinion, on record: it damps a biased
                # plane, so the sparse drawing this sweep is for scores under its lowest threshold
                finding = sa.lsb_plane_score(arr, channel=ci, bit=bit, structure_threshold=0.5)
                r.note = (f"agreement score {score:.2f}, {st['flat']:.0%} flat tiles, density {st['density']:.3f}; "
                          + (f"steganalysis {finding.method} {finding.score:.2f}" if finding is not None else
                             "steganalysis spatial-bitplane/visual-structure: under its threshold"))
                r.png = render_plane(bits)
            else:
                r.why = ("no spatial structure (noise)" if not st["blank"] else
                         "one value throughout" if st["density"] in (0.0, 1.0) else "under 8 pixels a side")
            rep.readings.append(r)


def _kind(data: bytes) -> str | None:
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "audio"
    if any(data.startswith(m) for m, _ in _OTHER_AUDIO):
        return "other-audio"
    if data.startswith(ic.PNG_SIG) or data[:2] in (b"BM", b"P5", b"P6") or data[:4] in (b"II*\x00", b"MM\x00*"):
        return "image"
    return None


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:120] or "file"


def examine(files: dict, ff, *, ocr: str = "auto", out_dir: Path | None = None, deadline=None, prefixes=(),
            top_hz: float | None = None, keys=(), read=None, ledger: bool = True) -> Report:
    """Both readings over {name: bytes}. `read(png, scale=, deadline=)` is the OCR call (default
    image_carve.ocr_text); ocr='off' renders and scores but reads nothing by OCR, 'on' raises
    ToolMissing when tesseract is absent, 'auto' says so in the report. Renderings with something
    drawn in them are written under out_dir. `ff` None: no flag search (texts only)."""
    # a bad ocr mode or key is refused here, before anything is read
    options = run_options(ff, ocr=ocr, keys=keys, top_hz=top_hz, prefixes=prefixes, ledger=ledger)
    read = read or ic.ocr_text
    rep, seen = Report(options=options), set()
    for name in sorted(files):
        data = files[name]
        kind = _kind(data)
        digest = hashlib.sha256(data).hexdigest()
        if kind is None or digest in seen:
            continue
        seen.add(digest)
        if kind == "other-audio":
            what = next(n for m, n in _OTHER_AUDIO if data.startswith(m))
            rep.skipped.append(f"{name}: {what} audio is not read here (PCM WAV only): convert it to WAV and run again")
            continue
        rep.files[name] = {"kind": kind, "sha256": digest, "detail": ""}
        if kind == "audio":
            _audio_readings(name, data, rep, top_hz, deadline)
        else:
            _plane_readings(name, data, rep)
    # ---- OCR: planes first (few, cheap to judge), then the light band pictures, then the dark ----
    jobs = sorted((r for r in rep.readings if r.png is not None), key=lambda r: r.order)
    if jobs and ocr == "off":
        rep.ocr = "off"
        for r in jobs:
            r.why = "OCR is off"
    stop = None
    for r in jobs if ocr != "off" else ():
        if stop is None and deadline is not None and time.monotonic() > deadline:
            stop = OUT_OF_TIME
            rep.skipped.append(f"OCR: {OUT_OF_TIME} before {r.file} {r.where} and what follows it")
        if stop is not None:
            r.why = stop
            continue
        try:
            for scale in r.scales:
                r.parts.append(read(r.png, scale=scale, deadline=deadline).strip()[:MAX_TEXT])
                r.text, r.state = "\n".join(dict.fromkeys(r.parts)), READ
            rep.ocr = "run"
        except ToolMissing as e:
            if ocr == "on":
                raise
            stop = str(e)
            rep.ocr = f"not run: {e}"
            rep.skipped.append(f"OCR not run: {e}; the renderings are written for a human or model read")
            r.why = stop
        except ic.OutOfBudget as e:
            r.why = f"{OUT_OF_TIME}: {e}"
            rep.skipped.append(f"OCR: {OUT_OF_TIME} in {r.file} {r.where}: {e}")
        except RuntimeError as e:
            r.why = str(e)
            rep.skipped.append(f"OCR failed on {r.file} {r.where}: {e}")
        if r.state == READ and len(r.parts) < len(r.scales):
            # some sizes were read before the stop: the text stands, but the reading is not a whole one
            r.partial = f"{len(r.parts)} of {len(r.scales)} sizes read: {r.why}"
    # ---- text to flags ----
    texts = [r for r in rep.readings if r.state == READ and r.text.strip()]
    if ff is not None and texts:
        try:
            for r in texts:
                r.decode(ff, prefixes, deadline, rep.skipped)
            # the decoder is only run against a known prefix (text_flags); one the clock cut is not a no
            rep.decode = (f"not run: {NO_PREFIX}" if not ff.known else
                          f"cut: {OUT_OF_TIME} before every line was read" if DECODE_CUT in rep.skipped else "run")
        except ImportError as e:
            rep.decode = f"not run: {e}"
            rep.skipped.append(f"keyless decode not run: {e}")
            for r in texts:
                r.flags = [(f, ()) for f in ic.ocr_flags(r.text, ff, prefixes)]
                r.votes = {f: 1 for f, _ in r.flags}
        _keyed(files, ff, prefixes, texts, rep, keys, deadline, ledger)
    rep.skipped = list(dict.fromkeys(rep.skipped))
    rep.out_of_time = ((deadline is not None and time.monotonic() > deadline)
                       or any(OUT_OF_TIME in n for n in rep.skipped + rep.key_notes))
    if out_dir is not None and jobs:
        out_dir.mkdir(parents=True, exist_ok=True)
        for r in jobs:
            p = out_dir / f"{_safe(r.file)}.{r.probe}.{_safe(r.where)}.png"
            p.write_bytes(r.png)
            rep.written.append(p)
    return rep


def _keyed(files, ff, prefixes, texts, rep: Report, keys, deadline, ledger: bool) -> None:
    """The cross-file join: every key (given, from sibling notes, from the B-068 ledger) on every line
    read from a different file than the key came from (a given key on all of them)."""
    notes = []
    found = given_keys(keys) + note_keys(files, ff, deadline, notes)
    rep.skipped += notes
    cut = list(dict.fromkeys(n for n in notes if OUT_OF_TIME in n))
    if cut:                                           # the payload scan of a sibling picture did not get to the end
        rep.key_notes.append(f"sibling notes not read to the end ({'; '.join(cut)})")
    if ledger:
        try:
            if deadline is not None and time.monotonic() > deadline:
                raise ValueError(OUT_OF_TIME)
            found += ledger_keys(files, deadline)
            if deadline is not None and time.monotonic() > deadline:
                rep.key_notes.append(f"evidence-ledger keys: {OUT_OF_TIME} while the delivery was read, so some "
                                     "may be missing")
        except (ImportError, ValueError) as e:
            rep.key_notes.append(f"evidence-ledger keys not read: {e}")
        except Exception as e:                       # a reader fault in the ledger must not lose the readings
            rep.key_notes.append(f"evidence-ledger keys not read: {type(e).__name__}: {e}")
    seen_keys = {}
    for k in found:
        seen_keys.setdefault((type(k.value).__name__, str(k.value).lower()), k)
    rep.keys = [k.source for k in seen_keys.values()]
    done = set()
    for r in texts:
        for line in text_lines(r.text)[:MAX_LINES]:
            for k in seen_keys.values():
                if k.file == r.file:
                    continue                          # a key from the same file as the text is not a join
                for what, out in apply_key(line, k):
                    if out == line or (r.file, line, what, str(k.value)) in done:
                        continue
                    done.add((r.file, line, what, str(k.value)))
                    flags = ic.ocr_flags(out, ff, prefixes)
                    if not flags and (not k.listed or len(rep.keyed) >= MAX_KEYED):
                        continue
                    rep.keyed.append({"file": r.file, "where": r.where, "key": k.source, "how": f"{what} ({k.source})",
                                      "text": out[:400], "flags": flags})


# ---- the result ------------------------------------------------------------------------------------

def result_of(rep: Report, *, challenge_id=None, seconds: float = 0.0, root: Path | None = None):
    """The SolverResult of a Report (status rules in the module docstring)."""
    from ctf.result import Cost, Evidence, SolverResult

    def rel(p):
        try:
            return str(Path(p).relative_to(root)) if root else str(p)
        except ValueError:
            return str(p)

    flags = rep.flags()
    evidence, proven = [], []
    for f, (src, chain) in flags.items():
        if isinstance(src, Reading):
            via = f" then {' + '.join(chain)}" if chain else ""
            how = "exact 5x7 glyph read" if src.exact else "OCR"
            evidence.append(Evidence("decode" if src.exact else "ocr", f"{src.probe}: {src.where}: {how}{via}", path=src.file))
            if src.exact and not chain:
                proven.append(f)
        else:
            evidence.append(Evidence("decode", f"{src['where']}: {src['how']}", path=src["file"]))
    for p in rep.written:
        evidence.append(Evidence("carve", "report written" if Path(p).name == REPORT_NAME else "rendering written",
                                 path=rel(p)))
    notes = []
    for name, info in sorted(rep.files.items()):
        rs = [r for r in rep.readings if r.file == name]
        if info["kind"] == "audio":
            spec = [r for r in rs if r.probe == PROBE_SPEC]
            notes.append(f"{name}: {info['detail']}: {sum(r.state == READ for r in spec)} band pictures read, "
                         f"{sum(r.state == BLANK_STATE for r in spec)} blank, {sum(r.state == NOT_READ for r in spec)} not read")
        else:
            drawn = [r for r in rs if r.note]
            notes.append(f"{name}: {info['detail']}: {len(drawn)} of {len(rs)} planes structured"
                         + (f" ({', '.join(r.where for r in drawn[:9])})" if drawn else ""))
    for r in rep.readings:
        if r.state == READ and r.text.strip() and (r.exact or text_lines(r.text)):
            shown = r.text if r.exact else " / ".join(text_lines(r.text)[:4])
            notes.append(f"read in {r.file} {r.where}: {shown[:200]}")
    for k in rep.keyed[:MAX_KEYED]:
        if not k["flags"]:
            notes.append(f"keyed reading of {k['file']}: {k['how']}: {k['text'][:120]}")
    notes += rep.key_notes
    if rep.ocr not in ("not needed", "run"):
        notes.append(f"OCR {rep.ocr}")
    notes += rep.skipped
    unread = [r for r in rep.readings if (r.state == NOT_READ or r.partial) and r.png is not None]
    if len(flags) == 1 and len(proven) == 1:
        status = "solved"
    elif flags:
        status = "candidate"
    elif unread and rep.ocr.startswith("not run"):
        status = "blocked"
    elif unread or any(r.state == READ and (r.exact or text_lines(r.text)) for r in rep.readings):
        status = "unsure"
    else:
        status = "none"
    if not notes and status == "blocked":
        notes.append(f"OCR {rep.ocr}")
    return SolverResult(status=status, flags=list(flags), evidence=evidence,
                        cost=Cost(seconds=round(seconds, 3)), engine=ENGINE, challenge_id=challenge_id,
                        notes="; ".join(dict.fromkeys(notes)))


# ---- the rejected-flag checklist (B-181) ------------------------------------------------------------

def method_of(probe: str, file: str | None = None) -> str:
    """The hypothesis-ledger method string of one probe: what `ctf hypothesis check` is asked."""
    return f"{ENGINE} {probe}" + (f" {file}" if file else "")


_HYPOTHESIS = {
    PROBE_SPEC: "text drawn in the spectrogram of {file}, anywhere from 0 Hz to Nyquist, either polarity",
    PROBE_GLYPH: "exact 5x7 glyphs on seven tones in {file}",
    PROBE_PLANE: "text drawn in a low bit plane (bits 0-2 of any channel) of {file}",
    PROBE_DECODE: "the texts read are the flag under a keyless encoding (rot13, a rotation, atbash, a base family)",
    PROBE_KEYS: "a key hint in one file (a shift in a note, a ledger candidate) decodes the text read from another",
}


def checklist(rep: Report, rejected: str | None = None) -> list:
    """The fixed checklist of the sweep: one item per file and probe in name order, then the two
    delivery-wide ones, each {method, probe, file, hypothesis, result, evidence, payload}. A file's
    probe is judged on the flags it read as they stand; a flag reached through a decode or a key is
    judged under the delivery-wide item that reached it. result is negative (ran to the end, no flag:
    ruled out), false_positive (its only flag is the rejected one), positive (it holds a flag that is
    not the rejected one), inconclusive (some pictures were read, some not, or one was read at fewer
    sizes than it was due; or the probe ran to the end but did not look at the whole file, the limit
    being in evidence) or error (pictures were waiting and none was read: no tesseract, OCR off, out
    of time; the reason is in evidence). The two delivery-wide items work on the texts the file
    probes read, so with no flag they are ruled out only when every reading was made, at every size,
    and their own work ran to the end: otherwise inconclusive, or error when no text was read at all
    while readings were missing."""
    items = []

    def judge(flags, unread, total, base, read=True, part=(), limit=None):
        other = [f for f in flags if f != rejected]
        if other:
            return "positive", other[0], f"{base}; flag read: {other[0]}"
        if rejected is not None and rejected in flags:
            return "false_positive", rejected, f"{base}; its reading {rejected} was rejected"
        if unread and not read:
            return "error", None, f"{base}; not run: {unread[0].why or 'not read'}"
        still = []                                    # why a probe with no flag is not ruled out
        if unread:
            still.append(f"{len(unread)} of {total} not read: {unread[0].why or 'not read'}")
        if part:
            still.append(f"{len(part)} of {total} not read at every size ({part[0].where}: {part[0].partial})")
        if limit:
            still.append(f"not ruled out: {limit}")
        if still:
            return "inconclusive", None, f"{base}; {'; '.join(still)}"
        return "negative", None, f"{base}; no flag in it"

    for name in sorted(rep.files):
        info = rep.files[name]
        for probe in ((PROBE_SPEC, PROBE_GLYPH) if info["kind"] == "audio" else (PROBE_PLANE,)):
            rs = [r for r in rep.readings if r.file == name and r.probe == probe]
            flags = list(dict.fromkeys(f for r in rs for f, chain in r.flags if not chain))
            unread = [r for r in rs if r.state == NOT_READ]
            part = [r for r in rs if r.state == READ and r.partial]
            lines =[x for r in rs if r.state == READ for x in ([r.text] if r.exact else text_lines(r.text)[:2])][:4]
            base = (f"{info['detail']}; {sum(r.state == READ for r in rs)} read, "
                    f"{sum(r.state == BLANK_STATE for r in rs)} blank" + (f"; text: {' / '.join(lines)[:160]}" if lines else ""))
            result, payload, evidence = judge(flags, unread, len(rs), base, any(r.state == READ for r in rs), part,
                                              info.get("limits", {}).get(probe))
            items.append({"method": method_of(probe, name), "probe": probe, "file": name,
                          "hypothesis": _HYPOTHESIS[probe].format(file=name), "result": result,
                          "evidence": evidence, "payload": payload})
    texts = [r for r in rep.readings if r.state == READ and r.text.strip()]
    missing = [r for r in rep.readings if r.state == NOT_READ]
    waiting = ([f"{len(missing)} readings were not made ({missing[0].file} {missing[0].where}: "
                f"{missing[0].why or 'not read'})"] if missing else [])
    part = [r for r in rep.readings if r.state == READ and r.partial]
    if part:                                          # a text read at one size of three is not the whole reading
        waiting.append(f"{len(part)} readings were not made at every size ({part[0].file} {part[0].where}: "
                       f"{part[0].partial})")

    def settled(result, evidence, open_reasons):
        """A delivery-wide item with no flag is ruled out only when nothing it depends on is open."""
        if result != "negative" or not open_reasons:
            return result, evidence
        return ("inconclusive" if texts else "error"), f"{evidence}; not ruled out: {'; '.join(open_reasons)}"

    chained = list(dict.fromkeys(f for r in texts for f, chain in r.flags if chain))
    if not texts:
        result, payload, evidence = "negative", None, "no text was read, so there was nothing to decode"
    elif rep.decode.startswith("not run"):
        result, payload, evidence = "error", None, rep.decode
    else:
        result, payload, evidence = judge(chained, [], len(texts), f"{len(texts)} texts through crib_decode's keyless readings")
    cut = [rep.decode[len("cut: "):]] if rep.decode.startswith("cut: ") else []
    result, evidence = settled(result, evidence, cut + waiting)
    items.append({"method": method_of(PROBE_DECODE), "probe": PROBE_DECODE, "file": None,
                  "hypothesis": _HYPOTHESIS[PROBE_DECODE], "result": result, "evidence": evidence, "payload": payload})
    keyed = list(dict.fromkeys(f for k in rep.keyed for f in k.get("flags", [])))
    base = (f"{len(rep.keys)} keys tried ({'; '.join(rep.keys[:4])[:200]})" if rep.keys else
            "no key hint in any sibling file" if texts else "no text was read, so no key was tried")
    base += "".join(f"; {n}" for n in rep.key_notes)
    result, payload, evidence = judge(keyed, [], 1, base)
    result, evidence = settled(result, evidence, (["a key source was not read to the end"] if rep.key_notes else [])
                               + waiting)
    items.append({"method": method_of(PROBE_KEYS), "probe": PROBE_KEYS, "file": None,
                  "hypothesis": _HYPOTHESIS[PROBE_KEYS], "result": result, "evidence": evidence, "payload": payload})
    return items


CHECK_LABEL = {"negative": "ruled out", "false_positive": "REJECTED", "positive": "open", "inconclusive": "incomplete",
               "error": "not run"}


def checklist_text(items: list, rejected: str | None = None) -> str:
    lines = [f"render_ocr_sweep checklist{f' after the rejection of {rejected}' if rejected else ''}:"]
    lines += [f"  [{CHECK_LABEL[i['result']]:<10}] {i['probe']:<16} {i['file'] or '(the delivery)'} -- {i['evidence']}"
              for i in items]
    lines.append("not covered by this sweep:")
    lines += [f"  - {x}" for x in NOT_COVERED]
    return "\n".join(lines)


def file_checklist(challenge_id: str, items: list, *, workdir=None, profile=None, agent: str = ENGINE) -> list:
    """Write a checklist to the challenge's hypothesis ledger (ctf.hypothesis): a negative per ruled-out
    probe, an inconclusive or error as it is, a positive with its flag, and for a rejected reading a
    positive (unless the ledger already holds one on that method) followed by its false-positive
    correction. Returns the records written."""
    from ctf import hypothesis as hyp
    written = []
    for it in items:
        common = dict(hypothesis=it["hypothesis"], method=it["method"], agent=agent, evidence=it["evidence"],
                      workdir=workdir)
        if it["result"] == "false_positive":
            prior = hyp.seen(challenge_id, it["method"], workdir)
            if prior is None or prior.get("result") != hyp.POSITIVE:
                written.append(hyp.record(challenge_id, result=hyp.POSITIVE, payload=it["payload"], profile=profile,
                                          **{**common, "evidence": "the reading the platform then rejected"}))
            written.append(hyp.mark_false_positive(challenge_id, it["method"], agent=agent, evidence=it["evidence"],
                                                   workdir=workdir))
        else:
            written.append(hyp.record(challenge_id, result=it["result"], payload=it["payload"], profile=profile, **common))
    return written


# ---- the engine contract ---------------------------------------------------------------------------

def swept(data: bytes) -> bool:
    """Whether examine() keeps a file in Report.files: a WAV, or a picture image_array reads or names
    as damaged. A text file that only begins with a picture's two-letter magic is neither."""
    kind = _kind(data)
    if kind != "image":
        return kind == "audio"
    try:
        return _open_picture(data) is not None
    except ValueError:                                # magic, but it does not open: kept in the report, named
        return True


def _digests(files: dict) -> dict:
    return {n: hashlib.sha256(d).hexdigest() for n, d in files.items() if swept(d)}


def save_report(rep: Report, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / REPORT_NAME
    p.write_text(json.dumps(rep.to_dict(), indent=1) + "\n", encoding="utf-8")
    return p


def run_options(ff=None, *, ocr: str = "auto", keys=(), top_hz=None, prefixes=(), ledger: bool = True) -> dict:
    """What a report depends on besides the files, in a form that compares: the flag format, whether
    OCR read ('read': auto and on alike) or was 'off', the given keys as they are applied (a shift
    modulo 26, a word in lower case), top_hz, the stated prefixes, and whether the evidence ledger was
    a key source. OptionError on a bad ocr mode or key."""
    if ocr not in ("auto", "on", "off"):
        raise OptionError("ocr must be auto, on or off")
    return {"flag": None if ff is None else f"{ff.pattern} ({ff.spec.case})",
            "ocr": "off" if ocr == "off" else "read",
            "keys": sorted({str(k.value).lower() for k in given_keys(keys)}),
            "top_hz": float(top_hz) if top_hz else None,
            "prefixes": sorted(str(x) for x in prefixes),
            "ledger": bool(ledger)}


def stale(rep: Report, options: dict, seconds: float | None = None) -> str | None:
    """Why a saved Report does not answer a run with these options (run_options) and this budget, or
    None when it does. It does not when it was made with other options (a key, OCR off, another
    top_hz, flag format or ledger setting) or with none on record; when its OCR could not start (no
    tesseract then: a run now may read what it could not); or when the clock cut it and this run has
    more seconds than it had (`seconds` None: the engine's default)."""
    if rep.options is None:
        return "the saved report does not record the options it was made with"
    if rep.options != options:
        changed = sorted(k for k in set(rep.options) | set(options) if rep.options.get(k) != options.get(k))
        return f"the saved report was made with other options ({', '.join(changed)})"
    if rep.ocr.startswith("not run"):
        return f"the saved report's OCR was {rep.ocr}"
    if rep.out_of_time and (rep.seconds is None or (DEFAULT_SECONDS if seconds is None else seconds) > rep.seconds):
        return "the saved report ran out of time, on a smaller budget than this run has"
    return None


def load_report(out_dir: Path, files: dict, options: dict | None = None, seconds: float | None = None):
    """The saved Report of exactly these files, or None (no report, or the files changed since). With
    `options` (run_options of the run that is asked for), also None when the saved one does not answer
    that run (stale): a report made without a key is not the answer to a run with one."""
    p = Path(out_dir) / REPORT_NAME
    if not p.is_file():
        return None
    rep = Report.from_dict(json.loads(p.read_text(encoding="utf-8")))
    want = _digests(files)
    have = {n: i["sha256"] for n, i in rep.files.items()}
    if set(have.values()) != set(want.values()):
        return None
    return None if options is not None and stale(rep, options, seconds) else rep


def default_out(challenge_dir: Path) -> Path:
    return Path(challenge_dir) / "recon" / "render_ocr_sweep"


def challenge_id_of(challenge_dir: Path) -> str | None:
    """The id in the challenge folder's challenge.json (written by intake and pull), or None."""
    p = Path(challenge_dir) / "challenge.json"
    try:
        cid = json.loads(p.read_text(encoding="utf-8")).get("id")
    except (OSError, ValueError, AttributeError):
        return None
    return str(cid) if cid not in (None, "") else None


def sweep(challenge_dir: Path, profile, **opts) -> Report:
    """examine() over a challenge folder's files with the engine's options; the Report is saved as
    <out>/report.json. ToolMissing when ocr=on and tesseract is absent; OptionError on a bad option."""
    challenge_dir = Path(challenge_dir)
    t0 = time.monotonic()
    out_dir = Path(opts["out"]) if opts.get("out") else default_out(challenge_dir)
    keys = opts.get("keys") or ()
    if isinstance(keys, (int, str)):
        keys = [keys]
    try:
        seconds = float(opts.get("seconds", DEFAULT_SECONDS))
        top = float(opts["top_hz"]) if opts.get("top_hz") else None
    except (TypeError, ValueError) as e:
        raise OptionError(f"seconds and top_hz are numbers: {e}") from e
    if str(opts.get("ledger", "on")) not in ("on", "off"):
        raise OptionError("ledger must be on or off")
    rep = examine(ic.challenge_files(challenge_dir), flagfmt.for_profile(profile), ocr=str(opts.get("ocr", "auto")),
                  out_dir=out_dir, deadline=t0 + seconds, prefixes=tuple(profile.flag.prefixes), top_hz=top, keys=keys,
                  read=opts["read"] if callable(opts.get("read")) else None, ledger=str(opts.get("ledger", "on")) == "on")
    rep.seconds = seconds
    if rep.files:
        rep.written.append(save_report(rep, out_dir))
    return rep


def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. opts: ocr (auto|on|off), out (folder for renderings and report.json; default
    <challenge>/recon/render_ocr_sweep), seconds (budget, default 40), top_hz (read the spectrogram
    only this high; default Nyquist), keys (shifts or key words to try on the texts), ledger (on|off:
    B-068 evidence-ledger keys), record (1: write the checklist to the hypothesis ledger; needs
    challenge_id or a challenge.json), challenge_id, workdir (the event workdir of that ledger)."""
    from ctf.result import SolverResult
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    cid = str(opts["challenge_id"]) if opts.get("challenge_id") else challenge_id_of(challenge_dir)
    record = str(opts.get("record", "")).lower() in ("1", "true", "yes", "on")
    if record and cid is None:
        return SolverResult(status="blocked", engine=ENGINE,
                            notes="record was asked for but there is no challenge id: pass challenge_id= "
                                  "or run on a folder with a challenge.json")
    try:
        rep = sweep(challenge_dir, profile, **opts)
    except ToolMissing as e:
        return SolverResult(status="blocked", engine=ENGINE, challenge_id=cid, notes=f"OCR was asked for (ocr=on) but {e}")
    except OptionError as e:
        return SolverResult(status="blocked", engine=ENGINE, challenge_id=cid, notes=f"bad option: {e}")
    res = result_of(rep, challenge_id=cid, seconds=time.monotonic() - t0, root=challenge_dir)
    if record:
        file_checklist(cid, checklist(rep), profile=profile,
                       workdir=Path(opts["workdir"]) if opts.get("workdir") else None)
    return res


def survey_read(name: str, data: bytes, seconds: float = 40.0) -> dict:
    """One file for stego_tools.survey: {ok, text, files, note, data}. text holds the lines read (and
    any flag of the current event a keyless decode reaches); files the renderings worth a look."""
    try:
        from ctf import event
        profile = event.current()
        ff, prefixes = flagfmt.for_profile(profile), tuple(profile.flag.prefixes)
    except Exception:                                   # no event resolves: texts only, and the note says so
        ff, prefixes = None, ()
    try:
        rep = examine({name: data}, ff, deadline=time.monotonic() + seconds, prefixes=prefixes, ledger=False)
    except Exception as e:
        return {"ok": False, "text": "", "files": {}, "data": None, "note": f"render_ocr_sweep: {type(e).__name__}: {e}"}
    lines, flags = [], list(rep.flags())
    for r in rep.readings:
        if r.state == READ and r.text.strip():
            lines += [f"{r.where}: {x}" for x in ([r.text] if r.exact else text_lines(r.text))]
    files = {f"{_safe(r.where)}.png": r.png for r in rep.readings if r.png is not None}
    states = [r.state for r in rep.readings]
    note = (f"render_ocr_sweep: {states.count(READ)} read, {states.count(BLANK_STATE)} blank, "
            f"{states.count(NOT_READ)} not read" + (f"; flags {flags}" if flags else "")
            + ("" if ff is not None else "; no event resolves, so no flag search")
            + "".join(f"; {s}" for s in rep.skipped[:3]))
    return {"ok": bool(lines or flags), "text": "\n".join([f"FLAG {f}" for f in flags] + lines), "files": files,
            "data": rep.to_dict(), "note": note}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="render_ocr_sweep.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--out", type=Path, help="folder for the renderings (default: none written)")
    ap.add_argument("--ocr", choices=("auto", "on", "off"), default="auto")
    ap.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    ap.add_argument("--top-hz", type=float, help="read the spectrogram only this high (default: Nyquist)")
    ap.add_argument("--key", action="append", default=[], help="a shift (1..25) or a key word to try on the texts")
    a = ap.parse_args(argv)
    from ctf import event
    profile = event.load(a.event) if a.event else event.current()
    missing = [str(p) for p in a.files if not p.is_file()]
    if missing:
        print(f"render_ocr_sweep.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 2
    t0 = time.monotonic()
    try:
        rep = examine({str(p): p.read_bytes() for p in a.files}, flagfmt.for_profile(profile), ocr=a.ocr,
                      out_dir=a.out, deadline=t0 + a.seconds, prefixes=tuple(profile.flag.prefixes),
                      top_hz=a.top_hz, keys=a.key)
    except (ToolMissing, ValueError) as e:
        print(f"render_ocr_sweep.py: {e}", file=sys.stderr)
        return 2
    print(checklist_text(checklist(rep)))
    for p in rep.written:
        print(f"written: {p}")
    print(result_of(rep, seconds=time.monotonic() - t0).to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
