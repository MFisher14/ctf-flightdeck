#!/usr/bin/env python3
"""Signal-in adapter for FSK / line-code WAV captures (B-083). A front end in front of the modems
already in the tree (rf.py, signal_stego_depth.py): it does the parts those were missing -- high-pass
(baseline removal), threshold + run-length, tone and baud estimation, the NRZ / NRZ-I / differential
and Manchester line codes, the common framings (raw, HDLC-style sync word, HDLC bit-stuffing, UART
8N1) -- and it chooses among the many (line code x polarity x bit order x framing x phase) readings
the one whose bytes carry a flag, using the event flag prefix as the crib (ctf.flagfmt).

    .venv/bin/python solvers/toolkits/wav_linecode.py <file.wav>...     triage, then a SolverResult line

Why an adapter and not a new modem: the hard, reusable parts (two-tone energy, Manchester pairing,
8N1 framing) already exist; what hand-decodes of these captures needed every time was the signal-in
plumbing and the search over the handful of conventions. This module is that plumbing, made
deterministic by crib selection.

Public functions (each a plain step an operator can call):

  load(data)                         -> (rate, float64 mono samples) or (None, None)
  goertzel_power(x, rate, f)         one DFT bin's power (2-D: per row)
  dominant_tones(sig, rate, n)       the n strongest spectral peaks (Hz), for FSK mark/space
  highpass_subtract(sig, w)          sig minus its w-sample moving average (kills drift + mains hum)
  adaptive_threshold(sig, w)         0/1 levels: sample above its local (w) mean
  symbols_from_runs(timings, unit)   a run-length capture re-expanded to one symbol per `unit`
  nrz_bits / nrzi_bits / manchester_bits    the three line codes, each in both polarities
  pack_bits(bits, msb_first)         bits -> bytes
  sync_align(bits, sync_byte)        re-align to a byte boundary on a sync word (0x7E), payload after it
  hdlc_frames(bits)                  HDLC deframe (flag 0x7E, 0-bit destuff, drop 16-bit FCS)
  crc8(data, poly, init)             CRC-8 (the telltale frame's trailer check)
  fsk_streams(sig, rate)             estimate the two tones + baud, demodulate to bit strings
  level_streams(sig, rate)           high-pass / threshold / run-length front end to bit strings
  stream_candidates(sources, ff, byte_sources=None)   the crib step alone: every framed reading of
                                     named bit strings, searched for a flag (reused by iq_demod, B-158)
  rank_candidates(cands)             best first: a flag, then the flag lead, then printable, then short
  decode(data, ff=None)             -> Decode: every candidate, the flags found, the chosen reading
"""
import io
import json
import math
import struct
import sys
import wave
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import rf  # noqa: E402  (sibling toolkit: runs, te_estimate, bits_to_bytes, uart_decode)

ENGINE = "toolkits.wav_linecode"
MAX_SAMPLES = 6_000_000             # ~2 minutes at 48 kHz; a longer capture is truncated
MIN_SYMBOLS = 16                    # fewer symbols than this is not a line-code capture
SYNC_BYTE = 0x7E                    # HDLC-style frame flag, the common sync word in these captures


# ---- loading ---------------------------------------------------------------------------------------

def load(data):
    """(rate, mono float64 numpy samples in about [-1, 1]) of a PCM WAV, or (None, None) when it is
    not a WAV this reads (no numpy, not PCM of 8/16/24/32-bit, empty, or over the sample cap)."""
    try:
        import numpy as np
    except Exception:
        return None, None
    if not isinstance(data, (bytes, bytearray)) or data[:4] != b"RIFF":
        return None, None
    try:
        with wave.open(io.BytesIO(bytes(data)), "rb") as w:
            if w.getcomptype() != "NONE":
                return None, None
            ch, sw, rate = w.getnchannels(), w.getsampwidth(), w.getframerate()
            n = min(w.getnframes(), MAX_SAMPLES)
            raw = w.readframes(n)
    except (wave.Error, EOFError, struct.error, ValueError):
        return None, None
    if rate <= 0 or ch < 1:
        return None, None
    if sw == 1:
        a = np.frombuffer(raw, dtype=np.uint8).astype(np.float64) - 128.0
    elif sw == 2:
        a = np.frombuffer(raw[:len(raw) // 2 * 2], dtype="<i2").astype(np.float64)
    elif sw == 3:
        b = np.frombuffer(raw[:len(raw) // 3 * 3], dtype=np.uint8).reshape(-1, 3).astype(np.int32)
        a = (b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)).astype(np.float64)
        a -= (a >= (1 << 23)) * (1 << 24)
    elif sw == 4:
        a = np.frombuffer(raw[:len(raw) // 4 * 4], dtype="<i4").astype(np.float64)
    else:
        return None, None
    if ch > 1:
        a = a[:len(a) // ch * ch].reshape(-1, ch).mean(axis=1)
    if a.size == 0:
        return None, None
    peak = float(np.max(np.abs(a))) or 1.0
    return rate, a / peak


# ---- DFT helpers -----------------------------------------------------------------------------------

def goertzel_power(x, rate, f):
    """Power at frequency f (Hz) of a 1-D sample window, or, when x is 2-D, a 1-D array of the power
    of each row. A plain single-bin DFT (|sum x e^-j...|^2), windowless so a whole-cycle slot lands
    on the bin exactly."""
    import numpy as np
    x = np.asarray(x, dtype=np.float64)
    n = x.shape[-1]
    k = np.arange(n) * (2.0 * math.pi * f / rate)
    re = x @ np.cos(k)
    im = x @ np.sin(k)
    return re * re + im * im


def dominant_tones(sig, rate, n=2, min_gap_hz=50.0):
    """The n strongest spectral peaks (Hz, high power first) of a window, separated by at least
    min_gap_hz. [] when fewer than n peaks stand above a tenth of the strongest. For FSK this names
    the mark and space tones without being told them."""
    import numpy as np
    s = np.asarray(sig, dtype=np.float64)
    if s.size < 16:
        return []
    mag = np.abs(np.fft.rfft(s * np.hanning(s.size)))
    freqs = np.fft.rfftfreq(s.size, 1.0 / rate)
    mag[0] = 0.0                     # ignore DC
    order = np.argsort(mag)[::-1]
    peaks = []
    for i in order:
        f = float(freqs[i])
        if mag[i] < mag[order[0]] * 0.1:
            break
        if all(abs(f - g) >= min_gap_hz for g in peaks):
            peaks.append(f)
        if len(peaks) >= n:
            break
    return peaks if len(peaks) >= n else []


# ---- burst detection + front end -------------------------------------------------------------------

def _fast_moving_average(sig, w):
    """A centred w-sample mean, O(n) with a cumulative sum (uniform box)."""
    import numpy as np
    w = max(1, int(w))
    if w <= 1 or w >= sig.size:
        return np.full(sig.size, float(np.mean(sig)))
    pad = np.concatenate(([0.0], np.cumsum(sig)))
    idx = np.arange(sig.size)
    half = w // 2
    a = np.clip(idx - half, 0, sig.size - w)
    b = a + w
    return (pad[b] - pad[a]) / w


def highpass_subtract(sig, w):
    """sig minus its w-sample moving average: removes a slow baseline drift and any periodic hum
    whose period divides w (a 20 ms window at 48 kHz cancels 50 Hz mains, the telltale case)."""
    return sig - _fast_moving_average(sig, w)


def find_burst(sig, rate, unit_ms=1.0):
    """(start, end) sample indices of the one active stretch: where a short-window amplitude
    envelope stays above the floor-to-peak midpoint. (0, len) when there is no clear burst."""
    import numpy as np
    env = _fast_moving_average(np.abs(sig), max(4, int(rate * unit_ms / 1000)))
    floor = float(np.percentile(env, 20))
    peak = float(np.percentile(env, 99))
    if peak <= floor * 1.3 + 1e-12:
        return 0, sig.size
    active = np.flatnonzero(env > (floor + peak) / 2.0)
    if active.size < MIN_SYMBOLS:
        return 0, sig.size
    return int(active[0]), int(active[-1]) + 1


def adaptive_threshold(sig, w):
    """0/1 levels: each sample compared with its local w-sample mean (w<=0: the global mean). A
    local mean tracks a drifting baseline, so a long run does not cross the threshold on drift."""
    import numpy as np
    base = _fast_moving_average(sig, w) if w and w > 1 else float(np.mean(sig))
    return (sig > base).astype(np.int64)


def estimate_unit(timings):
    """The short symbol unit (samples) of a run-length capture: rf.te_estimate, the median of the
    runs near the 10th-percentile run, so one glitch run does not set it. None under 8 runs."""
    return rf.te_estimate(timings)


def symbols_from_runs(timings, unit):
    """A run-length capture re-expanded to one symbol per `unit`: a +L run becomes round(L/unit)
    ones, a -L run that many zeros. This recovers the chip/bit stream without a precise global phase
    (the leading edge of each run realigns it)."""
    if not unit or unit <= 0:
        return []
    out = []
    for t in timings:
        n = max(1, int(round(abs(t) / unit)))
        out.extend([1 if t > 0 else 0] * n)
    return out


# ---- line codes ------------------------------------------------------------------------------------

def nrz_bits(symbols, invert=False):
    """NRZ: the symbol level is the bit. invert flips the polarity (idle-high vs idle-low)."""
    return "".join("1" if (s ^ invert) else "0" for s in symbols)


def nrzi_bits(symbols, transition_is_one=True):
    """NRZ-I / differential: a change between consecutive symbols is one bit value, no change the
    other. transition_is_one=True reads a transition as 1 (and a hold as 0). The first symbol has no
    predecessor, so it carries no bit."""
    out = []
    for i in range(1, len(symbols)):
        changed = symbols[i] != symbols[i - 1]
        out.append("1" if changed == transition_is_one else "0")
    return "".join(out)


def manchester_bits(symbols, convention="ieee"):
    """Manchester from a chip stream (two chips per bit): pair the chips at whichever of the two
    phases makes every pair a transition (01 or 10), then map 01->1, 10->0 for IEEE 802.3
    (convention='thomas' inverts). '' when neither phase pairs cleanly (not Manchester at this unit).
    Returns (bits, invalid_pairs) so a caller can compare phases."""
    best = ("", math.inf)
    for off in (0, 1):
        s = symbols[off:]
        s = s[:len(s) - len(s) % 2]
        if len(s) < 8:
            continue
        invalid = sum(1 for i in range(0, len(s), 2) if s[i] == s[i + 1])
        if invalid < best[1]:
            bits = "".join("1" if s[i] == 0 and s[i + 1] == 1 else "0" for i in range(0, len(s), 2))
            if convention == "thomas":
                bits = bits.translate(str.maketrans("01", "10"))
            best = (bits, invalid)
    return best


# ---- bit packing + framing -------------------------------------------------------------------------

def pack_bits(bits, msb_first=True):
    """Whole bytes of a bit string (a ragged tail is dropped)."""
    return rf.bits_to_bytes(bits, msb_first)


def _bits_of(data, msb_first=True):
    out = []
    for byte in data:
        for k in range(8):
            out.append((byte >> (7 - k)) & 1 if msb_first else (byte >> k) & 1)
    return out


def sync_align(bits, sync_byte=SYNC_BYTE, msb_first=True):
    """The byte stream re-aligned on the first occurrence of `sync_byte` as a bit pattern: the bits
    from the sync word on, packed into bytes (the sync byte is the first byte). None when the bit
    pattern does not occur. This fixes the byte boundary from the sync word, whatever the preamble
    length or the line-code pairing phase."""
    pat = "".join(str(b) for b in _bits_of([sync_byte], msb_first))
    i = bits.find(pat)
    if i < 0:
        return None
    return pack_bits(bits[i:], msb_first)


def payload_after_sync(data, sync_byte=SYNC_BYTE):
    """The bytes after the first `sync_byte` in a byte stream, or None when it is absent. (The
    simplest framing: a preamble, a sync byte, then the message.)"""
    i = data.find(bytes([sync_byte]))
    return data[i + 1:] if i >= 0 else None


def hdlc_frames(bits):
    """HDLC frames in a bit string: the content between two 0x7E flags (01111110), with the
    transparency 0 removed after every five 1s, and the trailing 16-bit FCS dropped. [payloads].
    Empty when no two flags bound a frame."""
    flag = "01111110"
    out, i = [], bits.find(flag)
    if i < 0:
        return out
    i += len(flag)
    while True:
        j = bits.find(flag, i)
        if j < 0:
            break
        content = bits[i:j]
        destuffed, ones = [], 0
        for c in content:
            if ones == 5:
                ones = 0
                if c == "0":        # a stuffed 0 after five 1s is removed
                    continue
            destuffed.append(c)
            ones = ones + 1 if c == "1" else 0
        frame = pack_bits("".join(destuffed))
        if len(frame) >= 3:
            out.append(frame[:-2])  # drop the 16-bit FCS
        i = j + len(flag)
    return out


def uart_8n1(symbols, invert=False):
    """Asynchronous 8N1 bytes from an NRZ symbol stream (one symbol per bit time, idle high; idle low
    with invert=True): a start bit (a 1->0 edge) then 8 data bits LSB first then a stop bit (must be
    1). A frame whose stop bit is not 1 is dropped. Returns the decoded bytes (empty when none frame
    cleanly). This is the line-code UART framing the captures use directly, no oversampling needed."""
    lv = [1 if (s ^ (1 if invert else 0)) else 0 for s in symbols]
    out, i, n = bytearray(), 0, len(lv)
    while i < n:
        if lv[i] != 0:              # wait for a start bit (idle is 1)
            i += 1
            continue
        if i + 9 >= n:
            break
        if lv[i + 9] != 1:          # stop bit must be high; not a frame
            i += 1
            continue
        v = 0
        for k in range(8):
            v |= lv[i + 1 + k] << k
        out.append(v)
        i += 10
    return bytes(out)


def crc8(data, poly=0x07, init=0x00):
    """CRC-8 of the bytes (MSB-first, no reflection). Default poly 0x07 init 0x00 is the frame check
    the telltale-style frame carries over its length byte and payload."""
    c = init
    for b in data:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c


# ---- demodulation front ends -----------------------------------------------------------------------

def _fsk_symbol_samples(sig, rate, f0, f1):
    """Samples per bit of an FSK burst, from the run lengths of a per-cycle tone decision. None when
    the decision has too few runs to estimate a unit."""
    import numpy as np
    block = max(8, int(round(rate / max(f0, f1))))     # one cycle of the higher tone
    n = sig.size // block
    if n < MIN_SYMBOLS:
        return None
    seg = sig[:n * block].reshape(n, block)
    decision = (goertzel_power(seg, rate, f1) > goertzel_power(seg, rate, f0)).astype(np.int64)
    unit = estimate_unit(rf.runs(decision.tolist()))
    if not unit:
        return None
    spb = int(round(unit * block))
    return spb if spb >= 4 else None


def fsk_streams(sig, rate):
    """Estimate the two tones and the baud of an FSK burst, then demodulate it to bit strings.
    Returns {'tones': (f0, f1), 'spb': samples_per_bit, 'baud': rate/spb, 'streams': {label: bits}}
    with a label per tone assignment ('f1=1', 'f0=1'), or None when it is not a two-tone burst."""
    import numpy as np
    s0, s1 = find_burst(sig, rate)
    burst = sig[s0:s1]
    if burst.size < MIN_SYMBOLS * 8:
        burst, s0 = sig, 0
    tones = dominant_tones(burst, rate, 2)
    if len(tones) < 2:
        return None
    f0, f1 = sorted(tones[:2])
    spb = _fsk_symbol_samples(burst, rate, f0, f1)
    if not spb:
        return None
    nbits = burst.size // spb
    if nbits < MIN_SYMBOLS:
        return None
    seg = burst[:nbits * spb].reshape(nbits, spb)
    p0, p1 = goertzel_power(seg, rate, f0), goertzel_power(seg, rate, f1)
    hi = (p1 > p0).astype(np.int64)
    return {"tones": (f0, f1), "spb": spb, "baud": rate / spb,
            "streams": {"f1=1": "".join(map(str, hi.tolist())),
                        "f0=1": "".join("1" if not b else "0" for b in hi.tolist())}}


def level_streams(sig, rate):
    """High-pass / threshold / run-length front end to candidate bit strings for a baseband
    (OOK / level-coded) capture: for a few detrend windows, threshold to levels, run-length, estimate
    the symbol unit, then read the symbol stream as NRZ (both polarities), NRZ-I (both) and
    Manchester (both conventions). Also decodes UART 8N1 bytes from the symbol stream directly
    (both polarities). Returns {'units': [...], 'streams': {label: bits}, 'bytes': {label: data}}.
    Crib selection decides among the labels."""
    import numpy as np
    out = {}
    byte_out = {}
    units = []
    windows = sorted({0, int(rate * 0.02), int(rate * 0.1)})     # none, 20 ms, 100 ms
    for w in windows:
        base = highpass_subtract(sig, w) if w > 1 else sig - float(np.mean(sig))
        s0, s1 = find_burst(base, rate)
        region = base[s0:s1] if s1 - s0 >= MIN_SYMBOLS else base
        levels = (region > 0).astype(np.int64)
        timings = rf.runs(levels.tolist())
        if len(timings) < 8:
            continue
        unit = estimate_unit(timings)
        if not unit:
            continue
        units.append(unit)
        symbols = symbols_from_runs(timings, unit)
        if len(symbols) < MIN_SYMBOLS:
            continue
        tag = f"w{w}"
        out[f"{tag}:nrz"] = nrz_bits(symbols, False)
        out[f"{tag}:nrz_inv"] = nrz_bits(symbols, True)
        out[f"{tag}:nrzi1"] = nrzi_bits(symbols, True)
        out[f"{tag}:nrzi0"] = nrzi_bits(symbols, False)
        for conv in ("ieee", "thomas"):
            bits, _ = manchester_bits(symbols, conv)
            if bits:
                out[f"{tag}:manchester_{conv}"] = bits
        # UART 8N1 is self-framing (start/stop bits), so it is read from the whole thresholded
        # signal, not the burst-trimmed region: trimming can clip a final stop bit and drop a byte.
        full = symbols_from_runs(rf.runs((base > 0).astype(np.int64).tolist()), unit)
        for inv in (False, True):
            u = uart_8n1(full, inv)
            if len(u) >= 3:
                byte_out[f"{tag}:uart8n1{'_inv' if inv else ''}"] = u
    return {"units": units, "streams": out, "bytes": byte_out}


# ---- orchestration + crib selection ----------------------------------------------------------------

@dataclass
class Candidate:
    scheme: str                     # the demod + line-code label
    framing: str                    # raw | sync | hdlc
    bit_order: str                  # msb | lsb
    data: bytes                     # the framed byte stream searched for a flag
    flags: tuple = ()               # flags found in `data`
    lead: bool = False              # the flag lead (PREFIX{) occurs, even without a full match
    text: str = ""                  # a printable preview


@dataclass
class Decode:
    ok: bool = False
    flags: tuple = ()
    best: Candidate | None = None
    candidates: list = field(default_factory=list)
    tones: tuple | None = None
    baud: float | None = None
    note: str = ""


def _framings(bits, bit_order, ff):
    """(framing label, byte stream) for each framing of one bit string under one bit order."""
    msb = bit_order == "msb"
    raw = pack_bits(bits, msb)
    yield "raw", raw
    aligned = sync_align(bits, SYNC_BYTE, msb)
    if aligned is not None:
        after = payload_after_sync(aligned, SYNC_BYTE)
        yield "sync", after if after is not None else aligned
    for frame in hdlc_frames(bits):
        yield "hdlc", frame


def _printable_ratio(data):
    if not data:
        return 0.0
    good = sum(1 for c in data if 32 <= c < 127 or c in (9, 10, 13))
    return good / len(data)


def stream_candidates(sources, ff, byte_sources=None):
    """Every framed reading of named bit strings as Candidates, each searched for a flag in the format
    `ff`: `sources` is {scheme label: bit string}, read under both bit orders and each framing
    (_framings); `byte_sources` is {scheme label: bytes} for streams that are already bytes (UART 8N1),
    scanned raw and after a sync word. Unranked: pass the list to rank_candidates. This is the crib
    step on its own, so another signal front end (the IQ demodulators, B-158) can reuse it."""
    cands = []
    # byte sources (UART 8N1): already framed into bytes, scanned raw and after a sync word
    for scheme, blob in (byte_sources or {}).items():
        for framing, data2 in (("raw", blob), ("sync", payload_after_sync(blob, SYNC_BYTE))):
            if not data2:
                continue
            flags = tuple(dict.fromkeys(ff.find_flags(data2)))
            lead = bool(ff.lead_bregex.search(data2)) if not flags else True
            text = "".join(chr(c) if 32 <= c < 127 else "." for c in data2[:120])
            cands.append(Candidate(scheme, framing, "lsb", data2, flags, lead, text))
    for scheme, bits in sources.items():
        if len(bits) < MIN_SYMBOLS:
            continue
        for order in ("msb", "lsb"):
            for framing, blob in _framings(bits, order, ff):
                if not blob:
                    continue
                flags = tuple(dict.fromkeys(ff.find_flags(blob)))
                lead = bool(ff.lead_bregex.search(blob)) if not flags else True
                text = "".join(chr(c) if 32 <= c < 127 else "." for c in blob[:120])
                cands.append(Candidate(scheme, framing, order, blob, flags, lead, text))
    return cands


def rank_candidates(cands):
    """The candidates best first: a flag beats a lead beats printable; among equals a shorter framed
    blob (closer to the payload) first. Sorts the list in place and returns it."""
    def key(c):
        return (bool(c.flags), c.lead, _printable_ratio(c.data), -len(c.data))
    cands.sort(key=key, reverse=True)
    return cands


def decode(data, ff=None):
    """Decode an FSK / line-code WAV. Tries every (demod x line code x polarity x bit order x framing)
    reading and selects by crib: a reading whose bytes carry a flag in the event format wins; failing
    that, one carrying the flag lead (`PREFIX{`); failing that, the most printable. Returns a Decode.
    ff defaults to the active event's flag format (ctf.flagfmt.current())."""
    if ff is None:
        ff = flagfmt.current()
    rate, sig = load(data)
    if sig is None:
        return Decode(note="not a PCM WAV this reads (needs numpy; 8/16/24/32-bit PCM)")
    sources = {}
    fsk = fsk_streams(sig, rate)
    tones = baud = None
    if fsk:
        tones, baud = fsk["tones"], fsk["baud"]
        for lbl, bits in fsk["streams"].items():
            sources[f"fsk[{int(round(fsk['tones'][0]))}/{int(round(fsk['tones'][1]))}Hz {int(round(baud))}bd]:{lbl}"] = bits
    lev = level_streams(sig, rate)
    for lbl, bits in lev["streams"].items():
        sources[lbl] = bits
    cands = rank_candidates(stream_candidates(sources, ff, lev["bytes"]))
    flags = tuple(dict.fromkeys(f for c in cands for f in c.flags))
    best = cands[0] if cands else None
    ok = bool(flags)
    note = "" if ok else ("flag lead seen but no full flag" if best and best.lead
                          else "no flag recovered from any reading")
    return Decode(ok=ok, flags=flags, best=best, candidates=cands, tones=tones, baud=baud, note=note)


# ---- CLI -------------------------------------------------------------------------------------------

def _result(path, dec):
    from ctf.result import Cost, Evidence, SolverResult
    if dec.flags:
        c = dec.best
        detail = f"{c.scheme}, {c.bit_order}, framing {c.framing}"
        return SolverResult(status="solved", flags=list(dec.flags),
                            evidence=[Evidence("decode", detail, path=path)], engine=ENGINE)
    if dec.best is None:
        return SolverResult(status="blocked", engine=ENGINE,
                            notes=dec.note or "could not read the WAV")
    if dec.best.lead:
        return SolverResult(status="unsure", engine=ENGINE,
                            notes=f"flag lead seen in a {dec.best.scheme} reading, no full flag: {dec.best.text!r}")
    return SolverResult(status="none", engine=ENGINE, notes=dec.note)


def triage(path, data):
    dec = decode(data)
    lines = [f"== {path}"]
    rate, sig = load(data)
    if sig is None:
        lines.append("  not a PCM WAV this reads")
        return "\n".join(lines), dec
    lines.append(f"  PCM WAV: {rate} Hz, {sig.size} samples ({sig.size / rate:.3f} s)")
    if dec.tones:
        lines.append(f"  FSK tones {int(round(dec.tones[0]))}/{int(round(dec.tones[1]))} Hz, "
                     f"baud {dec.baud:.1f}")
    for c in dec.candidates[:6]:
        tag = f"flags={list(c.flags)}" if c.flags else ("lead" if c.lead else f"print={_printable_ratio(c.data):.2f}")
        lines.append(f"  {c.scheme} {c.bit_order} {c.framing}: {tag}  {c.text!r}")
    if dec.flags:
        lines.append(f"  FLAG(S): {list(dec.flags)}")
    return "\n".join(lines), dec


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    if not argv:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    rc = 0
    for arg in argv:
        p = Path(arg)
        if not p.is_file():
            print(f"wav_linecode.py: {arg} is not a file", file=sys.stderr)
            rc = 1
            continue
        data = p.read_bytes()
        text, dec = triage(str(p), data)
        if as_json:
            print(json.dumps({"file": str(p), "flags": list(dec.flags),
                              "tones": dec.tones, "baud": dec.baud}, ensure_ascii=False))
        else:
            print(text)
        print(_result(str(p), dec).to_json())
    return rc


if __name__ == "__main__":
    sys.exit(main())
