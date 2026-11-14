#!/usr/bin/env python3
"""Bounded, offline audio signal/steganography decoders.

The module deliberately separates *demodulation* from *acceptance*.  The
``decode_*`` binary-modem APIs return a proven payload only after recovering
this self-validating envelope::

    b"R5A1" + uint16_be(length) + uint32_be(crc32(payload)) + payload

This prevents random audio from becoming an asserted byte string.  Parallel
``*_candidates`` APIs expose ordinary challenge traffic as explicitly labeled,
unproven candidates only after modulation dominance plus byte/flag/UART or
DTMF framing checks.  Morse and
spectrogram text have structural checks (valid timing lattice / exact glyph
matches), SSTV requires a valid leader and even-parity VIS code, and ggwave is
accepted only through ggwave's own framed/FEC decoder.

All APIs consume caller-supplied bytes or sample arrays; nothing executes an
artifact, invokes a media program, or uses the network.  Inputs and work are
bounded for CTF use.
"""
from __future__ import annotations

import binascii
import io
import math
import re
import struct
import wave
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

import numpy as np


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAGIC = b"R5A1"
MAX_AUDIO_BYTES = 128 << 20
MAX_SAMPLES = 12_000_000
MAX_PAYLOAD = 1 << 20
MAX_SYMBOLS = 1_000_000
MAX_CANDIDATES = 32
_FLAG = flagfmt.BYTES
_PRINTABLE = re.compile(rb"[\x20-\x7e]{6,4096}")


@dataclass(frozen=True)
class Audio:
    rate: int
    samples: np.ndarray


@dataclass(frozen=True)
class SignalCandidate:
    """A recovered value plus the byte-level check that justified surfacing it.

    ``proven`` is reserved for CRC/protocol checks.  Printable/flag/UART results
    remain candidates even at confidence 1.0.
    """

    scheme: str
    payload: bytes
    check: str
    confidence: float
    proven: bool = False


def _valid_rate(value) -> bool:
    try:
        return math.isfinite(float(value)) and 1000 <= int(value) <= 768000
    except (TypeError, ValueError, OverflowError):
        return False


def checked_frame(payload: bytes) -> bytes:
    """Build the binary envelope understood by the modem decoders."""
    payload = bytes(payload)
    if len(payload) > 0xFFFF:
        raise ValueError("payload too large for R5A1 frame")
    return MAGIC + struct.pack(">HI", len(payload), binascii.crc32(payload) & 0xFFFFFFFF) + payload


def _parse_checked(blob: bytes) -> bytes | None:
    """Return a CRC-validated payload at any byte offset, otherwise ``None``."""
    at = 0
    while True:
        at = blob.find(MAGIC, at)
        if at < 0:
            return None
        if at + 10 <= len(blob):
            length, expected = struct.unpack_from(">HI", blob, at + 4)
            end = at + 10 + length
            if length <= MAX_PAYLOAD and end <= len(blob):
                payload = blob[at + 10:end]
                if binascii.crc32(payload) & 0xFFFFFFFF == expected:
                    return payload
        at += 1


def _pcm_wav(data: bytes) -> Audio | None:
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_AUDIO_BYTES:
        return None
    try:
        with wave.open(io.BytesIO(bytes(data)), "rb") as wf:
            if wf.getcomptype() != "NONE" or wf.getnchannels() not in (1, 2, 3, 4):
                return None
            rate, width, channels, frames = (
                wf.getframerate(), wf.getsampwidth(), wf.getnchannels(), wf.getnframes()
            )
            if rate < 1000 or rate > 768000 or width not in (1, 2, 3, 4) or frames > MAX_SAMPLES:
                return None
            raw = wf.readframes(frames)
    except (wave.Error, EOFError, ValueError):
        return None
    if width == 1:
        values = np.frombuffer(raw, dtype=np.uint8).astype(np.float64) - 128.0
        scale = 128.0
    elif width == 2:
        values = np.frombuffer(raw, dtype="<i2").astype(np.float64)
        scale = 32768.0
    elif width == 4:
        values = np.frombuffer(raw, dtype="<i4").astype(np.float64)
        scale = float(1 << 31)
    else:
        b = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3)
        u = b[:, 0].astype(np.int32) | (b[:, 1].astype(np.int32) << 8) | (b[:, 2].astype(np.int32) << 16)
        values = np.where(u & 0x800000, u - 0x1000000, u).astype(np.float64)
        scale = float(1 << 23)
    if values.size % channels:
        return None
    mono = values.reshape(-1, channels).mean(axis=1) / scale
    return Audio(rate, mono)


def read_audio(
    source: bytes | bytearray | Sequence[float] | np.ndarray | Audio,
    *,
    sample_rate: int | None = None,
    raw_dtype: str = "<i2",
    channels: int = 1,
) -> Audio | None:
    """Read PCM WAV, raw PCM, or an in-memory mono sample array.

    Byte strings beginning with RIFF are parsed as WAV.  Other byte strings
    require ``sample_rate`` and use ``raw_dtype`` (``<i2``, ``<i4``, ``u1`` or
    ``<f4``).  Multi-channel raw input is downmixed.
    """
    if isinstance(source, Audio):
        try:
            valid = (_valid_rate(source.rate) and source.samples.ndim == 1
                     and 0 < source.samples.size <= MAX_SAMPLES
                     and np.all(np.isfinite(source.samples)))
        except (AttributeError, TypeError, ValueError):
            return None
        return source if valid else None
    if isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
        if raw.startswith(b"RIFF"):
            return _pcm_wav(raw)
        if (sample_rate is None or not _valid_rate(sample_rate)
                or len(raw) > MAX_AUDIO_BYTES or channels not in (1, 2, 3, 4)):
            return None
        try:
            values = np.frombuffer(raw, dtype=np.dtype(raw_dtype))
        except (TypeError, ValueError):
            return None
        if values.size == 0 or values.size > MAX_SAMPLES * channels or values.size % channels:
            return None
        try:
            if np.issubdtype(values.dtype, np.floating):
                norm = values.astype(np.float64)
            elif values.dtype == np.uint8:
                norm = (values.astype(np.float64) - 128.0) / 128.0
            elif np.issubdtype(values.dtype, np.integer):
                info = np.iinfo(values.dtype)
                norm = values.astype(np.float64) / max(abs(info.min), info.max)
            else:
                return None
        except (TypeError, ValueError, OverflowError):
            return None
        if not np.all(np.isfinite(norm)):
            return None
        return Audio(int(sample_rate), norm.reshape(-1, channels).mean(axis=1))
    if sample_rate is None or not _valid_rate(sample_rate):
        return None
    try:
        values = np.asarray(source, dtype=np.float64).reshape(-1)
    except (TypeError, ValueError):
        return None
    if not 0 < values.size <= MAX_SAMPLES or not np.all(np.isfinite(values)):
        return None
    return Audio(int(sample_rate), values)


def _tone_projection(segment: np.ndarray, rate: int, frequency: float) -> complex:
    n = np.arange(segment.size, dtype=np.float64)
    window = np.hanning(segment.size) if segment.size >= 8 else np.ones(segment.size)
    return complex(np.dot(segment * window, np.exp(-2j * np.pi * frequency * n / rate)))


def _bit_payload(bits: Sequence[int | None]) -> bytes | None:
    """Find byte-aligned or shifted R5A1 bits, requiring every used bit."""
    magic_bits = tuple((byte >> shift) & 1 for byte in MAGIC for shift in range(7, -1, -1))
    n = len(bits)
    for start in range(0, n - 80 + 1):
        if any(bits[start + i] != bit for i, bit in enumerate(magic_bits)):
            continue
        header_bits = bits[start:start + 80]
        if any(bit is None for bit in header_bits):
            continue
        header = _bits_bytes(header_bits)  # type: ignore[arg-type]
        length = struct.unpack_from(">H", header, 4)[0]
        total = (10 + length) * 8
        if length > MAX_PAYLOAD or start + total > n:
            continue
        selected = bits[start:start + total]
        if any(bit is None for bit in selected):
            continue
        payload = _parse_checked(_bits_bytes(selected))  # type: ignore[arg-type]
        if payload is not None:
            return payload
    return None


def _bits_bytes(bits: Sequence[int]) -> bytes:
    out = bytearray()
    for at in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[at:at + 8]:
            value = (value << 1) | (int(bit) & 1)
        out.append(value)
    return bytes(out)


def _bits_bytes_lsb(bits: Sequence[int]) -> bytes:
    out = bytearray()
    for at in range(0, len(bits) - 7, 8):
        value = 0
        for shift, bit in enumerate(bits[at:at + 8]):
            value |= (int(bit) & 1) << shift
        out.append(value)
    return bytes(out)


def _valid_bit_runs(bits: Sequence[int | None], scores: Sequence[float]) -> list[tuple[list[int], list[float]]]:
    runs: list[tuple[list[int], list[float]]] = []
    current: list[int] = []
    quality: list[float] = []
    for index, bit in enumerate(bits):
        if bit is None:
            if len(current) >= 24:
                runs.append((current, quality))
            current, quality = [], []
        else:
            current.append(int(bit))
            quality.append(float(scores[index]) if index < len(scores) else 1.0)
    if len(current) >= 24:
        runs.append((current, quality))
    return runs


def _uart_bytes(bits: Sequence[int]) -> list[bytes]:
    """Return streams whose every complete character has valid 8N1 framing."""
    found: list[bytes] = []
    for polarity in (0, 1):
        stream = [bit ^ polarity for bit in bits]
        for offset in range(10):
            chunks = (len(stream) - offset) // 10
            if chunks < 3:
                continue
            out = bytearray()
            valid = True
            for index in range(chunks):
                word = stream[offset + index * 10:offset + (index + 1) * 10]
                if word[0] != 0 or word[9] != 1:
                    valid = False
                    break
                out.append(sum(word[1 + bit] << bit for bit in range(8)))
            if valid:
                found.append(bytes(out))
    return found


def _surface_bytes(
    scheme: str,
    bits: Sequence[int | None],
    scores: Sequence[float],
    *,
    min_printable: int = 6,
) -> list[SignalCandidate]:
    """Surface only CRC, flag-shaped, wholly printable, or valid-8N1 values."""
    out: list[SignalCandidate] = []
    seen: set[tuple[bytes, str]] = set()

    def add(payload: bytes, check: str, confidence: float, proven: bool = False) -> None:
        key = (payload, check)
        if payload and key not in seen and len(out) < MAX_CANDIDATES:
            seen.add(key)
            out.append(SignalCandidate(scheme, payload, check, max(0.0, min(1.0, confidence)), proven))

    proven = _bit_payload(bits)
    if proven is not None:
        add(proven, "R5A1 length+CRC32", 1.0, True)
    for run, run_scores in _valid_bit_runs(bits, scores):
        # Scores are dominance/coherence measures.  Compress them to a bounded,
        # deterministic indicator without claiming a calibrated probability.
        quality = min(1.0, float(np.median(run_scores)) / 3.0) if run_scores else 0.0
        for inverted in (False, True):
            chosen = [bit ^ int(inverted) for bit in run]
            polarity = "inverted " if inverted else ""
            for shift in range(8):
                aligned = chosen[shift:]
                for order, pack in (("MSB", _bits_bytes), ("LSB", _bits_bytes_lsb)):
                    blob = pack(aligned)
                    for match in _FLAG.finditer(blob):
                        add(match.group(), f"{polarity}{order}-first flag shape + dominated symbols", quality)
                    stripped = blob.rstrip(b"\x00\r\n")
                    if len(stripped) >= min_printable and all(0x20 <= byte <= 0x7E for byte in stripped):
                        add(stripped, f"{polarity}{order}-first wholly printable + dominated symbols", quality)
                    else:
                        # Long internal runs are useful with preambles/padding, but
                        # are kept labeled and require a stronger eight-byte floor.
                        for match in _PRINTABLE.finditer(blob):
                            if len(match.group()) >= max(8, min_printable):
                                add(match.group(), f"{polarity}{order}-first printable run + dominated symbols", quality)
            for uart in _uart_bytes(chosen):
                flag = _FLAG.search(uart)
                if flag:
                    add(flag.group(), f"{polarity}8N1 framing + flag shape + dominated symbols", quality)
                stripped = uart.rstrip(b"\x00\r\n")
                if len(stripped) >= 3 and all(0x20 <= byte <= 0x7E for byte in stripped):
                    add(stripped, f"{polarity}valid 8N1 framing + printable bytes + dominated symbols", quality)
    return out


def _symbols(audio: Audio, baud: float, offset: int = 0) -> tuple[int, list[np.ndarray]] | None:
    if (not math.isfinite(baud) or baud <= 0
            or not isinstance(offset, (int, np.integer))):
        return None
    size = int(round(audio.rate / float(baud)))
    if size < 8 or offset < 0 or offset >= min(size, audio.samples.size):
        return None
    count = (audio.samples.size - offset) // size
    if count < 8 or count > MAX_SYMBOLS:
        return None
    return size, [audio.samples[offset + i * size:offset + (i + 1) * size] for i in range(count)]


def _fsk_bits(
    source,
    *,
    sample_rate: int | None = None,
    baud: float = 100.0,
    zero_hz: float = 1200.0,
    one_hz: float = 2200.0,
    offset: int = 0,
    dominance: float = 1.35,
) -> tuple[list[int | None], list[float]] | None:
    audio = read_audio(source, sample_rate=sample_rate)
    got = _symbols(audio, baud, offset) if audio else None
    if (not got or not math.isfinite(dominance) or dominance <= 1
            or not (0 < zero_hz < audio.rate / 2 and 0 < one_hz < audio.rate / 2)
            or abs(zero_hz - one_hz) < audio.rate / got[0]):
        return None
    _, segments = got
    bits: list[int | None] = []
    scores: list[float] = []
    for segment in segments:
        e0 = abs(_tone_projection(segment, audio.rate, zero_hz)) + 1e-15
        e1 = abs(_tone_projection(segment, audio.rate, one_hz)) + 1e-15
        ratio = max(e0, e1) / min(e0, e1)
        bits.append(None if ratio < dominance else int(e1 > e0))
        scores.append(ratio)
    return bits, scores


def decode_fsk(
    source,
    *,
    sample_rate: int | None = None,
    baud: float = 100.0,
    zero_hz: float = 1200.0,
    one_hz: float = 2200.0,
    offset: int = 0,
    dominance: float = 1.35,
) -> bytes | None:
    """Decode noncoherent binary FSK and return a CRC-proven payload."""
    got = _fsk_bits(source, sample_rate=sample_rate, baud=baud, zero_hz=zero_hz,
                    one_hz=one_hz, offset=offset, dominance=dominance)
    return _bit_payload(got[0]) if got else None


def fsk_candidates(source, **parameters) -> list[SignalCandidate]:
    """Labeled FSK candidates accepted by CRC, flag, printable, or 8N1 checks."""
    min_printable = int(parameters.pop("min_printable", 6))
    got = _fsk_bits(source, **parameters)
    return _surface_bytes("fsk", *got, min_printable=min_printable) if got else []


def _two_means(values: np.ndarray) -> tuple[float, float] | None:
    if values.size < 8 or not np.all(np.isfinite(values)):
        return None
    low, high = float(np.min(values)), float(np.max(values))
    if high <= low + 1e-12:
        return None
    for _ in range(20):
        midpoint = (low + high) / 2
        a, b = values[values <= midpoint], values[values > midpoint]
        if not a.size or not b.size:
            return None
        new = float(np.mean(a)), float(np.mean(b))
        if max(abs(new[0] - low), abs(new[1] - high)) < 1e-10:
            low, high = new
            break
        low, high = new
    return low, high


def _ask_bits(
    source,
    *,
    sample_rate: int | None = None,
    baud: float = 100.0,
    carrier_hz: float = 1800.0,
    offset: int = 0,
    separation: float = 2.5,
) -> tuple[list[int | None], list[float]] | None:
    audio = read_audio(source, sample_rate=sample_rate)
    got = _symbols(audio, baud, offset) if audio else None
    if (not got or not math.isfinite(separation) or separation <= 1
            or not 0 < carrier_hz < audio.rate / 2):
        return None
    _, segments = got
    energy = np.asarray([abs(_tone_projection(seg, audio.rate, carrier_hz)) for seg in segments])
    centers = _two_means(energy)
    if not centers or centers[1] < max(1e-9, centers[0] * separation):
        return None
    threshold = sum(centers) / 2
    # Reject points in the ambiguous middle third between the fitted centers.
    margin = (centers[1] - centers[0]) / 6
    bits = [None if abs(e - threshold) < margin else int(e > threshold) for e in energy]
    scale = max(centers[1] - centers[0], 1e-15)
    scores = [1.0 + abs(float(e) - threshold) / scale * 4.0 for e in energy]
    return bits, scores


def decode_ask(
    source,
    *,
    sample_rate: int | None = None,
    baud: float = 100.0,
    carrier_hz: float = 1800.0,
    offset: int = 0,
    separation: float = 2.5,
) -> bytes | None:
    """Decode on/off ASK after a two-cluster energy check."""
    got = _ask_bits(source, sample_rate=sample_rate, baud=baud, carrier_hz=carrier_hz,
                    offset=offset, separation=separation)
    return _bit_payload(got[0]) if got else None


def ask_candidates(source, **parameters) -> list[SignalCandidate]:
    """Labeled ASK/OOK candidates accepted by CRC, flag, printable, or 8N1 checks."""
    min_printable = int(parameters.pop("min_printable", 6))
    got = _ask_bits(source, **parameters)
    return _surface_bytes("ask", *got, min_printable=min_printable) if got else []


def _psk_bits(
    source,
    *,
    sample_rate: int | None = None,
    baud: float = 100.0,
    carrier_hz: float = 1800.0,
    offset: int = 0,
    min_coherence: float = 0.15,
) -> tuple[list[int | None], list[float]] | None:
    audio = read_audio(source, sample_rate=sample_rate)
    got = _symbols(audio, baud, offset) if audio else None
    if (not got or not math.isfinite(min_coherence) or not 0 < min_coherence < 1
            or not 0 < carrier_hz < audio.rate / 2):
        return None
    size, segments = got
    phasors = [_tone_projection(seg, audio.rate, carrier_hz) for seg in segments]
    # Projection uses a local time origin for each symbol.  A continuous carrier
    # therefore advances by omega*symbol_size even when the data phase does not;
    # remove that deterministic rotation before testing 0 versus pi.
    derotate = np.exp(-2j * np.pi * carrier_hz * size / audio.rate)
    bits: list[int | None] = []
    scores: list[float] = []
    for previous, current in zip(phasors, phasors[1:]):
        denom = abs(previous) * abs(current) + 1e-15
        metric = (current * previous.conjugate() * derotate).real / denom
        bits.append(None if abs(metric) < min_coherence else int(metric < 0))
        scores.append(abs(metric) * 3.0)
    return bits, scores


def decode_psk(
    source,
    *,
    sample_rate: int | None = None,
    baud: float = 100.0,
    carrier_hz: float = 1800.0,
    offset: int = 0,
    min_coherence: float = 0.15,
) -> bytes | None:
    """Decode differential BPSK (one leading reference symbol) with CRC acceptance."""
    got = _psk_bits(source, sample_rate=sample_rate, baud=baud, carrier_hz=carrier_hz,
                    offset=offset, min_coherence=min_coherence)
    return _bit_payload(got[0]) if got else None


def psk_candidates(source, **parameters) -> list[SignalCandidate]:
    """Labeled differential-BPSK candidates with byte/UART acceptance evidence."""
    min_printable = int(parameters.pop("min_printable", 6))
    got = _psk_bits(source, **parameters)
    return _surface_bytes("differential-bpsk", *got, min_printable=min_printable) if got else []


DTMF_ROWS = (697.0, 770.0, 852.0, 941.0)
DTMF_COLS = (1209.0, 1336.0, 1477.0, 1633.0)
DTMF_KEYS = ("123A", "456B", "789C", "*0#D")
_NIBBLE = {symbol: value for value, symbol in enumerate("0123456789ABCD*#")}


def _dtmf_symbol(segment: np.ndarray, rate: int, dominance: float) -> tuple[str, float] | None:
    rows = [abs(_tone_projection(segment, rate, f)) for f in DTMF_ROWS]
    cols = [abs(_tone_projection(segment, rate, f)) for f in DTMF_COLS]
    ri, ci = int(np.argmax(rows)), int(np.argmax(cols))
    rsort, csort = sorted(rows), sorted(cols)
    if rsort[-1] < 1e-8 or csort[-1] < 1e-8:
        return None
    if rsort[-1] < rsort[-2] * dominance or csort[-1] < csort[-2] * dominance:
        return None
    twist = max(rsort[-1], csort[-1]) / max(min(rsort[-1], csort[-1]), 1e-15)
    if twist > 6.0:
        return None
    score = min(rsort[-1] / max(rsort[-2], 1e-15), csort[-1] / max(csort[-2], 1e-15), 6.0 / twist)
    return DTMF_KEYS[ri][ci], score


def dtmf_key(segment: np.ndarray, rate: int, dominance: float = 1.8) -> str | None:
    """The DTMF key of one tone segment (row and column dominance plus twist), else ``None``."""
    got = _dtmf_symbol(np.asarray(segment, dtype=np.float64), int(rate), dominance)
    return got[0] if got else None


def _dtmf_stream(
    source,
    *,
    sample_rate: int | None = None,
    tone_ms: float = 70.0,
    gap_ms: float = 20.0,
    offset_ms: float = 0.0,
    dominance: float = 1.8,
) -> tuple[str, list[float]] | None:
    audio = read_audio(source, sample_rate=sample_rate)
    if (not audio or not all(math.isfinite(x) for x in (tone_ms, gap_ms, offset_ms, dominance))
            or tone_ms <= 0 or gap_ms < 0 or offset_ms < 0 or dominance <= 1):
        return None
    tone = int(round(audio.rate * tone_ms / 1000))
    stride = int(round(audio.rate * (tone_ms + gap_ms) / 1000))
    start = int(round(audio.rate * offset_ms / 1000))
    if tone < 16 or stride < tone or start < 0:
        return None
    symbols: list[str] = []
    scores: list[float] = []
    while start + tone <= audio.samples.size and len(symbols) < 2 * (MAX_PAYLOAD + 10):
        segment = audio.samples[start:start + tone]
        got = _dtmf_symbol(segment, audio.rate, dominance)
        if got is None:
            return None
        symbol, score = got
        if stride > tone:
            gap = audio.samples[start + tone:min(start + stride, audio.samples.size)]
            tone_rms = float(np.sqrt(np.mean(segment * segment)))
            gap_rms = float(np.sqrt(np.mean(gap * gap))) if gap.size else 0.0
            if gap_rms > max(1e-6, tone_rms * 0.35):
                return None
        symbols.append(symbol)
        scores.append(score)
        start += stride
    # A substantial partial tone is truncation, not a valid final symbol.
    if audio.samples.size - start > tone // 2:
        return None
    return ("".join(symbols), scores) if symbols else None


def decode_dtmf(
    source,
    *,
    sample_rate: int | None = None,
    tone_ms: float = 70.0,
    gap_ms: float = 20.0,
    offset_ms: float = 0.0,
    dominance: float = 1.8,
) -> bytes | None:
    """Decode DTMF nibbles (0..9,A..D,*=#xE,#=#xF) carrying R5A1."""
    got = _dtmf_stream(source, sample_rate=sample_rate, tone_ms=tone_ms, gap_ms=gap_ms,
                       offset_ms=offset_ms, dominance=dominance)
    if not got:
        return None
    symbols, _scores = got
    for nibble_offset in (0, 1):
        values = [_NIBBLE[s] for s in symbols[nibble_offset:]]
        blob = bytes((values[i] << 4) | values[i + 1] for i in range(0, len(values) - 1, 2))
        payload = _parse_checked(blob)
        if payload is not None:
            return payload
    return None


def dtmf_candidates(source, *, min_symbols: int = 3, **parameters) -> list[SignalCandidate]:
    """Return ordinary DTMF symbols plus a proven nibble payload when present."""
    if min_symbols < 1:
        return []
    got = _dtmf_stream(source, **parameters)
    if not got:
        return []
    symbols, scores = got
    if len(symbols) < min_symbols:
        return []
    confidence = min(1.0, float(np.median(scores)) / 3.0)
    out = [SignalCandidate("dtmf", symbols.encode("ascii"),
                           "dual-tone row/column dominance + twist + quiet gaps", confidence, False)]
    for nibble_offset in (0, 1):
        values = [_NIBBLE[s] for s in symbols[nibble_offset:]]
        blob = bytes((values[i] << 4) | values[i + 1] for i in range(0, len(values) - 1, 2))
        payload = _parse_checked(blob)
        if payload is not None:
            out.insert(0, SignalCandidate("dtmf-nibbles", payload, "R5A1 length+CRC32", 1.0, True))
            break
    return out[:MAX_CANDIDATES]


MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-..-.": "/", "-.--.": "(", "-.--.-": ")", ".----.": "'", "-....-": "-",
    "..--.-": "_", "---...": ":", "-.-.-.": ";", "-...-": "=", ".-.-.": "+",
    ".--.-.": "@", "...-..-": "$", "-.-.--": "!", ".-..-.": '"', ".-...": "&",
}


def _runs(states: np.ndarray) -> list[tuple[bool, int]]:
    if states.size == 0:
        return []
    out: list[tuple[bool, int]] = []
    current, count = bool(states[0]), 1
    for value in states[1:]:
        value = bool(value)
        if value == current:
            count += 1
        else:
            out.append((current, count))
            current, count = value, 1
    out.append((current, count))
    return out


def tone_levels(audio: Audio, block: int, tone_hz: float | None = None) -> np.ndarray | None:
    """One level per ``block`` samples: broadband RMS, or with ``tone_hz`` the magnitude of the
    block's I/Q projection at that frequency (a narrow-band envelope that ignores hiss, hum and
    other tones).  ``None`` for a frequency outside (0, Nyquist)."""
    count = audio.samples.size // block
    segment = audio.samples[:count * block]
    if tone_hz is None:
        matrix = segment.reshape(count, block)
        return np.sqrt(np.mean(matrix * matrix, axis=1))
    try:
        tone_hz = float(tone_hz)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(tone_hz) or not 0 < tone_hz < audio.rate / 2:
        return None
    phase = 2 * np.pi * tone_hz * np.arange(segment.size, dtype=np.float64) / audio.rate
    i = (segment * np.cos(phase)).reshape(count, block).mean(axis=1)
    q = (segment * np.sin(phase)).reshape(count, block).mean(axis=1)
    return 2 * np.sqrt(i * i + q * q)


def keyed_runs(
    source,
    *,
    sample_rate: int | None = None,
    tone_hz: float | None = None,
    analysis_ms: float = 5.0,
) -> list[tuple[bool, int]] | None:
    """On/off runs (state, blocks of ``analysis_ms``) of a keyed signal, leading and trailing
    silence dropped.  ``None`` unless the levels split into two clusters at least 3x apart."""
    audio = read_audio(source, sample_rate=sample_rate)
    if not audio or not math.isfinite(analysis_ms) or analysis_ms <= 0:
        return None
    block = max(4, int(round(audio.rate * analysis_ms / 1000)))
    if audio.samples.size // block < 4:
        return None
    levels = tone_levels(audio, block, tone_hz)
    if levels is None:
        return None
    centers = _two_means(levels)
    if not centers or centers[1] < max(1e-6, centers[0] * 3):
        return None
    runs = _runs(levels > (centers[0] + centers[1]) / 2)
    while runs and not runs[0][0]:
        runs.pop(0)
    while runs and not runs[-1][0]:
        runs.pop()
    return runs


def decode_morse_tone(
    source,
    *,
    sample_rate: int | None = None,
    unit_ms: float | None = None,
    analysis_ms: float = 5.0,
    tolerance: float = 0.36,
    min_chars: int = 3,
    tone_hz: float | None = None,
    long_gaps: bool = False,
) -> bytes | None:
    """Decode keyed-tone Morse only when all runs fit the 1/3/7 timing lattice.

    ``tone_hz`` keys on the envelope at that frequency instead of broadband RMS (a noisy or lossy
    recording).  ``long_gaps`` reads a silence longer than a word gap as a word gap (pauses between
    sentences); without it such a silence fails the lattice.  ``tolerance`` is the allowed error as
    a fraction of the lattice value: a 25/75/165 ms keying (word gap 6.6 units, not 7) needs
    about 0.06 or more."""
    runs = keyed_runs(source, sample_rate=sample_rate, tone_hz=tone_hz, analysis_ms=analysis_ms)
    if not runs:
        return None
    if unit_ms is None:
        tone_lengths = sorted(length for state, length in runs if state)
        if not tone_lengths:
            return None
        unit_blocks = float(np.median(tone_lengths[:max(1, len(tone_lengths) // 2)]))
    else:
        unit_blocks = unit_ms / analysis_ms
    if unit_blocks < 1:
        return None

    def quantize(length: int, choices: Sequence[int]) -> int | None:
        if long_gaps and 7 in choices and length / unit_blocks > 7:
            return 7
        ratios = [(abs(length / unit_blocks - choice), choice) for choice in choices]
        error, choice = min(ratios)
        return choice if error <= tolerance * choice else None

    words: list[list[str]] = [[]]
    code = ""
    for state, length in runs:
        if state:
            q = quantize(length, (1, 3))
            if q is None:
                return None
            code += "." if q == 1 else "-"
        else:
            q = quantize(length, (1, 3, 7))
            if q is None:
                return None
            if q >= 3:
                letter = MORSE.get(code)
                if letter is None:
                    return None
                words[-1].append(letter)
                code = ""
            if q == 7:
                words.append([])
    if code:
        letter = MORSE.get(code)
        if letter is None:
            return None
        words[-1].append(letter)
    if any(not word for word in words):
        return None
    text = " ".join("".join(word) for word in words)
    return text.encode("ascii") if len(text.replace(" ", "")) >= min_chars else None


# Canonical 5x7 glyphs.  A set bit means an audible frequency in that row.
FONT_5X7: Mapping[str, tuple[str, ...]] = {
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "B": ("11110", "10001", "10001", "11110", "10001", "10001", "11110"),
    "C": ("01111", "10000", "10000", "10000", "10000", "10000", "01111"),
    "D": ("11110", "10001", "10001", "10001", "10001", "10001", "11110"),
    "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
    "F": ("11111", "10000", "10000", "11110", "10000", "10000", "10000"),
    "G": ("01111", "10000", "10000", "10111", "10001", "10001", "01111"),
    "H": ("10001", "10001", "10001", "11111", "10001", "10001", "10001"),
    "I": ("11111", "00100", "00100", "00100", "00100", "00100", "11111"),
    "J": ("00111", "00010", "00010", "00010", "10010", "10010", "01100"),
    "K": ("10001", "10010", "10100", "11000", "10100", "10010", "10001"),
    "L": ("10000", "10000", "10000", "10000", "10000", "10000", "11111"),
    "M": ("10001", "11011", "10101", "10101", "10001", "10001", "10001"),
    "N": ("10001", "11001", "10101", "10011", "10001", "10001", "10001"),
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "P": ("11110", "10001", "10001", "11110", "10000", "10000", "10000"),
    "Q": ("01110", "10001", "10001", "10001", "10101", "10010", "01101"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "S": ("01111", "10000", "10000", "01110", "00001", "00001", "11110"),
    "T": ("11111", "00100", "00100", "00100", "00100", "00100", "00100"),
    "U": ("10001", "10001", "10001", "10001", "10001", "10001", "01110"),
    "V": ("10001", "10001", "10001", "10001", "10001", "01010", "00100"),
    "W": ("10001", "10001", "10001", "10101", "10101", "10101", "01010"),
    "X": ("10001", "10001", "01010", "00100", "01010", "10001", "10001"),
    "Y": ("10001", "10001", "01010", "00100", "00100", "00100", "00100"),
    "Z": ("11111", "00001", "00010", "00100", "01000", "10000", "11111"),
    "0": ("01110", "10001", "10011", "10101", "11001", "10001", "01110"),
    "1": ("00100", "01100", "00100", "00100", "00100", "00100", "01110"),
    "2": ("01110", "10001", "00001", "00010", "00100", "01000", "11111"),
    "3": ("11110", "00001", "00001", "01110", "00001", "00001", "11110"),
    "4": ("00010", "00110", "01010", "10010", "11111", "00010", "00010"),
    "5": ("11111", "10000", "10000", "11110", "00001", "00001", "11110"),
    "6": ("01110", "10000", "10000", "11110", "10001", "10001", "01110"),
    "7": ("11111", "00001", "00010", "00100", "01000", "01000", "01000"),
    "8": ("01110", "10001", "10001", "01110", "10001", "10001", "01110"),
    "9": ("01110", "10001", "10001", "01111", "00001", "00001", "01110"),
    "{": ("00111", "00100", "00100", "11000", "00100", "00100", "00111"),
    "}": ("11100", "00100", "00100", "00011", "00100", "00100", "11100"),
    "_": ("00000", "00000", "00000", "00000", "00000", "00000", "11111"),
    "-": ("00000", "00000", "00000", "11111", "00000", "00000", "00000"),
    ":": ("00000", "00100", "00100", "00000", "00100", "00100", "00000"),
    ".": ("00000", "00000", "00000", "00000", "00000", "00110", "00110"),
}


def decode_spectrogram_text(
    source,
    *,
    sample_rate: int | None = None,
    column_ms: float = 35.0,
    base_hz: float = 500.0,
    row_step_hz: float = 180.0,
    glyphs: Mapping[str, Sequence[str]] = FONT_5X7,
    min_chars: int = 2,
) -> bytes | None:
    """Read exact 5x7 glyphs drawn as seven spectrogram frequency rows.

    Glyphs occupy five time columns followed by one silent separator.  Every
    recovered glyph must exactly match ``glyphs`` and every separator must be
    blank; those are the acceptance checks.
    """
    audio = read_audio(source, sample_rate=sample_rate)
    if not audio or column_ms <= 0:
        return None
    width = int(round(audio.rate * column_ms / 1000))
    if width < 16:
        return None
    ncols = audio.samples.size // width
    if ncols < 6 * min_chars or ncols > 100_000:
        return None
    rows = len(next(iter(glyphs.values()), ()))
    if rows != 7 or base_hz <= 0 or base_hz + (rows - 1) * row_step_hz >= audio.rate / 2:
        return None
    energy = np.zeros((rows, ncols), dtype=np.float64)
    for col in range(ncols):
        segment = audio.samples[col * width:(col + 1) * width]
        for row in range(rows):
            energy[row, col] = abs(_tone_projection(segment, audio.rate, base_hz + row * row_step_hz))
    centers = _two_means(energy.reshape(-1))
    if not centers or centers[1] < max(1e-8, centers[0] * 2.5):
        return None
    threshold = sum(centers) / 2
    pixels = energy > threshold
    reverse = {tuple(str(row[c]) for row in pattern for c in range(5)): char for char, pattern in glyphs.items()}
    chars: list[str] = []
    for at in range(0, ncols - 5, 6):
        block = pixels[:, at:at + 5]
        separator = pixels[:, at + 5]
        if np.any(separator):
            return None
        key = tuple("1" if block[row, col] else "0" for row in range(7) for col in range(5))
        char = reverse.get(key)
        if char is None:
            return None
        chars.append(char)
    if len(chars) < min_chars:
        return None
    return "".join(chars).encode("ascii")


def _known_tone(segment: np.ndarray, rate: int, expected: float, alternatives: Sequence[float]) -> bool:
    energies = [(f, abs(_tone_projection(segment, rate, f))) for f in alternatives]
    winner, energy = max(energies, key=lambda item: item[1])
    others = [value for f, value in energies if f != winner]
    return winner == expected and energy > 1e-8 and (not others or energy > max(others) * 1.15)


def _slice_ms(samples: np.ndarray, rate: int, start_ms: float, duration_ms: float) -> np.ndarray:
    a = int(round(rate * start_ms / 1000))
    b = int(round(rate * (start_ms + duration_ms) / 1000))
    return samples[a:b]


def _audible(segment: np.ndarray) -> bool:
    """Energy check for Martin's 0.572 ms porches (too short for honest tone ID)."""
    return segment.size >= 8 and float(np.sqrt(np.mean(segment * segment))) > 0.05


def _sstv_color(segment: np.ndarray, rate: int, count: int = 320) -> np.ndarray:
    """Approximate Martin scanline colors with overlapping local correlations."""
    if segment.size < count:
        return np.zeros(count, dtype=np.uint8)
    centers = (np.arange(count) + 0.5) * segment.size / count
    radius = max(16, int(rate * 0.0015))
    frequencies = np.arange(1500.0, 2300.1, 100.0)
    values = np.empty(count, dtype=np.uint8)
    for i, center in enumerate(centers):
        a, b = max(0, int(center) - radius), min(segment.size, int(center) + radius)
        piece = segment[a:b]
        powers = [abs(_tone_projection(piece, rate, f)) for f in frequencies]
        frequency = frequencies[int(np.argmax(powers))]
        values[i] = int(np.clip(round((frequency - 1500) * 255 / 800), 0, 255))
    return values


SSTV_VIS_MODES = {
    8: "Robot 36", 12: "Robot 72", 40: "Martin M2", 44: "Martin M1",
    56: "Scottie S2", 60: "Scottie S1", 76: "Scottie DX",
    93: "PD50", 99: "PD90", 95: "PD120", 98: "PD160", 96: "PD180",
    97: "PD240", 94: "PD290",
}


def _sstv_header(audio: Audio) -> tuple[int, float] | None:
    """Validate the standard SSTV leader and return (VIS, first-scanline-ms)."""
    s, rate = audio.samples, audio.rate
    if s.size < int(rate * 0.91):
        return None
    alts = (1100.0, 1200.0, 1300.0, 1500.0, 1900.0)
    if not _known_tone(_slice_ms(s, rate, 40, 220), rate, 1900.0, alts):
        return None
    if not _known_tone(_slice_ms(s, rate, 301, 8), rate, 1200.0, alts):
        return None
    if not _known_tone(_slice_ms(s, rate, 340, 220), rate, 1900.0, alts):
        return None
    at = 610.0
    if not _known_tone(_slice_ms(s, rate, at, 30), rate, 1200.0, alts):
        return None
    at += 30.0
    bits = []
    for _ in range(8):  # seven VIS bits LSB-first, then even parity
        piece = _slice_ms(s, rate, at, 30)
        e0 = abs(_tone_projection(piece, rate, 1300.0))
        e1 = abs(_tone_projection(piece, rate, 1100.0))
        if max(e0, e1) < 1e-8 or max(e0, e1) < min(e0, e1) * 1.15:
            return None
        bits.append(int(e1 > e0))
        at += 30.0
    if not _known_tone(_slice_ms(s, rate, at, 30), rate, 1200.0, alts):
        return None
    vis = sum(bits[i] << i for i in range(7))
    if sum(bits) & 1:
        return None
    at += 30.0
    return vis, at


def detect_sstv_vis(source, *, sample_rate: int | None = None) -> dict | None:
    """Return validated SSTV VIS metadata without pretending unsupported pixels decoded."""
    audio = read_audio(source, sample_rate=sample_rate)
    if not audio or audio.rate < 8000:
        return None
    got = _sstv_header(audio)
    if not got:
        return None
    vis, _at = got
    return {
        "vis": vis,
        "mode": SSTV_VIS_MODES.get(vis, f"unknown VIS {vis}"),
        "check": "300/10/300 ms leader + start/stop + even VIS parity",
    }


def _decode_sstv_martin(
    source,
    *,
    sample_rate: int | None,
    max_lines: int,
    expected_vis: int | None,
) -> bytes | None:
    audio = read_audio(source, sample_rate=sample_rate)
    if not audio or audio.rate < 8000 or max_lines < 1 or max_lines > 256:
        return None
    header = _sstv_header(audio)
    if not header:
        return None
    vis, at = header
    if expected_vis is not None and vis != expected_vis:
        return None
    scan_ms = {44: 146.432, 40: 73.216}.get(vis)
    if scan_ms is None:
        return None
    s, rate = audio.samples, audio.rate
    alts = (1100.0, 1200.0, 1300.0, 1500.0, 1900.0)

    line_ms = 4.862 + 0.572 + scan_ms + 0.572 + scan_ms + 0.572 + scan_ms
    rows: list[np.ndarray] = []
    while len(rows) < max_lines and int(round(rate * (at + line_ms) / 1000)) <= s.size:
        sync = _slice_ms(s, rate, at, 4.862)
        if not _known_tone(sync, rate, 1200.0, alts):
            break
        at += 4.862
        # A 0.572 ms porch contains less than one cycle at 1500 Hz.  Frequency
        # discrimination would be false precision; validate its presence/energy
        # while the long leader, VIS, stop and per-line sync establish the mode.
        if not _audible(_slice_ms(s, rate, at, 0.572)):
            break
        at += 0.572
        channels = []
        valid = True
        for index in range(3):  # G, B, R
            piece = _slice_ms(s, rate, at, scan_ms)
            channels.append(_sstv_color(piece, rate))
            at += scan_ms
            if index < 2:
                if not _audible(_slice_ms(s, rate, at, 0.572)):
                    valid = False
                    break
                at += 0.572
        if not valid:
            break
        # Final separator before the next line.
        if not _audible(_slice_ms(s, rate, at, 0.572)):
            break
        at += 0.572
        green, blue, red = channels
        rows.append(np.stack((red, green, blue), axis=1))
    if not rows:
        return None
    pixels = np.stack(rows).astype(np.uint8)
    return f"P6\n320 {pixels.shape[0]}\n255\n".encode("ascii") + pixels.tobytes()


def decode_sstv_martin(
    source,
    *,
    sample_rate: int | None = None,
    max_lines: int = 256,
) -> bytes | None:
    """Decode validated Martin M1 (VIS 44) or M2 (VIS 40) to binary PPM."""
    return _decode_sstv_martin(source, sample_rate=sample_rate, max_lines=max_lines,
                               expected_vis=None)


def decode_sstv_martin_m1(
    source,
    *,
    sample_rate: int | None = None,
    max_lines: int = 256,
) -> bytes | None:
    """Decode validated Martin-M1 (VIS 44) audio to a binary PPM candidate."""
    return _decode_sstv_martin(source, sample_rate=sample_rate, max_lines=max_lines,
                               expected_vis=44)


def decode_sstv_martin_m2(
    source,
    *,
    sample_rate: int | None = None,
    max_lines: int = 256,
) -> bytes | None:
    """Decode validated Martin-M2 (VIS 40) audio to a binary PPM candidate."""
    return _decode_sstv_martin(source, sample_rate=sample_rate, max_lines=max_lines,
                               expected_vis=40)


def decode_ggwave(
    source,
    *,
    sample_rate: int | None = None,
    raw_float32: bool = False,
) -> bytes | None:
    """Use optional ggwave and return only a protocol/FEC-validated message."""
    try:
        import ggwave  # type: ignore
    except ImportError:
        return None
    if raw_float32 and isinstance(source, (bytes, bytearray)):
        waveform = bytes(source)
        if len(waveform) > MAX_AUDIO_BYTES or len(waveform) % 4:
            return None
    else:
        audio = read_audio(source, sample_rate=sample_rate, raw_dtype="<f4")
        if not audio or audio.rate != 48000:
            return None
        waveform = np.asarray(audio.samples, dtype="<f4").tobytes()
    instance = None
    try:
        if hasattr(ggwave, "disableLog"):
            ggwave.disableLog()
        instance = ggwave.init()
        decoded = ggwave.decode(instance, waveform)
        return bytes(decoded) if decoded else None
    except Exception:
        return None
    finally:
        if instance is not None:
            try:
                ggwave.free(instance)
            except Exception:
                pass


__all__ = [
    "Audio", "SignalCandidate", "FONT_5X7", "SSTV_VIS_MODES", "checked_frame", "read_audio",
    "decode_fsk", "fsk_candidates", "decode_ask", "ask_candidates", "decode_psk",
    "psk_candidates", "decode_dtmf", "dtmf_candidates", "decode_morse_tone",
    "decode_spectrogram_text", "detect_sstv_vis", "decode_sstv_martin",
    "decode_sstv_martin_m1", "decode_sstv_martin_m2", "decode_ggwave",
]
